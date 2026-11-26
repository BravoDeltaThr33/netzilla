"""ping / traceroute / mtr wrappers for the Diagnostics tab."""

from __future__ import annotations

import re

from .runner import CommandResult, have, run


async def ping(host: str, count: int = 4, timeout: float = 30.0) -> CommandResult:
    return await run(
        ["ping", "-c", str(count), "-W", "2", host],
        timeout=timeout,
        ok_returncodes=(0, 1),
    )


async def traceroute(host: str, max_hops: int = 20, timeout: float = 90.0) -> CommandResult:
    if have("traceroute"):
        return await run(
            ["traceroute", "-m", str(max_hops), "-w", "2", host], timeout=timeout
        )
    if have("tracepath"):
        return await run(["tracepath", "-m", str(max_hops), host], timeout=timeout)
    return CommandResult(
        False, "", "Neither traceroute nor tracepath is installed.", "traceroute",
        missing_tool="traceroute",
    )


async def mtr(host: str, cycles: int = 10, timeout: float = 90.0) -> CommandResult:
    return await run(
        ["mtr", "--report", "--report-cycles", str(cycles), "-n", host],
        timeout=timeout,
    )


async def port_check(host: str, port: int, timeout: float = 10.0) -> CommandResult:
    """TCP reachability without needing nmap installed."""
    import asyncio

    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return CommandResult(True, f"tcp/{port} on {host} is OPEN", "", f"connect {host}:{port}")
    except asyncio.TimeoutError:
        return CommandResult(
            False, "", f"tcp/{port} on {host} timed out (filtered or dropped).",
            f"connect {host}:{port}",
        )
    except OSError as exc:
        return CommandResult(
            False, "", f"tcp/{port} on {host} is CLOSED — {exc.strerror or exc}",
            f"connect {host}:{port}",
        )


PING_STATS = re.compile(
    r"(?P<tx>\d+) packets transmitted,\s*(?P<rx>\d+) received"
    r"(?:,\s*\+?(?P<errors>\d+) errors)?,\s*(?P<loss>[\d.]+)% packet loss"
)
RTT_STATS = re.compile(
    r"=\s*(?P<min>[\d.]+)/(?P<avg>[\d.]+)/(?P<max>[\d.]+)/(?P<mdev>[\d.]+)\s*ms"
)


def parse_ping(output: str) -> dict:
    stats: dict = {}
    match = PING_STATS.search(output)
    if match:
        stats.update({k: v for k, v in match.groupdict().items() if v is not None})
    rtt = RTT_STATS.search(output)
    if rtt:
        stats.update({f"rtt_{k}": v for k, v in rtt.groupdict().items()})
    return stats


_HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
_RTT_RE = re.compile(r"([\d.]+)\s*ms")


def parse_traceroute(output: str) -> list[dict]:
    """Turn traceroute/tracepath text into ordered hops with IP and best RTT."""
    hops: list[dict] = []
    for line in output.splitlines():
        m = _HOP_RE.match(line)
        if not m:
            continue
        number = int(m.group(1))
        rest = m.group(2)
        ip_match = _IP_RE.search(rest)
        ip = ip_match.group(1) if ip_match else None
        rtts = [float(x) for x in _RTT_RE.findall(rest)]
        hops.append({
            "hop": number,
            "ip": ip,
            "rtt_ms": min(rtts) if rtts else None,
            "timeout": ip is None and "*" in rest,
        })
    return hops


def hop_ips(output: str) -> list[str]:
    """Ordered hop IPs for path-change snapshots ('*' for a timeout hop)."""
    return [h["ip"] or "*" for h in parse_traceroute(output)]


def tools_status() -> list[tuple[str, bool]]:
    return [
        ("ping", have("ping")),
        ("traceroute", have("traceroute")),
        ("tracepath", have("tracepath")),
        ("mtr", have("mtr")),
        ("dig", have("dig")),
        ("whois", have("whois")),
        ("openssl", have("openssl")),
    ]
