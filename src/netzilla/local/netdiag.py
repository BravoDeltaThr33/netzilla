"""ping / traceroute / mtr wrappers for the Diagnostics tab.

The tools differ by system: Windows has `ping -n` (and writes its own report
format), `tracert` and `pathping` (its mtr); macOS has BSD ping, whose -W is in
milliseconds where Linux's is in seconds, and `ping6` for IPv6. ping_argv()
and friends build the right command; parse_ping() reads all three formats.
"""

from __future__ import annotations

import ipaddress
import re

from .. import hostos
from .runner import CommandResult, have, run


def _is_v6(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.strip("[]")).version == 6
    except ValueError:
        return False


def ping_argv(host: str, count: int, wait_s: float = 2.0) -> list[str]:
    """`count` echoes to `host`, waiting up to `wait_s` for each reply."""
    if hostos.is_windows():
        return ["ping", "-n", str(count), "-w", str(int(wait_s * 1000)), host]
    if hostos.is_macos():
        tool = "ping6" if _is_v6(host) else "ping"
        if tool == "ping6":                      # ping6 has no -W
            return [tool, "-c", str(count), host]
        return [tool, "-c", str(count), "-W", str(int(wait_s * 1000)), host]
    return ["ping", "-c", str(count), "-W", str(int(max(1, wait_s))), host]


async def ping(host: str, count: int = 4, timeout: float = 30.0) -> CommandResult:
    return await run(
        ping_argv(host, count, 2.0),
        timeout=timeout,
        ok_returncodes=(0, 1),
    )


def traceroute_tool() -> str:
    """The traceroute this system has: tracert on Windows."""
    if hostos.is_windows():
        return "tracert"
    if have("traceroute") or not have("tracepath"):
        return "traceroute"
    return "tracepath"


async def traceroute(host: str, max_hops: int = 20, timeout: float = 90.0) -> CommandResult:
    if hostos.is_windows():
        # -d: no name lookups (tracert's are slow); -w is per reply, in ms.
        return await run(["tracert", "-d", "-h", str(max_hops), "-w", "2000", host],
                         timeout=timeout, ok_returncodes=(0, 1))
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


def mtr_tool() -> str:
    """mtr, or on Windows its built-in cousin pathping."""
    return "pathping" if hostos.is_windows() else "mtr"


async def mtr(host: str, cycles: int = 10, timeout: float = 90.0) -> CommandResult:
    if hostos.is_windows():
        # pathping traces the route, then sends `cycles` pings to every hop,
        # 100 ms apart, and reports loss per hop and per link — mtr's report.
        return await run(
            ["pathping", "-n", "-q", str(cycles), "-p", "100", "-w", "1000", "-h", "20", host],
            timeout=max(timeout, 150.0), ok_returncodes=(0, 1),
        )
    argv = ["mtr", "--report", "--report-cycles", str(cycles), "-n", host]
    if hostos.is_macos() and not hostos.is_admin() and have("mtr") and hostos.has_sudo():
        # Homebrew's mtr needs root; an unlocked sudo session (CAPTURE →
        # AUTHENTICATE) or passwordless sudo provides it without a prompt.
        if (await run(["sudo", "-n", "true"], timeout=5)).ok:
            argv = ["sudo", "-n", *argv]
    return await run(argv, timeout=timeout)


def mtr_needs_root(result: CommandResult) -> bool:
    """Did mtr fail for want of root (Homebrew's mtr on macOS)?"""
    if result.ok or not hostos.is_macos():
        return False
    blob = f"{result.output}\n{result.error}".lower()
    return "mtr-packet" in blob or "permission denied" in blob or "not permitted" in blob


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
    r"(?P<tx>\d+) packets transmitted,\s*(?P<rx>\d+) (?:packets )?received"
    r"(?:,\s*\+?(?P<errors>\d+) errors)?,\s*(?P<loss>[\d.]+)% packet loss"
)
RTT_STATS = re.compile(
    r"=\s*(?P<min>[\d.]+)/(?P<avg>[\d.]+)/(?P<max>[\d.]+)/(?P<mdev>[\d.]+)\s*ms"
)
# Windows, in any language: "Packets: Sent = 4, Received = 3, Lost = 1 (25% loss)"
# ("Pakete: Gesendet = 4, Empfangen = 3, Verloren = 1 (25% Verlust)", …).
WIN_PING_STATS = re.compile(
    r"=\s*(?P<tx>\d+),\s*[^=,\n]+=\s*(?P<rx>\d+),\s*[^=,\n]+=\s*(?P<lost>\d+)"
    r"\s*\([^)\d]*(?P<loss>\d+)\s*%"
)
# "Minimum = 11ms, Maximum = 13ms, Average = 12ms" (labels translated).
WIN_RTT_STATS = re.compile(
    r"=\s*(?P<min>\d+)\s*ms,\s*[^=,\n]+=\s*(?P<max>\d+)\s*ms,\s*[^=,\n]+=\s*(?P<avg>\d+)\s*ms"
)
# One reply line: "Reply from 1.1.1.1: bytes=32 time=12ms TTL=57" or, for
# IPv6, "Reply from 2606:4700::1111: time=12ms"; "time<1ms" for under 1 ms.
WIN_REPLY_RTT = re.compile(r"[=<]\s*(?P<ms>\d+)\s*ms(?:\s+TTL=\d+)?\s*$", re.I)


def windows_reply_times(output: str) -> list[float]:
    """Round-trip times of the replies in Windows ping output. Summary lines
    (which hold commas) are skipped, so only real replies count."""
    times = []
    for line in (output or "").splitlines():
        if "," in line:
            continue
        match = WIN_REPLY_RTT.search(line.strip())
        if match:
            times.append(float(match.group("ms")))
    return times


def parse_ping(output: str) -> dict:
    stats: dict = {}
    match = PING_STATS.search(output)
    if match:
        stats.update({k: v for k, v in match.groupdict().items() if v is not None})
    rtt = RTT_STATS.search(output)
    if rtt:
        stats.update({f"rtt_{k}": v for k, v in rtt.groupdict().items()})
    if stats:
        return stats
    win = WIN_PING_STATS.search(output or "")
    if win:
        stats.update(tx=win.group("tx"), rx=win.group("rx"), loss=win.group("loss"))
        times = WIN_RTT_STATS.search(output)
        if times:
            stats.update({f"rtt_{k}": times.group(k) for k in ("min", "avg", "max")})
            replies = windows_reply_times(output)
            if replies:
                mean = sum(replies) / len(replies)
                spread = (sum((t - mean) ** 2 for t in replies) / len(replies)) ** 0.5
                stats["rtt_mdev"] = f"{spread:.3f}"
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


def tool_names() -> tuple[str, ...]:
    """The tools TOOL CHECK lists on this system."""
    if hostos.is_windows():
        return ("ping", "tracert", "pathping", "dig", "whois", "openssl")
    if hostos.is_macos():
        return ("ping", "traceroute", "mtr", "dig", "whois", "openssl")
    return ("ping", "traceroute", "tracepath", "mtr", "dig", "whois", "openssl")


def tools_status() -> list[tuple[str, bool]]:
    return [(tool, have(tool)) for tool in tool_names()]
