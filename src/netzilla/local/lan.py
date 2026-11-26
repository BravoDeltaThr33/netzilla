"""LAN discovery — ping sweep across a CIDR, enriched from the ARP cache.

This is the internal-network counterpart to the DISCOVERY tab (which only sees
public IPs via Shodan InternetDB). Everything here is local: it sends ICMP
echo through the system `ping` (no raw sockets, no root needed) and reads MACs
from the kernel neighbour table (`ip neigh`). A true ARP-request sweep needs
raw sockets; this ping+neighbour approach works unprivileged and finds every
host that answers ICMP or that the box has recently talked to.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re

from .runner import CommandResult, have, run

# Cap the sweep so a fat prefix can't spawn tens of thousands of pings.
MAX_HOSTS = 1024


def hosts_for(cidr: str) -> list[str]:
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    # Check the size before building the list: an IPv6 /64 or an IPv4 /8
    # would otherwise be materialised in full before being refused.
    if net.num_addresses - 2 > MAX_HOSTS:
        raise ValueError(
            f"{cidr} has {net.num_addresses - 2:,} hosts; netzilla sweeps at most "
            f"{MAX_HOSTS} at once. Narrow the prefix (e.g. a /22 or smaller)."
        )
    if net.version == 4 and net.prefixlen < 32:
        addrs = list(net.hosts())
    else:
        addrs = [net.network_address] if net.num_addresses == 1 else list(net.hosts())
    if len(addrs) > MAX_HOSTS:
        raise ValueError(
            f"{cidr} has {len(addrs):,} hosts; netzilla sweeps at most "
            f"{MAX_HOSTS} at once. Narrow the prefix (e.g. a /22 or smaller)."
        )
    return [str(a) for a in addrs]


NEIGH_RE = re.compile(
    r"^(?P<ip>\S+)\s+.*?lladdr\s+(?P<mac>[0-9a-fA-F:]{17})\s+(?P<state>\w+)",
)


def parse_neigh(output: str) -> dict[str, str]:
    """Map IP -> MAC from `ip neigh show` output (skips FAILED/INCOMPLETE)."""
    table: dict[str, str] = {}
    for line in output.splitlines():
        match = NEIGH_RE.match(line.strip())
        if not match:
            continue
        state = match.group("state").upper()
        if state in ("FAILED", "INCOMPLETE"):
            continue
        table[match.group("ip")] = match.group("mac").lower()
    return table


async def arp_table() -> dict[str, str]:
    if have("ip"):
        result = await run(["ip", "neigh", "show"], timeout=10.0)
        if result.ok:
            return parse_neigh(result.output)
    if have("arp"):
        result = await run(["arp", "-an"], timeout=10.0)
        if result.ok:
            return _parse_arp_a(result.output)
    return {}


ARP_A_RE = re.compile(r"\((?P<ip>[\d.]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]{17})")


def _parse_arp_a(output: str) -> dict[str, str]:
    return {
        m.group("ip"): m.group("mac").lower()
        for m in ARP_A_RE.finditer(output)
    }


_TTL_RE = re.compile(r"\bttl[=:]\s*(\d+)", re.I)


async def _ping_one(ip: str, timeout: float) -> tuple[str, float | None, int | None]:
    """(ip, rtt_ms, ttl) — rtt and ttl are None when the host does not answer.

    The reply's TTL is kept because on a LAN (no routers in between) it is
    the sender's starting value: 64 for Linux/Apple/Android, 128 for Windows,
    255 for most network gear. The device-identification columns use it.
    """
    result = await run(
        ["ping", "-c", "1", "-W", str(int(max(1, timeout))), ip],
        timeout=timeout + 2,
        ok_returncodes=(0, 1, 2),
    )
    if not result.ok and result.missing_tool:
        raise FileNotFoundError("ping")
    match = re.search(r"time[=<]\s*([\d.]+)\s*ms", result.output)
    if "1 received" in result.output or "1 packets received" in result.output or match:
        ttl = _TTL_RE.search(result.output)
        return (ip, float(match.group(1)) if match else 0.0,
                int(ttl.group(1)) if ttl else None)
    return ip, None, None


async def sweep(
    cidr: str, concurrency: int = 64, timeout: float = 1.0, progress=None
) -> dict:
    """Ping every host in `cidr`; return the live ones with RTT and MAC."""
    targets = hosts_for(cidr)
    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def probe(ip: str):
        nonlocal done
        async with sem:
            result = await _ping_one(ip, timeout)
        done += 1
        if progress and done % 32 == 0:
            progress(f"Pinged {done}/{len(targets)}…")
        return result

    results = await asyncio.gather(*(probe(ip) for ip in targets))
    macs = await arp_table()
    live = []
    for ip, rtt, ttl in results:
        if rtt is not None:
            live.append({"ip": ip, "rtt_ms": rtt, "mac": macs.get(ip), "ttl": ttl})
    live.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    return {
        "cidr": str(ipaddress.ip_network(cidr, strict=False)),
        "scanned": len(targets),
        "live": live,
        "arp_only": [
            {"ip": ip, "mac": mac}
            for ip, mac in sorted(macs.items(), key=lambda kv: kv[0])
            if ip not in {h["ip"] for h in live}
            and _in_network(ip, cidr)
        ],
    }


def _in_network(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def rows(result: dict) -> list[list[object]]:
    out = []
    for host in result["live"]:
        rtt = host["rtt_ms"]
        out.append([
            host["ip"],
            f"{rtt:.1f} ms" if rtt else "reply",
            host.get("mac") or "—",
        ])
    return out
