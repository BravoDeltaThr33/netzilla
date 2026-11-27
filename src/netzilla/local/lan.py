"""LAN discovery — ping sweep across a CIDR, enriched from the ARP cache.

This is the internal-network counterpart to the DISCOVERY tab (which only sees
public IPs via Shodan InternetDB). Everything here is local: it sends ICMP
echo through the system `ping` (no raw sockets, no root needed) and reads MACs
from the kernel neighbour table (`ip neigh` on Linux, `arp -an` on macOS,
`arp -a` on Windows). A true ARP-request sweep needs raw sockets; this
ping+neighbour approach works unprivileged and finds every host that answers
ICMP or that the box has recently talked to.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re

from .. import hostos
from .runner import have, run

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
    if hostos.is_windows():
        result = await run(["arp", "-a"], timeout=10.0)
        return parse_arp_windows(result.output) if result.ok else {}
    if have("ip") and not hostos.is_macos():
        result = await run(["ip", "neigh", "show"], timeout=10.0)
        if result.ok:
            return parse_neigh(result.output)
    if have("arp"):
        result = await run(["arp", "-an"], timeout=10.0)
        if result.ok:
            return _parse_arp_a(result.output)
    return {}


# Linux: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"; macOS leaves
# out leading zeros: "? (192.168.1.1) at 0:1b:2c:3:4:5 on en0 ifscope [ethernet]".
ARP_A_RE = re.compile(
    r"\((?P<ip>[\d.]+)\)\s+at\s+(?P<mac>[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\b"
)


def _parse_arp_a(output: str) -> dict[str, str]:
    table = {}
    for m in ARP_A_RE.finditer(output):
        mac = ":".join(part.zfill(2) for part in m.group("mac").split(":")).lower()
        if not _group_mac(mac):
            table[m.group("ip")] = mac
    return table


# Windows: "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic" (the
# headings and the type are translated; the two addresses never are).
ARP_WIN_RE = re.compile(
    r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<mac>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b",
    re.M,
)


def _group_mac(mac: str) -> bool:
    """Broadcast and multicast addresses (ff:ff:…, 01:00:5e:…): table
    entries for groups, not devices."""
    try:
        return bool(int(mac[:2], 16) & 1)
    except ValueError:
        return True


def parse_arp_windows(output: str) -> dict[str, str]:
    """IP -> MAC from Windows' `arp -a`, devices only."""
    table: dict[str, str] = {}
    for m in ARP_WIN_RE.finditer(output or ""):
        mac = m.group("mac").replace("-", ":").lower()
        if _group_mac(mac):
            continue
        table.setdefault(m.group("ip"), mac)
    return table


_TTL_RE = re.compile(r"\bttl[=:]\s*(\d+)", re.I)


async def _ping_one(ip: str, timeout: float) -> tuple[str, float | None, int | None]:
    """(ip, rtt_ms, ttl) — rtt and ttl are None when the host does not answer.

    The reply's TTL is kept because on a LAN (no routers in between) it is
    the sender's starting value: 64 for Linux/Apple/Android, 128 for Windows,
    255 for most network gear. The device-identification columns use it.
    """
    result = await run(
        sweep_ping_argv(ip, timeout),
        timeout=timeout + 2,
        ok_returncodes=(0, 1, 2),
    )
    if not result.ok and result.missing_tool:
        raise FileNotFoundError("ping")
    return (ip, *read_reply(result.output))


def sweep_ping_argv(ip: str, timeout: float) -> list[str]:
    """One echo to `ip`, giving up after `timeout` seconds."""
    if hostos.is_windows():
        return ["ping", "-n", "1", "-w", str(int(max(0.2, timeout) * 1000)), ip]
    if hostos.is_macos():
        return ["ping", "-c", "1", "-W", str(int(max(0.2, timeout) * 1000)), ip]
    return ["ping", "-c", "1", "-W", str(int(max(1, timeout))), ip]


# A Windows reply line in any language: "… time=2ms TTL=64", "… Zeit<1ms TTL=64".
_WIN_REPLY_RE = re.compile(r"[=<]\s*([\d.]+)\s*ms\s+TTL=(\d+)", re.I)


def read_reply(output: str) -> tuple[float | None, int | None]:
    """(rtt_ms, ttl) of the one echo's reply; (None, None) when there was none.

    Windows answers "Destination host unreachable" from this machine itself
    and still exits 0, so there only a real echo reply — which carries a TTL —
    counts."""
    output = output or ""
    if hostos.is_windows():
        reply = _WIN_REPLY_RE.search(output)
        if not reply:
            return None, None
        return float(reply.group(1)), int(reply.group(2))
    match = re.search(r"time[=<]\s*([\d.]+)\s*ms", output)
    if "1 received" in output or "1 packets received" in output or match:
        ttl = _TTL_RE.search(output)
        return (float(match.group(1)) if match else 0.0,
                int(ttl.group(1)) if ttl else None)
    return None, None


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
