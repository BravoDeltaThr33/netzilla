"""Duplicate-IP / ARP-conflict watcher.

Watches which MAC address claims a given IP over a short window and flags the
moment two different MACs answer for the same address — the signature of a
duplicate-IP misconfiguration (or ARP spoofing). It turns an intermittent,
maddening symptom ("some packets to .10 vanish") into an instant answer.

Observation sources, best first:
  1. `arping` (net-tools/iputils) — actively solicits ARP replies; best signal.
  2. the kernel neighbour cache (`ip neigh`) — passive, always available.
The conflict logic itself is a pure function so it is unit-tested directly.
"""

from __future__ import annotations

import asyncio
import time

from .lan import arp_table
from .runner import have, run


def conflicts(observations: list[tuple[str, str]]) -> dict[str, list[str]]:
    """Given (ip, mac) sightings, return {ip: [macs]} for IPs with >1 MAC."""
    seen: dict[str, list[str]] = {}
    for ip, mac in observations:
        mac = (mac or "").lower()
        if not mac:
            continue
        macs = seen.setdefault(ip, [])
        if mac not in macs:
            macs.append(mac)
    return {ip: macs for ip, macs in seen.items() if len(macs) > 1}


async def _arping(ip: str, count: int, timeout: float) -> list[str]:
    """MACs that answer arping for `ip` (empty if arping is absent)."""
    if not have("arping"):
        return []
    result = await run(
        ["arping", "-c", str(count), "-w", str(int(timeout)), ip],
        timeout=timeout + 3, ok_returncodes=(0, 1, 2),
    )
    macs = []
    import re
    for m in re.finditer(r"\[([0-9a-fA-F:]{17})\]", result.output):
        mac = m.group(1).lower()
        if mac not in macs:
            macs.append(mac)
    return macs


async def watch(ip: str, seconds: float = 8.0, interval: float = 1.0) -> dict:
    """Poll for who claims `ip` over `seconds`; report any MAC conflict."""
    observations: list[tuple[str, str]] = []
    use_arping = have("arping")
    deadline = time.monotonic() + seconds
    rounds = 0
    while time.monotonic() < deadline:
        rounds += 1
        if use_arping:
            for mac in await _arping(ip, 1, interval):
                observations.append((ip, mac))
        table = await arp_table()
        if ip in table:
            observations.append((ip, table[ip]))
        await asyncio.sleep(interval)
    macs: list[str] = []
    for _, mac in observations:
        if mac not in macs:
            macs.append(mac)
    return {
        "ip": ip,
        "method": "arping + neighbour cache" if use_arping else "neighbour cache",
        "rounds": rounds,
        "macs": macs,
        "conflict": len(macs) > 1,
    }


def verdict(result: dict) -> tuple[str, str]:
    macs = result.get("macs") or []
    if not macs:
        return (
            f"NO REPLY — nothing answered for {result['ip']} "
            "(host down, or ARP not observed on this segment)",
            "warn",
        )
    if len(macs) == 1:
        return f"OK — {result['ip']} is claimed by exactly one MAC ({macs[0]})", "ok"
    return (
        f"DUPLICATE IP — {result['ip']} is claimed by {len(macs)} MACs: "
        + ", ".join(macs),
        "bad",
    )
