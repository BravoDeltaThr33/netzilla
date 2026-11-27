"""SNMP quick-poll via the net-snmp command-line tools.

Answers "how busy is this port right now?" — the one thing the SPEED tab can't,
because SPEED measures this machine's internet path, not a device interface.

netzilla shells out to net-snmp (`snmpget`, `snmpbulkwalk`) rather than pulling
in a heavy pure-Python SNMP stack, matching how it already wraps dig/whois. Two
counter polls a few seconds apart give live throughput and error rate.

    sysDescr.0    1.3.6.1.2.1.1.1.0
    sysUpTime.0   1.3.6.1.2.1.1.3.0
    ifDescr       1.3.6.1.2.1.2.2.1.2
    ifHCInOctets  1.3.6.1.2.1.31.1.1.1.6   (64-bit)
    ifHCOutOctets 1.3.6.1.2.1.31.1.1.1.10
    ifInErrors    1.3.6.1.2.1.2.2.1.14
    ifOutErrors   1.3.6.1.2.1.2.2.1.20

Install with: sudo apt install snmp. macOS ships the tools; Net-SNMP has
no current Windows release.
"""

from __future__ import annotations

import asyncio
import re

from .runner import CommandResult, have, run

OID = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6",
    "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
    "ifInErrors": "1.3.6.1.2.1.2.2.1.14",
    "ifOutErrors": "1.3.6.1.2.1.2.2.1.20",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
}

COUNTER_MAX_64 = 2 ** 64


def available() -> bool:
    return have("snmpget") and have("snmpbulkwalk")


def _auth_args(community: str, version: str) -> list[str]:
    if version == "2c":
        return ["-v", "2c", "-c", community]
    if version == "1":
        return ["-v", "1", "-c", community]
    return ["-v", "2c", "-c", community]


async def _get(host: str, community: str, version: str, oid: str) -> CommandResult:
    return await run(
        ["snmpget", "-On", "-Oqv", *_auth_args(community, version), host, oid],
        timeout=15.0,
    )


async def _walk(host: str, community: str, version: str, oid: str) -> dict[str, str]:
    result = await run(
        ["snmpbulkwalk", "-On", *_auth_args(community, version), host, oid],
        timeout=25.0,
    )
    return parse_walk(result.output, oid) if result.ok else {}


def parse_walk(output: str, base_oid: str) -> dict[str, str]:
    """{ifIndex: value} from numeric snmpwalk output under base_oid."""
    table: dict[str, str] = {}
    prefix = "." + base_oid if not base_oid.startswith(".") else base_oid
    for line in output.splitlines():
        if "=" not in line:
            continue
        raw_oid, _, value = line.partition("=")
        raw_oid = raw_oid.strip()
        if not raw_oid.startswith(prefix):
            continue
        index = raw_oid[len(prefix):].lstrip(".")
        value = value.strip()
        value = re.sub(r"^\w+:\s*", "", value).strip().strip('"')
        table[index] = value
    return table


async def system_info(host: str, community: str, version: str = "2c") -> dict:
    descr = await _get(host, community, version, OID["sysDescr"])
    name = await _get(host, community, version, OID["sysName"])
    uptime = await _get(host, community, version, OID["sysUpTime"])
    return {
        "sysDescr": _clean(descr.output) if descr.ok else None,
        "sysName": _clean(name.output) if name.ok else None,
        "sysUpTime": _clean(uptime.output) if uptime.ok else None,
        "ok": descr.ok,
        "error": None if descr.ok else (descr.error or descr.output).strip(),
    }


def _clean(value: str) -> str:
    return value.strip().strip('"')


async def interfaces(host: str, community: str, version: str = "2c") -> dict[str, dict]:
    descr = await _walk(host, community, version, OID["ifDescr"])
    oper = await _walk(host, community, version, OID["ifOperStatus"])
    return {
        idx: {"name": name, "oper": _oper(oper.get(idx))}
        for idx, name in descr.items()
    }


def _oper(value) -> str:
    return {"1": "up", "2": "down", "3": "testing"}.get(str(value), str(value or "?"))


async def counters(host: str, community: str, version: str = "2c") -> dict[str, dict]:
    """Per-interface octet and error counters, one bulk walk each."""
    inoct = await _walk(host, community, version, OID["ifHCInOctets"])
    outoct = await _walk(host, community, version, OID["ifHCOutOctets"])
    inerr = await _walk(host, community, version, OID["ifInErrors"])
    outerr = await _walk(host, community, version, OID["ifOutErrors"])
    out: dict[str, dict] = {}
    for idx in set(inoct) | set(outoct):
        out[idx] = {
            "in_octets": _int(inoct.get(idx)),
            "out_octets": _int(outoct.get(idx)),
            "in_errors": _int(inerr.get(idx)),
            "out_errors": _int(outerr.get(idx)),
        }
    return out


def _int(value):
    try:
        return int(re.sub(r"[^\d]", "", str(value)))
    except (TypeError, ValueError):
        return None


def _delta(later, earlier) -> int:
    """Counter difference, correcting a single 64-bit wrap."""
    if later is None or earlier is None:
        return 0
    diff = later - earlier
    if diff < 0:
        diff += COUNTER_MAX_64
    return diff


def rate_table(
    first: dict[str, dict], second: dict[str, dict],
    seconds: float, names: dict[str, dict] | None = None,
) -> list[dict]:
    """Bit-rates and error deltas per interface between two counter samples."""
    names = names or {}
    seconds = max(seconds, 0.001)
    rows = []
    for idx, later in second.items():
        earlier = first.get(idx)
        if not earlier:
            continue
        in_bits = _delta(later["in_octets"], earlier["in_octets"]) * 8
        out_bits = _delta(later["out_octets"], earlier["out_octets"]) * 8
        rows.append({
            "index": idx,
            "name": names.get(idx, {}).get("name", idx),
            "oper": names.get(idx, {}).get("oper", "?"),
            "in_mbps": in_bits / seconds / 1_000_000,
            "out_mbps": out_bits / seconds / 1_000_000,
            "in_err_delta": _delta(later["in_errors"], earlier["in_errors"]),
            "out_err_delta": _delta(later["out_errors"], earlier["out_errors"]),
        })
    rows.sort(key=lambda r: r["in_mbps"] + r["out_mbps"], reverse=True)
    return rows


async def poll_rates(
    host: str, community: str, version: str = "2c", interval: float = 5.0, progress=None
) -> list[dict]:
    """Two counter polls `interval` apart -> live per-interface rates."""
    if progress:
        progress("First counter sample…")
    first = await counters(host, community, version)
    names = await interfaces(host, community, version)
    if progress:
        progress(f"Waiting {interval:.0f}s for the second sample…")
    await asyncio.sleep(interval)
    if progress:
        progress("Second counter sample…")
    second = await counters(host, community, version)
    return rate_table(first, second, interval, names)


def rate_rows(rates: list[dict], limit: int = 30) -> list[list[object]]:
    out = []
    for r in rates[:limit]:
        errs = r["in_err_delta"] + r["out_err_delta"]
        out.append([
            r["name"],
            r["oper"],
            f'{r["in_mbps"]:.2f}',
            f'{r["out_mbps"]:.2f}',
            str(errs) if errs else "0",
        ])
    return out


def uptime_pretty(ticks: str | None) -> str:
    """sysUpTime is in hundredths of a second (TimeTicks)."""
    if not ticks:
        return "—"
    match = re.search(r"(\d+)", str(ticks))
    if not match:
        return str(ticks)
    total = int(match.group(1)) // 100
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{days}d {hours}h {minutes}m {secs}s"
