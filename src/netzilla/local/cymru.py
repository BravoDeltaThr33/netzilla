"""Team Cymru IP-to-ASN mapping over plain DNS — the RIPEstat fallback.

Team Cymru publishes BGP origin data as DNS TXT records. It needs no key,
has no HTTP endpoint to time out, and answers through whatever resolver the
machine already uses, so it keeps the BGP/ASN tab useful when RIPEstat is
slow or down.

    8.8.8.8      -> TXT 8.8.8.8 reversed + .origin.asn.cymru.com
                    "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
    2001:db8::1  -> TXT nibble-reversed + .origin6.asn.cymru.com
    AS15169      -> TXT AS15169.asn.cymru.com
                    "15169 | US | arin | 2000-03-30 | GOOGLE, US"

Reference: https://www.team-cymru.com/ip-asn-mapping
"""

from __future__ import annotations

import ipaddress

from .dns_whois import dig_short


def origin_name(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _fields(txt_output: str) -> list[list[str]]:
    rows = []
    for line in txt_output.splitlines():
        line = line.strip().strip('"').strip()
        if "|" in line:
            rows.append([part.strip() for part in line.split("|")])
    return rows


def parse_origin(txt_output: str) -> dict | None:
    rows = _fields(txt_output)
    if not rows:
        return None
    # Several TXT rows can come back (one per covering prefix); the most
    # specific prefix is the one actually used for forwarding.
    def plen(row: list[str]) -> int:
        try:
            return ipaddress.ip_network(row[1], strict=False).prefixlen
        except (ValueError, IndexError):
            return -1
    best = max(rows, key=plen)
    asns = [int(a) for a in best[0].split() if a.isdigit()]
    return {
        "asns": asns,
        "prefix": best[1] if len(best) > 1 else None,
        "country": best[2] if len(best) > 2 else None,
        "registry": best[3] if len(best) > 3 else None,
        "allocated": best[4] if len(best) > 4 else None,
    }


def parse_asn(txt_output: str) -> dict | None:
    rows = _fields(txt_output)
    if not rows:
        return None
    row = rows[0]
    return {
        "asn": row[0],
        "country": row[1] if len(row) > 1 else None,
        "registry": row[2] if len(row) > 2 else None,
        "allocated": row[3] if len(row) > 3 else None,
        "holder": row[4] if len(row) > 4 else None,
    }


async def lookup_ip(ip: str) -> tuple[dict | None, str]:
    """(result, error). result is None when unrouted or dig failed."""
    res = await dig_short(origin_name(ip), "TXT", timeout=10.0)
    if not res.ok:
        return None, res.error or "dig failed"
    parsed = parse_origin(res.output)
    return parsed, "" if parsed else "no origin record (address not routed)"


async def lookup_asn(asn: int) -> tuple[dict | None, str]:
    res = await dig_short(f"AS{asn}.asn.cymru.com", "TXT", timeout=10.0)
    if not res.ok:
        return None, res.error or "dig failed"
    parsed = parse_asn(res.output)
    return parsed, "" if parsed else "no record for that AS"
