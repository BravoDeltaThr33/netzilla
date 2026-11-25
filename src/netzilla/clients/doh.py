"""DNS-over-HTTPS resolver-consistency check.

Queries the same name at several public DoH resolvers and compares the answers.
Disagreement between resolvers is a fast tell for DNS hijacking, split-horizon
misconfiguration, ISP NXDOMAIN redirection, or geo/DNS-based filtering.

Resolvers (all keyless JSON DoH, RFC 8484 'application/dns-json' style):
    Cloudflare  https://cloudflare-dns.com/dns-query
    Google      https://dns.google/resolve
    Quad9       https://dns.quad9.net:5053/dns-query

Cloudflare and Quad9 need an explicit 'accept: application/dns-json' header;
Google returns JSON from /resolve without it. All three take name= and type=.
"""

from __future__ import annotations

import asyncio

from ..cache import TTL
from ..services import ApiResult, Services

RESOLVERS = {
    "Cloudflare": "https://cloudflare-dns.com/dns-query",
    "Google": "https://dns.google/resolve",
    "Quad9": "https://dns.quad9.net:5053/dns-query",
}

# RFC 1035 numeric record types we let the user ask for.
RECORD_TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "TXT": 16, "NS": 2,
                "SOA": 6, "PTR": 12, "SRV": 33, "CAA": 257}


async def _query_one(
    services: Services, resolver: str, url: str, name: str, rtype: str
) -> tuple[str, ApiResult]:
    result = await services.fetch(
        source="doh",
        url=url,
        params={"name": name, "type": rtype},
        headers={"accept": "application/dns-json"},
        cache_key=f"doh:{resolver}:{name}:{rtype}",
        ttl=TTL["dns"],
        timeout=8.0,
    )
    return resolver, result


async def resolve(
    services: Services, name: str, rtype: str = "A", resolver: str = "Cloudflare"
) -> ApiResult:
    """One query at one public resolver, normalised: {"status", "answers"}.

    The fallback when the system has no `dig` — DNS/WHOIS and the one-shot
    `netzilla dns` use it so record lookups still work on a bare machine.
    """
    url = RESOLVERS.get(resolver) or RESOLVERS["Cloudflare"]
    _name, result = await _query_one(services, resolver, url, name, rtype.upper())
    if not result.ok:
        return result
    return ApiResult.success("doh", normalise_answer(result.data, rtype.upper()),
                             cached=result.cached)


async def resolve_many(
    services: Services, name: str, types: tuple[str, ...], resolver: str = "Cloudflare"
) -> dict[str, ApiResult]:
    """Several record types for one name, concurrently."""
    results = await asyncio.gather(
        *(resolve(services, name, rtype, resolver) for rtype in types)
    )
    return dict(zip(types, results))


async def ptr(services: Services, ip: str) -> ApiResult:
    """Reverse DNS over HTTPS: the PTR names for an address."""
    import ipaddress

    try:
        pointer = ipaddress.ip_address(ip.strip()).reverse_pointer
    except ValueError:
        return ApiResult.failure("doh", f"'{ip}' is not an IP address.")
    return await resolve(services, pointer, "PTR")


async def resolve_all(services: Services, name: str, rtype: str = "A") -> dict:
    """Query every resolver concurrently and normalise the answers."""
    rtype = rtype.upper()
    pairs = await asyncio.gather(
        *(_query_one(services, r, url, name, rtype) for r, url in RESOLVERS.items())
    )
    out: dict[str, dict] = {}
    for resolver, result in pairs:
        if not result.ok:
            out[resolver] = {"error": result.error or "unavailable", "answers": []}
            continue
        out[resolver] = normalise_answer(result.data, rtype)
    return {"name": name, "type": rtype, "resolvers": out}


def normalise_answer(payload: dict, rtype: str) -> dict:
    """Pull the answer records of the requested type into a sorted list."""
    if not isinstance(payload, dict):
        return {"error": "bad response", "answers": []}
    status = payload.get("Status")
    answers = []
    for entry in payload.get("Answer") or []:
        if not isinstance(entry, dict):
            continue
        data = str(entry.get("data", "")).strip()
        # Drop the root dot of a name ("dns.google." -> "dns.google"), but
        # keep a bare root: a null MX is "0 ." (RFC 7505), not "0".
        if data.endswith(".") and not data.endswith(" .") and data != ".":
            data = data[:-1]
        if data:
            answers.append(data)
    # NXDOMAIN (3) with no records is a meaningful, comparable answer.
    return {
        "status": status,
        "status_name": _rcode(status),
        "answers": sorted(set(answers), key=_answer_order),
    }


def _answer_order(answer: str):
    """Addresses in numeric order (.4 before .10); MX, SRV and CAA by their
    leading numbers ("5 mx" before "10 mx"); everything else A–Z."""
    import ipaddress

    try:
        address = ipaddress.ip_address(answer)
        return (0, (address.version, int(address)), answer)
    except ValueError:
        pass
    numbers = []
    for token in answer.split(" "):
        if not token.isdigit():
            break
        numbers.append(int(token))
    return (1 if numbers else 2, tuple(numbers), answer)


def _rcode(status) -> str:
    return {
        0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
        5: "REFUSED",
    }.get(status, str(status) if status is not None else "?")


def consensus(result: dict) -> tuple[bool, str]:
    """(all_agree, human_summary). Agreement = identical answer sets."""
    resolvers = result.get("resolvers") or {}
    answered = {
        r: tuple(info["answers"])
        for r, info in resolvers.items()
        if not info.get("error")
    }
    if not answered:
        return False, "No resolver returned an answer."
    distinct = set(answered.values())
    if len(distinct) == 1:
        return True, "All resolvers agree."
    return False, (
        f"{len(distinct)} different answer sets across "
        f"{len(answered)} resolvers — possible hijack, split-horizon or filtering."
    )


def rows(result: dict) -> list[list[object]]:
    out = []
    for resolver, info in (result.get("resolvers") or {}).items():
        if info.get("error"):
            out.append([resolver, "ERROR", info["error"]])
        else:
            answers = ", ".join(info["answers"]) or info.get("status_name", "—")
            out.append([resolver, info.get("status_name", "—"), answers])
    return out
