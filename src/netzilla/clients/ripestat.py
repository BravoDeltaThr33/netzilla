"""RIPEstat — BGP routing, prefix and AS data from RIPE NCC.

Endpoints: GET https://stat.ripe.net/data/{call}/data.json?resource=...
Auth:      none

RIPE asks API consumers to identify themselves with a `sourceapp`
parameter, which netzilla always sends.
"""

from __future__ import annotations

from ..cache import TTL
from ..services import ApiResult, Services

BASE = "https://stat.ripe.net/data"
SOURCEAPP = "netzilla"
RIPE_TIMEOUT = 20.0


async def _call(services: Services, call: str, resource: str, **extra) -> ApiResult:
    params = {"resource": resource, "sourceapp": SOURCEAPP}
    params.update({k: str(v) for k, v in extra.items()})
    cache_bits = ":".join(f"{k}={v}" for k, v in sorted(extra.items()))
    result = await services.fetch(
        source="ripestat",
        url=f"{BASE}/{call}/data.json",
        params=params,
        cache_key=f"ripe:{call}:{resource}:{cache_bits}",
        ttl=TTL["bgp"],
        # RIPEstat computes many answers on demand; 10-25s responses are
        # normal under load, so allow more than the global default and retry
        # once before giving up.
        timeout=max(RIPE_TIMEOUT, services.config.timeout_seconds),
        retries=1,
    )
    if not result.ok:
        if result.error and result.error.startswith("Timed out"):
            return ApiResult.failure(
                "ripestat",
                f"{result.error} RIPEstat is slow or overloaded right now "
                "(check https://stat.ripe.net).",
            )
        return result
    payload = result.data or {}
    if payload.get("status") not in (None, "ok"):
        messages = payload.get("messages") or []
        detail = messages[0][1] if messages and len(messages[0]) > 1 else "unknown error"
        return ApiResult.failure("ripestat", f"RIPEstat: {detail}")
    data = payload.get("data")
    if not isinstance(data, dict):
        return ApiResult.failure("ripestat", "RIPEstat returned no data block.")
    return ApiResult.success("ripestat", data, cached=result.cached)


async def network_info(services: Services, ip: str) -> ApiResult:
    """Which prefix and ASN currently originate this address."""
    return await _call(services, "network-info", ip)


async def as_overview(services: Services, asn: int) -> ApiResult:
    return await _call(services, "as-overview", f"AS{asn}")


async def routing_status(services: Services, resource: str) -> ApiResult:
    return await _call(services, "routing-status", resource)


async def announced_prefixes(services: Services, asn: int) -> ApiResult:
    return await _call(services, "announced-prefixes", f"AS{asn}")


async def as_neighbours(services: Services, asn: int) -> ApiResult:
    return await _call(services, "asn-neighbours", f"AS{asn}")


async def whois(services: Services, resource: str) -> ApiResult:
    return await _call(services, "whois", resource)


async def rpki(services: Services, asn: int, prefix: str) -> ApiResult:
    return await _call(services, "rpki-validation", f"AS{asn}", prefix=prefix)


def overview_rows(data: dict) -> list[tuple[str, object]]:
    block = data.get("block") or {}
    return [
        ("Holder", data.get("holder")),
        ("Announced", bool(data.get("announced"))),
        ("Resource", data.get("resource")),
        ("Block", block.get("resource")),
        ("Block description", block.get("desc")),
        ("Block name", block.get("name")),
        ("Registry type", data.get("type")),
    ]


def routing_rows(data: dict) -> list[tuple[str, object]]:
    origin = data.get("announced_space") or {}
    v4 = origin.get("v4") or {}
    v6 = origin.get("v6") or {}
    neighbours = data.get("observed_neighbours")
    return [
        ("Visibility", f'{(data.get("visibility") or {}).get("v4", {}).get("ris_peers_seeing", "?")} RIS peers (v4)'),
        ("IPv4 prefixes", v4.get("prefixes")),
        ("IPv4 addresses", v4.get("ips")),
        ("IPv6 prefixes", v6.get("prefixes")),
        ("Observed neighbours", neighbours),
        ("First seen", (data.get("first_seen") or {}).get("time")),
        ("Last seen", (data.get("last_seen") or {}).get("time")),
    ]
