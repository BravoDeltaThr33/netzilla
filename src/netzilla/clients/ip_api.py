"""IP-API — geolocation, ISP, ASN and hosting/proxy flags.

Endpoint: GET http://ip-api.com/json/{query}
Auth:     none
Limit:    45 requests/minute per source IP

Note on scheme: the free IP-API tier is HTTP-only; HTTPS is a paid feature.
That is a deliberate, documented exception to netzilla's HTTPS-everywhere
default and is called out in the UI, because the data returned is public
geolocation rather than anything sensitive.
"""

from __future__ import annotations

from ..cache import TTL
from ..services import ApiResult, Services

BASE = "http://ip-api.com/json"

FIELDS = ",".join([
    "status", "message", "continent", "country", "countryCode", "region",
    "regionName", "city", "zip", "lat", "lon", "timezone", "offset",
    "currency", "isp", "org", "as", "asname", "reverse", "mobile", "proxy",
    "hosting", "query",
])


async def lookup(services: Services, ip: str = "") -> ApiResult:
    """Look up one IP. Pass an empty string for the caller's own public IP."""
    target = ip.strip()
    result = await services.fetch(
        source="ip-api",
        url=f"{BASE}/{target}" if target else BASE,
        params={"fields": FIELDS},
        cache_key=f"ip-api:{target or 'self'}",
        ttl=TTL["geolocation"] if target else 300,
    )
    if not result.ok:
        return result
    payload = result.data or {}
    if payload.get("status") != "success":
        return ApiResult.failure(
            "ip-api", payload.get("message") or "IP-API returned no data."
        )
    return ApiResult.success("ip-api", payload, cached=result.cached)


def summarise(payload: dict) -> list[tuple[str, object]]:
    return [
        ("IP", payload.get("query")),
        ("Reverse DNS", payload.get("reverse")),
        ("ASN", payload.get("as")),
        ("AS Name", payload.get("asname")),
        ("ISP", payload.get("isp")),
        ("Organisation", payload.get("org")),
        ("City", payload.get("city")),
        ("Region", f'{payload.get("regionName") or ""} ({payload.get("region") or ""})'.strip()),
        ("Country", f'{payload.get("country") or ""} [{payload.get("countryCode") or ""}]'),
        ("Postal", payload.get("zip")),
        ("Coordinates", f'{payload.get("lat")}, {payload.get("lon")}'),
        ("Timezone", payload.get("timezone")),
        ("Mobile network", bool(payload.get("mobile"))),
        ("Hosting / datacentre", bool(payload.get("hosting"))),
        ("Proxy flagged", bool(payload.get("proxy"))),
    ]
