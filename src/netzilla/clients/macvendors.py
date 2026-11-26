"""macvendors.com — OUI to vendor, keyless.

Endpoint: GET https://api.macvendors.com/{mac}
Auth:     none
Limit:    roughly 1 request/second; a 429 means slow down

This is the network fallback. netzilla checks its bundled offline IEEE OUI
table first, so most lookups never leave the machine.
"""

from __future__ import annotations

from ..cache import TTL
from ..services import ApiResult, Services

BASE = "https://api.macvendors.com"


async def lookup(services: Services, mac: str) -> ApiResult:
    result = await services.fetch(
        source="macvendors",
        url=f"{BASE}/{mac}",
        expect="text",
        cache_key=f"macvendors:{mac[:8]}",
        ttl=TTL["mac"],
        ok_statuses=(200, 404),
    )
    if not result.ok:
        return result
    text = (result.data or "").strip()
    if not text or text.startswith("{"):
        return ApiResult.failure(
            "macvendors", "No vendor registered for that OUI."
        )
    return ApiResult.success("macvendors", text, cached=result.cached)
