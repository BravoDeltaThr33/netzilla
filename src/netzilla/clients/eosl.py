"""EOSL.ai — hardware end-of-sale and end-of-service-life dates.

Endpoints: GET https://eosl.ai/cell/{part}.txt        (one-line part status)
           GET https://eosl.ai/api/v1/families.json   (index of all families)
           GET https://eosl.ai/api/v1/family/{slug}.json
Auth:      none — free, and the data is CC BY 4.0. (EOSL.ai's optional
           attribution key gates nothing, so netzilla does not ask for one.)

Every date carries the URL of the vendor bulletin it came from, which is the
reason this source survived the trim: the answer is verifiable.
"""

from __future__ import annotations

from ..cache import TTL
from ..services import ApiResult, Services

BASE = "https://eosl.ai"


def _headers(services: Services) -> dict:
    return {"Accept": "application/json"}


async def part_status(services: Services, part: str) -> ApiResult:
    """Quick one-line status for an exact part number."""
    slug = part.strip().lower()
    result = await services.fetch(
        source="eosl",
        url=f"{BASE}/cell/{slug}.txt",
        headers={"Accept": "text/plain", **_headers(services)},
        expect="text",
        cache_key=f"eosl:cell:{slug}",
        ttl=TTL["eosl"],
        ok_statuses=(200, 404),
    )
    if not result.ok:
        return result
    text = (result.data or "").strip()
    if not text or "<" in text[:1]:
        return ApiResult.failure(
            "eosl", f"'{part}' is not in the EOSL.ai database."
        )
    return ApiResult.success("eosl", text, cached=result.cached)


async def families(services: Services) -> ApiResult:
    """The full family index — cached for a week, then searched locally."""
    result = await services.fetch(
        source="eosl",
        url=f"{BASE}/api/v1/families.json",
        headers=_headers(services),
        cache_key="eosl:families",
        ttl=TTL["eosl"],
    )
    if not result.ok:
        return result
    payload = result.data
    items = payload if isinstance(payload, list) else (payload or {}).get("families", [])
    return ApiResult.success("eosl", items or [], cached=result.cached)


async def family(services: Services, slug: str) -> ApiResult:
    return await services.fetch(
        source="eosl",
        url=f"{BASE}/api/v1/family/{slug}.json",
        headers=_headers(services),
        cache_key=f"eosl:family:{slug}",
        ttl=TTL["eosl"],
    )


def search_families(items: list, term: str, limit: int = 25) -> list[dict]:
    """Local substring search over the cached family index."""
    needle = term.lower()
    hits = []
    for item in items:
        if not isinstance(item, dict):
            continue
        haystack = " ".join(
            str(item.get(field, ""))
            for field in ("slug", "vendor", "series", "line", "category", "name")
        ).lower()
        if needle in haystack:
            hits.append(item)
        if len(hits) >= limit:
            break
    return hits


def family_rows(items: list[dict]) -> list[list[object]]:
    rows = []
    for item in items:
        status = item.get("status")
        if isinstance(status, dict):
            status = status.get("label") or status.get("key")
        rows.append([
            item.get("vendor", "—"),
            item.get("series") or item.get("line") or "—",
            item.get("category", "—"),
            status or "—",
            item.get("eosl") or item.get("endOfServiceLife") or "—",
            item.get("slug", "—"),
        ])
    return rows


def sku_group_rows(detail: dict) -> list[list[object]]:
    rows = []
    for group in detail.get("skuGroups") or []:
        rows.append([
            group.get("label", "—"),
            group.get("endOfSale") or "—",
            group.get("endOfServiceLife") or "—",
            "computed" if group.get("eoslComputed") else "published",
            group.get("replacement") or "—",
            len(group.get("skus") or []),
        ])
    return rows
