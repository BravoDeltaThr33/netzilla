"""OutageDeck — normalised live status for 180 cloud and SaaS vendors.

Documented at https://outagedeck.com/developers/api (OpenAPI 3.1 at
/api/v1/openapi). Every response is wrapped in an envelope:

    {"meta": {"version": "v1", "generatedAt": "..."}, "data": {...}}

Endpoints used:
    GET /api/v1/providers/{slug}      data = provider object
    GET /api/v1/providers?q=&sort=    data = {"count", "providers": [...]}
    GET /api/v1/incidents?state=active&limit=100
                                      data = {"count", "page", "totalPages",
                                              "totalIncidents", "incidents": [...]}
Provider object (fields netzilla reads):
    slug, name,
    currentStatus {code, label, headline, summary, capturedAt}
      code ∈ operational | degraded | partial_outage | major_outage |
             maintenance | unknown
    source {checkedAt, stale, statusPageUrl}
    counts {services, activeIncidents, incidents}
    services [{slug, name, category, status}]
    activeIncidents [{slug, title, status, severity}]
Incident object:
    slug, title, summary, status, severity (minor|major|critical|maintenance),
    startedAt, updatedAt, resolvedAt, provider {slug, name}, affectedServices

Auth: none — anonymous access is free (120 requests/hour per IP). OutageDeck
only issues API keys with its paid plans, so netzilla never sends one.
Errors: 404 not_found (unknown slug), 429 rate_limited.
"""

from __future__ import annotations

import asyncio
import re

from ..cache import TTL
from ..services import ApiResult, Services

BASE = "https://outagedeck.com/api/v1"

STATE = {
    "operational": "ok",
    "resolved": "ok",
    "degraded": "warn",
    "partial_outage": "warn",
    "maintenance": "warn",
    "minor": "warn",
    "major_outage": "bad",
    "major": "bad",
    "critical": "bad",
    "unknown": "info",
}

# Common names people type that are not OutageDeck slugs.
ALIASES = {
    "gcp": "google-cloud",
    "google": "google-cloud",
    "googlecloud": "google-cloud",
    "gworkspace": "google-workspace",
    "workspace": "google-workspace",
    "gmail": "google-workspace",
    "amazon": "aws",
    "amazon-web-services": "aws",
    "microsoft": "azure",
    "ms-azure": "azure",
    "gh": "github",
    "cf": "cloudflare",
}


def resolve_slug(slug: str) -> str:
    slug = slug.strip().lower()
    return ALIASES.get(slug, slug)


def _headers(services: Services) -> dict:
    return {"Accept": "application/json"}


def unwrap(payload):
    """Strip the {"meta", "data"} envelope; tolerate an already-bare body."""
    if isinstance(payload, dict) and "data" in payload and (
        "meta" in payload or len(payload) == 1
    ):
        return payload["data"]
    return payload


async def provider(services: Services, slug: str) -> ApiResult:
    slug = resolve_slug(slug)
    result = await services.fetch(
        source="outagedeck",
        url=f"{BASE}/providers/{slug}",
        headers=_headers(services),
        cache_key=f"outagedeck:v2:{slug}",
        ttl=TTL["status"],
    )
    if not result.ok:
        if result.status_code == 404:
            hint = await suggest(services, slug)
            msg = f"'{slug}' is not an OutageDeck provider slug."
            if hint:
                msg += " Did you mean: " + ", ".join(hint) + "?"
            return ApiResult.failure("outagedeck", msg, status_code=404)
        return result
    data = unwrap(result.data)
    if not isinstance(data, dict) or not (data.get("slug") or data.get("name")):
        return ApiResult.failure("outagedeck", "Unexpected response shape.")
    return ApiResult.success("outagedeck", data, cached=result.cached)


async def search(services: Services, query: str) -> ApiResult:
    result = await services.fetch(
        source="outagedeck",
        url=f"{BASE}/providers",
        params={"q": query, "sort": "name"},
        headers=_headers(services),
        cache_key=f"outagedeck:v2:search:{query}",
        ttl=TTL["status"],
    )
    if not result.ok:
        return result
    data = unwrap(result.data)
    providers = data.get("providers") if isinstance(data, dict) else data
    return ApiResult.success(
        "outagedeck", list(providers or []), cached=result.cached
    )


async def suggest(services: Services, slug: str, limit: int = 5) -> list[str]:
    """Up to `limit` real slugs matching what the user typed."""
    term = slug.replace("-", " ").split()[0] if slug else ""
    if not term:
        return []
    found = await search(services, term)
    if not found.ok:
        return []
    return [p.get("slug") for p in found.data if isinstance(p, dict) and p.get("slug")][:limit]


async def check_many(services: Services, slugs: list[str]) -> list[ApiResult]:
    """Check a whole stack concurrently."""
    return list(
        await asyncio.gather(*(provider(services, slug) for slug in slugs))
    )


async def active_incidents(services: Services, limit: int = 100) -> ApiResult:
    result = await services.fetch(
        source="outagedeck",
        url=f"{BASE}/incidents",
        params={"state": "active", "limit": str(limit)},
        headers=_headers(services),
        cache_key=f"outagedeck:v2:incidents:{limit}",
        ttl=TTL["status"],
    )
    if not result.ok:
        return result
    data = unwrap(result.data)
    if isinstance(data, list):
        incidents, total = data, len(data)
    elif isinstance(data, dict):
        incidents = data.get("incidents") or []
        total = data.get("totalIncidents") or data.get("count") or len(incidents)
    else:
        return ApiResult.failure("outagedeck", "Unexpected response shape.")
    incidents = [i for i in incidents if isinstance(i, dict)]
    return ApiResult.success(
        "outagedeck",
        {"incidents": incidents, "total": total},
        cached=result.cached,
    )


# --------------------------------------------------------------- rendering
def _name(value) -> str:
    if isinstance(value, dict):
        return str(value.get("name") or value.get("slug") or "—")
    return str(value or "—")


_ALARMING = re.compile(r"outage|degrad|disrupt|incident|maintenance|issue|down", re.I)


def normalise(data: dict) -> dict:
    """Flatten the pieces netzilla displays from a provider object."""
    status = data.get("currentStatus") or data.get("status") or {}
    if isinstance(status, dict):
        code = status.get("code") or "unknown"
        label = status.get("label") or code.replace("_", " ")
        headline = status.get("headline") or status.get("summary") or ""
        captured = status.get("capturedAt") or ""
    else:
        code = label = str(status or "unknown")
        headline = captured = ""
    if code == "operational" and _ALARMING.search(headline):
        # The vendor's page banner can say "Partial System Outage" while no
        # incident is open and no tracked service is affected; OutageDeck
        # then reports operational. Say so, rather than contradict the status.
        headline = f"{headline} (vendor page only — no incident open)"
    source = data.get("source") or {}
    counts = data.get("counts") or {}
    active = [
        i for i in (data.get("activeIncidents") or []) if isinstance(i, dict)
    ]
    degraded_services = [
        s.get("name") or s.get("slug")
        for s in (data.get("services") or [])
        if isinstance(s, dict) and (s.get("status") or "operational") != "operational"
    ]
    return {
        "name": data.get("name") or data.get("slug"),
        "slug": data.get("slug"),
        "status_key": code,
        "status_label": label,
        "headline": headline,
        "updated": (source.get("checkedAt") or captured or "")[:16].replace("T", " "),
        "stale": bool(source.get("stale")),
        "url": source.get("statusPageUrl") or source.get("officialUrl") or "",
        "active_count": counts.get("activeIncidents", len(active)),
        "active_titles": [i.get("title") for i in active if i.get("title")],
        "degraded_services": [s for s in degraded_services if s],
    }


def incident_rows(incidents: list[dict], limit: int = 40) -> list[list[object]]:
    rows = []
    for entry in list(incidents)[:limit]:
        rows.append([
            _name(entry.get("provider")),
            str(entry.get("severity") or "—").upper(),
            str(entry.get("status") or "—"),
            entry.get("title") or "—",
            (entry.get("startedAt") or "—")[:16].replace("T", " "),
        ])
    return rows


def state_of(status_key: str) -> str:
    return STATE.get(str(status_key).lower().replace("-", "_"), "info")
