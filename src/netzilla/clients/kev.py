"""CISA Known Exploited Vulnerabilities (KEV) catalog.

Endpoint: GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Auth:     none

The KEV catalog is CISA's authoritative list of CVEs with confirmed
in-the-wild exploitation. Cross-referencing an NVD CVE against it turns "this
scores high" into "this is being exploited right now, patch it first". The
whole catalog is one JSON document (~1-2 MB), so netzilla fetches it once and
caches it, then does membership checks locally.
"""

from __future__ import annotations

from ..cache import TTL
from ..services import ApiResult, Services

URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


async def catalog(services: Services) -> ApiResult:
    result = await services.fetch(
        source="kev",
        url=URL,
        headers={"Accept": "application/json"},
        cache_key="kev:catalog",
        ttl=TTL["cve"],
        timeout=30.0,
    )
    if not result.ok:
        return result
    payload = result.data or {}
    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list):
        return ApiResult.failure("kev", "CISA KEV feed had an unexpected shape.")
    return ApiResult.success(
        "kev",
        {
            "count": payload.get("count", len(vulns)),
            "catalogVersion": payload.get("catalogVersion"),
            "dateReleased": payload.get("dateReleased"),
            "vulnerabilities": vulns,
        },
        cached=result.cached,
    )


def _index(vulns: list) -> dict[str, dict]:
    return {
        str(v.get("cveID", "")).upper(): v
        for v in vulns if isinstance(v, dict) and v.get("cveID")
    }


async def check(services: Services, cve_id: str) -> ApiResult:
    """Is one CVE in the KEV catalog? Returns the KEV entry when it is."""
    cat = await catalog(services)
    if not cat.ok:
        return cat
    entry = _index(cat.data["vulnerabilities"]).get(cve_id.strip().upper())
    return ApiResult.success(
        "kev",
        {"cve": cve_id.strip().upper(), "listed": entry is not None, "entry": entry},
        cached=cat.cached,
    )


async def annotate(services: Services, cve_ids: list[str]) -> dict[str, dict]:
    """Map each CVE id to its KEV entry (or None). One catalog fetch for all."""
    cat = await catalog(services)
    if not cat.ok:
        return {}
    index = _index(cat.data["vulnerabilities"])
    return {cid.upper(): index.get(cid.upper()) for cid in cve_ids}


def verdict(payload: dict) -> tuple[str, str]:
    if not payload.get("listed"):
        return (
            "NOT IN KEV — no confirmed in-the-wild exploitation recorded by CISA",
            "ok",
        )
    entry = payload.get("entry") or {}
    due = entry.get("dueDate")
    ransom = entry.get("knownRansomwareCampaignUse", "").lower() == "known"
    tail = " · used in ransomware" if ransom else ""
    return (
        f"ACTIVELY EXPLOITED — in CISA KEV (federal patch due {due or 'n/a'}){tail}",
        "bad",
    )


def entry_summary(entry: dict) -> list[tuple[str, object]]:
    return [
        ("CVE", entry.get("cveID")),
        ("Name", entry.get("vulnerabilityName")),
        ("Vendor / product", f'{entry.get("vendorProject", "?")} / {entry.get("product", "?")}'),
        ("Added to KEV", entry.get("dateAdded")),
        ("Patch due", entry.get("dueDate")),
        ("Ransomware use", entry.get("knownRansomwareCampaignUse")),
        ("Required action", entry.get("requiredAction")),
    ]
