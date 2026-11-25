"""NVD — the US National Vulnerability Database (CVE lookups).

Endpoint: GET https://services.nvd.nist.gov/rest/json/cves/2.0
Auth:     optional 'apiKey' header
Limit:    5 requests / 30s without a key, 50 / 30s with one

NVD is slow by design and asks clients to pace themselves, so results are
cached for 12 hours.
"""

from __future__ import annotations

from ..cache import TTL
from ..services import ApiResult, Services

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _headers(services: Services) -> dict:
    headers = {"Accept": "application/json"}
    key = services.config.credential("nvd_api_key")
    if key:
        headers["apiKey"] = key
    return headers


async def _query(services: Services, params: dict, cache_key: str) -> ApiResult:
    result = await services.fetch(
        source="nvd",
        url=URL,
        params=params,
        headers=_headers(services),
        cache_key=cache_key,
        ttl=TTL["cve"],
    )
    if not result.ok:
        return result
    payload = result.data or {}
    vulns = payload.get("vulnerabilities")
    if vulns is None:
        return ApiResult.failure("nvd", "NVD returned no vulnerabilities block.")
    return ApiResult.success(
        "nvd",
        {"total": payload.get("totalResults", len(vulns)), "vulnerabilities": vulns},
        cached=result.cached,
    )


async def search_keyword(services: Services, keyword: str, limit: int = 20) -> ApiResult:
    return await _query(
        services,
        {"keywordSearch": keyword, "resultsPerPage": str(limit)},
        f"nvd:kw:{keyword}:{limit}",
    )


async def get_cve(services: Services, cve_id: str) -> ApiResult:
    return await _query(services, {"cveId": cve_id.upper()}, f"nvd:id:{cve_id.upper()}")


async def search_cpe(services: Services, cpe: str, limit: int = 20) -> ApiResult:
    return await _query(
        services,
        {"cpeName": cpe, "resultsPerPage": str(limit)},
        f"nvd:cpe:{cpe}:{limit}",
    )


def _severity(metrics: dict) -> tuple[str, str]:
    """Prefer CVSS v3.1, fall back to v3.0 then v2."""
    for version in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(version) or []
        if entries:
            data = entries[0].get("cvssData") or {}
            return (
                str(data.get("baseScore", "—")),
                str(data.get("baseSeverity", "—")).upper(),
            )
    entries = metrics.get("cvssMetricV2") or []
    if entries:
        data = entries[0].get("cvssData") or {}
        return (
            str(data.get("baseScore", "—")),
            str(entries[0].get("baseSeverity", "—")).upper(),
        )
    return "—", "—"


def cve_rows(payload: dict, limit: int = 20) -> list[list[object]]:
    rows = []
    for item in (payload.get("vulnerabilities") or [])[:limit]:
        cve = item.get("cve") or {}
        descriptions = cve.get("descriptions") or []
        english = next(
            (d.get("value") for d in descriptions if d.get("lang") == "en"), ""
        )
        score, severity = _severity(cve.get("metrics") or {})
        rows.append([
            cve.get("id", "—"),
            severity,
            score,
            (cve.get("published") or "")[:10],
            english[:110] + ("…" if len(english) > 110 else ""),
        ])
    return rows
