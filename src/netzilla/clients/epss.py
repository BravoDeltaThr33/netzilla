"""EPSS — FIRST's Exploit Prediction Scoring System.

Endpoint: GET https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2,…
Auth:     none — free and public

CVSS says how bad a vulnerability would be if exploited; EPSS estimates how
likely it is to be exploited in the next 30 days, from observed attack
activity. Together with CISA KEV ("already exploited") it is how a team
decides what to patch first. One request scores up to 100 CVEs, so netzilla
asks for a whole result table at once.
"""

from __future__ import annotations

from ..services import ApiResult, Services

URL = "https://api.first.org/data/v1/epss"
TTL_EPSS = 12 * 3600          # FIRST recomputes the scores once a day
BATCH = 100


async def scores(services: Services, cve_ids: list[str]) -> ApiResult:
    """{CVE: {"epss": float, "percentile": float, "date": str}} for the ids."""
    ids = sorted({str(c).strip().upper() for c in cve_ids
                  if str(c).strip().upper().startswith("CVE-")})
    if not ids:
        return ApiResult.success("epss", {})
    found: dict[str, dict] = {}
    cached = True
    for start in range(0, len(ids), BATCH):
        chunk = ids[start:start + BATCH]
        result = await services.fetch(
            source="epss",
            url=URL,
            params={"cve": ",".join(chunk)},
            cache_key="epss:" + ",".join(chunk),
            ttl=TTL_EPSS,
            timeout=15.0,
        )
        if not result.ok:
            return result
        cached = cached and result.cached
        for entry in (result.data or {}).get("data") or []:
            if not isinstance(entry, dict) or not entry.get("cve"):
                continue
            try:
                found[str(entry["cve"]).upper()] = {
                    "epss": float(entry.get("epss") or 0.0),
                    "percentile": float(entry.get("percentile") or 0.0),
                    "date": entry.get("date") or "",
                }
            except (TypeError, ValueError):
                continue
    return ApiResult.success("epss", found, cached=cached)


def label(entry: dict | None) -> str:
    """'97.4% (top 1%)' — the probability, and where it ranks."""
    if not entry:
        return "—"
    probability = entry.get("epss", 0.0) * 100
    rank = (1.0 - entry.get("percentile", 0.0)) * 100
    top = "top 1%" if rank <= 1 else f"top {rank:.0f}%" if rank < 50 else "lower half"
    digits = 1 if probability >= 1 else 2
    text = f"{probability:.{digits}f}%"
    if probability < 100 and text.startswith("100"):
        text = ">99.9%"           # 0.99999 is not a certainty: never show 100%
    return f"{text} ({top})"


def state(entry: dict | None) -> str:
    """ok / warn / bad for colouring an EPSS score."""
    if not entry:
        return "info"
    value = entry.get("epss", 0.0)
    return "bad" if value >= 0.5 else "warn" if value >= 0.05 else "ok"
