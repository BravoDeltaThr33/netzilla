"""crt.sh — Certificate Transparency log search.

Endpoint: GET https://crt.sh/?q=<query>&output=json
Auth:     none

crt.sh indexes the public CT logs every publicly-trusted CA must submit to.
Searching '%.example.com' returns every certificate ever issued for the domain
and its subdomains — the de-facto free way to enumerate subdomains and to spot
certificates you did not order (mis-issuance / shadow IT).

The JSON endpoint is unofficial and occasionally slow or rate-limited, so
answers are cached and the client uses a generous timeout.
"""

from __future__ import annotations

from ..cache import TTL
from ..services import ApiResult, Services

BASE = "https://crt.sh"


async def search(services: Services, domain: str, include_subdomains: bool = True) -> ApiResult:
    domain = domain.strip().lower().strip(".")
    query = f"%.{domain}" if include_subdomains else domain
    result = await services.fetch(
        source="crtsh",
        url=f"{BASE}/",
        params={"q": query, "output": "json"},
        headers={"Accept": "application/json"},
        cache_key=f"crtsh:{query}",
        ttl=TTL["tls"],
        timeout=30.0,
        retries=1,
    )
    if not result.ok:
        return result
    data = result.data
    if not isinstance(data, list):
        return ApiResult.failure(
            "crtsh",
            "crt.sh did not return a JSON array (it sometimes rate-limits or "
            "times out — try again shortly).",
        )
    return ApiResult.success("crtsh", data, cached=result.cached)


# --------------------------------------------------------------- parsing
def _names(entry: dict) -> set[str]:
    names = set()
    for field in ("common_name", "name_value"):
        value = entry.get(field) or ""
        for line in str(value).splitlines():
            line = line.strip().lower().lstrip("*.").rstrip(".")
            if line:
                names.add(line)
    return names


def unique_names(data: list, base_domain: str = "") -> list[str]:
    names: set[str] = set()
    for entry in data:
        if isinstance(entry, dict):
            names |= _names(entry)
    if base_domain:
        base = base_domain.strip().lower().rstrip(".")
        names = {n for n in names if n == base or n.endswith("." + base)}
    return sorted(names)


def earliest_entry(data: list) -> dict | None:
    """The first-issued certificate — used by the first-seen timeline."""
    dated = [e for e in data if isinstance(e, dict) and e.get("not_before")]
    if not dated:
        return None
    return min(dated, key=lambda e: e.get("not_before"))


def earliest_date(data: list) -> str:
    entry = earliest_entry(data)
    return (entry.get("not_before") or "")[:10] if entry else ""


def summary(data: list, base_domain: str = "") -> dict:
    names = unique_names(data, base_domain)
    issuers = sorted({
        (e.get("issuer_name") or "").split("O=")[-1].split(",")[0].strip('" ')
        for e in data if isinstance(e, dict) and e.get("issuer_name")
    } - {""})
    return {
        "certificates": len(data),
        "unique_names": names,
        "issuers": issuers,
        "earliest": earliest_date(data),
    }


def recent_rows(data: list, limit: int = 25) -> list[list[object]]:
    dated = [e for e in data if isinstance(e, dict)]
    dated.sort(key=lambda e: e.get("not_before") or "", reverse=True)
    rows = []
    for entry in dated[:limit]:
        issuer = (entry.get("issuer_name") or "").split("O=")[-1].split(",")[0].strip('" ')
        primary = sorted(_names(entry))
        rows.append([
            (entry.get("not_before") or "")[:10],
            (entry.get("not_after") or "")[:10],
            issuer or "—",
            (primary[0] if primary else "—") + (f" +{len(primary) - 1}" if len(primary) > 1 else ""),
        ])
    return rows
