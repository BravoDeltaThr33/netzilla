"""endoflife.date — software lifecycle dates, open data.

Endpoints: GET https://endoflife.date/api/v1/products/            (index)
           GET https://endoflife.date/api/v1/products/{name}/     (releases)
Auth:      none. The project and its data are open source (MIT).

Covers ~500 products, including the ones a network team runs: Cisco IOS XE,
PAN-OS, FortiOS, RouterOS, OPNsense, BIND, OpenSSL, nginx, ESXi, Windows
Server, Ubuntu, Debian, RHEL… Hardware part numbers stay with EOSL.ai on the
same tab; this answers "is the *software* on it still supported?".
"""

from __future__ import annotations

import datetime as _dt
import re

from ..services import ApiResult, Services

BASE = "https://endoflife.date/api/v1"
TTL_INDEX = 7 * 24 * 3600
TTL_PRODUCT = 24 * 3600

_VERSION_RE = re.compile(r"^v?(\d+[\w.\-]*)$", re.IGNORECASE)


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (text or "").lower())


async def products(services: Services) -> ApiResult:
    result = await services.fetch(
        source="endoflife",
        url=f"{BASE}/products/",
        cache_key="endoflife:products",
        ttl=TTL_INDEX,
        timeout=20.0,
    )
    if not result.ok:
        return result
    items = (result.data or {}).get("result") or []
    return ApiResult.success(
        "endoflife", [i for i in items if isinstance(i, dict)], cached=result.cached
    )


async def product(services: Services, name: str) -> ApiResult:
    name = name.strip().lower()
    result = await services.fetch(
        source="endoflife",
        url=f"{BASE}/products/{name}/",
        cache_key=f"endoflife:product:{name}",
        ttl=TTL_PRODUCT,
        timeout=20.0,
        ok_statuses=(200,),
    )
    if not result.ok:
        if result.status_code == 404:
            return ApiResult.failure(
                "endoflife", f"endoflife.date has no product called '{name}'.",
                status_code=404,
            )
        return result
    data = (result.data or {}).get("result")
    if not isinstance(data, dict):
        return ApiResult.failure("endoflife", "Unexpected response shape.")
    return ApiResult.success("endoflife", data, cached=result.cached)


# ------------------------------------------------------------- matching
def split_query(text: str) -> tuple[str, str]:
    """'Cisco IOS XE 17.9.4' -> ('Cisco IOS XE', '17.9.4'); no version -> ''."""
    words = (text or "").strip().split()
    if len(words) > 1 and _VERSION_RE.match(words[-1]):
        return " ".join(words[:-1]), _VERSION_RE.match(words[-1]).group(1)
    return " ".join(words), ""


def is_exact(item: dict, query: str) -> bool:
    """Does the query name this product exactly (name, alias or label)?"""
    wanted = _norm(query)
    names = [item.get("name", ""), item.get("label", "")] + list(item.get("aliases") or [])
    return bool(wanted) and any(_norm(n) == wanted for n in names)


def find_products(items: list[dict], query: str, limit: int = 12) -> list[dict]:
    """Best matches first: exact name or alias, exact label, then every word
    of the query appearing in the name, label, aliases or tags."""
    wanted = _norm(query)
    if not wanted:
        return []
    exact, label_hits, partial = [], [], []
    words = [_norm(w) for w in query.split() if _norm(w)]
    for item in items:
        names = [item.get("name", "")] + list(item.get("aliases") or [])
        if any(_norm(n) == wanted for n in names):
            exact.append(item)
            continue
        if _norm(item.get("label", "")) == wanted:
            label_hits.append(item)
            continue
        haystack = " ".join(
            [item.get("name", ""), item.get("label", "")]
            + list(item.get("aliases") or []) + list(item.get("tags") or [])
        )
        flat = _norm(haystack)
        if words and all(w in flat for w in words):
            partial.append(item)
    partial.sort(key=lambda i: (len(i.get("name", "")), i.get("name", "")))
    return (exact + label_hits + partial)[:limit]


def match_release(releases: list[dict], version: str) -> dict | None:
    """The release cycle a version belongs to: the longest release name that
    is the version itself or a dotted prefix of it (17.9.4 -> 17.9)."""
    if not version:
        return None
    version = version.lower().lstrip("v")
    best, best_len = None, -1
    for release in releases:
        name = str(release.get("name", "")).lower()
        if not name:
            continue
        if version == name or version.startswith(name + ".") or \
                version.startswith(name + "-"):
            if len(name) > best_len:
                best, best_len = release, len(name)
    return best


# ------------------------------------------------------------- rendering
def _date(value) -> str:
    return str(value)[:10] if value else ""


def _days_until(value) -> int | None:
    try:
        when = _dt.date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None
    return (when - _dt.date.today()).days


def release_state(release: dict) -> tuple[str, str]:
    """(verdict text, ok|warn|bad) for one release cycle."""
    eol = release.get("eolFrom")
    eoas = release.get("eoasFrom")
    if release.get("isEol"):
        return (f"END OF LIFE since {_date(eol)}" if eol else "END OF LIFE"), "bad"
    days = _days_until(eol)
    if release.get("isEoas"):
        tail = f" · end of life in {days} days ({_date(eol)})" if days is not None else ""
        return "SECURITY FIXES ONLY — active support has ended" + tail, "warn"
    if days is not None and days <= 180:
        return f"SUPPORTED — but end of life in {days} days ({_date(eol)})", "warn"
    if eol:
        return f"SUPPORTED until {_date(eol)}", "ok"
    if eoas:
        return f"SUPPORTED — active support until {_date(eoas)}", "ok"
    return "SUPPORTED — no end date announced", "ok"


def status_word(release: dict) -> str:
    """One or two words for a table cell: the release's support state."""
    if release.get("isEol"):
        return "end of life"
    if release.get("isEoas"):
        return "security only"
    days = _days_until(release.get("eolFrom"))
    if days is not None and days <= 180:
        return "ending soon"
    return "supported"


def release_rows(release_list: list[dict], limit: int = 14,
                 mine: dict | None = None) -> list[list[object]]:
    """The newest `limit` cycles; the one asked about (`mine`) is marked, and
    added at the end if it is older than that."""
    shown = list(release_list[:limit])
    if mine is not None and not any(r is mine for r in shown):
        shown.append(mine)
    rows = []
    for release in shown:
        latest = release.get("latest") or {}
        name = release.get("label") or release.get("name") or "—"
        if mine is not None and release is mine:
            name = f"{name}  ◀ yours"
        rows.append([
            name,
            _date(release.get("releaseDate")) or "—",
            _date(release.get("eoasFrom")) or ("ended" if release.get("isEoas") else "—"),
            _date(release.get("eolFrom")) or ("ended" if release.get("isEol") else "—"),
            (latest.get("name") if isinstance(latest, dict) else latest) or "—",
            status_word(release),
        ])
    return rows


def product_summary(data: dict) -> list[tuple[str, object]]:
    links = data.get("links") or {}
    labels = data.get("labels") or {}
    releases = data.get("releases") or []
    maintained = [r for r in releases if r.get("isMaintained")]
    return [
        ("Product", data.get("label") or data.get("name")),
        ("Category", data.get("category")),
        ("Release cycles tracked", len(releases)),
        ("Still maintained", ", ".join(str(r.get("name")) for r in maintained[:8])
            or "none"),
        ("'Support' means", labels.get("eoas") or "active support"),
        ("'End of life' means", labels.get("eol") or "end of security fixes"),
        ("Vendor policy", links.get("releasePolicy")),
        ("Reference", links.get("html")),
    ]
