"""VirusTotal API v3 — multi-engine reputation for IPs, domains, URLs, files.

Endpoints used (from VirusTotal's v3 reference):
    GET  /api/v3/ip_addresses/{ip}     IP address report
    GET  /api/v3/domains/{domain}      domain report
    GET  /api/v3/urls/{id}             URL report; id = unpadded base64url(URL)
    POST /api/v3/urls                  submit a URL (form field `url`) -> analysis id
    GET  /api/v3/analyses/{id}         poll a submitted analysis
    GET  /api/v3/files/{hash}          file report by MD5, SHA-1 or SHA-256
Auth:  'x-apikey' header
Free (public API) limits: 4 requests/minute, 500/day. Public-API data is not
for commercial use.

netzilla deliberately never uploads files: a file report by hash answers "is
this known-bad?" without sending the file anywhere.
"""

from __future__ import annotations

import asyncio
import base64
import re

from ..cache import TTL
from ..services import ApiResult, MissingCredential, Services

BASE = "https://www.virustotal.com/api/v3"
HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")


def _url_id(url: str) -> str:
    """VirusTotal identifies a URL by its unpadded base64url encoding."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def is_hash(value: str) -> bool:
    return bool(HASH_RE.match((value or "").strip()))


def hash_kind(value: str) -> str:
    return {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(value.strip()), "hash")


def _headers(services: Services) -> dict:
    key = services.require_credential("virustotal_api_key")
    return {"x-apikey": key, "Accept": "application/json"}


async def _get(
    services: Services, path: str, cache_key: str, ok_statuses=(200,)
) -> ApiResult:
    try:
        headers = _headers(services)
    except MissingCredential as exc:
        return ApiResult.failure("virustotal", str(exc))

    result = await services.fetch(
        source="virustotal",
        url=f"{BASE}/{path}",
        headers=headers,
        cache_key=cache_key,
        ttl=TTL["reputation"],
        ok_statuses=ok_statuses,
    )
    if not result.ok:
        return result
    attributes = ((result.data or {}).get("data") or {}).get("attributes")
    if not isinstance(attributes, dict):
        return ApiResult.failure("virustotal", "VirusTotal returned no attributes.")
    return ApiResult.success("virustotal", attributes, cached=result.cached)


async def check_ip(services: Services, ip: str) -> ApiResult:
    return await _get(services, f"ip_addresses/{ip}", f"vt:ip:{ip}")


async def check_domain(services: Services, domain: str) -> ApiResult:
    return await _get(services, f"domains/{domain}", f"vt:domain:{domain}")


async def check_url(services: Services, url: str) -> ApiResult:
    """URL report. A 404 means VirusTotal has never seen the URL."""
    result = await _get(services, f"urls/{_url_id(url)}", f"vt:url:{_url_id(url)}")
    if not result.ok and result.status_code == 404:
        result.meta["unknown"] = True
        result.error = (
            "VirusTotal has no report for this URL yet. Use SUBMIT TO VT to "
            "have it scanned (costs 2+ of your 4 requests/minute)."
        )
    return result


async def check_file(services: Services, file_hash: str) -> ApiResult:
    file_hash = file_hash.strip().lower()
    result = await _get(services, f"files/{file_hash}", f"vt:file:{file_hash}")
    if not result.ok and result.status_code == 404:
        result.meta["unknown"] = True
        result.error = (
            f"No file with this {hash_kind(file_hash)} has ever been submitted "
            "to VirusTotal. Unknown is not the same as clean."
        )
    return result


async def submit_url(
    services: Services,
    url: str,
    *,
    polls: int = 6,
    poll_seconds: float = 16.0,
    progress=None,
) -> ApiResult:
    """Submit a URL for scanning and wait (politely) for the analysis.

    The poll interval respects the free tier's 4 requests/minute.
    """
    try:
        headers = _headers(services)
    except MissingCredential as exc:
        return ApiResult.failure("virustotal", str(exc))

    submitted = await services.fetch(
        source="virustotal",
        url=f"{BASE}/urls",
        method="POST",
        form={"url": url},
        headers=headers,
    )
    if not submitted.ok:
        return submitted
    analysis_id = ((submitted.data or {}).get("data") or {}).get("id")
    if not analysis_id:
        return ApiResult.failure("virustotal", "VirusTotal did not return an analysis id.")

    for attempt in range(polls):
        if progress is not None:
            progress(f"VirusTotal is scanning — check {attempt + 1}/{polls}…")
        await asyncio.sleep(poll_seconds)
        polled = await services.fetch(
            source="virustotal",
            url=f"{BASE}/analyses/{analysis_id}",
            headers=headers,
        )
        if not polled.ok:
            return polled
        attributes = ((polled.data or {}).get("data") or {}).get("attributes") or {}
        if attributes.get("status") == "completed":
            # Drop any stale "not found" answer so the next lookup is fresh.
            services.store.delete(f"vt:url:{_url_id(url)}")
            return ApiResult.success(
                "virustotal",
                {"last_analysis_stats": attributes.get("stats") or {},
                 "analysis_id": analysis_id, "status": "completed"},
            )

    return ApiResult.failure(
        "virustotal",
        f"Submitted (analysis {analysis_id}) but the scan was still running "
        "when netzilla stopped waiting. Run VIRUSTOTAL URL again in a minute.",
    )


# ------------------------------------------------------------- rendering
def stats(attributes: dict) -> dict:
    raw = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    return {k: int(v or 0) for k, v in raw.items() if isinstance(v, (int, float))}


def verdict(attributes: dict) -> tuple[str, str]:
    counts = stats(attributes)
    malicious = counts.get("malicious", 0)
    suspicious = counts.get("suspicious", 0)
    harmless = counts.get("harmless", 0)
    total = sum(counts.values())
    if malicious:
        return f"FLAGGED by {malicious}/{total} engines", "bad"
    if suspicious:
        return f"SUSPICIOUS to {suspicious}/{total} engines", "warn"
    if total:
        return f"CLEAN — {harmless}/{total} engines report harmless", "ok"
    return "No analysis data available", "info"


def summarise(attributes: dict) -> list[tuple[str, object]]:
    counts = stats(attributes)
    rows: list[tuple[str, object]] = [
        ("Malicious", counts.get("malicious", 0)),
        ("Suspicious", counts.get("suspicious", 0)),
        ("Harmless", counts.get("harmless", 0)),
        ("Undetected", counts.get("undetected", 0)),
        ("Reputation", attributes.get("reputation")),
    ]
    if attributes.get("as_owner"):
        rows.append(("AS owner", attributes.get("as_owner")))
    if attributes.get("network"):
        rows.append(("Network", attributes.get("network")))
    if attributes.get("registrar"):
        rows.append(("Registrar", attributes.get("registrar")))
    categories = attributes.get("categories")
    if isinstance(categories, dict) and categories:
        joined = ", ".join(sorted({str(v) for v in categories.values()}))
        rows.append(("Categories", joined))
    return rows


def flagging_engines(attributes: dict, limit: int = 12) -> list[list[object]]:
    """Which engines said malicious/suspicious, and what they called it."""
    results = attributes.get("last_analysis_results") or {}
    rows = []
    for engine, detail in sorted(results.items()):
        if not isinstance(detail, dict):
            continue
        if detail.get("category") in ("malicious", "suspicious"):
            rows.append([engine, detail.get("category"), detail.get("result") or "—"])
        if len(rows) >= limit:
            break
    return rows


def file_summary(attributes: dict) -> list[tuple[str, object]]:
    threat = (attributes.get("popular_threat_classification") or {}).get(
        "suggested_threat_label"
    )
    names = attributes.get("names") or []
    size = attributes.get("size")
    return [
        ("Name", attributes.get("meaningful_name") or (names[0] if names else None)),
        ("Type", attributes.get("type_description")),
        ("Size", f"{int(size):,} bytes" if isinstance(size, (int, float)) else None),
        ("Suggested threat label", threat),
        ("SHA-256", attributes.get("sha256")),
        ("SHA-1", attributes.get("sha1")),
        ("MD5", attributes.get("md5")),
        ("First submitted", _epoch(attributes.get("first_submission_date"))),
        ("Last analysed", _epoch(attributes.get("last_analysis_date"))),
        ("Times submitted", attributes.get("times_submitted")),
        ("Other names", ", ".join(names[1:6]) if len(names) > 1 else None),
    ]


def _epoch(value) -> str | None:
    if not isinstance(value, (int, float)):
        return None
    from datetime import datetime, timezone

    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
