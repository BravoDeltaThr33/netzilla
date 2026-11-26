"""URLhaus (abuse.ch) — URLs and hosts known to distribute malware.

Live API:
    POST https://urlhaus-api.abuse.ch/v1/url/    form: url=
    POST https://urlhaus-api.abuse.ch/v1/host/   form: host=
    Auth: 'Auth-Key' header — free, from https://auth.abuse.ch/

abuse.ch calls this credential an Auth-Key rather than an API key; the
Settings tab labels it accordingly. The same key also covers MalwareBazaar
and ThreatFox if you extend netzilla later.

Offline fallback: when the API is unreachable, the key is missing, or
netzilla runs with --offline, answers come from the bundled URLhaus snapshot
(local/urlhaus_offline.py). Every answer says which source it came from, and
snapshot answers carry the snapshot's date so their age is never hidden.
"""

from __future__ import annotations

from ..cache import TTL
from ..local import urlhaus_offline
from ..services import ApiResult, Services

BASE = "https://urlhaus-api.abuse.ch/v1"


async def _post(services: Services, path: str, form: dict, cache_key: str) -> ApiResult:
    key = services.config.credential("abusech_auth_key")
    if not key:
        return ApiResult.failure(
            "urlhaus",
            "No abuse.ch Auth-Key configured. Add one on the SETTINGS tab "
            "(free at https://auth.abuse.ch/).",
        )

    result = await services.fetch(
        source="urlhaus",
        url=f"{BASE}/{path}/",
        method="POST",
        form=form,
        headers={"Auth-Key": key},
        cache_key=cache_key,
        ttl=TTL["reputation"],
    )
    if not result.ok:
        return result
    payload = result.data or {}
    status = payload.get("query_status")
    if status in ("no_results", "not_found"):
        return ApiResult.success(
            "urlhaus", {"query_status": status, "source": "live"},
            cached=result.cached, note="Not listed in URLhaus.",
        )
    if status != "ok":
        return ApiResult.failure("urlhaus", f"URLhaus: {status or 'unknown response'}")
    payload["source"] = "live"
    return ApiResult.success("urlhaus", payload, cached=result.cached)


# ----------------------------------------------------------- offline path
def _snapshot_note(reason: str) -> str:
    snap = urlhaus_offline.snapshot()
    when = snap.newest[:10] if snap.newest else "unknown date"
    return f"{reason} Answered from the offline URLhaus snapshot ({when}, {snap.count:,} URLs)."


def offline_host(host: str) -> dict:
    snap = urlhaus_offline.snapshot()
    hits = snap.lookup_host(host)
    if not hits:
        return {"query_status": "no_results", "source": "offline", "host": host}
    online = sum(1 for e in hits if e.url_status == "online")
    return {
        "query_status": "ok",
        "source": "offline",
        "host": host,
        "url_count": str(len(hits)),
        "urls_online": str(online),
        "firstseen": min((e.date_added for e in hits if e.date_added), default=""),
        "shared_platform": urlhaus_offline.is_shared_platform(host),
        "urls": [
            e.as_api_dict()
            for e in sorted(hits, key=lambda e: e.date_added, reverse=True)
        ],
    }


def offline_url(url: str) -> dict:
    snap = urlhaus_offline.snapshot()
    hits = snap.lookup_url(url)
    if not hits:
        return {"query_status": "no_results", "source": "offline", "url": url}
    newest = max(hits, key=lambda e: e.date_added)
    payload = newest.as_api_dict()
    payload.update({"query_status": "ok", "source": "offline"})
    return payload


async def _offline(lookup, target: str, reason: str) -> ApiResult:
    """Answer from the snapshot in a worker thread: the first lookup builds
    its indexes, which takes a moment the interface should not wait on."""
    import asyncio

    def answer() -> tuple[dict, str]:
        return lookup(target), _snapshot_note(reason)

    payload, note = await asyncio.to_thread(answer)
    return ApiResult.success("urlhaus", payload, note=note)


async def check_host(
    services: Services, host: str, allow_offline: bool = True
) -> ApiResult:
    host = host.strip().lower()
    if services.offline and allow_offline:
        return await _offline(offline_host, host, "Offline mode.")
    live = await _post(services, "host", {"host": host}, f"urlhaus:host:{host}")
    if live.ok and isinstance(live.data, dict):
        live.data["shared_platform"] = urlhaus_offline.is_shared_platform(host)
    if live.ok or not allow_offline:
        return live
    return await _offline(offline_host, host,
                          f"Live API unavailable ({_first_line(live.error)}).")


async def check_url(
    services: Services, url: str, allow_offline: bool = True
) -> ApiResult:
    if services.offline and allow_offline:
        return await _offline(offline_url, url, "Offline mode.")
    live = await _post(services, "url", {"url": url}, f"urlhaus:url:{url}")
    if live.ok or not allow_offline:
        return live
    return await _offline(offline_url, url,
                          f"Live API unavailable ({_first_line(live.error)}).")


def _first_line(text: str | None) -> str:
    return (text or "error").splitlines()[0][:80]


# ------------------------------------------------------------- rendering
def verdict(payload: dict) -> tuple[str, str]:
    if payload.get("query_status") != "ok":
        return "NOT LISTED — no malware URLs recorded for this target", "ok"
    count = payload.get("url_count")
    if count is None:
        threat = payload.get("threat") or "malware"
        status = payload.get("url_status") or "unknown"
        state = "bad" if status in ("online", "listed", "unknown") else "warn"
        return f"LISTED — {threat} ({status})", state
    try:
        count_int = int(count)
    except (TypeError, ValueError):
        count_int = 0
    if not count_int:
        return "NOT LISTED", "ok"
    if payload.get("shared_platform"):
        return (
            f"SHARED PLATFORM — {count_int} malware URL(s) hosted here, among "
            "millions of legitimate ones. Judge the exact URL, not the host.",
            "warn",
        )
    return f"LISTED — {count_int} malware URL(s) seen on this host", "bad"


def url_rows(payload: dict, limit: int = 15) -> list[list[object]]:
    rows = []
    entries = payload.get("urls")
    if entries is None and payload.get("url"):
        entries = [payload]
    for entry in (entries or [])[:limit]:
        rows.append([
            entry.get("url_status") or "—",
            entry.get("threat") or "—",
            ", ".join(entry.get("tags") or [])[:30] or "—",
            (entry.get("date_added") or "—")[:10],
            (entry.get("url") or "")[:80],
        ])
    return rows
