"""Qualys SSL Labs — deep TLS server analysis with an A+ to F grade.

Endpoint: GET https://api.ssllabs.com/api/v3/analyze
Auth:     none

SSL Labs runs a real scan, so an uncached assessment takes one to three
minutes. netzilla asks for a cached result first (fromCache=on) and only
polls when the scan is genuinely new. Their usage terms ask clients not to
hammer repeat scans, which is also why the local openssl quick-check exists
as the fast path on the same tab.
"""

from __future__ import annotations

import asyncio

from ..cache import TTL
from ..services import ApiResult, Services

URL = "https://api.ssllabs.com/api/v3/analyze"

GRADE_STATE = {
    "A+": "ok", "A": "ok", "A-": "ok",
    "B": "warn", "C": "warn", "D": "warn",
    "E": "bad", "F": "bad", "T": "bad", "M": "bad",
}


async def analyze(
    services: Services,
    host: str,
    *,
    max_polls: int = 20,
    poll_seconds: float = 12.0,
    progress=None,
) -> ApiResult:
    """Fetch (or run) an SSL Labs assessment.

    `progress` is an optional callable taking a status string, so the UI can
    show what the scan is doing while it waits.
    """
    cache_key = f"ssllabs:{host}"
    cached = services.store.get(cache_key)
    if cached is not None:
        return ApiResult.success("ssllabs", cached, cached=True)

    params = {
        "host": host,
        "fromCache": "on",
        "maxAge": "24",
        "all": "done",
    }

    for attempt in range(max_polls):
        result = await services.fetch(source="ssllabs", url=URL, params=params)
        if not result.ok:
            return result
        payload = result.data or {}
        status = payload.get("status")

        if status == "READY":
            services.store.set(cache_key, payload, TTL["tls"])
            return ApiResult.success("ssllabs", payload)
        if status == "ERROR":
            return ApiResult.failure(
                "ssllabs", payload.get("statusMessage") or "SSL Labs reported an error."
            )
        if progress is not None:
            detail = payload.get("statusMessage") or status or "starting"
            progress(f"SSL Labs scan in progress ({detail}) — poll {attempt + 1}")
        # After the first request the scan exists; keep polling the same host.
        params.pop("startNew", None)
        await asyncio.sleep(poll_seconds)

    return ApiResult.failure(
        "ssllabs",
        "SSL Labs scan did not finish in time. It is still running — "
        "try again in a minute and the cached result should be ready.",
    )


def endpoint_rows(payload: dict) -> list[list[object]]:
    rows = []
    for endpoint in payload.get("endpoints") or []:
        rows.append([
            endpoint.get("ipAddress"),
            endpoint.get("serverName") or "—",
            endpoint.get("grade") or endpoint.get("statusMessage") or "—",
            endpoint.get("gradeTrustIgnored") or "—",
            "yes" if endpoint.get("hasWarnings") else "no",
        ])
    return rows


def best_grade(payload: dict) -> tuple[str, str]:
    grades = [
        e.get("grade")
        for e in (payload.get("endpoints") or [])
        if e.get("grade")
    ]
    if not grades:
        return "NO GRADE — scan incomplete or endpoint unreachable", "info"
    worst = sorted(grades, key=lambda g: list(GRADE_STATE).index(g)
                   if g in GRADE_STATE else 99)[-1]
    return f"GRADE {worst}", GRADE_STATE.get(worst, "info")
