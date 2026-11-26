"""IPLogs — VPN / proxy / Tor / datacentre detection, fully keyless.

Endpoint: POST https://iplogs.com/v1/check  (JSON body: {"ip": "..."})
Auth:     none, no signup
Limit:    fair use, no enforced rate limit published
"""

from __future__ import annotations

from ..cache import TTL
from ..services import ApiResult, Services

URL = "https://iplogs.com/v1/check"


async def check(services: Services, ip: str) -> ApiResult:
    result = await services.fetch(
        source="iplogs",
        url=URL,
        method="POST",
        json_body={"ip": ip},
        headers={"content-type": "application/json"},
        cache_key=f"iplogs:{ip}",
        ttl=TTL["reputation"],
    )
    if not result.ok:
        return result
    payload = result.data
    if not isinstance(payload, dict):
        return ApiResult.failure("iplogs", "IPLogs returned an unexpected shape.")
    return ApiResult.success("iplogs", payload, cached=result.cached)


def verdict(payload: dict) -> tuple[str, str]:
    raw = (payload.get("verdict") or "unknown").lower()
    try:
        confidence = float(payload.get("confidence") or 0) * 100
    except (TypeError, ValueError):
        confidence = 0.0
    mapping = {
        "clean": ("CLEAN — no anonymisation detected", "ok"),
        "suspicious": ("SUSPICIOUS — some anonymisation signals", "warn"),
        "vpn_likely": ("VPN LIKELY", "warn"),
        "vpn_detected": ("VPN / PROXY DETECTED", "bad"),
    }
    text, state = mapping.get(raw, (f"UNKNOWN ({raw})", "info"))
    if confidence:
        text = f"{text} — {confidence:.0f}% confidence"
    return text, state


def summarise(payload: dict) -> list[tuple[str, object]]:
    info = payload.get("ip_info") or {}
    try:
        score = float(payload.get("score") or 0)
    except (TypeError, ValueError):
        score = 0.0
    return [
        ("Verdict", payload.get("verdict")),
        ("Score", f"{score:.2f}"),
        ("Is VPN", bool(payload.get("is_vpn"))),
        ("Connection type", info.get("type")),
        ("VPN provider", info.get("vpn_provider")),
        ("Is proxy", bool(info.get("is_proxy"))),
        ("ASN / Org", f'{info.get("asn") or ""} {info.get("org") or ""}'.strip()),
    ]


def matched_signals(payload: dict, limit: int = 12) -> list[tuple[str, str]]:
    """Only the signals that actually fired, most useful first."""
    rows = []
    for signal in payload.get("signals") or []:
        if not isinstance(signal, dict) or not signal.get("matched"):
            continue
        rows.append((str(signal.get("type", "?")), str(signal.get("detail", ""))))
        if len(rows) >= limit:
            break
    return rows
