"""GreyNoise Community API — is this IP mass-scanning noise, or a known
business service, or neither?

Endpoint: GET https://api.greynoise.io/v3/community/{ip}
Auth:     'key' header. Also answers without a key, at a lower limit.
Limits:   free account: 50 lookups per WEEK, shared with the web Visualizer
          unauthenticated: 10 lookups per day

Response (from GreyNoise's own documentation):
    200  {"ip", "noise": bool, "riot": bool, "classification",
          "name", "link", "last_seen", "message": "Success"}
    404  {"ip", "noise": false, "riot": false, "message": "IP not observed
          scanning the internet or contained in RIOT data set."}
         -> a real answer ("unknown to GreyNoise"), not an error
    400  not a valid routable IPv4 address  (IPv6 and private space are
         rejected, so netzilla checks locally and never spends a lookup)
    401  bad key      429  rate limit, with the plan's limit in "message"

  noise  seen scanning the internet in the last 90 days
  riot   belongs to a known business service (RIOT dataset: CDNs, DNS,
         SaaS, update servers) — i.e. traffic you can usually ignore

GreyNoise answers a different question from AbuseIPDB and VirusTotal: not
"is this IP bad" but "is this IP background noise". That is why all three
stay in netzilla.

Note from GreyNoise: accounts registered with free webmail addresses do not
get API-key access. If a key is rejected with 401, that is the usual cause.
"""

from __future__ import annotations

import ipaddress

from ..cache import TTL
from ..services import ApiResult, Services

BASE = "https://api.greynoise.io/v3/community"


def lookup_blocker(ip: str) -> str | None:
    """Why GreyNoise would reject this address, or None if it is queryable."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return f"'{ip}' is not an IP address."
    if addr.version != 4:
        return "GreyNoise Community only supports IPv4 addresses."
    if not addr.is_global:
        return (
            "GreyNoise only tracks public internet addresses; "
            f"{ip} is private, reserved or otherwise not routable."
        )
    return None


async def check(services: Services, ip: str) -> ApiResult:
    blocker = lookup_blocker(ip)
    if blocker:
        # Answered locally: no request, no quota spent.
        return ApiResult.success(
            "greynoise",
            {"ip": ip, "noise": False, "riot": False, "skipped": True,
             "message": blocker},
            note=blocker,
        )

    headers = {"Accept": "application/json"}
    key = services.config.credential("greynoise_api_key")
    if key:
        headers["key"] = key

    result = await services.fetch(
        source="greynoise",
        url=f"{BASE}/{ip}",
        headers=headers,
        cache_key=f"greynoise:{ip}",
        # Lookups are scarce (50/week), so hold answers longer than other
        # reputation data.
        ttl=TTL["reputation"] * 6,
        ok_statuses=(200, 404),
    )
    key_rejected = False
    if not result.ok and result.status_code == 401 and key:
        # The Community endpoint also answers anonymously, so a rejected key
        # degrades to a lower limit instead of a dead panel.
        key_rejected = True
        result = await services.fetch(
            source="greynoise",
            url=f"{BASE}/{ip}",
            headers={"Accept": "application/json"},
            cache_key=f"greynoise:{ip}",
            ttl=TTL["reputation"] * 6,
            ok_statuses=(200, 404),
        )
    if not result.ok:
        if key_rejected:
            result.error = (
                (result.error or "")
                + "\nThe GreyNoise key was rejected (401) and the anonymous "
                "fallback also failed. GreyNoise does not grant API-key access "
                "to accounts registered with free webmail addresses."
            )
        return result

    payload = result.data if isinstance(result.data, dict) else {}
    payload.setdefault("ip", ip)
    payload.setdefault("noise", False)
    payload.setdefault("riot", False)
    if key_rejected:
        note = (
            "Your GreyNoise key was rejected (401), so this answer came from "
            "an anonymous lookup (10 per day). GreyNoise does not grant "
            "API-key access to accounts registered with free webmail addresses."
        )
    elif not key:
        note = "Anonymous lookup (10 per day)."
    else:
        note = None
    return ApiResult.success(
        "greynoise", payload, cached=result.cached, note=note,
        meta={"key_rejected": key_rejected},
    )


def is_known(payload: dict) -> bool:
    return bool(payload.get("noise") or payload.get("riot"))


def verdict(payload: dict) -> tuple[str, str]:
    if payload.get("skipped"):
        return f"NOT QUERIED — {payload.get('message', '')}", "info"
    classification = (payload.get("classification") or "unknown").lower()
    name = payload.get("name") or "unknown actor"
    if payload.get("riot"):
        return f"KNOWN BUSINESS SERVICE — {name} (RIOT)", "ok"
    if payload.get("noise"):
        if classification == "benign":
            return f"BENIGN SCANNER — {name}", "ok"
        if classification == "malicious":
            return f"MALICIOUS SCANNER — {name}", "bad"
        return f"UNCLASSIFIED SCANNER — {name}", "warn"
    return (
        "NOT OBSERVED — not seen scanning the internet and not a known "
        "business service",
        "ok",
    )


def summarise(payload: dict) -> list[tuple[str, object]]:
    return [
        ("IP", payload.get("ip")),
        ("Internet scanner (noise)", bool(payload.get("noise"))),
        ("Business service (RIOT)", bool(payload.get("riot"))),
        ("Classification", payload.get("classification")),
        ("Owner / actor", payload.get("name")),
        ("Last seen", payload.get("last_seen")),
        ("GreyNoise message", payload.get("message")),
        ("Reference", payload.get("link")),
    ]
