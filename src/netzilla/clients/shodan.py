"""Shodan InternetDB — exposed-service discovery, free and keyless.

Endpoint: GET https://internetdb.shodan.io/{ip}
Auth:     none — no key, no account

Open ports, hostnames, CPEs, tags and known CVEs for a single IP, as Shodan
last observed them. Shodan's full host API and search need a paid
membership, so netzilla does not use them: the HOST PROFILE action on the
DISCOVERY tab builds the equivalent picture from free sources instead.
"""

from __future__ import annotations

from ..cache import TTL
from ..services import ApiResult, Services

INTERNETDB = "https://internetdb.shodan.io"


async def internetdb(services: Services, ip: str) -> ApiResult:
    result = await services.fetch(
        source="shodan-idb",
        url=f"{INTERNETDB}/{ip}",
        cache_key=f"shodan-idb:{ip}",
        ttl=TTL["internetdb"],
        ok_statuses=(200, 404),
    )
    if not result.ok:
        return result
    payload = result.data or {}
    if not payload or payload.get("detail"):
        return ApiResult.success(
            "shodan-idb",
            {"ip": ip, "ports": [], "vulns": [], "hostnames": [], "tags": [], "cpes": []},
            cached=result.cached,
            note="No records — Shodan has not observed open services on this IP.",
        )
    return ApiResult.success("shodan-idb", payload, cached=result.cached)


def summarise(payload: dict) -> list[tuple[str, object]]:
    ports = payload.get("ports") or []
    vulns = payload.get("vulns") or []
    return [
        ("IP", payload.get("ip")),
        ("Open ports", ", ".join(str(p) for p in sorted(ports)) if ports else None),
        ("Port count", len(ports)),
        ("Hostnames", payload.get("hostnames") or []),
        ("Tags", payload.get("tags") or []),
        ("Known CVEs", len(vulns)),
    ]
