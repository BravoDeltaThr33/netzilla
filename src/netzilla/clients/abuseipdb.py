"""AbuseIPDB — community abuse reports for an address or a small network.

Endpoints (APIv2, from AbuseIPDB's own documentation):
    GET https://api.abuseipdb.com/api/v2/check        ipAddress, maxAgeInDays, verbose
    GET https://api.abuseipdb.com/api/v2/check-block  network (CIDR), maxAgeInDays
Auth:  'Key' header (the docs recommend the header over ?key=, because query
       strings end up in server logs). Always send 'Accept: application/json',
       otherwise errors come back as an HTML page.

Free (Standard) daily limits:
    check        1,000/day
    check-block    100/day, network up to /24, maxAgeInDays up to 30
Exceeding a check-block plan limit returns 402 Payment Required.

Errors come back as {"errors": [{"detail": "...", "status": 4xx}]}; the
shared fetch layer lifts `detail` into the message. Every response carries
X-RateLimit-Limit / X-RateLimit-Remaining, which the DASH quota panel shows.
"""

from __future__ import annotations

import ipaddress

from ..cache import TTL
from ..services import ApiResult, MissingCredential, Services

BASE = "https://api.abuseipdb.com/api/v2"

# Free-plan ceilings for check-block.
FREE_BLOCK_MIN_PREFIX_V4 = 24
FREE_BLOCK_MAX_AGE_DAYS = 30

# AbuseIPDB report category IDs -> names.
CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}


def _headers(services: Services) -> dict:
    key = services.require_credential("abuseipdb_api_key")
    return {"Key": key, "Accept": "application/json"}


async def check(services: Services, ip: str, max_age_days: int = 90) -> ApiResult:
    try:
        headers = _headers(services)
    except MissingCredential as exc:
        return ApiResult.failure("abuseipdb", str(exc))

    result = await services.fetch(
        source="abuseipdb",
        url=f"{BASE}/check",
        # Bare `verbose` flag: adds the reports array and countryName.
        params={"ipAddress": ip, "maxAgeInDays": str(max_age_days), "verbose": ""},
        headers=headers,
        cache_key=f"abuseipdb:{ip}:{max_age_days}",
        ttl=TTL["reputation"],
    )
    if not result.ok:
        return result
    data = (result.data or {}).get("data")
    if not isinstance(data, dict):
        return ApiResult.failure("abuseipdb", "AbuseIPDB returned no data block.")
    return ApiResult.success("abuseipdb", data, cached=result.cached)


def block_blocker(network: str) -> str | None:
    """Why the free plan would refuse this network, or None if it is fine."""
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return f"'{network}' is not a valid network."
    if net.version == 4 and net.prefixlen < FREE_BLOCK_MIN_PREFIX_V4:
        return (
            f"The free AbuseIPDB plan checks networks up to /24; {net} is a "
            f"/{net.prefixlen}. Split it on the SUBNET tab and check each /24."
        )
    return None


async def check_block(
    services: Services, network: str, max_age_days: int = FREE_BLOCK_MAX_AGE_DAYS
) -> ApiResult:
    """Every reported address inside a CIDR block (free plan: up to /24)."""
    blocker = block_blocker(network)
    if blocker:
        return ApiResult.failure("abuseipdb-block", blocker)
    try:
        headers = _headers(services)
    except MissingCredential as exc:
        return ApiResult.failure("abuseipdb-block", str(exc))

    net = str(ipaddress.ip_network(network, strict=False))
    max_age_days = max(1, min(int(max_age_days), FREE_BLOCK_MAX_AGE_DAYS))
    result = await services.fetch(
        source="abuseipdb-block",
        url=f"{BASE}/check-block",
        params={"network": net, "maxAgeInDays": str(max_age_days)},
        headers=headers,
        cache_key=f"abuseipdb-block:{net}:{max_age_days}",
        ttl=TTL["reputation"],
    )
    if not result.ok:
        return result
    data = (result.data or {}).get("data")
    if not isinstance(data, dict):
        return ApiResult.failure("abuseipdb-block", "AbuseIPDB returned no data block.")
    return ApiResult.success("abuseipdb-block", data, cached=result.cached)


# ------------------------------------------------------------- rendering
def verdict(data: dict) -> tuple[str, str]:
    """(verdict text, state) where state is ok / warn / bad.

    AbuseIPDB recommends 75-100% as the range for blocking, which is why the
    'bad' threshold sits well above the first report.
    """
    try:
        score = int(data.get("abuseConfidenceScore") or 0)
    except (TypeError, ValueError):
        score = 0
    reports = data.get("totalReports") or 0
    if score >= 75:
        return f"MALICIOUS — {score}% confidence, {reports} reports", "bad"
    if score >= 25:
        return f"SUSPICIOUS — {score}% confidence, {reports} reports", "warn"
    if score > 0:
        return f"LOW RISK — {score}% confidence, {reports} reports", "warn"
    if reports:
        # A 0% score with reports on file: whitelisted (big public resolvers,
        # CDNs) or every report has aged out of the confidence window.
        why = "whitelisted by AbuseIPDB" if data.get("isWhitelisted") else \
            "reports too old or too few to count"
        return f"CLEAN — 0% confidence ({reports} reports on file, {why})", "ok"
    return "CLEAN — no abuse reports on file", "ok"


def summarise(data: dict) -> list[tuple[str, object]]:
    country = data.get("countryName") or ""
    code = data.get("countryCode") or ""
    return [
        ("Abuse score", f'{data.get("abuseConfidenceScore", 0)}%'),
        ("Total reports", data.get("totalReports")),
        ("Distinct reporters", data.get("numDistinctUsers")),
        ("Last reported", data.get("lastReportedAt")),
        ("Country", f"{country} [{code}]".strip() if country else code),
        ("ISP", data.get("isp")),
        ("Usage type", data.get("usageType")),
        ("Domain", data.get("domain")),
        ("Hostnames", data.get("hostnames") or []),
        ("Public address", data.get("isPublic")),
        ("Tor exit node", bool(data.get("isTor"))),
        # Per AbuseIPDB: whitelisting is benefit-of-the-doubt; do not act on it.
        ("Whitelisted", data.get("isWhitelisted")),
    ]


def category_names(ids) -> str:
    names = []
    for raw in ids or []:
        try:
            names.append(CATEGORIES.get(int(raw), f"#{raw}"))
        except (TypeError, ValueError):
            continue
    return ", ".join(names) or "—"


def category_counts(data: dict, top: int = 8) -> list[list[object]]:
    """Which kinds of abuse this address is reported for, most common first."""
    counts: dict[int, int] = {}
    for report in data.get("reports") or []:
        for raw in report.get("categories") or []:
            try:
                counts[int(raw)] = counts.get(int(raw), 0) + 1
            except (TypeError, ValueError):
                continue
    ordered = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return [[CATEGORIES.get(cid, f"#{cid}"), n] for cid, n in ordered[:top]]


def report_rows(data: dict, limit: int = 8) -> list[list[object]]:
    rows = []
    for report in (data.get("reports") or [])[:limit]:
        comment = " ".join(str(report.get("comment") or "").split())
        rows.append([
            (report.get("reportedAt") or "")[:16].replace("T", " "),
            report.get("reporterCountryCode") or "—",
            category_names(report.get("categories")),
            comment[:90] + ("…" if len(comment) > 90 else ""),
        ])
    return rows


def block_summary(data: dict) -> list[tuple[str, object]]:
    reported = data.get("reportedAddress") or []
    return [
        ("Network", f'{data.get("networkAddress")} / {data.get("netmask")}'),
        ("Host range", f'{data.get("minAddress")} – {data.get("maxAddress")}'),
        ("Possible hosts", data.get("numPossibleHosts")),
        ("Address space", data.get("addressSpaceDesc")),
        ("Reported addresses", len(reported)),
        ("Highest score", max(
            (int(r.get("abuseConfidenceScore") or 0) for r in reported), default=0
        )),
    ]


def block_rows(data: dict, limit: int = 60) -> list[list[object]]:
    reported = sorted(
        data.get("reportedAddress") or [],
        key=lambda r: (int(r.get("abuseConfidenceScore") or 0), int(r.get("numReports") or 0)),
        reverse=True,
    )
    return [
        [
            r.get("ipAddress", "—"),
            f'{r.get("abuseConfidenceScore", 0)}%',
            r.get("numReports", 0),
            (r.get("mostRecentReport") or "")[:10],
            r.get("countryCode") or "—",
        ]
        for r in reported[:limit]
    ]


def block_verdict(data: dict) -> tuple[str, str]:
    reported = data.get("reportedAddress") or []
    if not reported:
        return "CLEAN — no address in this block has been reported", "ok"
    worst = max(int(r.get("abuseConfidenceScore") or 0) for r in reported)
    text = f"{len(reported)} reported address(es), worst score {worst}%"
    if worst >= 75:
        return text, "bad"
    return text, "warn"
