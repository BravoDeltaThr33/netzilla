"""abuse.ch threat feeds beyond URLhaus, all keyed to the same Auth-Key.

ThreatFox     POST https://threatfox-api.abuse.ch/api/v1/   (Auth-Key)
    IOC -> malware family. {"query":"search_ioc","search_term":"<ioc>"}
MalwareBazaar POST https://mb-api.abuse.ch/api/v1/          (Auth-Key)
    hash -> sample metadata. form query=get_info&hash=<md5|sha1|sha256>
Feodo Tracker GET  https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json
    keyless list of active botnet C2 IPs — membership check.
SSLBL         GET  https://sslbl.abuse.ch/blacklist/sslblacklist.json
    keyless map of malicious TLS-certificate SHA1 fingerprints.

abuse.ch calls the credential an 'Auth-Key' (see config.py). ThreatFox and
MalwareBazaar require it; the two blocklist downloads do not.
"""

from __future__ import annotations

from ..cache import TTL
from ..services import ApiResult, Services

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
SSLBL_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.json"


def _auth(services: Services) -> str:
    return services.config.credential("abusech_auth_key")


# --------------------------------------------------------------- ThreatFox
async def threatfox(services: Services, ioc: str) -> ApiResult:
    key = _auth(services)
    if not key:
        return ApiResult.failure(
            "threatfox",
            "No abuse.ch Auth-Key configured. Add one on SETTINGS (free at "
            "https://auth.abuse.ch/).",
        )
    ioc = ioc.strip()
    result = await services.fetch(
        source="threatfox",
        url=THREATFOX_URL,
        method="POST",
        json_body={"query": "search_ioc", "search_term": ioc},
        headers={"Auth-Key": key},
        cache_key=f"threatfox:{ioc}",
        ttl=TTL["reputation"],
    )
    if not result.ok:
        return result
    payload = result.data or {}
    status = payload.get("query_status")
    if status == "no_result":
        return ApiResult.success(
            "threatfox", {"query_status": "no_result", "data": []},
            cached=result.cached, note="Not tracked by ThreatFox.",
        )
    if status != "ok":
        return ApiResult.failure("threatfox", f"ThreatFox: {status or 'unknown response'}")
    return ApiResult.success("threatfox", payload, cached=result.cached)


def threatfox_rows(payload: dict, limit: int = 20) -> list[list[object]]:
    rows = []
    for item in (payload.get("data") or [])[:limit]:
        if not isinstance(item, dict):
            continue
        rows.append([
            item.get("ioc", "—"),
            item.get("threat_type", "—"),
            item.get("malware_printable") or item.get("malware") or "—",
            str(item.get("confidence_level", "—")),
            (item.get("first_seen") or "—")[:10],
        ])
    return rows


def threatfox_verdict(payload: dict) -> tuple[str, str]:
    data = payload.get("data") or []
    if not data:
        return "NOT TRACKED — no ThreatFox IOC for this indicator", "ok"
    families = sorted({
        d.get("malware_printable") or d.get("malware")
        for d in data if isinstance(d, dict) and (d.get("malware_printable") or d.get("malware"))
    })
    fam = ", ".join(families) or "unknown family"
    return f"LISTED — {len(data)} IOC(s), malware: {fam}", "bad"


# ------------------------------------------------------------ MalwareBazaar
async def malwarebazaar(services: Services, file_hash: str) -> ApiResult:
    key = _auth(services)
    if not key:
        return ApiResult.failure(
            "malwarebazaar",
            "No abuse.ch Auth-Key configured. Add one on SETTINGS (free at "
            "https://auth.abuse.ch/).",
        )
    file_hash = file_hash.strip().lower()
    result = await services.fetch(
        source="malwarebazaar",
        url=MALWAREBAZAAR_URL,
        method="POST",
        form={"query": "get_info", "hash": file_hash},
        headers={"Auth-Key": key},
        cache_key=f"mb:{file_hash}",
        ttl=TTL["reputation"],
    )
    if not result.ok:
        return result
    payload = result.data or {}
    status = payload.get("query_status")
    if status == "hash_not_found":
        return ApiResult.success(
            "malwarebazaar", {"query_status": "hash_not_found", "data": []},
            cached=result.cached, note="Not in MalwareBazaar.",
        )
    if status != "ok":
        return ApiResult.failure(
            "malwarebazaar", f"MalwareBazaar: {status or 'unknown response'}"
        )
    return ApiResult.success("malwarebazaar", payload, cached=result.cached)


def malwarebazaar_summary(payload: dict) -> list[tuple[str, object]]:
    data = payload.get("data") or []
    if not data:
        return [("Result", "Not found in MalwareBazaar")]
    item = data[0]
    return [
        ("Signature", item.get("signature") or "unclassified"),
        ("File type", item.get("file_type")),
        ("File name", item.get("file_name")),
        ("File size", item.get("file_size")),
        ("First seen", item.get("first_seen")),
        ("Last seen", item.get("last_seen")),
        ("SHA-256", item.get("sha256_hash")),
        ("Reporter", item.get("reporter")),
        ("Tags", item.get("tags") or []),
        ("Delivery", item.get("delivery_method")),
    ]


def malwarebazaar_verdict(payload: dict) -> tuple[str, str]:
    data = payload.get("data") or []
    if not data:
        return "NOT KNOWN — no MalwareBazaar sample with this hash", "ok"
    sig = data[0].get("signature") or "unclassified malware"
    return f"KNOWN MALWARE — {sig}", "bad"


# --------------------------------------------------------------- Feodo
async def feodo_list(services: Services) -> ApiResult:
    result = await services.fetch(
        source="feodo",
        url=FEODO_URL,
        headers={"Accept": "application/json"},
        cache_key="feodo:recommended",
        ttl=TTL["reputation"],
    )
    if not result.ok:
        return result
    entries = result.data if isinstance(result.data, list) else []
    return ApiResult.success("feodo", entries, cached=result.cached)


async def feodo_check(services: Services, ip: str) -> ApiResult:
    listed = await feodo_list(services)
    if not listed.ok:
        return listed
    ip = ip.strip()
    match = next(
        (e for e in listed.data if isinstance(e, dict) and e.get("ip_address") == ip),
        None,
    )
    return ApiResult.success(
        "feodo",
        {"ip": ip, "listed": match is not None, "entry": match,
         "list_size": len(listed.data)},
        cached=listed.cached,
    )


def feodo_verdict(payload: dict) -> tuple[str, str]:
    if not payload.get("listed"):
        return "NOT LISTED — not an active Feodo/Dridex/Emotet C2", "ok"
    entry = payload.get("entry") or {}
    malware = entry.get("malware") or "botnet"
    return f"C2 SERVER — active {malware} command-and-control host", "bad"


# --------------------------------------------------------------- SSLBL
async def sslbl_check(services: Services, sha1: str) -> ApiResult:
    result = await services.fetch(
        source="sslbl",
        url=SSLBL_URL,
        headers={"Accept": "application/json"},
        cache_key="sslbl:all",
        ttl=TTL["reputation"],
    )
    if not result.ok:
        return result
    fingerprint = sha1.strip().upper().replace(":", "")
    data = result.data
    # SSLBL JSON is a map keyed by SHA1, or a list of records depending on era.
    entry = None
    if isinstance(data, dict):
        entry = data.get(fingerprint) or data.get(fingerprint.lower())
    elif isinstance(data, list):
        entry = next(
            (e for e in data if isinstance(e, dict)
             and str(e.get("SHA1") or e.get("sha1", "")).upper().replace(":", "") == fingerprint),
            None,
        )
    return ApiResult.success(
        "sslbl", {"sha1": fingerprint, "listed": entry is not None, "entry": entry},
        cached=result.cached,
    )


def sslbl_verdict(payload: dict) -> tuple[str, str]:
    if not payload.get("listed"):
        return "NOT LISTED — certificate fingerprint not on SSLBL", "ok"
    entry = payload.get("entry") or {}
    reason = ""
    if isinstance(entry, dict):
        reason = entry.get("Listingreason") or entry.get("listing_reason") or ""
    return f"MALICIOUS CERT — {reason or 'listed on SSLBL'}", "bad"
