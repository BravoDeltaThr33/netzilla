"""Have I Been Pwned — Pwned Passwords (k-anonymity) and the public breach list.

Pwned Passwords  GET https://api.pwnedpasswords.com/range/{first5-of-SHA1}
    keyless, privacy-preserving. netzilla hashes the password locally with
    SHA-1, sends ONLY the first five hex characters of that hash, and matches
    the 35-character suffix against the returned list. The password itself,
    and 35/40 of its hash, never leave the machine.
Breach list      GET https://haveibeenpwned.com/api/v3/breaches
    keyless directory of known breaches (metadata only; per-account search now
    needs a paid key and is intentionally not used here).
"""

from __future__ import annotations

import hashlib

from ..cache import TTL
from ..services import ApiResult, Services

RANGE_URL = "https://api.pwnedpasswords.com/range"
BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"


def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


async def check_password(services: Services, password: str) -> ApiResult:
    """k-anonymity breach check. Only the SHA-1 prefix is transmitted."""
    if not password:
        return ApiResult.failure("pwnedpw", "Enter a password to check.")
    digest = sha1_hex(password)
    prefix, suffix = digest[:5], digest[5:]
    result = await services.fetch(
        source="pwnedpw",
        url=f"{RANGE_URL}/{prefix}",
        headers={"Add-Padding": "true"},
        expect="text",
        cache_key=None,          # never cache anything derived from a password
        ttl=0,
    )
    if not result.ok:
        return result
    count = parse_range(result.data or "", suffix)
    return ApiResult.success(
        "pwnedpw",
        {"pwned": count > 0, "count": count, "prefix": prefix},
    )


def parse_range(body: str, suffix: str) -> int:
    """Find our hash suffix in the 'SUFFIX:COUNT' lines HIBP returns."""
    suffix = suffix.upper()
    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        candidate, _, count = line.partition(":")
        if candidate.strip().upper() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return 0
    return 0


def password_verdict(payload: dict) -> tuple[str, str]:
    count = payload.get("count", 0)
    if not count:
        return "NOT FOUND — this password is not in any known breach corpus", "ok"
    return (
        f"BREACHED — seen {count:,} time(s) in breach corpora. Do not use it.",
        "bad",
    )


# --------------------------------------------------------------- breaches
async def breaches(services: Services) -> ApiResult:
    result = await services.fetch(
        source="hibp",
        url=BREACHES_URL,
        headers={"Accept": "application/json", "User-Agent": "netzilla"},
        cache_key="hibp:breaches",
        ttl=TTL["whois"],
    )
    if not result.ok:
        return result
    data = result.data if isinstance(result.data, list) else []
    return ApiResult.success("hibp", data, cached=result.cached)


def normalise_term(term: str) -> str:
    """'https://www.LinkedIn.com/login' -> 'linkedin.com'."""
    term = term.strip().lower()
    for prefix in ("http://", "https://"):
        if term.startswith(prefix):
            term = term[len(prefix):]
    term = term.split("/")[0].split("?")[0]
    if "@" in term:                      # an email address: search its domain
        term = term.rsplit("@", 1)[1]
    if term.startswith("www."):
        term = term[4:]
    return term.strip(".")


def breach_matches(breach: dict, term: str) -> bool:
    """Substring match on name/title/domain, plus domain-aware matching so
    'mail.adobe.com' finds adobe.com and 'linkedin.com' finds 'LinkedIn'."""
    name = str(breach.get("Name", "")).lower()
    title = str(breach.get("Title", "")).lower()
    domain = str(breach.get("Domain", "")).lower().strip(".")
    if term in name or term in title or (domain and term in domain):
        return True
    if "." in term:
        if domain and (term.endswith("." + domain) or domain.endswith("." + term)):
            return True
        base = term.split(".")[-2] if term.count(".") >= 1 else term
        if len(base) >= 4 and (base == name or base == title.replace(" ", "")
                               or domain.split(".")[0] == base):
            return True
    return False


async def find_breaches(services: Services, term: str) -> ApiResult:
    """Filter the public breach directory by name/domain."""
    listed = await breaches(services)
    if not listed.ok:
        return listed
    term = normalise_term(term)
    matches = [
        b for b in listed.data
        if isinstance(b, dict) and breach_matches(b, term)
    ]
    matches.sort(key=lambda b: b.get("BreachDate") or "", reverse=True)
    return ApiResult.success(
        "hibp", {"term": term, "total": len(listed.data), "matches": matches},
        cached=listed.cached,
    )


def breach_rows(payload: dict, limit: int = 30) -> list[list[object]]:
    rows = []
    for b in (payload.get("matches") or [])[:limit]:
        rows.append([
            b.get("Title") or b.get("Name", "—"),
            b.get("Domain") or "—",
            b.get("BreachDate") or "—",
            _human(b.get("PwnCount")),
            ", ".join(b.get("DataClasses") or [])[:60] or "—",
        ])
    return rows


def _human(value) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "—"
