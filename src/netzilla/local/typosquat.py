"""Typosquat / lookalike detection — generate permutations, see which exist.

This replaces the DomainsDB keyword search, which started demanding an API key
(HTTP 401 "API key required") with no public way to obtain one. The approach
here is the one dnstwist popularised: build the typing mistakes and visual
tricks an attacker would register, then ask DNS which of them actually exist.
It needs no key, has no rate limit, and only sends ordinary DNS queries
through the system resolver.

Permutation families (each result is tagged with the one that produced it):
    omission       gogle.com         (a character dropped)
    repetition     gooogle.com       (a character doubled)
    transposition  googel.com        (neighbours swapped)
    replacement    goofle.com        (adjacent key on a QWERTY keyboard)
    insertion      gooqgle.com       (adjacent key added)
    homoglyph      g00gle.com        (looks the same: 0/o, rn/m, l/1 ...)
    hyphenation    goo-gle.com
    bitsquatting   foogle.com        (one bit flipped in a character)
    vowel-swap     guogle.com
    subdomain      goo.gle.com       (dot inserted — lands on another domain)
    tld-swap       google.co, google.net ...
    addition       googles.com, google-login.com ...
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import socket
import string

KEYBOARD = {
    "1": "2q", "2": "3wq1", "3": "4ew2", "4": "5re3", "5": "6tr4", "6": "7yt5",
    "7": "8uy6", "8": "9iu7", "9": "0oi8", "0": "po9",
    "q": "12wa", "w": "3esaq2", "e": "4rdsw3", "r": "5tfde4", "t": "6ygfr5",
    "y": "7uhgt6", "u": "8ijhy7", "i": "9okju8", "o": "0plki9", "p": "lo0",
    "a": "qwsz", "s": "edxzaw", "d": "rfcxse", "f": "tgvcdr", "g": "yhbvft",
    "h": "ujnbgy", "j": "ikmnhu", "k": "olmji", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
}

HOMOGLYPHS = {
    "a": ["4", "e", "o"], "b": ["d", "lb", "ib", "6"], "c": ["e", "o"],
    "d": ["b", "cl", "dl"], "e": ["3", "c", "a"], "g": ["q", "9", "6"],
    "h": ["lh", "ih", "b"], "i": ["1", "l", "j", "!"], "j": ["i"],
    "k": ["lk", "ik", "lc"], "l": ["1", "i", "I"], "m": ["n", "nn", "rn", "rr"],
    "n": ["m", "r"], "o": ["0", "q"], "q": ["g", "o"], "s": ["5", "z"],
    "t": ["7", "f"], "u": ["v", "w"], "v": ["u", "w"], "w": ["vv", "v"],
    "y": ["v"], "z": ["2", "s"],
}

VOWELS = "aeiou"
COMMON_TLDS = (
    "com", "net", "org", "co", "io", "info", "biz", "us", "app", "online",
    "site", "xyz", "top", "shop", "cc", "me", "cn", "ru",
)
ADDITIONS = (
    "s", "login", "secure", "support", "account", "verify", "online", "app",
    "mail", "portal", "help", "auth", "sso", "vpn",
)
LABEL_CHARS = set(string.ascii_lowercase + string.digits + "-")


# --------------------------------------------------------------- parsing
def split_domain(domain: str, tld_override: str = "") -> tuple[str, str]:
    """('google', 'com') from 'www.google.com' — best effort, no PSL needed.

    Handles common two-part suffixes (co.uk, com.au ...) so 'bbc.co.uk'
    yields ('bbc', 'co.uk').
    """
    domain = domain.strip().lower().rstrip(".")
    for prefix in ("http://", "https://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].split(":")[0]
    labels = [l for l in domain.split(".") if l]
    if tld_override:
        tld = tld_override.strip().lower().lstrip(".")
        if len(labels) >= 2 and ".".join(labels[-len(tld.split(".")):]) == tld:
            labels = labels[: -len(tld.split("."))]
        return (labels[-1] if labels else ""), tld
    if len(labels) < 2:
        return (labels[0] if labels else ""), "com"
    second = labels[-2]
    if len(labels) >= 3 and second in ("co", "com", "net", "org", "gov", "ac", "edu"):
        return labels[-3], ".".join(labels[-2:])
    return labels[-2], labels[-1]


def _valid_label(label: str) -> bool:
    return (
        0 < len(label) <= 63
        and set(label) <= LABEL_CHARS
        and not label.startswith("-")
        and not label.endswith("-")
        and "--" not in label[2:4]  # avoid accidental xn-- style labels
    )


# ------------------------------------------------------------ generation
def permutations(name: str, tld: str) -> list[tuple[str, str]]:
    """[(fuzzer, fqdn), ...] — deduplicated, original excluded."""
    out: dict[str, str] = {}

    def add(kind: str, label: str, suffix: str = tld) -> None:
        label = label.lower()
        if "." in label:  # subdomain family builds its own FQDN
            parts = label.split(".")
            if all(_valid_label(p) for p in parts):
                out.setdefault(f"{label}.{suffix}", kind)
            return
        if _valid_label(label) and label != name:
            out.setdefault(f"{label}.{suffix}", kind)

    n = len(name)
    for i in range(n):
        add("omission", name[:i] + name[i + 1:])
        add("repetition", name[:i] + name[i] + name[i:])
        if i < n - 1 and name[i] != name[i + 1]:
            add("transposition", name[:i] + name[i + 1] + name[i] + name[i + 2:])
        for key in KEYBOARD.get(name[i], ""):
            add("replacement", name[:i] + key + name[i + 1:])
            add("insertion", name[:i] + key + name[i:])
            add("insertion", name[:i + 1] + key + name[i + 1:])
        for glyph in HOMOGLYPHS.get(name[i], []):
            add("homoglyph", name[:i] + glyph.lower() + name[i + 1:])
        if name[i] in VOWELS:
            for v in VOWELS:
                if v != name[i]:
                    add("vowel-swap", name[:i] + v + name[i + 1:])
        for bit in range(8):
            flipped = chr(ord(name[i]) ^ (1 << bit))
            if flipped in LABEL_CHARS and flipped != "-":
                add("bitsquatting", name[:i] + flipped + name[i + 1:])
        if 0 < i < n:
            add("hyphenation", name[:i] + "-" + name[i:])
            add("subdomain", name[:i] + "." + name[i:])
    for other in COMMON_TLDS:
        if other != tld:
            out.setdefault(f"{name}.{other}", "tld-swap")
    for word in ADDITIONS:
        add("addition", name + word)
        add("addition", f"{name}-{word}")
    out.pop(f"{name}.{tld}", None)
    return [(kind, fqdn) for fqdn, kind in out.items()]


# -------------------------------------------------------------- resolution
async def _resolve(fqdn: str, timeout: float) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(fqdn, None, proto=socket.IPPROTO_TCP), timeout
        )
    except (socket.gaierror, asyncio.TimeoutError, OSError, UnicodeError):
        return []
    addrs: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in addrs:
            addrs.append(addr)
    return addrs


async def wildcard_addresses(tld: str, timeout: float = 4.0) -> set[str]:
    """Addresses the resolver hands out for names that cannot exist.

    Some ISPs and captive DNS answer every NXDOMAIN with an ad server; those
    addresses would make every permutation look registered.
    """
    junk = "".join(random.choices(string.ascii_lowercase, k=24))
    return set(await _resolve(f"nz-{junk}.{tld}", timeout))


async def scan(
    domain: str,
    tld_override: str = "",
    concurrency: int = 40,
    timeout: float = 4.0,
    progress=None,
) -> dict:
    name, tld = split_domain(domain, tld_override)
    if not name:
        raise ValueError("Could not work out a domain name to permute.")
    candidates = permutations(name, tld)
    fake = await wildcard_addresses(tld, timeout)
    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def probe(kind: str, fqdn: str):
        nonlocal done
        async with sem:
            addrs = await _resolve(fqdn, timeout)
        done += 1
        if progress and done % 50 == 0:
            progress(f"Checked {done}/{len(candidates)} permutations…")
        real = [a for a in addrs if a not in fake]
        return (kind, fqdn, real) if real else None

    results = await asyncio.gather(*(probe(k, f) for k, f in candidates))
    hits = sorted((r for r in results if r), key=lambda r: (r[0], r[1]))
    return {
        "original": f"{name}.{tld}",
        "checked": len(candidates),
        "registered": [
            {"fuzzer": k, "domain": d, "addresses": a, "private": _any_private(a)}
            for k, d, a in hits
        ],
        "wildcard_resolver": sorted(fake),
    }


def _any_private(addrs: list[str]) -> bool:
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return True
    return False


def rows(result: dict, limit: int = 200) -> list[list[object]]:
    out = []
    for hit in result["registered"][:limit]:
        addrs = hit["addresses"]
        shown = ", ".join(addrs[:2]) + (f" +{len(addrs) - 2}" if len(addrs) > 2 else "")
        out.append([hit["fuzzer"], hit["domain"], shown])
    return out
