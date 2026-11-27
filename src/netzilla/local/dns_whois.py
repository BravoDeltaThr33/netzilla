"""DNS and WHOIS through the tools every Linux box already has.

dig and whois are the reference implementations network engineers already
trust, cost nothing, have no rate limit and work on internal zones that no
public API can see. netzilla wraps them rather than proxying basic lookups
through a third party.

Windows has neither. Without dig, the DNS screen asks Cloudflare over
DNS-over-HTTPS (clients/doh.py); without whois, whois() speaks the WHOIS
protocol itself (RFC 3912: one line out on TCP port 43, the answer back),
starting at IANA and following each referral, as the whois program does.
"""

from __future__ import annotations

import asyncio
import re
import socket

from .runner import CommandResult, have, run

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "SRV", "PTR")


async def dig(
    domain: str, record_type: str = "A", server: str = "", timeout: float = 15.0
) -> CommandResult:
    argv = ["dig", "+nocmd", "+noall", "+answer", "+authority", "+comments"]
    if server:
        argv.append(f"@{server}")
    argv += [domain, record_type.upper()]
    return await run(argv, timeout=timeout)


async def dig_short(
    domain: str, record_type: str = "A", server: str = "", timeout: float = 15.0
) -> CommandResult:
    argv = ["dig", "+short"]
    if server:
        argv.append(f"@{server}")
    argv += [domain, record_type.upper()]
    return await run(argv, timeout=timeout)


async def all_records(
    domain: str, server: str = "", types: tuple[str, ...] = RECORD_TYPES
) -> dict[str, CommandResult]:
    """Query every common record type concurrently."""
    results = await asyncio.gather(
        *(dig_short(domain, rtype, server) for rtype in types)
    )
    return dict(zip(types, results))


async def reverse(ip: str, server: str = "") -> CommandResult:
    argv = ["dig", "+short", "-x", ip]
    if server:
        argv.insert(2, f"@{server}")
    return await run(argv)


async def trace(domain: str) -> CommandResult:
    """Full delegation path from the root servers down."""
    return await run(["dig", "+trace", "+nodnssec", domain], timeout=45.0)


async def whois(target: str, timeout: float = 25.0) -> CommandResult:
    if not have("whois"):
        return await whois_direct(target, timeout=min(timeout, 15.0))
    return await run(["whois", target], timeout=timeout, ok_returncodes=(0, 1))


# ------------------------------------------------- WHOIS without a client
WHOIS_PORT = 43
IANA_WHOIS = "whois.iana.org"
WHOIS_HOPS = 3
_REFERRAL_RE = re.compile(
    r"^\s*(?:refer|whois|registrar whois server|referralserver)\s*:\s*(\S+)",
    re.I | re.M)


def whois_referral(text: str, current: str = "") -> str:
    """The next server an answer points to ("refer: whois.verisign-grs.com",
    "Registrar WHOIS Server: …", "ReferralServer: whois://whois.ripe.net"),
    or '' when it points nowhere new."""
    for match in _REFERRAL_RE.finditer(text or ""):
        server = re.sub(r"^[a-z]+://", "", match.group(1).strip(), flags=re.I)
        server = server.split("/", 1)[0].split(":", 1)[0].strip().lower()
        if server and "." in server and server != current.lower():
            return server
    return ""


def _whois_ask(server: str, query: str, timeout: float) -> str:
    with socket.create_connection((server, WHOIS_PORT), timeout=timeout) as sock:
        sock.sendall(query.encode("utf-8", "replace") + b"\r\n")
        chunks, total = [], 0
        while total < 2_000_000:
            block = sock.recv(65536)
            if not block:
                break
            chunks.append(block)
            total += len(block)
    return b"".join(chunks).decode("utf-8", "replace")


def whois_chain(target: str, ask=None, timeout: float = 15.0) -> tuple[str, list[str], str]:
    """(answer, servers asked, error). IANA says which registry holds the
    name or address; a registry may in turn point at the registrar. The
    answers after IANA's are kept, joined, as the whois program prints them."""
    ask = ask or _whois_ask
    server, asked, answers = IANA_WHOIS, [], []
    for _hop in range(WHOIS_HOPS):
        try:
            text = ask(server, target, timeout)
        except OSError as exc:
            if answers:
                break
            return "", asked, f"{server} did not answer: {exc.strerror or exc}"
        asked.append(server)
        answers.append(text)
        following = whois_referral(text, server)
        if not following or following in asked:
            break
        server = following
    useful = answers[1:] or answers
    return "\n\n".join(a.strip() for a in useful if a.strip()), asked, ""


async def whois_direct(target: str, timeout: float = 15.0) -> CommandResult:
    """WHOIS over the network with no whois program installed."""
    text, asked, error = await asyncio.to_thread(whois_chain, target, None, timeout)
    command = "whois (built in) via " + " → ".join(asked or [IANA_WHOIS])
    return CommandResult(bool(text), text, error, command)


def tools_status() -> list[tuple[str, bool]]:
    return [("dig", have("dig")), ("whois", have("whois"))]


def condense_whois(text: str, max_lines: int = 60) -> str:
    """Strip the legal boilerplate most WHOIS servers prepend."""
    interesting = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("%", "#", ">>>")):
            continue
        if stripped.lower().startswith((
            "notice", "terms of use", "by the following", "to ", "for more",
            "the data in", "this query", "you agree", "we reserve",
            "url of the icann", "note:", "please note",
        )):
            continue
        interesting.append(line.rstrip())
        if len(interesting) >= max_lines:
            interesting.append("… (truncated)")
            break
    return "\n".join(interesting) if interesting else text[:2000]
