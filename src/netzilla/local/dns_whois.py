"""DNS and WHOIS through the tools every Linux box already has.

dig and whois are the reference implementations network engineers already
trust, cost nothing, have no rate limit and work on internal zones that no
public API can see. netzilla wraps them rather than proxying basic lookups
through a third party.
"""

from __future__ import annotations

import asyncio

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
    return await run(["whois", target], timeout=timeout, ok_returncodes=(0, 1))


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
