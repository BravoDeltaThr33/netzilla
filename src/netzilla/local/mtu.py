"""Path MTU discovery by binary search.

Sends ICMP echoes with the Don't-Fragment bit set and the payload size varied,
binary-searching for the largest packet that survives the whole path. When a
tunnel or VPN silently clamps the MTU, this is the "why is only this one app
slow / why do big downloads stall" answer that is otherwise diagnosed by hand.

Linux: `ping -M do -s <payload> -c1 -W2 host`; macOS: `ping -D -s <payload>`;
Windows: `ping -f -l <payload> -n 1`. The IP+ICMP headers add 28 bytes, so a
payload of N tests a path MTU of N+28. The binary search is a pure function
driven by an injected probe coroutine, so it is unit-tested without the
network.
"""

from __future__ import annotations

import re

from .. import hostos
from .runner import run

IP_ICMP_OVERHEAD = 28          # 20 (IPv4) + 8 (ICMP echo)
# Standard search window: 576 (IPv4 minimum) up to a jumbo frame.
MIN_PAYLOAD = 548              # 576 - 28
MAX_PAYLOAD = 8972             # 9000 (jumbo) - 28


def df_ping_argv(host: str, payload: int, timeout: float = 2.0) -> list[str]:
    """One echo of `payload` bytes with Don't-Fragment set, on this system."""
    if hostos.is_windows():
        return ["ping", "-f", "-l", str(payload), "-n", "1", "-w",
                str(int(timeout * 1000)), host]
    if hostos.is_macos():
        return ["ping", "-D", "-s", str(payload), "-c", "1", "-W",
                str(int(timeout * 1000)), host]
    return ["ping", "-M", "do", "-s", str(payload), "-c", "1", "-W", str(int(timeout)), host]


def df_ping_label() -> str:
    """The command PATH MTU runs, for its panel's subtitle."""
    return " ".join(df_ping_argv("host", 0)[:3]) if not hostos.is_linux() else "ping -M do"


_WIN_REPLY = re.compile(r"\bTTL=\d+", re.I)


def got_through(output: str) -> bool:
    """Did the one DF echo come back? Linux and macOS print '1 received' /
    '1 packets received'; Windows prints a reply line, which carries a TTL
    ("Packet needs to be fragmented but DF set." does not)."""
    out = output or ""
    if "1 received" in out or "1 packets received" in out:
        return True
    return hostos.is_windows() and bool(_WIN_REPLY.search(out))


async def _probe_ping(host: str, payload: int, timeout: float = 2.0) -> bool:
    """True if a DF ping of this payload size gets through."""
    result = await run(
        df_ping_argv(host, payload, timeout),
        timeout=timeout + 3, ok_returncodes=(0, 1, 2),
    )
    if result.missing_tool:
        raise FileNotFoundError("ping")
    # Explicit "message too long" / "Frag needed" both mean: too big.
    return got_through(result.output)


async def discover(host: str, probe=None, low: int = MIN_PAYLOAD, high: int = MAX_PAYLOAD,
                   progress=None) -> dict:
    """Binary-search the largest DF payload that reaches `host`."""
    probe = probe or (lambda payload: _probe_ping(host, payload))

    if not await probe(low):
        return {
            "host": host, "path_mtu": None, "reachable": False,
            "note": f"Even a {low + IP_ICMP_OVERHEAD}-byte packet did not get "
                    "through — the host may not answer ICMP at all.",
        }
    if await probe(high):
        return {
            "host": host, "path_mtu": high + IP_ICMP_OVERHEAD, "reachable": True,
            "note": f"Path carries at least {high + IP_ICMP_OVERHEAD} bytes "
                    "(search ceiling).", "at_ceiling": True,
        }
    best = low
    steps = 0
    while low <= high:
        steps += 1
        mid = (low + high) // 2
        if progress:
            progress(f"Testing MTU {mid + IP_ICMP_OVERHEAD}… (step {steps})")
        if await probe(mid):
            best = mid
            low = mid + 1
        else:
            high = mid - 1
    mtu = best + IP_ICMP_OVERHEAD
    return {
        "host": host, "path_mtu": mtu, "reachable": True, "steps": steps,
        "note": _interpret(mtu),
    }


def _interpret(mtu: int) -> str:
    if mtu >= 1500:
        return "Full 1500-byte Ethernet MTU — no clamping on this path."
    if mtu == 1492:
        return "1492 — classic PPPoE (DSL) overhead."
    if 1400 <= mtu < 1500:
        return f"{mtu} — a tunnel/VPN is clamping the path below 1500. Expect "
    if mtu < 1400:
        return f"{mtu} — unusually low; a tunnel or misconfig is fragmenting traffic."
    return f"{mtu}."


def verdict(result: dict) -> tuple[str, str]:
    mtu = result.get("path_mtu")
    if not result.get("reachable") or mtu is None:
        return f"NO PATH MTU — {result.get('note', 'host unreachable')}", "warn"
    if mtu >= 1500:
        return f"PATH MTU {mtu} — no clamping", "ok"
    return f"PATH MTU {mtu} — below 1500, path is clamped", "warn"
