"""Paste-in config / show-output summarizer.

Paste a `show interfaces`, `show ip route`, or a running-config and netzilla
flags what a human scans for: interfaces carrying errors, err-disabled or
admin-down ports, and the route count by protocol. It is pure local text
parsing — nothing is sent anywhere — and doubles as a CCNA study aid.

Cisco IOS / IOS-XE syntax is the primary target (by far the most common in
pasted output); the heuristics also catch common NX-OS and Arista variants.
"""

from __future__ import annotations

import re

# ------------------------------------------------------------ show interfaces
_IFACE_HEAD = re.compile(
    r"^(?P<name>[A-Za-z][\w./:-]*?)\s+is\s+(?P<link>administratively down|up|down|deleted)"
    r",?\s+line protocol is\s+(?P<proto>up|down|\S+)",
    re.IGNORECASE,
)
_ERR_FIELDS = [
    ("input errors", r"(\d+)\s+input errors"),
    ("CRC", r"(\d+)\s+CRC"),
    ("output errors", r"(\d+)\s+output errors"),
    ("collisions", r"(\d+)\s+collisions"),
    ("input drops", r"input\s+.*?(\d+)\s+drops|(\d+)\s+input\s+drops"),
    ("resets", r"(\d+)\s+interface resets"),
]


def parse_interfaces(text: str) -> list[dict]:
    """One record per interface stanza in `show interfaces` output."""
    interfaces: list[dict] = []
    current: dict | None = None
    buffer: list[str] = []

    def flush():
        if current is not None:
            current["errors"] = _errors_in("\n".join(buffer))
            interfaces.append(current)

    for line in text.splitlines():
        head = _IFACE_HEAD.match(line.strip())
        if head:
            flush()
            buffer = [line]
            current = {
                "name": head.group("name"),
                "link": head.group("link").lower(),
                "protocol": head.group("proto").lower(),
            }
        elif current is not None:
            buffer.append(line)
    flush()
    return interfaces


def _errors_in(block: str) -> dict[str, int]:
    found: dict[str, int] = {}
    for label, pattern in _ERR_FIELDS:
        m = re.search(pattern, block, re.IGNORECASE)
        if m:
            value = next((g for g in m.groups() if g and g.isdigit()), None)
            if value and int(value) > 0:
                found[label] = int(value)
    return found


# ---------------------------------------------------------------- err-disabled
_ERRDISABLE = re.compile(
    r"^(?P<name>\S+)\s+.*?err[- ]?disabled", re.IGNORECASE | re.MULTILINE
)


def err_disabled(text: str) -> list[str]:
    names = []
    for m in _ERRDISABLE.finditer(text):
        name = m.group("name")
        if name.lower() not in ("port", "interface") and name not in names:
            names.append(name)
    # Also catch "is down (err-disabled)" phrasing from show interfaces.
    for m in re.finditer(r"(\S+)\s+is\s+down\s*\(err-disabled\)", text, re.IGNORECASE):
        if m.group(1) not in names:
            names.append(m.group(1))
    return names


# ------------------------------------------------------------- show ip route
# Leading protocol code(s) at the start of a route line: C, S, O, D, B, R, i, L…
_ROUTE_LINE = re.compile(
    r"^(?P<code>[A-Za-z*]{1,4}(?:\s+[A-Z]{1,3})?)\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
)
_ROUTE_CODE = {
    "L": "local", "C": "connected", "S": "static", "R": "RIP",
    "D": "EIGRP", "O": "OSPF", "B": "BGP", "i": "IS-IS", "N": "OSPF NSSA",
    "E": "OSPF external", "IA": "OSPF inter-area",
}


def route_counts(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in text.splitlines():
        stripped = line.strip()
        m = _ROUTE_LINE.match(stripped)
        if not m:
            continue
        first = m.group("code").strip().split()[0].lstrip("*")
        key = first[0]
        proto = _ROUTE_CODE.get(first, _ROUTE_CODE.get(key, first))
        counts[proto] = counts.get(proto, 0) + 1
    return counts


# ------------------------------------------------------------------ dispatch
def detect_kind(text: str) -> str:
    low = text.lower()
    if "line protocol is" in low:
        return "interfaces"
    if re.search(r"codes:\s*[LCSORBDI]", text) or "gateway of last resort" in low:
        return "routes"
    if re.search(r"^\s*(interface|hostname|router \w+)", text, re.IGNORECASE | re.MULTILINE):
        return "config"
    return "unknown"


def summarize(text: str) -> dict:
    """Return findings for whichever kind of output was pasted."""
    kind = detect_kind(text)
    result: dict = {"kind": kind, "findings": []}

    if kind in ("interfaces", "config", "unknown"):
        interfaces = parse_interfaces(text)
        result["interfaces"] = interfaces
        with_errors = [i for i in interfaces if i["errors"]]
        down = [
            i for i in interfaces
            if i["link"] == "up" and i["protocol"] != "up"
        ]
        result["with_errors"] = with_errors
        result["proto_down"] = down
        for i in with_errors:
            detail = ", ".join(f"{v} {k}" for k, v in i["errors"].items())
            result["findings"].append(
                ("bad", f"{i['name']}: {detail}")
            )
        for i in down:
            result["findings"].append(
                ("warn", f"{i['name']}: line up but protocol {i['protocol']} "
                         "(keepalive/encapsulation/clocking?)")
            )

    disabled = err_disabled(text)
    if disabled:
        result["err_disabled"] = disabled
        result["findings"].append(
            ("bad", f"err-disabled: {', '.join(disabled)}")
        )

    if kind in ("routes", "config", "unknown"):
        counts = route_counts(text)
        if counts:
            result["route_counts"] = counts
            total = sum(counts.values())
            result["findings"].append(
                ("info", f"{total} routes: "
                         + ", ".join(f"{n} {p}" for p, n in sorted(counts.items())))
            )
            big = [(p, n) for p, n in counts.items() if n > 1000]
            for proto, n in big:
                result["findings"].append(
                    ("warn", f"{n} {proto} routes — unusually large table; check "
                             "redistribution or summarization")
                )

    if not result["findings"]:
        result["findings"].append(("ok", "No error counters, err-disabled ports "
                                          "or oversized route tables spotted."))
    return result


def finding_rows(result: dict) -> list[list[object]]:
    label = {"bad": "PROBLEM", "warn": "CHECK", "info": "INFO", "ok": "OK"}
    return [[label.get(state, state.upper()), text] for state, text in result["findings"]]
