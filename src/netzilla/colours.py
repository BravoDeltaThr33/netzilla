"""Colouring the data itself, the same way on every tab.

The theme (themes.py) colours netzilla's chrome — borders, titles, labels,
buttons. This module colours the *values* in result tables and key/value
panels by what they mean, so a reading looks the same wherever it turns up:
an excellent signal is green on SCAN, LIVE AIR, SIGNAL and LINK HEALTH alike,
an SSID is always pink, an IP address always teal.

The meanings are fixed across themes on purpose — learn them once — and every
colour is a light tint chosen to read on all seventeen themes' dark
backgrounds. Anything a rule doesn't recognise stays in the theme's own
foreground colour.

How a cell is coloured:
  1. by its column (or key) name — SSID, CH, BAND, SIGNAL, SECURITY, STATE…
     decide the colour of the whole value;
  2. then by what is inside it — IP and MAC addresses, "2.4 GHz", "-67 dBm",
     "<hidden>", CVE ids and AS numbers are picked out wherever they appear,
     even inside a free-text DETAILS or INFO column.

`style_cell()` is the one entry point; render.py calls it for every table
cell and every key/value row.
"""

from __future__ import annotations

import colorsys
import re
from typing import Callable

from rich.style import Style
from rich.text import Text

# ------------------------------------------------------------ the palette
SEMANTIC: dict[str, str] = {
    # signal / quality — one scale, used by the dBm number, the quality
    # word, the signal bars and the live graphs
    "excellent": "#5fdf7f",      # green
    "good": "#62b6ff",           # blue
    "fair": "#ffd75f",           # yellow
    "weak": "#ff9d4d",           # orange
    "very weak": "#ff5f6d",      # red
    # radio
    "band_24": "#8fd3ff",        # light blue
    "band_5": "#a8f0a8",         # light green
    "band_6": "#d4b0ff",         # lavender
    "ssid": "#ff8fd0",           # pink
    "hidden": "#ffd75f",         # yellow
    # addresses and names
    "ip": "#7fdbca",             # teal
    "mac": "#c3a6ff",            # lilac
    "vendor": "#e6c88a",         # sand
    "virtual": "#9a8fb8",        # dim lilac: virtual BSSID / private MAC
    "hostname": "#8ab4ff",       # periwinkle
    "device": "#f2a8ff",         # orchid
    "service": "#ffc98b",        # peach
    "process": "#d7c4ff",        # pale violet
    "port": "#ffcb6b",           # amber
    "asn": "#f7a8b8",            # rose
    "country": "#b8e0a8",        # sage
    "url": "#8ab4ff",
    "cve": "#ff9d9d",
    "time": "#9fb3c8",           # slate
    "muted": "#7a8288",
}

# Protocols get a colour each; anything unlisted gets a stable one from the
# categorical wheel below.
PROTOCOL_COLOURS = {
    "TCP": "#7fb2ff", "UDP": "#ffb86b", "TLS": "#7fe0a0", "TLSV1.2": "#7fe0a0",
    "TLSV1.3": "#7fe0a0", "SSL": "#7fe0a0", "QUIC": "#c792ea", "DNS": "#ffd75f",
    "MDNS": "#f6c177", "LLMNR": "#f6c177", "ARP": "#ff8fa3", "SSDP": "#9ccfd8",
    "NTP": "#a6da95", "HTTP": "#82aaff", "HTTPS": "#7fe0a0", "ICMP": "#f78c6c",
    "ICMPV6": "#f78c6c", "DHCP": "#e0af68", "SSH": "#bb9af7", "SMB": "#ff9e64",
    "SMB2": "#ff9e64", "NBNS": "#e0af68", "IGMPV3": "#9aa5ce", "STP": "#9aa5ce",
}

SECURITY_COLOURS = [
    # checked in order: the first word found decides
    ("WPA3", "excellent"), ("SAE", "excellent"), ("WPA2", "good"),
    ("WPA1", "weak"), ("WPA", "weak"), ("WEP", "very weak"), ("OPEN", "very weak"),
    ("--", "very weak"),
]

STATE_COLOURS = {
    "ESTAB": "excellent", "ESTABLISHED": "excellent", "LISTEN": "good",
    "SYN-SENT": "weak", "SYN-RECV": "weak", "TIME-WAIT": "fair",
    "CLOSE-WAIT": "fair", "FIN-WAIT-1": "fair", "FIN-WAIT-2": "fair",
    "LAST-ACK": "fair", "CLOSING": "fair", "UNCONN": "muted",
    "UP": "excellent", "DOWN": "very weak", "UNKNOWN": "muted",
    "ADMINISTRATIVELY DOWN": "muted", "DORMANT": "fair", "LOWERLAYERDOWN": "very weak",
}

LEVEL_COLOURS = {
    "OK": "excellent", "INFO": "good", "CHECK": "fair", "WARN": "fair",
    "WARNING": "fair", "PROBLEM": "very weak", "BAD": "very weak",
    "ERROR": "very weak", "CRITICAL": "very weak", "HIGH": "weak",
    "MEDIUM": "fair", "MODERATE": "fair", "LOW": "good", "NONE": "muted",
}

STATUS_WORDS = [
    # service status and verdict words, first match wins
    ("end of life", "very weak"), ("unsupported", "very weak"),
    ("security only", "weak"), ("ending soon", "fair"), ("supported", "excellent"),
    ("exploited", "very weak"),
    ("operational", "excellent"), ("all systems", "excellent"), ("resolved", "excellent"),
    ("clean", "excellent"), ("working", "excellent"), ("none", "excellent"),
    ("harmless", "excellent"), ("benign", "excellent"), ("valid", "excellent"),
    ("degraded", "fair"), ("partial", "fair"), ("minor", "fair"),
    ("maintenance", "good"), ("monitoring", "good"), ("investigating", "weak"),
    ("identified", "weak"), ("suspicious", "weak"), ("major", "very weak"),
    ("outage", "very weak"), ("malicious", "very weak"), ("expired", "very weak"),
    ("down", "very weak"), ("rejected", "very weak"), ("unknown", "muted"),
    ("not configured", "muted"), ("closed", "muted"), ("filtered", "fair"),
    ("refused", "weak"), ("timeout", "weak"), ("timed out", "weak"),
    ("open", "excellent"), ("reachable", "excellent"),
]


# ------------------------------------------------------------ channels
# Every Wi-Fi channel number gets its own colour. Hues are spread by the
# golden ratio in channel order, so neighbours (1, 6, 11; 36, 40, 44…) land
# far apart on the wheel, at one lightness that reads on every theme.
_KNOWN_CHANNELS = (
    list(range(1, 15))
    + [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124,
       128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177]
)


def _wheel(index: int, lightness: float = 0.74, saturation: float = 0.78) -> str:
    hue = (0.11 + index * 0.6180339887) % 1.0
    r, g, b = colorsys.hls_to_rgb(hue, lightness, saturation)
    return f"#{int(r * 255):02x}{int(g * 255):02x}{int(b * 255):02x}"


CHANNEL_COLOURS = {ch: _wheel(i) for i, ch in enumerate(_KNOWN_CHANNELS)}
# The channels that turn up in almost every scan get hand-picked colours as
# far apart as possible: 1 / 6 / 11 on 2.4 GHz, and the usual 5 GHz ones.
CHANNEL_COLOURS.update({
    1: "#ff7a93",     # rose
    6: "#c792ea",     # purple
    11: "#ffb86c",    # amber
    36: "#7fe7ff",    # cyan
    40: "#c3e88d",    # lime
    44: "#ff8b6b",    # coral
    48: "#f7e27a",    # straw
    149: "#ff79c6",   # magenta
    153: "#5fd7af",   # teal
    157: "#8ea6ff",   # periwinkle
    161: "#e0c3a0",   # tan
    165: "#a5f0c5",   # mint
})


def channel_colour(channel: int) -> str:
    if channel in CHANNEL_COLOURS:
        return CHANNEL_COLOURS[channel]
    return _wheel(len(_KNOWN_CHANNELS) + channel)       # 6 GHz and the rest


def category_colour(name: str) -> str:
    """A stable colour for any label that has none of its own."""
    return _wheel(sum(ord(c) * (i + 1) for i, c in enumerate(name.upper())) % 97)


# ------------------------------------------------------------ signal scale
def quality_of_dbm(dbm: float) -> str:
    """netzilla's one signal scale (the same thresholds as wifi.signal_label)."""
    if dbm >= -50:
        return "excellent"
    if dbm >= -60:
        return "good"
    if dbm >= -70:
        return "fair"
    if dbm >= -80:
        return "weak"
    return "very weak"


def signal_colour(dbm) -> str:
    if dbm is None:
        return SEMANTIC["muted"]
    return SEMANTIC[quality_of_dbm(float(dbm))]


def band_colour(band: str) -> str:
    band = band.replace(" ", "").lower()
    if band.startswith("2.4"):
        return SEMANTIC["band_24"]
    if band.startswith("5"):
        return SEMANTIC["band_5"]
    if band.startswith("6"):
        return SEMANTIC["band_6"]
    return SEMANTIC["muted"]


# ------------------------------------------------------------ token rules
_IPV4 = r"(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?::\d{1,5})?(?![\w.])"
_IPV6 = r"(?<![\w:])[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?:/\d{1,3})?(?![\w:])"
_MAC = r"(?<![\w:])[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}(?![\w:])"
_DBM = r"-\d{2,3}(?:\.\d+)?(?=\s*dBm)"
_BAND = r"\b(?:2\.4|5|6)\s?GHz\b"
_CVE = r"\bCVE-\d{4}-\d{4,}\b"
_ASN = r"\bAS\d{1,10}\b"
_URL = r"\bhttps?://\S+"

def _is_ipv6(text: str) -> bool:
    import ipaddress

    try:
        ipaddress.IPv6Address(text.split("/")[0])
    except ValueError:
        return False
    return True


TOKENS: list[tuple[re.Pattern, Callable[[str], str | None]]] = [
    (re.compile(_URL), lambda m: SEMANTIC["url"]),
    (re.compile(_MAC), lambda m: SEMANTIC["mac"]),
    (re.compile(_IPV4), lambda m: SEMANTIC["ip"]),
    # Candidates are checked by the ipaddress module, so a MAC or a clock
    # ("14:03:22") that merely looks colon-separated is not coloured as one.
    (re.compile(_IPV6), lambda m: SEMANTIC["ip"] if _is_ipv6(m) else None),
    (re.compile(_DBM), lambda m: signal_colour(float(m))),
    (re.compile(_BAND), band_colour),
    (re.compile(r"<hidden>"), lambda m: SEMANTIC["hidden"]),
    (re.compile(_CVE), lambda m: SEMANTIC["cve"]),
    (re.compile(_ASN), lambda m: SEMANTIC["asn"]),
]


# ------------------------------------------------------------ column rules
def _first_int(text: str):
    match = re.search(r"-?\d+", text)
    return int(match.group(0)) if match else None


def _first_float(text: str):
    match = re.search(r"-?\d+(?:\.\d+)?", text)
    return float(match.group(0)) if match else None


def _signal(text: str) -> str | None:
    low = text.strip().lower()
    for word in ("very weak", "excellent", "good", "fair", "weak"):
        if low.startswith(word):
            return SEMANTIC[word]
    if low in ("gone", "—", "-"):
        return SEMANTIC["muted"]
    value = _first_float(text)
    if value is not None and value < 0:
        return signal_colour(value)
    return None


def _security(text: str) -> str | None:
    up = text.upper()
    for word, key in SECURITY_COLOURS:
        if word in up:
            return SEMANTIC[key]
    return None


def _channel(text: str) -> str | None:
    number = _first_int(text)
    return channel_colour(number) if number and number > 0 else None


def _vendor(text: str) -> str:
    low = text.lower()
    if low in ("virtual bssid", "private mac", "random / virtual", "multicast"):
        return SEMANTIC["virtual"]
    return SEMANTIC["vendor"]


def _protocol(text: str) -> str:
    first = re.split(r"[,\s]+", text.strip())[0].upper()
    return PROTOCOL_COLOURS.get(first) or category_colour(first)


def _state(text: str) -> str | None:
    key = STATE_COLOURS.get(text.strip().upper())
    if key is None:
        up = text.strip().upper()
        key = next((v for k, v in STATE_COLOURS.items() if up.startswith(k)), None)
    return SEMANTIC[key] if key else None


def _level(text: str) -> str | None:
    key = LEVEL_COLOURS.get(text.strip().upper())
    return SEMANTIC[key] if key else None


def _status(text: str) -> str | None:
    low = text.lower()
    for word, key in STATUS_WORDS:
        if word in low:
            return SEMANTIC[key]
    return None


def _rtt(text: str) -> str | None:
    if text.strip() == "local":
        return SEMANTIC["excellent"]
    value = _first_float(text)
    if value is None:
        return None
    for limit, key in ((5, "excellent"), (20, "good"), (60, "fair"), (150, "weak")):
        if value < limit:
            return SEMANTIC[key]
    return SEMANTIC["very weak"]


def _percent_bad(text: str) -> str | None:
    """Retry / loss percentages: small is good."""
    value = _first_float(text)
    if value is None:
        return None
    for limit, key in ((2, "excellent"), (5, "good"), (10, "fair"), (20, "weak")):
        if value < limit:
            return SEMANTIC[key]
    return SEMANTIC["very weak"]


def _score_bad(text: str) -> str | None:
    """0–100 abuse / risk scores: high is bad."""
    value = _first_float(text)
    if value is None:
        return None
    for limit, key in ((1, "excellent"), (25, "good"), (50, "fair"), (75, "weak")):
        if value < limit:
            return SEMANTIC[key]
    return SEMANTIC["very weak"]


def _count_bad(text: str) -> str | None:
    """Error / drop counters: zero is good, anything else wants a look."""
    value = _first_float(text.replace(",", ""))
    if value is None:
        return None
    return SEMANTIC["excellent"] if value == 0 else SEMANTIC["weak"]


def _grade(text: str) -> str | None:
    grade = text.strip().upper()[:2]
    if grade.startswith("A"):
        return SEMANTIC["excellent"]
    if grade.startswith("B"):
        return SEMANTIC["good"]
    if grade.startswith("C"):
        return SEMANTIC["fair"]
    if grade[:1] in ("D", "E"):
        return SEMANTIC["weak"]
    if grade[:1] in ("F", "T", "M"):
        return SEMANTIC["very weak"]
    return None


def _cvss(text: str) -> str | None:
    value = _first_float(text)
    if value is None:
        return None
    for limit, key in ((4, "good"), (7, "fair"), (9, "weak")):
        if value < limit:
            return SEMANTIC[key]
    return SEMANTIC["very weak"]


def _epss(text: str) -> str | None:
    """EPSS percentages: the chance of exploitation in the next 30 days."""
    value = _first_float(text)
    if value is None:
        return None
    for limit, key in ((1, "excellent"), (5, "good"), (20, "fair"), (50, "weak")):
        if value < limit:
            return SEMANTIC[key]
    return SEMANTIC["very weak"]


def _fixed(key: str) -> Callable[[str], str]:
    return lambda _text: SEMANTIC[key]


# Column / key name -> rule. Names are matched upper-cased and trimmed.
COLUMN_RULES: dict[str, Callable[[str], str | None]] = {
    "SSID": lambda t: SEMANTIC["hidden"] if "<hidden>" in t else SEMANTIC["ssid"],
    "NETWORKS (UNIQUE SSID)": None,
    "CH": _channel, "CHANNEL": _channel,
    "BAND": band_colour, "BANDS": None,
    "SIGNAL": _signal, "QUALITY": _signal, "DBM": _signal, "STRONGEST": _signal,
    "SIGNAL NOW": _signal, "RANGE": None, "BEST / WORST SEEN": None,
    "SECURITY": _security,
    "BSSID": _fixed("mac"), "MAC": _fixed("mac"), "ACCESS POINT": None,
    "AP VENDOR": _vendor, "VENDOR": _vendor, "NIC VENDOR": _vendor,
    "ORGANISATION": _fixed("vendor"), "OWNER": _fixed("vendor"),
    "PROVIDER": _fixed("vendor"), "ISP": _fixed("vendor"), "ORG": _fixed("vendor"),
    "HOSTNAME": _fixed("hostname"), "NAME": _fixed("hostname"),
    "NAME / WHERE": _fixed("hostname"), "SERVER NAME": _fixed("hostname"),
    "DOMAIN": _fixed("hostname"), "RESOLVES TO": None, "NAMES": _fixed("hostname"),
    "DEVICE": _fixed("device"), "LIKELY DEVICE": _fixed("device"),
    "LOCATION / DEVICE": _fixed("device"), "THIS LOOKS LIKE": _fixed("device"),
    "PROTO": _protocol, "PROTOCOL": _protocol, "PROTOCOLS": _protocol,
    "STATE": _state, "LINK": _state, "OPER": _state,
    "SERVICE": _fixed("service"), "PROCESS": _fixed("process"),
    "PORT": _fixed("port"), "PORTS": _fixed("port"),
    "LEVEL": _level, "SEVERITY": _level,
    "STATUS": _status, "RESULT": _status, "VERDICT": _status,
    "RTT": _rtt, "LATENCY": _rtt,
    "RETRANSMITTED": _percent_bad, "RETRIES, LAST INTERVAL / WORST": _percent_bad,
    "LOSS": _percent_bad,
    "SCORE": _score_bad, "CONFIDENCE": _score_bad, "ABUSE SCORE": _score_bad,
    "ERRORS": _count_bad, "DROPS": _count_bad, "ERRORS Δ": _count_bad,
    "ERRORS / DROPS": _count_bad, "FAILED TO SEND": _count_bad,
    "BEACONS MISSED": _count_bad, "BEACONS MISSED WHILE WATCHING": _count_bad,
    "GRADE": _grade, "CVSS": _cvss, "EPSS (30-DAY)": _epss, "EPSS": _epss,
    "KEV": _status, "SUPPORT ENDS": _fixed("time"), "END OF LIFE": _fixed("time"),
    "RELEASED": _fixed("time"), "RELEASE": _fixed("service"),
    "LATEST": _fixed("service"),
    "COUNTRY": _fixed("country"), "REGISTRY / COUNTRY": _fixed("country"),
    "COUNTRYCODE": _fixed("country"),
    "AS": _fixed("asn"), "ASN": _fixed("asn"), "ORIGIN AS": _fixed("asn"),
    "SYSTIME": _fixed("time"), "TIME": _fixed("time"), "DATE": _fixed("time"),
    "WHEN": _fixed("time"), "WHEN (UTC)": _fixed("time"), "FIRST SEEN": _fixed("time"),
    "LAST SEEN": _fixed("time"), "PUBLISHED": _fixed("time"), "ADDED": _fixed("time"),
    "CHECKED (UTC)": _fixed("time"), "STARTED (UTC)": _fixed("time"),
    "EXPIRES": _fixed("time"), "ISSUED": _fixed("time"), "Δt": _fixed("time"),
    "URL": _fixed("url"), "CVE": _fixed("cve"),
}

# Names that aren't listed exactly but start with one of these.
PREFIX_RULES: list[tuple[str, Callable[[str], str | None]]] = [
    ("SIGNAL", None), ("CHANNEL", None), ("SSID", None),
]


def _column_rule(column: str):
    name = (column or "").strip().upper()
    if name in COLUMN_RULES:
        return COLUMN_RULES[name]
    for prefix, rule in PREFIX_RULES:
        if name.startswith(prefix):
            return rule
    return None


# Composite cells that need per-part colouring rather than one colour.
def _composite(column: str, text: str, out: Text) -> None:
    name = (column or "").strip().upper()
    if name.startswith("CHANNEL") and "/" in name or name == "CHANNEL / BAND":
        match = re.match(r"\s*(?:ch\s*)?(\d+)", text)
        if match:
            out.stylize(channel_colour(int(match.group(1))), match.start(1), match.end(1))
    if name in ("RANGE", "BEST / WORST SEEN") or name.startswith("SIGNAL NOW /"):
        for match in re.finditer(r"-\d{2,3}", text):
            out.stylize(signal_colour(int(match.group(0))), match.start(), match.end())


# ------------------------------------------------------------ links
def _link_for(token: str, colour: str) -> Style | str:
    """URLs, CVE ids and AS numbers become clickable (OSC 8) in terminals
    that support hyperlinks; elsewhere they are only coloured."""
    from . import termcaps

    if not termcaps.current().hyperlinks:
        return colour
    if token.startswith(("http://", "https://")):
        url = token.rstrip(".,);]'\"")
    elif token.upper().startswith("CVE-"):
        url = f"https://nvd.nist.gov/vuln/detail/{token.upper()}"
    elif token.upper().startswith("AS") and token[2:].isdigit():
        url = f"https://bgp.he.net/{token.upper()}"
    else:
        return colour
    return Style(color=colour, link=url)


_LINKABLE = {SEMANTIC["url"], SEMANTIC["cve"], SEMANTIC["asn"]}


# ------------------------------------------------------------ entry point
MUTED_VALUES = {"", "—", "-", "–", "n/a", "none open", "no results."}


def style_cell(column: str | None, value: object, foreground: str,
               muted: str | None = None) -> Text | None:
    """The coloured Text for one table cell or key/value value, or None to
    leave it to the default rendering (non-string values, Text already)."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    text = str(value)
    if text.strip().lower() in MUTED_VALUES:
        return Text(text or "—", style=muted or SEMANTIC["muted"])
    rule = _column_rule(column or "")
    colour = None
    if rule is not None:
        try:
            colour = rule(text)
        except (ValueError, TypeError):
            colour = None
    out = Text(text, style=colour or foreground)
    for pattern, pick in TOKENS:
        for match in pattern.finditer(text):
            try:
                token_colour = pick(match.group(0))
            except (ValueError, TypeError):
                continue
            if token_colour:
                if token_colour in _LINKABLE:
                    token_colour = _link_for(match.group(0), token_colour)
                out.stylize(token_colour, match.start(), match.end())
    _composite(column or "", text, out)
    return out
