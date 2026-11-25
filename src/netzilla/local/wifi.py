"""Wi-Fi / RF analysis — netzilla's take on inSSIDer.

Everything here is a pure function over the output of tools that already ship
on a Linux desktop, so the whole module is unit-testable without a radio,
root, or any of the tools installed:

  nmcli -t -f ... dev wifi list   the friendly path: no root, signal as a
                                  quality %, one AP per line
  iw dev <iface> scan             the detailed path: exact dBm, precise
                                  channel width and security, but it needs
                                  CAP_NET_ADMIN (root, or the fix on TOOL
                                  CHECK) and briefly interrupts the link

Both are parsed into the same access-point record, so the rest of netzilla
does not care which one produced it:

  {bssid, ssid, freq_mhz, channel, band, signal_dbm, signal_pct,
   security, rate_mbps, in_use}

The scan is a passive read of the beacon frames every access point already
broadcasts — the same thing your phone's Wi-Fi list shows. netzilla does not
transmit, associate, deauth or crack anything, and there is nothing here for
attacking a network.
"""

from __future__ import annotations

import re

from .runner import have, run

# ------------------------------------------------------------- interfaces
_IW_DEV_RE = re.compile(r"^\s*Interface\s+(\S+)", re.M)


def parse_iw_dev(text: str) -> list[str]:
    """Wireless interface names from `iw dev`."""
    return _IW_DEV_RE.findall(text or "")


def parse_nmcli_devices(text: str) -> list[str]:
    """Wi-Fi interface names from `nmcli -t -f DEVICE,TYPE dev`."""
    found = []
    for line in (text or "").splitlines():
        parts = _split_nmcli(line)
        if len(parts) >= 2 and parts[1] == "wifi":
            found.append(parts[0])
    return found


async def wireless_interfaces() -> list[str]:
    """Every wireless interface on the box, however we can find it."""
    if have("iw"):
        result = await run(["iw", "dev"], timeout=6)
        names = parse_iw_dev(result.output)
        if names:
            return names
    if have("nmcli"):
        result = await run(
            ["nmcli", "-t", "-f", "DEVICE,TYPE", "dev"], timeout=6
        )
        names = parse_nmcli_devices(result.output)
        if names:
            return names
    # Last resort: the kernel lists wireless interfaces in /proc.
    try:
        with open("/proc/net/wireless") as handle:
            lines = handle.read().splitlines()[2:]
        return [line.split(":")[0].strip() for line in lines if ":" in line]
    except OSError:
        return []


# --------------------------------------------------------- band / channel
def band_of(freq_mhz: int) -> str:
    if 2400 <= freq_mhz <= 2500:
        return "2.4 GHz"
    if 4900 <= freq_mhz <= 5900:
        return "5 GHz"
    if 5925 <= freq_mhz <= 7125:
        return "6 GHz"
    return "?"


def channel_of(freq_mhz: int) -> int:
    """The Wi-Fi channel number for a centre frequency in MHz."""
    if freq_mhz == 2484:
        return 14
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    if 5000 <= freq_mhz <= 5900:
        return (freq_mhz - 5000) // 5
    if 5925 <= freq_mhz <= 7125:
        return (freq_mhz - 5950) // 5 + 1
    return 0


# The classic non-overlapping 2.4 GHz set. Everything else steps on a
# neighbour, which is the whole point of the interference view.
NON_OVERLAPPING_24 = (1, 6, 11)


def overlaps_24(channel_a: int, channel_b: int) -> bool:
    """Do two 2.4 GHz channels share spectrum?

    Each channel is 5 MHz apart but ~22 MHz wide, so anything closer than
    five channels away overlaps. 1, 6 and 11 are the usual clean set.
    """
    return channel_a != channel_b and abs(channel_a - channel_b) < 5


# ---------------------------------------------------------------- signal
def pct_to_dbm(percent: float) -> int:
    """nmcli reports link quality 0-100; approximate it back to dBm.

    NetworkManager's own mapping is roughly linear from -100 dBm (0%) to
    -50 dBm (100%), which is what wpa_supplicant feeds it. It is an estimate,
    and netzilla labels it as one wherever it is shown.
    """
    percent = max(0.0, min(100.0, percent))
    return int(round(percent / 2.0 - 100.0))


def signal_label(dbm: float) -> str:
    if dbm >= -50:
        return "excellent"
    if dbm >= -60:
        return "good"
    if dbm >= -70:
        return "fair"
    if dbm >= -80:
        return "weak"
    return "very weak"


_RAMP = "▁▂▃▄▅▆▇█"


def sparkline(values: list[float], floor: float = -90.0, ceil: float = -30.0) -> str:
    """A block-glyph line for a run of dBm readings, fixed to a sensible
    window so a flat-but-strong signal does not look like a flat-but-weak one."""
    if not values:
        return ""
    span = ceil - floor
    out = []
    for value in values:
        clamped = max(floor, min(ceil, value))
        step = int((clamped - floor) / span * (len(_RAMP) - 1)) if span else 0
        out.append(_RAMP[max(0, min(len(_RAMP) - 1, step))])
    return "".join(out)


# ---------------------------------------------------------- security tidy
def tidy_security(raw: str) -> str:
    """Normalise the many ways the tools spell encryption into one label."""
    text = (raw or "").upper().strip()
    if not text or text in ("--", "NONE", "(NONE)", "ESS"):
        return "Open"
    if "WPA3" in text or "SAE" in text:
        return "WPA3" + (" (Enterprise)" if "802.1X" in text or "EAP" in text else "")
    if "WPA2" in text or "RSN" in text:
        return "WPA2" + (" (Enterprise)" if "802.1X" in text or "EAP" in text else "")
    if "WPA" in text:
        return "WPA"
    if "WEP" in text:
        return "WEP (insecure)"
    return raw.strip()


# ----------------------------------------------------------- nmcli parser
def _split_nmcli(line: str) -> list[str]:
    r"""Split an `nmcli -t` line on unescaped colons.

    nmcli's terse mode uses ':' as the separator and backslash-escapes any
    real colon in a value — which every BSSID is full of (AA\:BB\:CC...).
    """
    fields, current, i = [], [], 0
    while i < len(line):
        char = line[i]
        if char == "\\" and i + 1 < len(line):
            current.append(line[i + 1])
            i += 2
            continue
        if char == ":":
            fields.append("".join(current))
            current = []
            i += 1
            continue
        current.append(char)
        i += 1
    fields.append("".join(current))
    return fields


# Ask nmcli for exactly these columns, in this order.
NMCLI_FIELDS = "IN-USE,BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY,RATE"


def parse_nmcli_scan(text: str) -> list[dict]:
    """Access points from `nmcli -t -f <NMCLI_FIELDS> dev wifi list`."""
    found = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parts = _split_nmcli(line)
        if len(parts) < 8:
            continue
        in_use, bssid, ssid, chan, freq, signal, security, rate = parts[:8]
        try:
            freq_mhz = int(re.sub(r"[^\d]", "", freq) or 0)
        except ValueError:
            freq_mhz = 0
        try:
            pct = float(signal or 0)
        except ValueError:
            pct = 0.0
        try:
            channel = int(chan)
        except ValueError:
            channel = channel_of(freq_mhz)
        rate_mbps = _first_int(rate)
        found.append({
            "bssid": bssid.upper(),
            "ssid": ssid or "<hidden>",
            "freq_mhz": freq_mhz,
            "channel": channel,
            "band": band_of(freq_mhz),
            "signal_dbm": pct_to_dbm(pct),
            "signal_pct": int(pct),
            "security": tidy_security(security),
            "rate_mbps": rate_mbps,
            "in_use": in_use.strip() in ("*", "yes", "*yes"),
        })
    return found


# ------------------------------------------------------------- iw parser
def parse_iw_scan(text: str) -> list[dict]:
    """Access points from `iw dev <iface> scan` — exact dBm and channel."""
    blocks = re.split(r"(?m)^BSS\s+", text or "")
    found = []
    for block in blocks[1:]:
        bssid_match = re.match(r"([0-9a-fA-F:]{17})", block)
        if not bssid_match:
            continue
        bssid = bssid_match.group(1).upper()
        freq = _search_int(r"freq:\s*(\d+)", block)
        signal = _search_float(r"signal:\s*(-?\d+(?:\.\d+)?)\s*dBm", block)
        ssid = _iw_ssid(block)
        channel = _search_int(r"(?:DS Parameter set|primary channel):.*?(\d+)", block)
        if not channel:
            channel = channel_of(freq)
        rate_mbps = _iw_max_rate(block)
        security = _iw_security(block)
        width_mhz, centre = _iw_width(block, channel)
        found.append({
            "bssid": bssid,
            "ssid": ssid,
            "freq_mhz": freq,
            "channel": channel,
            "band": band_of(freq),
            "signal_dbm": int(round(signal)) if signal is not None else 0,
            "signal_pct": _dbm_to_pct(signal) if signal is not None else 0,
            "security": security,
            "rate_mbps": rate_mbps,
            "in_use": "associated" in block.lower(),
            # How wide the channel is and where it is centred (a 40/80 MHz
            # network occupies more than its primary channel) — the spectrum
            # graph draws each network over everything it really uses.
            "width_mhz": width_mhz,
            "centre_channel": centre,
            # How long ago the radio last heard this AP ("last seen: 196 ms
            # ago") — a cached result's age, so a live view can tell a fresh
            # reading from one it has already shown.
            "last_seen_ms": _search_int(r"last seen:\s*(\d+)\s*ms", block) if
            "last seen:" in block else None,
        })
    return found


_IW_SSID_RE = re.compile(r"^[ \t]*SSID:[ \t]?([^\n]*)$", re.M)


def _iw_width(block: str, channel: int | None) -> tuple[int, int | None]:
    """(channel width in MHz, centre channel) from the HT/VHT operation
    elements of an iw scan; (20, primary channel) when nothing says wider."""
    vht = re.search(r"VHT operation:(.*?)(?:\n\t[A-Z]|\Z)", block, re.S)
    if vht:
        width = re.search(r"channel width:\s*\d+\s*\((\d+)", vht.group(1))
        seg1 = re.search(r"center freq segment 1:\s*(\d+)", vht.group(1))
        seg2 = re.search(r"center freq segment 2:\s*(\d+)", vht.group(1))
        if width and int(width.group(1)) >= 80:
            mhz = int(width.group(1))
            centre = int(seg1.group(1)) if seg1 and int(seg1.group(1)) else channel
            if seg2 and int(seg2.group(1)) and seg1 and \
                    abs(int(seg2.group(1)) - int(seg1.group(1))) == 8:
                mhz, centre = 160, int(seg2.group(1))
            return mhz, centre
    offset = re.search(r"secondary channel offset:\s*(above|below)", block)
    if offset and channel:
        return 40, channel + (2 if offset.group(1) == "above" else -2)
    return 20, channel


def _iw_ssid(block: str) -> str:
    """The SSID line's own value. A hidden network prints an empty "SSID:"
    (or one made of \\x00 escapes); matching across the line end would take
    the next line — "Supported rates: …" — as the network's name."""
    match = _IW_SSID_RE.search(block)
    name = match.group(1).strip() if match else ""
    if not name or not name.replace("\\x00", "").strip():
        return "<hidden>"
    return name


def _iw_security(block: str) -> str:
    has_rsn = "RSN:" in block
    has_wpa = "WPA:" in block
    has_sae = "SAE" in block or "WPA3" in block
    has_eap = "802.1X" in block or "IEEE 802.1X" in block
    has_privacy = "Privacy" in block
    if has_sae:
        return "WPA3 (Enterprise)" if has_eap else "WPA3"
    if has_rsn:
        return "WPA2 (Enterprise)" if has_eap else "WPA2"
    if has_wpa:
        return "WPA"
    if has_privacy:
        return "WEP (insecure)"
    return "Open"


def _iw_max_rate(block: str) -> int:
    rates = [float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s*(?:Mbps|MBit/s)", block)]
    return int(max(rates)) if rates else 0


def _dbm_to_pct(dbm: float) -> int:
    return int(round(max(0.0, min(100.0, (dbm + 100.0) * 2.0))))


# ------------------------------------------------- channel congestion view
def channel_usage(aps: list[dict], band: str = "2.4 GHz") -> list[dict]:
    """Per-channel AP count and combined signal for one band."""
    tally: dict[int, dict] = {}
    for ap in aps:
        if ap["band"] != band or not ap["channel"]:
            continue
        entry = tally.setdefault(
            ap["channel"], {"channel": ap["channel"], "count": 0, "strongest": -120}
        )
        entry["count"] += 1
        entry["strongest"] = max(entry["strongest"], ap["signal_dbm"])
    return sorted(tally.values(), key=lambda e: e["channel"])


def congestion_by_channel(aps: list[dict]) -> dict[int, int]:
    """How many APs sit on or overlap each 2.4 GHz channel — the number that
    actually matters, since an AP on channel 4 interferes with channel 6."""
    on_channel = [ap["channel"] for ap in aps if ap["band"] == "2.4 GHz" and ap["channel"]]
    result = {}
    for channel in NON_OVERLAPPING_24:
        result[channel] = sum(
            1 for other in on_channel if other == channel or overlaps_24(channel, other)
        )
    return result


def recommend_channel_24(aps: list[dict]) -> tuple[int, str]:
    """The least-congested of 1/6/11, with a one-line reason."""
    congestion = congestion_by_channel(aps)
    if not any(ap["band"] == "2.4 GHz" for ap in aps):
        return 0, "No 2.4 GHz networks were seen, so there is nothing to avoid."
    best = min(NON_OVERLAPPING_24, key=lambda channel: congestion[channel])
    load = ", ".join(f"ch {c}: {congestion[c]}" for c in NON_OVERLAPPING_24)
    return best, (
        f"Channel {best} has the fewest overlapping networks ({load}). "
        "1, 6 and 11 are the only 2.4 GHz channels that do not overlap each "
        "other, so one of those three is almost always the right answer."
    )


# --------------------------------------------------------------- helpers
def bssid_key(value: str) -> str:
    """A BSSID with case and separators removed: 'aa-bb-cc-dd-ee-ff',
    'AA:BB:CC:DD:EE:FF' and 'aabb.ccdd.eeff' are the same access point."""
    digits = re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()
    return digits if len(digits) == 12 else ""


def pick_ap(aps: list[dict], target: str) -> dict | None:
    """Find an AP by BSSID (any case or separator) or SSID (ignoring case)."""
    target = (target or "").strip()
    if not target:
        return None
    wanted = bssid_key(target)
    if wanted:
        for ap in aps:
            if bssid_key(ap.get("bssid", "")) == wanted:
                return ap
    lower = target.lower()
    for ap in aps:
        if (ap.get("ssid") or "").lower() == lower:
            return ap
    return None


def band_summary(aps: list[dict]) -> list[tuple[str, object]]:
    bands: dict[str, int] = {}
    for ap in aps:
        bands[ap["band"]] = bands.get(ap["band"], 0) + 1
    secured = sum(1 for ap in aps if ap["security"] != "Open")
    return [
        ("Access points seen", len(aps)),
        ("Networks (unique SSID)", len({ap["ssid"] for ap in aps})),
        ("Bands", ", ".join(f"{band}: {n}" for band, n in sorted(bands.items())) or "—"),
        ("Open networks", len(aps) - secured),
        ("Strongest", _strongest_label(aps)),
    ]


def _strongest_label(aps: list[dict]) -> str:
    if not aps:
        return "—"
    top = max(aps, key=lambda ap: ap["signal_dbm"])
    return f'{top["ssid"]} ({top["signal_dbm"]} dBm, ch {top["channel"]})'


def _first_int(text: str) -> int:
    match = re.search(r"\d+", text or "")
    return int(match.group()) if match else 0


def _search_int(pattern: str, text: str) -> int:
    match = re.search(pattern, text)
    return int(match.group(1)) if match else 0


def _search_float(pattern: str, text: str):
    match = re.search(pattern, text)
    return float(match.group(1)) if match else None


# --------------------------------------------------------------- scanning
async def scan(
    iface: str = "", prefer: str = "auto", rescan: bool = False,
) -> tuple[list[dict], str, str]:
    """(access points, backend used, error).

    Tries nmcli first because it needs no privilege; falls back to `iw scan`
    (which does) only when asked or when nmcli is absent. rescan asks
    NetworkManager for a fresh scan rather than its cached list (WATCH AIR);
    NetworkManager refuses those when asked too often, and then the cached
    list is used instead.
    """
    if prefer in ("auto", "nmcli") and have("nmcli"):
        argv = ["nmcli", "-t", "-f", NMCLI_FIELDS, "dev", "wifi", "list"]
        result = None
        if rescan:
            result = await run(argv + ["--rescan", "yes"], timeout=25,
                               ok_returncodes=(0,))
            if not (result.ok and result.output.strip()):
                result = None
        if result is None:
            result = await run(argv, timeout=20, ok_returncodes=(0, 1))
        if result.ok and result.output.strip():
            aps = parse_nmcli_scan(result.output)
            if aps:
                return aps, "nmcli", ""
    if prefer in ("auto", "iw") and have("iw"):
        argv = ["iw", "dev", iface or "", "scan"] if iface else None
        if argv is None:
            return [], "iw", "iw scan needs an interface name — pick one first."
        result = await run(argv, timeout=25, ok_returncodes=(0, 1, 2, 240))
        if result.ok and result.output.strip():
            return parse_iw_scan(result.output), "iw", ""
        if "Operation not permitted" in (result.error or "") or result.error and "root" in result.error.lower():
            return [], "iw", "iw scan needs root — see TOOL CHECK for the one-time fix."
        if "network is down" in (result.error or "").lower():
            return [], "iw", (
                f"{iface} is down: Wi-Fi is switched off or the interface is "
                "disabled, so there is nothing to scan with. Turn Wi-Fi on "
                "(nmcli radio wifi on) — or, if it is blocked, rfkill unblock wifi.")
        return [], "iw", result.error or "iw returned nothing."
    if not have("nmcli") and not have("iw"):
        return [], "", "Neither nmcli nor iw is installed."
    return [], "", "No access points were seen. Is the radio on and unblocked (rfkill)?"


# ---------------------------------------------------------- live scanning
# A full scan tunes the radio through every channel and takes 2–4 seconds on
# most adapters, whoever asks for it. A live view that waited for one on every
# tick could never refresh faster than that. Instead it reads the latest
# *finished* results, which cost nothing to read, and keeps new scans going
# in the background (scan_trigger); each result is only as old as the last
# scan that completed.

async def scan_cached(iface: str = "", prefer: str = "auto") -> tuple[list[dict], str, str]:
    """(access points, backend, error) from the latest completed scan,
    without starting or waiting for a new one.

    `iw dev <if> scan dump` reads the kernel's scan results — exact dBm, and
    how long ago each AP was last heard — and needs no privilege; it sees
    NetworkManager's scans as well as netzilla's. NetworkManager's own list
    (`--rescan no`) is the fallback.
    """
    if prefer in ("auto", "iw") and iface and have("iw"):
        result = await run(["iw", "dev", iface, "scan", "dump"], timeout=8,
                           ok_returncodes=(0, 1, 2, 240))
        if result.ok and result.output.strip():
            aps = parse_iw_scan(result.output)
            if aps:
                return aps, "iw", ""
    if prefer in ("auto", "nmcli") and have("nmcli"):
        argv = ["nmcli", "-t", "-f", NMCLI_FIELDS, "dev", "wifi", "list"]
        result = await run(argv + ["--rescan", "no"], timeout=10, ok_returncodes=(0, 1))
        if not (result.ok and result.output.strip()):
            result = await run(argv, timeout=10, ok_returncodes=(0, 1))
        if result.ok and result.output.strip():
            aps = parse_nmcli_scan(result.output)
            if aps:
                return aps, "nmcli", ""
    return await scan(iface, prefer=prefer)


async def scan_trigger(iface: str = "", use_iw: bool = False) -> bool:
    """Ask for a new scan and return at once; True if one was started.

    `iw dev <if> scan trigger` needs the scan capability (DEEP SCAN's
    setup); otherwise NetworkManager is asked, which needs nothing. Either
    refuses while a scan is already running, or — NetworkManager — when
    asked too soon after the last; that is harmless, the next request goes
    through.
    """
    if use_iw and iface and have("iw"):
        result = await run(["iw", "dev", iface, "scan", "trigger"], timeout=6,
                           ok_returncodes=(0,))
        return result.ok
    if have("nmcli"):
        argv = ["nmcli", "device", "wifi", "rescan"] + (["ifname", iface] if iface else [])
        result = await run(argv, timeout=10, ok_returncodes=(0,))
        return result.ok
    return False


async def can_trigger_with_iw(iface: str) -> bool:
    """Whether this machine may start scans with iw (CAP_NET_ADMIN)."""
    if not (iface and have("iw")):
        return False
    result = await run(["iw", "dev", iface, "scan", "trigger"], timeout=6,
                       ok_returncodes=(0, 16, 240))
    text = (result.error or "") + (result.output or "")
    if "not permitted" in text.lower():
        return False
    return result.ok or "busy" in text.lower()      # busy = allowed, already scanning


INSTALL_HINTS = (
    "nmcli ships with NetworkManager and needs no root to scan:\n"
    "    (already present on Ubuntu, Mint and most desktops)\n\n"
    "iw gives exact dBm and channel width but needs privilege to scan:\n"
    "    sudo apt install -y iw\n"
    "    sudo setcap cap_net_admin,cap_net_raw+eip $(which iw)\n\n"
    "If no networks appear at all, the radio may be soft-blocked:\n"
    "    rfkill list          # look for 'Soft blocked: yes'\n"
    "    rfkill unblock wifi"
)
