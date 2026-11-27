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

Windows and macOS have neither tool, and get the same record from their own:

  Windows   the Native Wi-Fi API (wlanapi.py): exact dBm, frequency, width
            and security from each beacon — `netsh wlan show networks
            mode=bssid` is the fallback
  macOS     `system_profiler SPAirPortDataType -json` (no BSSIDs: macOS keeps
            them from command-line tools), or on releases before 14.4 the
            old `airport -s`, which still gives them

The scan is a passive read of the beacon frames every access point already
broadcasts — the same thing your phone's Wi-Fi list shows. netzilla does not
transmit, associate, deauth or crack anything, and there is nothing here for
attacking a network.
"""

from __future__ import annotations

import asyncio
import json
import re

from .. import hostos
from . import wlanapi
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
    if hostos.is_windows():
        return await _windows_wireless()
    if hostos.is_macos():
        return await _macos_wireless()
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


async def _windows_wireless() -> list[str]:
    """Wi-Fi adapters by the names Windows shows ("Wi-Fi", "Wi-Fi 2")."""
    found, _error = await asyncio.to_thread(wlanapi.interfaces)
    if found:
        return [entry["name"] for entry in found]
    if have("netsh"):
        result = await run(["netsh", "wlan", "show", "interfaces"], timeout=10,
                           ok_returncodes=(0, 1))
        names = [a["name"] for a in parse_netsh_interfaces(result.output)]
        if names:
            return names
    from . import netif

    adapters = await asyncio.to_thread(netif._windows_adapters)
    return [a["name"] for a in netif.windows_interfaces(adapters) if a.get("kind") == "wireless"]


async def _macos_wireless() -> list[str]:
    """Wi-Fi interfaces from the hardware ports ("Wi-Fi: en0")."""
    from . import netif

    ports = await netif.macos_hardware_ports()
    return [device for device, port in ports.items() if netif.port_kind(port) == "wireless"]


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
    if freq_mhz == 5935:                 # 6 GHz channel 2, below channel 1
        return 2
    if 5950 < freq_mhz <= 7125:          # channel 1 is 5955 MHz
        return (freq_mhz - 5950) // 5
    return 0


def freq_for(channel: int, band: str = "") -> int:
    """The centre frequency of a channel in MHz — channel_of() backwards —
    or 0 when it can't be told. Without a band, 1–14 is 2.4 GHz and the
    rest 5 GHz."""
    if not channel:
        return 0
    band = band or ("2.4 GHz" if channel <= 14 else "5 GHz")
    if band.startswith("2"):
        return 2484 if channel == 14 else 2407 + 5 * channel
    if band.startswith("5"):
        return 5000 + 5 * channel
    if band.startswith("6"):
        return 5935 if channel == 2 else 5950 + 5 * channel
    return 0


# Centre channels of the 5 GHz 40/80/160 MHz blocks.
_CENTRES_5 = {
    40: (38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175),
    80: (42, 58, 106, 122, 138, 155, 171),
    160: (50, 114, 163),
}


def centre_channel(primary: int, width: int, band: str) -> int:
    """Where a 40/80/160 MHz network is centred, from its primary channel —
    for tools that give only the width (macOS)."""
    if not primary or width <= 20:
        return primary
    if band == "6 GHz":
        block = width // 5                 # channel numbers per block
        start = (primary - 1) // block * block + 1
        return start + (block - 4) // 2
    if band == "5 GHz":
        for centre in _CENTRES_5.get(width, ()):
            if abs(primary - centre) <= width // 10:
                return centre
    return primary


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
    if not text or text in ("--", "NONE", "(NONE)", "ESS", "OPEN"):
        return "Open"
    enterprise = "802.1X" in text or "EAP" in text or "ENTERPRISE" in text
    if "WPA3" in text or "SAE" in text:
        return "WPA3" + (" (Enterprise)" if enterprise else "")
    if "WPA2" in text or "RSN" in text:
        return "WPA2" + (" (Enterprise)" if enterprise else "")
    if "WPA" in text:
        return "WPA"
    if "WEP" in text:
        return "WEP (insecure)"
    if "OWE" in text:
        return "OWE"
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


# ---------------------------------------------------- Windows: the Wi-Fi API
def from_wlanapi(entry: dict, joined_bssid: str = "") -> dict:
    """An access point from wlanapi.networks() as the scan record."""
    freq = int(entry.get("freq_mhz") or 0)
    channel = int(entry.get("channel") or 0) or channel_of(freq)
    rssi = entry.get("rssi")
    quality = int(entry.get("quality") or 0)
    bssid = (entry.get("bssid") or "").upper()
    return {
        "bssid": bssid,
        "ssid": entry.get("ssid") or "<hidden>",
        "freq_mhz": freq,
        "channel": channel,
        "band": band_of(freq) if freq else "?",
        "signal_dbm": int(rssi) if rssi is not None else pct_to_dbm(quality),
        "signal_pct": quality,
        "security": entry.get("security") or "Open",
        "rate_mbps": int(entry.get("rate_mbps") or 0),
        "in_use": bool(joined_bssid) and bssid_key(bssid) == bssid_key(joined_bssid),
        "width_mhz": int(entry.get("width_mhz") or 20),
        "centre_channel": entry.get("centre_channel") or channel,
        "last_seen_ms": entry.get("age_ms"),
    }


# --------------------------------------------------- Windows: netsh wlan
# The fallback when the Wi-Fi API can't be used. netsh translates its labels
# with Windows, so these parsers go by the shape of a value where they can
# (a MAC address, "92%", "802.11ax", "5 GHz") and by the label otherwise.
_NETSH_SSID_RE = re.compile(r"^SSID\s+\d+\s*:\s?(.*)$")
_NETSH_BSSID_RE = re.compile(
    r"^\s*(?:AP[\s-]+)?BSSID(?:\s+\d+)?\s*:\s*([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\s*$")
_MAC_VALUE_RE = re.compile(r"^[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}$")
_GUID_VALUE_RE = re.compile(r"^\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?$")
_PERCENT_RE = re.compile(r"^(\d{1,3})\s*%$")
_GHZ_RE = re.compile(r"^(\d+(?:[.,]\d+)?)\s*GHz$", re.I)
_NUMBER_RE = re.compile(r"^\d+(?:[.,]\d+)?$")
_RATE_LABEL_RE = re.compile(r"\(\s*m(?:bps|bit|b/s)", re.I)
_AUTH_LABELS = ("auth", "autent")
_CIPHER_LABELS = ("encryption", "cipher", "verschl", "chiffr", "cifrado", "crittograf",
                  "codifica", "versleuteling")
_NAME_LABELS = ("name", "nom", "nombre", "nome", "naam")
_STATE_LABELS = ("state", "status", "état", "etat", "estado", "stato")
_PROFILE_LABELS = ("profile", "profil", "perfil", "profilo", "profiel")
_CHANNEL_LABELS = ("channel", "kanal", "canal", "canale", "kanaal")


def _band_text(value: str) -> str:
    match = _GHZ_RE.match(value.strip())
    if not match:
        return ""
    number = float(match.group(1).replace(",", "."))
    return "2.4 GHz" if number < 3 else "5 GHz" if number < 5.9 else "6 GHz"


def _number(value: str) -> float | None:
    value = value.strip()
    return float(value.replace(",", ".")) if _NUMBER_RE.match(value) else None


def netsh_security(auth: str, cipher: str = "") -> str:
    """netsh's Authentication and Encryption lines as the scan's label."""
    text, code = (auth or "").upper(), (cipher or "").upper()
    if "WEP" in code or text.startswith(("SHARED", "GEMEINSAM", "PARTAG", "COMPARTID")):
        return "WEP (insecure)"
    if "OWE" in text:
        return "OWE"
    if any(word in text for word in ("WPA", "RSN", "SAE", "802.1X")):
        return tidy_security(text)
    return "Open"


def parse_netsh_networks(text: str) -> list[dict]:
    """Access points from `netsh wlan show networks mode=bssid`."""
    found: list[dict] = []
    ssid, network, current = "", [], None
    for raw in (text or "").splitlines():
        label, sep, value = raw.partition(":")
        if not sep:
            continue
        label, value = label.strip(), value.strip()
        head = _NETSH_SSID_RE.match(raw)
        if head:
            ssid, network, current = head.group(1).strip(), [], None
            continue
        bss = _NETSH_BSSID_RE.match(raw)
        if bss:
            current = {"bssid": bss.group(1).replace("-", ":").upper(), "ssid": ssid,
                       "network": network, "pct": None, "channel": 0, "band": "",
                       "rates": [], "nested": False}
            found.append(current)
            continue
        low = label.lower()
        if current is None:
            network.append((low, value))
            continue
        if not value:                    # "Bss Load:" opens a nested block
            current["nested"] = True
            continue
        percent = _PERCENT_RE.match(value)
        if percent and current["pct"] is None:
            current["pct"] = min(100, int(percent.group(1)))
        elif _band_text(value):
            current["band"] = _band_text(value)
        elif _RATE_LABEL_RE.search(label):
            current["nested"] = False
            current["rates"] += [float(x.replace(",", "."))
                                 for x in re.findall(r"\d+(?:[.,]\d+)?", value)]
        elif value.isdigit() and not current["channel"] and (
                low.startswith(_CHANNEL_LABELS) or not current["nested"]) \
                and 0 < int(value) <= 233:
            current["channel"] = int(value)
    aps = []
    for entry in found:
        auth = cipher = ""
        for low, value in entry["network"]:
            if low.startswith(_AUTH_LABELS):
                auth = value
            elif low.startswith(_CIPHER_LABELS):
                cipher = value
        values = [value for _low, value in entry["network"]]
        if not auth and len(values) >= 2:        # an unknown language: by position
            auth, cipher = values[1], values[2] if len(values) >= 3 else ""
        channel = entry["channel"]
        freq = freq_for(channel, entry["band"])
        pct = entry["pct"] or 0
        aps.append({
            "bssid": entry["bssid"],
            "ssid": entry["ssid"] or "<hidden>",
            "freq_mhz": freq,
            "channel": channel,
            "band": band_of(freq) if freq else (entry["band"] or "?"),
            "signal_dbm": pct_to_dbm(pct),
            "signal_pct": pct,
            "security": netsh_security(auth, cipher),
            "rate_mbps": int(max(entry["rates"], default=0)),
            "in_use": False,
        })
    return aps


def parse_netsh_interfaces(text: str) -> list[dict]:
    """`netsh wlan show interfaces` -> one dict per adapter: {name,
    description, guid, mac, state, connected, ssid, bssid, band, channel,
    radio, auth, cipher, rx_rate, tx_rate, signal_pct, rssi, profile}."""
    adapters: list[dict] = []
    current: dict | None = None
    for raw in (text or "").splitlines():
        label, sep, value = raw.partition(":")
        if not sep:
            continue
        label, value = label.strip(), value.strip()
        low = label.lower()
        if not value:
            continue
        if low in _NAME_LABELS or current is None:
            if current is None and low not in _NAME_LABELS and not raw[:1].isspace():
                continue                          # a header line, not an adapter
            current = {"name": value, "rates": [], "connected": False}
            adapters.append(current)
            continue
        if _GUID_VALUE_RE.match(value):
            current["guid"] = "{" + value.strip("{}").upper() + "}"
        elif "bssid" in low and _MAC_VALUE_RE.match(value):
            current["bssid"] = value.replace("-", ":").lower()
        elif _MAC_VALUE_RE.match(value) and "mac" not in current:
            current["mac"] = value.replace("-", ":").lower()
        elif low == "ssid":
            current["ssid"] = value
        elif low == "rssi":
            current["rssi"] = int(value) if re.fullmatch(r"-?\d+", value) else None
        elif _PERCENT_RE.match(value):
            current["signal_pct"] = min(100, int(_PERCENT_RE.match(value).group(1)))
        elif _band_text(value):
            current["band"] = _band_text(value)
        elif value.lower().startswith("802.11"):
            current["radio"] = value
        elif _RATE_LABEL_RE.search(label) and _number(value) is not None:
            current["rates"].append(_number(value))
        elif low.startswith(_AUTH_LABELS):
            current["auth"] = value
        elif low.startswith(_CIPHER_LABELS):
            current["cipher"] = value
        elif low.startswith(_STATE_LABELS):
            current["state"] = value
        elif low.startswith(_PROFILE_LABELS):
            current["profile"] = value
        elif value.isdigit() and "bssid" in current and "channel" not in current \
                and 0 < int(value) <= 233:
            current["channel"] = int(value)
        elif "description" not in current and len(current) <= 4:
            current["description"] = value
    for adapter in adapters:
        rates = adapter.pop("rates")
        adapter["rx_rate"] = rates[0] if rates else None
        adapter["tx_rate"] = rates[1] if len(rates) > 1 else None
        adapter["connected"] = bool(adapter.get("bssid"))
    return adapters


def netsh_problem(text: str) -> str:
    """Why netsh listed nothing, in plain words; '' if it says nothing useful."""
    low = (text or "").lower()
    if "location" in low and ("privacy" in low or "permission" in low):
        return wlanapi.LOCATION_HELP
    if "wlansvc" in low or "autoconfig" in low:
        return wlanapi.ERROR_HELP[wlanapi.ERROR_SERVICE_NOT_ACTIVE]
    if "no wireless interface" in low:
        return "Windows reports no Wi-Fi adapter."
    return ""


async def _netsh_scan(iface: str) -> tuple[list[dict], str]:
    argv = ["netsh", "wlan", "show", "networks", "mode=bssid"]
    result = await run(argv + ([f"interface={iface}"] if iface else []), timeout=20,
                       ok_returncodes=(0, 1))
    aps = parse_netsh_networks(result.output)
    if not aps and iface:
        result = await run(argv, timeout=20, ok_returncodes=(0, 1))
        aps = parse_netsh_networks(result.output)
    if aps:
        shown = await run(["netsh", "wlan", "show", "interfaces"], timeout=10,
                          ok_returncodes=(0, 1))
        joined = {bssid_key(a.get("bssid", "")) for a in parse_netsh_interfaces(shown.output)
                  if a.get("connected")}
        for ap in aps:
            ap["in_use"] = bssid_key(ap["bssid"]) in joined
        return aps, ""
    return [], netsh_problem(f"{result.output}\n{result.error}")


# Seconds SCAN waits after asking Windows for a fresh scan; drivers finish
# within four. Tests set it to 0.
WINDOWS_SCAN_WAIT = 3.5


async def _scan_windows(iface: str, fresh: bool) -> tuple[list[dict], str, str]:
    error = ""
    if wlanapi.available():
        if fresh and await asyncio.to_thread(wlanapi.request_scan, iface):
            await asyncio.sleep(WINDOWS_SCAN_WAIT)
        heard, link, error = await asyncio.to_thread(wlanapi.networks, iface)
        if heard:
            joined = link.get("bssid", "") if link.get("connected") else ""
            return [from_wlanapi(entry, joined) for entry in heard], "Windows Wi-Fi API", ""
        if error == wlanapi.LOCATION_HELP:
            return [], "Windows Wi-Fi API", error
    if have("netsh"):
        aps, problem = await _netsh_scan(iface)
        if aps:
            return aps, "netsh", ""
        error = problem or error
    return [], "Windows Wi-Fi API", error or (
        "No access points were seen. Is Wi-Fi switched on, and Airplane mode off?")


# ------------------------------------------------------------------ macOS
# `airport` lives inside a private framework, off PATH (hostos knows where).
# macOS 14.4 reduced it to a deprecation notice; older releases still scan.
AIRPORT = "airport"
_airport = {"retired": False}


def airport_usable() -> bool:
    """airport is on this Mac and still answers. 14.4 kept the program but
    left it printing a deprecation notice and nothing else; once that has
    been seen, netzilla stops asking it."""
    return not _airport["retired"] and have(AIRPORT)


def note_airport(output: str, answered: bool) -> None:
    """Remember that airport gave a deprecation notice instead of an answer."""
    if not answered and "deprecated" in (output or "").lower():
        _airport["retired"] = True

_AIRPORT_ROW_RE = re.compile(
    r"^\s*(?P<ssid>.*?)\s+(?:(?P<bssid>[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\s+)?"
    r"(?P<rssi>-\d+)\s+(?P<chan>\d+(?:,[+-]?\d+)?)\s+(?P<ht>[YN])\s+(?P<cc>\S+)\s+"
    r"(?P<sec>\S.*?)\s*$")


def parse_channel_spec(spec: str) -> tuple[int, int, int]:
    """(primary channel, width in MHz, centre channel) from airport's
    "149,+1" (40 MHz above), "6,-1", "36,80" or a plain "11"."""
    primary_text, _, extra = (spec or "").strip().partition(",")
    try:
        primary = int(primary_text)
    except ValueError:
        return 0, 20, 0
    band = "2.4 GHz" if primary <= 14 else "5 GHz"
    extra = extra.strip()
    if extra in ("+1", "-1"):
        return primary, 40, primary + (2 if extra == "+1" else -2)
    if extra in ("40", "80", "160"):
        width = int(extra)
        return primary, width, centre_channel(primary, width, band)
    return primary, 20, primary


def _mac_padded(text: str) -> str:
    """airport drops leading zeros ("0:1b:2c:…"); put them back. '' for
    anything that isn't a MAC address."""
    parts = (text or "").strip().split(":")
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p) for p in parts):
        return ""
    return ":".join(part.zfill(2) for part in parts).upper()


def parse_airport_scan(text: str) -> list[dict]:
    """Access points from `airport -s` (macOS 14.3 and earlier)."""
    found = []
    for line in (text or "").splitlines():
        if "RSSI" in line and "SSID" in line:
            continue                                   # the header
        match = _AIRPORT_ROW_RE.match(line)
        if not match:
            continue
        channel, width, centre = parse_channel_spec(match.group("chan"))
        freq = freq_for(channel)
        rssi = int(match.group("rssi"))
        ssid, bssid = match.group("ssid").strip(), match.group("bssid") or ""
        if not bssid and _mac_padded(ssid):            # a hidden network's row
            ssid, bssid = "", ssid
        found.append({
            "bssid": _mac_padded(bssid),
            "ssid": ssid or "<hidden>",
            "freq_mhz": freq,
            "channel": channel,
            "band": band_of(freq) if freq else "?",
            "signal_dbm": rssi,
            "signal_pct": _dbm_to_pct(rssi),
            "security": tidy_security(match.group("sec")),
            "rate_mbps": 0,
            "in_use": False,
            "width_mhz": width,
            "centre_channel": centre,
        })
    return found


_SP_CHANNEL_RE = re.compile(r"^\s*(\d+)(?:\s*\(\s*(\d+(?:\.\d+)?)\s*GHz(?:\s*,\s*(\d+)\s*MHz)?)?")
_SP_SIGNAL_RE = re.compile(r"(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm")


def parse_sp_channel(spec) -> tuple[int, str, int]:
    """(channel, band, width) from system_profiler's "149 (5GHz, 80MHz)"
    (older releases: a bare number, or "149,+1")."""
    if isinstance(spec, int):
        return spec, "2.4 GHz" if spec <= 14 else "5 GHz", 20
    text = str(spec or "")
    if "," in text and "(" not in text:
        primary, width, _centre = parse_channel_spec(text)
        return primary, "2.4 GHz" if primary <= 14 else "5 GHz", width
    match = _SP_CHANNEL_RE.match(text)
    if not match:
        return 0, "", 20
    channel = int(match.group(1))
    ghz = float(match.group(2)) if match.group(2) else 0.0
    band = ("2.4 GHz" if ghz < 3 else "5 GHz" if ghz < 5.9 else "6 GHz") if ghz else (
        "2.4 GHz" if channel <= 14 else "5 GHz")
    return channel, band, int(match.group(3)) if match.group(3) else 20


def parse_signal_noise(text) -> tuple[int | None, int | None]:
    """(-52, -93) from "-52 dBm / -93 dBm"."""
    match = _SP_SIGNAL_RE.search(str(text or ""))
    return (int(match.group(1)), int(match.group(2))) if match else (None, None)


def _sp_security(mode) -> str:
    text = str(mode or "").lower().replace("spairport_security_mode_", "")
    if not text:
        return "?"
    return tidy_security(text.replace("_", " "))


def _sp_network(entry, joined: bool = False) -> dict | None:
    if not isinstance(entry, dict):
        return None
    channel, band, width = parse_sp_channel(entry.get("spairport_network_channel"))
    freq = freq_for(channel, band)
    signal, noise = parse_signal_noise(entry.get("spairport_signal_noise"))
    rate = entry.get("spairport_network_rate")
    return {
        "bssid": _mac_padded(str(entry.get("spairport_network_bssid") or "")),
        "ssid": str(entry.get("_name") or "") or "<hidden>",
        "freq_mhz": freq,
        "channel": channel,
        "band": band or (band_of(freq) if freq else "?"),
        # A network listed with no reading sorts last instead of breaking.
        "signal_dbm": signal if signal is not None else -100,
        "signal_pct": _dbm_to_pct(signal) if signal is not None else 0,
        "noise_dbm": noise,
        "security": _sp_security(entry.get("spairport_security_mode")),
        "rate_mbps": int(rate) if isinstance(rate, (int, float)) else _first_int(str(rate or "")),
        "in_use": joined,
        "width_mhz": width,
        "centre_channel": centre_channel(channel, width, band),
        "phy": str(entry.get("spairport_network_phymode") or ""),
        "mcs": entry.get("spairport_network_mcs"),
    }


def parse_system_profiler(text: str) -> list[dict]:
    """`system_profiler SPAirPortDataType -json` -> one dict per Wi-Fi
    interface: {name, mac, status, current (the joined network, or None),
    networks (every network heard, the joined one first)}."""
    try:
        data = json.loads(text or "{}")
    except ValueError:
        return []
    found = []
    for block in data.get("SPAirPortDataType") or []:
        if not isinstance(block, dict):
            continue
        for iface in block.get("spairport_airport_interfaces") or []:
            if not isinstance(iface, dict):
                continue
            name = str(iface.get("_name") or "")
            if not name or name.startswith(("awdl", "llw")):
                continue                     # AirDrop's private links, not Wi-Fi
            status = str(iface.get("spairport_status_information") or "")
            status = status.replace("spairport_status_", "")
            current = _sp_network(iface.get("spairport_current_network_information"), True)
            others = [n for n in (_sp_network(e) for e in
                      iface.get("spairport_airport_other_local_wireless_networks") or []) if n]
            found.append({
                "name": name,
                "mac": str(iface.get("spairport_wireless_mac_address") or "").lower(),
                "status": status,
                "current": current,
                "networks": ([current] if current else []) + others,
            })
    return found


def _sp_pick(parsed: list[dict], iface: str) -> dict | None:
    for entry in parsed:
        if entry["name"] == iface:
            return entry
    return parsed[0] if parsed else None


async def system_profiler(iface: str = "") -> dict | None:
    """The Wi-Fi interface's entry from system_profiler (a few seconds)."""
    if not have("system_profiler"):
        return None
    result = await run(["system_profiler", "SPAirPortDataType", "-json"], timeout=40,
                       ok_returncodes=(0,))
    return _sp_pick(parse_system_profiler(result.output), iface)


async def _scan_macos(iface: str) -> tuple[list[dict], str, str]:
    if airport_usable():
        result = await run([AIRPORT, "-s"], timeout=25, ok_returncodes=(0, 1))
        aps = parse_airport_scan(result.output)
        note_airport(f"{result.output}\n{result.error}", bool(aps))
        if aps:
            info = await run([AIRPORT, "-I"], timeout=8, ok_returncodes=(0, 1))
            joined = re.search(r"^\s*BSSID:\s*(\S+)", info.output or "", re.M)
            for ap in aps:
                ap["in_use"] = bool(joined) and bssid_key(ap["bssid"]) == bssid_key(
                    _mac_padded(joined.group(1)))
            return aps, "airport", ""
    entry = await system_profiler(iface)
    if entry is None:
        return [], "system_profiler", "No Wi-Fi interface was found."
    if entry["networks"]:
        return entry["networks"], "system_profiler", ""
    if entry["status"] in ("off", "spairport_status_off"):
        return [], "system_profiler", (
            "Wi-Fi is switched off — turn it on from the menu bar or System Settings → Wi-Fi.")
    return [], "system_profiler", "No access points were seen. Is Wi-Fi switched on?"


# --------------------------------------------------------------- scanning
async def scan(
    iface: str = "", prefer: str = "auto", rescan: bool = False,
) -> tuple[list[dict], str, str]:
    """(access points, backend used, error).

    Tries nmcli first because it needs no privilege; falls back to `iw scan`
    (which does) only when asked or when nmcli is absent. rescan asks
    NetworkManager for a fresh scan rather than its cached list (WATCH AIR);
    NetworkManager refuses those when asked too often, and then the cached
    list is used instead. Windows and macOS use their own scanners, whatever
    `prefer` says.
    """
    if hostos.is_windows():
        return await _scan_windows(iface, fresh=True)
    if hostos.is_macos():
        return await _scan_macos(iface)
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
    (`--rescan no`) is the fallback. Windows keeps its latest results too;
    macOS has no such list, so each read there is a scan of its own.
    """
    if hostos.is_windows():
        return await _scan_windows(iface, fresh=False)
    if hostos.is_macos():
        return await _scan_macos(iface)
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
    through. Windows is asked through its Wi-Fi API; macOS scans whenever
    it is read, so there is nothing to start.
    """
    if hostos.is_windows():
        return await asyncio.to_thread(wlanapi.request_scan, iface)
    if hostos.is_macos():
        return False
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
    if not hostos.is_linux() or not (iface and have("iw")):
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

WINDOWS_HINTS = (
    "Windows' own Wi-Fi API does the scanning: nothing to install, and no\n"
    "Administrator needed. It gives exact dBm, channel width and security.\n\n"
    "Windows 11 (24H2 and later) shares nearby networks only with apps\n"
    "allowed to use the location:\n"
    "    Settings → Privacy & security → Location\n"
    "    Location services: On, and 'Let desktop apps access your location': On\n\n"
    "If no networks appear at all, check that Wi-Fi is on and Airplane mode\n"
    "is off, and that the WLAN AutoConfig service is running (services.msc)."
)

MACOS_HINTS = (
    "macOS's own system_profiler does the scanning: nothing to install, and\n"
    "no sudo needed. Each scan takes a few seconds.\n\n"
    "Since macOS 14.4, command-line tools no longer see access points' MAC\n"
    "addresses (BSSIDs), so the AP vendor column stays empty and two access\n"
    "points with one name on one channel show as one. Older releases still\n"
    "have the airport tool, which netzilla uses when it works.\n\n"
    "If network names show as <redacted>, macOS is keeping them from apps\n"
    "without Location Services permission: System Settings → Privacy &\n"
    "Security → Location Services, and allow your terminal app if listed.\n\n"
    "If no networks appear, check that Wi-Fi is on (menu bar → Wi-Fi)."
)


def install_hints() -> str:
    """How to get Wi-Fi scanning working on this system."""
    if hostos.is_windows():
        return WINDOWS_HINTS
    if hostos.is_macos():
        return MACOS_HINTS
    return INSTALL_HINTS
