"""Wi-Fi on Windows, through its Native Wi-Fi API (wlanapi.dll).

`netsh wlan` prints this in the system's language and rounds the signal to a
percentage. The API underneath it gives the same answers as numbers: every
wireless adapter, every access point the last scan heard — its RSSI in dBm,
its centre frequency, and the information elements of its beacon, which say
its security and channel width — the current connection, and a way to ask
for a new scan. ctypes makes the calls, so nothing has to be installed, and
none of them need Administrator.

Windows 11 24H2 and later answer only when desktop apps may use the location
(a list of nearby networks says roughly where you are). Without it the calls
fail with "access denied", and LOCATION_HELP says what to switch on.

Nothing here joins, transmits or changes a setting; WlanScan asks the radio
to listen. Every reader returns plain data and never raises. The byte
layouts are decoded by separate pure functions, so they are tested on any
system.
"""

from __future__ import annotations

import ctypes
import struct
import time

from . import winapi

# ------------------------------------------------------------ constants
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_STATE = 5023
ERROR_NOT_FOUND = 1168
ERROR_SERVICE_NOT_ACTIVE = 1062
ERROR_NDIS_POWER_STATE_INVALID = 0x80342002     # the radio is switched off

CLIENT_VERSION = 2                 # Vista and later
DOT11_BSS_TYPE_ANY = 3
OPCODE_CURRENT_CONNECTION = 7
OPCODE_RSSI = 0x10000102           # the joined access point's RSSI, a LONG

INTERFACE_STATES = {
    0: "not ready", 1: "connected", 2: "ad hoc network formed",
    3: "disconnecting", 4: "disconnected", 5: "associating",
    6: "discovering", 7: "authenticating",
}
PHY_TYPES = {
    4: "802.11a", 5: "802.11b", 6: "802.11g", 7: "802.11n", 8: "802.11ac",
    9: "802.11ad", 10: "802.11ax", 11: "802.11be",
}
# DOT11_AUTH_ALGORITHM, labelled the way the scan's security column is.
AUTH_LABELS = {
    1: "Open", 2: "WEP (insecure)", 3: "WPA", 4: "WPA", 5: "WPA",
    6: "WPA2 (Enterprise)", 7: "WPA2", 8: "WPA3 (Enterprise)", 9: "WPA3",
    10: "OWE", 11: "WPA3 (Enterprise)",
}
CIPHER_WEP = (1, 5, 0x101)

LOCATION_HELP = (
    "Windows shares nearby Wi-Fi networks only with apps allowed to use the "
    "location. Turn on Settings → Privacy & security → Location → Location "
    "services, and 'Let desktop apps access your location' below it, then "
    "try again."
)
ERROR_HELP = {
    ERROR_ACCESS_DENIED: LOCATION_HELP,
    ERROR_SERVICE_NOT_ACTIVE: (
        "The WLAN AutoConfig service is not running, so Windows has no Wi-Fi. "
        "Start it in Services (services.msc), or run 'net start wlansvc' in a "
        "terminal opened as Administrator."),
    ERROR_NDIS_POWER_STATE_INVALID: (
        "The Wi-Fi radio is switched off. Turn Wi-Fi on (quick settings, or "
        "Settings → Network & internet), and Airplane mode off."),
    ERROR_NOT_FOUND: "That wireless adapter is gone — unplugged or disabled.",
    ERROR_INVALID_STATE: "The wireless adapter is busy or not ready yet — try again.",
}


def error_text(code: int) -> str:
    code &= 0xFFFFFFFF
    return ERROR_HELP.get(code, f"Windows' Wi-Fi API returned error {code}.")


# ---------------------------------------------------------- byte layouts
# WLAN_INTERFACE_INFO_LIST: two DWORDs, then WLAN_INTERFACE_INFO entries of
# GUID (16) + WCHAR[256] description + WLAN_INTERFACE_STATE (4).
LIST_HEAD = 8
INTERFACE_INFO_SIZE = 532
_DESCRIPTION_AT = 16
_STATE_AT = 528

# WLAN_BSS_LIST: DWORD total size, DWORD count, then WLAN_BSS_ENTRY entries.
BSS_ENTRY_SIZE = 360
BSS_OFFSETS = {
    "uSSIDLength": 0, "ucSSID": 4, "uPhyId": 36, "dot11Bssid": 40,
    "dot11BssType": 48, "dot11BssPhyType": 52, "lRssi": 56,
    "uLinkQuality": 60, "bInRegDomain": 64, "usBeaconPeriod": 66,
    "ullTimestamp": 72, "ullHostTimestamp": 80,
    "usCapabilityInformation": 88, "ulChCenterFrequency": 92,
    "uRateSetLength": 96, "usRateSet": 100, "ulIeOffset": 352, "ulIeSize": 356,
}
RATE_SET_MAX = 126
# The legacy rates a rate set can hold, in its units of 500 kbit/s. Anything
# else in the array is not a rate (the length field's unit varies by driver).
LEGACY_RATES = frozenset((2, 4, 11, 12, 18, 22, 24, 36, 44, 48, 66, 72, 96, 108))

# WLAN_CONNECTION_ATTRIBUTES: state, mode, WCHAR[256] profile, then the
# association (SSID, BSS type, BSSID, PHY, PHY index, quality, rx/tx rate in
# kbit/s) and security (enabled, 802.1X, auth algorithm, cipher).
CONNECTION_SIZE = 604
CONNECTION_OFFSETS = {
    "isState": 0, "wlanConnectionMode": 4, "strProfileName": 8,
    "uSSIDLength": 520, "ucSSID": 524, "dot11BssType": 556,
    "dot11Bssid": 560, "dot11PhyType": 568, "uDot11PhyIndex": 572,
    "wlanSignalQuality": 576, "ulRxRate": 580, "ulTxRate": 584,
    "bSecurityEnabled": 588, "bOneXEnabled": 592,
    "dot11AuthAlgorithm": 596, "dot11CipherAlgorithm": 600,
}

# FILETIME (100 ns ticks since 1601) of the Unix epoch.
_EPOCH_AS_FILETIME = 116444736000000000


def filetime_now(now: float | None = None) -> int:
    return int((time.time() if now is None else now) * 10_000_000) + _EPOCH_AS_FILETIME


def guid_text(raw: bytes) -> str:
    """16 GUID bytes as Windows writes them: {XXXXXXXX-XXXX-XXXX-XXXX-…}."""
    if len(raw) != 16:
        return ""
    first, second, third = struct.unpack_from("<IHH", raw)
    tail = raw[8:].hex().upper()
    return "{%08X-%04X-%04X-%s-%s}" % (first, second, third, tail[:4], tail[4:])


def _utf16(raw: bytes) -> str:
    text = raw.decode("utf-16-le", "replace")
    return text.split("\x00", 1)[0].strip()


def _ssid(raw: bytes, length: int) -> str:
    """An SSID's bytes as text; an empty or all-zero one is a hidden network."""
    data = raw[:max(0, min(length, 32))]
    if not data.strip(b"\x00"):
        return ""
    return data.decode("utf-8", "replace")


def _mac(raw: bytes) -> str:
    return winapi.format_mac(raw)


def parse_interface_list(raw: bytes) -> list[dict]:
    """WLAN_INTERFACE_INFO_LIST bytes -> [{guid, guid_bytes, description, state}]."""
    if len(raw) < LIST_HEAD:
        return []
    (count,) = struct.unpack_from("<I", raw)
    found = []
    for index in range(min(count, 64)):
        at = LIST_HEAD + index * INTERFACE_INFO_SIZE
        if at + INTERFACE_INFO_SIZE > len(raw):
            break
        guid = raw[at:at + 16]
        (state,) = struct.unpack_from("<I", raw, at + _STATE_AT)
        found.append({
            "guid": guid_text(guid),
            "guid_bytes": bytes(guid),
            "description": _utf16(raw[at + _DESCRIPTION_AT:at + _STATE_AT]),
            "state": INTERFACE_STATES.get(state, str(state)),
        })
    return found


# ------------------------------------------------- information elements
RSN_OUI = b"\x00\x0f\xac"
WPA_IE_PREFIX = b"\x00\x50\xf2\x01"
AKM_SAE = (8, 9, 24, 25)
AKM_8021X = (1, 3, 5, 11, 12, 13)
AKM_SUITE_B = (12, 13)
AKM_OWE = 18


def parse_ies(blob: bytes) -> dict:
    """A beacon's information elements -> {element id: [bodies]}; extension
    elements (id 255) are keyed (255, extension id)."""
    found: dict = {}
    at = 0
    while at + 2 <= len(blob):
        tag, length = blob[at], blob[at + 1]
        body = blob[at + 2:at + 2 + length]
        if len(body) < length:
            break
        key = tag
        if tag == 255 and body:
            key, body = (255, body[0]), body[1:]
        found.setdefault(key, []).append(bytes(body))
        at += 2 + length
    return found


def _first(ies: dict, key) -> bytes:
    bodies = ies.get(key) or []
    return bodies[0] if bodies else b""


def rsn_akms(rsn: bytes) -> list[int]:
    """The key-management suite types an RSN element offers (2 = PSK,
    8 = SAE, 1 = 802.1X, 18 = OWE…); -1 for a vendor's own suite."""
    try:
        at = 2 + 4                                     # version, group cipher
        (pairwise,) = struct.unpack_from("<H", rsn, at)
        at += 2 + 4 * pairwise
        (count,) = struct.unpack_from("<H", rsn, at)
        at += 2
    except struct.error:
        return []
    akms = []
    for index in range(min(count, 16)):
        suite = rsn[at + 4 * index:at + 4 * index + 4]
        if len(suite) == 4:
            akms.append(suite[3] if suite[:3] == RSN_OUI else -1)
    return akms


def security_from(capability: int, ies: dict) -> str:
    """The scan's security label from a beacon, the way `iw scan` reads it."""
    rsn = _first(ies, 48)
    akms = rsn_akms(rsn) if rsn else []
    enterprise = any(a in AKM_8021X for a in akms)
    if any(a in AKM_SAE for a in akms):
        return "WPA3 (Enterprise)" if enterprise else "WPA3"
    if any(a in AKM_SUITE_B for a in akms):
        return "WPA3 (Enterprise)"
    if akms and all(a == AKM_OWE for a in akms):
        return "OWE"
    if rsn:
        return "WPA2 (Enterprise)" if enterprise else "WPA2"
    if any(body.startswith(WPA_IE_PREFIX) for body in ies.get(221, [])):
        return "WPA"
    if capability & 0x0010:                            # the Privacy bit
        return "WEP (insecure)"
    return "Open"


def _six_ghz_info(he: bytes) -> bytes:
    """The 6 GHz Operation Information inside an HE Operation element."""
    if len(he) < 6:
        return b""
    params = he[0] | he[1] << 8 | he[2] << 16
    at = 6                                  # parameters, BSS colour, basic MCS
    if params & (1 << 14):
        at += 3                             # VHT Operation Information
    if params & (1 << 15):
        at += 1                             # Max Co-Hosted BSSID Indicator
    if params & (1 << 17) and len(he) >= at + 5:
        return he[at:at + 5]
    return b""


def primary_channel(ies: dict) -> int:
    """The channel the beacon says it is on (DS Parameter Set, HT or 6 GHz
    operation); 0 when it does not say."""
    ds = _first(ies, 3)
    if ds:
        return ds[0]
    ht = _first(ies, 61)
    if ht:
        return ht[0]
    six = _six_ghz_info(_first(ies, (255, 36)))
    return six[0] if six else 0


def width_from(ies: dict, channel: int) -> tuple[int, int | None]:
    """(channel width in MHz, centre channel) from the HE (6 GHz), VHT and HT
    operation elements; (20, primary channel) when nothing says wider."""
    six = _six_ghz_info(_first(ies, (255, 36)))
    if six:
        code, seg0, seg1 = six[1] & 0x3, six[2], six[3]
        if code == 3:
            return 160, (seg1 if seg1 and abs(seg1 - seg0) == 8 else seg0) or channel
        return (20, 40, 80)[code], seg0 or channel
    vht = _first(ies, 192)
    if len(vht) >= 3 and vht[0] in (1, 2, 3):
        code, seg0, seg1 = vht[0], vht[1], vht[2]
        if code == 1 and seg1 and abs(seg1 - seg0) == 8:
            return 160, seg1
        if code == 2:
            return 160, seg0 or channel
        return 80, seg0 or channel
    ht = _first(ies, 61)
    if len(ht) >= 2 and channel:
        offset = ht[1] & 0x3
        if offset == 1:
            return 40, channel + 2
        if offset == 3:
            return 40, channel - 2
    return 20, channel


# -------------------------------------------------------- the BSS list
def parse_bss_entry(raw: bytes, at: int, now_ft: int | None = None) -> dict | None:
    """One WLAN_BSS_ENTRY at offset `at` of a WLAN_BSS_LIST buffer."""
    if at + BSS_ENTRY_SIZE > len(raw):
        return None
    o = BSS_OFFSETS
    (ssid_len,) = struct.unpack_from("<I", raw, at + o["uSSIDLength"])
    ssid = _ssid(raw[at + o["ucSSID"]:at + o["ucSSID"] + 32], ssid_len)
    bssid = _mac(raw[at + o["dot11Bssid"]:at + o["dot11Bssid"] + 6])
    _bss_type, phy, rssi, quality = struct.unpack_from("<IIiI", raw, at + o["dot11BssType"])
    (heard,) = struct.unpack_from("<Q", raw, at + o["ullHostTimestamp"])
    (capability,) = struct.unpack_from("<H", raw, at + o["usCapabilityInformation"])
    (freq_khz,) = struct.unpack_from("<I", raw, at + o["ulChCenterFrequency"])
    (rate_count,) = struct.unpack_from("<I", raw, at + o["uRateSetLength"])
    rates = struct.unpack_from(f"<{RATE_SET_MAX}H", raw, at + o["usRateSet"])
    rates = [r & 0x7FFF for r in rates[:min(rate_count, RATE_SET_MAX)]]
    ie_offset, ie_size = struct.unpack_from("<II", raw, at + o["ulIeOffset"])
    ies: dict = {}
    if ie_size and ie_offset >= BSS_ENTRY_SIZE and at + ie_offset + ie_size <= len(raw):
        ies = parse_ies(raw[at + ie_offset:at + ie_offset + ie_size])
    channel = primary_channel(ies)
    width, centre = width_from(ies, channel)
    age_ms = None
    if now_ft and heard and now_ft >= heard:
        age_ms = (now_ft - heard) // 10_000
    best = max((r for r in rates if r in LEGACY_RATES), default=0)
    return {
        "bssid": bssid,
        "ssid": ssid,
        "freq_mhz": freq_khz // 1000,
        "channel": channel,
        "rssi": rssi,
        "quality": min(100, quality),
        "security": security_from(capability, ies),
        "rate_mbps": best // 2,
        "width_mhz": width,
        "centre_channel": centre,
        "age_ms": age_ms,
        "phy": PHY_TYPES.get(phy, ""),
    }


def parse_bss_list(raw: bytes, now_ft: int | None = None) -> list[dict]:
    """WLAN_BSS_LIST bytes -> one dict per access point heard."""
    if len(raw) < LIST_HEAD:
        return []
    _total, count = struct.unpack_from("<II", raw)
    found = []
    for index in range(min(count, 1024)):
        entry = parse_bss_entry(raw, LIST_HEAD + index * BSS_ENTRY_SIZE, now_ft)
        if entry is None:
            break
        found.append(entry)
    return found


def parse_connection(raw: bytes) -> dict:
    """WLAN_CONNECTION_ATTRIBUTES bytes -> the link as LINK HEALTH shows it."""
    if len(raw) < CONNECTION_SIZE:
        return {"connected": False}
    o = CONNECTION_OFFSETS
    (state,) = struct.unpack_from("<I", raw, o["isState"])
    (ssid_len,) = struct.unpack_from("<I", raw, o["uSSIDLength"])
    phy, _index, quality, rx_kbps, tx_kbps = struct.unpack_from("<IIIII", raw, o["dot11PhyType"])
    secured, _onex, auth, cipher = struct.unpack_from("<IIII", raw, o["bSecurityEnabled"])
    security = AUTH_LABELS.get(auth, "")
    if auth == 1 and secured and cipher in CIPHER_WEP:
        security = "WEP (insecure)"
    state_name = INTERFACE_STATES.get(state, str(state))
    return {
        "connected": state_name == "connected",
        "state": state_name,
        "profile": _utf16(raw[o["strProfileName"]:o["uSSIDLength"]]),
        "ssid": _ssid(raw[o["ucSSID"]:o["ucSSID"] + 32], ssid_len),
        "bssid": _mac(raw[o["dot11Bssid"]:o["dot11Bssid"] + 6]).lower(),
        "phy": PHY_TYPES.get(phy, ""),
        "quality": min(100, quality),
        "rx_bitrate": rx_kbps / 1000.0 if rx_kbps else None,
        "tx_bitrate": tx_kbps / 1000.0 if tx_kbps else None,
        "security": security,
    }


# ------------------------------------------------------------- the calls
class _Error(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code & 0xFFFFFFFF


def _lib():
    lib = winapi._dll("wlanapi")
    if lib is None or getattr(lib, "_netzilla_typed", False):
        return lib
    void, dword = ctypes.c_void_p, ctypes.c_uint32
    pointer_out = ctypes.POINTER(ctypes.c_void_p)
    signatures = {
        "WlanOpenHandle": [dword, void, ctypes.POINTER(dword), pointer_out],
        "WlanCloseHandle": [void, void],
        "WlanEnumInterfaces": [void, void, pointer_out],
        "WlanGetNetworkBssList": [void, void, void, dword, ctypes.c_int32, void, pointer_out],
        "WlanQueryInterface": [void, void, dword, void, ctypes.POINTER(dword), pointer_out, void],
        "WlanScan": [void, void, void, void, void],
    }
    for name, argtypes in signatures.items():
        function = getattr(lib, name)
        function.argtypes = argtypes
        function.restype = dword
    lib.WlanFreeMemory.argtypes = [void]
    lib.WlanFreeMemory.restype = None
    lib._netzilla_typed = True
    return lib


class _Client:
    """An open Wi-Fi API handle, closed again on the way out."""

    def __init__(self, lib) -> None:
        self.lib = lib
        self.handle = ctypes.c_void_p()

    def __enter__(self) -> "_Client":
        version = ctypes.c_uint32()
        code = self.lib.WlanOpenHandle(CLIENT_VERSION, None, ctypes.byref(version),
                                       ctypes.byref(self.handle))
        if code:
            raise _Error(code)
        return self

    def __exit__(self, *_exc) -> None:
        if self.handle.value:
            self.lib.WlanCloseHandle(self.handle, None)

    def _take(self, pointer: ctypes.c_void_p, size: int) -> bytes:
        try:
            return ctypes.string_at(pointer.value, size) if pointer.value and size else b""
        finally:
            if pointer.value:
                self.lib.WlanFreeMemory(pointer)

    def interfaces(self) -> list[dict]:
        pointer = ctypes.c_void_p()
        code = self.lib.WlanEnumInterfaces(self.handle, None, ctypes.byref(pointer))
        if code:
            raise _Error(code)
        count = struct.unpack("<I", ctypes.string_at(pointer.value, 4))[0] if pointer.value else 0
        size = LIST_HEAD + min(count, 64) * INTERFACE_INFO_SIZE
        return parse_interface_list(self._take(pointer, size))

    def bss_list(self, guid: bytes) -> list[dict]:
        key = ctypes.create_string_buffer(guid, 16)
        pointer = ctypes.c_void_p()
        code = self.lib.WlanGetNetworkBssList(self.handle, key, None, DOT11_BSS_TYPE_ANY,
                                              0, None, ctypes.byref(pointer))
        if code:
            raise _Error(code)
        total = struct.unpack("<I", ctypes.string_at(pointer.value, 4))[0] if pointer.value else 0
        return parse_bss_list(self._take(pointer, min(total, 8 * 1024 * 1024)), filetime_now())

    def connection(self, guid: bytes) -> dict:
        key = ctypes.create_string_buffer(guid, 16)
        size = ctypes.c_uint32()
        pointer = ctypes.c_void_p()
        code = self.lib.WlanQueryInterface(self.handle, key, OPCODE_CURRENT_CONNECTION, None,
                                           ctypes.byref(size), ctypes.byref(pointer), None)
        if code:
            # Not connected is an "invalid state" for this query, not a fault.
            if code & 0xFFFFFFFF in (ERROR_INVALID_STATE, ERROR_NOT_FOUND):
                return {"connected": False, "state": "disconnected"}
            raise _Error(code)
        return parse_connection(self._take(pointer, min(size.value, 4096)))

    def rssi(self, guid: bytes) -> int | None:
        """The joined access point's signal in dBm, as the driver has it now."""
        key = ctypes.create_string_buffer(guid, 16)
        size = ctypes.c_uint32()
        pointer = ctypes.c_void_p()
        code = self.lib.WlanQueryInterface(self.handle, key, OPCODE_RSSI, None,
                                           ctypes.byref(size), ctypes.byref(pointer), None)
        if code:
            return None
        raw = self._take(pointer, min(size.value, 64))
        if len(raw) < 4:
            return None
        value = struct.unpack_from("<i", raw)[0]
        return value if -127 <= value < 0 else None

    def scan(self, guid: bytes) -> bool:
        key = ctypes.create_string_buffer(guid, 16)
        return self.lib.WlanScan(self.handle, key, None, None, None) == 0


def available() -> bool:
    """Whether this system has the Wi-Fi API at all (Windows, with WLAN)."""
    return _lib() is not None


def _named(found: list[dict]) -> list[dict]:
    """Give each Wi-Fi adapter the name the rest of Windows uses ("Wi-Fi",
    "Wi-Fi 2"), from the adapter with the same GUID."""
    by_guid = {a.get("guid", ""): a for a in (winapi.adapters() or [])}
    for entry in found:
        adapter = by_guid.get(entry["guid"].upper())
        entry["name"] = (adapter or {}).get("name") or entry["description"] or entry["guid"]
    return found


def _pick(found: list[dict], name: str) -> dict | None:
    if not found:
        return None
    wanted = (name or "").strip().lower()
    for entry in found:
        if wanted and wanted in (entry.get("name", "").lower(), entry["description"].lower(),
                                 entry["guid"].lower()):
            return entry
    return found[0]


def interfaces() -> tuple[list[dict], str]:
    """(wireless adapters, error): [{name, description, guid, state}]."""
    lib = _lib()
    if lib is None:
        return [], "The Windows Wi-Fi API (wlanapi.dll) is not available."
    try:
        with _Client(lib) as client:
            return _named(client.interfaces()), ""
    except _Error as exc:
        return [], error_text(exc.code)
    except Exception as exc:                 # never take the app down
        return [], f"The Windows Wi-Fi API failed: {exc}"


def networks(name: str = "") -> tuple[list[dict], dict, str]:
    """(access points the last scan heard, the current connection, error)
    for one adapter (by name, description or GUID; blank = the first)."""
    lib = _lib()
    if lib is None:
        return [], {}, "The Windows Wi-Fi API (wlanapi.dll) is not available."
    try:
        with _Client(lib) as client:
            chosen = _pick(_named(client.interfaces()), name)
            if chosen is None:
                return [], {}, "Windows reports no Wi-Fi adapter."
            try:
                link = client.connection(chosen["guid_bytes"])
            except _Error:
                link = {"connected": False}
            return client.bss_list(chosen["guid_bytes"]), link, ""
    except _Error as exc:
        return [], {}, error_text(exc.code)
    except Exception as exc:
        return [], {}, f"The Windows Wi-Fi API failed: {exc}"


def connection(name: str = "") -> tuple[dict, dict | None, str]:
    """(the current connection, that access point's scan entry or None,
    error). The scan entry carries the exact RSSI and frequency."""
    lib = _lib()
    if lib is None:
        return {"connected": False}, None, "The Windows Wi-Fi API is not available."
    try:
        with _Client(lib) as client:
            chosen = _pick(_named(client.interfaces()), name)
            if chosen is None:
                return {"connected": False}, None, "Windows reports no Wi-Fi adapter."
            link = client.connection(chosen["guid_bytes"])
            link["adapter"] = chosen
            if not link.get("connected"):
                return link, None, ""
            link["rssi"] = client.rssi(chosen["guid_bytes"])
            try:
                heard = client.bss_list(chosen["guid_bytes"])
            except _Error:
                heard = []
            mine = link.get("bssid", "").lower()
            entry = next((b for b in heard if b["bssid"].lower() == mine), None)
            return link, entry, ""
    except _Error as exc:
        return {"connected": False}, None, error_text(exc.code)
    except Exception as exc:
        return {"connected": False}, None, f"The Windows Wi-Fi API failed: {exc}"


def request_scan(name: str = "") -> bool:
    """Ask the adapter for a fresh scan and return at once (results land in
    the BSS list within about four seconds)."""
    lib = _lib()
    if lib is None:
        return False
    try:
        with _Client(lib) as client:
            chosen = _pick(_named(client.interfaces()), name)
            return bool(chosen) and client.scan(chosen["guid_bytes"])
    except Exception:
        return False
