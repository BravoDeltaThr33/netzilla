"""Bluetooth: what is broadcasting nearby.

Most Bluetooth devices announce themselves several times a second whether or
not they are paired with anything: phones, earbuds, watches, TVs, smart
bulbs, cars, beacons and item trackers. netzilla listens for those
broadcasts and, for each device, works out

  * its name, when it broadcasts one
  * its signal strength, a history of it, and a rough distance
  * its maker, from the manufacturer ID every broadcast carries (or, without
    one, from the owner of a service UUID or the address's IEEE prefix)
  * a best guess at what it is, from what the broadcast contains
  * when it was first and last heard

and keeps an eye on item trackers (AirTag, Tile, SmartTag, Chipolo, Find My
and Google Find Hub tags): one that stays near you for a long time, or that
turns up on more than one network you have been on, is flagged.

Scanning goes through bleak (BlueZ over D-Bus on Linux, CoreBluetooth on
macOS) and never pairs or connects. On Linux it is an *active* scan: the
radio may send a short "scan request" so that a device answers with its name
— nothing more.

Everything in this module except Scanner is plain Python and is tested with
recorded advertisements; Scanner is the thin layer over bleak.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import math
import re
import statistics
import time
from collections import deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data" / "bt_numbers.csv.gz"

# The Bluetooth base UUID: 16-bit UUIDs are 0000xxxx-0000-1000-8000-00805f9b34fb.
_BASE_UUID = re.compile(r"^0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb$", re.I)


# ------------------------------------------------------------ assigned numbers
@lru_cache(maxsize=1)
def _tables() -> tuple[dict[int, str], dict[int, str]]:
    """(company id -> name, 16-bit UUID -> name), read once."""
    companies: dict[int, str] = {}
    uuids: dict[int, str] = {}
    try:
        text = gzip.decompress(DATA.read_bytes()).decode("utf-8")
    except (OSError, EOFError, ValueError):
        return companies, uuids
    for row in csv.reader(io.StringIO(text)):
        if len(row) != 3 or row[0] == "kind":
            continue
        try:
            key = int(row[1], 16)
        except ValueError:
            continue
        (companies if row[0] == "company" else uuids)[key] = row[2]
    return companies, uuids


def company_name(company_id: int | None) -> str:
    """The registered owner of a Bluetooth company identifier."""
    if company_id is None:
        return ""
    return _tables()[0].get(int(company_id), "") or ""


def short_uuid(uuid: str | int) -> int | None:
    """0xFEED for "0000feed-0000-1000-8000-00805f9b34fb" (or "feed", 0xFEED);
    None for a full 128-bit vendor UUID."""
    if isinstance(uuid, int):
        return uuid if 0 <= uuid <= 0xFFFF else None
    text = str(uuid).strip().lower()
    match = _BASE_UUID.match(text)
    if match:
        return int(match.group(1), 16)
    if re.fullmatch(r"(0x)?[0-9a-f]{4}", text):
        return int(text[-4:], 16)
    return None


def uuid_name(uuid: str | int) -> str:
    short = short_uuid(uuid)
    return _tables()[1].get(short, "") if short is not None else ""


def short_company(name: str, width: int = 24) -> str:
    """"Apple, Inc." -> "Apple"; long registry names trimmed to fit a column."""
    text = re.sub(r",?\s+(inc\.?|incorporated|co\.?,?\s*ltd\.?|ltd\.?|llc|gmbh|"
                  r"corporation|corp\.?|limited|a/s|ab|ag|s\.?a\.?|b\.?v\.?|oy)$",
                  "", name.strip(), flags=re.I).strip(" ,")
    return text if len(text) <= width else text[: width - 1] + "…"


# ----------------------------------------------------------- one advertisement
@dataclass
class Advert:
    """Everything one broadcast (or BlueZ's running view of a device) told us."""

    address: str
    rssi: int | None = None
    name: str = ""
    manufacturer: dict[int, bytes] = field(default_factory=dict)
    service_data: dict[str, bytes] = field(default_factory=dict)
    service_uuids: list[str] = field(default_factory=list)
    tx_power: int | None = None
    address_type: str = ""          # "public", "random" or "" when not reported
    appearance: int | None = None   # GAP appearance (LE)
    device_class: int | None = None  # Class of Device (classic Bluetooth)
    icon: str = ""                  # BlueZ's own guess ("phone", "audio-headset"…)
    paired: bool = False
    connected: bool = False


def from_bleak(device, adv) -> Advert:
    """An Advert from bleak's (BLEDevice, AdvertisementData)."""
    props: dict = {}
    platform = getattr(adv, "platform_data", None)
    if isinstance(platform, tuple) and len(platform) >= 2 and isinstance(platform[1], dict):
        props = platform[1]              # BlueZ: (object path, Device1 properties)
    name = (getattr(adv, "local_name", None) or getattr(device, "name", None) or "")
    address = str(getattr(device, "address", "") or props.get("Address", ""))
    if name.replace("-", ":").upper() == address.upper():
        name = ""                        # BlueZ names unnamed devices after their address

    def as_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    rssi = as_int(getattr(adv, "rssi", None))
    if rssi is not None and rssi <= -127:
        rssi = None                      # BlueZ's "no reading" (a property change, not a broadcast)
    return Advert(
        address=address,
        rssi=rssi,
        name=str(name).strip(),
        manufacturer={int(k): bytes(v) for k, v in (getattr(adv, "manufacturer_data", None) or {}).items()},
        service_data={str(k): bytes(v) for k, v in (getattr(adv, "service_data", None) or {}).items()},
        service_uuids=[str(u) for u in (getattr(adv, "service_uuids", None) or [])],
        tx_power=as_int(getattr(adv, "tx_power", None)),
        address_type=str(props.get("AddressType", "") or ""),
        appearance=as_int(props.get("Appearance")),
        device_class=as_int(props.get("Class")),
        icon=str(props.get("Icon", "") or ""),
        paired=bool(props.get("Paired", False)),
        connected=bool(props.get("Connected", False)),
    )


def merge(old: Advert, new: Advert) -> Advert:
    """BlueZ reports a device's whole state each time; CoreBluetooth reports
    the latest broadcast only, which may lack the name or the manufacturer
    data a previous one carried. Keep what is not repeated."""
    manufacturer = dict(old.manufacturer)
    manufacturer.update(new.manufacturer)
    service_data = dict(old.service_data)
    service_data.update(new.service_data)
    uuids = list(dict.fromkeys([*old.service_uuids, *new.service_uuids]))
    return Advert(
        address=new.address or old.address,
        rssi=new.rssi if new.rssi is not None else old.rssi,
        name=new.name or old.name,
        manufacturer=manufacturer,
        service_data=service_data,
        service_uuids=uuids,
        tx_power=new.tx_power if new.tx_power is not None else old.tx_power,
        address_type=new.address_type or old.address_type,
        appearance=new.appearance if new.appearance is not None else old.appearance,
        device_class=new.device_class if new.device_class is not None else old.device_class,
        icon=new.icon or old.icon,
        paired=new.paired or old.paired,
        connected=new.connected,
    )


# ------------------------------------------------------------- the best guess
@dataclass
class Guess:
    """What a device probably is."""

    kind: str = "other"       # one of KIND_TITLES
    label: str = ""           # "AirPods Pro", "iPhone, iPad, Mac or Watch"…
    tracker: str = ""         # tracker family when it is one: "AirTag", "Tile"…
    separated: bool | None = None   # a tracker away from its owner (when it says)
    ref_1m: int | None = None       # its own calibrated dBm at 1 m, when it says
    sure: bool = False        # decoded from the broadcast, not inferred

    @property
    def text(self) -> str:
        """"Earbuds · AirPods Pro": the kind and the detail."""
        title = KIND_TITLES.get(self.kind, "Device")
        if not self.label or self.label.lower() == title.lower():
            return title
        return f"{title} · {self.label}"

    @property
    def short(self) -> str:
        """For a table cell: the detail when there is one ("AirPods Pro"
        says earbuds on its own), else the kind."""
        return self.label or KIND_TITLES.get(self.kind, "Device")


KIND_TITLES = {
    "phone": "Phone", "computer": "Computer", "tablet": "Tablet", "watch": "Watch",
    "earbuds": "Earbuds", "headphones": "Headphones", "speaker": "Speaker",
    "tv": "TV / media", "tracker": "Tracker", "beacon": "Beacon",
    "input": "Keyboard / mouse", "fitness": "Fitness / health", "home": "Smart home",
    "light": "Light", "car": "Car", "printer": "Printer", "camera": "Camera",
    "gaming": "Gaming", "other": "Device",
}

# How the summary counts them, in this order: (one, many, kinds).
SUMMARY_GROUPS = (
    ("phone", "phones", ("phone", "tablet")), ("computer", "computers", ("computer",)),
    ("earbuds/headphones", "earbuds/headphones", ("earbuds", "headphones")),
    ("watch", "watches", ("watch",)), ("tracker", "trackers", ("tracker",)),
    ("beacon", "beacons", ("beacon",)), ("TV/speaker", "TVs/speakers", ("tv", "speaker")),
    ("smart-home device", "smart-home devices", ("home", "light")),
    ("fitness device", "fitness devices", ("fitness",)),
    ("keyboard/mouse", "keyboards/mice", ("input",)), ("car", "cars", ("car",)),
    ("game device", "game devices", ("gaming",)),
)

# Apple Continuity message types (manufacturer data, company 0x004C).
APPLE_IBEACON = 0x02
APPLE_PROXIMITY_PAIRING = 0x07     # AirPods / Beats with the lid open
APPLE_AIRPLAY_TARGET = 0x09
APPLE_HANDOFF = 0x0C
APPLE_TETHERING_SOURCE = 0x0E      # an iPhone offering Instant Hotspot
APPLE_NEARBY_ACTION = 0x0F
APPLE_NEARBY_INFO = 0x10
APPLE_FIND_MY = 0x12               # offline finding (Find My network)

# Proximity Pairing model numbers (the two bytes after the prefix).
APPLE_AUDIO_MODELS = {
    0x0220: ("earbuds", "AirPods"), 0x0F20: ("earbuds", "AirPods (2nd gen)"),
    0x1320: ("earbuds", "AirPods (3rd gen)"), 0x0E20: ("earbuds", "AirPods Pro"),
    0x1420: ("earbuds", "AirPods Pro (2nd gen)"), 0x2420: ("earbuds", "AirPods Pro (2nd gen)"),
    0x0A20: ("headphones", "AirPods Max"), 0x0320: ("earbuds", "Powerbeats3"),
    0x0520: ("earbuds", "BeatsX"), 0x0620: ("headphones", "Beats Solo3"),
    0x0920: ("headphones", "Beats Studio3"), 0x0B20: ("earbuds", "Powerbeats Pro"),
    0x0C20: ("headphones", "Beats Solo Pro"), 0x1020: ("earbuds", "Beats Flex"),
    0x1120: ("earbuds", "Beats Studio Buds"), 0x1220: ("earbuds", "Beats Fit Pro"),
    0x1520: ("earbuds", "Beats Studio Buds+"), 0x1620: ("headphones", "Beats Studio Pro"),
}

# Find My status byte, bits 4–5: what kind of device is broadcasting.
FIND_MY_TYPES = {
    0: ("phone", "Apple device on Find My", ""),
    1: ("tracker", "AirTag", "AirTag"),
    2: ("earbuds", "AirPods on Find My", ""),
    3: ("tracker", "Find My accessory", "Find My accessory"),
}

# Microsoft Connected Devices Platform beacon: device type (low 5 bits).
MS_CDP_TYPES = {
    1: ("gaming", "Xbox One"), 6: ("phone", "iPhone"), 7: ("tablet", "iPad"),
    8: ("phone", "Android phone"),
    9: ("computer", "Windows desktop"), 11: ("phone", "Windows phone"),
    12: ("computer", "Linux device"), 13: ("home", "Windows IoT device"),
    14: ("tv", "Surface Hub"), 15: ("computer", "Windows laptop"),
    16: ("tablet", "Windows tablet"),
}

# Service and member UUIDs that say what a device is.
UUID_KINDS = {
    0xFD5A: ("tracker", "Samsung SmartTag", "SmartTag"),
    0xFEED: ("tracker", "Tile", "Tile"),
    0xFEEC: ("tracker", "Tile", "Tile"),
    0xFE33: ("tracker", "Chipolo", "Chipolo"),
    0xFE2C: ("earbuds", "Fast Pair audio", ""),
    0xFD6F: ("phone", "Exposure Notifications", ""),
    0x180D: ("fitness", "heart-rate sensor", ""),
    0x1816: ("fitness", "cycling sensor", ""),
    0x1814: ("fitness", "running sensor", ""),
    0x1810: ("fitness", "blood-pressure monitor", ""),
    0x1808: ("fitness", "glucose meter", ""),
    0x181D: ("fitness", "weight scale", ""),
    0x1809: ("fitness", "thermometer", ""),
    0x1812: ("input", "keyboard/mouse/controller", ""),
    0x110B: ("speaker", "audio receiver", ""),
    0x110A: ("phone", "audio source", ""),
    0x111E: ("earbuds", "hands-free headset", ""),
    0x1108: ("earbuds", "headset", ""),
}

# Member UUIDs that name a shared service rather than one company's product.
NOT_OWNERS = {0xFD6F}      # Exposure Notifications (Apple and Google)

# GAP appearance category (appearance >> 6) -> kind.
APPEARANCE_KINDS = {
    0x001: ("phone", "phone"), 0x002: ("computer", "computer"), 0x003: ("watch", "watch"),
    0x004: ("home", "clock"), 0x005: ("tv", "display"), 0x006: ("input", "remote control"),
    0x007: ("other", "glasses"), 0x008: ("tracker", "tag"), 0x009: ("tracker", "key ring"),
    0x00A: ("speaker", "media player"), 0x00C: ("fitness", "thermometer"),
    0x00D: ("fitness", "heart-rate sensor"), 0x00E: ("fitness", "blood-pressure monitor"),
    0x00F: ("input", "keyboard/mouse/controller"), 0x010: ("fitness", "glucose meter"),
    0x011: ("fitness", "running sensor"), 0x012: ("fitness", "cycling sensor"),
    0x015: ("home", "sensor"), 0x016: ("light", "light fixture"), 0x017: ("home", "fan"),
    0x018: ("home", "HVAC"), 0x01C: ("home", "access control"), 0x01F: ("light", "light"),
    0x021: ("speaker", "speaker"), 0x023: ("car", "vehicle"), 0x024: ("home", "appliance"),
    0x025: ("earbuds", "earbuds or headset"), 0x027: ("tv", "AV equipment"),
    0x028: ("tv", "display"), 0x029: ("earbuds", "hearing aid"), 0x02A: ("gaming", "gaming"),
    0x031: ("fitness", "pulse oximeter"), 0x032: ("fitness", "weight scale"),
}
APPEARANCE_EXACT = {0x03C1: ("input", "keyboard"), 0x03C2: ("input", "mouse"),
                    0x03C3: ("gaming", "joystick"), 0x03C4: ("gaming", "game controller"),
                    0x0941: ("earbuds", "earbuds"), 0x0942: ("earbuds", "headset"),
                    0x0943: ("headphones", "headphones")}

# Classic Bluetooth Class of Device: major class (bits 8–12).
COD_MAJOR = {1: ("computer", "computer"), 2: ("phone", "phone"),
             3: ("home", "network access point"), 4: ("speaker", "audio / video"),
             5: ("input", "keyboard or mouse"), 6: ("printer", "printer or camera"),
             7: ("watch", "wearable"), 8: ("gaming", "toy"), 9: ("fitness", "health device")}
# Audio/video minor classes (bits 2–7).
COD_AUDIO = {1: ("earbuds", "headset"), 2: ("earbuds", "hands-free"), 5: ("speaker", "speaker"),
             6: ("headphones", "headphones"), 7: ("speaker", "portable audio"),
             8: ("car", "car audio"), 9: ("tv", "set-top box"), 10: ("speaker", "hi-fi"),
             14: ("tv", "video monitor"), 15: ("tv", "TV"), 18: ("gaming", "games console")}

# BlueZ's own icon names.
ICON_KINDS = {
    "phone": ("phone", "phone"), "computer": ("computer", "computer"),
    "audio-headset": ("earbuds", "headset"), "audio-headphones": ("headphones", "headphones"),
    "audio-card": ("speaker", "speaker"), "video-display": ("tv", "display"),
    "input-keyboard": ("input", "keyboard"), "input-mouse": ("input", "mouse"),
    "input-gaming": ("gaming", "game controller"), "input-tablet": ("input", "tablet pen"),
    "printer": ("printer", "printer"), "camera-photo": ("camera", "camera"),
    "camera-video": ("camera", "video camera"), "modem": ("home", "modem"),
    "network-wireless": ("home", "network device"),
}

# Words in a device's own name.
NAME_HINTS = (
    (r"airtag", ("tracker", "AirTag")),
    (r"\btile\b", ("tracker", "Tile")),
    (r"smarttag|smart tag", ("tracker", "Samsung SmartTag")),
    (r"chipolo", ("tracker", "Chipolo")),
    (r"airpods max", ("headphones", "AirPods Max")),
    (r"airpods", ("earbuds", "AirPods")),
    (r"\bbuds|earbud|freebuds|soundcore|jabra|\bpods?\b|earfun|liberty", ("earbuds", "")),
    (r"\bwh-|\bwf-|headphone|qc ?\d|quietcomfort|bose|sennheiser|beats", ("headphones", "")),
    (r"iphone", ("phone", "iPhone")), (r"ipad", ("tablet", "iPad")),
    (r"galaxy (?!buds|watch|tab)|pixel(?! ?buds| ?watch)|\bmoto\b|oneplus|xperia|redmi",
     ("phone", "")),
    (r"macbook|imac|mac mini|\bmac\b", ("computer", "Mac")),
    (r"thinkpad|surface|laptop|desktop-|\bpc\b|chromebook", ("computer", "")),
    (r"watch|fitbit|forerunner|fenix|venu|vivo|amazfit|mi band|smart ?band|whoop",
     ("watch", "")),
    (r"\btv\b|\[tv\]|cast ?tv|\bcast\b|chromecast|google tv|android tv|webos|tizen|bravia|"
     r"roku|fire ?tv|apple tv|shield", ("tv", "")),
    (r"echo|alexa|homepod|nest|google home|sonos|speaker|soundbar|jbl|ue boom|megaboom",
     ("speaker", "")),
    (r"keyboard|mouse|\bmx\b|trackpad|k380|magic keyboard", ("input", "")),
    (r"xbox|dualsense|dualshock|joy-?con|pro controller|controller|gamepad|8 ?bit ?do|stadia",
     ("gaming", "")),
    (r"tesla|model [3sxy]\b|\bford\b|\btoyota\b|\bhonda\b|\bbmw\b|\bkia\b|hyundai|\bgm\b|"
     r"chevrolet|subaru|mazda|volkswagen|\bvw\b|carplay|\bcar\b", ("car", "")),
    # ELK-BLEDOM, Triones, QHM- and "LEDBLE" are the cheap LED-strip controllers.
    (r"bulb|lamp|hue|govee|nanoleaf|lifx|\bled\b|light|bledom|elk-bl|triones|\bqhm-|ledble|"
     r"led ?strip|magic ?home", ("light", "")),
    (r"lock|thermostat|ecobee|ring|doorbell|plug|switch|sensor|meross|wyze|kasa|"
     r"switchbot|smoke", ("home", "")),
    (r"scale|oximeter|thermometer|heart|polar|garmin|wahoo|zwift", ("fitness", "")),
    (r"printer|laserjet|officejet|deskjet|epson|brother|canon|envy", ("printer", "")),
)

# Makers whose broadcasts are nearly always one kind of device.
MAKER_HINTS = (
    ("tile", ("tracker", "Tile", "Tile")), ("chipolo", ("tracker", "Chipolo", "Chipolo")),
    ("bose", ("headphones", "", "")), ("sennheiser", ("headphones", "", "")),
    ("jabra", ("earbuds", "", "")), ("gn audio", ("earbuds", "", "")),
    ("skullcandy", ("earbuds", "", "")), ("anker", ("earbuds", "", "")),
    ("harman", ("speaker", "", "")), ("sonos", ("speaker", "", "")),
    ("garmin", ("watch", "", "")), ("fitbit", ("watch", "", "")),
    ("huami", ("watch", "", "")), ("zepp", ("watch", "", "")), ("polar", ("fitness", "", "")),
    ("suunto", ("watch", "", "")), ("whoop", ("watch", "", "")), ("wahoo", ("fitness", "", "")),
    ("roku", ("tv", "", "")), ("vizio", ("tv", "", "")), ("tcl", ("tv", "", "")),
    ("hisense", ("tv", "", "")), ("lg electronics", ("tv", "", "")),
    ("signify", ("light", "", "")), ("philips lighting", ("light", "", "")),
    ("govee", ("light", "", "")), ("nanoleaf", ("light", "", "")),
    ("ecobee", ("home", "", "")), ("august", ("home", "", "")), ("yale", ("home", "", "")),
    ("ring ", ("home", "", "")), ("wyze", ("home", "", "")), ("switchbot", ("home", "", "")),
    ("logitech", ("input", "", "")), ("razer", ("input", "", "")),
    ("nintendo", ("gaming", "", "")), ("sony interactive", ("gaming", "", "")),
    ("tesla", ("car", "", "")), ("ford", ("car", "", "")), ("toyota", ("car", "", "")),
    ("bmw", ("car", "", "")), ("volkswagen", ("car", "", "")),
)


def apple_messages(data: bytes) -> list[tuple[int, bytes]]:
    """Apple Continuity manufacturer data is a run of (type, length, payload)
    messages; an iPhone often sends two at once."""
    out = []
    i = 0
    while i + 2 <= len(data):
        kind, length = data[i], data[i + 1]
        out.append((kind, bytes(data[i + 2:i + 2 + length])))
        i += 2 + length
    return out


def _signed(byte: int) -> int:
    return byte - 256 if byte > 127 else byte


def _apple(data: bytes) -> Guess | None:
    messages = apple_messages(data)
    if not messages:
        return Guess("other", "Apple device", sure=True)
    types = {kind for kind, _ in messages}
    for kind, payload in messages:
        if kind == APPLE_FIND_MY and payload:
            device_type = (payload[0] >> 4) & 0x03
            what, label, tracker = FIND_MY_TYPES.get(device_type, FIND_MY_TYPES[0])
            # 25 bytes of payload is the full public key: the device is away
            # from its owner ("separated"). Two bytes: it is near its owner.
            separated = len(payload) >= 0x19
            if tracker:
                label = f"{label} ({'away from owner' if separated else 'with owner'})"
            return Guess(what, label, tracker=tracker or ("AirPods" if device_type == 2 else ""),
                         separated=separated, sure=True)
        if kind == APPLE_PROXIMITY_PAIRING and len(payload) >= 3:
            model = (payload[1] << 8) | payload[2]
            what, label = APPLE_AUDIO_MODELS.get(model, ("earbuds", "AirPods or Beats"))
            return Guess(what, label, sure=True)
        if kind == APPLE_IBEACON and len(payload) >= 21:
            major = (payload[16] << 8) | payload[17]
            minor = (payload[18] << 8) | payload[19]
            return Guess("beacon", f"iBeacon {major}/{minor}", ref_1m=_signed(payload[20]),
                         sure=True)
    if APPLE_TETHERING_SOURCE in types:
        return Guess("phone", "iPhone (Instant Hotspot)", sure=True)
    if APPLE_AIRPLAY_TARGET in types:
        return Guess("tv", "Apple TV or HomePod", sure=True)
    if types & {APPLE_NEARBY_INFO, APPLE_HANDOFF, APPLE_NEARBY_ACTION}:
        return Guess("phone", "iPhone/iPad/Mac/Watch", sure=True)
    return Guess("other", "Apple device", sure=True)


def _microsoft(data: bytes) -> Guess | None:
    if len(data) >= 2 and data[0] == 0x01:
        what, label = MS_CDP_TYPES.get(data[1] & 0x1F, ("computer", "Windows device"))
        return Guess(what, label, sure=True)
    if len(data) >= 1 and data[0] == 0x03:
        return Guess("input", "Swift Pair accessory", sure=True)
    return None


def _eddystone(data: bytes) -> Guess | None:
    if not data:
        return None
    frame = data[0]
    if frame in (0x40, 0x41):
        # Google's Find Hub (Find My Device) network. 0x41 is "unwanted
        # tracking protection" mode: away from its owner.
        separated = frame == 0x41
        return Guess("tracker", "Find Hub tag" + (" (away from owner)" if separated else ""),
                     tracker="Find Hub tag", separated=separated, sure=True)
    names = {0x00: "Eddystone-UID", 0x10: "Eddystone-URL", 0x20: "Eddystone-TLM",
             0x30: "Eddystone-EID"}
    if frame in names:
        ref = _signed(data[1]) - 41 if frame in (0x00, 0x10, 0x30) and len(data) > 1 else None
        return Guess("beacon", names[frame], ref_1m=ref, sure=True)
    return None


def _uuid_guess(adv: Advert) -> Guess | None:
    shorts = [short_uuid(u) for u in [*adv.service_data.keys(), *adv.service_uuids]]
    for short in shorts:
        if short == 0xFEAA:
            guess = _eddystone(_service_data(adv, 0xFEAA))
            if guess:
                return guess
        if short in UUID_KINDS:
            what, label, tracker = UUID_KINDS[short]
            return Guess(what, label, tracker=tracker, sure=True)
    return None


def _service_data(adv: Advert, short: int) -> bytes:
    for key, value in adv.service_data.items():
        if short_uuid(key) == short:
            return value
    return b""


def _altbeacon(adv: Advert) -> Guess | None:
    for data in adv.manufacturer.values():
        if len(data) >= 24 and data[0] == 0xBE and data[1] == 0xAC:
            return Guess("beacon", "AltBeacon", ref_1m=_signed(data[22]), sure=True)
    return None


def _appearance(value: int | None) -> Guess | None:
    if not value:
        return None
    if value in APPEARANCE_EXACT:
        what, label = APPEARANCE_EXACT[value]
        return Guess(what, label)
    found = APPEARANCE_KINDS.get(value >> 6)
    return Guess(*found) if found else None


def _device_class(value: int | None) -> Guess | None:
    if not value:
        return None
    major = (value >> 8) & 0x1F
    minor = (value >> 2) & 0x3F
    if major == 4 and minor in COD_AUDIO:
        return Guess(*COD_AUDIO[minor])
    if major == 2 and minor == 3:
        return Guess("phone", "smartphone")
    if major == 1 and minor in (3, 4):
        return Guess("computer", "laptop")
    found = COD_MAJOR.get(major)
    return Guess(*found) if found else None


def _from_name(name: str) -> Guess | None:
    low = name.lower()
    for pattern, (what, label) in NAME_HINTS:
        if re.search(pattern, low):
            return Guess(what, label, tracker=label if what == "tracker" else "")
    return None


def _from_maker(maker: str) -> Guess | None:
    low = f"{maker.lower()} "
    for needle, (what, label, tracker) in MAKER_HINTS:
        if low.startswith(needle) or f" {needle}" in f" {low}":
            return Guess(what, label, tracker=tracker)
    return None


def classify(adv: Advert, maker: str = "") -> Guess:
    """A best guess at what is broadcasting `adv`: decoded from the broadcast
    when it says (Apple, Microsoft, trackers, beacons), else from its
    appearance, class, BlueZ's icon, its name and finally its maker."""
    if 0x004C in adv.manufacturer:
        guess = _apple(adv.manufacturer[0x004C])
        if guess and (guess.kind != "other" or not adv.name):
            return guess
    if 0x0006 in adv.manufacturer:
        guess = _microsoft(adv.manufacturer[0x0006])
        if guess:
            return guess
    for guess in (_uuid_guess(adv), _altbeacon(adv)):
        if guess:
            return guess
    exact = _appearance(adv.appearance) or _device_class(adv.device_class)
    named = _from_name(adv.name) if adv.name else None
    if named and (named.label or exact is None or named.kind == exact.kind):
        if exact and not named.label:
            named.label = exact.label
        return named
    if exact:
        return exact
    if adv.icon in ICON_KINDS:
        return Guess(*ICON_KINDS[adv.icon])
    if named:
        return named
    if 0x004C in adv.manufacturer:
        return Guess("other", "Apple device", sure=True)
    by_maker = _from_maker(maker)
    if by_maker:
        return by_maker
    return Guess("other", "")


def maker_of(adv: Advert, oui_lookup=None) -> str:
    """Who made it: the owner of the broadcast's manufacturer ID, else the
    owner of a member service UUID, else (public addresses only) the IEEE
    prefix of its address."""
    for company_id in adv.manufacturer:
        name = company_name(company_id)
        if name:
            return short_company(name)
        return f"ID 0x{company_id:04X}"
    for uuid in [*adv.service_data.keys(), *adv.service_uuids]:
        short = short_uuid(uuid)
        if short is not None and short >= 0xFC00 and short not in NOT_OWNERS:
            name = uuid_name(short)
            if name:
                return short_company(re.sub(r"\s*\(.*\)$", "", name))
    if oui_lookup and adv.address_type != "random" and adv.address:
        try:
            vendor = oui_lookup(adv.address)
        except Exception:
            vendor = ""
        if vendor:
            return short_company(vendor)
    return ""


# ----------------------------------------------------------------- distance
REF_1M = -59          # typical RSSI at one metre for a phone or tag
PATH_LOSS = 2.2       # indoor path-loss exponent: 2 in open air, 3+ through walls


def distance_m(rssi: float | None, ref_1m: float | None = None) -> float | None:
    """Rough distance in metres from signal strength (log-distance model).
    Walls, bodies and pockets move it by a factor of two either way — it
    says near or far, not where."""
    if rssi is None:
        return None
    ref = REF_1M if ref_1m is None else ref_1m
    return round(10 ** ((ref - float(rssi)) / (10 * PATH_LOSS)), 2)


def distance_text(metres: float | None) -> str:
    if metres is None:
        return "—"
    for limit, text in ((1, "< 1 m"), (2, "~1–2 m"), (5, "~2–5 m"), (10, "~5–10 m"),
                        (20, "~10–20 m")):
        if metres < limit:
            return text
    return "20 m +"


# ------------------------------------------------------------- the watch
@dataclass
class Device:
    """One device across every broadcast heard from it."""

    address: str
    first_seen: float
    last_seen: float
    advert: Advert
    guess: Guess
    maker: str = ""
    heard: int = 0
    near_since: float = 0.0
    history: deque = field(default_factory=lambda: deque(maxlen=Watch.HISTORY))
    places: list = field(default_factory=list)   # (place key, label, first, last)
    # Its signal held steady: it moves only when the reading has moved by
    # Watch.STEADY dB, so a list sorted by it does not reshuffle on every
    # flicker. None = not heard for Watch.QUIET_AFTER seconds.
    level: float | None = None

    @property
    def rssi(self) -> int | None:
        return self.advert.rssi

    @property
    def name(self) -> str:
        return self.advert.name

    def smoothed(self, count: int = 5) -> float | None:
        readings = [v for v in list(self.history)[-count:] if v is not None]
        if not readings:
            return float(self.rssi) if self.rssi is not None else None
        return statistics.median(readings)

    @property
    def distance(self) -> float | None:
        return distance_m(self.smoothed(), self.guess.ref_1m)

    def readings(self) -> list[int]:
        """Every reading in the history (the gaps left out)."""
        return [v for v in self.history if v is not None]


@dataclass
class Flag:
    """The tracker safety check's verdict on one device."""

    level: str = ""       # "" (not a tracker), "ok", "watch" or "alert"
    text: str = ""
    why: str = ""


class Watch:
    """Every Bluetooth device heard, with a signal history per device —
    LIVE AIR's AirWatch for Bluetooth. `add` takes broadcasts as they
    arrive; `tick` closes one sampling interval (one point of history)."""

    HISTORY = 240          # readings kept per device
    FRESH = 8.0            # heard within this many seconds = present this tick
    QUIET_AFTER = 15.0     # not heard for this long: listed after those that are, reading greyed
    GONE_AFTER = 60.0      # not heard for this long = gone
    FORGET_AFTER = 900.0   # dropped from the list entirely
    LINGER = 10 * 60.0     # a tracker near you this long is worth a look
    PLACES_ALERT = 2       # ...and one seen on this many networks you were on
    STEADY = 4.0           # dB a reading must move before a device changes place

    def __init__(self, oui_lookup=None) -> None:
        self.devices: dict[str, Device] = {}
        self.updates = 0
        self.ticks = 0
        self.started: float | None = None
        self.oui_lookup = oui_lookup

    def add(self, adv: Advert, now: float | None = None) -> Device | None:
        now = time.time() if now is None else now
        key = (adv.address or "").upper()
        if not key:
            return None
        device = self.devices.get(key)
        if adv.rssi is None:
            # Not a broadcast heard now (BlueZ also reports a paired device
            # connecting, say): keep anything new it says, but it does not
            # count as heard — and a device never heard is not listed.
            if device is not None:
                device.advert = merge(device.advert, adv)
            return device
        if self.started is None:
            self.started = now
        self.updates += 1
        if device is None:
            maker = maker_of(adv, self.oui_lookup)
            device = Device(address=key, first_seen=now, last_seen=now, advert=adv,
                            guess=classify(adv, maker), maker=maker, near_since=now,
                            level=float(adv.rssi))
            self.devices[key] = device
        else:
            if now - device.last_seen > self.GONE_AFTER:
                device.near_since = now      # back after a gap: a new stretch nearby
            merged = merge(device.advert, adv)
            if _signature(merged) != _signature(device.advert):
                device.maker = maker_of(merged, self.oui_lookup)
                device.guess = classify(merged, device.maker)
            device.advert = merged
            device.last_seen = now
            if device.level is None:         # back after a quiet spell
                device.level = float(adv.rssi)
        device.heard += 1
        return device

    def tick(self, now: float | None = None) -> None:
        """One point of history per device: its latest reading if it was
        heard recently, a gap otherwise. Devices silent for FORGET_AFTER
        are dropped. Each device's steady level follows its recent readings
        once they have moved STEADY dB from it."""
        now = time.time() if now is None else now
        self.ticks += 1
        for key in list(self.devices):
            device = self.devices[key]
            age = now - device.last_seen
            if age > self.FORGET_AFTER:
                del self.devices[key]
                continue
            device.history.append(device.rssi if age <= self.FRESH else None)
            if age > self.QUIET_AFTER:
                device.level = None
                continue
            current = device.smoothed()
            if current is not None and (device.level is None
                                        or abs(current - device.level) >= self.STEADY):
                device.level = float(current)

    # ------------------------------------------------------------ views
    def present(self, now: float | None = None) -> list[Device]:
        now = time.time() if now is None else now
        return [d for d in self.devices.values() if now - d.last_seen <= self.GONE_AFTER]

    def gone(self, now: float | None = None) -> list[Device]:
        now = time.time() if now is None else now
        return [d for d in self.devices.values() if now - d.last_seen > self.GONE_AFTER]

    def quiet(self, device: Device, now: float | None = None) -> bool:
        """Still listed, but not heard for QUIET_AFTER seconds: its last
        reading is old news."""
        now = time.time() if now is None else now
        return now - device.last_seen > self.QUIET_AFTER

    def get(self, address: str) -> Device | None:
        return self.devices.get((address or "").upper())

    def nearest(self, now: float | None = None, trackers_only: bool = False) -> Device | None:
        """The device with the strongest steady signal among those heard in
        the last QUIET_AFTER seconds — never one that has gone quiet while
        its last reading was strong. With none heard lately, the one heard
        most recently."""
        now = time.time() if now is None else now
        present = [d for d in self.present(now) if not trackers_only or d.guess.tracker]
        heard = [d for d in present if d.level is not None and not self.quiet(d, now)]
        if heard:
            return max(heard, key=lambda d: (d.level, -d.first_seen))
        return max(present, key=lambda d: d.last_seen) if present else None

    def find(self, text: str, now: float | None = None) -> Device | None:
        """The device a typed name, address or kind refers to — or, with
        nothing typed, the nearest one heard right now."""
        if not text:
            return self.nearest(now)
        want = text.strip().lower()
        squash = re.sub(r"[^0-9a-f]", "", want)
        everything = self.ordered(now)
        if len(squash) >= 4 and len(squash) == len(re.sub(r"[\s:.-]", "", want)):
            # An address, whole or its last digits ("55:66", "aabbccddee01").
            for device in everything:
                if re.sub(r"[^0-9a-f]", "", device.address.lower()).endswith(squash):
                    return device
        for device in everything:
            if device.name and device.name.lower() == want:
                return device
        for device in everything:
            if want in device.name.lower() or want in device.guess.text.lower():
                return device
        return None

    def flag(self, device: Device, now: float | None = None) -> Flag:
        """Is this a tracker, and does it look like it is following you?"""
        now = time.time() if now is None else now
        if not device.guess.tracker:
            return Flag()
        near = max(0.0, device.last_seen - device.near_since)
        places = place_count(device)
        if device.guess.separated is False:
            return Flag("ok", "with owner",
                        "it reports being near its owner's phone — Find My only "
                        "flags a tracker that is away from its owner")
        if places >= self.PLACES_ALERT:
            labels = list(dict.fromkeys(label for _key, label, *_ in device.places))
            return Flag("alert", f"⚠ {places} places",
                        f"also heard on {places} networks you were on: " + ", ".join(labels))
        if near >= self.LINGER:
            return Flag("watch", f"⚠ {near / 60:.0f} min",
                        f"near you for {near / 60:.0f} minutes without a break")
        return Flag("ok", "tracker", "heard for "
                    + (f"{near / 60:.0f} min" if near >= 60 else f"{near:.0f} s"))

    def summary(self, now: float | None = None) -> list[tuple[str, int]]:
        """("phones", 3)… for what is present now, most numerous first;
        unknown devices last, as "other"."""
        present = self.present(now)
        out = []
        for one, many, kinds in SUMMARY_GROUPS:
            count = sum(1 for d in present if d.guess.kind in kinds)
            if count:
                out.append((one if count == 1 else many, count))
        out.sort(key=lambda item: -item[1])
        other = sum(1 for d in present
                    if not any(d.guess.kind in kinds for _o, _m, kinds in SUMMARY_GROUPS))
        if other:
            out.append(("other", other))
        return out

    def ordered(self, now: float | None = None) -> list[Device]:
        """Flagged trackers first; then everything heard lately, strongest
        steady signal first (a device changes place only when its signal
        has really moved — see STEADY); then the ones gone quiet, and those
        gone, most recently heard first."""
        now = time.time() if now is None else now
        rank = {"alert": 0, "watch": 1}

        def place(device: Device) -> tuple:
            flagged = rank.get(self.flag(device, now).level, 2)
            if device.level is not None and not self.quiet(device, now):
                return (flagged, 0, -device.level, device.first_seen)
            return (flagged, 1, -device.last_seen, device.first_seen)

        present = sorted(self.present(now), key=place)
        gone = sorted(self.gone(now), key=lambda d: -d.last_seen)
        return present + gone

    def export(self, now: float | None = None) -> tuple[list[str], list[list[object]]]:
        now = time.time() if now is None else now
        columns = ["address", "name", "device", "maker", "rssi_dbm", "distance",
                   "first_seen", "last_seen", "heard", "tracker_flag", "manufacturer_ids",
                   "service_uuids"]
        rows = []
        for device in self.ordered(now):
            flag = self.flag(device, now)
            rows.append([
                device.address, device.name, device.guess.text, device.maker,
                device.rssi if device.rssi is not None else "",
                distance_text(device.distance),
                _iso(device.first_seen), _iso(device.last_seen), device.heard,
                flag.text, " ".join(f"0x{k:04X}" for k in device.advert.manufacturer),
                " ".join(device.advert.service_uuids),
            ])
        return columns, rows


def place_count(device: Device) -> int:
    """How many different networks this machine was on when it heard the
    device (1 when it has only been heard here)."""
    return len({key for key, *_ in device.places}) or 1


# ---------------------------------------------------- one device, in full
def address_kind(device: Device) -> str:
    """What sort of address it broadcasts from. A random address's top two
    bits say whether it is static or a private one that keeps changing."""
    kind = device.advert.address_type
    if kind == "public":
        return "public — the maker's fixed address"
    if kind != "random":
        return "type not reported"
    try:
        top = int(device.address[:2], 16) >> 6
    except ValueError:
        return "random"
    return {3: "random, static — kept until it restarts",
            1: "random, private — changes every few minutes",
            0: "random, private, not resolvable"}.get(top, "random")


def _service_label(uuid: str) -> str:
    short = short_uuid(uuid)
    if short is None:
        return uuid
    name = uuid_name(short)
    return f"{name} (0x{short:04X})" if name else f"0x{short:04X}"


def span_text(seconds: float) -> str:
    """4 s, 12 min, 1 h 05 min."""
    seconds = max(0.0, seconds)
    if seconds < 60:
        return f"{seconds:.0f} s"
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes} min"
    return f"{minutes // 60} h {minutes % 60:02d} min"


def about_rows(device: Device) -> list[tuple[str, object]]:
    """Everything one device's broadcasts say about it, for the panel shown
    when a view shows only that device."""
    adv, guess = device.advert, device.guess
    rows: list[tuple[str, object]] = [
        ("Name", device.name or "— (it broadcasts none)"),
        ("Best guess", guess.text + ("  (decoded from its broadcast)" if guess.sure
                                     else "  (a guess from its name, class or maker)")),
        ("Maker", device.maker or "— (not in its broadcast)"),
        ("Address", f"{device.address}  ·  {address_kind(device)}"),
    ]
    if adv.manufacturer:
        rows.append(("Manufacturer data", "; ".join(
            f"0x{cid:04X} {short_company(company_name(cid)) or 'unregistered'} · "
            f"{len(data)} bytes" for cid, data in adv.manufacturer.items())))
    uuids = list(dict.fromkeys([*adv.service_data.keys(), *adv.service_uuids]))
    if uuids:
        rows.append(("Services", ", ".join(_service_label(u) for u in uuids[:6])
                     + (f" … +{len(uuids) - 6}" if len(uuids) > 6 else "")))
    if adv.tx_power is not None:
        rows.append(("Transmit power", f"{adv.tx_power} dBm (as it reports)"))
    if guess.ref_1m is not None:
        rows.append(("Calibrated at 1 m", f"{guess.ref_1m} dBm (from its broadcast)"))
    if adv.appearance:
        rows.append(("Appearance", f"0x{adv.appearance:04X}"))
    if adv.device_class:
        rows.append(("Class of device", f"0x{adv.device_class:06X}"))
    if adv.icon:
        rows.append(("BlueZ calls it", adv.icon))
    if adv.paired or adv.connected:
        rows.append(("Paired with this machine",
                     ("yes" if adv.paired else "no")
                     + (" · connected now" if adv.connected else "")))
    return rows


def signal_rows(watch: "Watch", device: Device, now: float | None = None) -> list[tuple[str, object]]:
    """One device's signal and sightings, for the same panel."""
    now = time.time() if now is None else now
    readings = device.readings()
    rows: list[tuple[str, object]] = []
    if device.rssi is not None:
        rows.append(("Signal now", f"{device.rssi} dBm"
                     + (f" — last heard {ago(now - device.last_seen)}"
                        if watch.quiet(device, now) else "")))
    if readings:
        rows.append(("Lowest / average / highest",
                     f"{min(readings)} / {statistics.mean(readings):.0f} / {max(readings)} dBm"
                     f"  ({len(readings)} readings)"))
    ref = device.guess.ref_1m
    rows.append(("Rough distance",
                 f"{distance_text(device.distance)}  (taking {REF_1M if ref is None else ref} "
                 f"dBm at 1 m — {'its own figure' if ref is not None else 'typical for a phone or tag'})"))
    lasted = max(1.0, device.last_seen - device.first_seen)
    rows.append(("Broadcasts heard", f"{device.heard:,}"
                 + (f"  ·  {device.heard / lasted:.1f} a second" if device.heard > 1 else "")))
    rows.append(("First heard", f"{clock(device.first_seen)}  ({ago(now - device.first_seen)})"))
    rows.append(("Last heard", ago(now - device.last_seen)))
    rows.append(("Near you for", span_text(device.last_seen - device.near_since)))
    flag = watch.flag(device, now)
    if flag.level:
        rows.append(("Tracker check", f"{flag.text} — {flag.why}"))
    labels = list(dict.fromkeys(label for _key, label, *_ in device.places))
    if labels:
        rows.append(("Heard on these networks", ", ".join(labels)))
    return rows


def _signature(adv: Advert) -> tuple:
    return (adv.name, tuple(sorted((k, v[:4]) for k, v in adv.manufacturer.items())),
            tuple(sorted(adv.service_data)), tuple(adv.service_uuids), adv.appearance,
            adv.device_class, adv.icon)


def _iso(stamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stamp))


def clock(stamp: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(stamp))


def ago(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 3:
        return "now"
    if seconds < 60:
        return f"{seconds:.0f}s ago"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m ago"
    return f"{seconds / 3600:.1f}h ago"


def sparkline_cells(history, count: int = 14, span: float = 12.0) -> list[tuple[str, float | None]]:
    """The last `count` readings as (glyph, dBm) pairs, a gap as "·".

    Heights are scaled to this device's own readings — over at least `span`
    dB, so a steady signal stays flat instead of turning noise into peaks —
    which makes it walking closer or away visible at a glance; the colour each
    glyph is drawn in (the caller's) carries the absolute strength."""
    ramp = "▁▂▃▄▅▆▇█"
    values = list(history)[-count:]
    readings = [float(v) for v in values if v is not None]
    if not readings:
        return [("·", None) for _ in values]
    low, high = min(readings), max(readings)
    if high - low < span:
        middle = (high + low) / 2
        low, high = middle - span / 2, middle + span / 2
    out = []
    for value in values:
        if value is None:
            out.append(("·", None))
            continue
        level = (float(value) - low) / (high - low)
        out.append((ramp[max(0, min(len(ramp) - 1, int(level * len(ramp))))], float(value)))
    return out


# ------------------------------------------------------------ where you are
@dataclass(frozen=True)
class Place:
    """Where this machine is, as far as its network says: the gateway's
    address (and Wi-Fi name). Used to tell 'the same tracker on two networks
    I was on' — it never leaves this machine."""

    key: str
    label: str


def place_from(gateway_ip: str = "", gateway_mac: str = "", ssid: str = "") -> Place:
    if not gateway_ip and not ssid:
        return Place("offline", "no network")
    basis = f"{(gateway_mac or gateway_ip).lower()}|{ssid}"
    key = hashlib.sha1(basis.encode()).hexdigest()[:12]
    label = f"Wi-Fi {ssid}" if ssid else f"network via {gateway_ip}"
    return Place(key, label)


async def current_place(wifi_iface: str = "") -> Place:
    """This machine's place now: default gateway, its MAC, and the Wi-Fi
    network name when on Wi-Fi. Reads local tables only — no packets."""
    from . import lan, netif, wifitools

    gateway = ""
    try:
        gateways = await netif.default_gateways()
        gateway = gateways[0] if gateways else ""
    except Exception:
        gateway = ""
    mac = ""
    if gateway:
        try:
            mac = (await lan.arp_table()).get(gateway, "")
        except Exception:
            mac = ""
    ssid = ""
    if wifi_iface:
        try:
            link = await wifitools.link_now(wifi_iface)
            if link.get("connected"):
                ssid = str(link.get("ssid") or "")
        except Exception:
            ssid = ""
    return place_from(gateway, mac, ssid)


# ------------------------------------------------------------ the scanner
class BluetoothUnavailable(Exception):
    """Scanning cannot start; the message says why and what to do."""

    def __init__(self, title: str, message: str) -> None:
        super().__init__(message)
        self.title = title
        self.message = message


INSTALL_HINTS = (
    "Bluetooth scanning needs a Bluetooth radio Linux can see — a laptop's own "
    "or a USB dongle — and the BlueZ service:\n\n"
    "    sudo apt install bluez            # usually already installed\n"
    "    sudo systemctl enable --now bluetooth\n"
    "    rfkill unblock bluetooth          # if it is blocked\n"
    "    bluetoothctl power on\n\n"
    "No root is needed to scan. A virtual machine normally cannot see the "
    "host's Bluetooth radio."
)


def explain(exc: BaseException) -> BluetoothUnavailable:
    """Turn whatever bleak or D-Bus raised into a title and what to do."""
    if isinstance(exc, BluetoothUnavailable):
        return exc
    text = f"{exc.__class__.__name__}: {exc}"
    reason = getattr(getattr(exc, "reason", None), "name", "")
    low = text.lower()
    if isinstance(exc, ImportError):
        return BluetoothUnavailable(
            "Bluetooth library missing",
            "netzilla scans with the 'bleak' library, which is not installed in "
            "netzilla's environment. Reinstall from the unpacked folder:\n\n"
            "    pipx install --force .")
    if reason == "NO_BLUETOOTH" or "no bluetooth adapters" in low or "adapter" in low \
            and "not found" in low:
        return BluetoothUnavailable(
            "No Bluetooth adapter",
            "This machine has no Bluetooth radio that Linux can see. A laptop's "
            "built-in Bluetooth or a USB dongle works; a virtual machine (Hyper-V, "
            "VirtualBox, WSL…) normally cannot see the host's.")
    if reason == "POWERED_OFF" or "notready" in low or "not ready" in low \
            or "no powered" in low:
        return BluetoothUnavailable(
            "Bluetooth is off",
            "The Bluetooth radio is switched off. Turn it on in the system "
            "settings or tray, or:\n\n"
            "    rfkill unblock bluetooth\n"
            "    bluetoothctl power on")
    if reason.startswith("DENIED") or "permission" in low or "not authorized" in low \
            or "accessdenied" in low or "access denied" in low:
        return BluetoothUnavailable(
            "Bluetooth permission denied",
            "The system refused access to Bluetooth. On Linux, check that "
            "bluetoothd is running and your account is allowed to use it; on "
            "macOS, allow this terminal under System Settings → Privacy & "
            "Security → Bluetooth.")
    if "serviceunknown" in low or "org.bluez was not provided" in low \
            or "name has no owner" in low:
        return BluetoothUnavailable(
            "Bluetooth service not running",
            "BlueZ (bluetoothd), the service that drives the radio, is not "
            "running:\n\n    sudo systemctl enable --now bluetooth")
    if isinstance(exc, (FileNotFoundError, ConnectionRefusedError)) or "dbus" in low \
            and ("connect" in low or "socket" in low):
        return BluetoothUnavailable(
            "Bluetooth service unreachable",
            "netzilla could not reach the system D-Bus, which BlueZ uses. Bluetooth "
            "scanning works on Linux with BlueZ, and on macOS.")
    if "inprogress" in low or "in progress" in low:
        return BluetoothUnavailable(
            "Bluetooth busy",
            "Another program is in the middle of starting a Bluetooth scan. Try "
            "again in a moment.")
    return BluetoothUnavailable("Bluetooth scan failed", text)


class Scanner:
    """bleak's BleakScanner, reporting each broadcast as an Advert. Never
    pairs or connects. `classic` also lists classic (BR/EDR) devices that are
    in discoverable mode, between LE scans."""

    def __init__(self, on_advert, adapter: str = "", classic: bool = True) -> None:
        self.on_advert = on_advert
        self.adapter = adapter
        self.classic = classic
        self._scanner = None
        self.backend = ""

    async def start(self) -> None:
        try:
            from bleak import BleakScanner
        except Exception as exc:        # ImportError, or a broken dbus-fast
            raise explain(exc if isinstance(exc, ImportError) else ImportError(str(exc)))
        bluez: dict = {"filters": {"Transport": "auto" if self.classic else "le",
                                   "DuplicateData": True}}
        if self.adapter:
            bluez["adapter"] = self.adapter
        try:
            self._scanner = BleakScanner(self._callback, scanning_mode="active", bluez=bluez)
            await self._scanner.start()
        except Exception as exc:
            self._scanner = None
            raise explain(exc) from exc
        backend = str(getattr(getattr(self._scanner, "backend_id", ""), "value", "") or "")
        self.backend = {"bluez_dbus": "BlueZ", "corebluetooth": "CoreBluetooth",
                        "winrt": "WinRT"}.get(backend, backend or "bleak")
        if self.backend == "BlueZ" and self.adapter:
            self.backend += f" ({self.adapter})"

    def _callback(self, device, adv) -> None:
        try:
            self.on_advert(from_bleak(device, adv))
        except Exception:
            pass        # one malformed broadcast must not end the scan

    async def stop(self) -> None:
        scanner, self._scanner = self._scanner, None
        if scanner is not None:
            try:
                await scanner.stop()
            except Exception:
                pass


# ------------------------------------------------------------- TOOL CHECK
def parse_bluetoothctl_show(text: str) -> dict:
    """The default controller from `bluetoothctl show`; {} when there is none."""
    info: dict = {}
    for line in text.splitlines():
        stripped = line.strip()
        match = re.match(r"Controller\s+([0-9A-F:]{17})", stripped, re.I)
        if match and "address" not in info:
            info["address"] = match.group(1).upper()
            continue
        if ":" not in stripped or "address" not in info:
            continue
        key, _, value = stripped.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key in ("name", "alias") and key not in info:
            info[key] = value
        elif key == "powered":
            info["powered"] = value.lower() == "yes"
        elif key == "discovering":
            info["discovering"] = value.lower() == "yes"
        elif key == "roles":
            info.setdefault("roles", []).append(value)
    return info


def parse_rfkill(text: str) -> list[dict]:
    """Bluetooth radios from `rfkill list bluetooth`."""
    radios: list[dict] = []
    for line in text.splitlines():
        match = re.match(r"\s*\d+:\s*(\S+):\s*(.+)", line)
        if match:
            radios.append({"name": match.group(1), "type": match.group(2).strip(),
                           "soft": False, "hard": False})
            continue
        stripped = line.strip().lower()
        if radios and stripped.startswith("soft blocked:"):
            radios[-1]["soft"] = stripped.endswith("yes")
        elif radios and stripped.startswith("hard blocked:"):
            radios[-1]["hard"] = stripped.endswith("yes")
    return [r for r in radios if "bluetooth" in r["type"].lower() or r["name"].startswith("hci")]


async def tool_report() -> tuple[list[tuple[str, object]], str]:
    """TOOL CHECK's Bluetooth rows, and what (if anything) stops BLUETOOTH
    from working — "" when it should."""
    from .runner import have, run

    rows: list[tuple[str, object]] = []
    problem = ""
    try:
        from importlib.metadata import version

        rows.append(("bleak (Bluetooth scanning library)", version("bleak")))
    except Exception:
        rows.append(("bleak (Bluetooth scanning library)",
                     "MISSING — reinstall: pipx install --force ."))
        problem = "the bleak library is missing"
    if have("systemctl"):
        result = await run(["systemctl", "is-active", "bluetooth"], timeout=4,
                           ok_returncodes=(0, 3, 4))
        state = (result.output or "").strip() or "unknown"
        rows.append(("BlueZ service (bluetoothd)",
                     "running" if state == "active" else
                     f"{state} — sudo systemctl enable --now bluetooth"))
        if state != "active" and not problem:
            problem = "the Bluetooth service is not running"
    if have("bluetoothctl"):
        result = await run(["bluetoothctl", "show"], timeout=4, ok_returncodes=(0, 1))
        info = parse_bluetoothctl_show(result.output or "")
        if info:
            powered = info.get("powered")
            rows.append(("Bluetooth adapter",
                         f"{info.get('alias') or info.get('name') or ''} {info['address']} · "
                         + ("powered on" if powered else
                            "powered OFF — bluetoothctl power on")))
            if not powered and not problem:
                problem = "Bluetooth is switched off"
        elif "timed out" in (result.error or ""):
            rows.append(("Bluetooth adapter", "bluetoothd did not answer"))
            problem = problem or "the Bluetooth service did not answer"
        else:
            rows.append(("Bluetooth adapter", "none found"))
            problem = problem or "no Bluetooth adapter was found"
    else:
        rows.append(("bluetoothctl", False))
    if have("rfkill"):
        result = await run(["rfkill", "list", "bluetooth"], timeout=4)
        radios = parse_rfkill(result.output or "")
        if radios:
            blocked = [r for r in radios if r["soft"] or r["hard"]]
            rows.append(("Bluetooth radio block (rfkill)",
                         "not blocked" if not blocked else
                         ", ".join(f"{r['name']} {'hard' if r['hard'] else 'soft'}-blocked"
                                   for r in blocked)
                         + ("" if not blocked else " — rfkill unblock bluetooth")))
            if blocked and not problem:
                problem = "the Bluetooth radio is blocked (rfkill)"
    return rows, problem


__all__ = [
    "Advert", "Guess", "Device", "Flag", "Watch", "Place", "Scanner",
    "BluetoothUnavailable", "classify", "maker_of", "company_name", "uuid_name",
    "distance_m", "distance_text", "explain", "from_bleak", "merge", "place_from",
    "current_place", "parse_bluetoothctl_show", "parse_rfkill", "tool_report",
    "sparkline_cells", "clock", "ago", "INSTALL_HINTS", "KIND_TITLES",
]
