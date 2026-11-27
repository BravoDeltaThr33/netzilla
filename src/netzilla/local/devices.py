"""Device identification — "what actually IS 10.0.0.185?"

A sweep finds addresses. This turns them into devices, using only what the
devices on your own LAN already say about themselves, with no API and no key:

  Vendor      the MAC's maker, from the bundled IEEE registry (oui.py)
  Private MAC a locally administered address — a phone, tablet or laptop
              using a randomised Wi-Fi address, which has no maker to look up
  Reverse DNS a PTR lookup, asked of this machine's resolver and of the
              gateway itself — home routers answer with the name each device
              gave when it took its DHCP lease ("Jordans-iPhone")
  mDNS        a unicast query to the device's own port 5353 for its name and
              the services it advertises (_airplay, _googlecast, _ipp …), plus
              the model string many of them publish ("MacBookPro18,3",
              "Chromecast Ultra", "HP OfficeJet Pro 8020")
  NetBIOS     a node-status query to udp/137: the computer name and workgroup
              a Windows PC or Samba server reports
  UPnP        one SSDP search of the LAN, then each responder's own device
              description: friendly name, manufacturer, model
  TTL         the hop limit on the ping reply — 64 for Linux/Apple/Android,
              128 for Windows, 255 for most network gear

The evidence is weighed into one best guess at what the device is ("Fire TV",
"Printer", "Windows PC") with the reasons kept alongside, so the table can be
checked rather than taken on faith. Everything is best-effort and bounded by
short timeouts: a device that answers none of it is still listed, just with
less to say about it.

Where the questions go: the device probes (mDNS, NetBIOS, UPnP) go only to
the addresses being identified, and addresses found some other way — a
connection in FLOW, a syslog sender, a packet in CAPTURE — are only probed
when they sit on one of this machine's own LAN segments, never across a VPN.
Reverse DNS for a LAN address is asked of the router first and never of a
resolver elsewhere (a VPN's corporate DNS, say), so your LAN's inventory
does not leave it. SWEEP alone also sends one SSDP search to the local
segment. Scan only networks you own or are authorised to manage.

The packet builders and parsers are pure functions and are tested against
real captured replies; the probes themselves are thin async wrappers.
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import re
import socket
import struct
from pathlib import Path

from . import oui

# ------------------------------------------------------------------ timeouts
DNS_TIMEOUT = 1.5
MDNS_TIMEOUT = 1.2
MDNS_FOLLOWUP_TIMEOUT = 0.9
NETBIOS_TIMEOUT = 1.0
SSDP_WINDOW = 2.5
SSDP_UNICAST_TIMEOUT = 1.0
HTTP_TIMEOUT = 2.0
PORT_TIMEOUT = 0.8
# Past this many devices the rest get vendor/private-MAC columns only (the
# ping-responders come first, so they are the ones probed); the summary says
# how many were skipped. Keeps a /22 from turning into a long wait.
MAX_PROBED = 256


# =========================================================== vendor naming
_LEGAL_SUFFIX = re.compile(
    r"(,|\s)+(inc\.?|incorporated|corp\.?|corporation|corporate|co\.?,?\s*ltd\.?|"
    r"co\.?|ltd\.?|limited|llc|l\.l\.c\.|gmbh|ag|s\.a\.s?\.?|sas|b\.v\.|bv|"
    r"s\.p\.a\.|oy|ab|plc|pte\.?|pty\.?|kk|k\.k\.|technologies|technology|"
    r"electronics|international|holdings?)\.?$",
    re.I,
)

# Registry names that are long, legal or not the name anyone uses.
_SHORT_NAMES = (
    ("sony interactive", "Sony (PlayStation)"),
    ("vantiva", "Vantiva (Technicolor)"),
    ("technicolor", "Technicolor"),
    ("hon hai", "Foxconn"),
    ("hewlett packard enterprise", "HPE / Aruba"),
    ("hewlett packard", "HP"),
    ("hp inc", "HP"),
    ("tp-link", "TP-Link"),
    ("amazon technologies", "Amazon"),
    ("google", "Google"),
    ("apple", "Apple"),
    ("samsung", "Samsung"),
    ("raspberry pi", "Raspberry Pi"),
    ("espressif", "Espressif"),
    ("microsoft", "Microsoft"),
    ("nintendo", "Nintendo"),
    ("intel corporate", "Intel"),
    ("liteon", "Lite-On"),
    ("lite-on", "Lite-On"),
    ("azurewave", "AzureWave"),
    ("murata", "Murata"),
    ("universal global scientific", "USI"),
    ("seiko epson", "Epson"),
    ("brother industries", "Brother"),
    ("lg electronics", "LG"),
    ("lg innotek", "LG Innotek"),
    ("arris", "ARRIS"),
    ("commscope", "CommScope (ARRIS)"),
    ("sagemcom", "Sagemcom"),
    ("ubiquiti", "Ubiquiti"),
    ("netgear", "Netgear"),
    ("eero", "eero"),
    ("roku", "Roku"),
    ("sonos", "Sonos"),
    ("tuya", "Tuya"),
    ("signify", "Philips Hue (Signify)"),
    ("philips lighting", "Philips Hue"),
    ("cisco", "Cisco"),
    ("dell", "Dell"),
    ("lenovo", "Lenovo"),
    ("asustek", "ASUS"),
    ("micro-star", "MSI"),
    ("realtek", "Realtek"),
    ("vmware", "VMware"),
    ("chamberlain", "Chamberlain (myQ)"),
    ("ring llc", "Ring"),
    ("wyze", "Wyze"),
    ("nest labs", "Nest"),
    ("ecobee", "ecobee"),
    ("synology", "Synology"),
    ("qnap", "QNAP"),
    ("belkin", "Belkin"),
    ("xiaomi", "Xiaomi"),
    ("huawei", "Huawei"),
)


def short_vendor(name: str | None, width: int = 26) -> str:
    """A readable vendor name for a narrow table column."""
    if not name:
        return ""
    lowered = name.lower()
    for needle, short in _SHORT_NAMES:
        if _has_word(lowered, needle):
            return short
    cleaned = name.strip().strip(",.")
    for _ in range(3):                      # "Foo Technology Co., Ltd."
        stripped = _LEGAL_SUFFIX.sub("", cleaned).strip().strip(",.")
        if stripped == cleaned or not stripped:
            break
        cleaned = stripped
    if cleaned.isupper() and len(cleaned) > 4:
        cleaned = cleaned.title()
    return cleaned if len(cleaned) <= width else cleaned[: width - 1] + "…"


def _has_word(text: str, needle: str) -> bool:
    """needle appears in text as whole words ('arris' is not in 'Harris')."""
    return re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", text) is not None


# Hypervisors and container runtimes. Several are locally administered
# (QEMU's 52:54:00, Docker's 02:42) and would otherwise read as a phone's
# private address; the rest are registered to a company whose name does not
# say "virtual" (Hyper-V is "Microsoft", VirtualBox "PCS Systemtechnik").
VIRTUAL_PREFIXES = (
    ("00155D", "Hyper-V virtual NIC"),
    ("525400", "QEMU / KVM virtual NIC"),
    ("080027", "VirtualBox virtual NIC"),
    ("0242", "Docker container"),
    ("000C29", "VMware virtual NIC"),
    ("005056", "VMware virtual NIC"),
    ("000569", "VMware virtual NIC"),
    ("001C42", "Parallels virtual NIC"),
    ("00163E", "Xen virtual NIC"),
)


def virtual_nic(mac: str | None) -> str:
    digits = oui.hex_only(mac or "")
    for prefix, name in VIRTUAL_PREFIXES:
        if digits.startswith(prefix):
            return name
    return ""


def vendor_for(mac: str | None) -> tuple[str, str]:
    """(full vendor or "", kind) for a MAC. kind is oui.mac_kind()'s, or
    'virtual' for a hypervisor/container address."""
    if not mac:
        return "", "none"
    virtual = virtual_nic(mac)
    if virtual:
        return virtual, "virtual"
    kind = oui.mac_kind(mac)
    if kind != "global":
        return "", kind
    return oui.lookup_mac(mac) or "", kind


# ========================================================= DNS wire format
QTYPE = {"A": 1, "PTR": 12, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255}
_TYPE_NAME = {v: k for k, v in QTYPE.items()}


def encode_name(name) -> bytes:
    """A dotted name, or a tuple of labels when a label may itself contain a
    dot (a service instance called "Mr. Speaker")."""
    labels = name if isinstance(name, (tuple, list)) else name.rstrip(".").split(".")
    out = b""
    for label in labels:
        raw = label.encode("utf-8")[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(qid: int, questions: list[tuple[str, str]],
                unicast_response: bool = False) -> bytes:
    """A standard query. `questions` is [(name, "PTR"), …].

    unicast_response sets mDNS's QU bit, asking a responder to answer this
    socket directly rather than the multicast group.
    """
    header = struct.pack("!HHHHHH", qid & 0xFFFF, 0x0000 if unicast_response
                         else 0x0100, len(questions), 0, 0, 0)
    body = b""
    qclass = 0x8001 if unicast_response else 0x0001
    for name, qtype in questions:
        body += encode_name(name) + struct.pack("!HH", QTYPE[qtype], qclass)
    return header + body


def _read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a (possibly compressed) name. Returns (name, next offset)."""
    labels = []
    jumped_to = None
    jumps = 0
    while True:
        if offset >= len(data):
            raise ValueError("name runs off the end of the packet")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if jumped_to is None:
                jumped_to = offset + 2
            jumps += 1
            if jumps > 20 or pointer >= len(data):
                raise ValueError("bad compression pointer")
            offset = pointer
            continue
        offset += 1
        labels.append(data[offset: offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (jumped_to if jumped_to is not None else offset)


def parse_message(data: bytes) -> dict:
    """{'id', 'rcode', 'answers': [(name, type, rdata), …]} — answers,
    authority and additional records together, since mDNS responders put
    the useful TXT/SRV/A records in the additional section."""
    if len(data) < 12:
        raise ValueError("short DNS message")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        _name, offset = _read_name(data, offset)
        offset += 4
    records = []
    for _ in range(an + ns + ar):
        # A record that runs off the end (truncated, or a count larger than
        # what was sent) ends the parse; everything before it is kept.
        try:
            name, offset = _read_name(data, offset)
        except ValueError:
            break
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset: offset + 10])
        offset += 10
        rdata_at, offset = offset, offset + rdlength
        if offset > len(data):
            break
        records.append((name, _TYPE_NAME.get(rtype, str(rtype)),
                        _rdata(data, rtype, rdata_at, rdlength)))
    return {"id": qid, "rcode": flags & 0x000F, "answers": records}


def _rdata(data: bytes, rtype: int, at: int, length: int):
    chunk = data[at: at + length]
    try:
        if rtype == QTYPE["PTR"]:
            return _read_name(data, at)[0]
        if rtype == QTYPE["A"] and length == 4:
            return socket.inet_ntoa(chunk)
        if rtype == QTYPE["AAAA"] and length == 16:
            return socket.inet_ntop(socket.AF_INET6, chunk)
        if rtype == QTYPE["SRV"] and length >= 7:
            prio, weight, port = struct.unpack("!HHH", chunk[:6])
            return (prio, weight, port, _read_name(data, at + 6)[0])
        if rtype == QTYPE["TXT"]:
            strings, pos = [], 0
            while pos < len(chunk):
                size = chunk[pos]
                strings.append(chunk[pos + 1: pos + 1 + size].decode("utf-8", "replace"))
                pos += 1 + size
            return strings
    except (ValueError, OSError, struct.error):
        return None
    return chunk


def reverse_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer


def txt_pairs(strings) -> dict[str, str]:
    pairs = {}
    for item in strings or ():
        if "=" in item:
            key, _, value = item.partition("=")
            pairs[key.strip().lower()] = value.strip()
    return pairs


# ================================================================== UDP I/O
class _Collector(asyncio.DatagramProtocol):
    """Gathers replies; resolves `done` early when there is enough, or when
    the target says nothing is listening (ICMP port unreachable)."""

    def __init__(self, until=None) -> None:
        self.packets: list[tuple[bytes, tuple]] = []
        self.until = until
        self.refused = False
        self.done: asyncio.Future = asyncio.get_running_loop().create_future()

    def _finish(self) -> None:
        if not self.done.done():
            self.done.set_result(None)

    def datagram_received(self, data, addr) -> None:
        self.packets.append((data, addr))
        if self.until is not None and self.until(self.packets):
            self._finish()

    def error_received(self, exc) -> None:
        # Only a *connected* UDP socket hears about ICMP port-unreachable;
        # that is what lets a silent-but-alive host be skipped at once
        # instead of costing the whole timeout. (Windows reports it as a
        # connection reset rather than refused.)
        if isinstance(exc, (ConnectionRefusedError, ConnectionResetError)):
            self.refused = True
            self._finish()

    def connection_lost(self, exc) -> None:
        self._finish()


async def udp_exchange(
    host: str, port: int, payloads: list[bytes], timeout: float,
    until=None, sock: socket.socket | None = None, connect: bool = True,
) -> list[tuple[bytes, tuple]]:
    """Send payloads to host:port and collect replies for up to `timeout`
    seconds, or until `until(packets)` says there is enough. Never raises.

    By default the socket is connected to the target, so replies can only
    come from it and a closed port ends the wait immediately. Pass
    connect=False when replies may come from another port (unicast SSDP),
    or a pre-built `sock` for multicast.
    """
    loop = asyncio.get_running_loop()
    collector = _Collector(until)
    try:
        if sock is not None:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: collector, sock=sock,
            )
        elif connect:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: collector, remote_addr=(host, port),
            )
        else:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            transport, _ = await loop.create_datagram_endpoint(
                lambda: collector, family=family,
            )
    except OSError:
        if sock is not None:
            sock.close()
        return []
    try:
        for payload in payloads:
            try:
                if connect and sock is None:
                    transport.sendto(payload)
                else:
                    transport.sendto(payload, (host, port))
            except OSError:
                return []
        try:
            await asyncio.wait_for(asyncio.shield(collector.done), timeout)
        except asyncio.TimeoutError:
            pass
        return list(collector.packets)
    finally:
        transport.close()


# ============================================================ reverse DNS
def nameservers(path: str = "/etc/resolv.conf") -> list[str]:
    """The resolvers this machine asks: /etc/resolv.conf on Linux and macOS
    (macOS keeps it current), the adapters' own DNS servers on Windows."""
    from .. import hostos

    if hostos.is_windows() and path == "/etc/resolv.conf":
        from . import netif

        return netif.windows_dns(netif._windows_adapters())
    servers = []
    try:
        for line in Path(path).read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                servers.append(parts[1].split("%")[0])
    except OSError:
        pass
    return servers


_UNINFORMATIVE = re.compile(
    r"(^|[.-])(\d{1,3}[.-]){3}\d{1,3}([.-]|$)|^ip-|^host-|^dhcp-?\d|"
    r"^(c|cpe|static|dynamic|pool)-", re.I,
)


def useful_hostname(name: str | None, ip: str = "") -> str:
    """The name, or "" if it is just the address spelled out."""
    if not name:
        return ""
    name = name.rstrip(".")
    if name.startswith("_"):
        # systemd-resolved invents '_gateway', '_outbound' and friends for
        # its own bookkeeping; they name nothing on the network.
        return ""
    first = name.split(".")[0]
    if not first or first.lower() in ("localhost", "unknown", "*"):
        return ""
    if _UNINFORMATIVE.search(name):
        return ""
    if ip and ip.replace(".", "-") in name:
        return ""
    return name


def short_host(name: str) -> str:
    """'Jordans-iPhone.home.example.net' -> 'Jordans-iPhone'; keeps a
    .local name's first label too."""
    if not name:
        return ""
    return name.rstrip(".").split(".")[0]


def dns_servers_for(ip: str, context: dict, resolvers: list[str] | None = None) -> list[list[str]]:
    """Who to ask for a PTR, as tiers asked in order.

    A LAN address is asked of the router first — it handed out the lease and
    knows the name the device gave — and then only of resolvers on this
    machine or its own LAN (the systemd-resolved stub, a Pi-hole). A remote
    resolver, such as a VPN's corporate DNS, is never asked about home
    addresses. Anything else goes to the system resolvers as usual.
    """
    resolvers = nameservers() if resolvers is None else resolvers
    if not is_local(ip, context):
        return [resolvers]
    # A full-tunnel VPN adds its own default gateway; only a gateway on the
    # LAN itself knows the names of the devices on it.
    gateways = sorted(g for g in context.get("gateways", ()) if is_local(g, context))
    nearby = []
    for server in resolvers:
        try:
            address = ipaddress.ip_address(server)
        except ValueError:
            continue
        if address.is_loopback or is_local(server, context):
            nearby.append(server)
    tiers = [gateways, [s for s in nearby if s not in gateways]]
    return [tier for tier in tiers if tier]


async def reverse_dns(ip: str, servers, timeout: float = DNS_TIMEOUT) -> str:
    """PTR for ip. `servers` is a list of addresses asked together, or a
    list of such lists asked tier by tier until one gives a name."""
    tiers = servers if servers and isinstance(servers[0], list) else [servers]
    for tier in tiers:
        name = await _reverse_dns_tier(ip, tier, timeout)
        if name:
            return name
    return ""


async def _reverse_dns_tier(ip: str, servers: list[str], timeout: float) -> str:
    try:
        question = reverse_name(ip)
    except ValueError:
        return ""
    targets = [s for s in dict.fromkeys(servers) if s]
    if not targets:
        return ""

    async def ask(server: str) -> str:
        qid = random.randrange(1, 0xFFFF)
        packets = await udp_exchange(
            server, 53, [build_query(qid, [(question, "PTR")])], timeout,
            until=lambda got: bool(got),
        )
        for data, _addr in packets:
            try:
                message = parse_message(data)
            except ValueError:
                continue
            if message["id"] != qid:
                continue
            for name, rtype, rdata in message["answers"]:
                if (rtype == "PTR" and isinstance(rdata, str) and rdata
                        and not rdata.startswith("_")):
                    return rdata
        return ""

    tasks = [asyncio.ensure_future(ask(s)) for s in targets]
    try:
        for next_done in asyncio.as_completed(tasks):
            name = await next_done
            if name:
                return name
        return ""
    finally:
        for task in tasks:
            task.cancel()


# ==================================================================== mDNS
SERVICES_QUERY = "_services._dns-sd._udp.local"

# service -> (short label for the details column, device it suggests or "",
# how strongly it suggests it). Unlisted services still show, unlabelled.
SERVICE_INFO: dict[str, tuple[str, str, int]] = {
    "_googlecast._tcp": ("Google Cast", "Chromecast / Google TV", 72),
    "_airplay._tcp": ("AirPlay", "AirPlay receiver", 55),
    "_raop._tcp": ("AirPlay audio", "AirPlay speaker", 50),
    "_companion-link._tcp": ("Apple Continuity", "Apple device", 58),
    "_apple-mobdev2._tcp": ("iOS sync", "iPhone / iPad", 74),
    "_rdlink._tcp": ("Apple rdlink", "Apple device", 45),
    "_sleep-proxy._udp": ("Sleep Proxy", "Apple TV / HomePod", 52),
    # A Linux box sharing a printer advertises _ipp too, so on its own it
    # must not outrank a Linux hostname; real printers add more below.
    "_ipp._tcp": ("IPP print", "Printer", 60),
    "_ipps._tcp": ("IPPS print", "Printer", 60),
    "_printer._tcp": ("LPD print", "Printer", 76),
    "_pdl-datastream._tcp": ("RAW print", "Printer", 76),
    "_uscan._tcp": ("eSCL scan", "Printer / scanner", 74),
    "_scanner._tcp": ("scanner", "Printer / scanner", 70),
    "_hap._tcp": ("HomeKit", "HomeKit accessory", 60),
    "_hap._udp": ("HomeKit", "HomeKit accessory", 60),
    "_matter._tcp": ("Matter", "Matter smart-home device", 58),
    "_matterc._udp": ("Matter", "Matter smart-home device", 58),
    "_meshcop._udp": ("Thread", "Thread border router", 56),
    "_spotify-connect._tcp": ("Spotify Connect", "Speaker / media player", 50),
    "_sonos._tcp": ("Sonos", "Sonos speaker", 78),
    "_amzn-wplay._tcp": ("Fire TV", "Fire TV", 78),
    "_amzn-alexa._tcp": ("Alexa", "Amazon Echo", 70),
    "_androidtvremote2._tcp": ("Android TV", "Android / Google TV", 72),
    "_hue._tcp": ("Hue", "Philips Hue bridge", 80),
    "_home-assistant._tcp": ("Home Assistant", "Home Assistant hub", 80),
    "_esphomelib._tcp": ("ESPHome", "ESPHome smart-home device", 78),
    "_nvstream._tcp": ("GameStream", "Gaming PC", 50),
    "_plexmediasvr._tcp": ("Plex", "Media server", 62),
    "_smb._tcp": ("SMB", "Computer / NAS", 34),
    "_afpovertcp._tcp": ("AFP", "Mac / NAS", 40),
    "_adisk._tcp": ("Time Machine", "NAS / Time Capsule", 50),
    "_ssh._tcp": ("SSH", "Linux / Unix computer", 30),
    "_sftp-ssh._tcp": ("SFTP", "Linux / Unix computer", 30),
    "_workstation._tcp": ("workstation", "Linux computer", 36),
    "_http._tcp": ("HTTP", "", 0),
    "_https._tcp": ("HTTPS", "", 0),
    "_device-info._tcp": ("", "", 0),
}

# Services worth a second question: their instance names are the friendly
# names people give devices, and their TXT records carry the model.
_FOLLOW_UP = (
    "_googlecast._tcp", "_companion-link._tcp", "_airplay._tcp", "_raop._tcp",
    "_ipp._tcp", "_printer._tcp", "_hap._tcp", "_sonos._tcp",
    "_amzn-wplay._tcp", "_androidtvremote2._tcp", "_hue._tcp",
)

# TXT keys that name the model, most specific first.
_MODEL_KEYS = ("md", "model", "rpmd", "am", "ty", "product", "usb_mdl", "mdl")


def service_type(name: str) -> str:
    """'_googlecast._tcp.local' -> '_googlecast._tcp'."""
    parts = name.rstrip(".").split(".")
    for i in range(len(parts) - 1):
        if parts[i].startswith("_") and parts[i + 1] in ("_tcp", "_udp"):
            return f"{parts[i]}.{parts[i + 1]}"
    return ""


def instance_label(name: str) -> str:
    """'Living Room TV._googlecast._tcp.local' -> 'Living Room TV'.

    AirPlay audio instances are 'A1B2C3D4E5F6@Kitchen'; the part after the @
    is the name.
    """
    stype = service_type(name)
    label = name.rstrip(".")
    if stype and f".{stype}" in label:
        label = label.split(f".{stype}")[0]
    if "@" in label:
        label = label.split("@", 1)[1]
    return label.replace("\\032", " ").strip()


CAST_GROUP_MODEL = "google cast group"


def read_mdns(messages: list[dict], ip: str = "") -> dict:
    """Fold a device's mDNS replies into {hostname, services, instances,
    txt, model, friendly, instance_names}.

    TXT records are kept per service *instance*, not per service type: a
    Nest speaker that leads a speaker group advertises the group as a second
    _googlecast instance (md=Google Cast Group, fn=<the group's name>), and
    that must not overwrite the speaker's own name and model.
    """
    try:
        reverse = reverse_name(ip) if ip else ""
    except ValueError:
        reverse = ""
    hostname = ""
    services: list[str] = []
    found: dict[str, list[str]] = {}          # service type -> instance names
    txt: dict[str, dict[str, str]] = {}       # owner name -> key/value pairs
    for message in messages:
        for name, rtype, rdata in message.get("answers", ()):
            lname = name.lower().rstrip(".")
            if rtype == "PTR" and isinstance(rdata, str):
                if reverse and lname == reverse.lower():
                    hostname = hostname or rdata.rstrip(".")
                elif lname == SERVICES_QUERY:
                    stype = service_type(rdata)
                    if stype and stype not in services:
                        services.append(stype)
                elif service_type(lname) and lname == f"{service_type(lname)}.local":
                    stype = service_type(lname)
                    if stype not in services:
                        services.append(stype)
                    instance = rdata.rstrip(".")
                    if instance not in found.setdefault(stype, []):
                        found[stype].append(instance)
            elif rtype == "TXT" and isinstance(rdata, list):
                pairs = txt_pairs(rdata)
                if pairs:
                    txt.setdefault(lname, {}).update(pairs)
            elif rtype == "SRV" and isinstance(rdata, tuple) and not hostname:
                target = str(rdata[3]).rstrip(".")
                if target.endswith(".local"):
                    hostname = target
            elif rtype in ("A", "AAAA") and rdata == ip and not hostname:
                if lname.endswith(".local"):
                    hostname = name.rstrip(".")

    groups = {owner for owner, pairs in txt.items()
              if pairs.get("md", "").lower() == CAST_GROUP_MODEL}
    own_txt = {owner: pairs for owner, pairs in txt.items() if owner not in groups}
    instances: dict[str, str] = {}
    instance_names: list[str] = []
    for stype, names in found.items():
        for full in names:
            if full.lower() in groups:
                continue
            instance_names.append(full)
            instances.setdefault(stype, instance_label(full))

    model = ""
    for key in _MODEL_KEYS:
        for pairs in own_txt.values():
            if pairs.get(key) and not model:
                model = pairs[key].strip("()")
    friendly = ""
    for owner, pairs in own_txt.items():
        if service_type(owner) == "_googlecast._tcp" and pairs.get("fn"):
            friendly = pairs["fn"]
            break
    for stype in _FOLLOW_UP:
        if not friendly and instances.get(stype):
            friendly = instances[stype]
    return {
        "hostname": hostname, "services": services, "instances": instances,
        "instance_names": instance_names, "txt": own_txt, "model": model,
        "friendly": friendly,
    }


# Instances whose names are worth a _device-info question: Apple publishes
# the model ("MacBookPro18,3") under the same name as these.
_DEVICE_INFO_FROM = ("_companion-link._tcp", "_airplay._tcp", "_raop._tcp")


async def mdns_probe(ip: str, timeout: float = MDNS_TIMEOUT) -> dict:
    """Ask the device itself, on its own port 5353, what it is called and
    what it offers. Up to three short rounds: names and service types; the
    instances and TXT records of the services worth a closer look; and, when
    there is still no model, the _device-info record for those instances.
    A device with nothing on 5353 answers 'port unreachable' and costs no
    wait at all."""
    try:
        reverse = reverse_name(ip)
    except ValueError:
        return read_mdns([], ip)
    q1, q2 = random.randrange(1, 0xFFFF), random.randrange(1, 0xFFFF)
    first = await udp_exchange(
        ip, 5353,
        [build_query(q1, [(reverse, "PTR")]),
         build_query(q2, [(SERVICES_QUERY, "PTR")])],
        timeout,
        until=lambda got: len(got) >= 2,
    )
    messages = _decode(first, ip)
    info = read_mdns(messages, ip)
    wanted = [s for s in _FOLLOW_UP + ("_smb._tcp",) if s in info["services"]][:6]
    questions = [(f"{s}.local", "PTR") for s in wanted]
    if info["hostname"]:
        host = info["hostname"].split(".")[0]
        questions.append((f"{host}._device-info._tcp.local", "TXT"))
    if questions:
        q3 = random.randrange(1, 0xFFFF)
        second = await udp_exchange(
            ip, 5353, [build_query(q3, questions)], MDNS_FOLLOWUP_TIMEOUT,
            until=lambda got: bool(got),
        )
        messages += _decode(second, ip)
        info = read_mdns(messages, ip)
    if not info["model"]:
        labels = []
        for full in info["instance_names"]:
            if service_type(full) in _DEVICE_INFO_FROM:
                label = instance_label(full)
                if label and label not in labels:
                    labels.append(label)
        if labels:
            q4 = random.randrange(1, 0xFFFF)
            third = await udp_exchange(
                ip, 5353,
                [build_query(q4, [((label, "_device-info", "_tcp", "local"), "TXT")
                                  for label in labels[:2]])],
                MDNS_FOLLOWUP_TIMEOUT, until=lambda got: bool(got),
            )
            messages += _decode(third, ip)
            info = read_mdns(messages, ip)
    return info


def _decode(packets, ip: str) -> list[dict]:
    out = []
    for data, addr in packets:
        if addr and addr[0] != ip:
            continue
        try:
            out.append(parse_message(data))
        except (ValueError, IndexError, struct.error):
            continue
    return out


# ================================================================= NetBIOS
def build_nbstat(tid: int) -> bytes:
    """A NetBIOS node-status request for the wildcard name '*'."""
    encoded = b""
    for byte in b"*" + b"\x00" * 15:
        encoded += bytes([0x41 + (byte >> 4), 0x41 + (byte & 0x0F)])
    return (
        struct.pack("!HHHHHH", tid & 0xFFFF, 0x0000, 1, 0, 0, 0)
        + b"\x20" + encoded + b"\x00"
        + struct.pack("!HH", 0x0021, 0x0001)
    )


def parse_nbstat(data: bytes) -> dict:
    """{computer, workgroup, names: [(name, suffix, is_group)], mac}."""
    if len(data) < 57:
        raise ValueError("short NBSTAT reply")
    offset = 12
    # The reply repeats the 34-byte encoded name (or a 2-byte pointer to it).
    if data[offset] & 0xC0 == 0xC0:
        offset += 2
    else:
        while offset < len(data) and data[offset] != 0:
            offset += 1 + data[offset]
        offset += 1
    rtype, _rclass, _ttl, _rdlength = struct.unpack("!HHIH", data[offset: offset + 10])
    if rtype != 0x0021:
        raise ValueError("not a node-status reply")
    offset += 10
    count = data[offset]
    offset += 1
    names = []
    for _ in range(count):
        if offset + 18 > len(data):
            break
        raw = data[offset: offset + 15].decode("ascii", "replace").rstrip(" \x00")
        suffix = data[offset + 15]
        flags = struct.unpack("!H", data[offset + 16: offset + 18])[0]
        names.append((raw, suffix, bool(flags & 0x8000)))
        offset += 18
    mac = ""
    if offset + 6 <= len(data):
        unit = data[offset: offset + 6]
        if any(unit):
            mac = ":".join(f"{b:02x}" for b in unit)
    computer = next((n for n, s, g in names if s == 0x00 and not g), "")
    computer = computer or next((n for n, s, g in names if s == 0x20 and not g), "")
    workgroup = next((n for n, s, g in names if s == 0x00 and g), "")
    return {"computer": computer, "workgroup": workgroup, "names": names, "mac": mac}


async def netbios_probe(ip: str, timeout: float = NETBIOS_TIMEOUT) -> dict:
    if ":" in ip:
        return {}
    tid = random.randrange(1, 0xFFFF)
    packets = await udp_exchange(ip, 137, [build_nbstat(tid)], timeout,
                                 until=lambda got: bool(got))
    for data, _addr in packets:
        try:
            return parse_nbstat(data)
        except (ValueError, IndexError, struct.error):
            continue
    return {}


# ============================================================ SSDP / UPnP
SSDP_GROUP = ("239.255.255.250", 1900)


def build_msearch(target: str = "ssdp:all", mx: int = 2,
                  host: str | None = None) -> bytes:
    """A multicast M-SEARCH, or a unicast one when `host` is given (UPnP
    1.1: sent straight to the device's port 1900, no MX)."""
    lines = [
        "M-SEARCH * HTTP/1.1",
        f"HOST: {host}:1900" if host else f"HOST: {SSDP_GROUP[0]}:{SSDP_GROUP[1]}",
        'MAN: "ssdp:discover"',
    ]
    if not host:
        lines.append(f"MX: {mx}")
    lines += [f"ST: {target}", "USER-AGENT: netzilla UPnP/1.1 device-identify"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def parse_ssdp(data: bytes) -> dict[str, str]:
    """Headers of one SSDP reply, lower-cased keys."""
    text = data.decode("utf-8", "replace")
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    if not lines or not lines[0].upper().startswith(("HTTP/", "NOTIFY")):
        return {}
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return headers


def _fold_ssdp(packets, found: dict[str, dict], only: str = "") -> dict[str, dict]:
    for data, addr in packets:
        if only and addr[0] != only:
            continue
        headers = parse_ssdp(data)
        if not headers:
            continue
        entry = found.setdefault(addr[0], {"server": "", "locations": [], "types": []})
        entry["server"] = entry["server"] or headers.get("server", "")
        location = headers.get("location", "")
        if location and location not in entry["locations"]:
            # The root device's description is the one that names the box.
            if headers.get("st", "").lower() == "upnp:rootdevice":
                entry["locations"].insert(0, location)
            else:
                entry["locations"].append(location)
        st = headers.get("st", "")
        if st and st not in entry["types"]:
            entry["types"].append(st)
    return found


async def ssdp_discover(window: float = SSDP_WINDOW) -> dict[str, dict]:
    """{ip: {server, locations[], types[]}} for every UPnP responder on the
    local segment — one multicast search, used by SWEEP only.

    With ufw on, the unicast replies to a multicast search are dropped (they
    match no outgoing connection), which is why ssdp_unicast() exists too.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except OSError:
        return {}
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.bind(("0.0.0.0", 0))
        sock.setblocking(False)
    except OSError:
        sock.close()
        return {}
    probe = build_msearch()
    packets = await udp_exchange(
        SSDP_GROUP[0], SSDP_GROUP[1], [probe, probe], window, sock=sock,
    )
    return _fold_ssdp(packets, {})


async def ssdp_unicast(ip: str, timeout: float = SSDP_UNICAST_TIMEOUT) -> dict:
    """Ask one device directly for its UPnP root device. The socket is
    connected to ip:1900, so the reply gets through a host firewall (it
    matches the request), a device without UPnP answers 'port unreachable'
    at once, and nobody else is asked."""
    if ":" in ip:
        return {}
    packets = await udp_exchange(
        ip, 1900, [build_msearch("upnp:rootdevice", host=ip)], timeout,
        until=lambda got: any(addr[0] == ip for _data, addr in got),
    )
    return _fold_ssdp(packets, {}, only=ip).get(ip, {})


def parse_upnp_xml(text: str) -> dict[str, str]:
    """friendlyName / manufacturer / modelName / … from a device description."""
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        return {}                              # never expand entities off the LAN
    from xml.etree import ElementTree

    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return {}

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    device = next((el for el in root.iter() if local(el.tag) == "device"), None)
    if device is None:
        return {}
    info = {}
    for child in device:
        key = local(child.tag)
        if key in ("friendlyName", "manufacturer", "modelName", "modelNumber",
                   "modelDescription", "deviceType") and child.text:
            info[key] = " ".join(child.text.split())
    return info


async def http_get(host: str, port: int, path: str = "/",
                   timeout: float = HTTP_TIMEOUT, limit: int = 65536):
    """(status, headers, body) from a plain-HTTP GET, or None. LAN use only."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout
        )
        request = (
            f"GET {path or '/'} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            "User-Agent: netzilla device-identify\r\nAccept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        blob = b""
        while len(blob) < limit:
            left = deadline - loop.time()
            if left <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(8192), left)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            blob += chunk
            if _complete(blob):
                break               # a server that keeps the socket open
    except (OSError, asyncio.TimeoutError, ValueError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 0.5)
            except Exception:
                pass
    return parse_http(blob[:limit])


def _complete(blob: bytes) -> bool:
    """True once a response with a Content-Length has all of its body."""
    head, sep, body = blob.partition(b"\r\n\r\n")
    if not sep:
        return False
    match = re.search(rb"(?im)^content-length:\s*(\d+)\s*$", head)
    return bool(match) and len(body) >= int(match.group(1))


def parse_http(blob: bytes):
    head, _, body = blob.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1", "replace").split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return None
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        status = 0
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    return status, headers, body


def _dechunk(body: bytes) -> bytes:
    out, pos = b"", 0
    while pos < len(body):
        end = body.find(b"\r\n", pos)
        if end < 0:
            break
        try:
            size = int(body[pos:end].split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += body[end + 2: end + 2 + size]
        pos = end + 2 + size + 2
    return out


def _safe_location(location: str, ip: str) -> tuple[str, int, str] | None:
    """(host, port, path) for a description URL — only plain http, and only
    on the device that advertised it."""
    match = re.match(r"^http://([^/:\]]+|\[[^\]]+\])(?::(\d+))?(/[^\s]*)?$",
                     location.strip(), re.I)
    if not match:
        return None
    host = match.group(1).strip("[]")
    if host != ip:
        return None
    port = int(match.group(2) or 80)
    if not 0 < port < 65536:
        return None
    return host, port, match.group(3) or "/"


async def upnp_describe(ip: str, locations: list[str]) -> dict[str, str]:
    for location in locations[:2]:
        target = _safe_location(location, ip)
        if target is None:
            continue
        response = await http_get(*target)
        if response and response[0] == 200:
            info = parse_upnp_xml(response[2].decode("utf-8", "replace"))
            if info:
                return info
    return {}


# ===================================================================== TTL
_TTL_RE = re.compile(r"\bttl[=:]\s*(\d+)", re.I)


def parse_ttl(ping_output: str) -> int | None:
    match = _TTL_RE.search(ping_output or "")
    return int(match.group(1)) if match else None


def ttl_hint(ttl: int | None) -> str:
    """What the starting TTL says about the OS. On a LAN there are no hops,
    so the reply arrives with the sender's initial value."""
    if not ttl:
        return ""
    if ttl <= 64:
        return "Unix-like (Linux/Apple/Android)"
    if ttl <= 128:
        return "Windows"
    return "network gear / embedded"


# ================================================================ guessing
# (pattern, label, score) — hostnames people and vendors actually use.
_HOST_RULES = (
    (r"iphone", "iPhone", 88),
    (r"ipad", "iPad", 88),
    (r"macbook|imac|mac-?mini|mac-?studio|mac-?pro", "Mac", 86),
    (r"apple-?tv", "Apple TV", 88),
    (r"homepod", "HomePod", 88),
    (r"apple-?watch", "Apple Watch", 86),
    (r"galaxy(?!-?book)|^sm-[a-z]\d", "Samsung phone / tablet", 70),
    (r"galaxy-?book", "PC / laptop", 72),
    (r"pixel", "Pixel phone", 78),
    (r"android|oneplus|moto(rola)?[-_ ]|redmi|xiaomi|^oppo|^vivo(?!book)", "Android phone", 78),
    (r"^desktop-|^laptop-|^win-|windows", "Windows PC", 84),
    (r"chromecast", "Chromecast", 88),
    (r"google-?(home|nest)|nest-?(mini|hub|audio|wifi)", "Google Nest device", 86),
    (r"\becho\b|alexa", "Amazon Echo", 80),
    (r"fire-?tv|firestick|^aft[a-z]", "Fire TV", 86),
    (r"kindle", "Kindle", 86),
    (r"roku", "Roku", 88),
    (r"\bps[345]\b|playstation", "PlayStation", 88),
    (r"xbox", "Xbox", 88),
    (r"nintendo", "Nintendo Switch", 80),
    (r"(^|[-_.])(sw|switch)([-_.]?\d|$)|(core|access|poe)-?switch", "Network switch", 70),
    (r"printer|^hp[0-9a-f]{6}|laserjet|officejet|deskjet|epson|^brn|^brw|\bcanon\b|"
     r"^npi[0-9a-f]", "Printer", 84),
    (r"raspberrypi|^pi-|^rpi", "Raspberry Pi", 84),
    (r"^ring-|ring-?(doorbell|cam)", "Ring camera / doorbell", 84),
    (r"wyze", "Wyze camera", 84),
    (r"camera|cam-|ipcam|reolink|hikvision|arlo", "IP camera", 76),
    (r"tasmota|shelly|esp[-_]|espressif|sonoff|wled", "Smart-home device (ESP)", 82),
    (r"^(hs\d{3}|kp\d{3}|ep\d{2}|kl\d{3})\b|^tapo|^kasa", "Smart plug / bulb", 82),
    (r"hue-?bridge|philips-hue", "Philips Hue bridge", 86),
    (r"sonos", "Sonos speaker", 86),
    (r"synology|diskstation|qnap|truenas|unraid|-nas\b|^nas", "NAS / file server", 82),
    (r"\b(ubuntu|linux|mint|fedora|debian|arch|manjaro|pop-os|kali)\b", "Linux computer", 72),
    (r"(^|[-_ ])tv\b|smart-?tv|lgwebos|bravia|vizio|tizen|\btcl\b|hisense", "Smart TV", 76),
    (r"\b(router|gateway|unifi|eero|orbi|deco|velop|archer|nighthawk|mesh)\b", "Router / Wi-Fi gear", 70),
    (r"thermostat|ecobee|nest-?(learning|thermostat)", "Thermostat", 84),
    (r"myq|garage", "Garage door opener", 84),
    (r"homeassistant|home-assistant", "Home Assistant hub", 86),
)

# (substring of the lower-cased vendor, label, score)
_VENDOR_RULES = (
    ("sony interactive", "PlayStation", 80),
    ("nintendo", "Nintendo console", 78),
    ("roku", "Roku", 80),
    ("sonos", "Sonos speaker", 80),
    ("ring llc", "Ring camera / doorbell", 78),
    ("wyze", "Wyze camera", 76),
    ("signify", "Philips Hue", 74),
    ("philips lighting", "Philips Hue", 74),
    ("ecobee", "Thermostat", 76),
    ("nest labs", "Google Nest device", 70),
    ("chamberlain", "Garage door opener", 76),
    ("raspberry pi", "Raspberry Pi", 80),
    ("espressif", "Smart-home device (ESP)", 64),
    ("tuya", "Smart-home device (Tuya)", 66),
    ("synology", "NAS / file server", 76),
    ("qnap", "NAS / file server", 76),
    ("western digital", "NAS / file server", 56),
    ("seiko epson", "Printer", 72),
    ("brother industries", "Printer", 72),
    ("canon", "Printer / camera", 60),
    ("hewlett packard enterprise", "Network gear", 50),
    ("hp inc", "HP printer / PC", 50),
    ("hewlett packard", "HP printer / PC", 50),
    ("vmware", "Virtual machine", 78),
    ("xensource", "Virtual machine", 78),
    ("parallels", "Virtual machine", 78),
    ("blink by amazon", "Blink camera", 78),
    ("amazon technologies", "Amazon device", 48),
    ("apple", "Apple device", 48),
    ("google", "Google / Nest device", 50),
    ("microsoft", "Microsoft (Xbox / Surface)", 48),
    ("samsung", "Samsung phone / TV", 42),
    ("lg electronics", "LG TV / appliance", 50),
    ("sony corporation", "Sony TV / device", 50),
    ("vizio", "Smart TV", 70),
    ("hisense", "Smart TV", 66),
    ("tcl", "Smart TV", 56),
    ("arlo", "IP camera", 74),
    ("hikvision", "IP camera", 74),
    ("dahua", "IP camera", 74),
    ("reolink", "IP camera", 74),
    ("bose", "Speaker", 66),
    ("irobot", "Robot vacuum", 76),
    ("ecovacs", "Robot vacuum", 76),
    ("roborock", "Robot vacuum", 76),
    ("peloton", "Peloton", 80),
    ("tesla", "Tesla vehicle", 70),
    ("garmin", "Garmin device", 60),
    ("fitbit", "Fitbit", 70),
    ("withings", "Withings health device", 70),
    # network gear
    ("vantiva", "Router / network gear", 40),
    ("technicolor", "Router / network gear", 40),
    ("arris", "Router / network gear", 40),
    ("commscope", "Router / network gear", 40),
    ("sagemcom", "Router / network gear", 40),
    ("ubiquiti", "Router / network gear", 44),
    ("netgear", "Router / network gear", 40),
    ("tp-link", "TP-Link device", 36),
    ("eero", "Mesh Wi-Fi node", 60),
    ("cisco", "Network gear", 44),
    ("juniper", "Network gear", 50),
    ("aruba", "Network gear", 50),
    ("routerboard", "Network gear", 56),
    ("mikrotik", "Network gear", 56),
    ("zyxel", "Router / network gear", 40),
    ("d-link", "Router / network gear", 36),
    ("actiontec", "Router / network gear", 44),
    ("calix", "Router / network gear", 44),
    ("linksys", "Router / network gear", 44),
    ("sercomm", "Router / network gear", 44),
    ("arcadyan", "Router / network gear", 44),
    ("askey", "Router / network gear", 44),
    ("hitron", "Router / network gear", 44),
    ("compal broadband", "Router / network gear", 44),
    ("nokia solutions", "Router / network gear", 44),
    ("nokia shanghai bell", "Router / network gear", 44),
    ("alcatel-lucent", "Router / network gear", 44),
    ("humax", "Router / set-top box", 44),
    ("belkin", "Smart plug / router (Belkin)", 36),
    ("asustek", "ASUS router / PC", 34),
    # the Wi-Fi or Ethernet chip of a PC or laptop
    ("intel corporate", "PC / laptop", 38),
    ("liteon", "PC / laptop", 36),
    ("lite-on", "PC / laptop", 36),
    ("azurewave", "PC / laptop", 34),
    ("hon hai", "PC / laptop", 30),
    ("rivet networks", "PC / laptop", 38),
    ("realtek", "PC / laptop", 30),
    ("dell", "PC / laptop", 40),
    ("lenovo", "PC / laptop", 40),
    ("micro-star", "PC / laptop", 40),
    ("gigabyte", "PC / laptop", 36),
    ("asrock", "PC / laptop", 36),
    ("chicony", "PC / laptop", 34),
    ("murata", "Phone / IoT module", 30),
    ("universal global scientific", "Phone / IoT module", 30),
)

# Model strings that settle the question outright.
_MODEL_RULES = (
    (r"^iphone", "iPhone", 94),
    (r"^ipad", "iPad", 94),
    (r"^(macbook|imac|macmini|macpro|mac\d|mac1\d)", "Mac", 94),
    (r"^appletv", "Apple TV", 94),
    (r"^audioaccessory", "HomePod", 94),
    (r"^watch", "Apple Watch", 90),
    (r"chromecast|google tv", "Chromecast", 92),
    (r"nest (mini|audio|hub)|google home", "Google Nest speaker", 92),
    (r"laserjet|officejet|deskjet|envy|epson|brother|pixma|imageclass|"
     r"workforce|ecotank|mfc-|hl-|canon|maxify|selphy", "Printer", 92),
    (r"roku", "Roku", 92),
    (r"sonos", "Sonos speaker", 92),
    (r"fire ?tv|^aft[a-z]", "Fire TV", 90),
    (r"echo", "Amazon Echo", 88),
    (r"bravia|webos|tizen|smart ?tv|vizio", "Smart TV", 86),
    (r"xbox", "Xbox", 92),
    (r"playstation|ps5|ps4", "PlayStation", 92),
    (r"hue bridge|bsb00", "Philips Hue bridge", 92),
    (r"diskstation|ds\d{3,4}|synology|qnap|ts-\d", "NAS / file server", 90),
)

# UPnP device types and manufacturers.
_UPNP_RULES = (
    (r"internetgatewaydevice|wanconnectiondevice", "Router / gateway", 72),
    # Generic UPnP roles are weak evidence: a Windows PC with DLNA "Play To"
    # is a MediaRenderer too. Brand rules below outrank them.
    (r"mediarenderer", "Smart TV / media player", 26),
    (r"mediaserver", "Media server", 30),
    (r"printer", "Printer", 80),
    (r"roku", "Roku", 88),
    (r"sonos", "Sonos speaker", 88),
    (r"samsung.*tv|tizen", "Smart TV", 84),
    (r"lg.*(tv|webos)|webos", "Smart TV", 84),
    (r"vizio|bravia|hisense|tcl", "Smart TV", 84),
    (r"xbox", "Xbox", 88),
    (r"playstation", "PlayStation", 88),
    (r"philips hue", "Philips Hue bridge", 88),
    (r"synology|qnap|wd my cloud", "NAS / file server", 86),
    (r"denon|marantz|yamaha|onkyo|heos", "AV receiver / speaker", 82),
    (r"amazon|fire ?tv", "Fire TV", 70),
)

# Open TCP ports (IDENTIFY only) that point at a kind of device.
PROBE_PORTS: dict[int, tuple[str, str, str, int]] = {
    # port: (service, what it usually means, device it suggests, score)
    22: ("SSH", "Linux/Unix host, NAS or managed network gear", "", 0),
    23: ("Telnet", "older network gear or IoT — worth turning off", "Network gear", 30),
    53: ("DNS", "router or a DNS server (Pi-hole, AdGuard)", "", 0),
    80: ("HTTP", "a web admin page — router, printer, camera, NAS", "", 0),
    139: ("NetBIOS", "Windows file sharing or Samba", "", 0),
    443: ("HTTPS", "a web admin page", "", 0),
    445: ("SMB", "Windows PC, Samba server or NAS", "Computer / NAS", 34),
    515: ("LPD", "a printer's print queue", "Printer", 70),
    548: ("AFP", "Mac file sharing or a Time Machine NAS", "Mac / NAS", 50),
    554: ("RTSP", "a video stream — IP camera or DVR", "IP camera", 66),
    631: ("IPP", "a printer (or CUPS on a computer)", "Printer", 56),
    1883: ("MQTT", "a smart-home hub or broker", "Smart-home hub", 50),
    3389: ("RDP", "Windows with Remote Desktop on", "Windows PC", 76),
    5000: ("UPnP / AirPlay / DSM", "AirPlay on a Mac, or a Synology NAS", "", 0),
    5900: ("VNC", "screen sharing — a Mac or Linux desktop", "Computer", 36),
    7000: ("AirPlay", "Apple TV, AirPlay speaker or a Mac", "AirPlay receiver", 54),
    8008: ("Google Cast", "Chromecast, Google TV or a Nest speaker", "Chromecast / Google TV", 68),
    8009: ("Google Cast", "Chromecast, Google TV or a Nest speaker", "Chromecast / Google TV", 68),
    8060: ("Roku ECP", "a Roku player or Roku TV", "Roku", 90),
    8080: ("HTTP-alt", "a web UI — camera, NAS, app server", "", 0),
    8123: ("Home Assistant", "Home Assistant", "Home Assistant hub", 88),
    8443: ("HTTPS-alt", "a web UI — UniFi controller, NAS", "", 0),
    9100: ("JetDirect", "a network printer", "Printer", 84),
    32400: ("Plex", "Plex Media Server", "Media server", 76),
    49152: ("UPnP", "a UPnP device — router, TV, media box", "", 0),
    62078: ("iPhone sync", "an iPhone or iPad (lockdownd)", "iPhone / iPad", 90),
}


def _all_names(dev: dict) -> list[str]:
    """Every name the device goes by, once each: 'DESKTOP-K3V9TQ1' from
    NetBIOS and 'DESKTOP-K3V9TQ1.home.example.net' from DNS are one name."""
    names = [dev.get("hostname", ""), dev.get("friendly", ""),
             (dev.get("netbios") or {}).get("computer", "")]
    names += [n for n in dev.get("names", [])]
    unique: list[str] = []
    for name in names:
        if not name:
            continue
        name = name.lower() if " " in name else short_host(name).lower()
        if name and name not in unique:
            unique.append(name)
    return unique


def classify(dev: dict) -> tuple[str, list[str]]:
    """Best guess at what the device is, and the evidence for it."""
    candidates: list[tuple[int, str, str]] = []

    role = dev.get("role")
    if role == "self":
        candidates.append((100, "This computer", "one of this machine's addresses"))
    elif role == "gateway":
        candidates.append((96, "Router / gateway", "the default gateway"))

    virtual = virtual_nic(dev.get("mac"))
    if virtual:
        candidates.append((90, "Virtual machine", virtual))

    # Every rule that matches is a candidate; the strongest wins below. (First
    # match would let a generic rule listed early hide a specific one.)
    model = (dev.get("model") or "").lower()
    upnp = dev.get("upnp") or {}
    for text, source in ((model, "model"), ((upnp.get("modelName") or "").lower(), "UPnP model")):
        for pattern, label, score in _MODEL_RULES:
            if text and re.search(pattern, text):
                candidates.append((score, label, f"{source} '{text}'"))

    for name in _all_names(dev):
        for pattern, label, score in _HOST_RULES:
            if re.search(pattern, name):
                candidates.append((score, label, f"name '{name}'"))

    for service in dev.get("services", []):
        _short, label, score = SERVICE_INFO.get(service, ("", "", 0))
        if label and score:
            candidates.append((score, label, f"advertises {service}"))

    upnp_text = " ".join(
        (upnp.get(k) or "") for k in ("deviceType", "manufacturer", "modelName",
                                      "modelDescription", "friendlyName")
    ).lower() + " " + (dev.get("ssdp_server") or "").lower()
    if upnp_text.strip():
        for pattern, label, score in _UPNP_RULES:
            if re.search(pattern, upnp_text):
                candidates.append((score, label, "UPnP description"))

    vendor = (dev.get("vendor") or "").lower()
    if vendor:
        for needle, label, score in _VENDOR_RULES:
            if _has_word(vendor, needle):
                candidates.append((score, label, f"MAC vendor {short_vendor(dev['vendor'])}"))
                break

    for port in dev.get("open_ports", []):
        _svc, _why, label, score = PROBE_PORTS.get(port, ("", "", "", 0))
        if label and score:
            candidates.append((score, label, f"tcp/{port} open"))

    if (dev.get("netbios") or {}).get("computer"):
        candidates.append((32, "Windows PC / Samba host", "answers NetBIOS"))
    hint = ttl_hint(dev.get("ttl"))
    if hint == "Windows":
        candidates.append((28, "Windows PC", f"TTL {dev.get('ttl')}"))
    elif hint == "network gear / embedded":
        candidates.append((22, "Network gear / embedded", f"TTL {dev.get('ttl')}"))
    if dev.get("mac_kind") == "random":
        candidates.append((20, "Phone / tablet / laptop", "private (randomised) MAC"))

    if not candidates:
        return "Unknown", []
    candidates.sort(key=lambda c: c[0], reverse=True)
    best = candidates[0]
    label = _refine(best[1], candidates)
    evidence = []
    for _score, _label, reason in candidates:
        if reason not in evidence:
            evidence.append(reason)
    return label, evidence[:5]


_GENERIC = {
    "Apple device": ("iPhone", "iPad", "Mac", "Apple TV", "HomePod",
                     "Apple Watch", "iPhone / iPad"),
    "Amazon device": ("Amazon Echo", "Fire TV", "Kindle",
                      "Ring camera / doorbell", "Blink camera"),
    "Google / Nest device": ("Chromecast", "Chromecast / Google TV",
                             "Google Nest device", "Google Nest speaker",
                             "Pixel phone"),
    "AirPlay receiver": ("Apple TV", "HomePod", "Mac", "Smart TV"),
    "AirPlay speaker": ("HomePod", "Sonos speaker"),
    "PC / laptop": ("Windows PC", "Linux computer", "Mac", "Gaming PC"),
    "Phone / tablet / laptop": ("Windows PC",),
    "Windows PC / Samba host": ("Windows PC",),
    "Computer / NAS": ("Windows PC", "Linux computer", "Mac", "NAS / file server"),
    "Smart TV / media player": ("Smart TV", "Roku", "Fire TV", "Chromecast",
                                "Chromecast / Google TV", "Apple TV"),
    "TP-Link device": ("Smart plug / bulb", "Router / Wi-Fi gear", "IP camera"),
}


def _refine(label: str, candidates) -> str:
    """Sharpen a generic winner with a more specific runner-up that agrees
    with it: an 'Apple device' that also advertises iOS sync is an iPhone.
    Only ever sharpens — one generic label is never swapped for another
    (a Mac advertising AirPlay stays an Apple device, not an 'AirPlay
    receiver')."""
    options = _GENERIC.get(label)
    if not options:
        return label
    for _score, other, _reason in candidates:
        if other in options and other not in _GENERIC:
            return other
    return label


# ============================================================ local context
# Interfaces whose subnets are not a LAN you can see: VPN tunnels
# (GlobalProtect's gpd0, OpenVPN's tun0, WireGuard, Tailscale, ZeroTier),
# container and VM bridges. Nothing is probed "locally" through them.
NOT_A_LAN = ("tun", "tap", "wg", "gpd", "tailscale", "zt", "docker", "br-",
             "veth", "virbr", "vmnet", "vboxnet", "cni", "flannel", "ppp",
             "ipsec", "utun")
# The same, told by kind — Windows names adapters "Ethernet 3" or "Wi-Fi",
# whatever they are, so there the kind is all there is to go on.
NOT_A_LAN_KINDS = ("tunnel/VPN", "WireGuard", "PPP", "virtual bridge", "docker",
                   "container veth")


async def local_context() -> dict:
    """This machine's own addresses and MACs, its networks and gateways."""
    from . import netif

    found, _source = await netif.interfaces()
    own: dict[str, str] = {}
    networks: list = []
    default_net = None
    fallback_net = None
    for iface in found:
        if iface.get("kind") == "loopback":
            continue
        lan_like = not iface.get("name", "").startswith(NOT_A_LAN) \
            and iface.get("kind") not in NOT_A_LAN_KINDS
        for addr in iface.get("addresses") or []:
            try:
                interface = ipaddress.ip_interface(addr)
            except ValueError:
                continue
            own[str(interface.ip)] = (iface.get("mac") or "").lower()
            if interface.ip.is_link_local or not lan_like:
                continue
            if interface.network.num_addresses <= 2:    # point-to-point
                continue
            networks.append(interface.network)
            if interface.version == 4 and interface.ip.is_private:
                if iface.get("default_route") and default_net is None:
                    default_net = interface
                if fallback_net is None and iface.get("kind") in ("wireless", "ethernet"):
                    fallback_net = interface
    gateways = await netif.default_gateways()
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = ""
    return {
        "hostname": hostname,
        "self": own,
        "networks": networks,
        "gateways": set(gateways),
        # A full-tunnel VPN owns the default route; the LAN is still there.
        "default_interface": default_net or fallback_net,
    }


def suggest_sweep(context: dict) -> tuple[str, str]:
    """(cidr, note) — this machine's own LAN, sized for a sweep."""
    interface = context.get("default_interface")
    if interface is None:
        return "", ""
    network = interface.network
    if network.prefixlen < 22:
        narrowed = ipaddress.ip_interface(f"{interface.ip}/24").network
        return str(narrowed), (
            f"This machine is on {network}, too big to sweep in one go; "
            f"swept the /24 around it ({narrowed}) instead."
        )
    return str(network), ""


def is_local_network(network, context: dict) -> bool:
    return any(network.overlaps(net) for net in context.get("networks", ())
               if net.version == network.version)


def is_local(ip: str, context: dict) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in net for net in context.get("networks", ()))


# ============================================================== the pipeline
async def identify(
    hosts: list[dict], *, context: dict | None = None, probe: bool = True,
    use_ssdp: bool = False, local_only: bool = False, progress=None,
    concurrency: int = 32,
) -> list[dict]:
    """Enrich [{ip, mac?, rtt_ms?, ttl?}, …], keeping their order, into
    dicts with vendor, mac_kind, hostname, friendly, model, services,
    netbios, upnp, role, device, evidence, sources and probed.

    use_ssdp adds one multicast UPnP search of the local segment (SWEEP).
    local_only restricts the device probes to addresses on this machine's own
    LAN segments — for addresses that turned up some other way (a FLOW
    connection, a syslog sender) — so nothing is sent across a VPN; those
    get a reverse-DNS lookup only.
    """
    await asyncio.to_thread(oui.entry_count)          # first load off the loop
    context = context if context is not None else await local_context()
    own = context.get("self", {})
    gateways = context.get("gateways", set())
    resolvers = nameservers()

    semaphore = asyncio.Semaphore(concurrency)
    done = 0
    ssdp_task = None
    if probe and use_ssdp and any(":" not in h["ip"] for h in hosts):
        ssdp_task = asyncio.ensure_future(ssdp_discover())

    async def one(index: int, host: dict) -> dict:
        nonlocal done
        dev = dict(host)
        ip = dev["ip"]
        if not dev.get("mac") and own.get(ip):
            dev["mac"] = own[ip]
        dev["role"] = "self" if ip in own else "gateway" if ip in gateways else ""
        if dev["role"] == "self" and context.get("hostname"):
            dev["hostname"] = context["hostname"]
        dev["vendor"], dev["mac_kind"] = vendor_for(dev.get("mac"))
        dev.setdefault("names", [])
        dev["sources"] = []
        allowed = probe and index < MAX_PROBED
        full = allowed and (not local_only or is_local(ip, context))
        dev["probed"] = allowed
        if allowed:
            servers = dns_servers_for(ip, context, resolvers)
            async with semaphore:
                if full:
                    ptr, mdns, nb, upnp = await asyncio.gather(
                        reverse_dns(ip, servers), mdns_probe(ip),
                        netbios_probe(ip), ssdp_unicast(ip),
                        return_exceptions=True,
                    )
                else:
                    ptr, mdns, nb, upnp = await reverse_dns(ip, servers), None, None, None
            _merge(dev, ptr, mdns, nb)
            if isinstance(upnp, dict) and upnp:
                dev["_ssdp"] = upnp
        done += 1
        if progress and done % 8 == 0:
            progress(f"Identified {done}/{len(hosts)} devices…")
        return dev

    try:
        devices = await asyncio.gather(*(one(i, h) for i, h in enumerate(hosts)))
        responders: dict[str, dict] = {}
        if ssdp_task is not None:
            try:
                responders = await ssdp_task
            except Exception:
                responders = {}
    finally:
        # A sweep cancelled mid-way (another button pressed) must not leave
        # the multicast search running behind it.
        if ssdp_task is not None and not ssdp_task.done():
            ssdp_task.cancel()

    for dev in devices:
        found = dev.pop("_ssdp", None)
        if found:
            entry = responders.setdefault(dev["ip"], {"server": "", "locations": [], "types": []})
            entry["server"] = entry["server"] or found.get("server", "")
            for location in found.get("locations", []):
                if location not in entry["locations"]:
                    entry["locations"].insert(0, location)

    wanted = [d for d in devices if d["ip"] in responders and d.get("probed")]
    if progress and wanted:
        progress(f"Reading {len(wanted)} UPnP device descriptions…")

    async def describe(dev: dict) -> None:
        entry = responders[dev["ip"]]
        dev["ssdp_server"] = entry.get("server", "")
        async with semaphore:
            info = await upnp_describe(dev["ip"], entry.get("locations", []))
        if info:
            dev["upnp"] = info
            if "UPnP" not in dev["sources"]:
                dev["sources"].append("UPnP")
            if not dev.get("friendly") and info.get("friendlyName"):
                dev["friendly"] = info["friendlyName"]

    await asyncio.gather(*(describe(d) for d in wanted), return_exceptions=True)

    for dev in devices:
        dev["device"], dev["evidence"] = classify(dev)
    return list(devices)


def _merge(dev: dict, ptr, mdns, nb) -> None:
    ip = dev["ip"]
    if isinstance(ptr, str) and useful_hostname(ptr, ip):
        dev["names"].append(ptr.rstrip("."))
        dev["hostname"] = ptr.rstrip(".")
        dev["sources"].append("DNS")
    if isinstance(mdns, dict):
        if mdns.get("hostname"):
            dev["names"].append(mdns["hostname"])
            dev.setdefault("hostname", mdns["hostname"])
        if mdns.get("services") or mdns.get("hostname"):
            dev["sources"].append("mDNS")
        dev["services"] = mdns.get("services", [])
        dev["model"] = mdns.get("model", "")
        if mdns.get("friendly"):
            dev["friendly"] = mdns["friendly"]
        dev["mdns"] = mdns
    if isinstance(nb, dict) and nb.get("computer"):
        dev["netbios"] = nb
        dev["names"].append(nb["computer"])
        dev.setdefault("hostname", nb["computer"])
        dev["sources"].append("NetBIOS")
        if not dev.get("mac") and nb.get("mac"):
            dev["mac"] = nb["mac"]
            dev["vendor"], dev["mac_kind"] = vendor_for(nb["mac"])


async def identify_ips(ips: list[str], *, context: dict | None = None,
                       probe: bool = True, progress=None) -> dict[str, dict]:
    """{ip: device} for addresses found some other way (FLOW, CAPTURE,
    SYSLOG, DHCP): the MAC comes from the neighbour table."""
    from .lan import arp_table

    if not ips:
        return {}
    context = context if context is not None else await local_context()
    arp = await arp_table()
    hosts = [{"ip": ip, "mac": arp.get(ip)} for ip in dict.fromkeys(ips)]
    devices = await identify(hosts, context=context, probe=probe,
                             local_only=True, progress=progress)
    return {d["ip"]: d for d in devices}


# ================================================================ rendering
SWEEP_COLUMNS = ["IP", "RTT", "MAC", "Vendor", "Hostname", "Device", "Details"]
ARP_COLUMNS = ["IP", "MAC", "Vendor", "Hostname", "Device", "Details"]


def display_name(dev: dict) -> str:
    return short_host(dev.get("hostname", "")) or dev.get("friendly", "") or ""


def vendor_cell(dev: dict) -> str:
    if dev.get("vendor"):
        return short_vendor(dev["vendor"])
    kind = dev.get("mac_kind")
    if kind == "random":
        return "private MAC"
    if kind == "multicast":
        return "multicast"
    return ""


def service_labels(services: list[str]) -> list[str]:
    labels = []
    for service in services:
        label = SERVICE_INFO.get(service, (None,))[0]
        if label is None:
            label = service.split(".")[0].lstrip("_")
        if label and label not in labels:
            labels.append(label)
    return labels


def details(dev: dict, width: int = 60) -> str:
    parts = []
    name = display_name(dev)
    friendly = dev.get("friendly", "")
    if friendly and friendly.lower() != name.lower():
        parts.append(f"“{friendly}”")
    model = dev.get("model") or upnp_model(dev.get("upnp") or {})
    if model:
        parts.append(model)
    services = service_labels(dev.get("services", []))
    if services:
        parts.append(", ".join(services[:3]) + ("…" if len(services) > 3 else ""))
    nb = dev.get("netbios") or {}
    if nb.get("workgroup"):
        parts.append(f"NetBIOS {nb['workgroup']}")
    hint = ttl_hint(dev.get("ttl"))
    if hint and not model:
        parts.append(f"TTL {dev['ttl']} · {hint}")
    text = " · ".join(parts)
    return text if len(text) <= width else text[: width - 1] + "…"


def upnp_model(upnp: dict) -> str:
    """'Roku' + 'Roku Ultra' reads as 'Roku Ultra', not 'Roku Roku Ultra'."""
    maker = (upnp.get("manufacturer") or "").strip()
    model = (upnp.get("modelName") or "").strip()
    if maker and model and model.lower().startswith(maker.split()[0].lower()):
        return model
    return " ".join(p for p in (maker, model) if p)


def rtt_cell(dev: dict) -> str:
    rtt = dev.get("rtt_ms")
    if rtt is None:
        return "—"
    if rtt < 0.1:
        return "local" if dev.get("role") == "self" else "<0.1 ms"
    return f"{rtt:.1f} ms"


def mac_cell(dev: dict) -> str:
    mac = dev.get("mac") or ""
    return mac if mac else "—"


def sweep_rows(devices: list[dict]) -> list[list[object]]:
    rows = []
    for dev in devices:
        rows.append([
            dev["ip"],
            rtt_cell(dev),
            mac_cell(dev),
            vendor_cell(dev),
            display_name(dev),
            dev.get("device", ""),
            details(dev),
        ])
    return rows


def arp_rows(devices: list[dict]) -> list[list[object]]:
    return [row[:1] + row[2:] for row in sweep_rows(devices)]


def summary(devices: list[dict]) -> list[tuple[str, object]]:
    named = sum(1 for d in devices if display_name(d))
    private = sum(1 for d in devices if d.get("mac_kind") == "random")
    by_type: dict[str, int] = {}
    for dev in devices:
        by_type[dev.get("device") or "Unknown"] = by_type.get(dev.get("device") or "Unknown", 0) + 1
    vendors: dict[str, int] = {}
    for dev in devices:
        if dev.get("vendor"):
            short = short_vendor(dev["vendor"])
            vendors[short] = vendors.get(short, 0) + 1
    sources: dict[str, int] = {}
    for dev in devices:
        for source in dev.get("sources", []):
            sources[source] = sources.get(source, 0) + 1
    top_types = sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))
    top_vendors = sorted(vendors.items(), key=lambda kv: (-kv[1], kv[0]))
    skipped = sum(1 for d in devices if d.get("probed") is False)
    rows: list[tuple[str, object]] = [
        ("Devices", len(devices)),
        ("Identified by name", f"{named} of {len(devices)}"),
        ("Private (random) MACs", private),
        ("Device mix", ", ".join(f"{k} ×{v}" if v > 1 else k for k, v in top_types[:8])),
        ("Top vendors", ", ".join(f"{k} ×{v}" if v > 1 else k for k, v in top_vendors[:6]) or "—"),
        ("Names came from", ", ".join(f"{k} ({v})" for k, v in sorted(sources.items())) or "no device answered a name query"),
    ]
    if skipped:
        rows.append((
            "Not asked for names",
            f"{skipped} — past the first {MAX_PROBED} devices, only the MAC "
            "vendor is shown. Sweep a smaller range to name them.",
        ))
    return rows


SOURCES_NOTE = (
    "Vendor: offline IEEE registry. Hostname: reverse DNS (your router usually "
    "knows each DHCP client's name), mDNS, NetBIOS or UPnP — whichever the "
    "device answers. Device is netzilla's best guess from all of it; press "
    "IDENTIFY with one IP in the box to see the evidence. A 'private MAC' is a "
    "randomised Wi-Fi address (phones, tablets, laptops), so it has no vendor."
)


# ========================================================= single-host deep
async def port_scan(ip: str, ports=None, timeout: float = PORT_TIMEOUT,
                    concurrency: int = 32) -> list[int]:
    """TCP-connect check of the handful of ports that identify devices."""
    ports = list(ports or PROBE_PORTS)
    semaphore = asyncio.Semaphore(concurrency)

    async def check(port: int) -> int | None:
        async with semaphore:
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout
                )
            except (OSError, asyncio.TimeoutError):
                return None
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 0.5)
            except Exception:
                pass
            return port

    results = await asyncio.gather(*(check(p) for p in ports))
    return sorted(p for p in results if p)


async def banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """The first line a service volunteers (SSH says its version)."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        line = await asyncio.wait_for(reader.readline(), timeout)
        return line.decode("utf-8", "replace").strip()[:120]
    except (OSError, asyncio.TimeoutError, ValueError):
        return ""
    finally:
        if writer is not None:
            writer.close()


_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


async def web_identity(ip: str, port: int) -> dict[str, str]:
    response = await http_get(ip, port, "/", limit=32768)
    if not response:
        return {}
    status, headers, body = response
    title = ""
    match = _TITLE_RE.search(body or b"")
    if match:
        title = " ".join(match.group(1).decode("utf-8", "replace").split())[:80]
    return {
        "status": str(status), "server": headers.get("server", "")[:80],
        "title": title,
    }


async def profile(ip: str, *, context: dict | None = None, progress=None) -> dict:
    """Everything netzilla can learn about one device."""
    from .lan import _ping_one, arp_table

    context = context if context is not None else await local_context()
    if progress:
        progress(f"Pinging {ip}…")
    try:
        _ip, rtt, ttl = await _ping_one(ip, 1.0)
    except FileNotFoundError:
        rtt, ttl = None, None
    arp = await arp_table()
    if progress:
        progress(f"Asking {ip} for its names, services and model…")
    devices = await identify(
        [{"ip": ip, "mac": arp.get(ip), "rtt_ms": rtt, "ttl": ttl}],
        context=context,
    )
    dev = devices[0]
    if progress:
        progress(f"Checking {len(PROBE_PORTS)} identifying ports on {ip}…")
    dev["open_ports"] = await port_scan(ip)
    dev["banners"] = {}
    if 22 in dev["open_ports"]:
        dev["banners"][22] = await banner(ip, 22)
    for port in (80, 8080):
        if port in dev["open_ports"]:
            web = await web_identity(ip, port)
            if web:
                dev["banners"][port] = web
    dev["reachable"] = rtt is not None or bool(dev["open_ports"]) or bool(dev.get("mac"))
    dev["device"], dev["evidence"] = classify(dev)
    return dev


def upnp_kind(upnp: dict) -> str:
    """'urn:schemas-upnp-org:device:MediaRenderer:1' -> 'MediaRenderer'."""
    parts = (upnp.get("deviceType") or "").split(":")
    return parts[3] if len(parts) >= 5 else ""


def profile_rows(dev: dict) -> list[tuple[str, object]]:
    nb = dev.get("netbios") or {}
    upnp = dev.get("upnp") or {}
    mdns = dev.get("mdns") or {}
    rtt = dev.get("rtt_ms")
    rows: list[tuple[str, object]] = [
        ("Looks like", dev.get("device") or "Unknown"),
        ("Role", {"self": "this computer", "gateway": "default gateway"}.get(dev.get("role"), "—")),
        ("Ping", f"{rtt:.1f} ms, TTL {dev.get('ttl')}" if rtt is not None else "no reply"),
        ("OS hint (TTL)", ttl_hint(dev.get("ttl")) or "—"),
        ("MAC", dev.get("mac") or "not in the neighbour table (off-link or silent)"),
        ("Vendor", dev.get("vendor") or oui.MAC_KIND_TEXT.get(dev.get("mac_kind", ""), "—")),
        ("Reverse DNS", dev.get("hostname") if "DNS" in dev.get("sources", []) else "—"),
        ("mDNS name", mdns.get("hostname") or "—"),
        ("NetBIOS name", f"{nb['computer']}  (workgroup {nb.get('workgroup') or '—'})" if nb.get("computer") else "—"),
        ("Friendly name", dev.get("friendly") or "—"),
        ("Model", dev.get("model") or upnp.get("modelName") or "—"),
    ]
    if upnp:
        rows.append(("UPnP", " · ".join(
            v for v in (upnp.get("manufacturer"), upnp.get("modelName"),
                        upnp.get("modelNumber"), upnp_kind(upnp))
            if v
        )))
    if dev.get("ssdp_server"):
        rows.append(("UPnP server", dev["ssdp_server"]))
    rows.append(("mDNS services", ", ".join(dev.get("services", [])) or "—"))
    for port, value in (dev.get("banners") or {}).items():
        if isinstance(value, dict):
            text = " · ".join(v for v in (value.get("server"), value.get("title")) if v)
            rows.append((f"Web tcp/{port}", text or f"HTTP {value.get('status')}"))
        elif value:
            rows.append((f"Banner tcp/{port}", value))
    return rows


def port_rows(dev: dict) -> list[list[object]]:
    rows = []
    for port in dev.get("open_ports", []):
        service, meaning, _label, _score = PROBE_PORTS.get(port, ("?", "", "", 0))
        rows.append([f"tcp/{port}", service, meaning])
    return rows
