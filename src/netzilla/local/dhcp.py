"""Rogue DHCP server detector.

Broadcasts a DHCPDISCOVER and records every DHCPOFFER that comes back, with the
offering server's identity and the address/range it proposed. More than one
distinct server answering a single broadcast is the classic signature of a
rogue DHCP server (a mis-plugged home router, a VM bridged by mistake, an
attacker) fighting the real one.

Sending from UDP/68 and receiving broadcast replies needs raw access to the
port, i.e. root — so `detect()` raises PermissionError without it and the tab
tells the user to run `sudo netzilla`. The packet build and parse are pure
functions with no privilege needed, so they are unit-tested directly.

Windows: its DHCP Client service keeps UDP/68 for itself, so the offers are
heard instead on a raw socket (SIO_RCVALL, Windows' own capture switch — no
Npcap needed) on the default route's interface, while the DISCOVER goes out
from an ordinary UDP socket. Raw sockets need an Administrator terminal, the
same way the other systems need root. When the DHCP Client service is stopped
the plain way is used.

BOOTP/DHCP wire format: RFC 2131 (message) and RFC 2132 (options).
"""

from __future__ import annotations

import asyncio
import random
import socket
import struct
import time

from .. import hostos

MAGIC_COOKIE = bytes([99, 130, 83, 99])
SERVER_PORT = 67
CLIENT_PORT = 68

# DHCP message types (option 53).
DISCOVER = 1
OFFER = 2

# Option 53 -> message type; a few option numbers we decode from offers.
OPT_MESSAGE_TYPE = 53
OPT_SERVER_ID = 54
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_LEASE_TIME = 51
OPT_DOMAIN = 15
OPT_END = 255


def _mac_bytes(mac: str | None) -> bytes:
    if mac:
        cleaned = mac.replace(":", "").replace("-", "").replace(".", "")
        try:
            return bytes.fromhex(cleaned)[:6].ljust(6, b"\x00")
        except ValueError:
            pass
    return bytes(random.getrandbits(8) for _ in range(6))


def build_discover(xid: int | None = None, mac: str | None = None) -> tuple[bytes, int, bytes]:
    """Return (packet, xid, chaddr) for a DHCPDISCOVER broadcast."""
    xid = xid if xid is not None else random.getrandbits(32)
    chaddr = _mac_bytes(mac)
    packet = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,               # op: BOOTREQUEST
        1,               # htype: Ethernet
        6,               # hlen
        0,               # hops
        xid,
        0,               # secs
        0x8000,          # flags: broadcast
        b"\x00" * 4,     # ciaddr
        b"\x00" * 4,     # yiaddr
        b"\x00" * 4,     # siaddr
        b"\x00" * 4,     # giaddr
        chaddr.ljust(16, b"\x00"),
        b"\x00" * 64,    # sname
        b"\x00" * 128,   # file
    )
    options = MAGIC_COOKIE + bytes([
        OPT_MESSAGE_TYPE, 1, DISCOVER,
        55, 4, OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS, OPT_DOMAIN,  # param request list
        OPT_END,
    ])
    return packet + options, xid, chaddr[:6]


def _parse_options(blob: bytes) -> dict[int, bytes]:
    opts: dict[int, bytes] = {}
    i = 0
    n = len(blob)
    while i < n:
        code = blob[i]
        if code == 0:            # pad
            i += 1
            continue
        if code == OPT_END or i + 1 >= n:
            break
        length = blob[i + 1]
        opts[code] = blob[i + 2:i + 2 + length]
        i += 2 + length
    return opts


def parse_offer(data: bytes, expected_xid: int | None = None) -> dict | None:
    """Decode a DHCPOFFER packet into the fields netzilla shows, or None."""
    if len(data) < 240:
        return None
    (op, _htype, _hlen, _hops, xid) = struct.unpack("!BBBBI", data[:8])
    if op != 2:                  # BOOTREPLY
        return None
    if expected_xid is not None and xid != expected_xid:
        return None
    yiaddr = socket.inet_ntoa(data[16:20])
    cookie_at = data.find(MAGIC_COOKIE, 236)
    if cookie_at < 0:
        return None
    opts = _parse_options(data[cookie_at + 4:])
    if opts.get(OPT_MESSAGE_TYPE, b"") and opts[OPT_MESSAGE_TYPE][0] != OFFER:
        return None
    server_id = socket.inet_ntoa(opts[OPT_SERVER_ID]) if OPT_SERVER_ID in opts else None
    mask = socket.inet_ntoa(opts[OPT_SUBNET_MASK]) if OPT_SUBNET_MASK in opts else None
    routers = _ip_list(opts.get(OPT_ROUTER))
    dns = _ip_list(opts.get(OPT_DNS))
    lease = struct.unpack("!I", opts[OPT_LEASE_TIME])[0] if OPT_LEASE_TIME in opts else None
    domain = opts[OPT_DOMAIN].decode("ascii", "replace") if OPT_DOMAIN in opts else None
    return {
        "server_id": server_id,
        "offered_ip": yiaddr,
        "subnet_mask": mask,
        "routers": routers,
        "dns": dns,
        "lease_seconds": lease,
        "domain": domain,
        "xid": xid,
    }


def _ip_list(blob: bytes | None) -> list[str]:
    if not blob:
        return []
    return [socket.inet_ntoa(blob[i:i + 4]) for i in range(0, len(blob) - 3, 4)]


async def detect(listen_seconds: float = 5.0, mac: str | None = None) -> list[dict]:
    """Broadcast a DISCOVER and collect OFFERs for `listen_seconds`.

    Raises PermissionError if binding UDP/68 is not allowed (needs root), or
    on Windows without an Administrator terminal.
    """
    if hostos.is_windows():
        return await asyncio.to_thread(detect_windows, listen_seconds, mac)
    packet, xid, _ = build_discover(mac=mac)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.bind(("", CLIENT_PORT))
    except PermissionError as exc:
        raise PermissionError("Binding UDP/68 requires root. Run: sudo netzilla") from exc
    except OSError as exc:
        raise PermissionError(
            f"Could not open the DHCP client port ({exc}). "
            "Another DHCP client may be using it, or this needs root."
        ) from exc

    offers: dict[str, dict] = {}
    loop = asyncio.get_running_loop()
    try:
        sock.setblocking(False)
        await loop.sock_sendto(sock, packet, ("255.255.255.255", SERVER_PORT))
        deadline = time.monotonic() + listen_seconds
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 2048), timeout=remaining
                )
            except asyncio.TimeoutError:
                break
            offer = parse_offer(data, expected_xid=xid)
            if offer:
                offer["from"] = addr[0]
                key = offer.get("server_id") or addr[0]
                offers.setdefault(key, offer)
    finally:
        sock.close()
    return list(offers.values())


# ---------------------------------------------------------------- Windows
WINDOWS_ADMIN_HELP = (
    "Windows' DHCP Client service keeps UDP/68, the port DHCP offers come back "
    "to, so netzilla listens for them on a raw socket instead — and Windows only "
    "lets an Administrator open one. Close netzilla, right-click Windows Terminal, "
    "choose 'Run as administrator', and run ROGUE DHCP again."
)
# Windows' capture switch for a raw socket (mstcpip.h), in case this Python
# doesn't name them.
SIO_RCVALL = 0x98000001
RCVALL_ON = 1           # everything the adapter sees (promiscuous where it can)
RCVALL_IPLEVEL = 3      # everything that reaches IP on this host, no promiscuity
UDP = 17
LAST_HEARD = ""         # how the last Windows run listened: "udp/68" or "raw socket on …"


def primary_ipv4(sockets=socket) -> str:
    """This machine's IPv4 address on the default route. Connecting a UDP
    socket picks the route without sending a single packet."""
    try:
        probe = sockets.socket(sockets.AF_INET, sockets.SOCK_DGRAM)
        try:
            probe.connect(("192.0.2.1", 9))       # TEST-NET-1: never contacted
            address = probe.getsockname()[0]
        finally:
            probe.close()
        if address and not address.startswith(("0.", "127.")):
            return address
    except OSError:
        pass
    try:
        address = sockets.gethostbyname(sockets.gethostname())
    except OSError:
        return ""
    return "" if address.startswith(("0.", "127.")) else address


def offer_from_ip_packet(data: bytes, xid: int | None = None) -> dict | None:
    """A DHCPOFFER out of a whole IPv4 packet, as a raw socket hands it over:
    IP header, then UDP from port 67 to port 68, then the BOOTP message."""
    if len(data) < 28 or data[0] >> 4 != 4:
        return None
    header = (data[0] & 0x0F) * 4
    if header < 20 or len(data) < header + 8 or data[9] != UDP:
        return None
    if struct.unpack("!H", data[6:8])[0] & 0x1FFF:
        return None                     # a later fragment of something bigger
    source = socket.inet_ntoa(data[12:16])
    sport, dport, length = struct.unpack("!HHH", data[header:header + 6])
    if sport != SERVER_PORT or dport != CLIENT_PORT:
        return None
    end = header + length if length >= 8 else len(data)
    offer = parse_offer(data[header + 8:end], expected_xid=xid)
    if offer is not None:
        offer["from"] = source
    return offer


def _client_port_socket(sockets=socket):
    """UDP/68 the plain way — free on Windows only when the DHCP Client
    service is stopped. No SO_REUSEADDR: the port is shared with nobody."""
    sock = sockets.socket(sockets.AF_INET, sockets.SOCK_DGRAM)
    try:
        sock.setsockopt(sockets.SOL_SOCKET, sockets.SO_BROADCAST, 1)
        sock.bind(("", CLIENT_PORT))
    except BaseException:
        sock.close()
        raise
    return sock


def _raw_listener(address: str, sockets=socket):
    """A raw socket on `address`'s interface that sees every IPv4 packet."""
    sock = sockets.socket(sockets.AF_INET, sockets.SOCK_RAW, sockets.IPPROTO_IP)
    try:
        sock.bind((address, 0))
        try:
            sock.setsockopt(sockets.SOL_SOCKET, sockets.SO_RCVBUF, 1 << 20)
        except OSError:
            pass
        control = getattr(sockets, "SIO_RCVALL", SIO_RCVALL)
        failure: OSError | None = None
        for mode in (getattr(sockets, "RCVALL_ON", RCVALL_ON),
                     getattr(sockets, "RCVALL_IPLEVEL", RCVALL_IPLEVEL)):
            try:
                sock.ioctl(control, mode)
                failure = None
                break
            except OSError as exc:
                failure = exc
        if failure is not None:
            raise failure
    except BaseException:
        sock.close()
        raise
    return sock


def _hear(sock, xid: int, listen_seconds: float, raw: bool,
          clock=time.monotonic) -> list[dict]:
    """Offers for `xid` until the time is up, one per server."""
    offers: dict[str, dict] = {}
    sock.settimeout(0.25)
    deadline = clock() + listen_seconds
    while clock() < deadline:
        try:
            if raw:
                data, addr = sock.recv(65535), None
            else:
                data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        if raw:
            offer = offer_from_ip_packet(data, xid)
        else:
            offer = parse_offer(data, expected_xid=xid)
            if offer is not None:
                offer["from"] = addr[0]
        if offer:
            offers.setdefault(offer.get("server_id") or offer["from"], offer)
    return list(offers.values())


def detect_windows(listen_seconds: float = 5.0, mac: str | None = None,
                   sockets=socket, admin: bool | None = None, address: str = "",
                   clock=time.monotonic) -> list[dict]:
    """ROGUE DHCP on Windows (runs on a worker thread). Each offer is marked
    with how it was heard: "heard" = "udp/68" or "raw socket on <address>"."""
    global LAST_HEARD
    packet, xid, _ = build_discover(mac=mac)
    LAST_HEARD = ""
    try:
        port = _client_port_socket(sockets)
    except OSError:
        port = None
    if port is not None:
        try:
            port.sendto(packet, ("255.255.255.255", SERVER_PORT))
            offers = _hear(port, xid, listen_seconds, raw=False, clock=clock)
        finally:
            port.close()
        LAST_HEARD = "udp/68"
        for offer in offers:
            offer["heard"] = LAST_HEARD
        return offers

    if not (hostos.is_admin() if admin is None else admin):
        raise PermissionError(WINDOWS_ADMIN_HELP)
    address = address or primary_ipv4(sockets)
    if not address:
        raise OSError("This machine has no IPv4 address on a network to listen on — "
                      "is it connected?")
    try:
        listener = _raw_listener(address, sockets)
    except PermissionError as exc:
        raise PermissionError(WINDOWS_ADMIN_HELP) from exc
    except OSError as exc:
        raise OSError(f"Windows would not open a raw socket on {address} ({exc}). "
                      "Some VPN and security software blocks them.") from exc
    sender = sockets.socket(sockets.AF_INET, sockets.SOCK_DGRAM)
    try:
        sender.setsockopt(sockets.SOL_SOCKET, sockets.SO_BROADCAST, 1)
        sender.bind((address, 0))
        sender.sendto(packet, ("255.255.255.255", SERVER_PORT))
        offers = _hear(listener, xid, listen_seconds, raw=True, clock=clock)
    finally:
        sender.close()
        try:
            listener.ioctl(getattr(sockets, "SIO_RCVALL", SIO_RCVALL),
                           getattr(sockets, "RCVALL_OFF", 0))
        except (OSError, AttributeError, ValueError):
            pass
        listener.close()
    LAST_HEARD = f"raw socket on {address}"
    for offer in offers:
        offer["heard"] = LAST_HEARD
    return offers


def verdict(offers: list[dict]) -> tuple[str, str]:
    if not offers:
        return "NO OFFERS — no DHCP server answered on this segment", "warn"
    if len(offers) == 1:
        return f"ONE SERVER — {offers[0].get('server_id')} (expected)", "ok"
    servers = ", ".join(o.get("server_id") or o.get("from") or "?" for o in offers)
    return (
        f"MULTIPLE DHCP SERVERS — {len(offers)} answered: {servers}. "
        "Investigate for a rogue server.",
        "bad",
    )


def rows(offers: list[dict]) -> list[list[object]]:
    out = []
    for o in offers:
        out.append([
            o.get("server_id") or o.get("from") or "—",
            o.get("offered_ip") or "—",
            o.get("subnet_mask") or "—",
            ", ".join(o.get("routers") or []) or "—",
            ", ".join(o.get("dns") or []) or "—",
            _lease(o.get("lease_seconds")),
        ])
    return out


def _lease(seconds) -> str:
    if not seconds:
        return "—"
    if seconds % 86400 == 0:
        return f"{seconds // 86400}d"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    return f"{seconds}s"
