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

BOOTP/DHCP wire format: RFC 2131 (message) and RFC 2132 (options).
"""

from __future__ import annotations

import asyncio
import random
import socket
import struct
import time

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

    Raises PermissionError if binding UDP/68 is not allowed (needs root).
    """
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
        raise PermissionError(
            "Binding UDP/68 requires root. Run: sudo netzilla"
        ) from exc
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
