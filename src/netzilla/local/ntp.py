"""NTP clock-drift check (stdlib only, no ntplib dependency).

Clock skew silently breaks TLS validation, Kerberos, TOTP and log correlation,
so this pairs naturally with the SSL/TLS tab. netzilla sends a single SNTP
request (RFC 4330) to an NTP server and compares the server's time to the local
clock, reporting the offset.

The 48-byte packet build and the timestamp parse are pure and unit-tested; only
the send/receive touches the network.
"""

from __future__ import annotations

import socket
import struct
import time

# Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
NTP_UNIX_DELTA = 2_208_988_800
DEFAULT_SERVER = "pool.ntp.org"


def build_request() -> bytes:
    """A client-mode SNTPv4 request: LI=0, VN=4, Mode=3, rest zero."""
    first = (0 << 6) | (4 << 3) | 3
    return struct.pack("!B", first) + b"\x00" * 47


def parse_transmit_timestamp(packet: bytes) -> float:
    """Server transmit time (Unix seconds) from an NTP reply's bytes 40-47."""
    if len(packet) < 48:
        raise ValueError("short NTP packet")
    seconds, fraction = struct.unpack("!II", packet[40:48])
    if seconds == 0:
        raise ValueError("NTP server returned a zero timestamp")
    return (seconds - NTP_UNIX_DELTA) + fraction / 2 ** 32


def check(server: str = DEFAULT_SERVER, timeout: float = 5.0) -> dict:
    """Return the offset between this machine's clock and `server`."""
    request = build_request()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        t0 = time.time()
        sock.sendto(request, (server, 123))
        data, _ = sock.recvfrom(512)
        t3 = time.time()
    finally:
        sock.close()
    server_time = parse_transmit_timestamp(data)
    # Round-trip midpoint is our best estimate of "now" to compare against.
    local_mid = (t0 + t3) / 2
    offset = server_time - local_mid
    return {
        "server": server,
        "server_time": server_time,
        "local_time": local_mid,
        "offset_seconds": offset,
        "round_trip_ms": (t3 - t0) * 1000,
    }


def verdict(result: dict) -> tuple[str, str]:
    offset = abs(result.get("offset_seconds", 0))
    sign = "+" if result.get("offset_seconds", 0) >= 0 else "-"
    pretty = f"{sign}{offset:.3f}s vs {result.get('server')}"
    if offset < 0.1:
        return f"IN SYNC — clock offset {pretty}", "ok"
    if offset < 2:
        return f"SLIGHT DRIFT — clock offset {pretty}", "warn"
    return (
        f"CLOCK SKEW — offset {pretty}. This can break TLS, Kerberos and TOTP; "
        "check the NTP/chrony service.",
        "bad",
    )


def summary(result: dict) -> list[tuple[str, object]]:
    import datetime as _dt

    def stamp(epoch):
        return _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    return [
        ("NTP server", result.get("server")),
        ("Server time", stamp(result.get("server_time", 0))),
        ("Local time", stamp(result.get("local_time", 0))),
        ("Offset", f'{result.get("offset_seconds", 0):+.3f} s'),
        ("Round trip", f'{result.get("round_trip_ms", 0):.1f} ms'),
    ]
