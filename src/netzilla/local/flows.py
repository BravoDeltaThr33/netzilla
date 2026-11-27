"""Live connection and traffic view — netzilla's take on Sniffnet.

This is a monitor of *this machine's own* network activity: the sockets it has
open, who they talk to, on what ports, and how much the interfaces are moving.
It reads the same places `ss`, `netstat` and /proc/net/dev do, and it never
touches anyone else's traffic — for on-the-wire packet capture there is the
CAPTURE tab, which this one hands off to for a PCAP.

Everything is a pure function over `ss` output and counter samples, so the
parsing, aggregation, service naming and blacklist matching are all testable
without a socket:

  ss -tunap        TCP+UDP, numeric, with the owning process where visible
  /proc/net/dev    interface byte counters, sampled twice for a rate

Windows hands over the same table, owning process included, through its IP
Helper API (winapi.py; `netstat -ano` as the fallback). macOS gets every
socket from `netstat -an` and the owning processes from `lsof`, which sees
other users' processes only when netzilla runs as root.

A connection record is:

  {proto, local_ip, local_port, remote_ip, remote_port, state, process, pid}
"""

from __future__ import annotations

import asyncio
import ipaddress
import re

from .. import hostos
from . import netif
from .runner import have, run

# ------------------------------------------------------- service naming
# Application-layer service behind a well-known port. Enough to make a flow
# list readable at a glance; not a substitute for real DPI.
WELL_KNOWN = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 161: "SNMP", 162: "SNMP-trap", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "syslog",
    587: "SMTP-sub", 636: "LDAPS", 853: "DoT", 993: "IMAPS", 995: "POP3S",
    1194: "OpenVPN", 1443: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5061: "SIPS", 5432: "Postgres",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9100: "JetDirect", 27017: "MongoDB", 51820: "WireGuard",
}


def service_for(port: int, proto: str = "") -> str:
    name = WELL_KNOWN.get(port)
    if name:
        return name
    if port >= 49152:
        return "ephemeral"
    if port >= 1024:
        return "registered"
    return f"port {port}"


def flow_service(conn: dict) -> str:
    """The service behind a connection, chosen from whichever end is the
    well-known port.

    A connection has two ports, and only one of them names the service: when
    you browse, the remote port is 443; when something connects to your SSH
    server, the *local* port is 22 and the remote is an ephemeral client port.
    Reading the remote port alone would miss every inbound connection, so this
    prefers whichever side is a recognised service port.
    """
    remote, local = conn.get("remote_port", 0), conn.get("local_port", 0)
    if remote in WELL_KNOWN:
        return WELL_KNOWN[remote]
    if local in WELL_KNOWN:
        return WELL_KNOWN[local]
    candidates = [p for p in (remote, local) if p]
    return service_for(min(candidates)) if candidates else "—"


# ------------------------------------------------------------- ss parser
# "tcp ESTAB 0 0 192.168.1.5:51234 142.250.191.78:443 users:(("firefox",pid=42,fd=90))"
_ADDR_RE = re.compile(r"^(?P<ip>.*):(?P<port>\d+|\*)$")
_PROC_RE = re.compile(r'\("(?P<name>[^"]+)",pid=(?P<pid>\d+)')


def _split_addr(token: str) -> tuple[str, int]:
    """Split ss's address:port, coping with IPv6 and the [::] forms."""
    token = token.strip()
    if token.startswith("["):                      # [2001:db8::1]:443
        host, _, port = token.rpartition("]:")
        return host.lstrip("["), _to_port(port)
    match = _ADDR_RE.match(token)
    if not match:
        return token, 0
    return match.group("ip"), _to_port(match.group("port"))


def _to_port(text: str) -> int:
    try:
        return int(text)
    except (TypeError, ValueError):
        return 0


def parse_ss(text: str) -> list[dict]:
    """Connections from `ss -tunap` (or -tuna without root for the process)."""
    connections = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in ("tcp", "udp"):
            continue
        # ss columns: Netid State Recv-Q Send-Q Local Peer [Process]
        state = parts[1]
        local_ip, local_port = _split_addr(parts[4])
        remote_ip, remote_port = _split_addr(parts[5]) if len(parts) > 5 else ("", 0)
        process, pid = "", 0
        proc_match = _PROC_RE.search(line)
        if proc_match:
            process = proc_match.group("name")
            pid = int(proc_match.group("pid"))
        connections.append({
            "proto": proto,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "state": state,
            "process": process,
            "pid": pid,
        })
    return connections


def source_label() -> str:
    """Where snapshot() reads the connection table on this system."""
    if hostos.is_windows():
        return "Windows' connection table"
    if hostos.is_macos():
        return "netstat and lsof"
    return "ss"


def is_external(ip: str) -> bool:
    """A remote address worth resolving/geolocating — not us, not a LAN peer."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_multicast or address.is_unspecified or address.is_reserved
    )


def established(connections: list[dict]) -> list[dict]:
    return [c for c in connections if c["state"] in ("ESTAB", "ESTABLISHED")]


# ------------------------------------------------------- aggregation
def by_remote_host(connections: list[dict]) -> list[dict]:
    """Group established connections by the remote IP — the 'top talkers'."""
    tally: dict[str, dict] = {}
    for conn in established(connections):
        ip = conn["remote_ip"]
        if not ip:
            continue
        entry = tally.setdefault(ip, {
            "remote_ip": ip, "connections": 0, "ports": set(),
            "processes": set(), "external": is_external(ip),
        })
        entry["connections"] += 1
        entry["ports"].add(conn["remote_port"])
        if conn["process"]:
            entry["processes"].add(conn["process"])
    rows = []
    for entry in tally.values():
        entry["ports"] = sorted(entry["ports"])
        entry["processes"] = sorted(entry["processes"])
        rows.append(entry)
    rows.sort(key=lambda e: e["connections"], reverse=True)
    return rows


def by_service(connections: list[dict]) -> list[dict]:
    """Group by the application service on the remote port."""
    tally: dict[str, dict] = {}
    for conn in established(connections):
        service = flow_service(conn)
        key = f"{service}/{conn['proto']}"
        entry = tally.setdefault(key, {
            "service": service, "proto": conn["proto"], "count": 0,
        })
        entry["count"] += 1
    rows = list(tally.values())
    rows.sort(key=lambda e: e["count"], reverse=True)
    return rows


def state_breakdown(connections: list[dict]) -> list[tuple[str, int]]:
    tally: dict[str, int] = {}
    for conn in connections:
        tally[conn["state"]] = tally.get(conn["state"], 0) + 1
    return sorted(tally.items(), key=lambda kv: kv[1], reverse=True)


# --------------------------------------------------------- blacklist
_CIDR_HINT = re.compile(r"/\d{1,3}$")


def load_blacklist(text: str) -> list[object]:
    """Parse a blacklist file: one IP or CIDR per line, # comments allowed."""
    entries: list[object] = []
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            if _CIDR_HINT.search(line):
                entries.append(ipaddress.ip_network(line, strict=False))
            else:
                entries.append(ipaddress.ip_address(line))
        except ValueError:
            continue
    return entries


def blacklist_hits(connections: list[dict], blacklist: list[object]) -> list[dict]:
    """Every established connection whose remote IP is on the blacklist."""
    if not blacklist:
        return []
    hits = []
    for conn in established(connections):
        try:
            address = ipaddress.ip_address(conn["remote_ip"])
        except ValueError:
            continue
        for entry in blacklist:
            matched = (
                address == entry
                if isinstance(entry, (ipaddress.IPv4Address, ipaddress.IPv6Address))
                else address in entry
            )
            if matched:
                hits.append(conn)
                break
    return hits


# ------------------------------------------------------------- summary
def summary(connections: list[dict]) -> list[tuple[str, object]]:
    live = established(connections)
    externals = {c["remote_ip"] for c in live if is_external(c["remote_ip"])}
    return [
        ("Sockets", len(connections)),
        ("Established", len(live)),
        ("Remote hosts", len({c["remote_ip"] for c in live if c["remote_ip"]})),
        ("External hosts", len(externals)),
        ("TCP / UDP", f'{sum(c["proto"] == "tcp" for c in connections)}'
                      f' / {sum(c["proto"] == "udp" for c in connections)}'),
    ]


def connection_rows(connections: list[dict], limit: int = 200) -> list[list[object]]:
    rows = []
    for conn in connections[:limit]:
        rows.append([
            conn["proto"].upper(),
            f'{conn["local_ip"]}:{conn["local_port"]}',
            f'{conn["remote_ip"]}:{conn["remote_port"]}' if conn["remote_ip"] else "—",
            flow_service(conn),
            conn["state"],
            conn["process"] or "—",
        ])
    return rows


# --------------------------------------------------------- live capture
async def snapshot() -> tuple[list[dict], str]:
    """One reading of the connection table. (connections, error)."""
    if hostos.is_windows():
        return await _windows_snapshot()
    if hostos.is_macos():
        return await _macos_snapshot()
    if not have("ss"):
        if have("netstat"):
            result = await run(["netstat", "-tunp"], timeout=8, ok_returncodes=(0, 1))
            return _parse_netstat(result.output), ""
        return [], "Neither ss nor netstat is installed (sudo apt install iproute2)."
    result = await run(["ss", "-tunap"], timeout=8, ok_returncodes=(0, 1))
    return parse_ss(result.output), ""


def _parse_netstat(text: str) -> list[dict]:
    """Fallback parser for netstat -tunp, close enough to feed the same views."""
    connections = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 6 or not parts[0].lower().startswith(("tcp", "udp")):
            continue
        proto = "tcp" if parts[0].lower().startswith("tcp") else "udp"
        local_ip, local_port = _split_addr(parts[3])
        remote_ip, remote_port = _split_addr(parts[4])
        state = parts[5] if proto == "tcp" and len(parts) > 5 else "UNCONN"
        process = ""
        if parts[-1] and "/" in parts[-1]:
            process = parts[-1].split("/", 1)[1]
        connections.append({
            "proto": proto, "local_ip": local_ip, "local_port": local_port,
            "remote_ip": remote_ip, "remote_port": remote_port,
            "state": "ESTAB" if state == "ESTABLISHED" else state,
            "process": process, "pid": 0,
        })
    return connections


# ------------------------------------------------------------ Windows
_STATE_NAMES = {
    "ESTABLISHED": "ESTAB", "LISTENING": "LISTEN", "LISTEN": "LISTEN",
    "SYN_SENT": "SYN-SENT", "SYN_RECEIVED": "SYN-RECV", "SYN_RCVD": "SYN-RECV",
    "FIN_WAIT_1": "FIN-WAIT-1", "FIN_WAIT_2": "FIN-WAIT-2", "CLOSE_WAIT": "CLOSE-WAIT",
    "CLOSING": "CLOSING", "LAST_ACK": "LAST-ACK", "TIME_WAIT": "TIME-WAIT",
    "CLOSED": "CLOSED", "DELETE_TCB": "DELETE-TCB",
    # Windows' netstat speaks the system's language. The IP Helper API, which
    # netzilla asks first, does not; these cover the fallback's commonest.
    "ABHÖREN": "LISTEN", "HERGESTELLT": "ESTAB", "WARTEND": "TIME-WAIT",
    "SCHLIESSEN_WARTEN": "CLOSE-WAIT", "ÉCOUTE": "LISTEN", "ÉTABLI": "ESTAB",
    "ESCUCHANDO": "LISTEN", "ESTABLECIDO": "ESTAB",
}


def _state(text: str) -> str:
    """A netstat state as `ss` names it (ESTABLISHED -> ESTAB)."""
    return _STATE_NAMES.get(text.upper(), text.upper())


def parse_netstat_windows(text: str) -> list[dict]:
    """Connections from Windows' `netstat -ano` (the PID is the last column;
    the state, blank for UDP, is in the system's language)."""
    connections = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].upper() not in ("TCP", "UDP"):
            continue
        proto = parts[0].lower()
        local_ip, local_port = _split_addr(parts[1])
        remote_ip, remote_port = _split_addr(parts[2])
        if remote_ip in ("*", "0.0.0.0", "::") and not remote_port:
            remote_ip = ""
        state = _state(parts[3]) if proto == "tcp" and len(parts) >= 5 else "UNCONN"
        connections.append({
            "proto": proto, "local_ip": local_ip, "local_port": local_port,
            "remote_ip": remote_ip, "remote_port": remote_port, "state": state,
            "process": "", "pid": _to_port(parts[-1]),
        })
    return connections


async def _windows_snapshot() -> tuple[list[dict], str]:
    from . import winapi

    found = await asyncio.to_thread(winapi.connections)
    if found is not None:
        return found, ""
    if have("netstat"):
        result = await run(["netstat", "-ano"], timeout=15, ok_returncodes=(0, 1))
        found = parse_netstat_windows(result.output)
        names = await asyncio.to_thread(winapi.process_names)
        for conn in found:
            conn["process"] = names.get(conn["pid"], "") if conn["pid"] else ""
        return found, ""
    return [], "Windows did not hand over its connection table."


# -------------------------------------------------------------- macOS
def _split_bsd(token: str) -> tuple[str, int]:
    """BSD netstat's address.port ("192.0.2.5.443", "*.22", "fe80::1%en0.5353")."""
    host, _, port = token.rpartition(".")
    if not host:
        return token, 0
    host = host.split("%", 1)[0]
    return ("" if host == "*" else host), _to_port(port)


def parse_netstat_bsd(text: str) -> list[dict]:
    """Every socket from macOS's `netstat -an` (no process names)."""
    connections = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 5 or not parts[0].lower().startswith(("tcp", "udp")):
            continue
        proto = "tcp" if parts[0].lower().startswith("tcp") else "udp"
        local_ip, local_port = _split_bsd(parts[3])
        remote_ip, remote_port = _split_bsd(parts[4])
        state = _state(parts[5]) if proto == "tcp" and len(parts) > 5 else "UNCONN"
        connections.append({
            "proto": proto, "local_ip": local_ip or ("::" if "6" in parts[0] and
                                                    "4" not in parts[0] else "0.0.0.0"),
            "local_port": local_port, "remote_ip": remote_ip, "remote_port": remote_port,
            "state": state, "process": "", "pid": 0,
        })
    return connections


def _split_lsof(token: str) -> tuple[str, int]:
    if token.startswith("["):
        return _split_addr(token)
    host, _, port = token.rpartition(":")
    return ("" if host == "*" else host), _to_port(port)


def parse_lsof(text: str) -> list[dict]:
    """Sockets and their processes from `lsof -nP -iTCP -iUDP -FpcPnT`."""
    connections: list[dict] = []
    pid, command, proto, current = 0, "", "", None
    for line in (text or "").splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            pid, command, current = _to_port(value), "", None
        elif tag == "c":
            command = value
        elif tag == "f":
            current = None
        elif tag == "P":
            proto = value.lower()
        elif tag == "n" and proto in ("tcp", "udp"):
            local, _, remote = value.partition("->")
            local_ip, local_port = _split_lsof(local)
            remote_ip, remote_port = _split_lsof(remote) if remote else ("", 0)
            current = {"proto": proto, "local_ip": local_ip, "local_port": local_port,
                       "remote_ip": remote_ip, "remote_port": remote_port,
                       "state": "UNCONN" if proto == "udp" else "", "process": command,
                       "pid": pid}
            connections.append(current)
        elif tag == "T" and current is not None and value.startswith("ST="):
            current["state"] = _state(value[3:])
    return connections


def _bare(ip: str) -> str:
    """An address with any ::ffff: v4-mapping and %zone stripped, to match on."""
    ip = (ip or "").split("%", 1)[0].lower()
    return ip[7:] if ip.startswith("::ffff:") else ip


def with_processes(sockets: list[dict], owned: list[dict]) -> list[dict]:
    """netstat's sockets with lsof's process names put on the ones it saw."""
    def key(conn: dict) -> tuple:
        return (conn["proto"], conn["local_port"], _bare(conn["remote_ip"]),
                conn["remote_port"])

    owners = {key(c): c for c in owned}
    for conn in sockets:
        match = owners.get(key(conn))
        if match:
            conn["process"], conn["pid"] = match["process"], match["pid"]
    return sockets


async def _macos_snapshot() -> tuple[list[dict], str]:
    tables = await asyncio.gather(
        run(["netstat", "-an", "-p", "tcp"], timeout=10, ok_returncodes=(0, 1)),
        run(["netstat", "-an", "-p", "udp"], timeout=10, ok_returncodes=(0, 1)),
        run(["lsof", "-nP", "-iTCP", "-iUDP", "-FpcPnT"], timeout=15, ok_returncodes=(0, 1)),
    )
    sockets = parse_netstat_bsd(tables[0].output + "\n" + tables[1].output)
    owned = parse_lsof(tables[2].output)
    if sockets:
        return with_processes(sockets, owned), ""
    if owned:
        return owned, ""
    return [], "netstat and lsof both came back empty."


async def interface_intensity(seconds: float = 2.0) -> list[dict]:
    """Per-interface throughput right now, reusing the INT tab's sampler."""
    return await netif.sample_rates(seconds=seconds)


def intensity_rows(rates: list[dict]) -> list[list[object]]:
    peak = max([r["rx_mbps"] + r["tx_mbps"] for r in rates], default=0.0)
    rows = []
    for rate in sorted(rates, key=lambda r: r["rx_mbps"] + r["tx_mbps"], reverse=True):
        total = rate["rx_mbps"] + rate["tx_mbps"]
        rows.append([
            rate["name"],
            f'{rate["rx_mbps"]:.2f}',
            f'{rate["tx_mbps"]:.2f}',
            netif.bar(total, peak),
        ])
    return rows
