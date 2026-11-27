"""Windows' own network tables, read through its IP Helper API.

On Linux netzilla reads /proc and runs ip and ss. Windows has none of those,
but the same answers are one call into iphlpapi.dll away — the API ipconfig,
netstat and Task Manager are built on. Python's ctypes makes the calls, so
nothing has to be installed, and nothing here needs Administrator:

  GetAdaptersAddresses    adapters, their addresses, gateways and DNS servers
  GetIfTable2             64-bit byte, packet, error and drop counters
  GetExtendedTcpTable     every TCP connection and its owning process
  GetExtendedUdpTable     every UDP socket and its owning process
  Toolhelp32 snapshot     process names for those process ids

Every reader returns plain Python data and never raises: on any failure — or
on another system — it returns None, and the caller falls back or says the
feature is unavailable. The byte layouts are decoded by separate pure
functions, so they are tested on any system.
"""

from __future__ import annotations

import ctypes
import ipaddress
import socket
import struct

# ------------------------------------------------------------ constants
AF_UNSPEC = 0
AF_INET = 2
AF_INET6 = 23                      # Windows' value (Linux uses 10)

NO_ERROR = 0
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_BUFFER_OVERFLOW = 111
ERROR_NO_DATA = 232

GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
GAA_FLAGS = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS

TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1

IF_OPER_UP = 1

# IANA ifType values Windows reports.
IF_TYPE_ETHERNET = 6
IF_TYPE_PPP = 23
IF_TYPE_LOOPBACK = 24
IF_TYPE_PROP_VIRTUAL = 53
IF_TYPE_IEEE80211 = 71
IF_TYPE_TUNNEL = 131
IF_TYPE_WWAN = (243, 244)

# MIB_TCP_STATE, named the way `ss` names them so FLOW reads them alike.
TCP_STATES = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN-SENT", 4: "SYN-RECV", 5: "ESTAB",
    6: "FIN-WAIT-1", 7: "FIN-WAIT-2", 8: "CLOSE-WAIT", 9: "CLOSING",
    10: "LAST-ACK", 11: "TIME-WAIT", 12: "DELETE-TCB",
}


# ------------------------------------------------------------- libraries
_LIBS: dict[str, object] = {}


def _dll(name: str):
    """A private handle on a system DLL (so argtypes set here never touch
    anyone else's), or None when this is not Windows."""
    if name in _LIBS:
        return _LIBS[name]
    loader = getattr(ctypes, "WinDLL", None)
    lib = None
    if loader is not None:
        try:
            lib = loader(name)
        except OSError:
            lib = None
    _LIBS[name] = lib
    return lib


# ===================================================== adapters (GAA)
class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int32)]


class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", ctypes.c_uint32),
    ("Flags", ctypes.c_uint32),
    ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
    ("PrefixOrigin", ctypes.c_int32),
    ("SuffixOrigin", ctypes.c_int32),
    ("DadState", ctypes.c_int32),
    ("ValidLifetime", ctypes.c_uint32),
    ("PreferredLifetime", ctypes.c_uint32),
    ("LeaseLifetime", ctypes.c_uint32),
    ("OnLinkPrefixLength", ctypes.c_uint8),
]


class IP_ADAPTER_ADDRESS_ENTRY(ctypes.Structure):
    """The shape shared by the gateway and DNS-server lists."""


IP_ADAPTER_ADDRESS_ENTRY._fields_ = [
    ("Length", ctypes.c_uint32),
    ("Reserved", ctypes.c_uint32),
    ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESS_ENTRY)),
    ("Address", SOCKET_ADDRESS),
]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    """IP_ADAPTER_ADDRESSES_LH up to FirstGatewayAddress — the part netzilla
    reads. The list is walked through Next pointers, never as an array, so
    the fields after it do not need to be declared."""


IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", ctypes.c_uint32),
    ("IfIndex", ctypes.c_uint32),
    ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.POINTER(IP_ADAPTER_ADDRESS_ENTRY)),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", ctypes.c_uint32),
    ("Flags", ctypes.c_uint32),
    ("Mtu", ctypes.c_uint32),
    ("IfType", ctypes.c_uint32),
    ("OperStatus", ctypes.c_int32),
    ("Ipv6IfIndex", ctypes.c_uint32),
    ("ZoneIndices", ctypes.c_uint32 * 16),
    ("FirstPrefix", ctypes.c_void_p),
    ("TransmitLinkSpeed", ctypes.c_uint64),
    ("ReceiveLinkSpeed", ctypes.c_uint64),
    ("FirstWinsServerAddress", ctypes.c_void_p),
    ("FirstGatewayAddress", ctypes.POINTER(IP_ADAPTER_ADDRESS_ENTRY)),
]


def parse_sockaddr(raw: bytes) -> str | None:
    """'192.0.2.5' or '2001:db8::5' from a Windows SOCKADDR, else None."""
    if len(raw) < 2:
        return None
    family = int.from_bytes(raw[0:2], "little")
    if family == AF_INET and len(raw) >= 8:
        return socket.inet_ntoa(raw[4:8])
    if family == AF_INET6 and len(raw) >= 24:
        return str(ipaddress.IPv6Address(raw[8:24]))
    return None


def _sockaddr_text(address: SOCKET_ADDRESS) -> str | None:
    if not address.lpSockaddr or address.iSockaddrLength <= 0:
        return None
    return parse_sockaddr(ctypes.string_at(address.lpSockaddr, min(address.iSockaddrLength, 128)))


def format_mac(raw: bytes) -> str:
    """'aa:bb:cc:dd:ee:ff' — the way `ip link` writes it — or '' when there
    is no Ethernet-style address (loopback, most tunnels)."""
    if len(raw) != 6 or not any(raw):
        return ""
    return ":".join(f"{b:02x}" for b in raw)


def _entries(first) -> list[str]:
    found: list[str] = []
    node = first
    hops = 0
    while node and hops < 64:
        entry = node.contents
        text = _sockaddr_text(entry.Address)
        if text and text not in found:
            found.append(text)
        node = entry.Next
        hops += 1
    return found


def walk_adapters(first) -> list[dict]:
    """Every adapter in a GetAdaptersAddresses list, as plain dicts:
    {name, description, guid, index, mac, mtu, if_type, up, addresses
    ['192.0.2.5/24', …], gateways, dns}."""
    adapters: list[dict] = []
    node = first
    hops = 0
    while node and hops < 512:
        adapter = node.contents
        addresses: list[str] = []
        unicast = adapter.FirstUnicastAddress
        inner = 0
        while unicast and inner < 128:
            entry = unicast.contents
            text = _sockaddr_text(entry.Address)
            if text:
                addresses.append(f"{text}/{int(entry.OnLinkPrefixLength)}")
            unicast = entry.Next
            inner += 1
        length = min(int(adapter.PhysicalAddressLength), 8)
        adapters.append({
            "name": adapter.FriendlyName or "",
            "description": adapter.Description or "",
            # "{4D36E972-…}": how the Wi-Fi API names the same adapter.
            "guid": (adapter.AdapterName or b"").decode("ascii", "replace").upper(),
            "index": int(adapter.IfIndex),
            "mac": format_mac(bytes(adapter.PhysicalAddress[:length])),
            "mtu": int(adapter.Mtu) if adapter.Mtu not in (0, 0xFFFFFFFF) else 0,
            "if_type": int(adapter.IfType),
            "up": int(adapter.OperStatus) == IF_OPER_UP,
            "addresses": addresses,
            "gateways": _entries(adapter.FirstGatewayAddress),
            "dns": _entries(adapter.FirstDnsServerAddress),
        })
        node = adapter.Next
        hops += 1
    return adapters


def adapters() -> list[dict] | None:
    """Every network adapter Windows knows, or None if it could not be asked."""
    lib = _dll("iphlpapi")
    if lib is None:
        return None
    try:
        size = ctypes.c_uint32(32 * 1024)
        result = ERROR_BUFFER_OVERFLOW
        buffer = None
        for _attempt in range(5):
            buffer = ctypes.create_string_buffer(max(size.value, 1024))
            result = lib.GetAdaptersAddresses(
                AF_UNSPEC, GAA_FLAGS, None, ctypes.byref(buffer), ctypes.byref(size))
            if result != ERROR_BUFFER_OVERFLOW:
                break
        if result == ERROR_NO_DATA:
            return []
        if result != NO_ERROR or buffer is None:
            return None
        return walk_adapters(ctypes.cast(buffer, ctypes.POINTER(IP_ADAPTER_ADDRESSES)))
    except Exception:
        return None


def adapter_kind(if_type: int, description: str = "", name: str = "") -> str:
    """The same rough labels the Linux interface names give."""
    text = f"{description} {name}".lower()
    if if_type == IF_TYPE_LOOPBACK or "loopback" in text:
        return "loopback"
    if any(word in text for word in ("wireguard",)):
        return "WireGuard"
    if if_type in (IF_TYPE_TUNNEL, IF_TYPE_PPP) or any(word in text for word in (
            "vpn", "tap-windows", "tap adapter", "openvpn", "tailscale", "zerotier",
            "anyconnect", "globalprotect", "fortinet", "wintun")):
        return "tunnel/VPN" if if_type != IF_TYPE_PPP else "PPP"
    if any(word in text for word in ("hyper-v", "vethernet", "virtualbox", "vmware",
                                     "wsl")):
        return "virtual bridge"
    if if_type == IF_TYPE_IEEE80211:
        return "wireless"
    if if_type in IF_TYPE_WWAN:
        return "mobile broadband"
    if if_type == IF_TYPE_ETHERNET:
        return "ethernet"
    return "other"


# ============================================== counters (GetIfTable2)
IF_ROW2_SIZE = 1352               # sizeof(MIB_IF_ROW2), x86 and x64 alike
IF_TABLE2_ROWS_AT = 8             # NumEntries, then rows 8-byte aligned
_ALIAS_AT, _DESCRIPTION_AT, _NAME_BYTES = 28, 542, 514
_PHYS_LEN_AT, _PHYS_AT = 1056, 1060
_MTU_AT, _TYPE_AT, _FLAGS_AT, _OPER_AT = 1124, 1128, 1152, 1156
_COUNTERS_AT = 1208               # InOctets … OutQLen: 18 × ULONG64

COUNTER_FIELDS = (
    "rx_bytes", "rx_packets", "rx_errs", "rx_drop", "rx_fifo", "rx_frame",
    "rx_compressed", "rx_multicast",
    "tx_bytes", "tx_packets", "tx_errs", "tx_drop", "tx_fifo", "tx_colls",
    "tx_carrier", "tx_compressed",
)


def _wide(raw: bytes) -> str:
    return raw.decode("utf-16-le", "replace").split("\x00", 1)[0].strip()


def parse_if_row2(row: bytes) -> dict:
    """One MIB_IF_ROW2: its names, type, state and counters, with the
    counters under the same names /proc/net/dev gives them."""
    (in_octets, in_ucast, in_nucast, in_discards, in_errors, _unknown,
     _in_ucast_octets, in_multicast_octets, _in_broadcast_octets,
     out_octets, out_ucast, out_nucast, out_discards, out_errors,
     _out_ucast_octets, _out_multicast_octets, _out_broadcast_octets,
     _out_qlen) = struct.unpack_from("<18Q", row, _COUNTERS_AT)
    flags = row[_FLAGS_AT]
    phys_len = min(struct.unpack_from("<I", row, _PHYS_LEN_AT)[0], 32)
    counters = dict.fromkeys(COUNTER_FIELDS, 0)
    counters.update(
        rx_bytes=in_octets, rx_packets=in_ucast + in_nucast, rx_errs=in_errors,
        rx_drop=in_discards, rx_multicast=in_multicast_octets,
        tx_bytes=out_octets, tx_packets=out_ucast + out_nucast, tx_errs=out_errors,
        tx_drop=out_discards,
    )
    return {
        "name": _wide(row[_ALIAS_AT:_ALIAS_AT + _NAME_BYTES]),
        "description": _wide(row[_DESCRIPTION_AT:_DESCRIPTION_AT + _NAME_BYTES]),
        "mac": format_mac(row[_PHYS_AT:_PHYS_AT + phys_len]),
        "mtu": struct.unpack_from("<I", row, _MTU_AT)[0],
        "if_type": struct.unpack_from("<I", row, _TYPE_AT)[0],
        "up": struct.unpack_from("<I", row, _OPER_AT)[0] == IF_OPER_UP,
        "hardware": bool(flags & 0x01),
        "filter": bool(flags & 0x02),
        "counters": counters,
    }


def parse_if_table2(raw: bytes, count: int) -> dict[str, dict]:
    """{alias: row} for every real interface. Filter drivers (the WFP, QoS
    and Npcap layers stacked on each adapter) repeat their adapter's numbers
    under names like 'Wi-Fi-QoS Packet Scheduler-0000' and are skipped."""
    rows: dict[str, dict] = {}
    for index in range(max(0, min(count, 4096))):
        start = index * IF_ROW2_SIZE
        row = raw[start:start + IF_ROW2_SIZE]
        if len(row) < IF_ROW2_SIZE:
            break
        info = parse_if_row2(row)
        if info["filter"] or not info["name"]:
            continue
        if info["name"] in rows and not info["hardware"]:
            continue
        rows[info["name"]] = info
    return rows


def if_table() -> dict[str, dict] | None:
    """{alias: row} from GetIfTable2, or None if it could not be read."""
    lib = _dll("iphlpapi")
    if lib is None:
        return None
    table = ctypes.c_void_p()
    try:
        if lib.GetIfTable2(ctypes.byref(table)) != NO_ERROR or not table.value:
            return None
        try:
            count = min(ctypes.c_uint32.from_address(table.value).value, 4096)
            raw = ctypes.string_at(table.value + IF_TABLE2_ROWS_AT, count * IF_ROW2_SIZE)
        finally:
            lib.FreeMibTable(table)
        return parse_if_table2(raw, count)
    except Exception:
        return None


def counters() -> dict[str, dict] | None:
    """{alias: counters} — Windows' answer to /proc/net/dev."""
    table = if_table()
    if table is None:
        return None
    return {name: row["counters"] for name, row in table.items()}


# ====================================== connections (TCP and UDP tables)
def _port(raw: bytes) -> int:
    return (raw[0] << 8) | raw[1]          # network byte order, low word


def _blank(ip: str, port: int) -> str:
    return "" if port == 0 and ip in ("0.0.0.0", "::") else ip


def parse_tcp_table(raw: bytes, v6: bool = False) -> list[dict]:
    """MIB_TCPTABLE_OWNER_PID (or the TCP6 one) -> connection records."""
    if len(raw) < 4:
        return []
    count = struct.unpack_from("<I", raw, 0)[0]
    size = 56 if v6 else 24
    found = []
    for index in range(count):
        at = 4 + index * size
        if at + size > len(raw):
            break
        if v6:
            local = str(ipaddress.IPv6Address(raw[at:at + 16]))
            local_port = _port(raw[at + 20:at + 22])
            remote = str(ipaddress.IPv6Address(raw[at + 24:at + 40]))
            remote_port = _port(raw[at + 44:at + 46])
            state, pid = struct.unpack_from("<II", raw, at + 48)
        else:
            state = struct.unpack_from("<I", raw, at)[0]
            local = socket.inet_ntoa(raw[at + 4:at + 8])
            local_port = _port(raw[at + 8:at + 10])
            remote = socket.inet_ntoa(raw[at + 12:at + 16])
            remote_port = _port(raw[at + 16:at + 18])
            pid = struct.unpack_from("<I", raw, at + 20)[0]
        found.append({
            "proto": "tcp", "local_ip": local, "local_port": local_port,
            "remote_ip": _blank(remote, remote_port), "remote_port": remote_port,
            "state": TCP_STATES.get(state, str(state)), "process": "", "pid": pid,
        })
    return found


def parse_udp_table(raw: bytes, v6: bool = False) -> list[dict]:
    """MIB_UDPTABLE_OWNER_PID (or the UDP6 one) -> socket records."""
    if len(raw) < 4:
        return []
    count = struct.unpack_from("<I", raw, 0)[0]
    size = 28 if v6 else 12
    found = []
    for index in range(count):
        at = 4 + index * size
        if at + size > len(raw):
            break
        if v6:
            local = str(ipaddress.IPv6Address(raw[at:at + 16]))
            local_port = _port(raw[at + 20:at + 22])
            pid = struct.unpack_from("<I", raw, at + 24)[0]
        else:
            local = socket.inet_ntoa(raw[at:at + 4])
            local_port = _port(raw[at + 4:at + 6])
            pid = struct.unpack_from("<I", raw, at + 8)[0]
        found.append({
            "proto": "udp", "local_ip": local, "local_port": local_port,
            "remote_ip": "", "remote_port": 0, "state": "UNCONN",
            "process": "", "pid": pid,
        })
    return found


def _extended_table(function, family: int, table_class: int) -> bytes | None:
    size = ctypes.c_uint32(0)
    function(None, ctypes.byref(size), False, family, table_class, 0)
    for _attempt in range(5):
        buffer = ctypes.create_string_buffer(max(size.value, 4) + 4096)
        size = ctypes.c_uint32(len(buffer))
        result = function(ctypes.byref(buffer), ctypes.byref(size), False, family,
                          table_class, 0)
        if result == ERROR_INSUFFICIENT_BUFFER:
            continue                       # the table grew between the calls
        if result != NO_ERROR:
            return None
        return buffer.raw[:size.value]
    return None


def connections() -> list[dict] | None:
    """Every TCP connection and UDP socket, with the owning process's name —
    Windows' answer to `ss -tunap`. None if the tables could not be read."""
    lib = _dll("iphlpapi")
    if lib is None:
        return None
    found: list[dict] = []
    try:
        for family, v6 in ((AF_INET, False), (AF_INET6, True)):
            raw = _extended_table(lib.GetExtendedTcpTable, family, TCP_TABLE_OWNER_PID_ALL)
            if raw is not None:
                found += parse_tcp_table(raw, v6)
            raw = _extended_table(lib.GetExtendedUdpTable, family, UDP_TABLE_OWNER_PID)
            if raw is not None:
                found += parse_udp_table(raw, v6)
    except Exception:
        return None
    names = process_names()
    for conn in found:
        conn["process"] = names.get(conn["pid"], "") if conn["pid"] else ""
    return found


# ================================================ processes and the box
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("cntUsage", ctypes.c_uint32),
        ("th32ProcessID", ctypes.c_uint32),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", ctypes.c_uint32),
        ("cntThreads", ctypes.c_uint32),
        ("th32ParentProcessID", ctypes.c_uint32),
        ("pcPriClassBase", ctypes.c_int32),
        ("dwFlags", ctypes.c_uint32),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def process_names() -> dict[int, str]:
    """{pid: 'firefox.exe'} for every running process; {} if unavailable."""
    kernel32 = _dll("kernel32")
    if kernel32 is None:
        return {}
    try:
        kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
        kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)   # TH32CS_SNAPPROCESS
        if not snapshot or snapshot == ctypes.c_void_p(-1).value:
            return {}
        names: dict[int, str] = {}
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while more and len(names) < 65536:
                names[int(entry.th32ProcessID)] = entry.szExeFile
                more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot)
        return names
    except Exception:
        return {}


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_uint32),
        ("dwMemoryLoad", ctypes.c_uint32),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]


def memory() -> tuple[int, int] | None:
    """(used, total) bytes of RAM, 'used' meaning not available."""
    kernel32 = _dll("kernel32")
    if kernel32 is None:
        return None
    try:
        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return None
        total = int(status.ullTotalPhys)
        if total <= 0:
            return None
        return total - int(status.ullAvailPhys), total
    except Exception:
        return None


def uptime_seconds() -> float | None:
    kernel32 = _dll("kernel32")
    if kernel32 is None:
        return None
    try:
        kernel32.GetTickCount64.restype = ctypes.c_uint64
        return kernel32.GetTickCount64() / 1000.0
    except Exception:
        return None


__all__ = [
    "adapters", "walk_adapters", "adapter_kind", "parse_sockaddr", "format_mac",
    "if_table", "counters", "parse_if_row2", "parse_if_table2", "connections",
    "parse_tcp_table", "parse_udp_table", "process_names", "memory",
    "uptime_seconds", "TCP_STATES", "IF_ROW2_SIZE",
]
