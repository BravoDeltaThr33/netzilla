"""Tests for netzilla 4.6: Windows and macOS.

  * hostos says which system this is, where netzilla keeps its files, where
    a tool lives off PATH and how to install one, in that system's terms
  * Windows: the IP Helper API (adapters, counters, connections) and the
    Native Wi-Fi API read through ctypes, with netsh, netstat, tracert and
    pathping where a program is the better source; output in the console's
    code page is decoded
  * macOS: ifconfig, networksetup, route, netstat -ib, system_profiler,
    lsof and the BSD tools' formats
  * WHOIS without a whois program, the TLS handshake without openssl
  * every screen and help card names the tool that runs on that system

Everything runs on Linux: the system is faked by setting hostos.NAME, the
Windows structures are built byte by byte, and the tools' output is recorded.
"""

from __future__ import annotations

import asyncio
import ctypes
import io
import json
import struct
from pathlib import Path

import pytest

from netzilla import __version__, hostos


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(hostos, "NAME", hostos.WINDOWS)


@pytest.fixture
def macos(monkeypatch):
    monkeypatch.setattr(hostos, "NAME", hostos.MACOS)


def test_version_is_4_6():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (4, 6), __version__


# ================================================================= hostos
@pytest.mark.parametrize("platform_name, expected", [
    ("linux", "linux"), ("win32", "windows"), ("cygwin", "linux"),
    ("darwin", "macos"), ("freebsd14", "linux"),
])
def test_detect_names_the_system(platform_name, expected):
    assert hostos.detect(platform_name) == expected


def test_config_lives_where_each_system_keeps_it(monkeypatch, tmp_path):
    monkeypatch.setattr(hostos, "NAME", hostos.WINDOWS)
    roaming = tmp_path / "Roaming"
    assert hostos.config_dir({"APPDATA": str(roaming)}) == roaming / "netzilla"
    monkeypatch.setattr(hostos, "NAME", hostos.MACOS)
    assert hostos.config_dir({"HOME": str(tmp_path)}).parts[-2:] == (".config", "netzilla")
    xdg = tmp_path / "xdg"
    assert hostos.config_dir({"XDG_CONFIG_HOME": str(xdg)}) == xdg / "netzilla"


def test_install_hints_speak_each_systems_package_manager(monkeypatch):
    monkeypatch.setattr(hostos, "NAME", hostos.LINUX)
    assert hostos.install_hint("mtr") == "sudo apt install mtr-tiny"
    monkeypatch.setattr(hostos, "NAME", hostos.MACOS)
    assert hostos.install_hint("mtr") == "brew install mtr"
    assert hostos.install_hint("dig") == "dig is built into macOS."
    assert hostos.install_commands(["mtr", "tshark", "iftop"]) == [
        "brew install mtr iftop", "brew install --cask wireshark-app"]
    assert hostos.install_hint("vnstat") == "brew install vnstat"
    monkeypatch.setattr(hostos, "NAME", hostos.WINDOWS)
    assert hostos.install_hint("tshark") == "winget install WiresharkFoundation.Wireshark"
    assert hostos.install_hint("tcpdump").startswith("tcpdump is not available on Windows")
    assert not hostos.available_here("iw") and hostos.available_here("ping")
    assert "could not find it" in hostos.missing_tool_text("ping")


def test_tools_off_path_are_found_where_they_install(monkeypatch, tmp_path):
    monkeypatch.setattr(hostos, "NAME", hostos.WINDOWS)
    program_files = tmp_path / "Program Files"
    dirs = hostos.extra_tool_dirs("tshark", {"ProgramFiles": str(program_files)})
    assert str(program_files / "Wireshark") in dirs
    monkeypatch.setattr(hostos, "NAME", hostos.MACOS)
    assert hostos.AIRPORT_DIR in hostos.extra_tool_dirs("airport")
    assert "/Applications/Wireshark.app/Contents/MacOS" in hostos.extra_tool_dirs("tshark")
    assert "/opt/homebrew/bin" in hostos.extra_tool_dirs("mtr")


def test_windows_output_is_read_in_the_consoles_code_page(monkeypatch):
    monkeypatch.setattr(hostos, "NAME", hostos.WINDOWS)
    monkeypatch.setattr(hostos, "_oem_encoding", lambda: "cp850")
    german = "Zeitüberschreitung der Anforderung."
    assert hostos.decode(german.encode("cp850")) == german
    assert hostos.decode("Antwort — ok".encode("utf-8")) == "Antwort — ok"
    assert hostos.decode(None) == ""


def test_file_names_suit_every_system():
    name = hostos.safe_filename(r"\Device\NPF_{4D36E972-E325}: Wi-Fi?")
    assert not set(name) & set('\\/:*?"<>|')
    assert name and not name.endswith((".", " "))
    assert hostos.safe_filename("...") == "capture"


def test_sudo_is_a_linux_and_macos_thing(monkeypatch):
    monkeypatch.setattr(hostos, "NAME", hostos.WINDOWS)
    assert hostos.has_sudo() is False
    assert "administrator" in hostos.admin_hint().lower()


# ============================================== Windows: IP Helper API
def _sockaddr_v4(ip: str) -> bytes:
    import socket

    return struct.pack("<H", 2) + b"\x00\x00" + socket.inet_aton(ip) + bytes(8)


def test_sockaddrs_and_macs_read_as_the_linux_tools_write_them():
    from netzilla.local import winapi

    assert winapi.parse_sockaddr(_sockaddr_v4("192.0.2.5")) == "192.0.2.5"
    v6 = struct.pack("<H", 23) + bytes(6) + bytes.fromhex("20010db8000000000000000000000005") + bytes(4)
    assert winapi.parse_sockaddr(v6) == "2001:db8::5"
    assert winapi.parse_sockaddr(b"\x01") is None
    assert winapi.format_mac(bytes.fromhex("a42bb0123456")) == "a4:2b:b0:12:34:56"
    assert winapi.format_mac(bytes(6)) == ""


def test_adapter_list_is_walked_into_plain_records():
    from netzilla.local import winapi

    keep = []

    def sockaddr(ip):
        buffer = ctypes.create_string_buffer(_sockaddr_v4(ip), 16)
        keep.append(buffer)
        return winapi.SOCKET_ADDRESS(ctypes.cast(buffer, ctypes.c_void_p), 16)

    unicast = winapi.IP_ADAPTER_UNICAST_ADDRESS(Address=sockaddr("192.168.1.23"),
                                                OnLinkPrefixLength=24)
    gateway = winapi.IP_ADAPTER_ADDRESS_ENTRY(Address=sockaddr("192.168.1.1"))
    dns = winapi.IP_ADAPTER_ADDRESS_ENTRY(Address=sockaddr("192.168.1.1"))
    adapter = winapi.IP_ADAPTER_ADDRESSES(
        IfIndex=11, AdapterName=b"{6f3d5b32-1a2b-4c3d-8e9f-0a1b2c3d4e5f}",
        FirstUnicastAddress=ctypes.pointer(unicast),
        FirstDnsServerAddress=ctypes.pointer(dns),
        FirstGatewayAddress=ctypes.pointer(gateway),
        Description="Intel(R) Wi-Fi 6 AX201 160MHz", FriendlyName="Wi-Fi",
        PhysicalAddressLength=6, Mtu=1500, IfType=71, OperStatus=1,
    )
    adapter.PhysicalAddress[:6] = list(bytes.fromhex("3c58c2112233"))
    found = winapi.walk_adapters(ctypes.pointer(adapter))
    assert found == [{
        "name": "Wi-Fi", "description": "Intel(R) Wi-Fi 6 AX201 160MHz",
        "guid": "{6F3D5B32-1A2B-4C3D-8E9F-0A1B2C3D4E5F}", "index": 11,
        "mac": "3c:58:c2:11:22:33", "mtu": 1500, "if_type": 71, "up": True,
        "addresses": ["192.168.1.23/24"], "gateways": ["192.168.1.1"],
        "dns": ["192.168.1.1"],
    }]
    assert winapi.adapter_kind(71) == "wireless"
    assert winapi.adapter_kind(6, "Hyper-V Virtual Ethernet Adapter") == "virtual bridge"
    assert winapi.adapter_kind(53, "WireGuard Tunnel") == "WireGuard"


def test_adapters_become_interfaces_gateways_and_dns_servers():
    from netzilla.local import netif

    adapters = [
        {"name": "Wi-Fi", "description": "Intel Wi-Fi", "guid": "{A}", "index": 11,
         "mac": "3c:58:c2:11:22:33", "mtu": 1500, "if_type": 71, "up": True,
         "addresses": ["192.168.1.23/24", "fe80::1/64"], "gateways": ["192.168.1.1"],
         "dns": ["192.168.1.1", "fec0:0:0:ffff::1"]},
        {"name": "Ethernet", "description": "Realtek", "guid": "{B}", "index": 7,
         "mac": "3c:58:c2:11:22:34", "mtu": 1500, "if_type": 6, "up": False,
         "addresses": [], "gateways": ["10.0.0.1"], "dns": ["10.0.0.53"]},
    ]
    found = netif.windows_interfaces(adapters)
    wifi = next(i for i in found if i["name"] == "Wi-Fi")
    assert wifi["state"] == "UP" and wifi["kind"] == "wireless"
    assert wifi["addresses"][0] == "192.168.1.23/24" and wifi["default_route"]
    assert next(i for i in found if i["name"] == "Ethernet")["state"] != "UP"
    assert netif.windows_gateways(adapters) == ["192.168.1.1"]
    assert "192.168.1.1" in netif.windows_dns(adapters)
    assert "10.0.0.53" not in netif.windows_dns(adapters)
    assert netif.windows_interfaces(None) == []


def _if_row(alias: str, counters: tuple, flags: int = 1, oper: int = 1) -> bytes:
    from netzilla.local import winapi

    row = bytearray(winapi.IF_ROW2_SIZE)
    encoded = alias.encode("utf-16-le")
    row[28:28 + len(encoded)] = encoded
    struct.pack_into("<I", row, 1056, 6)
    row[1060:1066] = bytes.fromhex("3c58c2112233")
    struct.pack_into("<II", row, 1124, 1500, 71)
    row[1152] = flags
    struct.pack_into("<I", row, 1156, oper)
    struct.pack_into("<18Q", row, 1208, *counters)
    return bytes(row)


def test_if_table2_counters_come_back_in_proc_net_dev_terms():
    from netzilla.local import winapi

    numbers = (5000, 40, 2, 1, 3, 0, 0, 77, 0, 9000, 50, 5, 4, 6, 0, 0, 0, 0)
    raw = (_if_row("Wi-Fi", numbers)
           + _if_row("Wi-Fi-QoS Packet Scheduler-0000", numbers, flags=3)
           + _if_row("Ethernet", (0,) * 18, oper=2))
    table = winapi.parse_if_table2(raw, 3)
    assert set(table) == {"Wi-Fi", "Ethernet"}             # filter drivers skipped
    wifi = table["Wi-Fi"]
    assert wifi["mac"] == "3c:58:c2:11:22:33" and wifi["mtu"] == 1500 and wifi["up"]
    counters = wifi["counters"]
    assert counters["rx_bytes"] == 5000 and counters["rx_packets"] == 42
    assert counters["rx_errs"] == 3 and counters["rx_drop"] == 1
    assert counters["tx_bytes"] == 9000 and counters["tx_packets"] == 55
    assert counters["tx_errs"] == 6 and counters["tx_drop"] == 4
    assert not table["Ethernet"]["up"]


def test_tcp_and_udp_tables_become_connection_records():
    import socket

    from netzilla.local import winapi

    def port(n):
        return struct.pack(">H", n) + b"\x00\x00"

    tcp = struct.pack("<I", 2)
    tcp += struct.pack("<I", 5) + socket.inet_aton("192.168.1.23") + port(52345) \
        + socket.inet_aton("142.250.72.14") + port(443) + struct.pack("<I", 5678)
    tcp += struct.pack("<I", 2) + socket.inet_aton("0.0.0.0") + port(135) \
        + socket.inet_aton("0.0.0.0") + port(0) + struct.pack("<I", 1234)
    rows = winapi.parse_tcp_table(tcp)
    assert rows[0] == {"proto": "tcp", "local_ip": "192.168.1.23", "local_port": 52345,
                       "remote_ip": "142.250.72.14", "remote_port": 443,
                       "state": "ESTAB", "process": "", "pid": 5678}
    assert rows[1]["state"] == "LISTEN" and rows[1]["remote_ip"] == ""
    udp = struct.pack("<I", 1) + socket.inet_aton("0.0.0.0") + port(5353) + struct.pack("<I", 99)
    assert winapi.parse_udp_table(udp)[0]["local_port"] == 5353
    assert winapi.parse_tcp_table(tcp[:30]) == rows[:1]          # cut short: no crash


def test_netstat_ano_is_read_in_any_language():
    from netzilla.local import flows

    english = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
  TCP    192.168.1.23:52345     142.250.72.14:443      ESTABLISHED     5678
  TCP    [2001:db8::5]:50000    [2606:4700::1111]:443  TIME_WAIT       0
  UDP    0.0.0.0:5353           *:*                                    2345
"""
    rows = flows.parse_netstat_windows(english)
    assert [r["proto"] for r in rows] == ["tcp", "tcp", "tcp", "udp"]
    assert rows[1]["remote_ip"] == "142.250.72.14" and rows[1]["pid"] == 5678
    assert rows[1]["state"] == "ESTAB" and rows[0]["state"] == "LISTEN"
    assert rows[2]["local_ip"] == "2001:db8::5" and rows[2]["remote_port"] == 443
    assert rows[3]["local_port"] == 5353 and rows[3]["state"] == "UNCONN"
    german = """
  Proto  Lokale Adresse         Remoteadresse          Status           PID
  TCP    0.0.0.0:135            0.0.0.0:0              ABHÖREN         1234
  TCP    192.168.1.23:52345     142.250.72.14:443      HERGESTELLT     5678
"""
    states = [r["state"] for r in flows.parse_netstat_windows(german)]
    assert states == ["LISTEN", "ESTAB"]


def test_windows_ping_is_read_in_any_language(windows):
    from netzilla.local import lan, netdiag

    english = """
Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=11ms TTL=57
Reply from 1.1.1.1: bytes=32 time=13ms TTL=57
Request timed out.
Reply from 1.1.1.1: bytes=32 time=12ms TTL=57

Ping statistics for 1.1.1.1:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
Approximate round trip times in milli-seconds:
    Minimum = 11ms, Maximum = 13ms, Average = 12ms
"""
    stats = netdiag.parse_ping(english)
    assert (stats["tx"], stats["rx"], stats["loss"]) == ("4", "3", "25")
    assert (stats["rtt_min"], stats["rtt_avg"], stats["rtt_max"]) == ("11", "12", "13")
    assert float(stats["rtt_mdev"]) == pytest.approx(0.816, abs=0.01)
    german = english.replace("Packets: Sent", "Pakete: Gesendet").replace(
        "Received", "Empfangen").replace("Lost", "Verloren").replace("loss", "Verlust")
    assert netdiag.parse_ping(german)["loss"] == "25"
    assert lan.read_reply("Reply from 192.168.1.1: bytes=32 time<1ms TTL=64") == (1.0, 64)
    assert lan.read_reply("Reply from 192.168.1.23: Destination host unreachable.") == (None, None)


def test_windows_arp_table_lists_devices_only():
    from netzilla.local import lan

    table = lan.parse_arp_windows("""
Interface: 192.168.1.23 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           a4-2b-b0-12-34-56     dynamic
  192.168.1.40          3c-58-c2-01-22-33     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
""")
    assert table == {"192.168.1.1": "a4:2b:b0:12:34:56", "192.168.1.40": "3c:58:c2:01:22:33"}


def test_dup_ip_watch_reads_both_arpings():
    from netzilla.local import arpwatch, lan

    iputils = """ARPING 192.168.1.1 from 192.168.1.23 eth0
Unicast reply from 192.168.1.1 [A4:2B:B0:12:34:56]  1.204ms
Sent 1 probes (1 broadcast(s))
Received 1 response(s)"""
    # Thomas Habets' arping, the one Homebrew installs on macOS.
    habets = """ARPING 192.168.1.1
60 bytes from a4:2b:b0:12:34:56 (192.168.1.1): index=0 time=1.338 msec
60 bytes from 3c:58:c2:01:22:33 (192.168.1.1): index=1 time=2.017 msec

--- 192.168.1.1 statistics ---
1 packets transmitted, 2 packets received,   0% unanswered (1 extra)"""
    assert arpwatch.parse_arping(iputils) == ["a4:2b:b0:12:34:56"]
    assert arpwatch.parse_arping(habets) == ["a4:2b:b0:12:34:56", "3c:58:c2:01:22:33"]
    assert arpwatch.parse_arping("arping: socket: Operation not permitted") == []
    # macOS's arp -an drops leading zeros, and lists broadcast entries too.
    assert lan._parse_arp_a(
        "? (192.168.1.1) at a4:2b:b0:12:34:5 on en0 ifscope [ethernet]\n"
        "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
        "? (192.168.1.77) at (incomplete) on en0 ifscope [ethernet]\n"
    ) == {"192.168.1.1": "a4:2b:b0:12:34:05"}


def test_each_system_gets_its_own_ping_traceroute_and_mtr(monkeypatch):
    from netzilla.local import mtu, netdiag

    monkeypatch.setattr(hostos, "NAME", hostos.WINDOWS)
    assert netdiag.ping_argv("1.1.1.1", 4) == ["ping", "-n", "4", "-w", "2000", "1.1.1.1"]
    assert netdiag.traceroute_tool() == "tracert" and netdiag.mtr_tool() == "pathping"
    assert mtu.df_ping_argv("1.1.1.1", 1472)[:5] == ["ping", "-f", "-l", "1472", "-n"]
    assert mtu.got_through("Reply from 1.1.1.1: bytes=1472 time=12ms TTL=57")
    assert not mtu.got_through("Packet needs to be fragmented but DF set.")
    assert "pathping" in netdiag.tool_names() and "mtr" not in netdiag.tool_names()
    monkeypatch.setattr(hostos, "NAME", hostos.MACOS)
    assert netdiag.ping_argv("1.1.1.1", 4) == ["ping", "-c", "4", "-W", "2000", "1.1.1.1"]
    assert netdiag.ping_argv("2606:4700::1111", 2)[0] == "ping6"
    assert mtu.df_ping_argv("1.1.1.1", 1472)[:4] == ["ping", "-D", "-s", "1472"]
    assert mtu.df_ping_label() == "ping -D -s"
    monkeypatch.setattr(hostos, "NAME", hostos.LINUX)
    assert mtu.df_ping_label() == "ping -M do"
    assert netdiag.ping_argv("1.1.1.1", 4) == ["ping", "-c", "4", "-W", "2", "1.1.1.1"]


def test_homebrews_mtr_asking_for_root_is_recognised(macos):
    from netzilla.local import netdiag
    from netzilla.local.runner import CommandResult

    refused = CommandResult(False, "", "mtr-packet: Failure to open IPv4 sockets: Permission denied")
    assert netdiag.mtr_needs_root(refused)
    assert not netdiag.mtr_needs_root(CommandResult(True, "HOST: x  Loss%", ""))


def test_windows_names_its_release_by_build():
    from netzilla.local import sysinfo

    assert sysinfo.windows_name("10", "10.0.22631", "Professional").startswith("Windows 11")
    assert "22631" in sysinfo.windows_name("10", "10.0.22631")
    assert sysinfo.windows_name("10", "10.0.19045").startswith("Windows 10")


# ================================================= Windows: Native Wi-Fi API
class _BSS(ctypes.Structure):
    _fields_ = [
        ("uSSIDLength", ctypes.c_uint32), ("ucSSID", ctypes.c_ubyte * 32),
        ("uPhyId", ctypes.c_uint32), ("dot11Bssid", ctypes.c_ubyte * 6),
        ("dot11BssType", ctypes.c_uint32), ("dot11BssPhyType", ctypes.c_uint32),
        ("lRssi", ctypes.c_int32), ("uLinkQuality", ctypes.c_uint32),
        ("bInRegDomain", ctypes.c_ubyte), ("usBeaconPeriod", ctypes.c_uint16),
        ("ullTimestamp", ctypes.c_uint64), ("ullHostTimestamp", ctypes.c_uint64),
        ("usCapabilityInformation", ctypes.c_uint16),
        ("ulChCenterFrequency", ctypes.c_uint32), ("uRateSetLength", ctypes.c_uint32),
        ("usRateSet", ctypes.c_uint16 * 126), ("ulIeOffset", ctypes.c_uint32),
        ("ulIeSize", ctypes.c_uint32),
    ]


class _CONNECTION(ctypes.Structure):
    _fields_ = [
        ("isState", ctypes.c_uint32), ("wlanConnectionMode", ctypes.c_uint32),
        ("strProfileName", ctypes.c_uint16 * 256), ("uSSIDLength", ctypes.c_uint32),
        ("ucSSID", ctypes.c_ubyte * 32), ("dot11BssType", ctypes.c_uint32),
        ("dot11Bssid", ctypes.c_ubyte * 6), ("dot11PhyType", ctypes.c_uint32),
        ("uDot11PhyIndex", ctypes.c_uint32), ("wlanSignalQuality", ctypes.c_uint32),
        ("ulRxRate", ctypes.c_uint32), ("ulTxRate", ctypes.c_uint32),
        ("bSecurityEnabled", ctypes.c_int32), ("bOneXEnabled", ctypes.c_int32),
        ("dot11AuthAlgorithm", ctypes.c_uint32), ("dot11CipherAlgorithm", ctypes.c_uint32),
    ]


def test_wlan_structure_layouts_match_windows():
    """The byte offsets wlanapi reads at are where Windows puts the fields."""
    from netzilla.local import wlanapi

    assert ctypes.sizeof(_BSS) == wlanapi.BSS_ENTRY_SIZE == 360
    assert {n: getattr(_BSS, n).offset for n, _ in _BSS._fields_} == wlanapi.BSS_OFFSETS
    assert ctypes.sizeof(_CONNECTION) == wlanapi.CONNECTION_SIZE == 604
    assert ({n: getattr(_CONNECTION, n).offset for n, _ in _CONNECTION._fields_}
            == wlanapi.CONNECTION_OFFSETS)


def _ie(tag: int, body: bytes) -> bytes:
    return bytes([tag, len(body)]) + body


def _bss_list(now: int) -> bytes:
    rsn = (struct.pack("<H", 1) + b"\x00\x0f\xac\x04" + struct.pack("<H", 1)
           + b"\x00\x0f\xac\x04" + struct.pack("<H", 2) + b"\x00\x0f\xac\x02"
           + b"\x00\x0f\xac\x08" + b"\x00\x00")
    blobs = [
        _ie(0, b"Home") + _ie(3, bytes([6])) + _ie(48, rsn) + _ie(61, bytes([6, 0x05]) + bytes(20)),
        _ie(0, b"") + _ie(61, bytes([36, 0x05]) + bytes(20)) + _ie(192, bytes([1, 42, 0]) + bytes(2)),
    ]
    entries = [
        (b"Home", "a42bb0123456", -48, 100, 2437000, 0x0411, 7,
         [0x8002, 0x8004, 0x800B, 0x8016, 0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C]),
        (b"", "a42bb0123457", -71, 58, 5180000, 0x0001, 8,
         [0x800C, 0x12, 0x8018, 0x24, 0x8030, 0x48, 0x60, 0x6C]),
    ]
    head = 8 + len(entries) * 360
    raw, area = bytearray(head), b""
    for index, (ssid, mac, rssi, quality, freq, cap, phy, rates) in enumerate(entries):
        entry = _BSS(uSSIDLength=len(ssid), dot11BssType=1, dot11BssPhyType=phy,
                     lRssi=rssi, uLinkQuality=quality, ullHostTimestamp=now - 1500 * 10000,
                     usCapabilityInformation=cap, ulChCenterFrequency=freq,
                     uRateSetLength=len(rates))
        entry.ucSSID[:len(ssid)] = list(ssid)
        entry.dot11Bssid[:] = list(bytes.fromhex(mac))
        for k, rate in enumerate(rates):
            entry.usRateSet[k] = rate
        at = 8 + index * 360
        entry.ulIeOffset = head + len(area) - at
        entry.ulIeSize = len(blobs[index])
        area += blobs[index]
        raw[at:at + 360] = bytes(entry)
    raw[:8] = struct.pack("<II", head + len(area), len(entries))
    return bytes(raw) + area


def test_bss_list_gives_exact_signal_security_and_width():
    from netzilla.local import wlanapi

    now = wlanapi.filetime_now()
    home, hidden = wlanapi.parse_bss_list(_bss_list(now), now)
    assert home["ssid"] == "Home" and home["bssid"] == "a4:2b:b0:12:34:56"
    assert home["rssi"] == -48 and home["channel"] == 6 and home["freq_mhz"] == 2437
    assert home["security"] == "WPA3"                    # SAE beside PSK, as iw reads it
    assert home["rate_mbps"] == 54 and home["width_mhz"] == 40
    assert 1400 <= home["age_ms"] <= 2500
    assert hidden["ssid"] == "" and hidden["channel"] == 36
    assert hidden["width_mhz"] == 80 and hidden["centre_channel"] == 42
    assert wlanapi.parse_bss_list(b"\x00" * 4, now) == []               # too short
    broken = bytearray(_bss_list(now))
    struct.pack_into("<I", broken, 8 + wlanapi.BSS_OFFSETS["ulIeOffset"], 0xFFFFFF)
    assert len(wlanapi.parse_bss_list(bytes(broken), now)) == 2         # bad IEs ignored


def test_connection_attributes_name_the_joined_network():
    from netzilla.local import wlanapi

    attrs = _CONNECTION(isState=1, uSSIDLength=4, dot11PhyType=10, wlanSignalQuality=90,
                        ulRxRate=866700, ulTxRate=433300, bSecurityEnabled=1,
                        dot11AuthAlgorithm=7, dot11CipherAlgorithm=4)
    for k, char in enumerate("Home"):
        attrs.strProfileName[k] = ord(char)
    attrs.ucSSID[:4] = list(b"Home")
    attrs.dot11Bssid[:] = list(bytes.fromhex("a42bb0123456"))
    link = wlanapi.parse_connection(bytes(attrs))
    assert link["ssid"] == "Home" and link["bssid"] == "a4:2b:b0:12:34:56"
    assert link["connected"] and link["quality"] == 90
    assert link["rx_bitrate"] == pytest.approx(866.7)
    assert link["tx_bitrate"] == pytest.approx(433.3)
    assert "WPA2" in link["security"]


def test_wlan_api_is_absent_rather_than_broken_off_windows():
    from netzilla.local import wlanapi

    assert wlanapi.available() is False
    names, error = wlanapi.interfaces()
    assert names == [] and error
    assert wlanapi.request_scan("Wi-Fi") is False


# =========================================================== netsh
NETSH_NETWORKS = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : a4:2b:b0:12:34:56
         Signal             : 92%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 44
         Basic rates (Mbps) : 6 12 24
         Other rates (Mbps) : 9 18 36 48 54
    BSSID 2                 : a4:2b:b0:12:34:57
         Signal             : 70%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6
         Basic rates (Mbps) : 1 2 5.5 11
         Other rates (Mbps) : 6 9 12 18 24 36 48 54

SSID 2 : Office: Guest
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 10:20:30:40:50:61
         Signal             : 31%
         Radio type         : 802.11ax
         Band               : 6 GHz
         Channel            : 37
"""


def test_netsh_networks_are_read_by_shape_not_by_label():
    from netzilla.local import wifi

    aps = wifi.parse_netsh_networks(NETSH_NETWORKS)
    assert [ap["bssid"] for ap in aps] == [                  # as nmcli and iw give them
        "A4:2B:B0:12:34:56", "A4:2B:B0:12:34:57", "10:20:30:40:50:61"]
    first = aps[0]
    assert first["ssid"] == "HomeNet" and first["channel"] == 44 and first["band"] == "5 GHz"
    assert first["signal_pct"] == 92 and first["rate_mbps"] == 54
    assert first["security"] == "WPA2"
    assert aps[1]["band"] == "2.4 GHz" and aps[1]["freq_mhz"] == 2437
    guest = aps[2]
    assert guest["ssid"] == "Office: Guest" and guest["security"] == "Open"
    assert guest["band"] == "6 GHz" and guest["freq_mhz"] == 6135
    german = """
SSID 1 : Zuhause
    Netzwerktyp             : Infrastruktur
    Authentifizierung       : WPA2-Personal
    Verschlüsselung         : CCMP
    BSSID 1                 : a4:2b:b0:12:34:56
         Signal             : 88%
         Funktyp            : 802.11ac
         Kanal              : 36
"""
    (ap,) = wifi.parse_netsh_networks(german)
    assert (ap["ssid"], ap["channel"], ap["signal_pct"]) == ("Zuhause", 36, 88)


def test_netsh_interfaces_and_the_location_refusal():
    from netzilla.local import wifi, wifitools

    shown = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 6f3d5b32-1a2b-4c3d-8e9f-0a1b2c3d4e5f
    Physical address       : 3c:58:c2:11:22:33
    State                  : connected
    SSID                   : HomeNet
    AP BSSID               : a4:2b:b0:12:34:56
    Channel                : 44
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 864.5
    Signal                 : 96%
    Rssi                   : -43
    Profile                : HomeNet
"""
    (adapter,) = wifi.parse_netsh_interfaces(shown)
    assert adapter["name"] == "Wi-Fi" and adapter["mac"] == "3c:58:c2:11:22:33"
    link = wifitools.netsh_link(adapter)
    assert link["connected"] and link["ssid"] == "HomeNet" and link["signal_dbm"] == -43
    assert link["rx_bitrate"] == pytest.approx(1201) and link["tx_bitrate"] == pytest.approx(864.5)
    refusal = ("Network shell commands need location permission to access WLAN information. "
               "Turn on Location services on the Location page in Privacy & security settings.")
    assert wifi.parse_netsh_networks(refusal) == []
    assert "Location" in wifi.netsh_problem(refusal)


def test_windows_scan_falls_back_to_netsh_and_explains_location(windows, monkeypatch):
    from netzilla.local import wifi
    from netzilla.local.runner import CommandResult

    monkeypatch.setattr(wifi, "WINDOWS_SCAN_WAIT", 0)
    monkeypatch.setattr(wifi.wlanapi, "available", lambda: False)
    monkeypatch.setattr(wifi, "have", lambda tool: tool == "netsh")

    async def fake_run(argv, **_kw):
        return CommandResult(True, NETSH_NETWORKS, "", " ".join(argv))

    monkeypatch.setattr(wifi, "run", fake_run)
    aps, used, error = asyncio.run(wifi.scan("Wi-Fi"))
    assert used == "netsh" and len(aps) == 3 and not error

    async def refused(argv, **_kw):
        return CommandResult(False, "", "Network shell commands need location permission "
                             "to access WLAN information.", " ".join(argv))

    monkeypatch.setattr(wifi, "run", refused)
    aps, used, error = asyncio.run(wifi.scan("Wi-Fi"))
    assert aps == [] and "Location" in error


# ============================================================ macOS
AIRPORT_SCAN = """                            SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
                       Cafe -55 0:1b:2c:3d:4e:5f -61  149,+1  Y  US WPA2(PSK/AES/AES)
                        Neighbor 11:22:33:44:55:66 -80  6       Y  -- WPA(PSK/TKIP/TKIP) WPA2(PSK/AES/TKIP)
                                 22:33:44:55:66:77 -90  11      Y  -- NONE
                          Corp 22:33:44:55:66:78 -70  36,80   Y  US WPA2(802.1x/AES/AES)
"""

SYSTEM_PROFILER = {"SPAirPortDataType": [{"spairport_airport_interfaces": [
    {"_name": "en0",
     "spairport_current_network_information": {
         "_name": "HomeNet", "spairport_network_channel": "149 (5GHz, 80MHz)",
         "spairport_network_phymode": "802.11ac", "spairport_network_rate": 867,
         "spairport_security_mode": "spairport_security_mode_wpa2_personal",
         "spairport_signal_noise": "-52 dBm / -93 dBm"},
     "spairport_airport_other_local_wireless_networks": [
         {"_name": "Neighbor", "spairport_network_channel": "6 (2GHz, 20MHz)",
          "spairport_security_mode": "spairport_security_mode_wpa3_transition",
          "spairport_signal_noise": "-70 dBm / -95 dBm"},
         {"_name": "Six", "spairport_network_channel": "37 (6GHz, 160MHz)",
          "spairport_security_mode": "spairport_security_mode_wpa3_personal",
          "spairport_signal_noise": "-75 dBm / -95 dBm"},
         {"_name": "Free", "spairport_network_channel": "11 (2GHz, 40MHz)",
          "spairport_security_mode": "spairport_security_mode_none",
          "spairport_signal_noise": "-85 dBm / -95 dBm"}],
     "spairport_status_information": "spairport_status_connected",
     "spairport_wireless_mac_address": "3C:58:C2:11:22:33"},
    {"_name": "awdl0", "spairport_status_information": "spairport_status_connected"}]}]}


def test_airport_scan_rows_keep_names_with_spaces_and_hidden_networks():
    from netzilla.local import wifi

    aps = wifi.parse_airport_scan(AIRPORT_SCAN)
    assert [ap["ssid"] for ap in aps] == ["Cafe -55", "Neighbor", "<hidden>", "Corp"]
    cafe = aps[0]
    assert cafe["bssid"] == "00:1B:2C:3D:4E:5F" and cafe["signal_dbm"] == -61
    assert cafe["channel"] == 149 and cafe["width_mhz"] == 40 and cafe["centre_channel"] == 151
    assert aps[2]["bssid"] == "22:33:44:55:66:77" and aps[2]["security"] == "Open"
    assert aps[3]["width_mhz"] == 80 and aps[3]["security"].startswith("WPA2")
    assert wifi.parse_channel_spec("6,-1") == (6, 40, 4)


def test_system_profiler_lists_networks_without_bssids():
    from netzilla.local import wifi, wifitools

    (entry,) = wifi.parse_system_profiler(json.dumps(SYSTEM_PROFILER))
    assert entry["name"] == "en0" and entry["mac"] == "3c:58:c2:11:22:33"
    names = [n["ssid"] for n in entry["networks"]]
    assert names[0] == "HomeNet" and set(names) == {"HomeNet", "Neighbor", "Six", "Free"}
    home = entry["networks"][0]
    assert home["in_use"] and home["channel"] == 149 and home["band"] == "5 GHz"
    assert home["signal_dbm"] == -52 and home["noise_dbm"] == -93
    assert home["width_mhz"] == 80 and home["centre_channel"] == 155
    six = next(n for n in entry["networks"] if n["ssid"] == "Six")
    assert six["band"] == "6 GHz" and six["freq_mhz"] == 6135 and six["centre_channel"] == 47
    assert next(n for n in entry["networks"] if n["ssid"] == "Free")["security"] == "Open"
    link = wifitools.macos_link(entry)
    assert link["connected"] and link["ssid"] == "HomeNet" and link["signal_dbm"] == -52
    assert wifi.parse_system_profiler("not json") == []


def test_airport_info_reads_as_a_link():
    from netzilla.local import wifitools

    link = wifitools.parse_airport_info("""     agrCtlRSSI: -52
    agrCtlNoise: -93
          state: running
     lastTxRate: 867
      link auth: wpa2-psk
          BSSID: 0:1b:2c:3d:4e:5f
           SSID: Cafe -55
        channel: 149,80
""")
    assert link["connected"] and link["bssid"] == "00:1b:2c:3d:4e:5f"
    assert link["ssid"] == "Cafe -55" and link["signal_dbm"] == -52 and link["noise_dbm"] == -93
    assert link["tx_bitrate"] == 867 and link["channel"] == 149 and link["width"] == "80 MHz"
    assert wifitools.parse_airport_info("AirPort: Off") == {"connected": False}


def test_a_retired_airport_is_not_asked_again(macos, monkeypatch):
    from netzilla.local import wifi

    monkeypatch.setattr(wifi, "_airport", {"retired": False})
    monkeypatch.setattr(wifi, "have", lambda tool: tool == wifi.AIRPORT)
    assert wifi.airport_usable()
    wifi.note_airport("AirPort: Off", False)
    assert wifi.airport_usable()
    wifi.note_airport("WARNING: The airport command line tool is deprecated and will be "
                      "removed in a future release.", False)
    assert not wifi.airport_usable()


def test_macos_ifconfig_route_and_ports():
    from netzilla.local import netif

    found = netif.parse_ifconfig_bsd("""lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 3c:58:c2:1:22:33
\tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
\tstatus: active
en5: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
\tether ae:de:48:00:11:22
\tstatus: inactive
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 10.8.0.2 --> 10.8.0.1 netmask 0xffffffff
""")
    by_name = {i["name"]: i for i in found}
    assert by_name["lo0"]["kind"] == "loopback"
    en0 = by_name["en0"]
    assert en0["state"] == "UP" and en0["mtu"] == "1500" and en0["mac"] == "3c:58:c2:01:22:33"
    assert "192.168.1.23/24" in en0["addresses"]
    assert by_name["en5"]["state"] != "UP"
    assert "10.8.0.2/32" in by_name["utun3"]["addresses"]
    assert netif.parse_route_get("""   route to: default
destination: default
    gateway: 192.168.1.1
  interface: en0
""") == {"gateway": "192.168.1.1", "interface": "en0"}
    ports = netif.parse_hardware_ports("""
Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 3c:58:c2:01:22:33

Hardware Port: Thunderbolt Bridge
Device: bridge0
""")
    assert ports == {"en0": "Wi-Fi", "bridge0": "Thunderbolt Bridge"}
    assert netif.port_kind("Wi-Fi") == "wireless"


def test_netstat_ib_counters_in_proc_net_dev_terms():
    from netzilla.local import netif

    counters = netif.parse_netstat_ib("""Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0        16384 <Link#1>                        123456     0   98765432   123456     0   98765432     0
lo0        16384 127           127.0.0.1         123456     -   98765432   123456     -   98765432     -
en0        1500  <Link#11>   3c:58:c2:01:22:33  5432100     2 6543210987  3210000     0  456789012     0
en0        1500  192.168.1     192.168.1.23     5432100     -  6543210987  3210000     -  456789012     -
en5*       1500  <Link#12>   ae:de:48:00:11:22        0     0          0        0     0          0     0
""")
    assert set(counters) == {"lo0", "en0", "en5"}
    en0 = counters["en0"]
    assert en0["rx_packets"] == 5432100 and en0["rx_errs"] == 2 and en0["rx_bytes"] == 6543210987
    assert en0["tx_packets"] == 3210000 and en0["tx_bytes"] == 456789012


def test_macos_uptime_and_memory():
    from netzilla.local import sysinfo

    up = sysinfo.parse_boottime("{ sec = 1732600000, usec = 0 } Tue Nov 26 08:26:40 2024",
                                now=1732603600.0)
    assert up == pytest.approx(3600.0)
    assert sysinfo.parse_boottime("garbage") is None
    total = 16 * 1024 ** 3
    used, all_of_it = sysinfo.parse_vm_stat("""Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                               12345.
Pages active:                            234567.
Pages inactive:                          223456.
Pages speculative:                         3456.
Pages wired down:                         98765.
Pages purgeable:                           4567.
""", total)
    assert all_of_it == total
    assert used == total - (12345 + 223456 + 3456 + 4567) * 16384


def test_macos_sockets_from_netstat_and_their_programs_from_lsof():
    from netzilla.local import flows

    sockets = flows.parse_netstat_bsd("""Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.1.23.52345     142.250.72.14.443      ESTABLISHED
tcp6       0      0  2001:db8::5.50000      2606:4700::1111.22     ESTABLISHED
tcp4       0      0  *.22                   *.*                    LISTEN
udp4       0      0  *.5353                 *.*
""")
    assert [s["proto"] for s in sockets] == ["tcp", "tcp", "tcp", "udp"]
    assert (sockets[0]["local_ip"], sockets[0]["local_port"]) == ("192.168.1.23", 52345)
    assert (sockets[0]["remote_ip"], sockets[0]["remote_port"]) == ("142.250.72.14", 443)
    assert sockets[1]["remote_ip"] == "2606:4700::1111" and sockets[1]["remote_port"] == 22
    assert sockets[2]["state"] == "LISTEN" and sockets[2]["local_port"] == 22
    owned = flows.parse_lsof("""p512
cSafari
f23
PTCP
n192.168.1.23:52345->142.250.72.14:443
TST=ESTABLISHED
TQR=0
f24
PUDP
n*:5353
p700
cssh
f3
PTCP
n[2001:db8::5]:50000->[2606:4700::1111]:22
TST=ESTABLISHED
""")
    assert [(o["process"], o["pid"]) for o in owned] == [("Safari", 512), ("Safari", 512),
                                                          ("ssh", 700)]
    assert owned[0]["state"] == "ESTAB" and owned[1]["state"] == "UNCONN"
    merged = flows.with_processes(sockets, owned)
    assert merged[0]["process"] == "Safari" and merged[1]["process"] == "ssh"
    assert merged[2]["process"] == ""


def test_macos_bluetooth_controller():
    from netzilla.local import bluetooth

    report = json.dumps({"SPBluetoothDataType": [{"controller_properties": {
        "controller_address": "3C:58:C2:01:22:33", "controller_chipset": "BCM_4387",
        "controller_state": "attrib_on"}}]})
    assert bluetooth.parse_sp_bluetooth(report) == {
        "on": True, "address": "3C:58:C2:01:22:33", "chipset": "BCM_4387"}
    assert bluetooth.parse_sp_bluetooth("{}") == {}


# ================================================= channels (all systems)
@pytest.mark.parametrize("freq, channel", [
    (2412, 1), (2437, 6), (2484, 14), (5180, 36), (5825, 165),
    (5935, 2), (5955, 1), (6135, 37), (6415, 93), (7115, 233),
])
def test_channels_including_six_gigahertz(freq, channel):
    from netzilla.local import wifi

    assert wifi.channel_of(freq) == channel
    band = "6 GHz" if freq > 5925 else ""
    assert wifi.freq_for(channel, band) == freq


def test_centre_channels_from_primary_and_width():
    from netzilla.local import wifi

    assert wifi.centre_channel(36, 80, "5 GHz") == 42
    assert wifi.centre_channel(149, 80, "5 GHz") == 155
    assert wifi.centre_channel(100, 160, "5 GHz") == 114
    assert wifi.centre_channel(37, 160, "6 GHz") == 47
    assert wifi.centre_channel(6, 20, "2.4 GHz") == 6


# ======================================================= WHOIS and TLS
def test_whois_referrals_are_followed_from_iana():
    from netzilla.local import dns_whois

    answers = {
        "whois.iana.org": "domain: COM\nrefer: whois.verisign-grs.com\n",
        "whois.verisign-grs.com": "Domain Name: EXAMPLE.COM\n"
                                  "Registrar WHOIS Server: whois.example-registrar.com\n",
        "whois.example-registrar.com": "Domain Name: example.com\nRegistrar: Example\n",
    }
    asked_with = []

    def ask(server, query, timeout):
        asked_with.append((server, query))
        return answers[server]

    text, asked, error = dns_whois.whois_chain("example.com", ask)
    assert asked == ["whois.iana.org", "whois.verisign-grs.com", "whois.example-registrar.com"]
    assert not error and "EXAMPLE.COM" in text and "Registrar: Example" in text
    assert "refer:" not in text                           # IANA's own answer is dropped
    assert all(query == "example.com" for _, query in asked_with)
    assert dns_whois.whois_referral("ReferralServer: whois://whois.ripe.net:43") == "whois.ripe.net"
    assert dns_whois.whois_referral("refer: whois.iana.org", "whois.iana.org") == ""


def test_whois_stops_on_loops_and_says_when_nobody_answers():
    from netzilla.local import dns_whois

    calls = []

    def looping(server, query, timeout):
        calls.append(server)
        return "refer: whois.a.example\n" if server != "whois.a.example" else "refer: whois.iana.org\n"

    dns_whois.whois_chain("x.example", looping)
    assert calls == ["whois.iana.org", "whois.a.example"]

    def down(server, query, timeout):
        raise OSError(111, "Connection refused")

    text, asked, error = dns_whois.whois_chain("example.com", down)
    assert text == "" and asked == [] and "whois.iana.org did not answer" in error


def test_whois_without_the_program_uses_the_built_in_client(monkeypatch):
    from netzilla.local import dns_whois

    monkeypatch.setattr(dns_whois, "have", lambda tool: False)
    monkeypatch.setattr(dns_whois, "whois_chain",
                        lambda target, ask, timeout: ("Domain Name: EXAMPLE.COM",
                                                      ["whois.iana.org", "whois.verisign-grs.com"], ""))
    result = asyncio.run(dns_whois.whois("example.com"))
    assert result.ok and result.output == "Domain Name: EXAMPLE.COM"
    assert result.command == "whois (built in) via whois.iana.org → whois.verisign-grs.com"


def test_tls_handshake_without_openssl_reads_like_it():
    from netzilla.local import tls_quick

    text = tls_quick.handshake_text({
        "protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "cipher_bits": 128,
        "subject_cn": "example.com", "issuer_cn": "R11", "issuer_o": "Let's Encrypt",
        "not_after": "2026-12-31", "verified": True,
    })
    assert "Protocol version: TLSv1.3" in text
    assert "Ciphersuite: TLS_AES_128_GCM_SHA256 (128 bits)" in text
    assert "Issuer: CN=R11, O=Let's Encrypt" in text and "Verification: OK" in text
    assert tls_quick.handshake_text({"error": "Connection refused"}) == "Connection refused"
    pem = "a\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\nb"
    assert "MIIB" not in tls_quick.without_pem(pem) and "b" in tls_quick.without_pem(pem)


def test_libressl_without_brief_is_asked_for_its_full_report(monkeypatch):
    from netzilla.local import tls_quick
    from netzilla.local.runner import CommandResult

    seen = []

    async def fake_run(argv, **kwargs):
        seen.append((argv, kwargs.get("stdin_text")))
        if "-brief" in argv:
            return CommandResult(False, "", "s_client: Unknown option: -brief", " ".join(argv))
        return CommandResult(True, "CONNECTED(00000003)\n-----BEGIN CERTIFICATE-----\nMIIB\n"
                             "-----END CERTIFICATE-----\nProtocol  : TLSv1.3", "", " ".join(argv))

    monkeypatch.setattr(tls_quick, "run", fake_run)
    result = asyncio.run(tls_quick.openssl_probe("example.com"))
    assert result.ok and "Protocol  : TLSv1.3" in result.output and "MIIB" not in result.output
    assert "-brief" not in seen[1][0] and all(stdin == "" for _, stdin in seen)


# ==================================================== capture permission
def test_npcap_and_bpf_access_are_found(monkeypatch, tmp_path):
    from netzilla.local import capture

    root = tmp_path / "Windows"
    assert not capture.npcap_installed({"SystemRoot": str(root)})
    (root / "System32" / "Npcap").mkdir(parents=True)
    (root / "System32" / "Npcap" / "wpcap.dll").write_bytes(b"MZ")
    assert capture.npcap_installed({"SystemRoot": str(root)})
    dev = tmp_path / "dev"
    dev.mkdir()
    assert not capture.bpf_readable(str(dev))
    (dev / "bpf0").write_bytes(b"")
    assert capture.bpf_readable(str(dev))


def test_capture_permission_on_windows_and_macos(monkeypatch):
    from netzilla.local import capture

    monkeypatch.setattr(hostos, "NAME", hostos.WINDOWS)
    monkeypatch.setattr(capture, "npcap_installed", lambda env=None: True)
    monkeypatch.setattr(capture, "npcap_admin_only", lambda: False)
    prefix, rows = asyncio.run(capture._permission_report())
    assert prefix == [] and dict(rows)["Capture permission"].startswith("ready")
    monkeypatch.setattr(capture, "npcap_installed", lambda env=None: False)
    prefix, rows = asyncio.run(capture._permission_report())
    assert prefix is None and "Npcap" in dict(rows)["Capture permission"]
    assert capture.fix_command()[0] is None and "Npcap" in capture.setup_steps()

    monkeypatch.setattr(hostos, "NAME", hostos.MACOS)
    monkeypatch.setattr(capture, "is_root", lambda: False)
    monkeypatch.setattr(capture, "bpf_readable", lambda dev="/dev": True)
    prefix, rows = asyncio.run(capture._permission_report())
    assert prefix == [] and "ChmodBPF" in dict(rows)["Capture permission"]
    assert capture.unlock_instead() and capture.fix_command()[0] is None
    assert "ChmodBPF" in capture.setup_steps()


def test_capture_files_get_names_windows_accepts(windows):
    from netzilla.local import capture

    name = Path(capture.default_pcap_path(r"\Device\NPF_{4D36E972}")).name
    assert not set(name) & set('\\/:*?"<>|') and name.endswith(".pcapng")


def test_iftop_on_macos_runs_as_is_with_chmodbpf(macos, monkeypatch):
    from netzilla.local import bwtools, capture

    monkeypatch.setattr(bwtools, "is_root", lambda: False)
    monkeypatch.setattr(capture, "bpf_readable", lambda dev="/dev": True)
    prefix, why = asyncio.run(bwtools.elevation("iftop"))
    assert prefix == [] and "ChmodBPF" in why
    assert bwtools.install_hint("bmon") == "brew install bmon"
    assert "sudo brew services start vnstat" in bwtools.vnstat_service_hint("Error: unable to open")


# ============================================================ odds and ends
def test_clipboard_text_survives_clip_exe_and_pbcopy():
    from netzilla import clipboard

    payload, env = clipboard.tool_input(["clip.exe"], "a — b")
    assert payload.startswith(b"\xff\xfe") and payload.decode("utf-16") == "a — b"
    assert env is None
    payload, env = clipboard.tool_input(["pbcopy"], "a — b")
    assert payload == "a — b".encode("utf-8") and env["LC_CTYPE"] == "UTF-8"
    assert clipboard.tool_input(["wl-copy"], "x") == (b"x", None)


def test_windows_console_output_never_stops_on_a_character(windows, monkeypatch):
    from netzilla import cli

    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252")
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setattr("sys.stderr", io.TextIOWrapper(io.BytesIO(), encoding="cp1252"))
    cli._safe_streams()
    print("route → ok", file=stream)
    stream.flush()
    assert raw.getvalue().decode("cp1252").strip() == "route ? ok"


def test_syslog_port_refused_on_windows_is_explained(windows, monkeypatch):
    from netzilla.local import syslog

    async def go():
        loop = asyncio.get_running_loop()

        async def refuse(*_args, **_kwargs):
            raise PermissionError(10013, "forbidden")

        monkeypatch.setattr(loop, "create_datagram_endpoint", refuse)
        with pytest.raises(PermissionError) as caught:
            await syslog.SyslogCollector(port=514).start()
        return str(caught.value)

    message = asyncio.run(go())
    assert message.startswith("Windows refused UDP/514") and "sudo" not in message


def test_file_hash_hint_names_each_systems_command(monkeypatch):
    from netzilla.screens import threat_intel

    assert threat_intel._HASH_HINT["windows"] == "On Windows: certutil -hashfile FILE SHA256"
    assert threat_intel._HASH_HINT["macos"] == "On macOS: shasum -a 256 FILE"


# ================================================================== help
def test_help_cards_read_right_on_each_system():
    from netzilla import help as cards

    for system, table in cards.ON_OS.items():
        for (pane, key), fields in table.items():
            assert key in cards.HELP[pane], (system, pane, key)
            card = cards.get_help(pane, key, system)
            for field, value in fields.items():
                if field == "note" and (pane, key) in cards._REFRESH_DEFAULTS:
                    assert card.note.startswith(value) and "REFRESH EVERY" in card.note
                else:
                    assert getattr(card, field) == value
    assert cards.get_help("LANPane", "snmp", "linux") is cards.HELP["LANPane"]["snmp"]
    windows_text = " ".join(
        f"{c.usage} {c.note}" for c in (
            cards.get_help(p, k, "windows") for p, keys in cards.HELP.items() for k in keys))
    for linux_only in ("sudo apt", "setcap", "systemctl", "/proc/net/dev", "nmcli", "usermod"):
        assert linux_only not in windows_text, linux_only
    mac_text = " ".join(
        f"{c.usage} {c.note}" for c in (
            cards.get_help(p, k, "macos") for p, keys in cards.HELP.items() for k in keys))
    for linux_only in ("sudo apt", "setcap", "systemctl", "/proc/net/dev", "nmcli", "usermod"):
        assert linux_only not in mac_text, linux_only


# ============================================== the whole app, as each OS
def _run_app(tmp_path, system, script, monkeypatch):
    from netzilla.app import NetzillaApp

    monkeypatch.setattr(hostos, "NAME", system)

    async def go():
        app = NetzillaApp(config_path=tmp_path / "config.toml", offline=True)
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            return await script(app, pilot)

    return asyncio.run(go())


def _text(pane) -> str:
    from netzilla.clipboard import plain

    return plain([w.content for w in pane.results.children
                  if getattr(w, "content", None)], 160)


# Buttons that answer from this machine alone: no packets leave it.
LOCAL_ACTIONS = {
    "InterfacesPane": ("refresh", "tools"),
    "DiagnosticsPane": ("tools",),
    "WifiPane": ("tools", "scan"),
    "FlowPane": ("tools", "connections"),
    "CapturePane": ("tools", "auth", "fix"),
}


@pytest.mark.parametrize("system", [hostos.WINDOWS, hostos.MACOS])
def test_every_tab_and_tool_check_works_as_each_system(tmp_path, monkeypatch, system):
    from textual.widgets import TabbedContent

    from netzilla.app import TABS

    async def script(app, pilot):
        tabs = app.query_one("#tabs", TabbedContent)
        seen = {}
        for tab_id, _label, pane_class in TABS:
            tabs.active = tab_id
            await pilot.pause()
            assert tabs.active == tab_id
            pane = app.query(pane_class).first()
            for action in LOCAL_ACTIONS.get(pane_class.__name__, ()):
                await pane.execute(action)
                await pilot.pause()
                text = _text(pane)
                assert "Unexpected error" not in text, (system, action, text)
                seen[(pane_class.__name__, action)] = text
                await pane.results.remove_children()
        return seen

    seen = _run_app(tmp_path, system, script, monkeypatch)
    everything = "\n".join(seen.values())
    assert "sudo apt" not in everything and "setcap" not in everything
    if system == hostos.WINDOWS:
        assert "WINDOWS WI-FI API" in seen[("WifiPane", "tools")]
        assert "NPCAP" in seen[("CapturePane", "tools")]
        assert "NOTHING TO UNLOCK ON WINDOWS" in seen[("CapturePane", "auth")]
        assert "pathping" in seen[("DiagnosticsPane", "tools")]
    else:
        assert "SYSTEM_PROFILER" in seen[("WifiPane", "tools")]
        assert "CHMODBPF" in seen[("CapturePane", "tools")]
        assert "brew" in seen[("CapturePane", "fix")]


def test_help_cards_show_the_windows_text_in_the_app(tmp_path, monkeypatch):
    from textual.widgets import TabbedContent

    async def script(app, pilot):
        app.query_one("#tabs", TabbedContent).active = "dns"
        await pilot.pause()
        from netzilla.screens.dns_whois import DNSWhoisPane

        pane = app.query(DNSWhoisPane).first()
        pane.show_help("whois")
        await pilot.pause()
        return pane._help_key, pane.query_one(".action-help").content

    key, content = _run_app(tmp_path, hostos.WINDOWS, script, monkeypatch)
    from netzilla.clipboard import plain

    assert key == "whois" and "Windows has no whois program" in plain([content], 160)
