"""Tests for netzilla 3.1: device identification.

Everywhere netzilla finds a client by IP or MAC it now says what the client
is: the maker (offline IEEE registry, all three block sizes), whether the MAC
is a randomised private address, a hostname from reverse DNS / mDNS /
NetBIOS / UPnP, and a best guess at the kind of device, with the evidence.

The probes send real packets to real LAN addresses, so conftest.py stubs them
out for every test. These tests feed the parsers wire-format replies built
here byte by byte, and drive the pipeline and the panes with recorded answers.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import struct
from pathlib import Path

import pytest
from rich.console import Console

from netzilla import __version__
from netzilla.local import devices, lan, netif, oui
from netzilla.validators import ValidationError

# Sample LAN (10.0.0.0/24): real vendor prefixes, invented device bytes.
SCREENSHOT = {
    "10.0.0.1": "b8:5e:71:a1:b2:c3",
    "10.0.0.9": "9c:37:cb:0d:1e:2f",
    "10.0.0.61": "98:bd:80:3a:4b:5c",
    "10.0.0.185": "52:7a:8b:6d:7e:8f",
    "10.0.0.213": "c6:db:20:9a:ab:bc",
    "10.0.0.217": "0c:dc:91:4c:5d:6e",
    "10.0.0.134": "44:00:49:7f:80:91",
    "10.0.0.145": "ec:31:5f:a2:b3:c4",
}


def text_of(renderable, width: int = 260) -> str:
    console = Console(width=width, record=True, color_system=None)
    console.print(renderable)
    return console.export_text()


def test_version_is_3_1():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (3, 1), __version__


# ================================================================ registry
def test_the_whole_ieee_registry_ships():
    assert oui.BUNDLED.name == "oui.csv.gz" and oui.BUNDLED.exists()
    assert oui.entry_count() > 50_000       # MA-L + MA-M + MA-S


def test_every_mac_in_the_screenshot_resolves_or_is_private():
    expected = {
        "10.0.0.1": "Vantiva", "10.0.0.9": "Sony Interactive",
        "10.0.0.61": "Intel", "10.0.0.217": "Amazon",
        "10.0.0.134": "Amazon", "10.0.0.145": "Amazon",
    }
    for ip, mac in SCREENSHOT.items():
        vendor = oui.lookup_mac(mac)
        if ip in expected:
            assert vendor and expected[ip] in vendor, (ip, vendor)
        else:
            assert vendor is None and oui.mac_kind(mac) == "random", ip


def test_longest_prefix_wins_across_the_three_block_sizes():
    # MA-S: a 36-bit slice of an IEEE block.
    assert oui.match("8C:1F:64:AF:A0:01") == ("DATA ELECTRONIC DEVICES, INC", "MA-S")
    # MA-M: a 28-bit slice.
    vendor, registry = oui.match("C8:5C:E2:70:00:01")
    assert registry == "MA-M" and "SYNERGY" in vendor
    # Plain MA-L still works, and the old 3-byte API is unchanged.
    assert oui.match("00:00:0C:12:34:56")[1] == "MA-L"
    assert "Cisco" in oui.lookup("00000C")


def test_a_carved_up_block_is_not_reported_as_a_vendor():
    # 70:B3:D5 is an IEEE block cut into slices; an unassigned slice must not
    # come back as "IEEE Registration Authority".
    vendor, registry = oui.match("70:B3:D5:00:00:01")
    assert vendor is None and registry == "IEEE sub-allocated block"


def test_a_table_from_an_older_update_oui_still_loads(tmp_path, monkeypatch):
    legacy = tmp_path / "oui.csv"
    legacy.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        'MA-L,FCFCFC,"Legacy Test Vendor, Inc.",Somewhere\n'
    )
    monkeypatch.setattr(oui, "user_table_path", lambda: legacy)
    oui.reload()
    try:
        assert oui.lookup("FCFCFC") == "Legacy Test Vendor, Inc."
        assert oui.entry_count() > 50_000       # the bundled table is still there
    finally:
        monkeypatch.undo()
        oui.reload()


def test_mac_kinds():
    assert oui.mac_kind("98:bd:80:3a:4b:5c") == "global"
    assert oui.mac_kind("52:7a:8b:6d:7e:8f") == "random"     # 0x52 has bit 1 set
    assert oui.mac_kind("c6:db:20:9a:ab:bc") == "random"
    assert oui.mac_kind("01:00:5e:00:00:fb") == "multicast"
    assert oui.mac_kind("00:11:22") == "invalid"


def test_describe_explains_a_randomised_address():
    rows = dict(oui.describe("52:7A:8B:6D:7E:8F", None, "offline"))
    assert "randomised" in rows["Vendor"]
    assert "phone" in rows["Address type"]


# ================================================================ vendors
@pytest.mark.parametrize("raw, short", [
    ("Amazon Technologies Inc.", "Amazon"),
    ("Sony Interactive Entertainment Inc.", "Sony (PlayStation)"),
    ("Vantiva USA LLC", "Vantiva (Technicolor)"),
    ("Intel Corporate", "Intel"),
    ("Shenzhen Example Technology Co., Ltd.", "Shenzhen Example"),
    ("SYNERGY SYSTEMS AND SOLUTIONS", "Synergy Systems And Solut…"),
])
def test_vendor_names_are_shortened_for_the_table(raw, short):
    assert devices.short_vendor(raw) == short


def test_vendor_matching_is_by_whole_word():
    # 'arris' must not match inside 'Harris'; 'apple' not inside 'Snapple'.
    assert devices.short_vendor("Harris Corporation") == "Harris"
    label, _ = devices.classify({"vendor": "Harris Corporation", "mac_kind": "global"})
    assert label == "Unknown"
    assert devices.classify({"vendor": "Snapple Beverage", "mac_kind": "global"})[0] == "Unknown"


# ============================================================= DNS format
def _rr(name: str, rtype: str, rdata: bytes, ttl: int = 10) -> bytes:
    return (devices.encode_name(name)
            + struct.pack("!HHIH", devices.QTYPE[rtype], 1, ttl, len(rdata)) + rdata)


def _txt(*items: str) -> bytes:
    return b"".join(bytes([len(i)]) + i.encode() for i in items)


def _reply(qid: int, *records: bytes, additional: int = 0) -> bytes:
    answers = len(records) - additional
    return struct.pack("!HHHHHH", qid, 0x8400, 0, answers, 0, additional) + b"".join(records)


def test_query_is_well_formed():
    packet = devices.build_query(0x1234, [("61.0.0.10.in-addr.arpa", "PTR")])
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
    assert (qid, flags, qd, an, ns, ar) == (0x1234, 0x0100, 1, 0, 0, 0)
    assert packet[12:] == (b"\x0261\x010\x010\x0210\x07in-addr\x04arpa\x00"
                           + struct.pack("!HH", 12, 1))


def test_parse_follows_name_compression():
    # A PTR answer whose owner name is a pointer back to the question.
    question = devices.encode_name("61.0.0.10.in-addr.arpa")
    target = devices.encode_name("Jordans-PC.home.example.net")
    packet = (struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + question
              + struct.pack("!HH", 12, 1) + b"\xc0\x0c"
              + struct.pack("!HHIH", 12, 1, 60, len(target)) + target)
    message = devices.parse_message(packet)
    assert message["id"] == 7
    assert message["answers"] == [
        ("61.0.0.10.in-addr.arpa", "PTR", "Jordans-PC.home.example.net")
    ]


def test_a_pointer_loop_is_refused_not_followed_forever():
    packet = struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c"
    assert devices.parse_message(packet + b"\x00" * 10)["answers"] == []
    with pytest.raises(ValueError):
        devices._read_name(packet, 12)


def test_one_bad_record_keeps_the_ones_before_it():
    # Claims three answers, carries one good one and then garbage.
    good = _rr("_ipp._tcp.local", "PTR", devices.encode_name("Office._ipp._tcp.local"))
    packet = struct.pack("!HHHHHH", 5, 0x8400, 0, 3, 0, 0) + good + b"\xc0"
    answers = devices.parse_message(packet)["answers"]
    assert answers == [("_ipp._tcp.local", "PTR", "Office._ipp._tcp.local")]


def test_reverse_names():
    assert devices.reverse_name("10.0.0.61") == "61.0.0.10.in-addr.arpa"
    assert devices.reverse_name("2001:db8::1").endswith(".ip6.arpa")


@pytest.mark.parametrize("name, useful", [
    ("Jordans-iPhone.home.example.net.", "Jordans-iPhone.home.example.net"),
    ("10-0-0-61.dynamic.example.net", ""),
    ("c-73-12-34-56.home.example.net", ""),
    ("localhost", ""),
    ("", ""),
])
def test_names_that_only_spell_out_the_address_are_dropped(name, useful):
    assert devices.useful_hostname(name, "10.0.0.61") == useful


# ==================================================================== mDNS
def test_an_iphone_answers_with_its_name_services_and_model():
    rev = devices.reverse_name("10.0.0.185")
    reply = _reply(
        1,
        _rr(rev, "PTR", devices.encode_name("Jordans-iPhone.local")),
        _rr(devices.SERVICES_QUERY, "PTR", devices.encode_name("_companion-link._tcp.local")),
        _rr(devices.SERVICES_QUERY, "PTR", devices.encode_name("_apple-mobdev2._tcp.local")),
        _rr("Jordans-iPhone._companion-link._tcp.local", "TXT",
            _txt("rpMd=iPhone15,2", "rpVr=510.1")),
        additional=1,
    )
    info = devices.read_mdns([devices.parse_message(reply)], "10.0.0.185")
    assert info["hostname"] == "Jordans-iPhone.local"
    assert info["services"] == ["_companion-link._tcp", "_apple-mobdev2._tcp"]
    assert info["model"] == "iPhone15,2"


def test_a_chromecast_gives_its_friendly_name_and_model():
    reply = _reply(
        2,
        _rr("_googlecast._tcp.local", "PTR",
            devices.encode_name("Google-TV-3a9f._googlecast._tcp.local")),
        _rr("Google-TV-3a9f._googlecast._tcp.local", "TXT",
            _txt("id=3a9f", "md=Chromecast HD", "fn=Living Room TV")),
        additional=1,
    )
    info = devices.read_mdns([devices.parse_message(reply)], "10.0.0.40")
    assert info["friendly"] == "Living Room TV"
    assert info["model"] == "Chromecast HD"
    assert "_googlecast._tcp" in info["services"]


def test_airplay_audio_instance_names_drop_the_mac_prefix():
    assert devices.instance_label("A1B2C3D4E5F6@Kitchen._raop._tcp.local") == "Kitchen"
    assert devices.instance_label("Living Room._airplay._tcp.local") == "Living Room"
    assert devices.service_type("x._googlecast._tcp.local.") == "_googlecast._tcp"


def test_replies_from_another_address_are_ignored():
    reply = _reply(3, _rr("_ipp._tcp.local", "PTR", devices.encode_name("P._ipp._tcp.local")))
    assert devices._decode([(reply, ("10.0.0.99", 5353))], "10.0.0.40") == []
    assert len(devices._decode([(reply, ("10.0.0.40", 5353))], "10.0.0.40")) == 1


# ================================================================= NetBIOS
def _nbstat_reply(tid: int, names, mac: str = "00:11:22:33:44:55") -> bytes:
    query = devices.build_nbstat(tid)
    body = bytes([len(names)]) + b"".join(
        n.ljust(15).encode() + bytes([suffix]) + struct.pack("!H", flags)
        for n, suffix, flags in names
    ) + bytes.fromhex(mac.replace(":", ""))
    return (struct.pack("!HHHHHH", tid, 0x8400, 0, 1, 0, 0) + query[12:12 + 34]
            + struct.pack("!HHIH", 0x21, 1, 0, len(body)) + body)


def test_nbstat_query_encodes_the_wildcard_name():
    packet = devices.build_nbstat(0xBEEF)
    assert len(packet) == 50
    assert packet[12] == 32 and packet[13:45] == b"CK" + b"A" * 30
    assert packet[-4:] == struct.pack("!HH", 0x21, 1)


def test_nbstat_reply_gives_computer_workgroup_and_mac():
    reply = _nbstat_reply(9, [
        ("DESKTOP-K3V9TQ1", 0x00, 0x0400),
        ("WORKGROUP", 0x00, 0x8400),          # group bit set
        ("DESKTOP-K3V9TQ1", 0x20, 0x0400),
    ])
    info = devices.parse_nbstat(reply)
    assert info["computer"] == "DESKTOP-K3V9TQ1"
    assert info["workgroup"] == "WORKGROUP"
    assert info["mac"] == "00:11:22:33:44:55"


def test_a_short_nbstat_reply_is_rejected():
    with pytest.raises(ValueError):
        devices.parse_nbstat(b"\x00" * 20)


# ============================================================ SSDP / UPnP
ROKU_SSDP = (
    b"HTTP/1.1 200 OK\r\nCache-Control: max-age=3600\r\nST: upnp:rootdevice\r\n"
    b"USN: uuid:roku:ecp:X00400ABCDEF::upnp:rootdevice\r\n"
    b"LOCATION: http://10.0.0.77:8060/\r\nServer: Roku/12.5.0 UPnP/1.0 Roku/12.5.0\r\n\r\n"
)

ROKU_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:roku-com:device:player:1-0</deviceType>
    <friendlyName>Den Roku Ultra</friendlyName>
    <manufacturer>Roku</manufacturer>
    <modelName>Roku Ultra</modelName>
    <modelNumber>4850X</modelNumber>
  </device>
</root>"""


def test_ssdp_reply_headers():
    headers = devices.parse_ssdp(ROKU_SSDP)
    assert headers["location"] == "http://10.0.0.77:8060/"
    assert headers["server"].startswith("Roku/")
    assert devices.parse_ssdp(b"garbage") == {}
    assert b"ssdp:discover" in devices.build_msearch()


def test_upnp_description_names_the_box():
    info = devices.parse_upnp_xml(ROKU_XML)
    assert info["friendlyName"] == "Den Roku Ultra"
    assert info["modelName"] == "Roku Ultra"
    assert devices.upnp_kind({"deviceType": "urn:schemas-upnp-org:device:MediaRenderer:1"}) == "MediaRenderer"


def test_upnp_description_never_expands_entities():
    bomb = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]>'
            "<root><device><friendlyName>&a;</friendlyName></device></root>")
    assert devices.parse_upnp_xml(bomb) == {}


def test_description_is_only_fetched_from_the_device_that_offered_it():
    assert devices._safe_location("http://10.0.0.77:8060/", "10.0.0.77") == ("10.0.0.77", 8060, "/")
    assert devices._safe_location("http://10.0.0.77/desc.xml", "10.0.0.77") == ("10.0.0.77", 80, "/desc.xml")
    assert devices._safe_location("http://203.0.113.9:8060/", "10.0.0.77") is None
    assert devices._safe_location("https://10.0.0.77/", "10.0.0.77") is None
    assert devices._safe_location("file:///etc/passwd", "10.0.0.77") is None


def test_http_parsing_handles_chunked_bodies():
    blob = (b"HTTP/1.1 200 OK\r\nServer: lighttpd\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\n<titl\r\n12\r\ne>Router</title>\r\n\r\n0\r\n\r\n")
    status, headers, body = devices.parse_http(blob)
    assert status == 200 and headers["server"] == "lighttpd"
    assert body == b"<title>Router</title>\r\n"
    assert devices.parse_http(b"not http") is None


# ===================================================================== TTL
def test_ttl_is_read_from_ping_and_turned_into_a_hint():
    out = "64 bytes from 10.0.0.61: icmp_seq=1 ttl=128 time=53.6 ms"
    assert devices.parse_ttl(out) == 128
    assert devices.ttl_hint(128) == "Windows"
    assert devices.ttl_hint(64).startswith("Unix-like")
    assert devices.ttl_hint(255) == "network gear / embedded"
    assert devices.ttl_hint(None) == ""


def _fake(dir_path: Path, name: str, body: str) -> None:
    path = dir_path / name
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(0o755)


FAKE_PING = r'''
ip="${@: -1}"
case "$ip" in
  10.0.0.1)   echo "64 bytes from $ip: icmp_seq=1 ttl=64 time=6.1 ms";;
  10.0.0.61)  echo "64 bytes from $ip: icmp_seq=1 ttl=128 time=53.6 ms";;
  10.0.0.5)   echo "64 bytes from $ip: icmp_seq=1 ttl=64 time=0.04 ms";;
  *) echo "1 packets transmitted, 0 received"; exit 1;;
esac
echo "1 packets transmitted, 1 received, 0% packet loss"
'''

FAKE_IP = r'''
if [ "$1" = "neigh" ]; then
  echo "10.0.0.1 dev wlp3s0 lladdr b8:5e:71:a1:b2:c3 REACHABLE"
  echo "10.0.0.61 dev wlp3s0 lladdr 98:bd:80:3a:4b:5c STALE"
  echo "10.0.0.6 dev wlp3s0 lladdr 52:7a:8b:6d:7e:8f STALE"
fi
'''


def test_ping_keeps_the_reply_ttl(tmp_path, monkeypatch):
    _fake(tmp_path, "ping", FAKE_PING)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    assert asyncio.run(lan._ping_one("10.0.0.61", 1.0)) == ("10.0.0.61", 53.6, 128)
    assert asyncio.run(lan._ping_one("10.0.0.99", 1.0)) == ("10.0.0.99", None, None)


# ================================================================ guessing
def _dev(**fields) -> dict:
    mac = fields.get("mac")
    vendor, kind = devices.vendor_for(mac) if mac else ("", "none")
    return {"vendor": vendor, "mac_kind": kind, **fields}


@pytest.mark.parametrize("fields, expected", [
    (dict(mac=SCREENSHOT["10.0.0.1"], role="gateway"), "Router / gateway"),
    (dict(mac=SCREENSHOT["10.0.0.61"], role="self"), "This computer"),
    (dict(mac=SCREENSHOT["10.0.0.9"]), "PlayStation"),
    (dict(mac=SCREENSHOT["10.0.0.61"], ttl=128), "Windows PC"),
    (dict(mac=SCREENSHOT["10.0.0.185"]), "Phone / tablet / laptop"),
    (dict(mac=SCREENSHOT["10.0.0.134"], services=["_amzn-wplay._tcp"]), "Fire TV"),
    (dict(mac=SCREENSHOT["10.0.0.145"], hostname="Echo-Dot-4B"), "Amazon Echo"),
    (dict(mac=SCREENSHOT["10.0.0.217"]), "Amazon device"),
    (dict(mac="52:00:00:00:00:01", model="iPhone15,2",
          services=["_companion-link._tcp"]), "iPhone"),
    (dict(hostname="core-switch-01"), "Network switch"),
    (dict(hostname="Archer-C7"), "Router / Wi-Fi gear"),
    (dict(netbios={"computer": "DESKTOP-K3V9TQ1"}, hostname="DESKTOP-K3V9TQ1"), "Windows PC"),
    (dict(open_ports=[9100, 80]), "Printer"),
    (dict(open_ports=[62078]), "iPhone / iPad"),
    (dict(upnp={"deviceType": "urn:roku-com:device:player:1-0",
                "manufacturer": "Roku", "modelName": "Roku Ultra"}), "Roku"),
    (dict(), "Unknown"),
])
def test_classification(fields, expected):
    label, evidence = devices.classify(_dev(**fields))
    assert label == expected
    assert bool(evidence) == (expected != "Unknown")


def test_classification_keeps_its_evidence():
    label, evidence = devices.classify(_dev(
        mac=SCREENSHOT["10.0.0.134"], services=["_amzn-wplay._tcp"], ttl=64,
    ))
    assert label == "Fire TV"
    assert "advertises _amzn-wplay._tcp" in evidence
    assert any("Amazon" in reason for reason in evidence)


# ================================================================= context
def _iface(address: str) -> ipaddress.IPv4Interface:
    return ipaddress.ip_interface(address)


def test_blank_sweep_uses_this_machines_subnet():
    assert devices.suggest_sweep({"default_interface": _iface("10.0.0.219/24")}) == ("10.0.0.0/24", "")
    cidr, note = devices.suggest_sweep({"default_interface": _iface("10.1.44.9/16")})
    assert cidr == "10.1.44.0/24" and "too big" in note
    assert devices.suggest_sweep({"default_interface": None}) == ("", "")


def test_default_gateways_are_parsed():
    text = ("default via 10.0.0.1 dev wlp3s0 proto dhcp metric 600\n"
            "default via 10.0.0.1 dev enp3s0 proto dhcp metric 100\n")
    assert netif.parse_default_gateways(text) == ["10.0.0.1"]


# ================================================================ pipeline
CONTEXT = {
    "hostname": "workstation",
    "self": {"10.0.0.219": "98:bd:80:00:00:01"},
    "networks": [ipaddress.ip_network("10.0.0.0/24")],
    "gateways": {"10.0.0.1"},
    "default_interface": _iface("10.0.0.219/24"),
}


@pytest.fixture
def recorded(monkeypatch):
    """Answers as a real home LAN gives them."""
    async def reverse_dns(ip, servers, timeout=0):
        return {"10.0.0.61": "DESKTOP-K3V9TQ1.home.example.net.",
                "10.0.0.217": "10-0-0-217.dynamic.example.net"}.get(ip, "")

    async def mdns_probe(ip, timeout=0):
        if ip == "10.0.0.134":
            return {"hostname": "", "services": ["_amzn-wplay._tcp"], "instances": {},
                    "txt": {}, "model": "", "friendly": "Living Room Fire TV"}
        return devices.read_mdns([], ip)

    async def netbios_probe(ip, timeout=0):
        if ip == "10.0.0.61":
            return {"computer": "DESKTOP-K3V9TQ1", "workgroup": "WORKGROUP",
                    "names": [], "mac": ""}
        return {}

    async def ssdp_discover(window=0):
        return {"10.0.0.77": {"server": "Roku/12.5.0 UPnP/1.0",
                              "locations": ["http://10.0.0.77:8060/"], "types": []}}

    async def upnp_describe(ip, locations):
        return devices.parse_upnp_xml(ROKU_XML) if ip == "10.0.0.77" else {}

    for name, fake in dict(reverse_dns=reverse_dns, mdns_probe=mdns_probe,
                           netbios_probe=netbios_probe, ssdp_discover=ssdp_discover,
                           upnp_describe=upnp_describe).items():
        monkeypatch.setattr(devices, name, fake)


def test_identify_folds_every_source_together(recorded):
    hosts = [
        {"ip": "10.0.0.1", "mac": SCREENSHOT["10.0.0.1"], "rtt_ms": 6.1, "ttl": 64},
        {"ip": "10.0.0.61", "mac": SCREENSHOT["10.0.0.61"], "rtt_ms": 53.6, "ttl": 128},
        {"ip": "10.0.0.77", "mac": "d8:31:34:00:00:01", "rtt_ms": 3.0, "ttl": 64},
        {"ip": "10.0.0.134", "mac": SCREENSHOT["10.0.0.134"]},
        {"ip": "10.0.0.185", "mac": SCREENSHOT["10.0.0.185"], "rtt_ms": 206.0, "ttl": 64},
        {"ip": "10.0.0.217", "mac": SCREENSHOT["10.0.0.217"], "rtt_ms": 43.3, "ttl": 64},
        {"ip": "10.0.0.219", "mac": None, "rtt_ms": 0.0, "ttl": 64},
    ]
    found = {d["ip"]: d for d in asyncio.run(
        devices.identify(hosts, context=CONTEXT, use_ssdp=True))}

    assert found["10.0.0.1"]["device"] == "Router / gateway"
    pc = found["10.0.0.61"]
    assert pc["hostname"] == "DESKTOP-K3V9TQ1.home.example.net"
    assert pc["device"] == "Windows PC" and set(pc["sources"]) == {"DNS", "NetBIOS"}
    roku = found["10.0.0.77"]
    assert roku["device"] == "Roku" and roku["friendly"] == "Den Roku Ultra"
    assert found["10.0.0.134"]["device"] == "Fire TV"
    assert found["10.0.0.185"]["device"] == "Phone / tablet / laptop"
    assert "hostname" not in found["10.0.0.217"]       # the IP spelled out is no name
    me = found["10.0.0.219"]
    assert me["device"] == "This computer" and me["mac"] == "98:bd:80:00:00:01"
    assert me["hostname"] == "workstation"                   # this machine's own name
    assert devices.rtt_cell(me) == "local"
    # The friendly name is already the Hostname cell, so Details only adds the model.
    assert devices.display_name(roku) == "Den Roku Ultra"
    assert devices.details(roku) == "Roku Ultra"


def test_upnp_found_by_asking_the_device_directly(recorded, monkeypatch):
    # With ufw on, replies to the multicast search never arrive; the unicast
    # M-SEARCH to the device itself still gets through.
    async def no_multicast(window=0):
        return {}

    async def unicast(ip, timeout=0):
        if ip == "10.0.0.77":
            return {"server": "Roku/12.5.0", "locations": ["http://10.0.0.77:8060/"],
                    "types": ["upnp:rootdevice"]}
        return {}

    monkeypatch.setattr(devices, "ssdp_discover", no_multicast)
    monkeypatch.setattr(devices, "ssdp_unicast", unicast)
    found = asyncio.run(devices.identify(
        [{"ip": "10.0.0.77", "mac": "d8:31:34:00:00:01"}], context=CONTEXT))
    assert found[0]["friendly"] == "Den Roku Ultra" and "UPnP" in found[0]["sources"]


def test_unicast_msearch_is_addressed_to_the_device():
    packet = devices.build_msearch("upnp:rootdevice", host="10.0.0.77").decode()
    assert "HOST: 10.0.0.77:1900" in packet and "MX:" not in packet
    assert "MX: 2" in devices.build_msearch().decode()


def test_sweep_rows_and_summary(recorded):
    hosts = [{"ip": ip, "mac": mac, "rtt_ms": 5.0, "ttl": 64}
             for ip, mac in SCREENSHOT.items()]
    found = asyncio.run(devices.identify(hosts, context=CONTEXT))
    rows = devices.sweep_rows(found)
    assert len(rows[0]) == len(devices.SWEEP_COLUMNS) == 7
    by_ip = {row[0]: row for row in rows}
    assert by_ip["10.0.0.1"][3] == "Vantiva (Technicolor)"
    assert by_ip["10.0.0.185"][3] == "private MAC"
    assert by_ip["10.0.0.61"][4] == "DESKTOP-K3V9TQ1"         # short name in the table
    assert len(devices.arp_rows(found)[0]) == len(devices.ARP_COLUMNS)
    summary = dict(devices.summary(found))
    assert summary["Devices"] == len(SCREENSHOT)
    assert summary["Private (random) MACs"] == 2
    assert "Amazon ×3" in summary["Top vendors"]


def test_a_huge_sweep_probes_the_first_devices_and_says_so(monkeypatch):
    asked = []

    async def reverse_dns(ip, servers, timeout=0):
        asked.append(ip)
        return ""

    monkeypatch.setattr(devices, "reverse_dns", reverse_dns)
    hosts = [{"ip": f"10.0.{i // 250}.{i % 250 + 2}", "mac": SCREENSHOT["10.0.0.9"]}
             for i in range(devices.MAX_PROBED + 5)]
    found = asyncio.run(devices.identify(hosts, context=CONTEXT))
    assert len(asked) == devices.MAX_PROBED           # the first ones only
    assert found[-1]["probed"] is False
    assert found[-1]["device"] == "PlayStation"       # vendor columns still filled
    assert "5 — past the first" in dict(devices.summary(found))["Not asked for names"]


# ================================================================== capture
def test_capture_counts_only_unicast_on_this_machines_subnets():
    from netzilla.screens.capture import capture_lan_counts

    packets = [
        {"src": "10.0.0.61", "dst": "142.250.191.78"},
        {"src": "10.0.0.61", "dst": "10.0.0.1"},
        {"src": "10.0.0.9", "dst": "10.0.0.255"},     # broadcast
        {"src": "10.0.0.9", "dst": "224.0.0.251"},    # mDNS multicast
        {"src": "aa:bb:cc:dd:ee:ff", "dst": "Broadcast"},
        {"src": "192.168.5.5", "dst": "192.168.5.6"},  # someone else's pcap
    ]
    assert capture_lan_counts(packets, CONTEXT) == {"10.0.0.61": 2, "10.0.0.1": 1, "10.0.0.9": 2}


# =================================================================== panes
class _PaneBase:
    def __init__(self, fields):
        self._fields = fields
        self.events = []

    @property
    def palette(self):
        from netzilla.themes import get_palette
        return get_palette("phosphor-green")

    @property
    def services(self):
        return None

    def field(self, key):
        return self._fields.get(key, "")

    def set_choices(self, *a, **k):
        pass

    async def begin(self, m="…"):
        self.events.append(("begin", m))

    def progress(self, m):
        pass

    async def finish(self, m=""):
        self.events.append(("finish", m))

    async def push(self, r):
        self.events.append(("push", r))

    async def push_widget(self, w):
        self.events.append(("widget", w))

    async def push_error(self, t, m):
        self.events.append(("error", t))

    async def push_warning(self, t, m):
        self.events.append(("warning", t))

    def text(self) -> str:
        return "\n".join(text_of(r) for kind, r in self.events if kind == "push")


def _lan_pane(fields):
    from netzilla.screens.lan import LANPane

    class Pane(_PaneBase, LANPane):
        def __init__(self, fields):
            LANPane.__init__(self)
            _PaneBase.__init__(self, fields)

    return Pane(fields)


def test_lan_sweep_shows_vendor_hostname_and_device(tmp_path, monkeypatch, recorded):
    _fake(tmp_path, "ping", FAKE_PING)
    _fake(tmp_path, "ip", FAKE_IP)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    async def context():
        return CONTEXT

    monkeypatch.setattr(devices, "local_context", context)
    pane = _lan_pane({"target": "10.0.0.0/26"})
    asyncio.run(pane._sweep())
    shown = pane.text()
    for column in ("VENDOR", "HOSTNAME", "DEVICE", "DETAILS"):
        assert column in shown
    assert "Vantiva (Technicolor)" in shown and "Router / gateway" in shown
    assert "DESKTOP-K3V9TQ1" in shown and "Windows PC" in shown
    # 10.0.0.6 is only in the ARP table, with a private MAC.
    assert "IN ARP CACHE BUT DID NOT ANSWER PING" in shown and "private MAC" in shown
    assert "error" not in [e[0] for e in pane.events]


def test_lan_sweep_with_a_blank_box_uses_this_machines_subnet(tmp_path, monkeypatch, recorded):
    _fake(tmp_path, "ping", FAKE_PING)
    _fake(tmp_path, "ip", FAKE_IP)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(lan, "MAX_HOSTS", 1024)

    async def context():
        return dict(CONTEXT, default_interface=_iface("10.0.0.5/29"))

    monkeypatch.setattr(devices, "local_context", context)
    pane = _lan_pane({"target": ""})
    asyncio.run(pane._sweep())
    assert "10.0.0.0/29" in pane.text()


def test_lan_sweep_blank_box_without_a_default_route_asks_for_one():
    pane = _lan_pane({"target": ""})
    with pytest.raises(ValidationError, match="could not work out"):
        asyncio.run(pane._sweep())


@pytest.mark.parametrize("target", ["", "10.0.0.0/24"])
def test_identify_wants_exactly_one_ip(target):
    pane = _lan_pane({"target": target})
    with pytest.raises(ValidationError, match="one device"):
        asyncio.run(pane._identify())


def test_identify_shows_the_profile_and_evidence(tmp_path, monkeypatch, recorded):
    _fake(tmp_path, "ping", FAKE_PING)
    _fake(tmp_path, "ip", FAKE_IP)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    async def ports(ip, *a, **k):
        return [135, 139, 445, 3389]

    monkeypatch.setattr(devices, "port_scan", ports)
    pane = _lan_pane({"target": "10.0.0.61"})
    asyncio.run(pane._identify())
    shown = pane.text()
    assert "10.0.0.61 looks like: Windows PC" in shown
    assert "WHY NETZILLA THINKS SO" in shown and "tcp/3389 open" in shown
    assert "RDP" in shown and "DESKTOP-K3V9TQ1" in shown


def test_dup_ip_names_each_claimant():
    from netzilla.screens.lan import LANPane

    rows = LANPane._claimant_rows([SCREENSHOT["10.0.0.1"], SCREENSHOT["10.0.0.185"]])
    assert rows[0][1] == "Vantiva (Technicolor)" and rows[0][2] == "burned-in"
    assert rows[1][1] == "private MAC" and rows[1][2] == "randomised / local"


def test_flow_talkers_identify_lan_peers(tmp_path, monkeypatch):
    from netzilla.screens.flows import FlowPane

    async def identify_ips(ips, **_k):
        return {"10.0.0.5": {"ip": "10.0.0.5", "mac": "00:11:32:00:00:01",
                             "vendor": "Synology Incorporated", "mac_kind": "global",
                             "hostname": "diskstation.local", "device": "NAS / file server"}}

    async def reverse_dns(ip, servers, timeout=0):
        return "lga25s74-in-f14.1e100.net." if ip == "142.250.191.78" else ""

    monkeypatch.setattr(devices, "identify_ips", identify_ips)
    monkeypatch.setattr(devices, "reverse_dns", reverse_dns)

    class Pane(_PaneBase, FlowPane):
        def __init__(self):
            FlowPane.__init__(self)
            _PaneBase.__init__(self, {})

        async def _geo(self, ip):
            return "AS15169", "Google LLC", "Mountain View, US"

    hosts = [
        {"remote_ip": "142.250.191.78", "connections": 3, "ports": [443],
         "processes": ["firefox"], "external": True},
        {"remote_ip": "10.0.0.5", "connections": 1, "ports": [445],
         "processes": ["smbclient"], "external": False},
        {"remote_ip": "127.0.0.1", "connections": 1, "ports": [631],
         "processes": ["cups"], "external": False},
    ]
    rows = asyncio.run(Pane()._resolve(hosts))
    assert rows[0][1] == "lga25s74-in-f14.1e100.net" and rows[0][4] == "AS15169 Google LLC"
    assert rows[1][1] == "diskstation" and rows[1][4] == "LAN · Synology"
    assert rows[1][5] == "NAS / file server"
    assert rows[2][1:2] == ["localhost"] and rows[2][5] == "loopback"


def test_wifi_names_the_access_point_maker():
    from netzilla.screens.wifi import WifiPane

    assert WifiPane.ap_vendor("B8:5E:71:A1:B2:C3") == "Vantiva (Technicolor)"
    assert WifiPane.ap_vendor("BA:5E:71:A1:B2:C3") == "virtual BSSID"   # guest SSID


def test_int_tab_shows_the_nic_maker():
    found = [{"name": "wlp3s0", "kind": "wifi", "state": "UP", "mtu": "1500",
              "mac": "98:bd:80:3a:4b:5c", "addresses": ["10.0.0.219/24"],
              "default_route": True},
             {"name": "lo", "kind": "loopback", "state": "UNKNOWN", "mtu": "65536",
              "mac": "00:00:00:00:00:00", "addresses": [], "default_route": False}]
    rows = netif.interface_rows(found)
    assert len(rows[0]) == len(netif.INTERFACE_COLUMNS)
    assert rows[0][netif.INTERFACE_COLUMNS.index("NIC vendor")] == "Intel"
    assert rows[1][netif.INTERFACE_COLUMNS.index("NIC vendor")] == "—"


def test_mac_tab_never_sends_a_randomised_address_online(monkeypatch):
    from netzilla.clients import macvendors
    from netzilla.screens.mac_lookup import MACPane

    async def must_not_call(*_a, **_k):
        raise AssertionError("a private MAC was sent to macvendors.com")

    monkeypatch.setattr(macvendors, "lookup", must_not_call)

    class Pane(_PaneBase, MACPane):
        def __init__(self, fields):
            MACPane.__init__(self)
            _PaneBase.__init__(self, fields)

    pane = Pane({"mac": "52:7A:8B:6D:7E:8F"})
    asyncio.run(pane.execute("lookup"))
    assert "WHY THERE IS NO VENDOR" in pane.text()


# ===================================================================== CLI
def test_cli_sweep_prints_identified_devices(monkeypatch, capsys, recorded):
    from netzilla import cli

    async def sweep(cidr, **_k):
        return {"cidr": "10.0.0.0/24", "scanned": 254,
                "live": [{"ip": "10.0.0.61", "mac": SCREENSHOT["10.0.0.61"],
                          "rtt_ms": 53.6, "ttl": 128}],
                "arp_only": [{"ip": "10.0.0.185", "mac": SCREENSHOT["10.0.0.185"]}]}

    async def context():
        return CONTEXT

    monkeypatch.setattr(lan, "sweep", sweep)
    monkeypatch.setattr(devices, "local_context", context)
    assert cli.main(["sweep", "--json", "--no-default-keys", "--offline"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["network"] == "10.0.0.0/24" and payload["alive"] == 1
    pc, phone = payload["devices"]
    assert pc["vendor"] == "Intel Corporate" and pc["device"] == "Windows PC"
    assert pc["os_hint"] == "Windows" and pc["answered_ping"] is True
    assert phone["address_type"] == "random" and phone["answered_ping"] is False


def test_cli_mac_reports_the_address_type(capsys):
    from netzilla import cli

    assert cli.main(["mac", "52:7a:8b:6d:7e:8f", "--json", "--offline",
                     "--no-default-keys"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["address_type"] == "random" and payload["vendor"] is None


def test_new_actions_have_help():
    from netzilla.help import get_help
    from netzilla.screens.lan import LANPane

    assert [a.key for a in LANPane.ACTIONS][:2] == ["sweep", "identify"]
    assert get_help("LANPane", "identify") is not None
    assert "blank" in get_help("LANPane", "sweep").usage


# ====================================================== review follow-ups
def test_off_lan_addresses_found_elsewhere_are_not_probed(monkeypatch):
    """A FLOW connection across a VPN to 10.20.30.40 must not be sent mDNS,
    NetBIOS or SSDP — only a reverse-DNS question, to the system resolver."""
    sent = []

    async def probe(ip, *_a, **_k):
        sent.append(ip)
        return {}

    async def reverse_dns(ip, servers, timeout=0):
        sent.append(("ptr", ip, tuple(tuple(t) for t in servers)))
        return ""

    async def context():
        return CONTEXT

    async def arp():
        return {}

    monkeypatch.setattr(devices, "mdns_probe", probe)
    monkeypatch.setattr(devices, "netbios_probe", probe)
    monkeypatch.setattr(devices, "ssdp_unicast", probe)
    monkeypatch.setattr(devices, "reverse_dns", reverse_dns)
    monkeypatch.setattr(devices, "local_context", context)
    monkeypatch.setattr(devices, "nameservers", lambda: ["10.99.0.53"])
    monkeypatch.setattr(lan, "arp_table", arp)
    asyncio.run(devices.identify_ips(["10.20.30.40", "10.0.0.61"]))
    assert "10.20.30.40" not in sent                     # no device probes
    assert "10.0.0.61" in sent                           # the LAN one is probed
    ptr = {entry[1]: entry[2] for entry in sent if isinstance(entry, tuple)}
    assert ptr["10.20.30.40"] == (("10.99.0.53",),)      # its own resolver
    # The home address is asked of the router, never of the VPN's DNS.
    assert ptr["10.0.0.61"] == (("10.0.0.1",),)


def test_lan_ptr_asks_the_router_then_nearby_resolvers_only():
    tiers = devices.dns_servers_for("10.0.0.61", CONTEXT,
                                    ["127.0.0.53", "10.99.0.53", "10.0.0.2"])
    assert tiers == [["10.0.0.1"], ["127.0.0.53", "10.0.0.2"]]
    assert devices.dns_servers_for("142.250.191.78", CONTEXT, ["10.99.0.53"]) == [["10.99.0.53"]]


def test_systemd_resolved_bookkeeping_names_are_not_hostnames():
    assert devices.useful_hostname("_gateway") == ""
    assert devices.useful_hostname("_outbound.") == ""


def test_vpn_and_container_interfaces_are_not_the_lan(monkeypatch):
    async def interfaces():
        return ([
            {"name": "wlp3s0", "kind": "wireless", "mac": "98:bd:80:00:00:01",
             "addresses": ["10.0.0.219/24"], "default_route": False},
            {"name": "gpd0", "kind": "other", "mac": "",
             "addresses": ["10.212.4.9/32"], "default_route": True},
            {"name": "docker0", "kind": "docker", "mac": "02:42:00:00:00:01",
             "addresses": ["172.17.0.1/16"], "default_route": False},
        ], "ip")

    async def gateways():
        return ["10.0.0.1"]

    from netzilla.local import netif as netif_module
    monkeypatch.setattr(netif_module, "interfaces", interfaces)
    monkeypatch.setattr(netif_module, "default_gateways", gateways)
    # conftest replaced local_context; use the real one here.
    import importlib
    real = importlib.reload(devices).local_context
    try:
        ctx = asyncio.run(real())
    finally:
        importlib.reload(devices)
    assert [str(n) for n in ctx["networks"]] == ["10.0.0.0/24"]
    # The VPN holds the default route, but the blank-box sweep still finds the LAN.
    assert str(ctx["default_interface"]) == "10.0.0.219/24"


@pytest.mark.parametrize("fields, expected", [
    # A Samsung TV's UPnP description names it, even though it is also a
    # generic MediaRenderer.
    (dict(upnp={"deviceType": "urn:schemas-upnp-org:device:MediaRenderer:1",
                "manufacturer": "Samsung Electronics", "modelName": "UN55TU7000",
                "friendlyName": "[TV] Samsung 7 Series"}), "Smart TV"),
    # A Mac advertising AirPlay with no model stays an Apple device.
    (dict(mac="a4:83:e7:00:00:01", services=["_companion-link._tcp", "_airplay._tcp",
                                             "_raop._tcp"]), "Apple device"),
    # Hyper-V and QEMU guests.
    (dict(mac="00:15:5d:01:02:03"), "Virtual machine"),
    (dict(mac="52:54:00:12:34:56"), "Virtual machine"),
    # An ASUS VivoBook is not a vivo phone; a Galaxy Book is not a phone.
    (dict(hostname="Jordan-VivoBook", ttl=128), "Windows PC"),
    (dict(hostname="Galaxy-Book3"), "PC / laptop"),
    # A Linux box that shares a printer is still the Linux box.
    (dict(hostname="mint-desktop", services=["_ipp._tcp"]), "Linux computer"),
    # TP-Link smart plug by hostname.
    (dict(mac="50:c7:bf:00:00:01", hostname="HS105"), "Smart plug / bulb"),
])
def test_review_classification_cases(fields, expected):
    assert devices.classify(_dev(**fields))[0] == expected


def test_a_cast_group_does_not_rename_the_speaker():
    reply = _reply(
        4,
        _rr("_googlecast._tcp.local", "PTR",
            devices.encode_name("Google-Nest-Mini-ab12._googlecast._tcp.local")),
        _rr("_googlecast._tcp.local", "PTR",
            devices.encode_name("Google-Cast-Group-77._googlecast._tcp.local")),
        _rr("Google-Nest-Mini-ab12._googlecast._tcp.local", "TXT",
            _txt("md=Google Nest Mini", "fn=Kitchen speaker")),
        _rr("Google-Cast-Group-77._googlecast._tcp.local", "TXT",
            _txt("md=Google Cast Group", "fn=Downstairs")),
        additional=2,
    )
    info = devices.read_mdns([devices.parse_message(reply)], "10.0.0.40")
    assert info["model"] == "Google Nest Mini"
    assert info["friendly"] == "Kitchen speaker"
    assert info["instance_names"] == ["Google-Nest-Mini-ab12._googlecast._tcp.local"]


def test_http_stops_at_content_length():
    assert devices._complete(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd")
    assert not devices._complete(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabcd")
    assert not devices._complete(b"HTTP/1.1 200 OK\r\n\r\nabcd")


def test_a_huge_or_ipv6_range_is_refused_before_it_is_built():
    import time

    started = time.monotonic()
    for cidr in ("10.0.0.0/8", "2001:db8::/64"):
        with pytest.raises(ValueError):
            lan.hosts_for(cidr)
    assert time.monotonic() - started < 1


def test_udp_exchange_stops_at_port_unreachable():
    """The un-stubbed exchange, against a closed port on this machine:
    the kernel's 'port unreachable' ends the wait at once."""
    import importlib
    import time

    real = importlib.reload(devices).udp_exchange
    try:
        probe = socket_closed_port()
        started = time.monotonic()
        packets = asyncio.run(real("127.0.0.1", probe, [b"x"], 3.0))
        elapsed = time.monotonic() - started
    finally:
        importlib.reload(devices)
    assert packets == [] and elapsed < 1.0


def socket_closed_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_pcap_files_are_not_matched_against_todays_lan():
    import inspect

    from netzilla.screens.capture import CapturePane

    source = inspect.getsource(CapturePane._render_capture)
    assert 'source.endswith("(live)")' in source


def test_a_vpn_gateway_is_not_asked_about_home_addresses():
    context = dict(CONTEXT, gateways={"10.0.0.1", "10.212.0.1"})
    assert devices.dns_servers_for("10.0.0.61", context, ["127.0.0.53"]) == [
        ["10.0.0.1"], ["127.0.0.53"]]


def test_a_windows_pc_with_play_to_is_not_a_tv():
    label, _ = devices.classify(_dev(
        netbios={"computer": "DESKTOP-K3V9TQ1"}, ttl=128,
        upnp={"deviceType": "urn:schemas-upnp-org:device:MediaRenderer:1",
              "manufacturer": "Microsoft Corporation", "modelName": "Windows Media Player"},
    ))
    assert label == "Windows PC"


def test_an_instance_label_with_a_dot_stays_one_label():
    encoded = devices.encode_name(("Mr. Speaker", "_device-info", "_tcp", "local"))
    assert encoded.startswith(bytes([len("Mr. Speaker")]) + b"Mr. Speaker")
    packet = devices.build_query(1, [(("Mr. Speaker", "_device-info", "_tcp", "local"), "TXT")])
    assert b"Mr. Speaker" in packet
