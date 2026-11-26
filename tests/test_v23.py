"""Tests for netzilla 2.3: the CAPTURE tab (tshark / tcpdump) and the
sapphire-ice theme carried over from kwkpass.

tshark output is parsed from captured text, so none of these need tshark,
tcpdump, root or a network.
"""

from __future__ import annotations

import asyncio

from netzilla import __version__
from netzilla.app import TABS
from netzilla.help import get_help
from netzilla.local import capture
from netzilla.screens.capture import CapturePane
from netzilla.themes import DEFAULT_THEME, PALETTES, THEME_NAMES, get_palette
from netzilla.validators import ValidationError

# Real tshark output: modern unicode arrows, an older ascii arrow, IPv6, ARP,
# and the banner/footer lines that are not packets.
TSHARK = """Capturing on 'enp3s0'
    1 0.000000000 192.168.1.42 → 142.250.191.78 TCP 74 51234 → 443 [SYN] Seq=0 Win=64240
    2 0.018224511 142.250.191.78 → 192.168.1.42 TCP 74 443 → 51234 [SYN, ACK] Seq=0 Ack=1
    3 0.018300000 192.168.1.42 → 142.250.191.78 TLSv1.3 583 Client Hello (SNI=example.com)
    4 0.041000000 192.168.1.42 → 192.168.1.1 DNS 74 Standard query 0x1a2b A example.com
    5 0.062000000 192.168.1.1 -> 192.168.1.42 DNS 122 Standard query response A 93.184.216.34
    6 1.500000000 fe80::1 → ff02::1 ICMPv6 86 Router Advertisement
    7 2.000000000 aa:bb:cc:dd:ee:ff → Broadcast ARP 42 Who has 192.168.1.1?
12 packets captured"""


def test_version_is_2_3():
    """The features below arrived in 2.3; later releases keep them."""
    assert tuple(int(part) for part in __version__.split(".")[:2]) >= (2, 3), (
        __version__
    )


def test_capture_tab_is_registered_after_int():
    # CAPTURE comes after INT, but no longer immediately: 3.0 added the WIFI
    # tab between them. Order is what matters here, not adjacency.
    ids = [t[0] for t in TABS]
    assert ("capture", "CAPTURE", CapturePane) in TABS
    assert ids.index("capture") > ids.index("int")


def test_every_capture_button_has_help():
    for action in CapturePane.ACTIONS:
        assert get_help("CapturePane", action.key) is not None, action.key


# ------------------------------------------------------------ tshark output
def test_parse_packets_handles_both_arrow_styles_and_every_layer():
    packets = capture.parse_packets(TSHARK)
    assert len(packets) == 7, "banner and footer lines are not packets"
    first = packets[0]
    assert first["no"] == 1
    assert first["src"] == "192.168.1.42"
    assert first["dst"] == "142.250.191.78"
    assert first["protocol"] == "TCP"
    assert first["length"] == 74
    assert first["info"].startswith("51234")
    # Older tshark prints "->" rather than "→".
    assert packets[4]["protocol"] == "DNS" and packets[4]["src"] == "192.168.1.1"
    # IPv6 and layer-2 addresses survive.
    assert packets[5]["src"] == "fe80::1"
    assert packets[6]["dst"] == "Broadcast"


def test_parse_packets_is_empty_on_junk():
    assert capture.parse_packets("") == []
    assert capture.parse_packets("tshark: unknown filter\n") == []


def test_protocol_mix_counts_and_shares():
    rows = capture.protocol_mix(capture.parse_packets(TSHARK))
    top = rows[0]
    assert top[0] in ("TCP", "DNS") and top[1] == 2
    assert top[2].endswith("%")
    assert sum(row[1] for row in rows) == 7


def test_talkers_pairs_addresses_regardless_of_direction():
    rows = capture.talkers(capture.parse_packets(TSHARK))
    busiest = rows[0]
    assert "142.250.191.78" in busiest[0] and "192.168.1.42" in busiest[0]
    assert busiest[1] == 3          # both directions counted together
    assert busiest[2] == "731 B"


def test_capture_summary_reports_rate_and_protocols():
    summary = dict(capture.capture_summary(capture.parse_packets(TSHARK), "eth0"))
    assert summary["Packets"] == 7
    assert summary["Bytes"] == "1,055"
    assert summary["Time span"] == "2.00s"
    assert "DNS" in summary["Protocols seen"]
    assert dict(capture.capture_summary([], "eth0"))["Packets"] == 0


def test_packet_rows_truncate_long_info():
    """Info is the last column and is cut so one packet stays on one line.

    2.6 added the Systime column in front of it, so its position and width
    come from PACKET_COLUMNS rather than being written in here twice.
    """
    packets = capture.parse_packets(TSHARK)
    packets[0]["info"] = "x" * 200
    info = capture.packet_rows(packets)[0][capture.PACKET_COLUMNS.index("Info")]
    assert 0 < len(info) <= 70


# ----------------------------------------------------------- command shapes
def test_tshark_capture_is_bounded_by_count_and_duration():
    result = asyncio.run(
        capture.tshark_capture(iface="eth0", count=25, display_filter="dns",
                               seconds=15)
    )
    command = result.command
    assert "-i eth0" in command and "-c 25" in command
    assert "-a duration:15" in command, "a live capture must always stop itself"
    assert "-Y dns" in command


def test_reading_a_pcap_uses_r_and_never_a_duration():
    result = asyncio.run(capture.tshark_capture(pcap="/tmp/x.pcapng", count=10))
    assert "-r /tmp/x.pcapng" in result.command
    assert "duration" not in result.command
    assert "-i" not in result.command


def test_elevation_prefix_is_placed_before_the_tool():
    result = asyncio.run(
        capture.tshark_capture(iface="eth0", prefix=["sudo", "-n"])
    )
    assert result.command.startswith("sudo -n tshark")


def test_tcpdump_capture_is_numeric_and_counted():
    result = asyncio.run(
        capture.tcpdump_capture(iface="eth0", count=5, bpf="port 80", seconds=1)
    )
    assert "-nn" in result.command and "-c 5" in result.command
    assert "port 80" in result.command


def test_tcpdump_line_count_ignores_its_banner():
    output = (
        "tcpdump: verbose output suppressed, use -v for full protocol decode\n"
        "listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes\n"
        "12:00:00.100 IP 10.0.0.1.443 > 10.0.0.2.51234: Flags [P.], length 100\n"
        "12:00:00.200 IP 10.0.0.2.51234 > 10.0.0.1.443: Flags [.], length 0"
    )
    assert capture.tcpdump_line_count(output) == 2
    assert capture.tcpdump_line_count("") == 0


def test_stats_actions_ask_tshark_for_the_right_tap():
    phs = asyncio.run(capture.tshark_stats("io,phs", iface="eth0", seconds=5))
    assert "-q -z io,phs" in phs.command
    conv = asyncio.run(capture.tshark_stats("conv,ip", pcap="/tmp/x.pcapng"))
    assert "-z conv,ip" in conv.command and "-r /tmp/x.pcapng" in conv.command


def test_write_targets_a_file_the_full_wireshark_can_open():
    result = asyncio.run(
        capture.tshark_write(iface="eth0", count=10, path="/tmp/out.pcapng",
                             seconds=5, capture_filter="port 53")
    )
    assert "-w /tmp/out.pcapng" in result.command
    assert "-f port 53" in result.command      # -f is a capture filter, not -Y


# ------------------------------------------------------------- pcap helpers
def test_pcap_path_helpers(tmp_path):
    from pathlib import Path

    assert capture.resolve_pcap("  ~/x.pcapng ") == str(Path.home() / "x.pcapng")
    assert capture.resolve_pcap("   ") == ""
    assert not capture.pcap_exists("")
    real = tmp_path / "c.pcapng"
    real.write_bytes(b"\\xd4\\xc3\\xb2\\xa1")
    assert capture.pcap_exists(str(real))
    details = dict(capture.pcap_details(str(real)))
    assert details["File"] == str(real)
    assert "wireshark" in details["Open in Wireshark"]
    assert capture.default_pcap_path("eth0").endswith(".pcapng")
    assert "eth0" in capture.default_pcap_path("eth0")


# ------------------------------------------------------------- filter help
def test_filter_help_covers_every_category_the_notes_asked_for():
    labels = [row[0].lower() for row in capture.FILTER_ROWS]
    for wanted in ("protocol", "ip address", "port", "content", "combining"):
        assert any(wanted in label for label in labels), wanted
    # Each row gives the tshark form, the tcpdump form and an explanation.
    for row in capture.FILTER_ROWS:
        assert len(row) == 4 and all(str(cell).strip() for cell in row)


def test_filter_help_shows_both_filter_languages():
    by_label = {row[0]: row for row in capture.FILTER_ROWS}
    assert by_label["By port"][1] == "tcp.port == 80"      # tshark display
    assert by_label["By port"][2] == "tcp port 80"         # tcpdump BPF
    assert "ip.addr == 192.168.1.1" == by_label["By IP address"][1]
    assert "host 192.168.1.1" == by_label["By IP address"][2]
    assert 'frame contains "password"' == by_label["By content"][1]
    assert "cannot search text" in by_label["By content"][2]
    assert capture.FILTER_EXAMPLES and all(
        len(pair) == 2 for pair in capture.FILTER_EXAMPLES
    )
    assert "display filter" in capture.FILTER_NOTES.lower()


# -------------------------------------------------------------- permissions
def test_permission_report_always_explains_itself():
    prefix, rows = asyncio.run(capture.permission_report())
    fields = dict(rows)
    assert "Capture permission" in fields
    assert isinstance(fields["Running as root"], bool)
    assert "In 'wireshark' group" in fields
    if prefix is None:
        assert "blocked" in fields["Capture permission"]
    else:
        assert "ready" in fields["Capture permission"]


def test_setup_steps_name_the_group_and_the_capability():
    assert "usermod -aG wireshark" in capture.SETUP_STEPS
    assert "cap_net_raw" in capture.SETUP_STEPS
    assert "log out" in capture.SETUP_STEPS.lower()


# --------------------------------------------------------- pane validation
class _FakePane:
    def __init__(self, **values: str) -> None:
        self._values = values

    def field(self, key: str) -> str:
        return self._values.get(key, "")


def test_pane_requires_an_interface_and_sane_counts():
    try:
        CapturePane._iface(_FakePane(iface=""))
    except ValidationError as exc:
        assert "TOOL CHECK" in str(exc)
    else:
        raise AssertionError("expected ValidationError")
    assert CapturePane._iface(_FakePane(iface="eth0")) == "eth0"
    assert CapturePane._count(_FakePane(count="100")) == 100
    assert CapturePane._count(_FakePane()) == 50           # field default
    for bad in ("abc", "0", "99999"):
        try:
            CapturePane._count(_FakePane(count=bad))
        except ValidationError:
            continue
        raise AssertionError(f"{bad} should have been rejected")


def test_capture_fields_hold_values_not_just_placeholders():
    fields = {f.key: f for f in CapturePane.FIELDS}
    assert fields["count"].value == "50"
    assert fields["iface"].choices == ()        # filled at mount


# -------------------------------------------------------------- themes
def test_all_five_original_themes_survive():
    for name in ("phosphor-green", "amber-phosphor", "ice-cyan",
                 "vhs-magenta", "ember-rust"):
        assert name in PALETTES, name
    assert DEFAULT_THEME == "phosphor-green"


def test_sapphire_ice_uses_the_kwkpass_colours_exactly():
    palette = get_palette("sapphire-ice")
    assert palette.name == "sapphire-ice"
    assert "kwkpass" in palette.label
    assert palette.primary == "#0F52BA"      # Sapphire Blue
    assert palette.secondary == "#0000FF"    # Blue
    assert palette.accent == "#D8EBF2"       # Ice Blue
    assert palette.background == "#000000"   # solid black
    assert palette.name in THEME_NAMES


def test_every_theme_defines_every_colour():
    for name, palette in PALETTES.items():
        for field in ("background", "surface", "panel", "primary", "secondary",
                      "accent", "foreground", "success", "warning", "error",
                      "muted"):
            value = getattr(palette, field)
            assert value.startswith("#") and len(value) == 7, (name, field)
