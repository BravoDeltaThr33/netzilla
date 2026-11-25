"""Tests for netzilla 3.2: the WIFI tab becomes a netscanner-style workbench.

  LIVE AIR      every network's signal, graphed live, until stopped
  SIGNAL        one network, live, until stopped
  LINK HEALTH   this machine's association, live: signal, bitrate, retries
                per interval, missed beacons, roaming
  DEVICES       the LAN tab's sweep/identify on the Wi-Fi interface's subnet
  PORTS         the LAN tab's identifying-port check across those devices
  TRAFFIC       live throughput + this machine's connections over the Wi-Fi
  PACKETS       live capture on the Wi-Fi interface, hosts named by DNS
  EXPORT        all of it as CSV

Radios, raw sockets and tshark aren't available to a test run, so the logic
is fed recorded tool output, and the live views are driven for a fixed
number of ticks (WifiPane.MAX_TICKS) against fake tools on PATH.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from netzilla import __version__
from netzilla.local import capture, devices, flows, lan, netif, wifi, wifitools
from netzilla.validators import ValidationError


def test_version_is_3_2():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (3, 2), __version__


def _fake(dir_path, name, body):
    path = dir_path / name
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(0o755)


# ================================================================ the link
IW_LINK = """Connected to aa:bb:cc:11:22:33 (on wlan0)
\tSSID: HomeNet
\tfreq: 2437
\tRX: 12345678 bytes (54321 packets)
\tTX: 1234567 bytes (5432 packets)
\tsignal: -55 dBm
\trx bitrate: 144.4 MBit/s
\ttx bitrate: 72.2 MBit/s
"""

IW_STATION = """Station aa:bb:cc:11:22:33 (on wlan0)
\tinactive time:\t120 ms
\trx bytes:\t123456
\trx packets:\t1000
\ttx bytes:\t234567
\ttx packets:\t1950
\ttx retries:\t50
\ttx failed:\t3
\trx drop misc:\t5
\tsignal:  \t-55 [-55, -56] dBm
\tsignal avg:\t-56 [-56, -57] dBm
\ttx bitrate:\t72.2 MBit/s
\trx bitrate:\t144.4 MBit/s
\texpected throughput:\t65.0Mbps
\tbeacon loss:\t2
\tconnected time:\t3600 seconds
"""

NMCLI_SHOW = r"""GENERAL.DEVICE:wlan0
GENERAL.TYPE:wifi
GENERAL.HWADDR:AA\:BB\:CC\:11\:22\:33
GENERAL.STATE:100 (connected)
GENERAL.CONNECTION:HomeNet
IP4.ADDRESS[1]:192.168.1.42/24
IP4.GATEWAY:192.168.1.1
IP4.DNS[1]:192.168.1.1
IP4.DNS[2]:8.8.8.8
IP6.ADDRESS[1]:fe80::aaaa:bbbb:cccc:dddd/64
"""

NMCLI_SCAN = (
    r"*:AA\\:BB\\:CC\\:11\\:22\\:33:HomeNet:6:2437 MHz:82:WPA2:270 Mbit/s\n"
    r" :DE\\:AD\\:BE\\:EF\\:00\\:01:Neighbour:1:2412 MHz:55:WPA2:130 Mbit/s\n"
    r" :12\\:34\\:56\\:78\\:9A\\:BC:Cafe5G:36:5180 MHz:47:--:866 Mbit/s\n"
)


def _radio(tmp_path, monkeypatch):
    """Fake iw + nmcli on PATH: joined to HomeNet, three networks in range."""
    _fake(tmp_path, "iw", f'''
if [ "$3" = "link" ]; then printf '%s' "{IW_LINK}"
elif [ "$3" = "station" ]; then printf '%s' "{IW_STATION}"
else exit 1
fi
exit 0
''')
    _fake(tmp_path, "nmcli", f'''
if echo "$*" | grep -q "wifi list"; then printf '{NMCLI_SCAN}'
elif echo "$*" | grep -q "device show"; then printf %s "{NMCLI_SHOW}"
elif [ "$*" = "-t -f DEVICE,TYPE dev" ]; then printf 'wlan0:wifi\\n'
fi
exit 0
''')
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")


def test_parse_iw_link_reads_ssid_freq_signal_and_rates():
    info = wifitools.parse_iw_link(IW_LINK)
    assert info["connected"] is True
    assert info["bssid"] == "aa:bb:cc:11:22:33"
    assert info["ssid"] == "HomeNet"
    assert info["freq"] == 2437
    assert info["channel"] == 6 and info["band"] == "2.4 GHz"
    assert info["signal_dbm"] == -55
    assert info["rx_bitrate"] == 144.4 and info["tx_bitrate"] == 72.2


def test_parse_iw_link_not_connected():
    assert wifitools.parse_iw_link("Not connected.") == {"connected": False}
    assert wifitools.parse_iw_link("") == {"connected": False}


def test_parse_station_dump_and_retry_rate():
    station = wifitools.parse_station_dump(IW_STATION)
    assert station["tx_packets"] == 1950 and station["tx_retries"] == 50
    assert station["beacon_loss"] == 2 and station["connected_s"] == 3600
    assert station["signal_avg"] == -56
    assert station["expected_mbps"] == 65.0
    assert wifitools.retry_rate(station) == pytest.approx(2.5)


def test_retry_rate_needs_both_counters():
    assert wifitools.retry_rate({}) is None
    assert wifitools.retry_rate({"tx_packets": 0, "tx_retries": 5}) is None


def test_parse_nmcli_device_show_unescapes_the_hwaddr_and_collects_dns():
    info = wifitools.parse_nmcli_device_show(NMCLI_SHOW)
    assert info["hwaddr"] == "aa:bb:cc:11:22:33"
    assert info["state"] == "100 (connected)"
    assert info["connection"] == "HomeNet"
    assert info["ipv4"] == ["192.168.1.42/24"]
    assert info["gateway"] == "192.168.1.1"
    assert info["dns"] == ["192.168.1.1", "8.8.8.8"]


def test_link_info_combines_iw_and_nmcli(tmp_path, monkeypatch):
    _radio(tmp_path, monkeypatch)
    info = asyncio.run(wifitools.link_info("wlan0"))
    assert info["link"]["connected"] and info["link"]["ssid"] == "HomeNet"
    assert info["station"]["tx_retries"] == 50
    assert info["device"]["gateway"] == "192.168.1.1"
    assert "iw link" in info["sources"] and "nmcli" in info["sources"]


def test_link_info_with_no_iface():
    assert asyncio.run(wifitools.link_info(""))["link"] == {"connected": False}


def test_link_info_with_neither_tool_installed(monkeypatch):
    monkeypatch.setattr(wifitools, "have", lambda _tool: False)
    info = asyncio.run(wifitools.link_info("wlan0"))
    assert info["link"] == {"connected": False}
    assert info["station"] == {} and info["device"] == {} and info["sources"] == []


def test_link_rows_reads_signal_rate_and_addresses():
    info = {
        "link": wifitools.parse_iw_link(IW_LINK),
        "station": wifitools.parse_station_dump(IW_STATION),
        "device": wifitools.parse_nmcli_device_show(NMCLI_SHOW),
    }
    rows = dict(wifitools.link_rows(info, vendor="Ubiquiti"))
    assert rows["SSID"] == "HomeNet"
    assert "Ubiquiti" in rows["Access point"]
    assert "-55 dBm" in rows["Signal"]
    assert rows["IPv4"] == "192.168.1.42/24"
    assert rows["Gateway"] == "192.168.1.1"
    assert "8.8.8.8" in rows["DNS"]


def test_link_advice_flags_weak_signal_and_heavy_retries():
    link = {"connected": True, "bssid": "aa:bb:cc:11:22:33", "channel": 6,
            "band": "2.4 GHz", "signal_dbm": -82}
    station = {"tx_packets": 800, "tx_retries": 250}          # ~24% retries
    findings = wifitools.link_advice({"link": link, "station": station}, {}, [])
    assert [s for s, _ in findings].count("bad") == 2
    assert sum("sent again" in t for _, t in findings) == 1


def test_link_advice_flags_weak_security_and_channel_overlap():
    link = {"connected": True, "bssid": "aa:bb:cc:11:22:33", "channel": 1,
            "band": "2.4 GHz", "signal_dbm": -50}
    ap = {"security": "WEP", "channel": 1, "band": "2.4 GHz"}
    neighbours = [{"bssid": "de:ad:be:ef:00:01", "channel": 3, "band": "2.4 GHz"}]
    joined = " ".join(t for _, t in wifitools.link_advice(
        {"link": link, "station": {}}, ap, neighbours))
    assert "WEP" in joined and "overlap" in joined


def test_link_advice_when_not_associated_at_all():
    assert wifitools.link_advice({"link": {"connected": False}, "station": {}}, None, []) == [
        ("warn", "Not associated with any access point.")
    ]


def test_advice_rows_labels_each_state():
    rows = wifitools.advice_rows([("bad", "x"), ("warn", "y"), ("info", "z"), ("ok", "w")])
    assert [r[0] for r in rows] == ["PROBLEM", "CHECK", "INFO", "OK"]


# ================================================================== charts
def test_chart_scrolls_in_from_the_right_and_is_labelled():
    lines = wifitools.signal_chart([-80, -60, -40], width=10, height=4)
    assert len(lines) == 5                                  # 4 rows + axis
    assert lines[0].startswith("-30 dBm") and lines[-2].startswith("-90 dBm")
    body = [line.split("┤", 1)[1] for line in lines[:-1]]
    assert all(len(row) == 10 for row in body)
    assert all(row[:7].strip() == "" for row in body)       # padded on the left
    assert body[0][-1] == "▅" or body[0][-1] in "▁▂▃▄▅▆▇█"   # -40 reaches the top row
    assert body[-1][-3:] != "   "                           # every sample shows


def test_chart_keeps_only_the_newest_samples():
    lines = wifitools.chart_lines(list(range(100)), width=20, height=3, floor=0, ceil=100)
    assert all(len(line.split("┤", 1)[1]) == 20 for line in lines[:-1])


def test_chart_draws_a_barely_there_sample():
    lines = wifitools.chart_lines([-89.9], width=3, height=2, floor=-90, ceil=-30)
    assert lines[1].endswith("▁")


def test_nice_ceiling():
    assert [wifitools.nice_ceiling(v) for v in (0, 0.7, 3.2, 17, 230, 520)] == [
        1, 0.8, 4, 20, 250, 600]


def test_rate_chart_scales_to_its_peak():
    lines = wifitools.rate_chart([0.5, 12.4, 3.0], width=5, height=4)
    assert lines[0].lstrip().startswith("15 Mb/s") and lines[-2].lstrip().startswith("0 Mb/s")


def test_signal_state_bands():
    assert [wifitools.signal_state(v) for v in (-50, -70, -85, None)] == ["ok", "warn", "bad", "info"]


# ============================================================== live air
def _ap(ssid, bssid, dbm, channel=6, band="2.4 GHz", in_use=False):
    return {"ssid": ssid, "bssid": bssid, "signal_dbm": dbm, "channel": channel,
            "band": band, "security": "WPA2", "in_use": in_use}


def test_air_watch_keeps_history_and_marks_networks_gone():
    watch = wifitools.AirWatch(gone_after=10)
    watch.update([_ap("Home", "AA", -50, in_use=True), _ap("Next", "BB", -70)], now=100)
    watch.update([_ap("Home", "AA", -52, in_use=True)], now=105)
    watch.update([_ap("Home", "AA", -48, in_use=True)], now=120)
    rows = watch.live_rows(now=120)
    assert rows[0][0] == "* Home" and rows[0][4] == "-48"
    assert rows[-1][0] == "Next" and rows[-1][4] == "gone"
    assert rows[0][7] == "-52 / -48"
    assert watch.focus(now=120)["ssid"] == "Home"


def test_air_watch_focus_by_name_or_strongest():
    watch = wifitools.AirWatch()
    watch.update([_ap("A", "AA", -70), _ap("B", "BB", -40)], now=1)
    assert watch.focus("a", now=1)["ssid"] == "A"
    assert watch.focus("", now=1)["ssid"] == "B"            # strongest, none in use
    assert wifitools.AirWatch().focus() is None


# ============================================================ link, live
def test_link_watch_counts_retries_per_interval_not_since_joining():
    watch = wifitools.LinkWatch()
    base = {"connected": True, "bssid": "aa", "signal_dbm": -50,
            "rx_bitrate": 100.0, "tx_bitrate": 50.0}
    watch.update({"link": base, "station": {"tx_packets": 100_000, "tx_retries": 1_000,
                                            "beacon_loss": 0}}, now=1)
    watch.update({"link": base, "station": {"tx_packets": 100_090, "tx_retries": 1_010,
                                            "beacon_loss": 3}}, now=2)
    assert watch.retry[0] is None
    assert watch.retry[1] == pytest.approx(10.0)            # 10 of 100, this second
    assert watch.beacons_lost == 3
    rows = dict(watch.rows())
    assert rows["Samples"] == 2 and "10.0%" in rows["Retries, last interval / worst"]


def test_link_watch_notices_roaming_and_counter_resets():
    watch = wifitools.LinkWatch()
    watch.update({"link": {"bssid": "aa"}, "station": {"tx_packets": 500, "tx_retries": 50}})
    watch.update({"link": {"bssid": "bb"}, "station": {"tx_packets": 10, "tx_retries": 1}})
    assert len(watch.roams) == 1 and watch.roams[0][1:] == ("aa", "bb")
    assert watch.retry[-1] is None                          # counters went backwards
    columns, rows = watch.export()
    assert columns[0] == "time" and len(rows) == 2


# ======================================================== traffic, live
def _counters(rx, tx):
    return {"wlan0": {"rx_bytes": rx, "tx_bytes": tx, "rx_packets": 0, "tx_packets": 0,
                      "rx_errs": 0, "tx_errs": 0, "rx_drop": 0, "tx_drop": 0}}


def test_rate_watch_turns_counters_into_mbps():
    watch = wifitools.RateWatch("wlan0")
    assert watch.update(_counters(0, 0), now=10.0) is None   # first reading
    rate = watch.update(_counters(1_250_000, 125_000), now=11.0)
    assert rate["rx_mbps"] == pytest.approx(10.0) and rate["tx_mbps"] == pytest.approx(1.0)
    assert watch.down == [pytest.approx(10.0)]
    assert watch.update({}, now=12.0) is None                # interface vanished
    assert "10.00" in dict(watch.rows())["Down now / peak"]


def test_connections_on_keeps_only_the_wifi_addresses():
    conns = [
        {"local_ip": "192.168.1.42", "remote_ip": "1.1.1.1"},
        {"local_ip": "10.8.0.2", "remote_ip": "9.9.9.9"},        # the VPN
        {"local_ip": "0.0.0.0", "remote_ip": ""},
    ]
    assert wifitools.connections_on(conns, {"192.168.1.42"}) == conns[:1]


def test_iface_addresses(monkeypatch):
    async def interfaces():
        return [{"name": "wlan0", "addresses": ["192.168.1.42/24", "fe80::1/64", "junk"]},
                {"name": "eth0", "addresses": ["10.0.0.2/24"]}], "ip"

    monkeypatch.setattr(netif, "interfaces", interfaces)
    assert asyncio.run(wifitools.iface_addresses("wlan0")) == {"192.168.1.42", "fe80::1"}


# ============================================================ iface_subnet
def test_iface_subnet_picks_the_named_interfaces_own_address(monkeypatch):
    async def interfaces():
        return [
            {"name": "eth0", "addresses": ["10.9.9.9/24"]},
            {"name": "wlan0", "addresses": ["192.168.1.42/24", "fe80::1/64"]},
        ], "ip (iproute2)"

    monkeypatch.setattr(netif, "interfaces", interfaces)
    assert asyncio.run(wifitools.iface_subnet("wlan0")) == ("192.168.1.0/24", "")


def test_iface_subnet_narrows_a_network_bigger_than_a_slash_22(monkeypatch):
    async def interfaces():
        return [{"name": "wlan0", "addresses": ["10.0.0.5/8"]}], "ip (iproute2)"

    monkeypatch.setattr(netif, "interfaces", interfaces)
    cidr, note = asyncio.run(wifitools.iface_subnet("wlan0"))
    assert cidr == "10.0.0.0/24" and "too big to sweep" in note


def test_iface_subnet_empty_when_iface_missing_or_not_private(monkeypatch):
    async def interfaces():
        return [{"name": "wlan0", "addresses": ["81.2.69.160/24"]}], "ip (iproute2)"

    monkeypatch.setattr(netif, "interfaces", interfaces)
    assert asyncio.run(wifitools.iface_subnet("wlan0")) == ("", "")
    assert asyncio.run(wifitools.iface_subnet("")) == ("", "")
    assert asyncio.run(wifitools.iface_subnet("does-not-exist")) == ("", "")


# ================================================================== ports
def test_ports_use_the_identify_port_set():
    assert set(wifitools.WORTH_A_LOOK) <= set(devices.PROBE_PORTS)
    results = [{"ip": "192.168.1.9", "name": "plug", "device": "Smart plug", "open": [23, 80]},
               {"ip": "192.168.1.5", "name": "", "device": "", "open": []}]
    rows = wifitools.port_rows(results)
    assert rows[0][3] == 2 and "23 Telnet" in rows[0][4]
    assert rows[1][4] == "none open"
    findings = wifitools.port_findings(results)
    assert len(findings) == 1 and "clear text" in findings[0][3]


# ========================================================= packets + DNS
PACKETS = capture.parse_packets("\n".join([
    "1 14:00:00.000 192.168.1.42 → 192.168.1.1 DNS 74 Standard query 0x1a2b A example.com",
    "2 14:00:00.020 192.168.1.1 → 192.168.1.42 DNS 90 Standard query response 0x1a2b "
    "A example.com A 93.184.216.34",
    "3 14:00:00.050 192.168.1.42 → 93.184.216.34 TCP 74 51234 → 443 [SYN] Seq=0",
    "4 14:00:00.090 93.184.216.34 → 192.168.1.42 TCP 1514 443 → 51234 [ACK] Seq=1",
    "5 14:00:00.200 192.168.1.42 → 192.168.1.1 DNS 74 Standard query 0x2c3d A nope.invalid",
    "6 14:00:00.230 192.168.1.1 → 192.168.1.42 DNS 90 Standard query response 0x2c3d "
    "No such name A nope.invalid",
]))


def test_dns_records_pair_questions_with_answers():
    records = {r["name"]: r for r in wifitools.dns_records(PACKETS)}
    assert records["example.com"]["answers"] == ["93.184.216.34"]
    assert records["example.com"]["queries"] == 1
    assert records["nope.invalid"]["error"] == "No such name"
    assert wifitools.names_from_dns(list(records.values())) == {"93.184.216.34": "example.com"}


def test_traffic_by_host_splits_in_and_out_and_uses_dns_names():
    names = wifitools.names_from_dns(wifitools.dns_records(PACKETS))
    hosts = {h["host"]: h for h in wifitools.traffic_by_host(PACKETS, {"192.168.1.42"}, names)}
    web = hosts["93.184.216.34"]
    assert web["name"] == "example.com" and web["in"] == 1514 and web["out"] == 74
    rows = wifitools.traffic_rows(list(hosts.values()))
    assert rows[0][0] == "93.184.216.34"


# =================================================================== panes
class _PaneBase:
    def __init__(self, fields):
        self._fields = fields
        self.events = []
        self.widgets = []

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
        self.widgets.append(w)

    async def push_error(self, t, m):
        self.events.append(("error", t))

    async def push_warning(self, t, m):
        self.events.append(("warning", t))

    def run_worker(self, *a, **k):
        pass

    def kinds(self):
        return [e[0] for e in self.events]

    def text(self) -> str:
        from rich.console import Console

        def render(r):
            console = Console(width=240, record=True, color_system=None)
            console.print(r)
            return console.export_text()

        shown = [r for kind, r in self.events if kind == "push"]
        shown += [w.content for w in self.widgets if getattr(w, "content", None) is not None]
        return "\n".join(render(r) for r in shown)


class _Panel:
    """Stands in for a mounted Static: remembers what it was last shown."""

    def __init__(self):
        self.content = None
        self.updates = 0

    def update(self, renderable):
        self.content = renderable
        self.updates += 1


def _wifi_pane(fields, ticks=2):
    from netzilla.screens.wifi import WifiPane

    class Pane(_PaneBase, WifiPane):
        MAX_TICKS = ticks
        AIR_EVERY = LINK_EVERY = TRAFFIC_EVERY = 0.01
        RESCAN_EVERY = 0.0

        def __init__(self, fields):
            WifiPane.__init__(self)
            _PaneBase.__init__(self, fields)

        def _panel(self):
            return _Panel()

    return Pane(fields)


def _widget_text(widget) -> str:
    from rich.console import Console

    console = Console(width=240, record=True, color_system=None)
    console.print(widget.content if widget.content is not None else "")
    return console.export_text()


def _all_widget_text(pane) -> str:
    return "\n".join(_widget_text(w) for w in pane.widgets)


def test_wifi_tab_has_every_netscanner_view_with_help():
    from netzilla.help import get_help
    from netzilla.screens.wifi import WifiPane

    keys = [a.key for a in WifiPane.ACTIONS]
    for key in ("scan", "air", "signal", "link", "devices", "ports", "traffic",
                "packets", "export"):
        assert key in keys, key
        assert get_help("WifiPane", key) is not None, key
    assert len(WifiPane._action_rows()) == 2                 # two rows of six


def test_stop_after_is_optional_and_validated():
    assert _wifi_pane({"secs": ""})._limit() is None
    assert _wifi_pane({"secs": "0"})._limit() is None
    assert _wifi_pane({"secs": "30"})._limit() == 30
    for bad in ("abc", "2", "999999"):
        with pytest.raises(ValidationError):
            _wifi_pane({"secs": bad})._limit()


def test_live_views_refuse_without_an_interface():
    pane = _wifi_pane({"iface": ""})
    for view in (pane._link, pane._devices, pane._traffic, pane._packets_live):
        with pytest.raises(ValidationError, match="No wireless interface"):
            asyncio.run(view())


def test_live_air_keeps_updating_in_place(tmp_path, monkeypatch):
    _radio(tmp_path, monkeypatch)
    pane = _wifi_pane({"iface": "wlan0"}, ticks=3)
    asyncio.run(pane._live_air())
    assert pane._air.scans == 3
    # headline, graph, the pick line (4.3), table, channel spectrum (4.0) and
    # 2.4 GHz load
    assert len(pane.widgets) == 6                            # mounted once...
    assert pane.widgets[0].updates == 3                      # ...updated every tick
    shown = _all_widget_text(pane)
    assert "LIVE AIR" in shown and "HomeNet" in shown and "Neighbour" in shown
    assert "now -55 dbm" in shown.lower()                    # own network, from iw link
    assert "┤" in shown                                      # the graph
    home = pane._air.focus()
    assert home["ssid"] == "HomeNet" and home["history"] == [-55, -55, -55]
    assert pane.kinds()[-1] == "push"                        # the closing line


def test_signal_graphs_one_network_live(tmp_path, monkeypatch):
    _radio(tmp_path, monkeypatch)
    pane = _wifi_pane({"iface": "wlan0", "target": "Neighbour"}, ticks=2)
    asyncio.run(pane._signal())
    shown = _all_widget_text(pane)
    assert "neighbour" in shown.lower() and "┤" in shown
    assert "warning" not in pane.kinds()


def test_signal_requires_a_target_and_warns_if_never_seen(tmp_path, monkeypatch):
    with pytest.raises(ValidationError):
        asyncio.run(_wifi_pane({"iface": "wlan0", "target": ""})._signal())
    _radio(tmp_path, monkeypatch)
    pane = _wifi_pane({"iface": "wlan0", "target": "NoSuchNet"}, ticks=2)
    asyncio.run(pane._signal())
    assert "warning" in pane.kinds()


def test_link_pane_warns_when_not_associated(tmp_path, monkeypatch):
    _fake(tmp_path, "iw", 'printf "Not connected.\\n"\nexit 0\n')
    _fake(tmp_path, "nmcli", 'exit 10\n')
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    pane = _wifi_pane({"iface": "wlan0"})
    asyncio.run(pane._link())
    assert "warning" in pane.kinds() and not pane.widgets


def test_link_health_is_live(tmp_path, monkeypatch):
    _radio(tmp_path, monkeypatch)
    pane = _wifi_pane({"iface": "wlan0"}, ticks=3)
    asyncio.run(pane._link())
    assert len(pane._link_watch.samples) == 3
    shown = _all_widget_text(pane)
    assert "HomeNet" in shown and "-55" in shown
    assert "WHILE WATCHING" in shown and "WHAT THIS MEANS" in shown


def test_devices_pane_refuses_when_iface_has_no_address(monkeypatch):
    async def no_subnet(iface):
        return "", ""

    monkeypatch.setattr(wifitools, "iface_subnet", no_subnet)
    with pytest.raises(ValidationError, match="no IPv4 address"):
        asyncio.run(_wifi_pane({"iface": "wlan0"})._devices())


def _one_device(monkeypatch, cidr="192.168.50.0/24", note=""):
    async def subnet(iface):
        assert iface == "wlan0"
        return cidr, note

    async def sweep(target, progress=None):
        assert target == cidr
        return {"live": ["192.168.50.5"], "arp_only": [], "scanned": 254, "cidr": cidr}

    async def context():
        return {"self": {}, "networks": [], "gateways": set(), "default_interface": None}

    async def identify(found, *, context=None, progress=None, use_ssdp=True):
        return [{"ip": "192.168.50.5", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Acme",
                 "mac_kind": "global", "hostname": "kitchen-plug", "device": "Smart plug"}]

    monkeypatch.setattr(wifitools, "iface_subnet", subnet)
    monkeypatch.setattr(lan, "sweep", sweep)
    monkeypatch.setattr(devices, "local_context", context)
    monkeypatch.setattr(devices, "identify", identify)


def test_devices_pane_sweeps_the_wireless_interfaces_own_subnet(monkeypatch):
    _one_device(monkeypatch)
    pane = _wifi_pane({"iface": "wlan0"})
    asyncio.run(pane._devices())
    shown = pane.text()
    assert "192.168.50.0/24" in shown and "Smart plug" in shown
    assert "error" not in pane.kinds() and "warning" not in pane.kinds()
    assert pane._found and pane._names() == {"192.168.50.5": "kitchen-plug (Smart plug)"}


def test_devices_pane_shows_the_narrowing_note(monkeypatch):
    _one_device(monkeypatch, cidr="10.0.0.0/24", note="too big to sweep in one go")
    pane = _wifi_pane({"iface": "wlan0"})
    asyncio.run(pane._devices())
    assert "warning" in pane.kinds()


def test_ports_runs_devices_first_then_flags_telnet(monkeypatch):
    _one_device(monkeypatch)
    asked = []

    async def port_scan(ip, *a, **k):
        asked.append(ip)
        return [23, 80]

    monkeypatch.setattr(devices, "port_scan", port_scan)
    pane = _wifi_pane({"iface": "wlan0"})
    asyncio.run(pane._ports_check())
    assert asked == ["192.168.50.5"]
    shown = pane.text()
    assert "23 Telnet" in shown and "WORTH A SECOND LOOK" in shown


def test_traffic_is_live_and_limited_to_the_wifi(tmp_path, monkeypatch):
    readings = iter([_counters(0, 0), _counters(1_250_000, 250_000),
                     _counters(2_500_000, 500_000), _counters(2_500_000, 500_000)])
    last = {}

    def counters():
        last["value"] = next(readings, last.get("value"))
        return last["value"]

    async def interfaces():
        return [{"name": "wlan0", "addresses": ["192.168.1.42/24"]}], "ip"

    async def snapshot():
        return flows.parse_ss(
            'tcp ESTAB 0 0 192.168.1.42:51234 93.184.216.34:443 users:(("firefox",pid=4,fd=9))\n'
            "tcp ESTAB 0 0 10.8.0.2:40000 9.9.9.9:443\n"), ""

    monkeypatch.setattr(netif, "read_counters", counters)
    monkeypatch.setattr(netif, "interfaces", interfaces)
    monkeypatch.setattr(flows, "snapshot", snapshot)
    pane = _wifi_pane({"iface": "wlan0"}, ticks=3)
    asyncio.run(pane._traffic())
    assert len(pane._rates.down) == 2
    shown = _all_widget_text(pane)
    assert "93.184.216.34" in shown and "firefox" in shown
    assert "9.9.9.9" not in shown                            # that one is the VPN
    assert "DOWNLOAD" in shown


def test_traffic_reports_an_interface_with_no_counters(monkeypatch):
    monkeypatch.setattr(netif, "read_counters", lambda: {"eth0": {}})
    pane = _wifi_pane({"iface": "wlan0"})
    asyncio.run(pane._traffic())
    assert "error" in pane.kinds()


class _FakeLive:
    """capture.LiveCapture without tshark: replays PACKETS."""

    def __init__(self, iface, display_filter="", prefix=None, keep=300):
        self.iface, self.display_filter = iface, display_filter
        self.packets, self.total, self.stopped = [], 0, False

    async def start(self):
        return ""

    async def packets_as_they_arrive(self, idle=0.5):
        for packet in PACKETS:
            await asyncio.sleep(0.02)
            self.packets.append(packet)
            self.total += 1
            yield True

    async def stop(self):
        self.stopped = True
        return ""


def test_packets_is_live_and_names_hosts_from_dns(monkeypatch):
    made = []

    def live(*a, **k):
        made.append(_FakeLive(*a, **k))
        return made[-1]

    async def permitted(self):
        return []

    async def interfaces():
        return [{"name": "wlan0", "addresses": ["192.168.1.42/24"]}], "ip"

    from netzilla.screens.wifi import WifiPane

    monkeypatch.setattr(capture, "LiveCapture", live)
    monkeypatch.setattr(WifiPane, "_permission", permitted)
    monkeypatch.setattr(netif, "interfaces", interfaces)
    pane = _wifi_pane({"iface": "wlan0", "filter": ""}, ticks=None)
    pane.PACKET_REPAINT = 0.03
    asyncio.run(pane._packets_live())
    assert made[0].stopped and made[0].iface == "wlan0"
    assert len(pane._packets) == 6
    shown = _all_widget_text(pane)
    assert "example.com" in shown and "PACKETS PER SECOND" in shown
    assert "DNS LOOKUPS" in shown


def test_packets_stops_when_permission_is_refused(monkeypatch):
    async def refused(self):
        return None

    from netzilla.screens.wifi import WifiPane

    monkeypatch.setattr(WifiPane, "_permission", refused)
    monkeypatch.setattr(capture, "LiveCapture", lambda *a, **k: pytest.fail("started"))
    asyncio.run(_wifi_pane({"iface": "wlan0"})._packets_live())


def test_packets_rejects_a_line_pasted_from_filter_help():
    with pytest.raises(ValidationError, match="FILTER HELP"):
        asyncio.run(_wifi_pane({"iface": "wlan0", "filter": "DNS only: dns"})._packets_live())


def test_export_needs_something_then_writes_csv(tmp_path, monkeypatch):
    pane = _wifi_pane({"iface": "wlan0"})
    pane.EXPORT_BASE = tmp_path
    with pytest.raises(ValidationError, match="Nothing to export"):
        asyncio.run(pane._export())
    pane._air.update([_ap("Home", "AA", -50, in_use=True)])
    pane._packets = PACKETS
    pane._dns = wifitools.dns_records(PACKETS)
    asyncio.run(pane._export())
    written = sorted(p.name for p in tmp_path.rglob("*.csv"))
    assert written == ["dns.csv", "networks.csv", "packets.csv"]
    assert "Home" in next(tmp_path.rglob("networks.csv")).read_text()
