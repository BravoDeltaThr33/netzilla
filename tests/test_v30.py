"""Tests for netzilla 3.0: the WIFI (RF analysis) and FLOW (traffic) modules.

Both are built as pure functions over the output of tools that need a radio,
root, or a live socket to produce for real — so the tests feed them recorded
output and check the parsing, the channel maths, the aggregation, the service
naming and the blacklist matching, none of which need any of that.
"""

from __future__ import annotations

from netzilla import __version__
from netzilla.validators import ValidationError
from netzilla.local import flows, wifi


# ------------------------------------------------------------------ version
def test_version_is_3_0():
    """A major version: the two new tabs arrived here and stay."""
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (3, 0), __version__


# ============================================================ WIFI: bands
def test_channel_and_band_from_frequency():
    assert wifi.channel_of(2412) == 1
    assert wifi.channel_of(2437) == 6
    assert wifi.channel_of(2462) == 11
    assert wifi.channel_of(2484) == 14
    assert wifi.channel_of(5180) == 36
    assert wifi.channel_of(5745) == 149
    assert wifi.band_of(2412) == "2.4 GHz"
    assert wifi.band_of(5180) == "5 GHz"
    assert wifi.band_of(6115) == "6 GHz"


def test_overlap_is_the_classic_2_4ghz_story():
    assert wifi.overlaps_24(1, 3)          # 2 channels apart -> overlap
    assert wifi.overlaps_24(6, 9)
    assert not wifi.overlaps_24(1, 6)      # the whole reason 1/6/11 exist
    assert not wifi.overlaps_24(6, 11)
    assert not wifi.overlaps_24(1, 11)
    assert not wifi.overlaps_24(6, 6)      # a channel does not overlap itself


# ============================================================ WIFI: signal
def test_percent_to_dbm_is_labelled_and_monotonic():
    assert wifi.pct_to_dbm(100) == -50
    assert wifi.pct_to_dbm(0) == -100
    assert wifi.pct_to_dbm(50) == -75
    assert wifi.pct_to_dbm(200) == -50     # clamped
    assert wifi.signal_label(-45) == "excellent"
    assert wifi.signal_label(-67) == "fair"
    assert wifi.signal_label(-85) == "very weak"


def test_sparkline_scales_within_a_fixed_window():
    line = wifi.sparkline([-90, -75, -60, -45, -30])
    assert len(line) == 5
    assert line[0] == "▁" and line[-1] == "█"
    assert wifi.sparkline([]) == ""
    # A flat strong signal is not drawn the same as a flat weak one.
    assert wifi.sparkline([-40, -40])[0] != wifi.sparkline([-85, -85])[0]


# ============================================================ WIFI: nmcli
NMCLI = "\n".join([
    r"*:AA\:BB\:CC\:11\:22\:33:HomeNet:6:2437 MHz:82:WPA2:270 Mbit/s",
    r" :DE\:AD\:BE\:EF\:00\:01:Neighbour 2.4:1:2412 MHz:55:WPA2 WPA3:130 Mbit/s",
    r" :12\:34\:56\:78\:9A\:BC:CoffeeShop:36:5180 MHz:47:--:866 Mbit/s",
    r" :00\:11\:22\:33\:44\:55::11:2462 MHz:30:WPA1:54 Mbit/s",
])


def test_nmcli_scan_parses_every_field_including_escaped_bssids():
    aps = wifi.parse_nmcli_scan(NMCLI)
    assert len(aps) == 4
    home = aps[0]
    assert home["bssid"] == "AA:BB:CC:11:22:33"
    assert home["ssid"] == "HomeNet"
    assert home["channel"] == 6
    assert home["band"] == "2.4 GHz"
    assert home["signal_pct"] == 82
    assert home["signal_dbm"] == wifi.pct_to_dbm(82)
    assert home["security"] == "WPA2"
    assert home["rate_mbps"] == 270
    assert home["in_use"] is True


def test_nmcli_hidden_ssid_and_open_and_wep():
    aps = wifi.parse_nmcli_scan(NMCLI)
    assert aps[2]["security"] == "Open"          # "--"
    assert aps[3]["security"] == "WPA"           # "WPA1"
    assert aps[3]["ssid"] == "<hidden>"          # empty SSID field
    assert aps[1]["security"] == "WPA3"          # WPA2+WPA3 advertised -> WPA3


def test_a_real_colon_in_an_ssid_survives_the_split():
    line = r" :AA\:BB\:CC\:DD\:EE\:FF:My\:Network:6:2437 MHz:60:WPA2:130 Mbit/s"
    ap = wifi.parse_nmcli_scan(line)[0]
    assert ap["ssid"] == "My:Network"
    assert ap["bssid"] == "AA:BB:CC:DD:EE:FF"


# ============================================================ WIFI: iw
IW_SCAN = """BSS aa:bb:cc:11:22:33(on wlan0) -- associated
	freq: 2437
	signal: -42.00 dBm
	SSID: HomeNet
	DS Parameter set: channel 6
	RSN:	 * Version: 1
	supported rates: 6.0 9.0 12.0 54.0 Mbps
BSS de:ad:be:ef:00:01(on wlan0)
	freq: 5180
	signal: -71.00 dBm
	SSID: FarAway
	* primary channel: 36
	supported rates: 6.0 54.0 866.0 Mbps
"""


def test_iw_scan_gives_exact_dbm_and_channel():
    aps = wifi.parse_iw_scan(IW_SCAN)
    assert len(aps) == 2
    home = aps[0]
    assert home["bssid"] == "AA:BB:CC:11:22:33"
    assert home["signal_dbm"] == -42
    assert home["channel"] == 6
    assert home["security"] == "WPA2"          # RSN present
    assert home["in_use"] is True
    assert aps[1]["channel"] == 36
    assert aps[1]["signal_dbm"] == -71
    assert aps[1]["security"] == "Open"


# ================================================= WIFI: congestion / advice
def test_congestion_counts_overlap_not_just_exact_channel():
    aps = [
        {"band": "2.4 GHz", "channel": 1, "signal_dbm": -50},
        {"band": "2.4 GHz", "channel": 2, "signal_dbm": -60},   # overlaps 1
        {"band": "2.4 GHz", "channel": 3, "signal_dbm": -65},   # overlaps 1 and 6
        {"band": "2.4 GHz", "channel": 11, "signal_dbm": -55},
        {"band": "5 GHz", "channel": 36, "signal_dbm": -55},    # ignored for 2.4
    ]
    congestion = wifi.congestion_by_channel(aps)
    assert congestion[1] == 3          # ch 1 itself + ch 2 + ch 3
    assert congestion[6] == 2          # ch 2 and ch 3 both bleed into 6
    assert congestion[11] == 1         # ch 11 itself, nothing else near it
    best, why = wifi.recommend_channel_24(aps)
    assert best == 11                  # the clear winner here
    assert "do not overlap" in why


def test_recommendation_when_there_is_no_2_4ghz():
    best, why = wifi.recommend_channel_24(
        [{"band": "5 GHz", "channel": 36, "signal_dbm": -50}]
    )
    assert best == 0 and "No 2.4 GHz" in why


def test_pick_ap_by_bssid_or_ssid():
    aps = wifi.parse_nmcli_scan(NMCLI)
    assert wifi.pick_ap(aps, "aa:bb:cc:11:22:33")["ssid"] == "HomeNet"
    assert wifi.pick_ap(aps, "coffeeshop")["channel"] == 36
    assert wifi.pick_ap(aps, "nope") is None


# ============================================================ FLOW: ss parse
SS = """Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   ESTAB  0      0      192.168.1.5:51234  142.250.191.78:443 users:(("firefox",pid=42,fd=90))
tcp   ESTAB  0      0      192.168.1.5:22     192.168.1.9:55010  users:(("sshd",pid=7,fd=3))
udp   UNCONN 0      0      192.168.1.5:68     0.0.0.0:*
tcp   ESTAB  0      0      192.168.1.5:40012  10.0.0.5:445       users:(("smbclient",pid=99,fd=5))
tcp   ESTAB  0      0      [2001:db8::5]:5000 [2606:4700::1111]:443 users:(("curl",pid=8,fd=3))
"""


def test_ss_parses_addresses_ports_state_and_process():
    conns = flows.parse_ss(SS)
    assert len(conns) == 5
    first = conns[0]
    assert first["proto"] == "tcp"
    assert first["local_ip"] == "192.168.1.5" and first["local_port"] == 51234
    assert first["remote_ip"] == "142.250.191.78" and first["remote_port"] == 443
    assert first["state"] == "ESTAB"
    assert first["process"] == "firefox" and first["pid"] == 42


def test_ss_handles_ipv6_bracket_form():
    conns = flows.parse_ss(SS)
    v6 = conns[-1]
    assert v6["local_ip"] == "2001:db8::5" and v6["local_port"] == 5000
    assert v6["remote_ip"] == "2606:4700::1111" and v6["remote_port"] == 443


def test_external_vs_lan_classification():
    assert flows.is_external("142.250.191.78")
    assert flows.is_external("2606:4700::1111")
    assert not flows.is_external("192.168.1.9")
    assert not flows.is_external("10.0.0.5")
    assert not flows.is_external("127.0.0.1")
    assert not flows.is_external("not-an-ip")


def test_service_naming():
    assert flows.service_for(443) == "HTTPS"
    assert flows.service_for(22) == "SSH"
    assert flows.service_for(51820) == "WireGuard"
    assert flows.service_for(50000) == "ephemeral"
    assert flows.service_for(1234) == "registered"


def test_top_talkers_group_by_remote_host():
    conns = flows.parse_ss(SS)
    hosts = flows.by_remote_host(conns)
    # UDP UNCONN is not established, so it is excluded.
    ips = [h["remote_ip"] for h in hosts]
    assert "142.250.191.78" in ips
    assert "0.0.0.0" not in ips
    google = next(h for h in hosts if h["remote_ip"] == "142.250.191.78")
    assert google["external"] is True
    assert 443 in google["ports"]
    assert "firefox" in google["processes"]
    lan = next(h for h in hosts if h["remote_ip"] == "192.168.1.9")
    assert lan["external"] is False


def test_service_breakdown_counts_by_the_well_known_side():
    conns = flows.parse_ss(SS)
    services = {s["service"]: s["count"] for s in flows.by_service(conns)}
    assert services.get("HTTPS") == 2       # firefox + curl, both out to :443
    assert services.get("SMB") == 1         # out to :445
    # The inbound SSH connection has an ephemeral *remote* port; the service
    # is the local :22, which flow_service picks up.
    assert services.get("SSH") == 1


def test_the_service_is_taken_from_whichever_end_is_well_known():
    inbound_ssh = {"remote_port": 55010, "local_port": 22}
    outbound_https = {"remote_port": 443, "local_port": 51234}
    assert flows.flow_service(inbound_ssh) == "SSH"
    assert flows.flow_service(outbound_https) == "HTTPS"


def test_summary_counts_line_up():
    summary = dict(flows.summary(flows.parse_ss(SS)))
    assert summary["Sockets"] == 5
    assert summary["Established"] == 4
    assert summary["External hosts"] == 2   # google v4 + cloudflare v6


# ============================================================ FLOW: blacklist
def test_blacklist_matches_ip_and_cidr_and_ignores_comments():
    blacklist = flows.load_blacklist(
        "# known-bad\n"
        "142.250.191.78\n"
        "10.0.0.0/8   # internal range\n"
        "\n"
        "not-an-ip-skip-me\n"
    )
    assert len(blacklist) == 2
    hits = flows.blacklist_hits(flows.parse_ss(SS), blacklist)
    hit_ips = {h["remote_ip"] for h in hits}
    assert "142.250.191.78" in hit_ips       # exact IP
    assert "10.0.0.5" in hit_ips             # inside the CIDR
    assert "192.168.1.9" not in hit_ips


def test_empty_blacklist_flags_nothing():
    assert flows.blacklist_hits(flows.parse_ss(SS), []) == []


# ============================================================ FLOW: netstat
NETSTAT = """Proto Recv-Q Send-Q Local Address    Foreign Address   State  PID/Program name
tcp   0      0      192.168.1.5:51234 142.250.191.78:443 ESTABLISHED 42/firefox
udp   0      0      192.168.1.5:68    0.0.0.0:*                       -
"""


def test_netstat_fallback_parses_when_ss_is_absent():
    conns = flows._parse_netstat(NETSTAT)
    assert len(conns) == 2
    assert conns[0]["remote_ip"] == "142.250.191.78"
    assert conns[0]["state"] == "ESTAB"
    assert conns[0]["process"] == "firefox"


def test_connection_rows_are_shaped_for_the_table():
    rows = flows.connection_rows(flows.parse_ss(SS))
    assert len(rows) == 5
    assert len(rows[0]) == 6
    assert rows[0][0] == "TCP"
    assert rows[0][3] == "HTTPS"


# ==================================================== the panes themselves
# The modules above are pure; these drive the actual pane methods against fake
# nmcli / ss binaries, so the glue (parsing -> render, filtering, the geo
# lookup, the blacklist file path) is covered too, without Textual.
import asyncio
import os
from pathlib import Path


def _fake(dir_path, name, body):
    path = dir_path / name
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(0o755)


class _PaneBase:
    def __init__(self, fields):
        self._fields = fields
        self.events = []
        self.widgets = []

    @property
    def palette(self):
        from netzilla.themes import get_palette
        return get_palette("amber")

    @property
    def services(self):
        return getattr(self, "_services", None)

    def field(self, key):
        return self._fields.get(key, "")

    def set_choices(self, *a, **k):
        pass

    async def begin(self, m="…"):
        self.events.append(("begin",))

    def progress(self, m):
        pass

    async def finish(self, m=""):
        self.events.append(("finish",))

    async def push(self, r):
        self.events.append(("push",))

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


NMCLI_BODY = r'''
if echo "$*" | grep -q "wifi list"; then
  printf '*:AA\\:BB\\:CC\\:11\\:22\\:33:HomeNet:6:2437 MHz:82:WPA2:270 Mbit/s\n'
  printf ' :DE\\:AD\\:BE\\:EF\\:00\\:01:Neighbour:1:2412 MHz:55:WPA2:130 Mbit/s\n'
  printf ' :12\\:34\\:56\\:78\\:9A\\:BC:Cafe5G:36:5180 MHz:47:--:866 Mbit/s\n'
elif [ "$*" = "-t -f DEVICE,TYPE dev" ]; then
  printf 'wlp3s0:wifi\nlo:loopback\n'
fi
exit 0
'''

SS_BODY = (
    'printf "tcp ESTAB 0 0 192.168.1.5:51234 142.250.191.78:443 '
    'users:((\\"firefox\\",pid=42,fd=90))\\n'
    'tcp ESTAB 0 0 192.168.1.5:40012 10.0.0.5:445 '
    'users:((\\"smbclient\\",pid=9,fd=5))\\n"'
)


def test_wifi_pane_scans_and_maps_channels(tmp_path, monkeypatch):
    from netzilla.screens.wifi import WifiPane

    _fake(tmp_path, "nmcli", NMCLI_BODY)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    class Pane(_PaneBase, WifiPane):
        def __init__(self, fields):
            WifiPane.__init__(self)
            _PaneBase.__init__(self, fields)

    async def go():
        pane = Pane({"iface": "wlp3s0"})
        aps, backend = await pane._scan("auto")
        assert len(aps) == 3 and backend == "nmcli"
        assert "push" in pane.kinds()
        pane.events.clear()
        await pane._channels()               # reuses the cached scan
        assert pane.kinds().count("push") >= 3

    asyncio.run(go())


def test_wifi_signal_requires_a_target():
    from netzilla.screens.wifi import WifiPane

    class Pane(_PaneBase, WifiPane):
        def __init__(self, fields):
            WifiPane.__init__(self)
            _PaneBase.__init__(self, fields)

    async def go():
        pane = Pane({"iface": "wlp3s0", "target": ""})
        try:
            await pane._signal()
            assert False, "should have refused"
        except ValidationError:
            pass

    asyncio.run(go())


def test_flow_pane_reads_and_filters_connections(tmp_path, monkeypatch):
    from netzilla.screens.flows import FlowPane

    _fake(tmp_path, "ss", SS_BODY)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    class Pane(_PaneBase, FlowPane):
        def __init__(self, fields):
            FlowPane.__init__(self)
            _PaneBase.__init__(self, fields)

    async def go():
        pane = Pane({"filter": ""})
        await pane._connections()
        assert "push" in pane.kinds() and "error" not in pane.kinds()

        # The host filter narrows the set.
        raw = flows.parse_ss(
            'tcp ESTAB 0 0 192.168.1.5:51234 142.250.191.78:443 '
            'users:(("firefox",pid=42,fd=90))'
        )
        assert len(Pane({"filter": "firefox"})._filtered(raw)) == 1
        assert len(Pane({"filter": "chrome"})._filtered(raw)) == 0

        # Talkers with no services object must not crash on the geo lookup.
        talker = Pane({"filter": ""})
        await talker._talkers()
        assert "error" not in talker.kinds()

    asyncio.run(go())


def test_flow_blacklist_reads_a_file_and_flags(tmp_path, monkeypatch):
    from netzilla.screens.flows import FlowPane

    _fake(tmp_path, "ss", SS_BODY)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    blacklist = tmp_path / "bad.txt"
    blacklist.write_text("142.250.191.78\n10.0.0.0/8\n")

    class Pane(_PaneBase, FlowPane):
        def __init__(self, fields):
            FlowPane.__init__(self)
            _PaneBase.__init__(self, fields)

    async def go():
        empty = Pane({"blacklist": ""})
        try:
            await empty._blacklist()
            assert False
        except ValidationError:
            pass

        pane = Pane({"blacklist": str(blacklist), "filter": ""})
        await pane._blacklist()
        assert "push" in pane.kinds() and "error" not in pane.kinds()

    asyncio.run(go())


def test_flow_geo_parses_ip_api_shape():
    from netzilla.screens.flows import FlowPane

    class FakeResult:
        ok = True
        data = {"as": "AS15169 Google LLC", "isp": "Google LLC",
                "city": "Mountain View", "countryCode": "US"}

    class FakeApi:
        async def lookup(self, services, ip):
            return FakeResult()

    class Pane(_PaneBase, FlowPane):
        def __init__(self):
            FlowPane.__init__(self)
            _PaneBase.__init__(self, {})

    async def go():
        import netzilla.screens.flows as module
        pane = Pane()
        pane._services = object()
        original = module.ip_api
        module.ip_api = FakeApi()
        try:
            asn, org, location = await pane._geo("142.250.191.78")
        finally:
            module.ip_api = original
        assert asn == "AS15169"
        assert org == "Google LLC"
        assert location == "Mountain View, US"

    asyncio.run(go())


def test_both_new_tabs_are_registered_with_help():
    from netzilla.app import TABS
    from netzilla.help import get_help
    from netzilla.screens.flows import FlowPane
    from netzilla.screens.wifi import WifiPane

    ids = [t[0] for t in TABS]
    assert "wifi" in ids and "flow" in ids
    for pane in (WifiPane, FlowPane):
        for action in pane.ACTIONS:
            assert get_help(pane.__name__, action.key), f"{pane.__name__}.{action.key}"
