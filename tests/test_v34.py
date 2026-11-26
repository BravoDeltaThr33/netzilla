"""Tests for netzilla 3.4.

  * REFRESH EVERY: every live view's update interval is a box on its tab
    (WIFI, INT, FLOW, CAPTURE, LAN), blank = that view's default
  * data is coloured by what it means, the same way on every tab
    (colours.py): signal/quality on one five-colour scale, bands, a colour per
    channel, pink SSIDs and yellow <hidden>, addresses, states, levels…
  * LIVE AIR's HISTORY in quadrants (every terminal draws them), without
    block outlines; outlines stay everywhere else
  * RANGE reads "-62 / -48"
"""

from __future__ import annotations

import asyncio
import unicodedata

import pytest
from rich.text import Text

from netzilla import __version__, colours
from netzilla.colours import SEMANTIC, channel_colour, style_cell
from netzilla.config import Config
from netzilla.local import wifi, wifitools
from netzilla.render import block_text, kv_panel, table_panel
from netzilla.themes import get_palette
from netzilla.validators import ValidationError


def test_version_is_3_4():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (3, 4), __version__


def _colour(text: Text, fragment: str | None = None) -> str:
    """The colour a fragment of a styled cell is drawn in (last span wins,
    as in Rich); the whole cell's base style when no span covers it."""
    target = fragment or text.plain
    start = text.plain.index(target)
    colour = str(text.style)
    for span in text.spans:
        if span.start <= start and span.end >= start + len(target):
            colour = str(span.style)
    return colour.lower()


def cell(column, value):
    return style_cell(column, value, "#ffffff", "#777777")


# ================================================================ colours
@pytest.mark.parametrize("label, key", [
    ("excellent", "excellent"), ("good", "good"), ("fair", "fair"),
    ("weak", "weak"), ("very weak", "very weak"),
])
def test_quality_words_use_the_five_colour_scale(label, key):
    assert _colour(cell("Quality", label)) == SEMANTIC[key]


def test_signal_and_quality_are_coloured_together():
    for dbm in range(-95, -25, 3):
        signal = cell("Signal", f"{dbm} dBm")
        quality = cell("Quality", wifi.signal_label(dbm))
        assert _colour(signal) == _colour(quality), dbm


def test_the_scale_is_the_asked_for_hues():
    assert SEMANTIC["excellent"].startswith("#5f")          # green
    assert _colour(cell("Signal", "-45 dBm")) == SEMANTIC["excellent"]
    assert _colour(cell("Signal", "-55 dBm")) == SEMANTIC["good"]
    assert _colour(cell("Signal", "-65 dBm")) == SEMANTIC["fair"]
    assert _colour(cell("Signal", "-75 dBm")) == SEMANTIC["weak"]
    assert _colour(cell("Signal", "-85 dBm")) == SEMANTIC["very weak"]


def test_bands():
    assert _colour(cell("Band", "2.4 GHz")) == SEMANTIC["band_24"]
    assert _colour(cell("Band", "5 GHz")) == SEMANTIC["band_5"]
    assert _colour(cell("Band", "6 GHz")) == SEMANTIC["band_6"]
    # ...and the same colours wherever a band appears inside other text
    assert _colour(cell("Channel / band", "44 · 5 GHz"), "5 GHz") == SEMANTIC["band_5"]


def test_ssids_are_pink_and_hidden_ones_yellow():
    assert _colour(cell("SSID", "Maple-House")) == SEMANTIC["ssid"]
    assert _colour(cell("SSID", "* Maple-House-5G")) == SEMANTIC["ssid"]
    assert _colour(cell("SSID", "<hidden>")) == SEMANTIC["hidden"]
    assert _colour(cell("Detail", "the strongest is <hidden>"), "<hidden>") == SEMANTIC["hidden"]


def test_every_channel_has_its_own_colour():
    common = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 36, 40, 44, 48, 149, 153, 157, 161, 165]
    colours_seen = [channel_colour(ch) for ch in common]
    assert len(set(colours_seen)) == len(common)
    assert _colour(cell("Ch", "6")) == channel_colour(6)
    assert _colour(cell("Channel", "ch 11  ← best")) == channel_colour(11)
    assert _colour(cell("Ch", 44)) == channel_colour(44)


def test_addresses_are_picked_out_anywhere():
    text = cell("Info", "Who has 192.168.1.60? Tell 192.168.1.1 from aa:bb:cc:dd:ee:ff")
    assert _colour(text, "192.168.1.60") == SEMANTIC["ip"]
    assert _colour(text, "aa:bb:cc:dd:ee:ff") == SEMANTIC["mac"]
    assert _colour(cell("Source", "fe80::1")) == SEMANTIC["ip"]
    assert not cell("Systime", "14:03:22.918").spans         # a clock isn't IPv6


@pytest.mark.parametrize("column, value, key", [
    ("Security", "Open", "very weak"), ("Security", "WEP (insecure)", "very weak"),
    ("Security", "WPA2 (Enterprise)", "good"), ("Security", "WPA2 WPA3", "excellent"),
    ("State", "ESTAB", "excellent"), ("State", "LISTEN", "good"),
    ("Level", "PROBLEM", "very weak"), ("Level", "CHECK", "fair"), ("Level", "OK", "excellent"),
    ("RTT", "1.9 ms", "excellent"), ("RTT", "206.0 ms", "very weak"), ("RTT", "local", "excellent"),
    ("Status", "Major outage", "very weak"), ("Status", "operational", "excellent"),
    ("Grade", "A+", "excellent"), ("Grade", "F", "very weak"),
    ("Errors", "0", "excellent"), ("Errors", "12", "weak"),
])
def test_meaningful_columns(column, value, key):
    assert _colour(cell(column, value)) == SEMANTIC[key]


def test_empties_are_muted_and_unknown_columns_left_alone():
    assert _colour(cell("Anything", "—")) == "#777777"
    assert _colour(cell("Notes", "plain words")) == "#ffffff"
    assert cell("Anything", True) is None                  # booleans keep YES/no


def test_tables_and_kv_panels_colour_by_column_and_key():
    palette = get_palette("amber-phosphor")
    panel = table_panel(palette, "x", ["SSID", "Band", "Ch"], [["Home", "5 GHz", 36]])
    ssid, band, ch = (col._cells[0] for col in panel.renderable.columns)
    assert _colour(ssid) == SEMANTIC["ssid"] and _colour(band) == SEMANTIC["band_5"]
    assert _colour(ch) == channel_colour(36)
    kv = kv_panel(palette, "x", [("Security", "Open")])
    value = kv.renderable.columns[1]._cells[0]
    assert _colour(value) == SEMANTIC["very weak"]


def test_deep_scan_rows_are_coloured_like_the_request():
    aps = [
        {"in_use": True, "bssid": "BA:5E:71:2C:04:F0", "ssid": "WLAN52", "channel": 44,
         "band": "5 GHz", "signal_dbm": -48, "security": "WPA2", "rate_mbps": 540},
        {"in_use": False, "bssid": "BA:5E:71:25:04:F0", "ssid": "<hidden>", "channel": 6,
         "band": "2.4 GHz", "signal_dbm": -77, "security": "WPA2 (Enterprise)", "rate_mbps": 260},
    ]
    columns = ["SSID", "BSSID", "AP vendor", "Band", "Ch", "Signal", "Quality",
               "Security", "Rate"]
    panel = table_panel(get_palette("phosphor-green"), "Access points", columns,
                        _rows(aps))
    cols = {c.header: c._cells for c in panel.renderable.columns}
    assert _colour(cols["SSID"][0]) == SEMANTIC["ssid"]
    assert _colour(cols["SSID"][1]) == SEMANTIC["hidden"]
    assert _colour(cols["BAND"][0]) == SEMANTIC["band_5"]
    assert _colour(cols["BAND"][1]) == SEMANTIC["band_24"]
    assert _colour(cols["CH"][0]) != _colour(cols["CH"][1])
    assert _colour(cols["SIGNAL"][0]) == _colour(cols["QUALITY"][0]) == SEMANTIC["excellent"]
    assert _colour(cols["SIGNAL"][1]) == _colour(cols["QUALITY"][1]) == SEMANTIC["weak"]


def _rows(aps):
    from netzilla.screens.wifi import WifiPane

    class Pane(WifiPane):
        pass

    return Pane._ap_rows(Pane(), aps)


# ======================================================= history column
# 3.4 drew HISTORY in quadrants; since 3.5 it shows the dBm readings
# themselves (test_v35.py). Outlines still stay off it.


def test_history_has_no_outlines_but_bars_keep_them():
    from test_v32 import _Panel
    from test_v33 import _air, _live_pane

    pane = _air(_live_pane())
    table = _Panel()
    import time as _time

    real = _time.time
    _time.time = lambda: 1040.0
    try:
        pane._render_air(_Panel(), _Panel(), table, _Panel(), "", "nmcli", 10.0, "")
    finally:
        _time.time = real
    columns = table.content.renderable.columns
    history = columns[6]._cells[0]
    bar = columns[5]._cells[0]
    assert "▕" not in history.plain and not any("underline" in str(s.style) for s in history.spans)
    assert "▕" in bar.plain
    assert not any(0x1FB00 <= ord(c) <= 0x1FBFF for c in history.plain)


def test_block_text_can_skip_outlines():
    assert block_text("██", "green", "black", outline=False).plain == "██"
    assert block_text("██", "green", "black").plain == "▕▕"


def test_range_reads_low_slash_high():
    assert wifitools.range_text([-48, -62, -55]) == "-62 / -48"
    assert wifitools.range_text([]) == "—"
    assert _colour(cell("Range", "-62 / -48"), "-62") == SEMANTIC["fair"]
    assert _colour(cell("Range", "-62 / -48"), "-48") == SEMANTIC["excellent"]


# ========================================================== REFRESH EVERY
LIVE_TABS = ["WifiPane", "InterfacesPane", "FlowPane", "CapturePane", "LANPane"]


def _pane_class(name):
    from netzilla.app import TABS

    return next(cls for _t, _l, cls in TABS if cls.__name__ == name)


@pytest.mark.parametrize("name", LIVE_TABS)
def test_every_live_tab_has_a_refresh_box(name):
    keys = [f.key for f in _pane_class(name).FIELDS]
    assert "every" in keys, name


def test_only_live_tabs_have_one():
    from netzilla.app import TABS

    with_box = {cls.__name__ for _t, _l, cls in TABS
                if any(f.key == "every" for f in getattr(cls, "FIELDS", ()))}
    assert with_box == set(LIVE_TABS)


def _bare(cls, fields):
    class Pane(cls):
        def field(self, key):
            return fields.get(key, "")

    return Pane()


def test_refresh_every_is_validated():
    from netzilla.screens.wifi import WifiPane

    assert _bare(WifiPane, {})._every(3.0) == 3.0
    assert _bare(WifiPane, {"every": "0.5"})._every(3.0) == 0.5
    assert _bare(WifiPane, {"every": "10"})._every(3.0) == 10.0
    for bad in ("fast", "0.1", "99999"):
        with pytest.raises(ValidationError, match="REFRESH EVERY"):
            _bare(WifiPane, {"every": bad})._every(3.0)
    with pytest.raises(ValidationError, match="between 1"):
        _bare(WifiPane, {"every": "0.5"})._every(3.0, low=1.0)


@pytest.mark.parametrize("view, default", [
    ("_live_air", 3.0), ("_signal", 3.0), ("_link", 1.0), ("_traffic", 1.0),
])
def test_wifi_live_views_use_the_box(view, default, monkeypatch, tmp_path):
    from test_v32 import _radio, _wifi_pane
    from netzilla.local import netif

    _radio(tmp_path, monkeypatch)
    monkeypatch.setattr(netif, "read_counters", lambda: {"wlan0": {
        "rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0,
        "rx_errs": 0, "tx_errs": 0, "rx_drop": 0, "tx_drop": 0}})
    seen = []

    for fields, expect in (({}, default), ({"every": "7"}, 7.0)):
        pane = _wifi_pane({"iface": "wlan0", "target": "HomeNet", **fields}, ticks=1)
        pane.AIR_EVERY, pane.LINK_EVERY, pane.TRAFFIC_EVERY = 3.0, 1.0, 1.0

        async def fake_run_live(tick, every, what):
            seen.append(every)
            await tick(0.0, 1)
            return "finished"

        pane._run_live = fake_run_live
        asyncio.run(getattr(pane, view)())
        assert seen[-1] == expect, (view, fields)


def test_live_air_refuses_to_scan_faster_than_once_a_second(tmp_path, monkeypatch):
    from test_v32 import _radio, _wifi_pane

    _radio(tmp_path, monkeypatch)
    with pytest.raises(ValidationError, match="between 1"):
        asyncio.run(_wifi_pane({"iface": "wlan0", "every": "0.5"})._live_air())


def test_live_air_subtitle_follows_the_box(tmp_path, monkeypatch):
    from test_v32 import _radio, _wifi_pane

    _radio(tmp_path, monkeypatch)
    pane = _wifi_pane({"iface": "wlan0", "every": "5"}, ticks=1)
    asyncio.run(pane._live_air())
    table = pane.widgets[3].content          # after the pick line (4.3)
    assert "updated every 5s" in str(table.subtitle)
    assert "the last 10 readings" in str(table.subtitle)


def _sleeps(monkeypatch, module):
    naps = []
    real = asyncio.sleep

    async def nap(seconds, *a, **k):
        naps.append(seconds)
        await real(0)

    monkeypatch.setattr(module.asyncio, "sleep", nap)
    return naps


def test_flow_watch_uses_the_box(monkeypatch):
    from netzilla.local import flows
    from netzilla.screens import flows as flow_screen
    from test_v32 import _PaneBase, _Panel

    class Pane(_PaneBase, flow_screen.FlowPane):
        def __init__(self, fields):
            flow_screen.FlowPane.__init__(self)
            _PaneBase.__init__(self, fields)

    async def snapshot():
        return [], ""

    monkeypatch.setattr(flows, "snapshot", snapshot)
    monkeypatch.setattr(flow_screen, "Static", lambda **k: _Panel())
    naps = _sleeps(monkeypatch, flow_screen)
    asyncio.run(Pane({"secs": "4", "every": "2.5"})._watch())
    assert naps and naps[0] == 2.5


def test_int_live_rates_use_the_box(monkeypatch):
    from netzilla.local import netif
    from netzilla.screens import interfaces
    from test_v32 import _PaneBase, _Panel

    class Pane(_PaneBase, interfaces.InterfacesPane):
        def __init__(self, fields):
            interfaces.InterfacesPane.__init__(self)
            _PaneBase.__init__(self, fields)

    counters = {"wlan0": {"rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0,
                          "rx_errs": 0, "tx_errs": 0, "rx_drop": 0, "tx_drop": 0}}
    monkeypatch.setattr(netif, "read_counters", lambda: counters)
    monkeypatch.setattr(interfaces, "Static", lambda **k: _Panel())
    naps = _sleeps(monkeypatch, interfaces)
    pane = Pane({"iface": "wlan0", "secs": "2", "every": "0.5"})
    pane._iface = lambda: "wlan0"
    asyncio.run(pane._rates())
    assert naps and naps[0] == 0.5


def test_lan_dup_ip_polls_at_the_box(monkeypatch):
    from netzilla.local import arpwatch
    from netzilla.screens.lan import LANPane
    from test_v32 import _PaneBase

    class Pane(_PaneBase, LANPane):
        def __init__(self, fields):
            LANPane.__init__(self)
            _PaneBase.__init__(self, fields)

    asked = {}

    async def watch(ip, seconds=8.0, interval=1.0):
        asked.update(seconds=seconds, interval=interval)
        return {"ip": ip, "method": "neighbour cache", "rounds": 1, "macs": [],
                "conflict": False}

    monkeypatch.setattr(arpwatch, "watch", watch)
    asyncio.run(Pane({"target": "192.168.1.1", "secs": "6", "every": "2"})._dupip())
    assert asked == {"seconds": 6.0, "interval": 2.0}


def test_help_cards_explain_the_box():
    from netzilla.help import get_help

    for pane, key in [("WifiPane", "air"), ("InterfacesPane", "rates"),
                      ("FlowPane", "watch"), ("CapturePane", "live"),
                      ("LANPane", "syslog")]:
        assert "REFRESH EVERY" in get_help(pane, key).note, (pane, key)


def test_every_tab_still_fits_its_fields_on_a_wide_terminal(tmp_path):
    from textual.widgets import TabbedContent

    from netzilla.app import TABS, NetzillaApp

    async def go():
        app = NetzillaApp(config_path=tmp_path / "c.toml", offline=True)
        async with app.run_test(size=(200, 60)) as pilot:
            tabs = app.query_one("#tabs", TabbedContent)
            for tab_id, _label, pane_class in TABS:
                tabs.active = tab_id
                await pilot.pause()
                for field in app.query_one(pane_class).query(".field"):
                    assert field.region.right <= 200, (tab_id, field.region)
                    assert field.region.width >= 12, (tab_id, field.region)

    asyncio.run(go())
