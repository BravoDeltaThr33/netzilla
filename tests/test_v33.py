"""Tests for netzilla 3.3.

  * every tab's control box rolls up (▲ / ▼, or F3) so the output gets the
    screen, and rolls back down
  * LIVE AIR and SIGNAL scan on a fixed three-second cadence
  * every full block in a graph or bar is outlined in the theme's background
  * LIVE AIR's HISTORY column in sextants (two rows, two samples a character),
    switchable back to block characters on SETTINGS
  * iw's empty SSID line for a hidden network is no longer read as the next
    line ("Supported rates: …")
"""

from __future__ import annotations

import asyncio
import time
import unicodedata

import pytest
from rich.style import Style
from rich.text import Text

from netzilla import __version__
from netzilla.config import Config
from netzilla.local import wifi, wifitools
from netzilla.render import block_text


def test_version_is_3_3():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (3, 3), __version__


# ======================================================= history graphs
# 3.3 drew HISTORY in sextants, 3.4 in quadrants; since 3.5 it shows the dBm
# readings themselves (test_v35.py).


# ================================================================ outlines
def test_full_blocks_are_outlined_in_the_edge_colour():
    text = block_text("█▃·", "#00ff00", "#101010", scaffold="#555555")
    assert text.plain == "▕▃·"
    spans = {text.plain[s.start:s.end]: Style.parse(str(s.style)) for s in text.spans}
    outlined = spans["▕"]
    assert outlined.underline and outlined.bgcolor.name == "#00ff00"
    assert outlined.color.name == "#101010"                 # the outline
    assert spans["▃"].color.name == "#00ff00" and not spans["▃"].underline
    assert spans["·"].color.name == "#555555"


def test_block_text_keeps_lines_and_every_block_in_a_column():
    lines = wifitools.signal_chart([-30] * 5, width=5, height=4)
    text = block_text(lines, "green", "black")
    assert text.plain.count("\n") == len(lines) - 1
    assert text.plain.count("▕") == 20                      # 5 columns × 4 full rows


# ============================================================= iw SSIDs
IW_SCAN = """BSS ba:5e:71:25:04:f0(on wlp114s0f0)
\tfreq: 2437
\tsignal: -50.00 dBm
\tSSID:
\tSupported rates: 6.0* 9.0 12.0* 18.0 24.0* 36.0 48.0 54.0
\tDS Parameter set: channel 6
\tRSN:\t * Version: 1
BSS ba:5e:71:2c:04:f0(on wlp114s0f0) -- associated
\tfreq: 5220
\tsignal: -29.00 dBm
\tSSID: WLAN52
\tRSN:\t * Version: 1
BSS 82:da:c2:ec:a8:95(on wlp114s0f0)
\tfreq: 2437
\tsignal: -62.00 dBm
\tSSID: \\x00\\x00\\x00\\x00
\tSupported rates: 6.0* 9.0
"""


def test_hidden_ssids_are_not_read_from_the_next_line():
    aps = wifi.parse_iw_scan(IW_SCAN)
    assert [a["ssid"] for a in aps] == ["<hidden>", "WLAN52", "<hidden>"]
    assert aps[1]["in_use"] and aps[1]["signal_dbm"] == -29


# ================================================================ config
def test_an_old_graphs_setting_is_ignored(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[theme]\nname = "amber-phosphor"\ngraphs = "sextant"\n')
    config = Config.load(path)
    assert config.theme == "amber-phosphor"
    config.save()
    assert "graphs" not in path.read_text()


# ========================================================= live cadence
class _Pane:
    def __init__(self):
        from netzilla.screens.wifi import WifiPane

        class Pane(WifiPane):
            MAX_TICKS = 4

            def field(self, key):
                return ""

            def progress(self, message):
                pass

        self.pane = Pane()


def test_live_air_scans_every_three_seconds():
    from netzilla.screens.wifi import WifiPane

    assert WifiPane.AIR_EVERY == 3.0 and WifiPane.RESCAN_EVERY <= WifiPane.AIR_EVERY


def test_the_cadence_is_start_to_start_not_after_a_slow_tick():
    pane = _Pane().pane
    starts = []

    async def tick(elapsed, count):
        starts.append(time.monotonic())
        await asyncio.sleep(0.15)                            # a slow scan

    asyncio.run(pane._run_live(tick, 0.25, "TEST"))
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    assert len(gaps) == 3
    assert all(0.22 < gap < 0.34 for gap in gaps), gaps       # not 0.15 + 0.25


def test_a_tick_slower_than_the_cadence_runs_back_to_back():
    pane = _Pane().pane
    starts = []

    async def tick(elapsed, count):
        starts.append(time.monotonic())
        await asyncio.sleep(0.2)

    asyncio.run(pane._run_live(tick, 0.1, "TEST"))
    assert all(b - a < 0.33 for a, b in zip(starts, starts[1:]))


# ======================================================= LIVE AIR table
def _live_pane(style=None):
    """A WIFI pane for render tests; `style` is ignored (the HISTORY style
    setting was removed in 3.5)."""
    from test_v32 import _wifi_pane

    return _wifi_pane({"iface": "wlan0"}, ticks=1)


def _air(pane, samples=40):
    for i in range(samples):
        pane._air.update([
            {"ssid": "Home", "bssid": "AA", "signal_dbm": -45 - i % 5, "channel": 6,
             "band": "2.4 GHz", "security": "WPA2", "in_use": True},
            {"ssid": "Far", "bssid": "BB", "signal_dbm": -82, "channel": 1,
             "band": "2.4 GHz", "security": "WPA2", "in_use": False},
        ], now=1000 + i)
    return pane


def test_history_column_is_one_line_of_readings(monkeypatch):
    pane = _air(_live_pane())
    monkeypatch.setattr(time, "time", lambda: 1040.0)
    from test_v32 import _Panel

    table = _Panel()
    pane._render_air(_Panel(), _Panel(), table, _Panel(), "", "nmcli", 10.0, "")
    rendered = table.content.renderable
    history = rendered.columns[6]._cells[0]
    bar = rendered.columns[5]._cells[0]
    assert isinstance(history, Text) and "\n" not in history.plain
    assert isinstance(bar, Text) and "▕" in bar.plain       # outlined signal blocks


def test_the_graph_is_outlined_too():
    pane = _air(_live_pane("quadrant"))
    panel = pane._chart("Signal", wifitools.signal_chart([-40] * 10, width=10, height=4))
    assert "▕" in panel.renderable.plain and "█" not in panel.renderable.plain


# ================================================== collapsible controls
def _app(tmp_path):
    from netzilla.app import NetzillaApp

    return NetzillaApp(config_path=tmp_path / "config.toml", offline=True)


def test_every_tab_rolls_its_controls_up_and_back_down(tmp_path):
    from textual.widgets import TabbedContent

    from netzilla.app import TABS
    from netzilla.screens.base import CollapseToggle

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            tabs = app.query_one("#tabs", TabbedContent)
            for tab_id, _label, pane_class in TABS:
                tabs.active = tab_id
                await pilot.pause()
                pane = app.query_one(pane_class)
                toggle = pane.query_one(CollapseToggle)
                assert str(toggle.label) == "▲", tab_id
                before = pane.region.height, pane.query_one(".control-head").region
                await pilot.click(f"#{tab_id} #collapse-toggle")
                await pilot.pause()
                assert pane.controls_collapsed, tab_id
                assert str(toggle.label) == "▼", tab_id
                for hidden in pane.query(".field-row, .control-bar .action-row, "
                                         ".collapsible, .banner"):
                    assert hidden.region.height == 0, (tab_id, hidden)
                note = pane.query_one(".collapsed-note")
                assert note.region.height == 1, tab_id
                await pilot.press("f3")                     # the key does it too
                await pilot.pause()
                assert not pane.controls_collapsed, tab_id
                assert str(toggle.label) == "▲", tab_id

    asyncio.run(go())


def test_rolling_up_gives_the_results_more_room(tmp_path):
    from textual.widgets import TabbedContent

    from netzilla.screens.wifi import WifiPane

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            app.query_one("#tabs", TabbedContent).active = "wifi"
            await pilot.pause()
            pane = app.query_one(WifiPane)
            before = pane.results.region.height
            await pilot.press("f3")
            await pilot.pause()
            after = pane.results.region.height
            assert after >= before + 10, (before, after)

    asyncio.run(go())


def test_each_tab_remembers_its_own_state(tmp_path):
    from textual.widgets import TabbedContent

    from netzilla.screens.lan import LANPane
    from netzilla.screens.wifi import WifiPane

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            tabs = app.query_one("#tabs", TabbedContent)
            tabs.active = "wifi"
            await pilot.pause()
            await pilot.press("f3")
            tabs.active = "lan"
            await pilot.pause()
            assert app.query_one(WifiPane).controls_collapsed
            assert not app.query_one(LANPane).controls_collapsed

    asyncio.run(go())
