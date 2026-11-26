"""Tests for netzilla 3.5.

  * LIVE AIR honours REFRESH EVERY: a tick reads the latest *finished* scan
    (iw scan dump / NetworkManager's list) instead of waiting 2–4 s for the
    radio to scan every channel; new scans run in the background
  * the same cached result read twice is one reading, not two
  * HISTORY shows the dBm readings themselves — "-52 -51 -50" — each in its
    signal colour
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest
from rich.text import Text

from netzilla import __version__
from netzilla.colours import SEMANTIC
from netzilla.config import Config
from netzilla.local import runner, wifi, wifitools


def test_version_is_3_5():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (3, 5), __version__


def _fake(dir_path, name, body):
    path = dir_path / name
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(0o755)


IW_DUMP = """BSS aa:bb:cc:11:22:33(on wlan0) -- associated
\tlast seen: 120 ms ago
\tfreq: 5220
\tsignal: -48.00 dBm
\tSSID: HomeNet
\tRSN:\t * Version: 1
BSS de:ad:be:ef:00:01(on wlan0)
\tlast seen: 2400 ms ago
\tfreq: 2412
\tsignal: -71.00 dBm
\tSSID: Neighbour
\tRSN:\t * Version: 1
"""

IW_LINK = """Connected to aa:bb:cc:11:22:33 (on wlan0)
\tSSID: HomeNet
\tfreq: 5220
\tsignal: -47 dBm
\trx bitrate: 866.7 MBit/s
\ttx bitrate: 650.0 MBit/s
"""


def _slow_radio(tmp_path, monkeypatch, scan_seconds=3):
    """iw where a real scan takes `scan_seconds`, but the dump and link
    reads are instant — like real hardware."""
    log = tmp_path / "calls.log"
    _fake(tmp_path, "iw", f'''
echo "$*" >> "{log}"
case "$3 $4" in
  "link "*) printf '%s' "{IW_LINK}" ;;
  "scan dump") printf '%s' "{IW_DUMP}" ;;
  "scan trigger") exit 0 ;;             # returns at once; the scan runs on
  "scan "*) sleep {scan_seconds}; printf '%s' "{IW_DUMP}" ;;
  *) exit 1 ;;
esac
exit 0
''')
    _fake(tmp_path, "nmcli", "exit 0\n")
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    return log


# ======================================================== the cadence fix
def test_scan_dump_is_read_with_ages(tmp_path, monkeypatch):
    _slow_radio(tmp_path, monkeypatch)
    started = time.monotonic()
    aps, backend, error = asyncio.run(wifi.scan_cached("wlan0"))
    assert time.monotonic() - started < 1.5                 # didn't wait for a scan
    assert backend == "iw" and not error
    home = next(a for a in aps if a["ssid"] == "HomeNet")
    assert home["in_use"] and home["signal_dbm"] == -48 and home["last_seen_ms"] == 120
    assert next(a for a in aps if a["ssid"] == "Neighbour")["last_seen_ms"] == 2400


def test_live_air_ticks_at_the_asked_rate_even_when_a_scan_takes_3s(tmp_path, monkeypatch):
    from test_v32 import _wifi_pane

    log = _slow_radio(tmp_path, monkeypatch, scan_seconds=3)
    pane = _wifi_pane({"iface": "wlan0"}, ticks=5)
    pane.AIR_EVERY = 0.3                                     # "REFRESH EVERY" = 0.3 s
    starts = []
    real_render = pane._render_air

    def render(*args, **kwargs):
        starts.append(time.monotonic())
        return real_render(*args, **kwargs)

    pane._render_air = render
    asyncio.run(pane._live_air())
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    assert len(starts) == 5
    assert max(gaps) < 0.9, gaps                             # never waits out a 3 s scan
    calls = log.read_text().splitlines()
    assert any("scan trigger" in c for c in calls)          # scans still requested…
    assert not any(c.strip().endswith(" scan") for c in calls)   # …never a blocking one


def test_the_background_scanner_stops_with_the_view(tmp_path, monkeypatch):
    from test_v32 import _wifi_pane

    _slow_radio(tmp_path, monkeypatch, scan_seconds=3)
    pane = _wifi_pane({"iface": "wlan0"}, ticks=2)
    pane.AIR_EVERY = 0.2

    async def go():
        await pane._live_air()
        await asyncio.sleep(0)
        return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    assert asyncio.run(go()) == []


def test_own_network_is_read_live_every_tick(tmp_path, monkeypatch):
    from test_v32 import _wifi_pane

    _slow_radio(tmp_path, monkeypatch)
    pane = _wifi_pane({"iface": "wlan0"}, ticks=3)
    pane.AIR_EVERY = 0.05
    asyncio.run(pane._live_air())
    home = pane._air.focus()
    assert home["ssid"] == "HomeNet" and home["history"] == [-47, -47, -47]   # iw link
    neighbour = next(e for e in pane._air.seen.values() if e["ssid"] == "Neighbour")
    assert neighbour["history"] == [-71]                    # one scan result, read 3×


@pytest.mark.parametrize("output, code, expected", [
    ("", 0, True),
    ("command failed: Device or resource busy (-16)", 240, True),
    ("command failed: Operation not permitted (-1)", 255, False),
])
def test_can_trigger_with_iw(tmp_path, monkeypatch, output, code, expected):
    _fake(tmp_path, "iw", f'echo "{output}" >&2\nexit {code}\n')
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    assert asyncio.run(wifi.can_trigger_with_iw("wlan0")) is expected


def test_nmcli_fallback_reads_its_list_without_rescanning(tmp_path, monkeypatch):
    log = tmp_path / "nm.log"
    _fake(tmp_path, "nmcli", f'''echo "$*" >> "{log}"
printf '*:AA\\\\:BB\\\\:CC\\\\:11\\\\:22\\\\:33:HomeNet:6:2437 MHz:82:WPA2:270 Mbit/s\\n'
''')
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(wifi, "have", lambda tool: tool == "nmcli")
    aps, backend, _ = asyncio.run(wifi.scan_cached("wlan0"))
    assert backend == "nmcli" and aps[0]["ssid"] == "HomeNet"
    assert "--rescan no" in log.read_text() and "--rescan yes" not in log.read_text()


def test_a_cancelled_command_is_killed(tmp_path, monkeypatch):
    marker = tmp_path / "finished"
    _fake(tmp_path, "slowtool", f'sleep 2\ntouch "{marker}"\n')
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    async def go():
        task = asyncio.create_task(runner.run(["slowtool"], timeout=10))
        await asyncio.sleep(0.3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(go())
    time.sleep(2.3)
    assert not marker.exists()


# ======================================================== one reading once
def _ap(dbm, seen_at=None):
    return {"ssid": "Next", "bssid": "BB", "signal_dbm": dbm, "channel": 1,
            "band": "2.4 GHz", "security": "WPA2", "in_use": False, "seen_at": seen_at}


def test_the_same_cached_result_is_one_reading():
    watch = wifitools.AirWatch()
    watch.update([_ap(-70, seen_at=100.0)], now=100.5)
    watch.update([_ap(-70, seen_at=100.02)], now=101.5)     # same scan, read again
    watch.update([_ap(-68, seen_at=103.1)], now=103.5)      # a new scan
    assert watch.seen["BB"]["history"] == [-70, -68]


def test_with_no_age_every_read_counts():
    watch = wifitools.AirWatch()
    for _ in range(3):
        watch.update([_ap(-70)], now=100.0)
    assert watch.seen["BB"]["history"] == [-70, -70, -70]


def test_a_stale_kernel_entry_is_shown_as_gone():
    watch = wifitools.AirWatch(gone_after=20)
    watch.update([_ap(-70, seen_at=100.0)], now=130.0)      # last heard 30 s ago
    assert watch.present(now=130.0) == [] and len(watch.gone(now=130.0)) == 1


# ============================================================ HISTORY text
def test_history_text_is_the_readings_newest_on_the_right():
    assert wifitools.history_text([-26, -25, -26, -27, -25, -26, -28]) == \
        "-26 -25 -26 -27 -25 -26 -28"
    assert wifitools.history_text(list(range(-80, -60)), count=4) == "-64 -63 -62 -61"
    assert wifitools.history_text([-50.4, None, -49.6]) == "-50 -50"
    assert wifitools.history_text([]) == "—"


def test_each_reading_has_its_signal_colour():
    from test_v32 import _wifi_pane

    pane = _wifi_pane({})
    text = pane._history("-45 -55 -65 -75 -85")
    colours = [str(s.style) for s in text.spans]
    assert colours == [SEMANTIC[k] for k in ("excellent", "good", "fair", "weak", "very weak")]
    assert text.plain == "-45 -55 -65 -75 -85"
    gone = pane._history("-45 -55", live=False)
    assert {str(s.style) for s in gone.spans} == {pane.palette.muted}


def test_live_air_table_shows_readings(monkeypatch):
    from test_v32 import _Panel, _wifi_pane

    pane = _wifi_pane({"iface": "wlan0"})
    for i, dbm in enumerate([-52, -51, -50]):
        pane._air.update([{"ssid": "Home", "bssid": "AA", "signal_dbm": dbm, "channel": 6,
                           "band": "2.4 GHz", "security": "WPA2", "in_use": True}],
                         now=1000 + i)
    monkeypatch.setattr(time, "time", lambda: 1003.0)
    table = _Panel()
    pane._render_air(_Panel(), _Panel(), table, _Panel(), "", "iw", 5.0, "", 0.4)
    history = table.content.renderable.columns[6]._cells[0]
    assert isinstance(history, Text) and history.plain == "-52 -51 -50"
    assert "▕" not in history.plain


def test_settings_no_longer_offers_a_history_graph_style(tmp_path):
    from textual.widgets import TabbedContent

    from netzilla.app import NetzillaApp

    async def go():
        app = NetzillaApp(config_path=tmp_path / "c.toml", offline=True)
        async with app.run_test(size=(200, 60)) as pilot:
            app.query_one("#tabs", TabbedContent).active = "settings"
            await pilot.pause()
            assert not app.query("#graphs-select")

    asyncio.run(go())
    assert not hasattr(Config(), "graph_style")
