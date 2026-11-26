"""Tests for netzilla 4.1: DASH and SETTINGS fill the screen.

  * PanelGrid / grid_layout put panels in columns with equal heights
  * DASH: centred logo, three rows of panels, a live network pulse, a
    tagline that fits its width, everything visible on a 160 x 50 screen
  * this machine's facts (sysinfo): memory, uptime, resolvers
  * SETTINGS: buttons on top, keys on the left, the rest on the right, a
    keys-and-storage panel; stacked on a narrow terminal
"""

from __future__ import annotations

import asyncio
import io

import pytest
from rich.console import Console
from rich.panel import Panel

from netzilla import __version__
from netzilla.render import PanelGrid, grid_layout
from netzilla.themes import get_palette

PALETTE = get_palette("phosphor-green")


def plain(renderable, width: int = 120) -> list[str]:
    console = Console(width=width, color_system=None, file=io.StringIO())
    console.print(renderable)
    return console.file.getvalue().splitlines()


def screen_text(app) -> list[str]:
    """What the terminal shows, line by line."""
    console = Console(width=app.size.width, height=app.size.height, file=io.StringIO(),
                      force_terminal=True, color_system=None, record=True)
    console.print(app.screen._compositor.render_update(
        full=True, screen_stack=app._background_screens))
    text = "".join(seg.text for seg in console._record_buffer if not seg.control)
    return text.split("\n")[: app.size.height]


def _app(tmp_path, **kwargs):
    from netzilla.app import NetzillaApp

    return NetzillaApp(config_path=tmp_path / "config.toml", offline=True,
                       **kwargs)


def test_version_is_4_1():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (4, 1), __version__


# ================================================================ PanelGrid
def test_grid_layout_picks_columns_from_the_width():
    assert len(grid_layout(160, [1, 1, 1], min_width=46, max_cols=3)[0]) == 3
    assert len(grid_layout(110, [1, 1, 1], min_width=46, max_cols=3)[0]) == 2
    assert len(grid_layout(60, [1, 1, 1], min_width=46, max_cols=3)[0]) == 1
    # never more columns than asked for
    assert len(grid_layout(400, [1, 1, 1, 1, 1], min_width=46, max_cols=3)[0]) == 3


def test_grid_layout_rows_fill_the_width_exactly():
    for width in (99, 110, 160, 161, 203):
        for row in grid_layout(width, [1, 1, 1, 2, 1], min_width=46, max_cols=3):
            used = sum(w for _, w in row) + (len(row) - 1)          # one-column gaps
            assert used == width, (width, row)


def test_grid_layout_spans_take_their_share():
    rows = grid_layout(160, [2, 1], min_width=46, max_cols=3)
    assert len(rows) == 1
    (first, wide), (second, narrow) = rows[0]
    assert (first, second) == (0, 1) and wide > narrow * 1.8


def test_panel_grid_places_panels_side_by_side_with_equal_heights():
    short = Panel("one line", title="SHORT")
    tall = Panel("1\n2\n3\n4\n5", title="TALL")
    lines = plain(PanelGrid([short, tall], min_width=30, max_cols=2), width=80)
    assert len(lines) == 7                              # the taller panel's height
    assert "SHORT" in lines[0] and "TALL" in lines[0]
    # both bottom borders are on the last line
    assert lines[-1].count("╰") == 2
    assert all(len(line) <= 80 for line in lines)


def test_panel_grid_stacks_on_a_narrow_screen():
    lines = plain(PanelGrid([Panel("a", title="ONE"), Panel("b", title="TWO")],
                            min_width=40, max_cols=2), width=50)
    titles = [i for i, line in enumerate(lines) if "ONE" in line or "TWO" in line]
    assert len(titles) == 2 and titles[0] < titles[1]
    assert not any("ONE" in line and "TWO" in line for line in lines)


# ================================================================== sysinfo
def test_meminfo_and_uptime_text():
    from netzilla.local import sysinfo

    meminfo = "MemTotal:  8000000 kB\nMemFree: 1000 kB\nMemAvailable:  6000000 kB\n"
    used, total = sysinfo.parse_meminfo(meminfo)
    assert total == 8000000 * 1024 and used == 2000000 * 1024
    assert "(25%)" in sysinfo.memory_text((used, total))
    assert sysinfo.parse_meminfo("nonsense") is None
    assert sysinfo.memory_text(None) == "—"
    assert sysinfo.uptime_text(42 * 60) == "42m"
    assert sysinfo.uptime_text(5 * 3600 + 7 * 60) == "5h 07m"
    assert sysinfo.uptime_text(3 * 86400 + 4 * 3600 + 12 * 60) == "3d 04h 12m"
    assert sysinfo.uptime_text(None) == "—"


def test_resolvers_behind_systemd_resolved(tmp_path, monkeypatch):
    from netzilla.local import sysinfo

    stub = tmp_path / "resolv.conf"
    upstream = tmp_path / "upstream.conf"
    stub.write_text("# stub\nnameserver 127.0.0.53\noptions edns0\n")
    upstream.write_text("nameserver 1.1.1.1\nnameserver 9.9.9.9\nnameserver 1.1.1.1\n")
    monkeypatch.setattr(sysinfo, "RESOLV_CONF", stub)
    monkeypatch.setattr(sysinfo, "RESOLVED_UPSTREAM", upstream)
    assert sysinfo.dns_servers() == (["1.1.1.1", "9.9.9.9"], "via systemd-resolved")

    stub.write_text("nameserver 192.168.1.1\n")
    assert sysinfo.dns_servers() == (["192.168.1.1"], "")


def test_machine_facts_have_every_key():
    from netzilla.local import sysinfo

    facts = sysinfo.facts()
    for key in ("host", "os", "kernel", "uptime", "load", "memory", "python",
                "textual", "netzilla"):
        assert facts[key], key
    assert facts["netzilla"] == __version__


# ==================================================================== DASH
def test_tagline_drops_parts_from_the_end_to_fit():
    from netzilla.screens.dashboard import tagline_text

    parts = ["v4.1.0", "21 tabs", "free & open data only", "kitty 0.36.4",
             "pixel graphs", "disco-70s"]
    full = tagline_text(PALETTE, parts, 200).plain
    assert full.endswith("disco-70s")
    narrow = tagline_text(PALETTE, parts, 60).plain
    assert narrow.startswith("v4.1.0") and len(narrow) <= 60
    assert "disco-70s" not in narrow
    assert tagline_text(PALETTE, parts, 3).plain == "v4.1.0"


def test_quota_rows_on_dash_skip_unused_unlimited_services(tmp_path):
    from netzilla.config import Config
    from netzilla.services import Services

    services = Services(Config.load(tmp_path / "c.toml"))
    every = services.quota_rows()
    active = services.quota_rows(active_only=True)
    assert len(active) < len(every)
    assert all("/" in usage for _, usage, _ in active)       # only hard limits


def _dash(tmp_path, size):
    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause(0.3)
            pane = app._active_pane()
            regions = {name: pane.query_one(f"#{name}").region
                       for name in ("banner", "dash-row-1", "dash-row-2", "dash-row-3")}
            return pane, regions, "\n".join(screen_text(app)), app.screen.size
    return asyncio.run(go())


def test_dash_fits_on_one_160_by_50_screen(tmp_path):
    pane, regions, text, screen = _dash(tmp_path, (160, 50))
    for name in ("dash-row-1", "dash-row-2", "dash-row-3"):
        assert regions[name].height > 0, name
        assert regions[name].bottom <= screen.height - 1, (name, regions[name])
    for title in ("THIS MACHINE", "NETWORK", "TERMINAL", "LOCAL TOOLING",
                  "API KEYS", "DATA & CACHE", "API QUOTA", "NETWORK PULSE"):
        assert title in text, title


def test_dash_logo_is_centred(tmp_path):
    from netzilla.screens.dashboard import BANNER

    pane, regions, text, screen = _dash(tmp_path, (160, 50))
    lines = text.splitlines()
    banner = regions["banner"]
    art = BANNER.splitlines()
    width = len(art[0])
    for row, art_line in zip(lines[banner.y:banner.y + len(art)], art):
        inside = row[banner.x:banner.right]
        left = inside.index(art_line.strip()[:6]) - (len(art_line) - len(art_line.lstrip()))
        right = banner.width - left - width
        assert abs(left - right) <= 1, (left, right)


def test_dash_uses_three_columns_wide_and_fewer_narrow(tmp_path):
    _, _, wide, _ = _dash(tmp_path, (160, 50))
    row = next(line for line in wide.splitlines() if "THIS MACHINE" in line)
    assert "NETWORK" in row and "TERMINAL" in row
    _, _, narrow, _ = _dash(tmp_path, (90, 50))
    row = next(line for line in narrow.splitlines() if "THIS MACHINE" in line)
    assert "NETWORK" not in row and "TERMINAL" not in row


def test_the_pulse_samples_the_default_interface(tmp_path, monkeypatch):
    from netzilla.local import netif
    from netzilla.screens.dashboard import DashboardPane

    samples = iter([
        {"eth0": {"rx_bytes": 0, "tx_bytes": 0}},
        {"eth0": {"rx_bytes": 1_250_000, "tx_bytes": 125_000}},
        {"eth0": {"rx_bytes": 2_500_000, "tx_bytes": 250_000}},
    ])
    monkeypatch.setattr(netif, "read_counters", lambda: next(samples))
    monkeypatch.setattr(netif, "rates_between",
                        lambda a, b, s: [{"name": "eth0",
                                          "rx_mbps": (b["eth0"]["rx_bytes"] - a["eth0"]["rx_bytes"]) * 8 / 1e6,
                                          "tx_mbps": (b["eth0"]["tx_bytes"] - a["eth0"]["tx_bytes"]) * 8 / 1e6}])
    pane = DashboardPane.__new__(DashboardPane)
    pane._pulse_iface = "eth0"
    pane._network = {}
    pane._facts = None
    pane._pulse_prev = None
    pane._pulse_down, pane._pulse_up = [], []
    pane.query_one = lambda *a, **k: (_ for _ in ()).throw(LookupError())
    for _ in range(3):
        pane._pulse_tick()
    assert pane._pulse_down == [10.0, 10.0] and pane._pulse_up == [1.0, 1.0]


# ================================================================ SETTINGS
def _settings(tmp_path, size):
    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await pilot.press("f2")
            await pilot.pause(0.3)
            pane = app._active_pane()
            got = {name: pane.query_one(f"#{name}").region
                   for name in ("act-save", "act-test", "settings-columns",
                                "settings-left", "settings-right", "cred-abuseipdb_api_key",
                                "theme-select", "graphics-select", "sw-notify",
                                "in-timeout", "sw-cache", "settings-status",
                                "settings-results")}
            wide = pane.query_one("#settings-columns").has_class("-wide")
            return got, wide, "\n".join(screen_text(app))
    return asyncio.run(go())


def test_settings_puts_keys_and_preferences_side_by_side(tmp_path):
    got, wide, text = _settings(tmp_path, (160, 50))
    assert wide
    left, right = got["settings-left"], got["settings-right"]
    assert left.x < right.x and left.y == right.y
    # the buttons come first, above both columns
    assert got["act-save"].bottom <= got["settings-columns"].y
    assert got["cred-abuseipdb_api_key"].x < right.x <= got["theme-select"].x
    # one-row boxes and switches
    assert got["cred-abuseipdb_api_key"].height == 1
    assert got["sw-cache"].height == 1 and got["in-timeout"].height == 1
    assert "KEYS AND STORAGE" in text and "CONFIG FILE" in text
    assert "API KEYS" in text and "BEHAVIOUR" in text


def test_settings_all_fits_on_a_160_by_50_screen(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    got, _, _ = _settings(tmp_path, (160, 50))
    assert got["settings-status"].bottom <= 49, got["settings-status"]


def test_settings_stacks_on_a_narrow_terminal(tmp_path):
    got, wide, _ = _settings(tmp_path, (100, 40))
    assert not wide
    assert got["settings-right"].y > got["settings-left"].y
    assert got["settings-left"].x == got["settings-right"].x
