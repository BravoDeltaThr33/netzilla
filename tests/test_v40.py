"""Tests for netzilla 4.0.

  * no paid APIs: Shodan's paid host/search and the OutageDeck/EOSL keys are
    gone; DISCOVERY's HOST PROFILE and CVE DETAIL use free sources only
  * every control: each button on each tab runs without a netzilla bug,
    Enter in a box runs that box's action, letter keys work in both cases,
    command names / tab names / themes are matched in any case
  * terminal detection: which terminal, which version, what it can draw
  * pixel graphs (kitty graphics protocol, Unicode placeholders) with a text
    form of every graph; both lay out identically
  * speed: tabs are built when first opened
  * new free features: endoflife.date, EPSS, the built-in speed test,
    DNS-over-HTTPS fallback, copy output (F4), desktop notifications
"""

from __future__ import annotations

import asyncio
import base64
import io
import os
import struct
import zlib

import pytest
from rich.console import Console
from rich.text import Text

from netzilla import __version__, termcaps
from netzilla.config import CREDENTIAL_KEYS, Config
from netzilla.graphics import charts, kitty, plot
from netzilla.themes import get_palette

PALETTE = get_palette("phosphor-green")


def plain(renderable, width: int = 160) -> str:
    console = Console(width=width, color_system=None, file=io.StringIO())
    console.print(renderable)
    return console.file.getvalue()


@pytest.fixture(autouse=True)
def _reset_terminal_and_writer():
    """Each test starts in an unknown terminal with no image writer."""
    termcaps.set_current(termcaps.TerminalInfo())
    kitty.set_writer(None)
    yield
    termcaps.set_current(termcaps.TerminalInfo())
    kitty.set_writer(None)


def test_version_is_4():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (4, 0), __version__


# ============================================================ no paid APIs
def test_paid_credentials_are_gone():
    for key in ("shodan_api_key", "outagedeck_api_key", "eosl_api_key"):
        assert key not in CREDENTIAL_KEYS, key


def test_shodan_client_is_internetdb_only():
    from netzilla.clients import shodan

    assert not hasattr(shodan, "host") and not hasattr(shodan, "search")
    assert "api.shodan.io" not in open(shodan.__file__).read()


def test_no_client_sends_an_optional_paid_key(tmp_path):
    from netzilla.clients import eosl, outagedeck
    from netzilla.services import Services

    config = Config.load(tmp_path / "c.toml", use_defaults=False)
    services = Services(config)
    assert outagedeck._headers(services) == {"Accept": "application/json"}
    assert eosl._headers(services) == {"Accept": "application/json"}


def test_an_old_config_with_removed_keys_still_loads(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text('[credentials]\nshodan_api_key = "x"\nnvd_api_key = "abc"\n')
    config = Config.load(path, use_defaults=False)
    assert config.credential("nvd_api_key") == "abc"
    assert "shodan_api_key" not in config.credentials


def test_discovery_offers_only_free_actions():
    from netzilla.screens.discovery import DiscoveryPane

    keys = [a.key for a in DiscoveryPane.ACTIONS]
    assert keys == ["idb", "profile", "cves"]
    assert "paid" not in DiscoveryPane.DESCRIPTION.lower() or "without" in \
        DiscoveryPane.DESCRIPTION.lower()


class _Recorder:
    """A pane stand-in that records what it pushes."""

    def __init__(self, fields):
        self._fields = fields
        self.pushed = []

    def field(self, key):
        return self._fields.get(key, "")

    async def begin(self, message="…"):
        pass

    def progress(self, message):
        pass

    async def finish(self, message=""):
        pass

    async def push(self, renderable):
        self.pushed.append(renderable)

    async def push_error(self, title, message):
        self.pushed.append(("error", title, message))

    async def push_warning(self, title, message):
        self.pushed.append(("warning", title, message))

    def text(self) -> str:
        return "\n".join(
            plain(p) if not isinstance(p, tuple) else " ".join(p[1:]) for p in self.pushed
        )


def _discovery(fields, services):
    from netzilla.screens.discovery import DiscoveryPane

    class Pane(_Recorder, DiscoveryPane):
        def __init__(self, fields):
            DiscoveryPane.__init__(self)
            _Recorder.__init__(self, fields)

        @property
        def palette(self):
            return PALETTE

        @property
        def services(self):
            return services

    return Pane(fields)


def test_host_profile_combines_four_free_sources(monkeypatch, tmp_path):
    from netzilla.clients import ip_api, rdap, ripestat, shodan
    from netzilla.services import ApiResult, Services

    async def idb(services, ip):
        return ApiResult.success("shodan-idb", {"ip": ip, "ports": [53, 443], "vulns": [],
                                                "hostnames": ["one.one.one.one"],
                                                "tags": [], "cpes": ["cpe:/a:x"]})

    async def geo(services, ip):
        return ApiResult.success("ip-api", {"query": ip, "reverse": "one.one.one.one",
                                            "org": "APNIC and Cloudflare", "isp": "Cloudflare",
                                            "as": "AS13335 Cloudflare, Inc.", "city": "Sydney",
                                            "country": "Australia", "hosting": True})

    async def reg(services, ip):
        return ApiResult.failure("rdap", "No RDAP record found")

    async def net(services, ip):
        return ApiResult.success("ripestat", {"asns": ["13335"], "prefix": "1.1.1.0/24"})

    async def overview(services, asn):
        return ApiResult.success("ripestat", {"holder": "CLOUDFLARENET"})

    monkeypatch.setattr(shodan, "internetdb", idb)
    monkeypatch.setattr(ip_api, "lookup", geo)
    monkeypatch.setattr(rdap, "ip", reg)
    monkeypatch.setattr(ripestat, "network_info", net)
    monkeypatch.setattr(ripestat, "as_overview", overview)
    services = Services(Config.load(tmp_path / "c.toml", use_defaults=False))
    pane = _discovery({"ip": "1.1.1.1"}, services)
    asyncio.run(pane.execute("profile"))
    shown = pane.text()
    assert "one.one.one.one" in shown and "AS13335 — CLOUDFLARENET" in shown
    assert "1.1.1.0/24" in shown and "53, 443" in shown
    assert "Partly answered" in shown and "RDAP" in shown      # the one that failed


def test_cve_detail_ranks_by_kev_then_epss(monkeypatch, tmp_path):
    from netzilla.clients import epss, kev, nvd, shodan
    from netzilla.services import ApiResult, Services

    async def idb(services, ip):
        return ApiResult.success("shodan-idb", {"ip": ip, "ports": [80],
                                                "vulns": ["CVE-2020-0001", "CVE-2021-0002",
                                                          "CVE-2022-0003"]})

    async def scores(services, ids):
        return ApiResult.success("epss", {
            "CVE-2020-0001": {"epss": 0.02, "percentile": 0.5},
            "CVE-2021-0002": {"epss": 0.9, "percentile": 0.999},
            "CVE-2022-0003": {"epss": 0.3, "percentile": 0.9},
        })

    async def annotate(services, ids):
        return {"CVE-2020-0001": {"cveID": "CVE-2020-0001"}, "CVE-2021-0002": None,
                "CVE-2022-0003": None}

    async def get_cve(services, cve):
        return ApiResult.failure("nvd", "rate limited")

    monkeypatch.setattr(shodan, "internetdb", idb)
    monkeypatch.setattr(epss, "scores", scores)
    monkeypatch.setattr(kev, "annotate", annotate)
    monkeypatch.setattr(nvd, "get_cve", get_cve)
    services = Services(Config.load(tmp_path / "c.toml", use_defaults=False))
    pane = _discovery({"ip": "192.0.2.1"}, services)
    asyncio.run(pane.execute("cves"))
    shown = pane.text()
    order = [shown.index(c) for c in ("CVE-2020-0001", "CVE-2021-0002", "CVE-2022-0003")]
    assert order == sorted(order), "KEV first, then by EPSS"
    assert "EXPLOITED" in shown and "1 known exploited" in shown
    assert "Patch these first" in shown


def test_epss_label_and_state():
    from netzilla.clients import epss

    assert epss.label({"epss": 0.97, "percentile": 0.999}) == "97.0% (top 1%)"
    assert epss.label({"epss": 0.0004, "percentile": 0.1}).endswith("(lower half)")
    # FIRST reports 0.99999 for the most-exploited CVEs: never rounded to 100%.
    assert epss.label({"epss": 0.99999, "percentile": 0.99997}) == ">99.9% (top 1%)"
    assert epss.label({"epss": 1.0, "percentile": 1.0}) == "100.0% (top 1%)"
    assert epss.state({"epss": 0.6}) == "bad" and epss.state({"epss": 0.01}) == "ok"
    assert epss.label(None) == "—"


# ============================================================ endoflife.date
ITEMS = [
    {"name": "cisco-ios-xe", "label": "Cisco IOS XE", "aliases": [], "tags": ["cisco"]},
    {"name": "panos", "label": "Palo Alto Networks PAN-OS", "aliases": ["pan-os"],
     "tags": ["palo-alto-networks"]},
    {"name": "ubuntu", "label": "Ubuntu", "aliases": [], "tags": ["os"]},
    {"name": "ubuntu-pro", "label": "Ubuntu Pro", "aliases": [], "tags": ["os"]},
]


def test_endoflife_matching():
    from netzilla.clients import endoflife

    assert endoflife.split_query("Cisco IOS XE 17.9.4") == ("Cisco IOS XE", "17.9.4")
    assert endoflife.split_query("panos") == ("panos", "")
    assert endoflife.split_query("ubuntu v22.04") == ("ubuntu", "22.04")
    assert endoflife.find_products(ITEMS, "Cisco IOS XE")[0]["name"] == "cisco-ios-xe"
    assert endoflife.find_products(ITEMS, "PAN-OS")[0]["name"] == "panos"
    assert endoflife.is_exact(ITEMS[1], "pan-os")
    hits = endoflife.find_products(ITEMS, "ubuntu")
    assert hits[0]["name"] == "ubuntu" and endoflife.is_exact(hits[0], "UBUNTU")
    releases = [{"name": "17.9"}, {"name": "17.12"}, {"name": "17"}]
    assert endoflife.match_release(releases, "17.9.4")["name"] == "17.9"
    assert endoflife.match_release(releases, "17.12")["name"] == "17.12"
    assert endoflife.match_release(releases, "16.1") is None


def test_endoflife_release_state():
    from netzilla.clients import endoflife

    text, state = endoflife.release_state({"isEol": True, "eolFrom": "2020-01-01"})
    assert state == "bad" and "2020-01-01" in text
    text, state = endoflife.release_state({"isEol": False, "isEoas": True,
                                           "eolFrom": "2099-01-01"})
    assert state == "warn" and "SECURITY FIXES ONLY" in text
    text, state = endoflife.release_state({"isEol": False, "eolFrom": "2099-01-01"})
    assert state == "ok"
    assert endoflife.status_word({"isEol": True}) == "end of life"
    # The release asked about is marked — and shown even when it is older
    # than the newest cycles listed.
    cycles = [{"name": f"1.{n}", "isEol": n < 18} for n in range(20, 0, -1)]
    rows = endoflife.release_rows(cycles, limit=3, mine=cycles[-1])
    assert [r[0] for r in rows] == ["1.20", "1.19", "1.18", "1.1  ◀ yours"]
    assert endoflife.release_rows(cycles, limit=3, mine=cycles[1])[1][0] == "1.19  ◀ yours"


def test_lifecycle_software_eol(monkeypatch, tmp_path):
    from netzilla.clients import endoflife
    from netzilla.screens.lifecycle import LifecyclePane
    from netzilla.services import ApiResult, Services

    async def products(services):
        return ApiResult.success("endoflife", ITEMS)

    async def product(services, name):
        return ApiResult.success("endoflife", {
            "name": name, "label": "Palo Alto Networks PAN-OS", "category": "os",
            "releases": [
                {"name": "11.1", "isEol": False, "eolFrom": "2099-05-03", "isMaintained": True},
                {"name": "10.2", "isEol": True, "eolFrom": "2025-08-27"},
            ]})

    monkeypatch.setattr(endoflife, "products", products)
    monkeypatch.setattr(endoflife, "product", product)
    services = Services(Config.load(tmp_path / "c.toml", use_defaults=False))

    class Pane(_Recorder, LifecyclePane):
        def __init__(self, fields):
            LifecyclePane.__init__(self)
            _Recorder.__init__(self, fields)

        @property
        def palette(self):
            return PALETTE

        @property
        def services(self):
            return services

    pane = Pane({"software": "PAN-OS 10.2.7"})
    asyncio.run(pane.execute("software"))
    shown = pane.text()
    assert "END OF LIFE since 2025-08-27" in shown
    assert "11.1" in shown and "10.2" in shown
    pane = Pane({"software": "ubu"})
    asyncio.run(pane.execute("software"))
    assert "products matching" in pane.text().lower() and "ubuntu-pro" in pane.text()
    assert LifecyclePane.submit_action_for("in-software") == "software"
    assert LifecyclePane.submit_action_for("in-search") == "search"
    assert LifecyclePane.submit_action_for("in-part") == "part"


# ============================================================ terminal detection
def test_xtversion_parsing():
    parse = termcaps.parse_xtversion
    assert parse("kitty(0.36.4)") == ("kitty", "0.36.4")
    assert parse("ghostty 1.1.3") == ("ghostty", "1.1.3")
    assert parse("WezTerm 20240203-110809-5046fc22")[0] == "wezterm"
    assert parse("XTerm(390)") == ("xterm", "390")
    assert parse("tmux 3.4") == ("tmux", "3.4")
    assert parse("foot(1.17.2)") == ("foot", "1.17.2")
    assert termcaps.version_tuple("1.2.0-dev+abc") == (1, 2, 0)


def _replies(*parts: str) -> bytes:
    return "".join(parts).encode()


DA1 = "\x1b[?62;22c"


def test_kitty_answering_the_probe_gets_pixels():
    replies = _replies("\x1bP>|kitty(0.36.4)\x1b\\", "\x1b_Gi=31;OK\x1b\\",
                       "\x1b[6;21;10t", DA1)
    info = termcaps.detect({"TERM": "xterm-kitty"}, replies)
    assert info.name == "kitty" and info.version == "0.36.4"
    assert info.identified_by == "XTVERSION reply"
    assert info.placeholders and info.truecolor and info.cell_px == (10, 21)
    assert info.graphics_mode("auto") == "pixel"
    assert info.graphics_mode("text") == "text"
    assert info.notify == "osc99" and info.hyperlinks and info.clipboard


def test_old_kitty_is_told_to_update():
    replies = _replies("\x1bP>|kitty(0.26.5)\x1b\\", "\x1b_Gi=31;OK\x1b\\", DA1)
    info = termcaps.detect({"TERM": "xterm-kitty"}, replies)
    assert not info.placeholders and info.graphics_mode() == "text"
    assert "0.28.0" in info.graphics_reason()


def test_ghostty_from_environment_and_from_its_reply():
    env = {"TERM": "xterm-ghostty", "TERM_PROGRAM": "ghostty",
           "TERM_PROGRAM_VERSION": "1.1.3"}
    info = termcaps.detect(env)                       # not asked: environment only
    assert info.name == "ghostty" and info.version == "1.1.3" and info.placeholders
    replies = _replies("\x1bP>|ghostty 1.2.0\x1b\\", "\x1b_Gi=31;OK\x1b\\", DA1)
    info = termcaps.detect(env, replies)
    assert info.version == "1.2.0" and info.graphics_mode() == "pixel"
    assert info.notify == "osc777"


def test_feature_query_decides_when_answered():
    no = _replies("\x1bP>|kitty(0.50.1)\x1b\\", "\x1b_Gi=31;OK\x1b\\",
                  "\x1b_Gi=32,e=T;OK\x1b\\", DA1)
    assert not termcaps.detect({}, no).placeholders
    yes = _replies("\x1b_Gi=31;OK\x1b\\", "\x1b_Gi=32,e=T,U=1;OK\x1b\\", DA1)
    info = termcaps.detect({"TERM": "xterm-256color", "COLORTERM": "truecolor"}, yes)
    assert info.placeholders and info.feature_query


@pytest.mark.parametrize("env,name", [
    ({"TERM_PROGRAM": "WezTerm", "TERM_PROGRAM_VERSION": "20240203"}, "wezterm"),
    ({"KONSOLE_VERSION": "230804"}, "konsole"),
    ({"VTE_VERSION": "7600"}, "vte"),
    ({"TERM_PROGRAM": "iTerm.app"}, "iterm2"),
    ({"WT_SESSION": "x"}, "windows-terminal"),
    ({"TERM_PROGRAM": "Apple_Terminal"}, "apple-terminal"),
    ({"TERM": "alacritty"}, "alacritty"),
    ({"TERM": "foot"}, "foot"),
])
def test_other_terminals_get_text_graphs(env, name):
    replies = _replies("\x1b_Gi=31;OK\x1b\\", DA1) if name in ("wezterm", "konsole") \
        else _replies(DA1)
    info = termcaps.detect(env, replies)
    assert info.name == name, info
    assert info.graphics_mode("auto") == "text"
    assert info.graphics_reason()
    if name == "konsole":
        assert info.version == "23.08.04"
    if name == "vte":
        assert info.version == "0.76.0"


TMUX_KITTY = {"termtype": "kitty(0.36.4)", "termname": "xterm-kitty",
              "features": "256,RGB,bpaste,clipboard,focus,title"}


def test_tmux_needs_passthrough():
    env = {"TMUX": "/tmp/tmux-1/default,1,0", "TERM_PROGRAM": "tmux",
           "TERM_PROGRAM_VERSION": "3.4", "KITTY_WINDOW_ID": "1"}
    without = termcaps.detect(env, _replies("\x1bP>|tmux 3.4\x1b\\", DA1), tmux=TMUX_KITTY)
    assert without.multiplexer == "tmux" and not without.placeholders
    assert "allow-passthrough" in without.graphics_reason()
    with_pass = termcaps.detect(env, _replies("\x1bP>|tmux 3.4\x1b\\",
                                              "\x1b_Gi=33;OK\x1b\\", DA1), tmux=TMUX_KITTY)
    assert with_pass.placeholders and with_pass.passthrough and with_pass.name == "kitty"
    assert with_pass.version == "0.36.4" and "tmux 3.4" in with_pass.where
    wrapped = termcaps.wrap_tmux("\x1b_Ga=d\x1b\\")
    assert wrapped.startswith("\x1bPtmux;\x1b\x1b_G") and wrapped.endswith("\x1b\\")


def test_tmux_trusts_tmux_not_a_stale_environment():
    """A tmux server keeps the environment of the terminal that started it:
    KITTY_WINDOW_ID can be left over while the user is attached from
    WezTerm, which answers the graphics query but has no placeholders."""
    env = {"TMUX": "/tmp/tmux-1/default,1,0", "KITTY_WINDOW_ID": "1"}
    replies = _replies("\x1bP>|tmux 3.4\x1b\\", "\x1b_Gi=33;OK\x1b\\", DA1)
    wezterm = termcaps.detect(env, replies, tmux={
        "termtype": "WezTerm 20240203-110809-5046fc22", "termname": "xterm-256color",
        "features": "256,RGB,clipboard"})
    assert wezterm.name == "wezterm" and not wezterm.placeholders
    # tmux can't be asked: the leftover variable isn't trusted either.
    unknown = termcaps.detect(env, replies, tmux=None)
    assert not unknown.placeholders and "could not be identified" in unknown.graphics_reason()
    # The outside terminal answered the feature query itself: that decides.
    answered = termcaps.detect(env, _replies("\x1bP>|tmux 3.4\x1b\\", "\x1b_Gi=33;OK\x1b\\",
                                             "\x1b_Gi=34,e=T,U=1;OK\x1b\\", DA1), tmux=None)
    assert answered.placeholders
    # tmux without 24-bit colour would mangle every image id.
    no_rgb = dict(TMUX_KITTY, features="256,bpaste,clipboard")
    flat = termcaps.detect(env, replies, tmux=no_rgb)
    assert not flat.pixel_capable() and "RGB" in flat.graphics_reason()


def test_probe_never_sends_bare_graphics_queries_inside_a_multiplexer():
    """Bare APC inside tmux becomes the pane title; inside GNU screen, its
    status line. There the graphics questions are wrapped, or not asked."""
    plain = termcaps.probe_query()
    assert "\x1b_Gi=31" in plain and plain.endswith(termcaps.DA1_Q)
    tmux = termcaps.probe_query(in_tmux=True)
    assert tmux.endswith(termcaps.DA1_Q)
    unwrapped = tmux.replace(termcaps.wrap_tmux(termcaps.TMUX_KITTY_Q), "").replace(
        termcaps.wrap_tmux(termcaps.TMUX_FEATURE_Q), "")
    assert "\x1b_G" not in unwrapped and "i=34,e=T,U=1" in tmux
    assert "\x1b_G" not in termcaps.probe_query(graphics=False)


def test_no_color_means_text_graphs_and_colorterm_is_filled_in():
    info = termcaps.detect({"TERM": "xterm-kitty", "NO_COLOR": "1"},
                           _replies("\x1bP>|kitty(0.36.4)\x1b\\", "\x1b_Gi=31;OK\x1b\\", DA1))
    assert not info.placeholders and "NO_COLOR" in info.graphics_reason()
    # Over SSH COLORTERM is usually missing; Textual would draw in 256
    # colours. A terminal known to have 24-bit colour gets it filled in.
    env = {"TERM": "xterm-kitty", "SSH_CONNECTION": "1 2 3 4"}
    kitty_info = termcaps.detect(env, _replies("\x1bP>|kitty(0.36.4)\x1b\\", DA1))
    termcaps.use_truecolour(kitty_info, env)
    assert env["COLORTERM"] == "truecolor"
    vt = {"TERM": "vt100"}
    termcaps.use_truecolour(termcaps.detect(vt), vt)
    assert "COLORTERM" not in vt
    quiet = {"TERM": "xterm-kitty", "NO_COLOR": ""}
    termcaps.use_truecolour(termcaps.detect(quiet), quiet)
    assert "COLORTERM" not in quiet


def test_ssh_is_noted():
    info = termcaps.detect({"TERM": "xterm-kitty", "SSH_CONNECTION": "1 2 3 4"})
    assert info.remote and "over SSH" in info.where


def test_probe_is_skipped_without_a_terminal(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    info = termcaps.startup(allow_probe=True)
    assert not info.probed


# ============================================================ kitty protocol
def test_image_upload_is_chunked_quietly():
    png = os.urandom(9000)
    sequences = kitty.transmit_sequences(png, 4242, 30, 6)
    assert sequences[0].startswith("\x1b_Ga=T,U=1,f=100,t=d,i=4242,c=30,r=6,q=2,m=1;")
    assert sequences[-1].startswith("\x1b_Gm=0,q=2;")
    payload = ""
    for seq in sequences:
        body = seq.split(";", 1)[1][:-2]
        assert len(body) <= 4096
        payload += body
    for seq in sequences[:-1]:
        assert len(seq.split(";", 1)[1][:-2]) % 4 == 0
    assert base64.standard_b64decode(payload) == png


def test_placeholders_carry_row_column_and_id():
    rows = kitty.placeholder_rows(0x2A0B07, 3, 2)
    assert len(rows) == 2
    first = rows[0].plain
    assert first.count(kitty.PLACEHOLDER) == 3
    assert first[1:3] == kitty.DIACRITICS[0] + kitty.DIACRITICS[0]
    assert rows[1].plain[1] == kitty.DIACRITICS[1]
    assert str(rows[0].style.color.triplet.hex) == "#2a0b07"
    from rich.cells import cell_len
    assert cell_len(first) == 3


def test_canvas_double_buffers_and_frees():
    written = []
    kitty.set_writer(written.append)
    canvas = kitty.Canvas()
    ids = [canvas.upload(b"png", 4, 2) for _ in range(4)]
    deletes = [w for w in written if "a=d,d=I" in w]
    assert len(deletes) == 2, "only the frame before last is freed each time"
    assert f"i={ids[0]}" in deletes[0] and f"i={ids[1]}" in deletes[1]
    canvas.clear()
    deletes = [w for w in written if "a=d,d=I" in w]
    assert len(deletes) == 4


def test_tmux_wrapping_of_image_commands():
    written = []
    kitty.set_writer(written.append, tmux=True)
    kitty.delete(123)
    assert written[0].startswith("\x1bPtmux;\x1b\x1b_Ga=d")


# ============================================================ pixel plots
def _png_size(png: bytes) -> tuple[int, int]:
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    width, height = struct.unpack(">II", png[16:24])
    return width, height


@pytest.mark.skipif(not plot.HAVE_PIL, reason="Pillow not installed")
def test_line_chart_is_exactly_the_cells_it_fills():
    frame = plot.Frame(cols=40, rows=6, cell_w=9, cell_h=19)
    png = plot.line_chart([plot.Series([-80, -60, None, -50, -45], colour="signal")],
                          frame, plot.Theme.from_palette(PALETTE), floor=-90, ceil=-30,
                          grid_rows=(0, 3, 5))
    assert _png_size(png) == (360, 114)


def _brightest_row(png: bytes, x: int) -> int:
    """The y of the brightest pixel in column x of a PNG (the drawn line)."""
    from PIL import Image

    image = Image.open(io.BytesIO(png)).convert("RGB")
    column = [sum(image.getpixel((x, y))) for y in range(image.height)]
    return column.index(max(column))


@pytest.mark.skipif(not plot.HAVE_PIL, reason="Pillow not installed")
def test_graph_labels_are_the_values_on_their_grid_lines():
    """The middle label used to sit half a row away from its value on even
    heights (-60 dBm drawn level with a line labelled -64). Graphs are now an
    odd number of rows, and every labelled row centre is exactly its value."""
    assert charts._odd(8) == 9 and charts._odd(9) == 9 and charts._odd(4) == 5
    frame = plot.Frame(cols=30, rows=9, cell_w=10, cell_h=20)
    theme = plot.Theme.from_palette(PALETTE)
    for value, row in ((-30, 0), (-60, 4), (-90, 8)):
        png = plot.line_chart([plot.Series([value] * 30, colour="#ffffff", fill=False)],
                              frame, theme, floor=-90, ceil=-30, grid_rows=())
        assert abs(_brightest_row(png, 150) - frame.row_centre(row)) <= 2, value
    # The spectrum: a network at the middle value peaks on the middle line.
    aps = [{"ssid": "", "band": "2.4 GHz", "channel": 6, "signal_dbm": -60}]
    png = plot.spectrum_chart(aps, "2.4 GHz", frame, theme, floor=-95, ceil=-25,
                              grid_rows=())
    x = int(plot.channel_x(6, "2.4 GHz", frame.width))
    assert abs(_brightest_row(png, x) - frame.row_centre(4)) <= 3
    text = plain(charts.render(charts.LineGraph([-60] * 30, -90, -30, width=30, height=8),
                               charts.Context(pixel=False, palette=PALETTE)))
    assert len([line for line in text.splitlines() if "┤" in line]) == 9


@pytest.mark.skipif(not plot.HAVE_PIL, reason="Pillow not installed")
def test_spectrum_logo_and_gauge_render():
    theme = plot.Theme.from_palette(PALETTE)
    aps = [{"ssid": "HomeNet", "band": "2.4 GHz", "channel": 6, "signal_dbm": -40,
            "in_use": True},
           {"ssid": "Wide", "band": "5 GHz", "channel": 36, "centre_channel": 42,
            "width_mhz": 80, "signal_dbm": -60}]
    frame = plot.Frame(cols=50, rows=8, cell_w=8, cell_h=16)
    assert _png_size(plot.spectrum_chart(aps, "2.4 GHz", frame, theme)) == (400, 128)
    assert _png_size(plot.spectrum_chart(aps, "5 GHz", frame, theme)) == (400, 128)
    assert _png_size(plot.logo(["█╗", "╚█"], plot.Frame(2, 2, 10, 20), theme,
                               ["#ff0000", "#00ff00"])) == (20, 40)
    assert _png_size(plot.bar_gauge(0.5, plot.Frame(10, 1, 10, 20), theme,
                                    "#00ff00")) == (100, 20)


def test_signal_gradient_follows_the_semantic_scale():
    from netzilla.colours import SEMANTIC

    assert plot.signal_rgb(-30) == plot.rgb(SEMANTIC["excellent"])
    assert plot.signal_rgb(-95) == plot.rgb(SEMANTIC["very weak"])


# ============================================================ graphs, both modes
GRAPH = charts.LineGraph([-70, -65, -60, -58], floor=-90, ceil=-30, width=20, height=5,
                         label=lambda v: f"{v:.0f} dBm")


def test_text_graph_is_the_classic_block_chart():
    from netzilla.local.wifitools import chart_lines

    ctx = charts.Context(pixel=False, palette=PALETTE, colour="#00ff00",
                         edge=PALETTE.background)
    text = charts.render(GRAPH, ctx)
    expected = chart_lines(GRAPH.values, height=5, width=20, floor=-90, ceil=-30,
                           label=GRAPH.label)
    # Full blocks are drawn as outlined cells, so compare everything else.
    assert text.plain.replace("▕", "█") == "\n".join(expected)


@pytest.mark.skipif(not plot.HAVE_PIL, reason="Pillow not installed")
def test_pixel_graph_has_the_same_frame_as_the_text_one():
    written = []
    kitty.set_writer(written.append)
    canvas = kitty.Canvas()
    ctx = charts.Context(pixel=True, palette=PALETTE, canvas=canvas, cell_px=(8, 16))
    text_ctx = charts.Context(pixel=False, palette=PALETTE)
    pixel = charts.render(GRAPH, ctx)
    words = charts.render(GRAPH, text_ctx)
    assert len(pixel.plain.splitlines()) == len(words.plain.splitlines())
    for a, b in zip(pixel.plain.splitlines(), words.plain.splitlines()):
        assert a.split("┤")[0] == b.split("┤")[0]        # same axis labels
    from rich.cells import cell_len
    assert max(cell_len(l) for l in pixel.plain.splitlines()) == \
        max(cell_len(l) for l in words.plain.splitlines())
    assert pixel.plain.count(kitty.PLACEHOLDER) == 20 * 5
    assert any(w.startswith("\x1b_Ga=T") for w in written)


def test_pixel_graph_falls_back_to_text_when_drawing_fails(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("no pixels today")

    monkeypatch.setattr(plot, "line_chart", boom)
    ctx = charts.Context(pixel=True, palette=PALETTE, canvas=kitty.Canvas())
    text = charts.render(GRAPH, ctx)
    assert kitty.PLACEHOLDER not in text.plain and "┤" in text.plain


def test_braille_spectrum_marks_peaks_and_channels():
    aps = [{"ssid": "HomeNet", "band": "2.4 GHz", "channel": 6, "signal_dbm": -40,
            "in_use": True},
           {"ssid": "Next door", "band": "2.4 GHz", "channel": 1, "signal_dbm": -70}]
    text = charts.render(charts.SpectrumGraph(aps, "2.4 GHz", width=80, height=8),
                         charts.Context(pixel=False, palette=PALETTE))
    shown = text.plain
    assert "● HomeNet" in shown and "Next door" in shown
    assert any(0x2800 < ord(c) <= 0x28FF for c in shown)
    assert " 1 " in shown.splitlines()[-1] and "11" in shown.splitlines()[-1]


def test_speed_graph_fills_a_fixed_time_axis_from_the_left():
    graph = charts.LineGraph([10, 20], floor=0, ceil=40, width=30, height=3,
                             slots=10, align="left", colour="#fff")
    text = charts.render(graph, charts.Context(pixel=False, palette=PALETTE))
    bottom = [line for line in text.plain.splitlines() if "┤" in line][-1]
    body = bottom.split("┤", 1)[1]
    assert len(body) == 30                    # 10 slots of 3 columns
    assert body[0] != " " and body[5] != " "  # the two samples, from the left
    assert body[6:].strip() == ""             # the rest of the run still to come


# ============================================================ the app
def _app(tmp_path, **kwargs):
    from netzilla.app import NetzillaApp

    return NetzillaApp(config_path=tmp_path / "config.toml", offline=True,
                       use_default_keys=False, **kwargs)


def test_only_the_opening_tab_is_built_at_start(tmp_path):
    from netzilla.screens.base import LookupPane
    from netzilla.screens.wifi import WifiPane

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            panes = [p for p in app.query(LookupPane)]
            assert len(panes) == 1 and type(panes[0]).__name__ == "DashboardPane"
            assert not app.query(WifiPane)
            await app.action_show_tab("WIFI")
            await pilot.pause()
            assert app.query(WifiPane)
            pane = await app.ensure_tab("wifi")
            assert pane is app.query_one(WifiPane), "built once, not twice"

    asyncio.run(go())


@pytest.mark.parametrize("name,tab", [
    ("wifi", "wifi"), ("WIFI", "wifi"), ("Wi-Fi", "wifi"), ("dns/whois", "dns"),
    ("DNS", "dns"), ("ip lookup", "ip"), ("IP", "ip"), ("Dash", "dashboard"),
    ("life", "lifecycle"), ("nonsense", None), ("", None),
])
def test_tab_names_in_any_case(name, tab):
    from netzilla.app import resolve_tab

    assert resolve_tab(name) == tab


def test_start_tab_by_label(tmp_path):
    from netzilla.screens.lifecycle import LifecyclePane

    async def go():
        app = _app(tmp_path, start_tab="LIFECYCLE")
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            assert app.query_one("#tabs").active == "lifecycle"
            assert app.query(LifecyclePane)

    asyncio.run(go())


def test_letter_keys_work_in_both_cases(tmp_path):
    from textual.widgets import Input

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            seen = [app.config_obj.theme]
            for key in ("t", "T", "ctrl+t"):
                await pilot.press(key)
                await pilot.pause()
                seen.append(app.config_obj.theme)
            assert len(set(seen)) == 4, seen
            # In a text box a letter is just a letter…
            await app.action_show_tab("ip")
            await pilot.pause()
            box = app.query_one("#in-ip", Input)
            box.focus()
            await pilot.pause()
            before = app.config_obj.theme
            await pilot.press("T")
            await pilot.pause()
            assert box.value == "T" and app.config_obj.theme == before
            # …and Ctrl+T still changes the theme.
            await pilot.press("ctrl+t")
            await pilot.pause()
            assert app.config_obj.theme != before
            footer = [str(w.render()).strip() for w in app.query("FooterKey")]
            assert "T Theme" not in footer, "hidden while typing — it would type"
            app.query_one("ContentTabs").focus()
            await pilot.pause()
            footer = [str(w.render()).strip() for w in app.query("FooterKey")]
            for label in ("Q Quit", "T Theme", "F3 Hide/show controls", "F4 Copy output"):
                assert label in footer, footer

    asyncio.run(go())


@pytest.mark.parametrize("key", ["q", "Q"])
def test_q_quits_in_both_cases(tmp_path, key):
    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            await pilot.press(key)
            await pilot.pause()
            return app.is_running

    assert asyncio.run(go()) is False


def test_function_keys(tmp_path, monkeypatch):
    from netzilla import clipboard

    copied = []
    monkeypatch.setattr(clipboard, "copy", lambda text, app=None, directory=None:
                        copied.append(text) or "to a test clipboard")

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            await pilot.press("f2")
            await pilot.pause()
            assert app.query_one("#tabs").active == "settings"
            await pilot.press("f1")
            await pilot.pause()
            assert app.query_one("#tabs").active == "dashboard"
            await pilot.press("f3")
            await pilot.pause()
            assert app._active_pane().controls_collapsed
            await pilot.press("f3")
            await pilot.pause()
            assert not app._active_pane().controls_collapsed
            await app.workers.wait_for_complete()
            await pilot.press("f4")
            await pilot.pause()
            assert copied and "LOCAL TOOLING" in copied[0]

    asyncio.run(go())


def test_enter_in_a_box_runs_that_boxs_action(tmp_path):
    from netzilla.screens.creds import CredsPane

    assert CredsPane.submit_action_for("in-term") == "breach"
    assert CredsPane.submit_action_for("in-value") == "password"
    assert CredsPane.FIELDS[0].password, "the password box is masked"

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            await app.action_show_tab("creds")
            await pilot.pause()
            pane = app.query_one(CredsPane)
            assert pane.query_one("#in-value").password
            ran = []
            pane.dispatch = ran.append
            pane.query_one("#in-term").focus()
            await pilot.press("a", "d", "enter")
            await pilot.pause()
            assert ran == ["breach"]

    asyncio.run(go())


def test_command_palette_has_tabs_themes_and_graphics(tmp_path):
    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            titles = [c.title for c in app.get_system_commands(app.screen)]
            assert "Go to WIFI" in titles and "Go to SETTINGS" in titles
            assert any(t.startswith("Theme: ") for t in titles)
            assert {"Graphics: auto", "Graphics: pixel", "Graphics: text"} <= set(titles)
            assert "Theme" not in titles, "Textual's own theme picker is replaced"
            go_wifi = next(c for c in app.get_system_commands(app.screen)
                           if c.title == "Go to WIFI")
            go_wifi.callback()
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.query_one("#tabs").active == "wifi"

    asyncio.run(go())


def test_every_button_on_every_tab_runs_without_a_bug(tmp_path, monkeypatch):
    """The control audit: press every action button on every tab (offline,
    with the tools this machine happens to have) and fail on any
    'Unexpected error' — the panel netzilla shows for its own bugs."""
    from textual.widgets import Input, TextArea

    from netzilla.app import TABS
    from netzilla.local import oui
    from netzilla.screens.base import LookupPane
    from netzilla.screens.wifi import WifiPane

    monkeypatch.setattr(WifiPane, "MAX_TICKS", 2)
    monkeypatch.setattr(WifiPane, "AIR_EVERY", 0.05)
    monkeypatch.setattr(WifiPane, "LINK_EVERY", 0.05)
    monkeypatch.setattr(WifiPane, "TRAFFIC_EVERY", 0.05)
    monkeypatch.setattr(WifiPane, "EXPORT_BASE", tmp_path)
    monkeypatch.setattr(oui, "update_from_ieee", lambda *a, **k: 0)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    # Only the machine's real tools: no fake tshark/iw left on PATH by
    # another test's temporary directory.
    real_path = os.pathsep.join(
        d for d in os.environ.get("PATH", "").split(os.pathsep)
        if d and "pytest-of" not in d and not d.startswith("/tmp/"))
    monkeypatch.setenv("PATH", real_path)
    from netzilla.local import typosquat

    async def no_squat(*a, **k):
        return {"original": "example.com", "checked": 0, "registered": [],
                "wildcard_resolver": []}

    monkeypatch.setattr(typosquat, "scan", no_squat)
    from netzilla.local import tls_quick, dns_whois
    from netzilla.local.runner import CommandResult

    async def quick_openssl(*a, **k):
        return CommandResult(ok=False, output="", error="openssl skipped in tests",
                             missing_tool=None)

    monkeypatch.setattr(tls_quick, "openssl_probe", quick_openssl)

    def quick_cert(host, port=443, timeout=10.0):
        return {"ok": False, "error": "no network in tests"}

    monkeypatch.setattr(tls_quick, "inspect_certificate", quick_cert)

    values = {
        "ip": {"ip": "8.8.8.8"}, "subnet": {"network": "192.168.10.0/24"},
        "dns": {"target": "example.com"}, "tls": {"host": "example.com"},
        "bgp": {"resource": "8.8.8.8"}, "threat": {"query": "CVE-2024-3400"},
        "discovery": {"ip": "1.1.1.1"}, "lan": {"target": "127.0.0.1", "secs": "5"},
        "int": {"secs": "2"}, "flow": {"secs": "4"}, "mac": {"mac": "00:1A:2B:3C:4D:5E"},
        "lifecycle": {"part": "WS-C3850-24T-L", "software": "panos 10.2"},
        "diag": {"host": "127.0.0.1", "count": "1", "port": "1"},
        "creds": {"value": "hunter2", "term": "adobe"},
    }
    bugs, pressed = [], []

    async def settle(app, timeout=60.0):
        """Wait for every worker; one cancelled by a newer press of its own
        tab is expected, not a failure."""
        from textual.worker import WorkerState

        async def wait_all():
            while True:
                running = [w for w in app.workers
                           if w.state in (WorkerState.PENDING, WorkerState.RUNNING)]
                if not running:
                    return
                await asyncio.gather(*(w.wait() for w in running), return_exceptions=True)

        await asyncio.wait_for(wait_all(), timeout)

    async def go():
        app = _app(tmp_path)
        original = LookupPane.push_error

        async def push_error(self, title, message):
            if title == "Unexpected error":
                bugs.append((type(self).__name__, message.splitlines()[0]))
            return await original(self, title, message)

        monkeypatch.setattr(LookupPane, "push_error", push_error)
        async with app.run_test(size=(200, 60)) as pilot:
            for tab_id, _label, cls in TABS:
                await app.action_show_tab(tab_id)
                await pilot.pause()
                await settle(app)
                pane = app.query_one(cls)
                for button in [b for b in pane.query("Button")
                               if (b.id or "").startswith("act-")]:
                    if (tab_id, button.id) in (("lan", "act-syslog"), ("lan", "act-dupip"),
                                               ("flow", "act-watch"), ("diag", "act-ntp"),
                                               ("lan", "act-dhcp")):
                        continue        # long listeners: covered by their own tests
                    for field, value in values.get(tab_id, {}).items():
                        for box in pane.query(f"#in-{field}"):
                            if isinstance(box, Input):
                                box.value = value
                    if tab_id == "config":
                        pane.query_one(TextArea).text = "interface Gi0/1\n shutdown\n"
                    button.press()
                    await pilot.pause()
                    try:
                        await settle(app)
                    except asyncio.TimeoutError:
                        running = [w.name for w in app.workers if not w.is_finished]
                        bugs.append((f"{tab_id}:{button.id}", f"still running: {running}"))
                        app.workers.cancel_all()
                    await pilot.pause()
                    pressed.append(f"{tab_id}:{button.id}")

    asyncio.run(go())
    assert not bugs, bugs
    assert len(pressed) >= 100, len(pressed)


def test_channels_pressed_twice_replaces_its_output(tmp_path):
    """CHANNELS reuses the last scan; it used to append its panels under
    whatever was on screen, so a second press showed everything twice."""
    from netzilla.screens.wifi import WifiPane

    aps = [{"ssid": "A", "bssid": "aa:bb:cc:dd:ee:01", "channel": 6, "band": "2.4 GHz",
            "signal_dbm": -50, "security": "WPA2", "in_use": True},
           {"ssid": "B", "bssid": "aa:bb:cc:dd:ee:02", "channel": 11, "band": "2.4 GHz",
            "signal_dbm": -70, "security": "WPA2"},
           {"ssid": "C", "bssid": "aa:bb:cc:dd:ee:03", "channel": 36, "band": "5 GHz",
            "signal_dbm": -60, "security": "WPA3"}]

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            await app.action_show_tab("wifi")
            await pilot.pause()
            pane = app.query_one(WifiPane)
            pane._last = aps
            counts = []
            for _ in range(2):
                pane.query_one("#act-channels").press()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                counts.append(len([c for c in pane.results.children if c.display]))
            return counts

    first, second = asyncio.run(go())
    assert first == second and first >= 4, (first, second)


# ============================================================ pixel mode in the app
def test_pixel_mode_draws_live_air_as_images(tmp_path, monkeypatch):
    """LIVE AIR with pixels on: graphs become placeholder cells, the image
    goes out through the writer, and the text around it is unchanged."""
    import test_v32

    test_v32._radio(tmp_path, monkeypatch)
    written = []
    kitty.set_writer(written.append)
    pane = test_v32._wifi_pane({"iface": "wlan0"}, ticks=2)
    type(pane)._app_setting = lambda self, name, default: {
        "graphics_mode": "pixel", "cell_px": (8, 16)}.get(name, default)
    asyncio.run(pane._live_air())
    shown = test_v32._all_widget_text(pane)
    if plot.HAVE_PIL:
        assert kitty.PLACEHOLDER in shown
        assert any(w.startswith("\x1b_Ga=T,U=1") for w in written)
        assert "-30 dBm ┤" in shown                       # axis labels stay text
    assert "Every network, live".upper() in shown.upper()


@pytest.mark.skipif(not plot.HAVE_PIL, reason="Pillow not installed")
def test_switching_pixel_to_text_still_frees_every_image(tmp_path):
    """Leaving pixel mode used to drop the writer first, so the images on
    screen were never deleted — kitty kept them until the window closed.
    Now every image uploaded is deleted by the time netzilla exits."""
    import re

    written = []

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            kitty.set_writer(written.append)
            app.terminal = termcaps.detect({"TERM": "xterm-kitty"})
            app._pixels_ready = True                  # as in kitty or Ghostty
            app._refresh_static_graphics()            # the DASH banner, as an image
            await pilot.pause()
            assert any("a=T" in w for w in written)
            app.set_graphics("text", persist=False)   # headless: pixels go off
            await pilot.pause()
            assert app.graphics_mode == "text"
        return written

    asyncio.run(go())
    uploaded = {m for w in written for m in re.findall(r"a=T,[^;]*?i=(\d+)", w)}
    deleted = {m for w in written for m in re.findall(r"a=d,d=I,i=(\d+)", w)}
    assert uploaded and uploaded <= deleted, (uploaded, deleted)


def test_pixel_graphs_need_truecolour_output(tmp_path):
    """The image id rides in the placeholder's 24-bit colour, so a Textual
    drawing in 256 colours (COLORTERM missing) can't show pixel graphs."""
    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            return app._pixel_blocker()

    assert "real terminal" in asyncio.run(go())     # headless in tests

    class Console256:
        color_system = "256"

    class FakeApp:
        is_headless = False
        _driver = type("D", (), {"write": lambda self, s: None})()
        console = Console256()
        no_color = False

    from netzilla.app import NetzillaApp

    blocker = NetzillaApp._pixel_blocker(FakeApp())
    if plot.HAVE_PIL:
        assert "256 colours" in blocker and "COLORTERM" in blocker
    FakeApp.console = type("C", (), {"color_system": "truecolor"})()
    FakeApp.no_color = True
    if plot.HAVE_PIL:
        assert "NO_COLOR" in NetzillaApp._pixel_blocker(FakeApp())
    FakeApp.no_color = False
    assert NetzillaApp._pixel_blocker(FakeApp()) in ("", "Pillow is not installed "
                                                     "(pipx runpip netzilla install pillow).")


def test_graphics_setting_round_trip(tmp_path):
    path = tmp_path / "c.toml"
    config = Config.load(path, use_defaults=False)
    assert config.graphics == "auto" and config.notify is True
    config.graphics, config.notify = "text", False
    config.save()
    again = Config.load(path, use_defaults=False)
    assert again.graphics == "text" and again.notify is False
    path.write_text('[display]\ngraphics = "PIXEL"\n')
    assert Config.load(path, use_defaults=False).graphics == "pixel"
    path.write_text('[display]\ngraphics = "sparkles"\n')
    assert Config.load(path, use_defaults=False).graphics == "auto"


def test_stale_user_agent_is_replaced(tmp_path):
    from netzilla.config import DEFAULT_USER_AGENT

    path = tmp_path / "c.toml"
    path.write_text('[general]\nuser_agent = "netzilla/2.0 (+https://github.com/)"\n')
    config = Config.load(path, use_defaults=False)
    assert config.user_agent == DEFAULT_USER_AGENT and __version__ in DEFAULT_USER_AGENT
    config.save()
    assert "user_agent" not in path.read_text()
    path.write_text('[general]\nuser_agent = "my-agent/1.0"\n')
    assert Config.load(path, use_defaults=False).user_agent == "my-agent/1.0"


def test_settings_graphics_select_applies_and_persists(tmp_path):
    from textual.widgets import Select

    async def go():
        app = _app(tmp_path, start_tab="settings")
        async with app.run_test(size=(200, 70)) as pilot:
            await pilot.pause()
            select = app.query_one("#graphics-select", Select)
            assert select.value == "auto"
            select.value = "text"
            await pilot.pause()
            assert app.config_obj.graphics == "text"
            assert app.graphics_mode == "text"
            note = str(app.query_one("#graphics-note").content)
            assert "graphs drawn as TEXT" in note.replace("\n", " ") or "TEXT" in note

    asyncio.run(go())
    assert Config.load(tmp_path / "config.toml", use_defaults=False).graphics == "text"


def test_headless_never_writes_images(tmp_path):
    async def go():
        app = _app(tmp_path, graphics="pixel")
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            assert app.graphics_setting == "pixel"
            assert app.graphics_mode == "text", "no real terminal to draw on"
            assert not kitty.active()

    asyncio.run(go())


def test_dash_shows_the_terminal(tmp_path):
    termcaps.set_current(termcaps.detect({"TERM": "xterm-kitty"}))

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            from netzilla import clipboard

            return clipboard.pane_text(app._active_pane())

    shown = asyncio.run(go())
    assert "TERMINAL" in shown and "kitty" in shown


# ============================================================ copy, notify, links
def test_plain_text_drops_image_placeholders():
    from netzilla import clipboard

    rows = kitty.placeholder_rows(77, 4, 1)
    text = Text("axis ┤")
    text.append_text(rows[0])
    out = clipboard.plain([text])
    assert kitty.PLACEHOLDER not in out and "░░░░" in out


def test_copy_falls_back_to_a_file(tmp_path, monkeypatch):
    from netzilla import clipboard

    monkeypatch.setattr(clipboard, "_tool_command", lambda: None)
    how = clipboard.copy("hello\n", app=None, directory=tmp_path)
    assert how.startswith("saved to") and (tmp_path / how.split("saved to ")[1].split("/")[-1]).exists()


def test_notification_sequences():
    from netzilla import notify

    assert notify.sequence("osc99", "T", "B").startswith("\x1b]99;i=netzilla:d=0;T")
    assert notify.sequence("osc777", "T;x", "B\x1b") == "\x1b]777;notify;T x;B\x07"
    assert notify.sequence("osc9", "T", "B") == "\x1b]9;T: B\x07"
    assert notify.sequence("", "T", "B") == ""


def test_notifications_only_for_long_runs_in_the_background():
    from netzilla import notify

    class Driver:
        def __init__(self):
            self.out = []

        def write(self, data):
            self.out.append(data)

    class App:
        is_headless = False
        app_focus = False

        def __init__(self):
            self._driver = Driver()
            self.config_obj = Config()

    termcaps.set_current(termcaps.TerminalInfo(name="kitty", notify="osc99"))
    app = App()
    assert not notify.finished(app, "SPEED TEST", "RUN SPEED TEST", 3)
    assert notify.finished(app, "SPEED TEST", "RUN SPEED TEST", 20)
    app.app_focus = True
    assert not notify.finished(app, "SPEED TEST", "RUN SPEED TEST", 20)
    app.app_focus, app.config_obj.notify = False, False
    assert not notify.finished(app, "SPEED TEST", "RUN SPEED TEST", 20)


def test_links_only_in_terminals_that_support_them():
    from netzilla.colours import style_cell

    termcaps.set_current(termcaps.TerminalInfo(name="kitty", hyperlinks=True))
    cell = style_cell("Detail", "see CVE-2024-3400", "#ffffff")
    assert any(getattr(s.style, "link", None) ==
               "https://nvd.nist.gov/vuln/detail/CVE-2024-3400" for s in cell.spans)
    termcaps.set_current(termcaps.TerminalInfo(name="xterm"))
    cell = style_cell("Detail", "see CVE-2024-3400", "#ffffff")
    assert not any(getattr(s.style, "link", None) for s in cell.spans)


# ============================================================ speed test
def test_bufferbloat_grades():
    from netzilla.local import cfspeed

    assert cfspeed.bufferbloat_grade(10, 12)[0] == "A+"
    assert cfspeed.bufferbloat_grade(10, 35)[0] == "A"
    assert cfspeed.bufferbloat_grade(10, 150)[0] == "C"
    assert cfspeed.bufferbloat_grade(10, 300)[0] == "D"
    assert cfspeed.bufferbloat_grade(10, 900)[0] == "F"
    assert cfspeed.jitter([10, 20, 10]) == 10.0


def test_speed_tab_draws_the_test_live(tmp_path):
    from netzilla.local import cfspeed
    from netzilla.screens.speedtest_pane import SpeedTestPane

    async def fake_run(callback, user_agent=""):
        progress = cfspeed.Progress()
        progress.latency = [12.0, 13.0]
        for phase, target in (("download", progress.down), ("upload", progress.up)):
            progress.phase = phase
            for value in (100.0, 300.0, 320.0):
                await asyncio.sleep(0.25)
                target.append(value)
                progress.now_mbps = value
                callback(progress)
        # "done" lands straight after the last sample, as in the real test.
        progress.phase = "done"
        callback(progress)
        return {"download_mbps": 310.0, "upload_mbps": 300.0, "ping_ms": 12.5,
                "jitter_ms": 1.0, "loaded_ms": 80.0, "bufferbloat": "C",
                "bufferbloat_added_ms": 67.5, "server_name": "Cloudflare IAD",
                "backend": "Cloudflare (built in)", "downloaded_bytes": 120_000_000}

    async def go():
        app = _app(tmp_path, start_tab="speed")
        app.services.offline = False
        async with app.run_test(size=(200, 70)) as pilot:
            await pilot.pause()
            pane = app.query_one(SpeedTestPane)
            pane.RUNNER = staticmethod(fake_run)
            pane.query_one("#act-run").press()
            await pilot.pause()
            await asyncio.wait_for(app.workers.wait_for_complete(), 30)
            await pilot.pause()
            from netzilla import clipboard

            return clipboard.pane_text(pane)

    shown = asyncio.run(go())
    assert "THROUGHPUT, LIVE" in shown and "Download" in shown
    assert "finished" in shown and "uploading" not in shown, "the last phase is shown"
    assert "310.0 Mbit/s down" in shown and "bufferbloat C" in shown
    assert "bufferbloat grade c" in shown.lower() and "SQM" in shown


def test_speed_tab_respects_offline(tmp_path):
    from netzilla.screens.speedtest_pane import SpeedTestPane

    async def go():
        app = _app(tmp_path, start_tab="speed")
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            pane = app.query_one(SpeedTestPane)
            pane.query_one("#act-run").press()
            await pilot.pause()
            await app.workers.wait_for_complete()
            from netzilla import clipboard

            return clipboard.pane_text(pane)

    assert "offline mode" in asyncio.run(go()).lower()


# ============================================================ DNS without dig
def test_all_records_falls_back_to_dns_over_https(tmp_path, monkeypatch):
    from netzilla.clients import doh
    from netzilla.local import dns_whois
    from netzilla.local.runner import CommandResult
    from netzilla.screens.dns_whois import DNSWhoisPane
    from netzilla.services import ApiResult, Services

    async def no_dig(domain, server="", types=dns_whois.RECORD_TYPES):
        return {t: CommandResult(ok=False, output="", error="", missing_tool="dig")
                for t in types}

    async def answers(services, name, types, resolver="Cloudflare"):
        return {t: ApiResult.success("doh", {"status": 0, "status_name": "NOERROR",
                                             "answers": ["192.0.2.1"] if t == "A" else []})
                for t in types}

    monkeypatch.setattr(dns_whois, "all_records", no_dig)
    monkeypatch.setattr(doh, "resolve_many", answers)
    services = Services(Config.load(tmp_path / "c.toml", use_defaults=False))

    class Pane(_Recorder, DNSWhoisPane):
        def __init__(self, fields):
            DNSWhoisPane.__init__(self)
            _Recorder.__init__(self, fields)

        @property
        def palette(self):
            return PALETTE

        @property
        def services(self):
            return services

    pane = Pane({"target": "example.com", "server": "10.0.0.53"})
    asyncio.run(pane.execute("records"))
    shown = pane.text()
    assert "192.0.2.1" in shown and "DNS-over-HTTPS" in shown
    assert "DNS server box ignored" in shown


def test_null_mx_keeps_its_root_dot():
    from netzilla.clients.doh import normalise_answer

    out = normalise_answer({"Status": 0, "Answer": [{"data": "0 ."},
                                                    {"data": "mx.example.com."}]}, "MX")
    assert out["answers"] == ["0 .", "mx.example.com"]


def test_dns_answers_sort_by_number_not_by_text():
    from netzilla.clients.doh import normalise_answer

    mx = normalise_answer({"Status": 0, "Answer": [
        {"data": "10 mxa.example."}, {"data": "5 mxb.example."}]}, "MX")
    assert mx["answers"] == ["5 mxb.example", "10 mxa.example"]
    a = normalise_answer({"Status": 0, "Answer": [
        {"data": "192.0.2.10"}, {"data": "192.0.2.4"}]}, "A")
    assert a["answers"] == ["192.0.2.4", "192.0.2.10"]


# ============================================================ small fixes
def test_select_null_reads_as_empty():
    from textual.widgets import Select

    from netzilla.screens.base import _is_blank

    assert _is_blank(getattr(Select, "NULL", None) or getattr(Select, "BLANK", None))
    assert not _is_blank("wlan0")


def test_uppercase_url_scheme_is_accepted():
    from netzilla.validators import valid_url

    assert valid_url("HTTPS://Example.com/X") == "https://Example.com/X"


def test_bssid_with_any_separator_finds_the_ap():
    from netzilla.local.wifi import pick_ap

    aps = [{"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "HomeNet"}]
    for target in ("aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff", "AABBCCDDEEFF", "homenet"):
        assert pick_ap(aps, target) is aps[0], target


def test_status_headline_does_not_contradict_the_status():
    """OutageDeck can say operational while the vendor's banner says
    'Partial System Outage' (no incident open): STATUS explains, rather than
    showing OPERATIONAL beside an outage headline."""
    from netzilla.clients import outagedeck

    info = outagedeck.normalise({"name": "Cloudflare", "currentStatus": {
        "code": "operational", "headline": "Partial System Outage"}})
    assert info["status_key"] == "operational"
    assert info["headline"] == "Partial System Outage (vendor page only — no incident open)"
    calm = outagedeck.normalise({"currentStatus": {"code": "operational",
                                                   "headline": "All Systems Operational"}})
    assert calm["headline"] == "All Systems Operational"
    real = outagedeck.normalise({"currentStatus": {"code": "partial_outage",
                                                   "headline": "Partial System Outage"}})
    assert real["headline"] == "Partial System Outage"


def test_abuseipdb_verdict_matches_the_report_count():
    from netzilla.clients.abuseipdb import verdict

    text, state = verdict({"abuseConfidenceScore": 0, "totalReports": 235,
                           "isWhitelisted": True})
    assert state == "ok" and "235 reports" in text and "no abuse reports" not in text
    assert verdict({"abuseConfidenceScore": 0, "totalReports": 0})[0] == \
        "CLEAN — no abuse reports on file"


def test_iw_channel_width_is_parsed():
    from netzilla.local.wifi import _iw_width

    block = ("\tHT operation:\n\t\t * primary channel: 36\n"
             "\t\t * secondary channel offset: above\n"
             "\tVHT operation:\n\t\t * channel width: 1 (80 MHz)\n"
             "\t\t * center freq segment 1: 42\n\t\t * center freq segment 2: 0\n")
    assert _iw_width(block, 36) == (80, 42)
    assert _iw_width("\t\t * secondary channel offset: below\n", 6) == (40, 4)
    assert _iw_width("", 11) == (20, 11)


def test_cli_matches_names_in_any_case(capsys):
    from netzilla.cli import build_parser

    args = build_parser().parse_args(["SUBNET", "10.0.0.0/30", "--theme", "AMBER-PHOSPHOR",
                                      "--graphics", "TEXT"])
    assert args.command == "subnet" and args.theme == "amber-phosphor"
    assert args.graphics == "text"


def test_cli_output_into_a_closed_pipe_is_quiet(monkeypatch):
    """`netzilla dns example.com | head -3` used to end in a BrokenPipeError
    traceback once head had what it wanted."""
    from netzilla import cli

    class ClosedPipe(io.StringIO):
        def write(self, text):
            raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr("sys.stdout", ClosedPipe())
    assert cli.main(["subnet", "10.0.0.0/22"]) == 1


def test_cli_rejects_an_unknown_tab(capsys):
    from netzilla.cli import main

    with pytest.raises(SystemExit):
        main(["--tab", "nowhere"])
    assert "unknown tab" in capsys.readouterr().err


def test_cli_terminal_report(capsys, monkeypatch):
    from netzilla.cli import main

    monkeypatch.setenv("TERM", "xterm-kitty")
    assert main(["--terminal", "--no-probe"]) == 0
    out = capsys.readouterr().out
    assert "kitty" in out and "Graphs will be drawn as" in out
