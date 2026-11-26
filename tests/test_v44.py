"""Tests for netzilla 4.4: pictures either side of DASH's title.

  * on the left, a horned beast breathing a storm of energy at the title; on
    the right, Tokyo at night (both pictures shipped with netzilla, coloured
    from the theme — 4.5 made the city a picture too and the breath alive)
  * part of the banner image in kitty and Ghostty, sextant characters
    anywhere else — the beast shaded, two colours to a cell inside it
  * shown only when the window has room; the title stays centred and DASH
    still fits a 160 x 50 screen
"""

from __future__ import annotations

import asyncio
import base64
import io
import re

import pytest
from rich.cells import cell_len
from rich.console import Console

from netzilla import __version__, termcaps
from netzilla.graphics import banner, kitty, plot
from netzilla.screens.dashboard import BANNER, _WIDTH, text_banner
from netzilla.themes import THEME_NAMES, get_palette

pytestmark = pytest.mark.skipif(not plot.HAVE_PIL, reason="Pillow not installed")

LINES = BANNER.splitlines()
ROWS = len(LINES)


@pytest.fixture(autouse=True)
def _no_writer():
    kitty.set_writer(None)
    yield
    kitty.set_writer(None)


def test_version_is_4_4():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (4, 4), __version__


# ============================================================== sextants
def _bits(char: str) -> int:
    if char == " ":
        return 0
    if char == "█":
        return 63
    if char == "▌":
        return 21
    if char == "▐":
        return 42
    bits = ord(char) - 0x1FB00 + 1
    bits += bits >= 21
    bits += bits >= 42
    return bits


def test_every_sextant_pattern_has_its_own_character():
    chars = [banner.sextant(bits) for bits in range(64)]
    assert len(set(chars)) == 64
    assert chars[0] == " " and chars[63] == "█" and chars[21] == "▌" and chars[42] == "▐"
    assert chars[1] == "\U0001FB00" and chars[62] == "\U0001FB3B"    # Unicode's first and last
    others = [c for b, c in enumerate(chars) if b not in (0, 21, 42, 63)]
    assert all(0x1FB00 <= ord(c) <= 0x1FB3B for c in others)
    assert all(_bits(chars[bits]) == bits for bits in range(64))       # and back again
    assert all(cell_len(c) == 1 for c in chars)                        # one cell each


# ================================================================ layout
def test_pictures_need_room_and_never_grow_past_their_widest():
    assert banner.side_cols(112, _WIDTH) == 0           # a 112-column window: the title alone
    assert banner.side_cols(113, _WIDTH) == banner.MIN_SIDE
    assert banner.side_cols(158, _WIDTH) == 44          # a 160-column terminal
    assert banner.side_cols(400, _WIDTH) == banner.MAX_SIDE


# =============================================================== drawing
@pytest.mark.parametrize("name", THEME_NAMES)
def test_both_pictures_draw_in_every_theme_both_ways(name):
    palette = get_palette(name)
    scheme = banner.colours(palette)
    png = banner.banner_png(LINES, _WIDTH, ROWS, 44, 10, 20, scheme,
                            [palette.primary, palette.accent, palette.success])
    from PIL import Image

    image = Image.open(io.BytesIO(png))
    assert image.size == ((_WIDTH + 2 * (44 + banner.GAP)) * 10, ROWS * 20)
    for kind in banner.KINDS:
        cells = banner.cells(kind, 44, ROWS, scheme)
        assert len(cells) == ROWS and all(len(line) == 44 for line in cells)
        lit = [c for line in cells for c in line if c[1]]
        assert len(lit) > 44 * ROWS * 0.15, (kind, len(lit))          # a picture, not specks
        assert all(re.fullmatch(r"#[0-9a-f]{6}", colour) for _, colour, _ in lit)
        assert all(re.fullmatch(r"(#[0-9a-f]{6})?", background) for _, _, background in lit)
        assert all(char != " " for char, _, _ in lit)
        assert all(cell == (" ", "", "") for line in cells for cell in line if not cell[1])


def _hue_of(cells) -> tuple[float, float, float]:
    from PIL import ImageColor

    lit = [ImageColor.getrgb(colour) for line in cells for _, colour, _ in line if colour]
    return tuple(sum(c[i] for c in lit) / len(lit) for i in range(3))


def test_the_pictures_take_the_themes_colours():
    green = _hue_of(banner.cells("beast", 40, ROWS, banner.colours(get_palette("phosphor-green"))))
    amber = _hue_of(banner.cells("beast", 40, ROWS, banner.colours(get_palette("amber-phosphor"))))
    assert green[1] > green[0] and amber[0] > amber[2]                 # green; orange
    assert green != amber


def test_the_beast_ships_with_netzilla():
    import pathlib
    import tomllib

    from PIL import Image

    assert banner.BEAST.is_file() and banner.BEAST.parent.name == "data"
    with Image.open(banner.BEAST) as picture:
        assert picture.mode == "L" and picture.width > 2 * picture.height
    project = tomllib.loads((pathlib.Path(__file__).parent.parent / "pyproject.toml").read_text())
    assert "data/*.png" in project["tool"]["setuptools"]["package-data"]["netzilla"]


def test_the_beast_takes_the_themes_colours_in_pixels_too():
    def mean(name):
        art = banner.pixels("beast", 44, ROWS, 10, 20, banner.colours(get_palette(name)))
        data = art.convert("RGB").tobytes()
        lit = [data[i:i + 3] for i in range(0, len(data), 3) if max(data[i:i + 3]) > 90]
        return tuple(sum(p[i] for p in lit) / len(lit) for i in range(3))

    green, amber, ice = mean("phosphor-green"), mean("amber-phosphor"), mean("ice-cyan")
    assert green[1] > green[0] and green[1] > green[2]               # green
    assert amber[0] > amber[2] and ice[2] > ice[0]                   # orange; blue


def test_in_characters_the_beast_is_shaded():
    """Cells wholly inside the beast take two colours — the bright sixths
    lit, the rest filled with the dark ones' colour; cells on its edge leave
    the background to the screen."""
    cells = banner.cells("beast", 44, ROWS, banner.colours(get_palette("phosphor-green")))
    two_tone = [c for line in cells for c in line if c[2]]
    edge = [c for line in cells for c in line if c[1] and not c[2]]
    assert len(two_tone) > 10 and len(edge) > 10
    assert all(colour != background for _, colour, background in two_tone)
    assert all(char not in (" ", "█") for char, _, _ in two_tone)


def test_the_beast_faces_the_title():
    """Its breath runs to the picture's right edge, next to the title; with
    room to spare, the spare room is on its left."""
    scheme = banner.colours(get_palette("phosphor-green"))
    for side in (banner.MIN_SIDE, 30, 44, banner.MAX_SIDE):
        cells = banner.cells("beast", side, ROWS, scheme)
        assert any(line[-1][1] for line in cells), side
        if side >= 44:
            assert not any(line[0][1] for line in cells), side


def test_the_pictures_keep_their_proportions_at_any_width():
    """Sized by the row, not stretched with the width: a narrow picture is
    shorter, not squashed."""
    from PIL import Image

    scheme = banner.colours(get_palette("phosphor-green"))
    for kind in banner.KINDS:
        narrow = banner.pixels(kind, banner.MIN_SIDE, ROWS, 10, 20, scheme)
        wide = banner.pixels(kind, banner.MAX_SIDE, ROWS, 10, 20, scheme)
        assert narrow.size == (banner.MIN_SIDE * 10, ROWS * 20)
        assert wide.size == (banner.MAX_SIDE * 10, ROWS * 20)
        assert isinstance(narrow, Image.Image)
    # The beast keeps its shape: as tall as the band when there's room, and
    # smaller, not squashed, when there isn't.
    tall = banner._box("beast", banner.MAX_SIDE * 10, ROWS * 20)[2:]
    small = banner._box("beast", banner.MIN_SIDE * 10, ROWS * 20)[2:]
    assert tall[1] == ROWS * 20 and small[1] < tall[1] and small[0] == banner.MIN_SIDE * 10
    assert abs(tall[0] / tall[1] - small[0] / small[1]) < 0.05

    def rows_lit(cells):
        return sum(1 for line in cells if any(c[1] for c in line))

    assert rows_lit(banner.cells("beast", banner.MAX_SIDE, ROWS, scheme)) == ROWS
    assert rows_lit(banner.cells("beast", banner.MIN_SIDE, ROWS, scheme)) < ROWS


# ============================================================ characters
def test_text_banner_lines_up_the_title_between_the_pictures():
    palette = get_palette("phosphor-green")
    text = text_banner(LINES, 44, palette)
    console = Console(width=200, color_system=None, file=io.StringIO())
    rows = text.plain.split("\n")
    assert len(rows) == ROWS
    width = _WIDTH + 2 * (44 + banner.GAP)
    assert {cell_len(row) for row in rows} == {width}
    for row, line in zip(rows, LINES):
        assert row[44 + banner.GAP:44 + banner.GAP + len(line)] == line
    assert any(0x1FB00 <= ord(c) <= 0x1FB3B for row in rows for c in row)
    console.print(text)                                  # renders without trouble
    # Pictures in their own colours, never bold; the title left to the stylesheet.
    styled = [span for span in text.spans if span.style]
    assert styled and all(str(span.style).startswith("not bold #") for span in styled)
    title_at = 44 + banner.GAP
    assert not [s for s in text.spans if s.start <= title_at < s.end and s.style]


def test_with_no_room_the_text_banner_is_the_title_alone():
    assert text_banner(LINES, 0, get_palette("phosphor-green")).plain == BANNER


# ================================================================ in DASH
def _screen_text(app) -> list[str]:
    console = Console(width=app.size.width, height=app.size.height, file=io.StringIO(),
                      force_terminal=True, color_system=None, record=True)
    console.print(app.screen._compositor.render_update(
        full=True, screen_stack=app._background_screens))
    text = "".join(seg.text for seg in console._record_buffer if not seg.control)
    return text.split("\n")[: app.size.height]


def _dash(tmp_path, script, size=(160, 50)):
    from netzilla.app import NetzillaApp

    async def go():
        app = NetzillaApp(config_path=tmp_path / "config.toml", offline=True)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause(0.3)
            return await script(app, app._active_pane(), pilot)
    return asyncio.run(go())


def _banner_rows(app, pane) -> list[str]:
    region = pane.query_one("#banner").region
    return [line[region.x:region.right] for line in _screen_text(app)[region.y:region.bottom]]


def _sextants(rows) -> int:
    return sum(1 for row in rows for c in row if 0x1FB00 <= ord(c) <= 0x1FB3B)


def test_dash_shows_both_pictures_when_there_is_room(tmp_path):
    async def script(app, pane, pilot):
        rows = _banner_rows(app, pane)
        title = next(i for i, row in enumerate(rows) if LINES[0].strip()[:6] in row)
        found = {}
        for row, line in zip(rows[title:title + ROWS], LINES):
            at = row.index(line.strip()[:6])
            found.setdefault("left", 0)
            found["left"] += _sextants([row[:at]])
            found.setdefault("right", 0)
            found["right"] += _sextants([row[at + len(line.strip()):]])
        return found

    found = _dash(tmp_path, script)
    assert found["left"] > 20 and found["right"] > 20


def test_a_narrow_window_gets_the_title_alone_and_a_wide_one_the_pictures(tmp_path):
    async def script(app, pane, pilot):
        seen = [_sextants(_banner_rows(app, pane))]
        await pilot.resize_terminal(100, 50)
        await pilot.pause(0.6)                           # the resize is debounced
        seen.append(_sextants(_banner_rows(app, pane)))
        await pilot.resize_terminal(170, 50)
        await pilot.pause(0.6)
        seen.append(_sextants(_banner_rows(app, pane)))
        return seen

    wide, narrow, again = _dash(tmp_path, script)
    assert wide > 40 and narrow == 0 and again > 40


def test_in_kitty_the_banner_image_spans_title_and_pictures(tmp_path):
    written = []

    async def script(app, pane, pilot):
        kitty.set_writer(written.append)
        app.terminal = termcaps.detect({"TERM": "xterm-kitty"})
        app._pixels_ready = True
        app._cell_px = (10, 20)
        app._refresh_static_graphics()
        await pilot.pause()
        return pane.query_one("#banner").content

    art = _dash(tmp_path, script)
    side = banner.side_cols(158, _WIDTH)
    widths = {cell_len(line) for line in art.plain.split("\n")}
    assert widths == {_WIDTH + 2 * (side + banner.GAP)}, widths
    pngs = []
    for chunk in written:
        for payload in re.findall(r"\x1b_G[^;]*a=T[^;]*;([A-Za-z0-9+/=]+)", chunk):
            pngs.append(payload)
    from PIL import Image

    sizes = []
    for payload in pngs:
        try:
            sizes.append(Image.open(io.BytesIO(base64.b64decode(payload))).size)
        except Exception:
            continue
    assert ((_WIDTH + 2 * (side + banner.GAP)) * 10, ROWS * 20) in sizes, sizes
