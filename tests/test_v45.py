"""Tests for netzilla 4.5: Tokyo from the owner's picture, and the beast's
breath alive.

  * the city beside DASH's title is a picture shipped with netzilla
    (data/tokyo.png), coloured from the theme like the beast
  * the breath rolls through the theme's own bright colours in waves from
    the jaws, its brightness rippling: a seamless loop of FIRE_FRAMES frames
  * in kitty and Ghostty the breath's cells are a separate small image per
    frame (uploaded once, the first time it is wanted); in characters its
    cells are re-coloured; only while the banner is on screen
"""

from __future__ import annotations

import asyncio
import io

import pytest
from rich.cells import cell_len

from netzilla import __version__, termcaps
from netzilla.graphics import banner, kitty, plot
from netzilla.screens.dashboard import BANNER, _WIDTH, pixel_banner, text_banner
from netzilla.themes import THEME_NAMES, get_palette

pytestmark = pytest.mark.skipif(not plot.HAVE_PIL, reason="Pillow not installed")

LINES = BANNER.splitlines()
ROWS = len(LINES)
GREEN = banner.colours(get_palette("phosphor-green"))


@pytest.fixture(autouse=True)
def _no_writer():
    kitty.set_writer(None)
    yield
    kitty.set_writer(None)


def test_version_is_4_5():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (4, 5), __version__


# ================================================================ the city
def test_the_city_and_the_breath_ship_with_netzilla():
    from PIL import Image

    for name in ("tokyo.png", "beast-fire.png", "beast.png"):
        path = banner.DATA / name
        assert path.is_file(), name
        with Image.open(path) as picture:
            assert picture.mode == "L", name
    with Image.open(banner.DATA / "beast-fire.png") as fire, Image.open(banner.BEAST) as beast:
        assert fire.size == beast.size                       # the breath, on the beast
    assert banner.KINDS == ("beast", "city")


@pytest.mark.parametrize("name", ["phosphor-green", "amber-phosphor", "ice-cyan"])
def test_the_city_takes_the_themes_colours(name):
    scheme = banner.colours(get_palette(name))
    image = banner.pixels("city", 44, ROWS, 10, 20, scheme)
    data = image.tobytes()
    lit = [data[i:i + 3] for i in range(0, len(data), 3) if max(data[i:i + 3]) > 120]
    mean = [sum(p[k] for p in lit) / len(lit) for k in range(3)]
    primary = plot.rgb(get_palette(name).primary)
    top = max(range(3), key=lambda k: primary[k])
    assert max(range(3), key=lambda k: mean[k]) == top, (name, mean, primary)


def test_the_city_keeps_to_the_title():
    """On the right of the title, against it: spare room goes to its far side."""
    for side in (banner.MIN_SIDE, 44, banner.MAX_SIDE):
        grid = banner.cells("city", side, ROWS, GREEN)
        assert any(line[0][1] for line in grid), side
    wide = banner.cells("city", banner.MAX_SIDE, ROWS, GREEN)
    assert not any(line[-1][1] for line in wide)
    assert banner._box("city", 460, 120)[0] == 0 and banner._box("beast", 460, 120)[0] > 0


# ================================================================ the fire
@pytest.mark.parametrize("name", THEME_NAMES)
def test_the_breath_burns_in_the_themes_own_colours(name):
    palette = get_palette(name)
    scheme = banner.colours(palette)
    fire = banner.fire_palette(scheme)
    assert len(fire) >= 3
    own = {plot.rgb(getattr(palette, role))
           for role in ("primary", "accent", "success", "warning", "error")}
    primary, foreground = plot.rgb(palette.primary), plot.rgb(palette.foreground)
    mixes = {plot.mix(primary, foreground, 0.35 * n) for n in range(1, 3)}
    assert all(colour in own | mixes for colour in fire), (name, fire)
    hues = [banner._hue(c) for c in fire]
    assert hues == sorted(hues)                                     # each melts into the next
    assert all(sum((a - b) ** 2 for a, b in zip(x, y)) >= 60 ** 2
               for i, x in enumerate(fire) for y in fire[i + 1:])  # no two alike


def test_the_colours_roll_out_from_the_jaws_and_loop():
    near = [banner._fire_at(GREEN, f, 0.0)[0] for f in range(banner.FIRE_FRAMES)]
    assert len(set(near)) > banner.FIRE_FRAMES // 2                  # it keeps changing
    # What the jaws show now, the breath further out shows a little later.
    later = banner.FIRE_FRAMES // 4
    assert banner._fire_at(GREEN, 0, 0.0)[0] == banner._fire_at(GREEN, later, 0.5)[0]
    assert banner._fire_at(GREEN, banner.FIRE_FRAMES, 0.3) == banner._fire_at(GREEN, 0, 0.3)
    pulses = [banner._fire_at(GREEN, f, 0.2)[1] for f in range(banner.FIRE_FRAMES)]
    assert 0.55 < min(pulses) < max(pulses) <= 1.0


def test_the_fire_window_holds_the_breath():
    for side, cell in ((44, (10, 20)), (banner.MIN_SIDE, (10, 20)), (46, (16, 34))):
        col, row, width, height = banner.fire_window(side, ROWS, *cell)
        assert col + width == side and 0 < width < side
        assert row >= 0 and row + height <= ROWS and height >= 2
        W, H = side * cell[0], ROWS * cell[1]
        x, y, w, h = banner._box("beast", W, H)
        box = banner._sized(banner.FIRE_MASK, w, h).getbbox()
        assert col * cell[0] <= x + box[0] and (row * cell[1] <= y + box[1])
        assert y + box[3] <= (row + height) * cell[1]


def test_only_the_breath_changes_from_frame_to_frame():
    from PIL import Image, ImageChops

    col, row, width, height = banner.fire_window(44, ROWS, 10, 20)
    one = banner.pixels("beast", 44, ROWS, 10, 20, GREEN, 0)
    two = banner.pixels("beast", 44, ROWS, 10, 20, GREEN, banner.FIRE_FRAMES // 2)
    assert ImageChops.difference(one, two).getbbox()                 # the breath moved
    outside = (0, 0, col * 10, ROWS * 20)
    assert not ImageChops.difference(one.crop(outside), two.crop(outside)).getbbox()
    frames = {banner.fire_png(44, ROWS, 10, 20, GREEN, f) for f in (0, 6, 12, 18)}
    assert len(frames) == 4
    for png in frames:
        assert Image.open(io.BytesIO(png)).size == (width * 10, height * 20)


def test_in_characters_the_breath_is_recoloured_and_nothing_else():
    first = banner.cells("beast", 44, ROWS, GREEN, frame=0)
    other = banner.cells("beast", 44, ROWS, GREEN, frame=banner.FIRE_FRAMES // 2)
    changed = [(r, c) for r in range(ROWS) for c in range(44) if first[r][c] != other[r][c]]
    assert len(changed) >= 10
    col = banner.fire_window(44, ROWS, 10, 20)[0]
    assert all(c >= col for _, c in changed)                         # only round the breath
    assert all(first[r][c][0] == other[r][c][0] for r, c in changed)  # same shapes, new colours
    assert banner.cells("beast", 44, ROWS, GREEN, frame=banner.FIRE_FRAMES) == first
    text = text_banner(LINES, 44, get_palette("phosphor-green"), frame=5)
    assert {cell_len(row) for row in text.plain.split("\n")} == {_WIDTH + 2 * (44 + banner.GAP)}


def test_pixel_banner_puts_the_frame_in_the_fire_window():
    cols = _WIDTH + 2 * (44 + banner.GAP)
    window = banner.fire_window(44, ROWS, 10, 20)
    art = pixel_banner(0x123456, cols, ROWS, window, 0x654321)
    rows = art.plain.split("\n")
    assert len(rows) == ROWS and {cell_len(row) for row in rows} == {cols}
    fire = [s for s in art.spans if str(s.style).endswith("#654321")]
    assert len(fire) == window[3]
    whole = pixel_banner(0x123456, cols, ROWS)
    assert whole.plain == kitty.placeholder_text(0x123456, cols, ROWS).plain


# ================================================================== in DASH
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


def test_dash_keeps_the_breath_moving_in_characters(tmp_path):
    async def script(app, pane, pilot):
        widget = pane.query_one("#banner")
        looks, frames = [], []
        for _ in range(5):
            looks.append(str(widget.content.spans))
            frames.append(pane._fire_frame)
            await pilot.pause(banner.FIRE_EVERY * 2.5)
        title = [line[44 + banner.GAP:44 + banner.GAP + _WIDTH] for line in widget.content.plain.split("\n")]
        return looks, frames, title

    looks, frames, title = _dash(tmp_path, script)
    assert len(set(looks)) >= 4 and len(set(frames)) >= 4
    assert [line.rstrip() for line in title] == [line.rstrip() for line in LINES]


def test_dash_shows_each_frame_of_the_breath_as_its_own_image_in_kitty(tmp_path):
    written = []

    async def script(app, pane, pilot):
        kitty.set_writer(written.append)
        app.terminal = termcaps.detect({"TERM": "xterm-kitty"})
        app._pixels_ready = True
        app._cell_px = (10, 20)
        app._refresh_static_graphics()
        await pilot.pause(0.05)
        logo = dict(pane._logo)
        await pilot.pause(banner.FIRE_EVERY * banner.FIRE_FRAMES + 0.6)
        ids = dict(logo["fire_ids"])
        art = pane.query_one("#banner").content
        pane.refresh_theme()                       # a new drawing: the old frames go
        await pilot.pause(0.8)
        return logo, ids, art

    logo, ids, art = _dash(tmp_path, script)
    side = banner.side_cols(158, _WIDTH)
    assert logo["mode"] == "pixels" and logo["window"] == banner.fire_window(side, ROWS, 10, 20)
    assert len(ids) == banner.FIRE_FRAMES                        # every frame, uploaded once
    uploads = [chunk for chunk in written if "a=T" in chunk]
    _, _, width, height = logo["window"]
    for image_id in ids.values():
        assert sum(f"i={image_id},c={width},r={height}," in chunk for chunk in uploads) == 1
    shown = {str(s.style).split()[-1] for s in art.spans if s.style}
    assert kitty.id_colour(logo["banner_id"]) in shown
    assert len(shown & {kitty.id_colour(i) for i in ids.values()}) == 1
    assert {cell_len(line) for line in art.plain.split("\n")} == {_WIDTH + 2 * (side + banner.GAP)}
    for image_id in ids.values():
        assert any(f"a=d,d=I,i={image_id}," in chunk for chunk in written)


def test_the_breath_rests_while_dash_is_out_of_sight(tmp_path):
    async def script(app, pane, pilot):
        await app.action_show_tab("ip")
        await pilot.pause(0.2)
        before = pane._fire_frame
        await pilot.pause(banner.FIRE_EVERY * 6)
        after = pane._fire_frame
        await app.action_show_tab("dash")
        await pilot.pause(banner.FIRE_EVERY * 6)
        return before, after, pane._fire_frame

    before, after, back = _dash(tmp_path, script)
    assert before == after and back != after
