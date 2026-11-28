"""Tests for netzilla 4.8: netzilla in a window of its own (netzilla.exe).

  * the window's terminal (window/screen.py): text, wide characters,
    colours, cursor moves, erasing, links, the clipboard, notifications and
    kitty graphics uploads with Unicode placeholders
  * cells drawn as Ghostty draws them: box drawing, blocks, sextants and
    braille to the pixel, JetBrains Mono at Ghostty's cell size
  * the painter: incremental repaints that match a full repaint, images in
    placeholder cells, the CRT glow and scanlines (and none of it with
    --no-crt)
  * keys and the mouse as the bytes Ghostty sends, through Textual's own
    input parser
  * the Textual driver: netzilla started, drawn, driven by keys and stopped,
    with no window at all
  * the [window] settings, --window, the Windows console handling, the icon
    and the PyInstaller build
  * where there is a display, the real tkinter window's self-test

Nothing here touches the network. Only the last test opens a window, and it
is skipped where there is no display.
"""

from __future__ import annotations

import base64
import collections
import importlib.util
import io
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from PIL import Image, ImageChops

from netzilla import __version__, hostos, termcaps
from netzilla.config import Config
from netzilla.graphics import kitty, plot
from netzilla.window import glyphs, keys
from netzilla.window.fonts import BUNDLED, FontSet, fit_px
from netzilla.window.paint import Painter, rgb, screenshot
from netzilla.window.screen import (
    BOLD, REVERSE, UNDERLINE, Screen, Style, apply_sgr, char_width, xterm256,
)

ROOT = Path(__file__).resolve().parent.parent


def test_version_is_4_8():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (4, 8), __version__
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{__version__}"' in pyproject


# ===================================================================== screen
def fed(text: str, cols: int = 20, rows: int = 5) -> Screen:
    screen = Screen(cols, rows)
    screen.feed(text)
    return screen


def test_text_lands_in_the_grid_and_wraps():
    screen = fed("hello\r\nworld", cols=10, rows=3)
    assert screen.text().splitlines()[:2] == ["hello     ", "world     "]
    screen = fed("abcdefghijkl", cols=10, rows=3)
    assert screen.text().splitlines()[1].startswith("kl")


def test_wide_characters_take_two_cells_and_marks_join_their_cell():
    screen = fed("日本x")
    row = screen.chars[0]
    assert row[:5] == ["日", "", "本", "", "x"]
    assert char_width("日") == 2 and char_width("a") == 1
    screen = fed("éz")
    assert screen.chars[0][:2] == ["é", "z"]


def test_cursor_moves_and_erasing():
    screen = fed("xxxxxxxxxx\x1b[1;3Hab\x1b[2;1Hline2\x1b[1;5H\x1b[K", cols=10, rows=3)
    lines = screen.text().splitlines()
    assert lines[0] == "xxab      "
    assert lines[1].startswith("line2")
    screen.feed("\x1b[2J")
    assert screen.text().strip() == ""


def test_sgr_colours_and_attributes():
    style = apply_sgr(Style(), "1;4;38;2;255;128;0;48;5;21")
    assert style.fg == 0xFF8000 and style.bg == xterm256(21) == 0x0000FF
    assert style.flags & BOLD and style.flags & UNDERLINE
    assert apply_sgr(style, "0") == Style()
    assert apply_sgr(Style(), "7").flags & REVERSE
    assert apply_sgr(Style(), "38:2::1:2:3").fg == 0x010203
    screen = fed("\x1b[38;2;1;2;3mA\x1b[0mB")
    assert screen.styles[0][0].fg == 0x010203 and screen.styles[0][1].fg is None


def test_split_sequences_and_stray_escapes():
    screen = Screen(20, 2)
    screen.feed("\x1b[38;2;9")
    screen.feed(";9;9mZ")
    assert screen.chars[0][0] == "Z" and screen.styles[0][0].fg == 0x090909
    screen = Screen(20, 2)
    screen.feed("a\x1b")
    screen.feed("[1;5Hb")           # the ESC waited for the rest of its sequence
    assert screen.chars[0][4] == "b"
    screen = Screen(20, 2)
    screen.feed("a\x1b\x07bc")       # an ESC nothing follows is dropped, not kept
    assert "bc" in screen.text()


def test_links_clipboard_title_pointer_and_notifications():
    screen = Screen(30, 2)
    got = collections.defaultdict(list)
    screen.on_clipboard = got["clip"].append
    screen.on_title = got["title"].append
    screen.on_pointer = got["pointer"].append
    screen.on_notify = lambda title, body: got["notify"].append((title, body))
    replies = []
    screen.on_reply = replies.append
    copied = base64.b64encode("copied ✔".encode()).decode()
    screen.feed("\x1b]8;;https://example.com/\x1b\\link\x1b]8;;\x1b\\ plain"
                f"\x1b]52;c;{copied}\x07\x1b]2;my title\x07\x1b]22;pointer\x1b\\"
                "\x1b]777;notify;LIVE AIR;done\x1b\\\x1b[6n")
    assert screen.styles[0][0].link == "https://example.com/"
    assert screen.styles[0][5].link is None
    assert got["clip"] == ["copied ✔"] and got["title"] == ["my title"]
    assert got["pointer"] == ["pointer"] and got["notify"] == [("LIVE AIR", "done")]
    assert replies == ["\x1b[1;11R"]


def png_payload(colour=(255, 0, 0, 255), size=(18, 40)) -> str:
    buffer = io.BytesIO()
    Image.new("RGBA", size, colour).save(buffer, "PNG")
    return base64.b64encode(buffer.getvalue()).decode()


def upload(image_id: int, cols: int, rows: int, colour=(255, 0, 0, 255),
           size=(18, 40), chunk: int = 64) -> str:
    """A kitty upload of a PNG in chunks, with a virtual placement."""
    data = png_payload(colour, size)
    pieces = [data[i:i + chunk] for i in range(0, len(data), chunk)]
    out = []
    for n, piece in enumerate(pieces):
        more = 1 if n < len(pieces) - 1 else 0
        if n == 0:
            out.append(f"\x1b_Ga=T,U=1,f=100,i={image_id},c={cols},r={rows},q=2,m={more};"
                       f"{piece}\x1b\\")
        else:
            out.append(f"\x1b_Gm={more};{piece}\x1b\\")
    return "".join(out)


def placeholders(image_id: int, cols: int, rows: int) -> str:
    """The placeholder cells for an image, as netzilla writes them."""
    colour = kitty.id_colour(image_id) if hasattr(kitty, "id_colour") else None
    r, g, b = (image_id >> 16) & 255, (image_id >> 8) & 255, image_id & 255
    lines = []
    for row in range(rows):
        cells = "".join(kitty.PLACEHOLDER + kitty.DIACRITICS[row] + kitty.DIACRITICS[col]
                        for col in range(cols))
        lines.append(f"\x1b[{row + 1};1H\x1b[38;2;{r};{g};{b}m{cells}\x1b[0m")
    del colour
    return "".join(lines)


def test_kitty_upload_placement_and_delete():
    screen = Screen(20, 4)
    changed = []
    screen.on_images = lambda: changed.append(True)
    screen.feed(upload(7, 2, 2))
    assert 7 in screen.images and screen.images[7].image.size == (18, 40)
    assert (screen.images[7].cols, screen.images[7].rows) == (2, 2)
    assert screen.take_changed_images() == {7} and changed
    screen.feed(placeholders(7, 2, 2))
    assert screen.chars[0][0][0] == kitty.PLACEHOLDER and screen.chars[1][1][0] == kitty.PLACEHOLDER
    screen.feed("\x1b_Ga=d,d=I,i=7,q=2\x1b\\")
    assert 7 not in screen.images and screen.take_changed_images() == {7}
    screen.feed("\x1b_Ga=d,d=I,i=99,q=2\x1b\\")      # not there: nothing changes
    assert screen.take_changed_images() == set()


def test_graphics_query_is_answered():
    screen = Screen(10, 2)
    replies = []
    screen.on_reply = replies.append
    screen.feed("\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\")
    assert replies == ["\x1b_Gi=31;OK\x1b\\"]


# ===================================================================== glyphs
def lit(mask: Image.Image) -> int:
    return sum(1 for v in mask.tobytes() if v > 127)


def test_box_drawing_is_drawn_not_taken_from_a_font():
    for char in "─│┌┐└┘├┤┬┴┼━┃╋═║╔╗╚╝╭╮╯╰":
        assert glyphs.drawn(char), char
    w, h = 9, 20
    horizontal = glyphs.mask("─", w, h)
    rows = [y for y in range(h) if horizontal.getpixel((4, y)) > 127]
    assert len(rows) == glyphs.thickness(h)
    assert all(horizontal.getpixel((x, rows[0])) > 127 for x in range(w))  # edge to edge
    vertical = glyphs.mask("│", w, h)
    assert all(vertical.getpixel((w // 2, y)) > 127 for y in range(h))
    heavy = glyphs.mask("━", w, h)
    assert lit(heavy) > lit(horizontal)
    cross = glyphs.mask("┼", w, h)
    assert cross.getpixel((0, rows[0])) > 127 and cross.getpixel((w // 2, 0)) > 127


def test_blocks_fill_their_part_of_the_cell():
    w, h = 10, 20
    assert lit(glyphs.mask("█", w, h)) == w * h
    upper = glyphs.mask("▀", w, h)
    assert upper.getpixel((5, 2)) > 127 and upper.getpixel((5, h - 2)) < 128
    left = glyphs.mask("▌", w, h)
    assert left.getpixel((1, 10)) > 127 and left.getpixel((w - 1, 10)) < 128
    # shades are the whole cell at a quarter, half and three quarters, as Ghostty
    light, medium, dark = (sum(glyphs.mask(c, w, h).tobytes()) for c in "░▒▓")
    assert 0 < light < medium < dark < 255 * w * h


def test_sextants_are_two_by_three():
    w, h = 10, 21
    for code in glyphs.SEXTANTS:
        char = chr(code)
        bits = code - 0x1FB00 + 1
        bits += (bits >= 21) + (bits >= 41)
        mask = glyphs.mask(char, w, h)
        for n in range(6):
            x = 2 if n % 2 == 0 else w - 3
            y = (n // 2) * (h // 3) + h // 6
            assert (mask.getpixel((x, y)) > 127) == bool(bits & (1 << n)), (hex(code), n)


def test_braille_dots():
    w, h = 10, 20
    empty, one, full = (glyphs.mask(chr(c), w, h) for c in (0x2800, 0x2801, 0x28FF))
    assert lit(empty) == 0 < lit(one) < lit(full)
    assert one.getbbox()[1] < h // 4          # dot 1 is top left


# ===================================================================== fonts
def test_bundled_font_and_ghostty_cell_size():
    for path in BUNDLED.values():
        assert Path(path).exists(), path
    licence = Path(BUNDLED["regular"]).parent / "OFL.txt"
    assert "SIL OPEN FONT LICENSE" in licence.read_text(encoding="utf-8").upper()
    fonts = FontSet(15)
    assert fonts.cell == (9, 20)                # JetBrains Mono 15 px, as in Ghostty
    assert fonts.baseline < fonts.cell[1]
    assert FontSet(17).cell[0] >= fonts.cell[0]


def test_dash_fits_the_screen():
    px = fit_px(160, 50, 1920 - 16, 1080 - 48)
    fonts = FontSet(px)
    assert 160 * fonts.cell[0] <= 1904 and 50 * fonts.cell[1] <= 1032
    assert fit_px(160, 50, 400, 300) == 8       # never smaller than the floor


# ===================================================================== painter
def dash_like() -> Screen:
    screen = Screen(40, 10)
    screen.feed("\x1b[38;2;0;255;0m┌─ NETZILLA ──────────┐\r\n│ \x1b[1mbold\x1b[22m text 🔥 日本 │"
                "\r\n└──────────────────────┘\x1b[0m\r\n🬀🬁🬂🬃 ⠿⠇ ▀▄█")
    screen.feed(upload(5, 4, 2, colour=(0, 200, 255, 255), size=(36, 40)))
    screen.feed("\x1b[6;1H")
    for row in range(2):
        cells = "".join(kitty.PLACEHOLDER + kitty.DIACRITICS[row] + kitty.DIACRITICS[col]
                        for col in range(4))
        screen.feed(f"\x1b[{6 + row};3H\x1b[38;2;0;0;5m{cells}\x1b[0m")
    return screen


def test_painter_draws_text_and_images():
    fonts = FontSet(15)
    screen = dash_like()
    picture = screenshot(screen, fonts, crt=False, default_bg=0x101010)
    assert picture.size == (40 * 9, 10 * 20)
    # the image's cyan is in its cells, the green text in its own
    assert picture.getpixel((2 * 9 + 10, 5 * 20 + 10)) == (0, 200, 255)
    box = picture.crop((0, 0, 9 * 24, 20)).convert("RGB")
    assert (0, 255, 0) in {box.getpixel((x, 10)) for x in range(box.width)}
    assert picture.getpixel((39 * 9 + 4, 9 * 20 + 10)) == rgb(0x101010)


def test_incremental_paint_matches_a_full_repaint():
    fonts = FontSet(15)
    screen = dash_like()
    painter = Painter(fonts, crt=True, default_bg=0x101010)
    painter.paint(screen)
    for n in range(6):
        screen.feed(f"\x1b[{2 + n % 3};{5 + n}H\x1b[38;2;255;{40 * n};0mX{n}\x1b[0m")
        screen.feed("\x1b[1;1H\x1b[38;2;0;255;0m┌─ NETZILLA ─")   # rewritten unchanged
        boxes = painter.paint(screen)
        assert boxes
    assert painter.paint(screen) == []          # nothing new: nothing repainted
    full = screenshot(screen, fonts, crt=True, default_bg=0x101010)
    difference = ImageChops.difference(full, painter.frame).getextrema()
    assert max(high for _low, high in difference) <= 12


def test_unchanged_rewrites_cost_nothing():
    fonts = FontSet(15)
    screen = Screen(30, 3)
    screen.feed("same text on the row")
    painter = Painter(fonts, crt=False)
    painter.paint(screen)
    screen.feed("\x1b[1;1Hsame text on the row")
    assert painter.paint(screen) == []
    screen.feed("\x1b[1;6HTEXT")
    boxes = painter.paint(screen)
    assert boxes == [(5 * 9, 0, 9 * 9, 20)]


def test_a_new_image_repaints_only_its_rows():
    fonts = FontSet(15)
    screen = dash_like()
    painter = Painter(fonts, crt=False)
    painter.paint(screen)
    screen.feed(upload(5, 4, 2, colour=(255, 0, 255, 255), size=(36, 40)))
    painter.images_changed(screen, screen.take_changed_images())
    boxes = painter.paint(screen)
    assert boxes and all(5 * 20 <= y0 and y1 <= 7 * 20 for _x0, y0, _x1, y1 in boxes)
    assert painter.frame.getpixel((2 * 9 + 10, 5 * 20 + 10)) == (255, 0, 255)


def test_crt_glow_and_scanlines_and_none_without_it():
    fonts = FontSet(15)
    screen = Screen(20, 4)
    screen.feed("\x1b[2;3H\x1b[38;2;0;255;0m██████\x1b[0m")
    plain = screenshot(screen, fonts, crt=False)
    crt = screenshot(screen, fonts, crt=True)
    assert plain.size == crt.size
    # glow: light spills into the dark cells beside the lit ones
    beside = (8 * 9 + 3, 20 + 10)
    assert plain.getpixel(beside) == (0, 0, 0)
    assert crt.getpixel(beside)[1] > 0
    # scanlines: every third pixel row of a lit cell is darker
    x = 3 * 9 + 4
    column = [crt.getpixel((x, y))[1] for y in range(20, 40)]
    assert min(column) < max(column)
    assert {plain.getpixel((x, y))[1] for y in range(20, 40)} == {255}


def test_per_image_scanlines_switch_off_under_the_window_crt():
    image = Image.new("RGBA", (6, 6), (200, 200, 200, 255))
    try:
        plot.SCANLINES = False
        assert plot.add_scanlines(image).tobytes() == image.tobytes()
        plot.SCANLINES = True
        assert plot.add_scanlines(image).tobytes() != image.tobytes()
    finally:
        plot.SCANLINES = True


# ===================================================================== keys
@pytest.fixture
def parse():
    from textual import events
    from textual._xterm_parser import XTermParser

    parser = XTermParser()

    def keys_of(data: str):
        return [e.key for e in parser.feed(data) if isinstance(e, events.Key)]

    keys_of.parser = parser
    return keys_of


@pytest.mark.parametrize("keysym, char, state, system, expected", [
    ("F2", "", 0, "linux", "f2"),
    ("F12", "", 0, "windows", "f12"),
    ("t", "\x14", 0x4, "linux", "ctrl+t"),
    ("p", "\x10", 0x4, "windows", "ctrl+p"),
    ("Tab", "\t", 0, "linux", "tab"),
    ("Tab", "\t", 0x1, "windows", "shift+tab"),
    ("ISO_Left_Tab", "", 0x1, "linux", "shift+tab"),
    ("Escape", "\x1b", 0, "linux", "escape"),
    ("Return", "\r", 0, "linux", "enter"),
    ("BackSpace", "\x08", 0, "windows", "backspace"),
    ("Up", "", 0x1, "linux", "shift+up"),
    ("Next", "", 0, "windows", "pagedown"),
    ("Delete", "", 0, "linux", "delete"),
    ("q", "q", 0, "linux", "q"),
    ("Q", "Q", 0x1, "linux", "Q"),
    ("a", "a", 0x20000, "windows", "alt+a"),
    ("a", "a", 0x8, "linux", "alt+a"),
])
def test_keys_reach_textual_with_their_linux_names(parse, keysym, char, state, system,
                                                   expected):
    action = keys.key_action(keysym, char, state, system)
    assert action.kind in ("text", "keys")
    names = parse(action.value)
    assert names == [expected] or (expected == "Q" and names in (["Q"], ["shift+q"]))


def test_altgr_and_option_type_their_character():
    # AltGr is Ctrl+Alt on Windows: "@" on a German keyboard is typed.
    assert keys.key_action("at", "@", 0x4 | 0x20000, "windows") == keys.KeyAction("text", "@")
    assert keys.key_action("2", "™", 0x10, "macos") == keys.KeyAction("text", "™")


def test_window_keys_stay_in_the_window():
    def action(keysym, state, system="linux"):
        return keys.key_action(keysym, "", state, system)

    assert action("plus", 0x4) == keys.KeyAction("window", "zoom_in")
    assert action("minus", 0x4) == keys.KeyAction("window", "zoom_out")
    assert action("0", 0x4) == keys.KeyAction("window", "zoom_reset")
    assert action("F11", 0) == keys.KeyAction("window", "fullscreen")
    assert action("Return", 0x20000, "windows") == keys.KeyAction("window", "fullscreen")
    assert action("v", 0x4) == keys.KeyAction("window", "paste")
    assert action("Insert", 0x1) == keys.KeyAction("window", "paste")
    assert keys.key_action("Shift_L", "", 0x1) == keys.NOTHING


def test_mouse_reports(parse):
    from textual import events

    parser = parse.parser
    down = list(parser.feed(keys.mouse_sequence("press", 1, 10, 5)))
    assert isinstance(down[0], events.MouseDown) and (down[0].x, down[0].y) == (10, 5)
    up = list(parser.feed(keys.mouse_sequence("release", 1, 10, 5)))
    assert isinstance(up[0], events.MouseUp)
    move = list(parser.feed(keys.mouse_sequence("move", 1, 3, 4)))
    assert isinstance(move[0], events.MouseMove) and move[0].button == 1
    wheel = list(parser.feed(keys.mouse_sequence("wheel_down", 0, 3, 4)))
    assert isinstance(wheel[0], events.MouseScrollDown)
    ctrl = list(parser.feed(keys.mouse_sequence("press", 3, 0, 0, keys.CTRL)))
    assert ctrl[0].button == 3 and ctrl[0].ctrl
    assert keys.held_button(0x0100) == 1 and keys.held_button(0) == 0


# ===================================================================== driver
class FakeWindow:
    """Everything the driver needs from a window, and no window."""

    def __init__(self, cols: int = 160, rows: int = 50, cell=(9, 20)) -> None:
        self.grid = (cols, rows)
        self.cell_px = cell
        self.screen = Screen(cols, rows)
        self.chunks: collections.deque = collections.deque()
        self.driver = None
        self.stopped = threading.Event()
        self.requests: list = []

    def output(self, data: str) -> None:
        self.chunks.append(data)

    def attach(self, driver) -> None:
        self.driver = driver

    def app_stopped(self) -> None:
        self.stopped.set()

    def request(self, action: str, *args) -> None:
        self.requests.append((action, args))

    def wait_for(self, test, timeout: float = 30.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            while self.chunks:
                self.screen.feed(self.chunks.popleft())
            if test():
                return True
            time.sleep(0.05)
        return False


@pytest.fixture
def window_world(tmp_path, monkeypatch):
    """The process as netzilla.window.run leaves it, put back afterwards."""
    from netzilla.window import prepare_process

    for name in ("TEXTUAL_COLOR_SYSTEM", "COLORTERM", "NETZILLA_NO_PROBE"):
        monkeypatch.setenv(name, os.environ.get(name, ""))
    monkeypatch.setattr(hostos, "hide_console_windows", lambda: False)
    before = termcaps.current()
    prepare_process()
    yield tmp_path
    termcaps.set_current(before)
    plot.SCANLINES = True


def test_netzilla_runs_through_the_driver_without_a_window(window_world):
    from netzilla.app import NetzillaApp
    from netzilla.window import truecolour
    from netzilla.window.driver import bind

    window = FakeWindow()
    termcaps.set_current(termcaps.window_info(window.cell_px))
    app = NetzillaApp(config_path=str(window_world / "config.toml"), offline=True)
    truecolour(app)
    app.driver_class = bind(window)
    failures = []

    def run():
        try:
            app.run()
        except BaseException as error:          # pragma: no cover - reported below
            failures.append(error)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        assert window.wait_for(lambda: "SYSTEM OVERVIEW" in window.screen.text()), \
            window.screen.text()
        assert app.in_window and app.graphics_mode == "pixel"
        # DASH's banner and graphs arrived as kitty images in placeholder cells
        assert window.wait_for(lambda: window.screen.images and any(
            c[:1] == kitty.PLACEHOLDER for row in window.screen.chars for c in row))
        assert window.wait_for(lambda: "(built in)" in window.screen.text())
        window.driver.feed(keys.key_action("F2", "", 0).value)
        assert window.wait_for(lambda: "SAVE SETTINGS" in window.screen.text())
        # the palette lists the window's own commands, which go to the window
        commands = [c.title for c in app.get_system_commands(app.screen)]
        assert any("CRT" in title for title in commands)
        window.driver.window_command("zoom_in")
        assert window.requests == [("zoom_in", ())]
        window.driver.resize(120, 40, 9, 20)
        assert window.wait_for(lambda: app.size == (120, 40))
        window.driver.quit()
        thread.join(20)
        assert not thread.is_alive() and window.stopped.is_set()
    finally:
        if thread.is_alive():                   # pragma: no cover - a hang
            app.exit()
            thread.join(5)
    assert not failures


def test_copy_goes_to_the_window_clipboard():
    from netzilla import clipboard

    copied = []

    class Driver:
        is_window = True

    class App:
        _driver = Driver()

        def copy_to_clipboard(self, text):
            copied.append(text)

    where = clipboard.copy("netzilla", App())
    assert copied == ["netzilla"] and "clipboard" in where


def test_window_terminal_info():
    info = termcaps.window_info((9, 20))
    assert info.graphics_mode("auto") == "pixel"
    assert info.placeholders and info.truecolor and info.hyperlinks and info.clipboard
    assert info.cell_px == (9, 20) and "netzilla window" in info.where


# ===================================================================== settings, CLI
def test_window_settings_are_saved(tmp_path):
    path = tmp_path / "config.toml"
    config = Config.load(path)
    assert (config.window_font_size, config.window_crt) == (0, True)
    config.window_font_size, config.window_crt = 17, False
    config.save()
    again = Config.load(path)
    assert (again.window_font_size, again.window_crt) == (17, False)
    assert "[window]" in path.read_text(encoding="utf-8")
    path.write_text('[window]\nfont_size = "huge"\ncrt = false\n', encoding="utf-8")
    odd = Config.load(path)
    assert (odd.window_font_size, odd.window_crt) == (0, False)
    path.write_text("[window]\nfont_size = 500\n", encoding="utf-8")
    assert Config.load(path).window_font_size == 0


def test_window_flag_hands_over_to_the_window(monkeypatch):
    from netzilla import cli, window

    seen = []
    monkeypatch.setattr(window, "main", lambda argv=None: seen.append(argv) or 0)
    assert cli.main(["--window", "--theme", "amber-phosphor", "--no-crt"]) == 0
    assert seen == [["--theme", "amber-phosphor", "--no-crt"]]
    assert "--window" in cli.build_parser().format_help()


def test_window_options():
    from netzilla.window import build_parser

    args = build_parser().parse_args(["--theme", "AMBER-PHOSPHOR", "--font-size", "18",
                                      "--no-crt", "--tab", "wifi"])
    assert (args.theme, args.font_size, args.crt, args.tab) == ("amber-phosphor", 18,
                                                                False, "wifi")
    assert build_parser().parse_args([]).crt is None


def test_console_windows_stay_hidden_on_windows(monkeypatch):
    calls = []

    def fake_init(self, *args, **kwargs):
        calls.append(kwargs.get("creationflags", 0))

    monkeypatch.setattr(subprocess.Popen, "__init__", fake_init)
    monkeypatch.setattr(hostos, "NAME", hostos.LINUX)
    assert hostos.hide_console_windows() is False
    monkeypatch.setattr(hostos, "NAME", hostos.WINDOWS)
    assert hostos.hide_console_windows() is True
    assert hostos.hide_console_windows() is True            # only wrapped once
    subprocess.Popen(["ping"])
    subprocess.Popen(["cmd"], creationflags=0x00000010)     # its own console: left alone
    assert calls == [0x08000000, 0x00000010]


def test_icon_is_the_dash_n():
    from netzilla.window.icon import ICO_SIZES, icon_image, save_ico

    image = icon_image(64)
    assert image.size == (64, 64) and image.mode == "RGBA"
    assert image.getpixel((0, 0))[3] == 0 and image.getpixel((32, 32))[3] == 255
    buffer = io.BytesIO()
    save_ico(buffer)
    assert buffer.getvalue()[:4] == b"\x00\x00\x01\x00"
    assert 256 in ICO_SIZES and 16 in ICO_SIZES


def test_pyinstaller_build_takes_everything_netzilla_needs():
    spec = importlib.util.spec_from_file_location("build_exe",
                                                  ROOT / "packaging" / "build_exe.py")
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    command = build.pyinstaller_command("4.8.0", Path("netzilla.ico"), False, True)
    text = " ".join(command)
    for part in ("--onefile", "--windowed", "--collect-data netzilla",
                 "--hidden-import PIL._tkinter_finder", "--copy-metadata textual",
                 "--collect-submodules winrt", "--version-file", "--icon netzilla.ico"):
        assert part in text, part
    assert command[-1].endswith("netzilla_exe.py")
    assert "--onedir" in build.pyinstaller_command("4.8.0", None, True, False)
    workflow = (ROOT / ".github" / "workflows" / "windows-exe.yml").read_text(encoding="utf-8")
    assert "windows-latest" in workflow and "packaging/build_exe.py" in workflow
    assert "--selftest" in workflow


def test_fonts_ship_with_the_package():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "data/fonts/*.ttf" in pyproject and "data/fonts/*.txt" in pyproject
    assert 'netzilla-window = "netzilla.window:main"' in pyproject


# ===================================================================== the real window
def _display_available() -> bool:
    try:
        import tkinter
    except ImportError:
        return False
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY") \
            and not os.environ.get("WAYLAND_DISPLAY"):
        return False
    try:
        root = tkinter.Tk()
        root.destroy()
    except Exception:
        return False
    return True


@pytest.mark.skipif(not _display_available(), reason="no display for a window")
def test_the_window_self_test(window_world):
    import json

    from netzilla.window import run
    from netzilla.window.tkwindow import Options

    report = window_world / "report.json"
    picture = window_world / "window.png"
    options = Options(config_path=str(window_world / "config.toml"), offline=True,
                      selftest=10.0, press=["F2"], report=str(report),
                      screenshot=str(picture))
    assert run(options, sys.stderr) == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["tab"] == "settings" and data["pixel_graphs"] and data["images"] > 0
    assert data["font"] == "JetBrainsMonoNL-Regular.ttf" and data["crt"] is True
    cols, rows = data["grid"]
    assert cols >= 40 and rows >= 10
    assert Image.open(picture).size == tuple(data["frame"])
