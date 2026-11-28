"""The window's terminal: a grid of cells kept up to date from what Textual
writes, as a real terminal would keep it.

Textual draws by writing text and escape sequences (cursor moves, SGR
colours, OSC 8 links, OSC 52 clipboard); netzilla's pixel graphs arrive as
kitty graphics protocol uploads (APC G) and Unicode placeholder cells. This
module understands that stream: it moves the cursor, writes characters with
their colours into the grid (wide characters take two cells, combining
marks join the cell before them), keeps uploaded images by id, and remembers
which cells changed so the painter only redraws those.

Nothing here needs tkinter or a display, so all of it is tested headless.
"""

from __future__ import annotations

import base64
import binascii
import io
import re
import zlib
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable, NamedTuple

from rich.cells import get_character_cell_size

# ------------------------------------------------------------------ styles
BOLD, DIM, ITALIC, UNDERLINE, BLINK, REVERSE, CONCEAL, STRIKE, UNDERLINE2, OVERLINE = (
    1 << n for n in range(10))

# xterm's 16 colours, for the rare segment that isn't truecolour (Textual
# turns ANSI colours into its theme's truecolour before writing them).
ANSI = (
    0x000000, 0xCD0000, 0x00CD00, 0xCDCD00, 0x0000EE, 0xCD00CD, 0x00CDCD, 0xE5E5E5,
    0x7F7F7F, 0xFF0000, 0x00FF00, 0xFFFF00, 0x5C5CFF, 0xFF00FF, 0x00FFFF, 0xFFFFFF,
)


def xterm256(index: int) -> int:
    """The 24-bit colour of xterm's 256-colour palette entry `index`."""
    index = max(0, min(255, index))
    if index < 16:
        return ANSI[index]
    if index < 232:
        index -= 16
        steps = (0, 95, 135, 175, 215, 255)
        r, g, b = steps[index // 36], steps[(index // 6) % 6], steps[index % 6]
        return (r << 16) | (g << 8) | b
    grey = 8 + (index - 232) * 10
    return (grey << 16) | (grey << 8) | grey


class Style(NamedTuple):
    """How a cell is drawn: colours as 0xRRGGBB (None: the window's default),
    attribute bits, and the OSC 8 link it belongs to."""

    fg: int | None = None
    bg: int | None = None
    flags: int = 0
    link: str | None = None


PLAIN = Style()

_SGR_FLAGS = {1: BOLD, 2: DIM, 3: ITALIC, 4: UNDERLINE, 5: BLINK, 6: BLINK, 7: REVERSE,
              8: CONCEAL, 9: STRIKE, 21: UNDERLINE2, 53: OVERLINE}
_SGR_CLEAR = {22: BOLD | DIM, 23: ITALIC, 24: UNDERLINE | UNDERLINE2, 25: BLINK,
              27: REVERSE, 28: CONCEAL, 29: STRIKE, 55: OVERLINE}


@lru_cache(maxsize=8192)
def apply_sgr(style: Style, params: str) -> Style:
    """`style` after one SGR sequence (CSI params m)."""
    if not params:
        return Style(link=style.link)
    fg, bg, flags = style.fg, style.bg, style.flags
    parts = params.replace(":", ";").split(";")
    numbers = [int(p) if p.isdigit() else 0 for p in parts]
    i = 0
    while i < len(numbers):
        n = numbers[i]
        if n == 0:
            fg, bg, flags = None, None, 0
        elif n in _SGR_FLAGS:
            flags |= _SGR_FLAGS[n]
        elif n in _SGR_CLEAR:
            flags &= ~_SGR_CLEAR[n]
        elif 30 <= n <= 37:
            fg = ANSI[n - 30]
        elif 90 <= n <= 97:
            fg = ANSI[n - 90 + 8]
        elif 40 <= n <= 47:
            bg = ANSI[n - 40]
        elif 100 <= n <= 107:
            bg = ANSI[n - 100 + 8]
        elif n == 39:
            fg = None
        elif n == 49:
            bg = None
        elif n in (38, 48, 58):
            colour = None
            if i + 1 < len(numbers) and numbers[i + 1] == 5 and i + 2 < len(numbers):
                colour = xterm256(numbers[i + 2])
                i += 2
            elif i + 1 < len(numbers) and numbers[i + 1] == 2:
                # 38;2;r;g;b — or 38:2::r:g:b with an empty colour-space id
                rest = numbers[i + 2:i + 6]
                if len(parts) > i + 5 and parts[i + 2] == "" and len(rest) == 4:
                    rest = rest[1:]
                    i += 1
                if len(rest) >= 3:
                    r, g, b = (max(0, min(255, v)) for v in rest[:3])
                    colour = (r << 16) | (g << 8) | b
                i += 4
            if n == 38:
                fg = colour
            elif n == 48:
                bg = colour
        i += 1
    return Style(fg, bg, flags, style.link)


# ------------------------------------------------------------------ images
@dataclass
class KittyImage:
    """One image uploaded with the kitty graphics protocol."""

    image_id: int
    image: object                      # PIL.Image.Image (RGBA)
    cols: int = 0                      # its virtual placement, in cells
    rows: int = 0
    serial: int = 0                    # bumped on every change


@dataclass
class _Upload:
    control: dict
    chunks: list = field(default_factory=list)


def parse_control(text: str) -> dict:
    """'a=T,i=31,c=10' -> {'a': 'T', 'i': '31', 'c': '10'}"""
    out = {}
    for part in text.split(","):
        key, _, value = part.partition("=")
        if key:
            out[key.strip()] = value.strip()
    return out


def _int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def decode_image(control: dict, payload: bytes):
    """A PIL image from one kitty upload's data, or None if it can't be read."""
    try:
        from PIL import Image
    except Exception:              # pragma: no cover - Pillow is a dependency
        return None
    if control.get("o") == "z":
        try:
            payload = zlib.decompress(payload)
        except zlib.error:
            return None
    fmt = _int(control.get("f"), 32)
    try:
        if fmt == 100:
            image = Image.open(io.BytesIO(payload))
            image.load()
            return image.convert("RGBA")
        width, height = _int(control.get("s")), _int(control.get("v"))
        if width <= 0 or height <= 0:
            return None
        mode = "RGB" if fmt == 24 else "RGBA"
        size = width * height * (3 if fmt == 24 else 4)
        if len(payload) < size:
            return None
        return Image.frombytes(mode, (width, height), payload[:size]).convert("RGBA")
    except Exception:
        return None


# ------------------------------------------------------------------ the parser
_TOKEN = re.compile(
    r"(?P<text>[^\x00-\x1f\x7f-\x9f]+)"
    r"|\x1b\[(?P<csi_p>[0-?]*)(?P<csi_i>[ -/]*)(?P<csi_f>[@-~])"
    r"|\x1b\](?P<osc>[^\x07\x1b]*)(?:\x07|\x1b\\)"
    r"|\x1b_(?P<apc>[^\x1b]*)\x1b\\"
    r"|\x1bP(?P<dcs>[^\x1b]*)\x1b\\"
    r"|\x1b(?P<esc>[ -/]*[0-~])"
    r"|(?P<ctl>[\x00-\x1f\x7f-\x9f])",
    re.S,
)
# A sequence that started but hasn't finished in this chunk: kept for the next.
_OPENERS = "[]_P"
MAX_PENDING = 64 * 1024 * 1024     # a runaway sequence is dropped, not kept forever


@lru_cache(maxsize=4096)
def char_width(char: str) -> int:
    return get_character_cell_size(char)


class Screen:
    """The cell grid and everything Textual has told it."""

    def __init__(self, cols: int = 80, rows: int = 24) -> None:
        self.cols = max(1, cols)
        self.rows = max(1, rows)
        self.chars: list[list[str]] = []
        self.styles: list[list[Style]] = []
        self._blank_rows()
        self.x = 0
        self.y = 0
        self.wrap_pending = False
        self.autowrap = True
        self.style = PLAIN
        self._saved = (0, 0, PLAIN)
        self.title = ""
        self.images: dict[int, KittyImage] = {}
        self._upload: _Upload | None = None
        self._serial = 0
        self._pending = ""
        # rows that changed since the painter last looked: row -> [first, last]
        self.dirty: dict[int, list[int]] = {}
        self.all_dirty = True
        # callbacks into the window (all optional)
        self.on_title: Callable[[str], None] | None = None
        self.on_clipboard: Callable[[str], None] | None = None
        self.on_bell: Callable[[], None] | None = None
        self.on_notify: Callable[[str, str], None] | None = None
        self.on_pointer: Callable[[str], None] | None = None
        self.on_reply: Callable[[str], None] | None = None
        self.on_images: Callable[[], None] | None = None
        self.changed_images: set[int] = set()     # uploaded or deleted since asked

    # ------------------------------------------------------------ grid
    def _blank_rows(self) -> None:
        self.chars = [[" "] * self.cols for _ in range(self.rows)]
        self.styles = [[PLAIN] * self.cols for _ in range(self.rows)]

    def resize(self, cols: int, rows: int) -> None:
        """Change the grid size, keeping what fits (Textual repaints anyway)."""
        cols, rows = max(1, cols), max(1, rows)
        if (cols, rows) == (self.cols, self.rows):
            return
        chars = [[" "] * cols for _ in range(rows)]
        styles = [[PLAIN] * cols for _ in range(rows)]
        for y in range(min(rows, self.rows)):
            width = min(cols, self.cols)
            chars[y][:width] = self.chars[y][:width]
            styles[y][:width] = self.styles[y][:width]
            if width < self.cols and chars[y][width - 1] and char_width(chars[y][width - 1][0]) == 2:
                chars[y][width - 1] = " "           # a wide character cut in half
        self.cols, self.rows = cols, rows
        self.chars, self.styles = chars, styles
        self.x = min(self.x, cols - 1)
        self.y = min(self.y, rows - 1)
        self.wrap_pending = False
        self.all_dirty = True
        self.dirty.clear()

    def _mark(self, y: int, first: int, last: int) -> None:
        if self.all_dirty:
            return
        span = self.dirty.get(y)
        if span is None:
            self.dirty[y] = [first, last]
        else:
            if first < span[0]:
                span[0] = first
            if last > span[1]:
                span[1] = last

    def take_dirty(self) -> tuple[bool, dict[int, list[int]]]:
        """What changed since last time: (everything?, {row: [first, last]})."""
        everything, rows = self.all_dirty, self.dirty
        self.all_dirty = False
        self.dirty = {}
        return everything, rows

    def mark_all(self) -> None:
        self.all_dirty = True
        self.dirty.clear()

    def text(self) -> str:
        """The grid as plain text, one line per row (tests, debugging)."""
        return "\n".join("".join(c for c in row if c) for row in self.chars)

    # ------------------------------------------------------------ feeding
    def feed(self, data: str) -> None:
        """Process one chunk of terminal output."""
        if self._pending:
            data = self._pending + data
            self._pending = ""
        pos, end = 0, len(data)
        match = _TOKEN.match
        while pos < end:
            m = match(data, pos)
            if m is None:            # pragma: no cover - every char matches something
                pos += 1
                continue
            kind = m.lastgroup
            if kind == "text":
                self._text(m.group("text"))
            elif kind == "csi_f":
                self._csi(m.group("csi_p"), m.group("csi_i"), m.group("csi_f"))
            elif kind == "esc":
                seq = m.group("esc")
                if seq in _OPENERS and self._incomplete(data, pos):
                    self._keep(data[pos:])
                    return
                self._esc(seq)
            elif kind == "osc":
                self._osc(m.group("osc"))
            elif kind == "apc":
                self._apc(m.group("apc"))
            elif kind == "dcs":
                pass                 # no DCS we act on (Sixel, tmux passthrough)
            elif kind == "ctl":
                char = m.group("ctl")
                if char == "\x1b":
                    if pos == end - 1:
                        # A lone ESC at the very end: the rest is in the next chunk.
                        self._keep(data[pos:])
                        return
                    # An ESC followed by something no sequence starts with: dropped.
                else:
                    self._control(char)
            pos = m.end()

    def _incomplete(self, data: str, pos: int) -> bool:
        """True when the escape at `pos` is a CSI/OSC/APC/DCS whose end hasn't
        arrived yet (the regex fell back to reading it as a two-byte ESC)."""
        rest = data[pos:]
        opener = rest[1:2]
        if opener == "[":
            return re.match(r"\x1b\[[0-?]*[ -/]*\Z", rest) is not None
        if opener == "]":
            return "\x07" not in rest and "\x1b\\" not in rest
        return "\x1b\\" not in rest

    def _keep(self, rest: str) -> None:
        self._pending = rest if len(rest) <= MAX_PENDING else ""

    # ------------------------------------------------------------ text
    def _text(self, run: str) -> None:
        if run.isascii():
            self._ascii(run)
            return
        for char in run:
            self._char(char)

    def _wrap(self) -> None:
        self.wrap_pending = False
        self.x = 0
        self._linefeed()

    def _ascii(self, run: str) -> None:
        style = self.style
        cols = self.cols
        while run:
            if self.wrap_pending:
                if not self.autowrap:
                    # Without autowrap the last column is simply overwritten.
                    self._put(self.x, run[-1], style)
                    return
                self._wrap()
            x, y = self.x, self.y
            room = cols - x
            piece, run = run[:room], run[room:]
            n = len(piece)
            row_chars = self.chars[y]
            self._clear_wide_edges(y, x, x + n - 1)
            row_chars[x:x + n] = piece
            self.styles[y][x:x + n] = [style] * n
            self._mark(y, x, x + n - 1)
            if x + n >= cols:
                self.x = cols - 1
                self.wrap_pending = True
            else:
                self.x = x + n

    def _clear_wide_edges(self, y: int, first: int, last: int) -> None:
        """Writing over half of a wide character blanks its other half."""
        row = self.chars[y]
        if row[first] == "" and first > 0:
            row[first - 1] = " "
            self._mark(y, first - 1, first - 1)
        if last + 1 < self.cols and row[last + 1] == "":
            row[last + 1] = " "
            self._mark(y, last + 1, last + 1)

    def _put(self, x: int, char: str, style: Style) -> None:
        self._clear_wide_edges(self.y, x, x)
        self.chars[self.y][x] = char
        self.styles[self.y][x] = style
        self._mark(self.y, x, x)

    def _char(self, char: str) -> None:
        width = char_width(char)
        if width == 0:
            self._combine(char)
            return
        if self.wrap_pending:
            if self.autowrap:
                self._wrap()
            else:
                self.wrap_pending = False
        if width == 2 and self.x >= self.cols - 1:
            if self.cols < 2:
                return
            if self.autowrap:
                # No room for both halves: wrap first, as terminals do.
                self._put(self.x, " ", self.style)
                self._wrap()
            else:
                self.x = self.cols - 2
        x, y = self.x, self.y
        self._clear_wide_edges(y, x, x + width - 1)
        self.chars[y][x] = char
        self.styles[y][x] = self.style
        if width == 2:
            self.chars[y][x + 1] = ""
            self.styles[y][x + 1] = self.style
        self._mark(y, x, x + width - 1)
        if x + width >= self.cols:
            self.x = self.cols - 1
            self.wrap_pending = True
        else:
            self.x = x + width

    def _combine(self, mark: str) -> None:
        """A zero-width character (a combining mark, a variation selector,
        a kitty placeholder's row and column) joins the cell written last."""
        x = self.x if self.wrap_pending else self.x - 1
        y = self.y
        if x < 0:
            return
        if self.chars[y][x] == "" and x > 0:
            x -= 1
        if len(self.chars[y][x]) >= 8:        # keep a runaway cluster bounded
            return
        self.chars[y][x] += mark
        self._mark(y, x, x)

    # ------------------------------------------------------------ controls
    def _control(self, char: str) -> None:
        if char in "\n\x0b\x0c":
            self.wrap_pending = False
            self._linefeed()
        elif char == "\r":
            self.x = 0
            self.wrap_pending = False
        elif char == "\x08":
            self.x = max(0, self.x - 1)
            self.wrap_pending = False
        elif char == "\t":
            self.x = min(self.cols - 1, (self.x // 8 + 1) * 8)
            self.wrap_pending = False
        elif char == "\x07":
            if self.on_bell:
                self.on_bell()

    def _linefeed(self) -> None:
        if self.y < self.rows - 1:
            self.y += 1
        else:
            self._scroll_up(1)

    def _scroll_up(self, count: int) -> None:
        count = max(1, min(count, self.rows))
        blank = Style(bg=self.style.bg)
        del self.chars[:count]
        del self.styles[:count]
        for _ in range(count):
            self.chars.append([" "] * self.cols)
            self.styles.append([blank] * self.cols)
        self.mark_all()

    def _scroll_down(self, count: int) -> None:
        count = max(1, min(count, self.rows))
        blank = Style(bg=self.style.bg)
        del self.chars[self.rows - count:]
        del self.styles[self.rows - count:]
        for _ in range(count):
            self.chars.insert(0, [" "] * self.cols)
            self.styles.insert(0, [blank] * self.cols)
        self.mark_all()

    def _erase(self, y: int, first: int, last: int) -> None:
        """Blank cells first..last of row y with the current background."""
        first, last = max(0, first), min(self.cols - 1, last)
        if last < first:
            return
        blank = Style(bg=self.style.bg)
        self._clear_wide_edges(y, first, last)
        n = last - first + 1
        self.chars[y][first:last + 1] = [" "] * n
        self.styles[y][first:last + 1] = [blank] * n
        self._mark(y, first, last)

    # ------------------------------------------------------------ escapes
    def _esc(self, seq: str) -> None:
        if seq == "7":
            self._saved = (self.x, self.y, self.style)
        elif seq == "8":
            self.x, self.y, self.style = self._saved
            self.x = min(self.x, self.cols - 1)
            self.y = min(self.y, self.rows - 1)
            self.wrap_pending = False
        elif seq == "D":
            self._linefeed()
        elif seq == "E":
            self.x = 0
            self._linefeed()
        elif seq == "M":
            if self.y > 0:
                self.y -= 1
            else:
                self._scroll_down(1)
        elif seq == "c":
            self.style = PLAIN
            self._blank_rows()
            self.x = self.y = 0
            self.wrap_pending = False
            self.mark_all()
        # ESC = / ESC > (keypad), ESC ( B (character set), ESC \ (a stray
        # string terminator): nothing to do.

    def _csi(self, params: str, inter: str, final: str) -> None:
        if final == "m" and not inter:
            if params[:1] in "<=>?" and params:
                return               # private SGR-like sequences (kitty's CSI > m)
            self.style = apply_sgr(self.style, params)
            return
        private = params[:1] if params[:1] in "<=>?" else ""
        body = params[1:] if private else params
        nums = [int(p) if p.isdigit() else 0 for p in body.split(";")] if body else []

        def arg(index: int, default: int = 1) -> int:
            value = nums[index] if index < len(nums) else 0
            return value or default

        if private == "?" and final in "hl":
            on = final == "h"
            for mode in nums:
                if mode == 7:
                    self.autowrap = on
                elif mode in (47, 1047, 1049) and on:
                    self.style = PLAIN
                    self._blank_rows()
                    self.mark_all()
            return
        if private or inter:
            if private == "?" and final == "p" and inter == "$":
                return               # DECRQM: unsupported modes go unanswered
            if private == ">" and final == "q" and self.on_reply:
                from .. import __version__

                self.on_reply(f"\x1bP>|netzilla window {__version__}\x1b\\")
            return
        if final in "Hf":
            self.y = min(self.rows - 1, arg(0) - 1)
            self.x = min(self.cols - 1, arg(1) - 1)
            self.wrap_pending = False
        elif final == "A":
            self.y = max(0, self.y - arg(0))
            self.wrap_pending = False
        elif final in "Be":
            self.y = min(self.rows - 1, self.y + arg(0))
            self.wrap_pending = False
        elif final in "Ca":
            self.x = min(self.cols - 1, self.x + arg(0))
            self.wrap_pending = False
        elif final == "D":
            self.x = max(0, self.x - arg(0))
            self.wrap_pending = False
        elif final == "E":
            self.y = min(self.rows - 1, self.y + arg(0))
            self.x = 0
            self.wrap_pending = False
        elif final == "F":
            self.y = max(0, self.y - arg(0))
            self.x = 0
            self.wrap_pending = False
        elif final in "G`":
            self.x = min(self.cols - 1, arg(0) - 1)
            self.wrap_pending = False
        elif final == "d":
            self.y = min(self.rows - 1, arg(0) - 1)
            self.wrap_pending = False
        elif final == "J":
            how = nums[0] if nums else 0
            if how == 0:
                self._erase(self.y, self.x, self.cols - 1)
                for y in range(self.y + 1, self.rows):
                    self._erase(y, 0, self.cols - 1)
            elif how == 1:
                for y in range(0, self.y):
                    self._erase(y, 0, self.cols - 1)
                self._erase(self.y, 0, self.x)
            else:
                for y in range(self.rows):
                    self._erase(y, 0, self.cols - 1)
        elif final == "K":
            how = nums[0] if nums else 0
            if how == 0:
                self._erase(self.y, self.x, self.cols - 1)
            elif how == 1:
                self._erase(self.y, 0, self.x)
            else:
                self._erase(self.y, 0, self.cols - 1)
        elif final == "X":
            self._erase(self.y, self.x, self.x + arg(0) - 1)
        elif final == "P":
            count = min(arg(0), self.cols - self.x)
            row, styles = self.chars[self.y], self.styles[self.y]
            del row[self.x:self.x + count]
            del styles[self.x:self.x + count]
            row.extend([" "] * count)
            styles.extend([Style(bg=self.style.bg)] * count)
            self._mark(self.y, self.x, self.cols - 1)
        elif final == "@":
            count = min(arg(0), self.cols - self.x)
            row, styles = self.chars[self.y], self.styles[self.y]
            for _ in range(count):
                row.insert(self.x, " ")
                styles.insert(self.x, Style(bg=self.style.bg))
            del row[self.cols:]
            del styles[self.cols:]
            self._mark(self.y, self.x, self.cols - 1)
        elif final == "S":
            self._scroll_up(arg(0))
        elif final == "T":
            self._scroll_down(arg(0))
        elif final in "LM":
            count = min(arg(0), self.rows - self.y)
            blank = Style(bg=self.style.bg)
            if final == "L":
                for _ in range(count):
                    self.chars.insert(self.y, [" "] * self.cols)
                    self.styles.insert(self.y, [blank] * self.cols)
                del self.chars[self.rows:]
                del self.styles[self.rows:]
            else:
                del self.chars[self.y:self.y + count]
                del self.styles[self.y:self.y + count]
                for _ in range(count):
                    self.chars.append([" "] * self.cols)
                    self.styles.append([blank] * self.cols)
            self.mark_all()
        elif final == "s":
            self._saved = (self.x, self.y, self.style)
        elif final == "u":
            self.x, self.y, self.style = self._saved
            self.x = min(self.x, self.cols - 1)
            self.y = min(self.y, self.rows - 1)
        elif final == "n" and self.on_reply:
            if nums[:1] == [6]:
                self.on_reply(f"\x1b[{self.y + 1};{self.x + 1}R")
            elif nums[:1] == [5]:
                self.on_reply("\x1b[0n")

    # ------------------------------------------------------------ OSC
    def _osc(self, body: str) -> None:
        code, _, rest = body.partition(";")
        if code in ("0", "2"):
            self.title = rest
            if self.on_title:
                self.on_title(rest)
        elif code == "8":
            _params, _, url = rest.partition(";")
            self.style = self.style._replace(link=url or None)
        elif code == "52":
            _target, _, data = rest.partition(";")
            if data == "?" or not self.on_clipboard:
                return
            try:
                text = base64.b64decode(data, validate=False).decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                return
            self.on_clipboard(text)
        elif code == "22":
            if self.on_pointer:
                self.on_pointer(rest)
        elif code == "777":
            kind, _, more = rest.partition(";")
            if kind == "notify" and self.on_notify:
                title, _, text = more.partition(";")
                self.on_notify(title, text)
        elif code == "9" and self.on_notify and not rest[:2].isdigit():
            self.on_notify("netzilla", rest)
        elif code == "99" and self.on_notify:
            meta, _, text = rest.partition(";")
            if "p=body" in meta:
                self.on_notify("netzilla", text)

    # ------------------------------------------------------------ kitty graphics
    def _apc(self, body: str) -> None:
        if not body.startswith("G"):
            return
        control_text, _, payload = body[1:].partition(";")
        control = parse_control(control_text)
        upload = self._upload
        if upload is not None:
            # A chunked upload continues until a chunk with m=0 (only m and q
            # are sent after the first).
            upload.chunks.append(payload)
            if control.get("m", "0") != "1":
                self._upload = None
                self._finish_upload(upload)
            return
        action = control.get("a", "t")
        if action in ("t", "T"):
            upload = _Upload(control, [payload])
            if control.get("m") == "1":
                self._upload = upload
            else:
                self._finish_upload(upload)
        elif action == "p":
            image = self.images.get(_int(control.get("i")))
            if image is not None and control.get("U") == "1":
                image.cols = _int(control.get("c"), image.cols)
                image.rows = _int(control.get("r"), image.rows)
                self._changed(image)
        elif action == "d":
            target = control.get("d", "a")
            if target in ("a", "A"):
                self.changed_images.update(self.images)
                self.images.clear()
            elif target in ("i", "I"):
                image_id = _int(control.get("i"))
                if self.images.pop(image_id, None) is None:
                    return
                self.changed_images.add(image_id)
            if self.on_images:
                self.on_images()
        elif action == "q":
            quiet = _int(control.get("q"))
            if quiet < 1 and self.on_reply:
                self.on_reply(f"\x1b_Gi={control.get('i', '0')};OK\x1b\\")

    def _changed(self, image: KittyImage) -> None:
        self._serial += 1
        image.serial = self._serial
        self.changed_images.add(image.image_id)
        if self.on_images:
            self.on_images()

    def take_changed_images(self) -> set[int]:
        """The ids of the images uploaded, moved or deleted since last asked."""
        changed, self.changed_images = self.changed_images, set()
        return changed

    def _finish_upload(self, upload: _Upload) -> None:
        control = upload.control
        if control.get("t", "d") != "d":
            return                   # files and shared memory: not used by netzilla
        image_id = _int(control.get("i"))
        if not image_id:
            return
        try:
            data = base64.b64decode("".join(upload.chunks), validate=False)
        except (binascii.Error, ValueError):
            return
        picture = decode_image(control, data)
        if picture is None:
            return
        image = KittyImage(image_id, picture, _int(control.get("c")), _int(control.get("r")))
        self.images[image_id] = image
        self._changed(image)


__all__ = ["Screen", "Style", "KittyImage", "PLAIN", "apply_sgr", "xterm256", "char_width",
           "decode_image", "parse_control", "BOLD", "DIM", "ITALIC", "UNDERLINE", "BLINK",
           "REVERSE", "CONCEAL", "STRIKE", "UNDERLINE2", "OVERLINE"]
