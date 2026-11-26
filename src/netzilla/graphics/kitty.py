"""kitty graphics protocol — the Unicode-placeholder way of showing images.

How a pixel graph reaches the screen:

  1. the image is sent once, out of band, as an APC escape:
       ESC _G a=T,U=1,f=100,i=<id>,c=<cols>,r=<rows>,q=2 ; <base64 PNG> ESC \\
     (chunked to 4096 bytes; U=1 makes a *virtual* placement, q=2 keeps the
     terminal from answering — an answer would arrive as keyboard input);
  2. the interface then prints ordinary text where the image belongs: one
     U+10EEEE placeholder per cell, with combining diacritics giving the row
     and column, in a foreground colour that encodes the image id.

Because step 2 is plain text, Textual lays it out, scrolls it, crops it and
repaints it like any other cell — the terminal fills those cells with the
image's pixels. Each Canvas double-buffers: a new frame goes up under a fresh
id before the text switches to it, and the frame before last is deleted, so a
live graph never flashes empty.

Spec: https://sw.kovidgoyal.net/kitty/graphics-protocol/#unicode-placeholders
"""

from __future__ import annotations

import base64
import random
import threading
from typing import Callable

from rich.style import Style
from rich.text import Text

PLACEHOLDER = "\U0010EEEE"
CHUNK = 4096

# Row / column numbers, in order, from kitty's rowcolumn-diacritics.txt
# (combining characters from Unicode 6.0.0, all zero-width).
DIACRITICS = tuple(chr(c) for c in (
    0x0305, 0x030D, 0x030E, 0x0310, 0x0312, 0x033D, 0x033E, 0x033F, 0x0346, 0x034A,
    0x034B, 0x034C, 0x0350, 0x0351, 0x0352, 0x0357, 0x035B, 0x0363, 0x0364, 0x0365,
    0x0366, 0x0367, 0x0368, 0x0369, 0x036A, 0x036B, 0x036C, 0x036D, 0x036E, 0x036F,
    0x0483, 0x0484, 0x0485, 0x0486, 0x0487, 0x0592, 0x0593, 0x0594, 0x0595, 0x0597,
    0x0598, 0x0599, 0x059C, 0x059D, 0x059E, 0x059F, 0x05A0, 0x05A1, 0x05A8, 0x05A9,
    0x05AB, 0x05AC, 0x05AF, 0x05C4, 0x0610, 0x0611, 0x0612, 0x0613, 0x0614, 0x0615,
    0x0616, 0x0617, 0x0657, 0x0658, 0x0659, 0x065A, 0x065B, 0x065D, 0x065E, 0x06D6,
    0x06D7, 0x06D8, 0x06D9, 0x06DA, 0x06DB, 0x06DC, 0x06DF, 0x06E0, 0x06E1, 0x06E2,
    0x06E4, 0x06E7, 0x06E8, 0x06EB, 0x06EC, 0x0730, 0x0732, 0x0733, 0x0735, 0x0736,
    0x073A, 0x073D, 0x073F, 0x0740, 0x0741, 0x0743, 0x0745, 0x0747, 0x0749, 0x074A,
    0x07EB, 0x07EC, 0x07ED, 0x07EE, 0x07EF, 0x07F0, 0x07F1, 0x07F3, 0x0816, 0x0817,
    0x0818, 0x0819, 0x081B, 0x081C, 0x081D, 0x081E, 0x081F, 0x0820, 0x0821, 0x0822,
    0x0823, 0x0825, 0x0826, 0x0827, 0x0829, 0x082A, 0x082B, 0x082C, 0x082D, 0x0951,
    0x0953, 0x0954, 0x0F82, 0x0F83, 0x0F86, 0x0F87, 0x135D, 0x135E, 0x135F, 0x17DD,
    0x193A, 0x1A17, 0x1A75, 0x1A76, 0x1A77, 0x1A78, 0x1A79, 0x1A7A, 0x1A7B, 0x1A7C,
    0x1B6B, 0x1B6D, 0x1B6E, 0x1B6F, 0x1B70, 0x1B71, 0x1B72, 0x1B73, 0x1CD0, 0x1CD1,
    0x1CD2, 0x1CDA, 0x1CDB, 0x1CE0, 0x1DC0, 0x1DC1, 0x1DC3, 0x1DC4, 0x1DC5, 0x1DC6,
    0x1DC7, 0x1DC8, 0x1DC9, 0x1DCB, 0x1DCC, 0x1DD1, 0x1DD2, 0x1DD3, 0x1DD4, 0x1DD5,
    0x1DD6, 0x1DD7, 0x1DD8, 0x1DD9, 0x1DDA, 0x1DDB, 0x1DDC, 0x1DDD, 0x1DDE, 0x1DDF,
    0x1DE0, 0x1DE1, 0x1DE2, 0x1DE3, 0x1DE4, 0x1DE5, 0x1DE6, 0x1DFE, 0x20D0, 0x20D1,
    0x20D4, 0x20D5, 0x20D6, 0x20D7, 0x20DB, 0x20DC, 0x20E1, 0x20E7, 0x20E9, 0x20F0,
    0x2CEF, 0x2CF0, 0x2CF1, 0x2DE0, 0x2DE1, 0x2DE2, 0x2DE3, 0x2DE4, 0x2DE5, 0x2DE6,
    0x2DE7, 0x2DE8, 0x2DE9, 0x2DEA, 0x2DEB, 0x2DEC, 0x2DED, 0x2DEE, 0x2DEF, 0x2DF0,
    0x2DF1, 0x2DF2, 0x2DF3, 0x2DF4, 0x2DF5, 0x2DF6, 0x2DF7, 0x2DF8, 0x2DF9, 0x2DFA,
    0x2DFB, 0x2DFC, 0x2DFD, 0x2DFE, 0x2DFF, 0xA66F, 0xA67C, 0xA67D, 0xA6F0, 0xA6F1,
    0xA8E0, 0xA8E1, 0xA8E2, 0xA8E3, 0xA8E4, 0xA8E5, 0xA8E6, 0xA8E7, 0xA8E8, 0xA8E9,
    0xA8EA, 0xA8EB, 0xA8EC, 0xA8ED, 0xA8EE, 0xA8EF, 0xA8F0, 0xA8F1, 0xAAB0, 0xAAB2,
    0xAAB3, 0xAAB7, 0xAAB8, 0xAABE, 0xAABF, 0xAAC1, 0xFE20, 0xFE21, 0xFE22, 0xFE23,
    0xFE24, 0xFE25, 0xFE26, 0x10A0F, 0x10A38, 0x1D185, 0x1D186, 0x1D187, 0x1D188, 0x1D189,
    0x1D1AA, 0x1D1AB, 0x1D1AC, 0x1D1AD, 0x1D242, 0x1D243, 0x1D244,
))
MAX_CELLS = len(DIACRITICS)          # 297 rows or columns per image

# ------------------------------------------------------------------ output
_writer: Callable[[str], None] | None = None
_wrap_tmux = False
_lock = threading.Lock()
# Image ids live in one namespace shared by every program in the terminal,
# so start somewhere random in the 24-bit range a truecolour id can encode.
_next = random.randint(0x10_0000, 0xA0_0000)
_live: set[int] = set()


def set_writer(writer: Callable[[str], None] | None, tmux: bool = False) -> None:
    """Where escape sequences go — the app's terminal driver — and whether
    they must be wrapped for tmux passthrough."""
    global _writer, _wrap_tmux
    _writer = writer
    _wrap_tmux = tmux


def active() -> bool:
    return _writer is not None


def _send(sequence: str) -> None:
    if _writer is None:
        return
    if _wrap_tmux:
        sequence = "\x1bPtmux;" + sequence.replace("\x1b", "\x1b\x1b") + "\x1b\\"
    try:
        _writer(sequence)
    except Exception:            # a closed driver at exit: nothing to draw on
        pass


def new_id() -> int:
    global _next
    with _lock:
        _next += 1
        if _next > 0xFF_FFFE:
            _next = 0x10_0000
        image_id = _next
        _live.add(image_id)
    return image_id


# --------------------------------------------------------------- sequences
def transmit_sequences(png: bytes, image_id: int, cols: int, rows: int) -> list[str]:
    """APC chunks that upload a PNG and give it a virtual placement of
    `cols` x `rows` cells, with every reply suppressed."""
    payload = base64.standard_b64encode(png).decode("ascii")
    chunks = [payload[i:i + CHUNK] for i in range(0, len(payload), CHUNK)] or [""]
    out = []
    for index, chunk in enumerate(chunks):
        more = 1 if index < len(chunks) - 1 else 0
        if index == 0:
            control = (f"a=T,U=1,f=100,t=d,i={image_id},c={cols},r={rows},"
                       f"q=2,m={more}")
        else:
            control = f"m={more},q=2"
        out.append(f"\x1b_G{control};{chunk}\x1b\\")
    return out


def delete_sequence(image_id: int) -> str:
    """Delete one image and free its data (uppercase I)."""
    return f"\x1b_Ga=d,d=I,i={image_id},q=2\x1b\\"


def show(png: bytes, cols: int, rows: int) -> int:
    """Upload a PNG for a cols x rows placeholder; returns its image id."""
    image_id = new_id()
    for sequence in transmit_sequences(png, image_id, cols, rows):
        _send(sequence)
    return image_id


def delete(image_id: int) -> None:
    with _lock:
        _live.discard(image_id)
    _send(delete_sequence(image_id))


def delete_all() -> None:
    """Free every image netzilla uploaded (called on exit)."""
    with _lock:
        ids = sorted(_live)
        _live.clear()
    for image_id in ids:
        _send(delete_sequence(image_id))


# ------------------------------------------------------------- placeholders
def id_colour(image_id: int) -> str:
    return f"#{(image_id >> 16) & 0xFF:02x}{(image_id >> 8) & 0xFF:02x}{image_id & 0xFF:02x}"


def placeholder_text(image_id: int, cols: int, rows: int) -> Text:
    """`rows` lines of `cols` placeholder cells for one image. Every cell
    carries its row and column diacritics, so the image survives being
    cropped, scrolled or partly repainted."""
    cols = max(1, min(cols, MAX_CELLS))
    rows = max(1, min(rows, MAX_CELLS))
    style = Style(color=id_colour(image_id))
    text = Text(no_wrap=True, overflow="crop", end="")
    for row in range(rows):
        diacritic = DIACRITICS[row]
        line = "".join(PLACEHOLDER + diacritic + DIACRITICS[col] for col in range(cols))
        text.append(line, style=style)
        if row < rows - 1:
            text.append("\n")
    return text


def placeholder_rows(image_id: int, cols: int, rows: int) -> list[Text]:
    """The same placeholder cells, one Text per row, for interleaving with
    other text (a graph's axis labels)."""
    cols = max(1, min(cols, MAX_CELLS))
    rows = max(1, min(rows, MAX_CELLS))
    style = Style(color=id_colour(image_id))
    out = []
    for row in range(rows):
        diacritic = DIACRITICS[row]
        out.append(Text("".join(PLACEHOLDER + diacritic + DIACRITICS[col]
                                for col in range(cols)), style=style, end=""))
    return out


def placeholder_span(image_id: int, row: int, first: int, last: int) -> Text:
    """Columns `first` up to (not including) `last` of one row of an image's
    placeholder cells — for putting cells of different images side by side
    on a line (DASH's banner, whose breath is a separate image per frame)."""
    row = max(0, min(row, MAX_CELLS - 1))
    first, last = max(0, first), min(last, MAX_CELLS)
    return Text("".join(PLACEHOLDER + DIACRITICS[row] + DIACRITICS[col]
                        for col in range(first, last)),
                style=Style(color=id_colour(image_id)), end="")


class Canvas:
    """One spot on screen that shows a changing image (a live graph).

    show() uploads the new frame under a fresh id and returns the placeholder
    text for it; the frame before the previous one is then deleted. The
    previous frame stays until the screen has switched to the new text, so
    an update never flashes blank.
    """

    KEEP = 2

    def __init__(self) -> None:
        self._ids: list[int] = []
        self.size: tuple[int, int] = (0, 0)

    def upload(self, png: bytes, cols: int, rows: int) -> int:
        """Upload a frame; returns its image id for placeholder_rows()."""
        image_id = show(png, cols, rows)
        self._ids.append(image_id)
        while len(self._ids) > self.KEEP:
            delete(self._ids.pop(0))
        self.size = (cols, rows)
        return image_id

    def show(self, png: bytes, cols: int, rows: int) -> Text:
        return placeholder_text(self.upload(png, cols, rows), cols, rows)

    def clear(self) -> None:
        while self._ids:
            delete(self._ids.pop())


__all__ = ["PLACEHOLDER", "DIACRITICS", "Canvas", "set_writer", "active", "show",
           "delete", "delete_all", "placeholder_text", "placeholder_rows", "placeholder_span",
           "transmit_sequences",
           "delete_sequence", "id_colour", "new_id"]
