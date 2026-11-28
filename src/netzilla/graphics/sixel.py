"""Sixel — pixel graphs where kitty's placeholders aren't available.

Windows Terminal (1.22 and later) and WezTerm draw Sixel images but not the
Unicode-placeholder part of the kitty protocol that netzilla's pixel graphs
are built on. A placeholder moves with the text; a Sixel image doesn't: it is
drawn at the cursor, once, and stays as pixels in the cells it covered until
text is written over them — Windows Terminal, WezTerm and xterm erase an
image cell by cell as text lands on it.

So the layout stays exactly as in kitty mode, built from text, and an overlay
keeps the pictures on it:

  1. Where an image belongs, the text holds marker cells: blank cells (the
     blank braille pattern, so centring never trims them as it would trim
     spaces) in the image's background colour, whose style carries — as
     metadata Textual keeps but never prints — which image, which row of it
     and which column the run starts at. Each cell is one cell of the image,
     as with placeholders.
  2. Every frame Textual writes goes through overlay(): any marker cells in
     it are cells Textual has just written over, so their image is redrawn
     straight after the frame, wherever its markers are now — cropped to
     what's visible, with holes (unset, i.e. transparent, pixels) where
     something sits on top of it, like a notification. Pictures follow
     scrolling, resizing, tab switches and theme changes like any text.

Images are drawn at the cell size netzilla renders at (the terminal reports
it; Windows Terminal's Sixel cell is always 10 x 20), quantised to at most
255 colours by Pillow, six pixel rows to a band, runs compressed.

Spec: the VT330/VT340 Programmer Reference, chapter 14 (Sixel Graphics).
"""

from __future__ import annotations

import io
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable

from rich.style import Style
from rich.text import Text

try:
    from PIL import Image
    HAVE_PIL = True
except Exception:  # pragma: no cover - only without Pillow
    HAVE_PIL = False

META = "nzsx"                 # the marker's key in a cell's style metadata
MARKER = "\u2800"             # a marker cell's character: blank, and not whitespace
MAX_COLOURS = 255             # index 255 is kept for "leave this pixel unset"
SKIP = 255
MAX_CELLS = 512               # rows or columns one image may span
CACHE = 64                    # encoded images kept (a scrolled graph re-crops)

# ------------------------------------------------------------------ output
_writer: Callable[[str], None] | None = None
_lock = threading.Lock()
_next = 0x51_0000
_images: dict[int, "Picture"] = {}


def set_writer(writer: Callable[[str], None] | None, tmux: bool = False) -> None:
    """Where escape sequences go (the app's terminal driver). Sixel isn't
    passed through tmux, so `tmux` is ignored."""
    global _writer
    _writer = writer


def active() -> bool:
    return _writer is not None


def _send(sequence: str) -> None:
    if _writer is None or not sequence:
        return
    try:
        _writer(sequence)
    except Exception:            # a closed driver at exit: nothing to draw on
        pass


# ------------------------------------------------------------------ images
@dataclass
class Picture:
    """One image netzilla may draw: its pixels and the cells it spans."""

    image_id: int
    image: object                 # PIL RGB image
    cols: int
    rows: int
    background: tuple[int, int, int] = (0, 0, 0)

    @property
    def cell(self) -> tuple[int, int]:
        width, height = self.image.size
        return max(1, width // max(1, self.cols)), max(1, height // max(1, self.rows))


def new_id() -> int:
    global _next
    with _lock:
        _next += 1
        if _next > 0xFF_FFFE:
            _next = 0x51_0000
        return _next


def _corner_colour(image) -> tuple[int, int, int]:
    try:
        return tuple(image.getpixel((0, 0))[:3])  # type: ignore[return-value]
    except Exception:
        return (0, 0, 0)


def show(png, cols: int, rows: int) -> int:
    """Take a picture (PNG bytes or a PIL image) for a cols x rows spot;
    returns its id for the marker functions. Nothing is drawn yet."""
    image = png if hasattr(png, "size") else Image.open(io.BytesIO(png))
    image = image.convert("RGB")
    image.load()
    image_id = new_id()
    cols = max(1, min(int(cols), MAX_CELLS))
    rows = max(1, min(int(rows), MAX_CELLS))
    with _lock:
        _images[image_id] = Picture(image_id, image, cols, rows, _corner_colour(image))
    return image_id


def picture(image_id: int) -> Picture | None:
    return _images.get(image_id)


def delete(image_id: int) -> None:
    with _lock:
        _images.pop(image_id, None)
    OVERLAY.forget(image_id)


def delete_all() -> None:
    with _lock:
        ids = list(_images)
        _images.clear()
    for image_id in ids:
        OVERLAY.forget(image_id)


# ------------------------------------------------------------------ markers
def _hex(colour: tuple[int, int, int]) -> str:
    return "#{:02x}{:02x}{:02x}".format(*colour)


def marker_style(image_id: int, row: int, first: int) -> Style:
    pic = _images.get(image_id)
    background = _hex(pic.background) if pic else "#000000"
    return Style(bgcolor=background, meta={META: image_id, "r": row, "c": first})


def placeholder_span(image_id: int, row: int, first: int, last: int) -> Text:
    """Columns `first` up to (not including) `last` of one row of an image."""
    row = max(0, min(row, MAX_CELLS - 1))
    first, last = max(0, first), min(last, MAX_CELLS)
    return Text(MARKER * max(0, last - first), style=marker_style(image_id, row, first), end="")


def placeholder_rows(image_id: int, cols: int, rows: int) -> list[Text]:
    cols = max(1, min(cols, MAX_CELLS))
    rows = max(1, min(rows, MAX_CELLS))
    return [placeholder_span(image_id, row, 0, cols) for row in range(rows)]


def placeholder_text(image_id: int, cols: int, rows: int) -> Text:
    text = Text(no_wrap=True, overflow="crop", end="")
    for index, row in enumerate(placeholder_rows(image_id, cols, rows)):
        if index:
            text.append("\n")
        text.append_text(row)
    return text


class Canvas:
    """One spot on screen that shows a changing image (a live graph). The
    frame before the current one is kept until the screen has moved on."""

    KEEP = 2

    def __init__(self) -> None:
        self._ids: list[int] = []
        self.size: tuple[int, int] = (0, 0)

    def upload(self, png, cols: int, rows: int) -> int:
        image_id = show(png, cols, rows)
        self._ids.append(image_id)
        while len(self._ids) > self.KEEP:
            delete(self._ids.pop(0))
        self.size = (cols, rows)
        return image_id

    def show(self, png, cols: int, rows: int) -> Text:
        return placeholder_text(self.upload(png, cols, rows), cols, rows)

    def clear(self) -> None:
        while self._ids:
            delete(self._ids.pop())


# ------------------------------------------------------------------ encoding
_TABLES: dict[tuple[int, int], bytes] = {}
_RUN = re.compile(rb"(.)\1{3,}")


def _table(colour: int, bit: int) -> bytes:
    """bytes.translate table: `colour` -> 1 << bit, every other byte -> 0."""
    table = _TABLES.get((colour, bit))
    if table is None:
        raw = bytearray(256)
        raw[colour] = 1 << bit
        table = _TABLES[(colour, bit)] = bytes(raw)
    return table


def _runs(match) -> bytes:
    run = match.group(0)
    return b"!%d%c" % (len(run), run[0])


def _not_colour(image, colour: tuple[int, int, int]):
    """An 'L' mask: 0 where `image` is exactly `colour`, 255 elsewhere."""
    from PIL import ImageChops

    diff = ImageChops.difference(image, Image.new("RGB", image.size, colour))
    r, g, b = (band.point(lambda v: 255 if v else 0) for band in diff.split())
    return ImageChops.lighter(ImageChops.lighter(r, g), b)


def _packed(image) -> memoryview:
    """Each pixel of an RGB image as one 32-bit number (RGBX bytes), so a
    whole image can be looked up pixel by pixel without Image.getdata."""
    return memoryview(image.convert("RGBX").tobytes()).cast("I")


def _indexed(image, mask=None):
    """(palette-index bytes, palette) with SKIP wherever `mask` is 0."""
    if image.mode != "RGB":
        image = image.convert("RGB")
    colours = image.getcolors(MAX_COLOURS)
    if colours is not None:
        # Few enough colours to keep them all, exactly.
        palette = [tuple(c[:3]) for _count, c in colours]
        flat = bytes(v for c in palette for v in c)
        keys = _packed(Image.frombytes("RGB", (len(palette), 1), flat))
        lookup = {key: index for index, key in enumerate(keys)}
        data = bytes(map(lookup.__getitem__, _packed(image)))
    else:
        indexed = image.quantize(colors=MAX_COLOURS, method=Image.Quantize.FASTOCTREE,
                                 dither=Image.Dither.NONE)
        data = indexed.tobytes()
        raw = indexed.getpalette() or []
        palette = [tuple(raw[i:i + 3]) for i in range(0, len(raw), 3)]
    if mask is not None:
        holes = mask.point(lambda v: 255 if v == 0 else 0, "L")
        layer = Image.frombytes("L", image.size, data)
        layer.paste(SKIP, (0, 0, image.width, image.height), holes)
        data = layer.tobytes()
    return data, palette


def _compress(line: bytes) -> bytes:
    """Runs of four or more of a sixel as !<count><sixel>."""
    body = line.lstrip(b"?")
    lead = len(line) - len(body)
    if lead >= 4:
        return b"!%d?" % lead + _RUN.sub(_runs, body)
    return _RUN.sub(_runs, line)


def encode(image, mask=None, clear: tuple[int, int, int] | None = None) -> str:
    """A whole Sixel image (DCS … ST) for a PIL image. Pixels are left unset
    — what is on the screen there shows through — where `mask` ('L', same
    size) is 0, and wherever the image is exactly the colour `clear` (the
    background the marker cells under the image already show)."""
    width, height = image.size
    if image.mode != "RGB":
        image = image.convert("RGB")
    if clear is not None:
        from PIL import ImageChops

        keep = _not_colour(image, clear)
        mask = keep if mask is None else ImageChops.darker(mask, keep)
    data, palette = _indexed(image, mask)
    used = sorted(set(data) - {SKIP})
    out = [f'\x1bP0;1;0q"1;1;{width};{height}']
    for index in used:
        r, g, b = (palette[index] + (0, 0, 0))[:3] if index < len(palette) else (0, 0, 0)
        out.append(f"#{index};2;{round(r * 100 / 255)};{round(g * 100 / 255)};"
                   f"{round(b * 100 / 255)}")
    body = bytearray()
    offset = int.from_bytes(b"\x3f" * width, "big")
    for top in range(0, height, 6):
        rows = [data[(top + k) * width:(top + k + 1) * width]
                for k in range(min(6, height - top))]
        present = set(b"".join(rows))
        present.discard(SKIP)
        first = True
        for colour in sorted(present):
            bits = 0
            for k, row in enumerate(rows):
                bits |= int.from_bytes(row.translate(_table(colour, k)), "big")
            line = (bits + offset).to_bytes(width, "big").rstrip(b"?")
            if not line:
                continue
            if not first:
                body += b"$"
            first = False
            body += b"#%d" % colour
            body += _compress(line)
        if top + 6 < height:
            body += b"-"
    out.append(body.decode("ascii"))
    out.append("\x1b\\")
    return "".join(out)


# ------------------------------------------------------------------ overlay
@dataclass
class Placement:
    """Where an image was last drawn, and through which cells."""

    widget: object
    region: tuple[int, int, int, int]      # the widget's region then
    left: int                              # screen column of the image's column 0
    top: int                               # screen row of the image's row 0
    cells: set = field(default_factory=set)    # (col, row) the image owns on screen


def _marker(segment) -> dict | None:
    style = segment.style
    if style is None or style._meta is None:
        return None
    try:
        meta = style.meta
    except Exception:
        return None
    return meta if META in meta else None


def _touched_in_strip(strip, x: int, y: int, x1: int, x2: int, found: dict) -> None:
    """Markers among the cells x1 up to (not including) x2 of a strip that
    starts at column x."""
    for segment in strip:
        width = segment.cell_length
        if width and x < x2 and x + width > x1:
            meta = _marker(segment)
            if meta is not None and meta[META] not in found:
                found[meta[META]] = (max(x, x1), y, meta.get("r", 0))
        x += width


def touched(update) -> dict[int, tuple[int, int, int]]:
    """{image id: (x, y, image row)} for every image with a marker cell in
    this frame — cells Textual is overwriting right now. The cells counted
    are the ones Textual's render_segments writes for the update."""
    found: dict[int, tuple[int, int, int]] = {}
    strips = getattr(update, "strips", None)
    if strips is not None:                               # a whole-screen frame
        region = update.region
        for y, line in enumerate(strips, region.y):
            x = region.x
            for strip in line:
                if strip is None:
                    continue
                end = x + strip.cell_length
                _touched_in_strip(strip, x, y, x, end, found)
                x = end
        return found
    chops, spans = getattr(update, "chops", None), getattr(update, "spans", None)
    if chops is None or not spans:
        return found
    for y, x1, x2 in spans:
        if not 0 <= y < len(chops):
            continue
        for x, strip in chops[y].items():
            if strip is None:
                continue
            end = x + strip.cell_length
            # As ChopsUpdate.render_segments: a chop that reaches into the
            # span is written from its own start up to the span's end.
            if x > x2 or end <= x1:
                continue
            _touched_in_strip(strip, x, y, x, min(end, x2), found)
    return found


class Overlay:
    """Redraws images Textual has written over, right after each frame."""

    def __init__(self) -> None:
        self.placements: dict[int, Placement] = {}
        # An image laid over another (DASH's breath over the banner):
        # base id -> (image id, col, row); drawn again whenever the base is.
        self.layers: dict[int, tuple[int, int, int]] = {}
        self._cache: OrderedDict = OrderedDict()
        self._bottom: int | None = None          # screen rows at the last frame

    def forget(self, image_id: int) -> None:
        self.placements.pop(image_id, None)
        self.layers.pop(image_id, None)
        for base, (layer, _col, _row) in list(self.layers.items()):
            if layer == image_id:
                del self.layers[base]

    def reset(self) -> None:
        self.placements.clear()
        self.layers.clear()
        self._cache.clear()

    # -------------------------------------------------------- per frame
    def frame(self, screen, update) -> str:
        """The escape sequences that put back every image this frame
        (a Textual LayoutUpdate or ChopsUpdate) wrote over."""
        out = []
        self._bottom = screen.size.height
        for image_id, (x, y, row) in touched(update).items():
            pic = _images.get(image_id)
            if pic is None:
                continue
            try:
                sequence = self.draw(screen, pic, x, y, row)
                layer = self.layers.get(image_id) if sequence else None
                if layer is not None:
                    sequence += self.draw_over(screen, image_id, *layer)
            except Exception:
                sequence = ""
            if sequence:
                out.append(sequence)
        return "".join(out)

    def draw(self, screen, pic: Picture, x: int, y: int, row: int) -> str:
        """Find the image's cells on screen from one of its marker cells at
        (x, y), and the sequence that draws it there."""
        widget, region = screen.get_widget_at(x, y)
        placement = self._place(screen, widget, region, pic, y - row)
        if placement is None:
            self.forget(pic.image_id)
            return ""
        self.placements[pic.image_id] = placement
        return self._sequence(pic, placement.left, placement.top, placement.cells, clear=True)

    def _place(self, screen, widget, region, pic: Picture, top: int) -> Placement | None:
        from textual.geometry import Region

        cells: set[tuple[int, int]] = set()
        left = None
        width, height = screen.size.width, screen.size.height
        try:
            visible = screen.find_widget(widget).visible_region
        except Exception:
            visible = region
        for image_row in range(pic.rows):
            sy = top + image_row
            if not (region.y <= sy < region.bottom) or not (0 <= sy < height - 1):
                continue
            if not (visible.y <= sy < visible.bottom):
                continue
            lines = widget.render_lines(Region(0, sy - region.y, region.width, 1))
            if not lines:
                continue
            row_left = None
            wx = 0
            for segment in lines[0]:
                length = segment.cell_length
                meta = _marker(segment) if length else None
                if meta is not None and meta[META] == pic.image_id and meta.get("r") == image_row:
                    if row_left is None:
                        row_left = region.x + wx - int(meta.get("c", 0))
                        left = row_left if left is None else left
                    for sx in range(region.x + wx, region.x + wx + length):
                        col = sx - left
                        if (0 <= col < pic.cols and 0 <= sx < width
                                and visible.x <= sx < visible.right):
                            cells.add((col, image_row))
                wx += length
        if left is None or not cells:
            return None
        cells = self._uncovered(screen, widget, left, top, cells)
        if not cells:
            return None
        return Placement(widget, tuple(region), left, top, cells)

    @staticmethod
    def _uncovered(screen, widget, left: int, top: int, cells: set) -> set:
        """The cells where nothing is drawn on top of `widget`."""
        rows: dict[int, list[int]] = {}
        for col, row in cells:
            rows.setdefault(row, []).append(col)
        keep = set()
        layers = getattr(getattr(screen, "_compositor", None), "layers_visible", None)
        for row, cols in rows.items():
            sy = top + row
            covers = None
            if layers is not None and 0 <= sy < len(layers):
                covers = []
                for other, cropped, _region in layers[sy]:
                    if other is widget:
                        break
                    if getattr(other, "visible", True) and cropped.y <= sy < cropped.bottom:
                        covers.append((cropped.x, cropped.right))
                else:
                    covers = None             # not found in this row: ask per cell
            for col in cols:
                sx = left + col
                if covers is not None:
                    if not any(a <= sx < b for a, b in covers):
                        keep.add((col, row))
                    continue
                try:
                    if screen.get_widget_at(sx, sy)[0] is widget:
                        keep.add((col, row))
                except Exception:
                    pass
        return keep

    # -------------------------------------------------------- drawing
    def _sequence(self, pic: Picture, left: int, top: int, cells: set,
                  clear: bool = False) -> str:
        """Cursor to the image's first visible cell, the Sixel image of its
        visible cells, cursor back. With `clear`, pixels in the image's
        background colour are left unset: the marker cells under them are
        already that colour, and the image is smaller to send."""
        cols = [c for c, _r in cells]
        rows = [r for _c, r in cells]
        c0, c1, r0, r1 = min(cols), max(cols) + 1, min(rows), max(rows) + 1
        full = len(cells) == (c1 - c0) * (r1 - r0)
        # A terminal leaves the cursor under an image's last six-pixel band.
        # Next to the bottom row, a band that overhangs the image could push
        # the cursor off the screen and scroll it — so there the image is
        # cut to whole bands.
        trim = self._bottom is not None and top + r1 >= self._bottom - 1
        key = (pic.image_id, c0, r0, c1, r1, None if full else frozenset(cells), clear, trim)
        sixel = self._cache.get(key)
        if sixel is None:
            sixel = self._encode(pic, c0, r0, c1, r1, None if full else cells, clear, trim)
            self._cache[key] = sixel
            while len(self._cache) > CACHE:
                self._cache.popitem(last=False)
        else:
            self._cache.move_to_end(key)
        if not sixel:
            return ""
        return f"\x1b7\x1b[{top + r0 + 1};{left + c0 + 1}H{sixel}\x1b8"

    @staticmethod
    def _encode(pic: Picture, c0: int, r0: int, c1: int, r1: int, cells,
                clear: bool = False, trim: bool = False) -> str:
        cw, ch = pic.cell
        box = (c0 * cw, r0 * ch, c1 * cw, r1 * ch)
        if trim:
            height = (box[3] - box[1]) // 6 * 6
            if height <= 0:
                return ""
            box = (box[0], box[1], box[2], box[1] + height)
        crop = pic.image.crop(box)
        mask = None
        if cells is not None:
            mask = Image.new("L", crop.size, 0)
            for col, row in cells:
                mask.paste(255, ((col - c0) * cw, (row - r0) * ch,
                                 (col - c0 + 1) * cw, (row - r0 + 1) * ch))
        return encode(crop, mask, clear=pic.background if clear else None)

    # -------------------------------------------------------- live layers
    def draw_over(self, screen, base_id: int, image_id: int, col: int, row: int) -> str:
        """The sequence that lays `image_id` over the image `base_id` as last
        drawn, its top-left at the base's (col, row) — DASH's breath, one
        frame at a time, without Textual repainting the banner. Remembered,
        so the layer comes back whenever the base is drawn again. '' when
        the base isn't on screen as it was."""
        self.layers[base_id] = (image_id, col, row)
        base = self.placements.get(base_id)
        pic = _images.get(image_id)
        if base is None or pic is None:
            return ""
        widget = base.widget
        try:
            if getattr(widget, "screen", None) is not screen or not widget.is_on_screen:
                return ""
            if screen.app.screen is not screen:          # a dialog is on top
                return ""
            if tuple(screen.find_widget(widget).region) != base.region:
                return ""
        except Exception:
            return ""
        cells = {(c - col, r - row) for c, r in base.cells
                 if col <= c < col + pic.cols and row <= r < row + pic.rows}
        if not cells:
            return ""
        cells = self._uncovered(screen, widget, base.left + col, base.top + row, cells)
        if not cells:
            return ""
        return self._sequence(pic, base.left + col, base.top + row, cells)


OVERLAY = Overlay()


def overlay(screen, update) -> str:
    return OVERLAY.frame(screen, update)


def draw_over(screen, base_id: int, image_id: int, col: int, row: int) -> bool:
    """Draw `image_id` over the image `base_id` now; False when it couldn't."""
    sequence = OVERLAY.draw_over(screen, base_id, image_id, col, row)
    if sequence:
        _send(sequence)
    return bool(sequence)


__all__ = ["Canvas", "Overlay", "OVERLAY", "Picture", "set_writer", "active", "show",
           "delete", "delete_all", "picture", "placeholder_text", "placeholder_rows",
           "placeholder_span", "encode", "overlay", "draw_over", "touched", "new_id",
           "marker_style", "META", "MARKER"]
