"""Painting the window: the cell grid drawn with Pillow, then the CRT.

Every cell is drawn as a small tile — its background, then its character
(from glyphs.py for box drawing, blocks, sextants and braille, from the
fonts for everything else) in its foreground colour, with underline and
strike-through — and tiles are cached, so a repaint is mostly pasting.
Kitty placeholder cells show their slice of the uploaded image instead,
scaled the way kitty scales it, so netzilla's pixel graphs and the DASH
banner appear exactly where they do in Ghostty.

The CRT is laid over the finished cells: a soft phosphor glow around
everything lit, and the same fine scanlines the banner has in Ghostty (a
dark line every third pixel row), across the whole window. Only the part
of the window that changed is redrawn.
"""

from __future__ import annotations

from collections import OrderedDict

from PIL import Image, ImageChops, ImageDraw, ImageFilter

from ..graphics.kitty import DIACRITICS, PLACEHOLDER
from . import glyphs
from .fonts import FontSet
from .screen import (BOLD, CONCEAL, DIM, ITALIC, OVERLINE, REVERSE, STRIKE, UNDERLINE,
                     UNDERLINE2, Screen, char_width)

_DIACRITIC = {char: index for index, char in enumerate(DIACRITICS)}
TILE_CACHE = 30_000
# The banner's own scanlines (graphics/plot.py add_scanlines): black at
# alpha 46 on every third pixel row, starting with the second.
SCAN_EVERY = 3
SCAN_ROW = 1
SCAN_LEVEL = 255 - 46


def rgb(value: int) -> tuple[int, int, int]:
    return (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF


def mix(a: int, b: int, t: float) -> int:
    ar, ag, ab = rgb(a)
    br, bg, bb = rgb(b)
    return ((round(ar + (br - ar) * t) << 16) | (round(ag + (bg - ag) * t) << 8)
            | round(ab + (bb - ab) * t))


class Painter:
    """Draws a Screen into `frame` (an RGB image), CRT included."""

    def __init__(self, fonts: FontSet, crt: bool = True,
                 default_fg: int = 0xC8C8C8, default_bg: int = 0x000000) -> None:
        self.fonts = fonts
        self.crt = crt
        self.default_fg = default_fg
        self.default_bg = default_bg
        self.cols = self.rows = 0
        self.base: Image.Image | None = None      # the cells
        self.frame: Image.Image | None = None     # what the window shows
        self._scan: Image.Image | None = None
        self._tiles: OrderedDict = OrderedDict()
        self._scaled: dict = {}
        self._image_rows: dict[int, set[int]] = {}   # image id -> rows showing it
        self._row_images: dict[int, set[int]] = {}   # row -> image ids on it
        # What each row showed when it was last painted (None: repaint it
        # whatever it holds), so a row Textual rewrites unchanged costs nothing.
        self._shown: list = []

    # ------------------------------------------------------------ setup
    @property
    def cell(self) -> tuple[int, int]:
        return self.fonts.cell

    def set_fonts(self, fonts: FontSet) -> None:
        self.fonts = fonts
        self._tiles.clear()
        self._scaled.clear()
        self.cols = self.rows = 0               # the next paint resizes

    def set_crt(self, on: bool) -> None:
        self.crt = bool(on)
        self.cols = self.rows = 0

    def _resize(self, cols: int, rows: int) -> None:
        cw, ch = self.cell
        size = (max(1, cols * cw), max(1, rows * ch))
        self.cols, self.rows = cols, rows
        self.base = Image.new("RGB", size, rgb(self.default_bg))
        self.frame = Image.new("RGB", size, rgb(self.default_bg)) if self.crt else self.base
        self._scan = None
        if self.crt:
            column = Image.new("L", (1, size[1]), 255)
            for y in range(SCAN_ROW, size[1], SCAN_EVERY):
                column.putpixel((0, y), SCAN_LEVEL)
            self._scan = column.resize(size, Image.NEAREST).convert("RGB")
        self._image_rows.clear()
        self._row_images.clear()
        self._shown = [None] * rows

    @property
    def size(self) -> tuple[int, int]:
        return self.base.size if self.base is not None else (0, 0)

    # ------------------------------------------------------------ painting
    def images_changed(self, screen: Screen, image_ids=None) -> None:
        """Images were uploaded or deleted: repaint the rows showing them."""
        ids = self._image_rows.keys() if image_ids is None else image_ids
        for image_id in list(ids):
            for y in self._image_rows.get(image_id, ()):
                if y < screen.rows:
                    screen._mark(y, 0, screen.cols - 1)
                    if y < len(self._shown):
                        self._shown[y] = None

    def paint(self, screen: Screen) -> list[tuple[int, int, int, int]]:
        """Bring `frame` up to date; returns the pixel boxes that changed."""
        everything, dirty = screen.take_dirty()
        if (screen.cols, screen.rows) != (self.cols, self.rows) or self.base is None:
            self._resize(screen.cols, screen.rows)
            everything = True
        if everything:
            dirty = {y: [0, screen.cols - 1] for y in range(screen.rows)}
        if not dirty:
            return []
        painted = {}
        shown = self._shown
        for y, (first, last) in dirty.items():
            if y >= screen.rows:
                continue
            chars, styles = screen.chars[y], screen.styles[y]
            before = None if everything else shown[y]
            if before is not None:
                # Only the cells that differ from what is on show.
                old_chars, old_styles = before
                last = min(last, screen.cols - 1)
                while first <= last and chars[first] == old_chars[first] \
                        and styles[first] == old_styles[first]:
                    first += 1
                if first > last:
                    continue
                while chars[last] == old_chars[last] and styles[last] == old_styles[last]:
                    last -= 1
            first = self._paint_row(screen, y, first, last)
            painted[y] = [first, last]
            shown[y] = (list(chars), list(styles))
        if not painted:
            return []
        cw, ch = self.cell
        boxes = []
        for top, bottom, first, last in _bands(painted):
            boxes.append((first * cw, top * ch, (last + 1) * cw, (bottom + 1) * ch))
        if everything:
            boxes = [(0, 0) + self.size]
        if self.crt:
            for box in _merge(boxes):
                self._crt(box)
            return _merge([self._reach(box) for box in boxes])
        return boxes

    def _paint_row(self, screen: Screen, y: int, first: int, last: int) -> int:
        """Paint cells first to last of row y; returns the first cell painted."""
        chars, styles = screen.chars[y], screen.styles[y]
        cols = screen.cols
        # Start on a wide character's first half, never its second.
        while first > 0 and chars[first] == "":
            first -= 1
        cw, ch = self.cell
        base = self.base
        top = y * ch
        old_images = self._row_images.pop(y, set())
        for image_id in old_images:
            rows = self._image_rows.get(image_id)
            if rows is not None:
                rows.discard(y)
                if not rows:
                    del self._image_rows[image_id]
        # Images on the parts of the row not being repainted stay.
        images_here: set[int] = set()
        if first > 0 or last < cols - 1:
            for x in list(range(0, first)) + list(range(last + 1, cols)):
                text = chars[x]
                if text[:1] == PLACEHOLDER:
                    images_here.add(styles[x].fg or 0)
        x = first
        while x <= last and x < cols:
            text = chars[x]
            style = styles[x]
            if text[:1] == PLACEHOLDER:
                x = self._paint_placeholders(screen, y, x, last, images_here)
                continue
            width = 2 if (x + 1 < cols and chars[x + 1] == "") else 1
            if text == "":
                text, width = " ", 1
            tile = self._tile(text or " ", style, width)
            base.paste(tile, (x * cw, top))
            x += width
        if images_here:
            self._row_images[y] = images_here
            for image_id in images_here:
                self._image_rows.setdefault(image_id, set()).add(y)
        return first

    # ------------------------------------------------------------ text cells
    def _colours(self, style) -> tuple[int, int]:
        fg = self.default_fg if style.fg is None else style.fg
        bg = self.default_bg if style.bg is None else style.bg
        flags = style.flags
        if flags & REVERSE:
            fg, bg = bg, fg
        if flags & DIM:
            fg = mix(fg, bg, 0.5)
        if flags & CONCEAL:
            fg = bg
        return fg, bg

    def _tile(self, text: str, style, width: int) -> Image.Image:
        fg, bg = self._colours(style)
        flags = style.flags & (BOLD | ITALIC | UNDERLINE | UNDERLINE2 | STRIKE | OVERLINE)
        key = (text, fg, bg, flags, width)
        tile = self._tiles.get(key)
        if tile is not None:
            self._tiles.move_to_end(key)
            return tile
        tile = self._draw_tile(text, fg, bg, flags, width)
        self._tiles[key] = tile
        if len(self._tiles) > TILE_CACHE:
            self._tiles.popitem(last=False)
        return tile

    def _draw_tile(self, text: str, fg: int, bg: int, flags: int, width: int) -> Image.Image:
        cw, ch = self.cell
        w = cw * width
        tile = Image.new("RGB", (w, ch), rgb(bg))
        colour = rgb(fg)
        base = text[0]
        if text.strip():
            if len(text) == 1 and glyphs.drawn(base) and width == 1:
                tile.paste(colour, (0, 0), glyphs.mask(base, cw, ch))
            else:
                self._glyph(tile, text, colour, flags, w)
        fonts = self.fonts
        line = fonts.line_px
        draw = None
        if flags & (UNDERLINE | UNDERLINE2 | STRIKE | OVERLINE):
            draw = ImageDraw.Draw(tile)
        if flags & (UNDERLINE | UNDERLINE2):
            y = fonts.underline_y
            draw.rectangle([0, y, w - 1, min(ch - 1, y + line - 1)], fill=colour)
            if flags & UNDERLINE2:
                y2 = min(ch - line, y + 2 * line)
                draw.rectangle([0, y2, w - 1, y2 + line - 1], fill=colour)
        if flags & STRIKE:
            y = max(0, fonts.baseline - round(fonts.px * 0.3))
            draw.rectangle([0, y, w - 1, y + line - 1], fill=colour)
        if flags & OVERLINE:
            draw.rectangle([0, 0, w - 1, line - 1], fill=colour)
        return tile

    def _glyph(self, tile: Image.Image, text: str, colour, flags: int, w: int) -> None:
        cw, ch = self.cell
        fonts = self.fonts
        bold = bool(flags & BOLD)
        font, in_colour = fonts.pick(text, bold)
        if in_colour:
            self._emoji(tile, text, font, w)
            return
        mask = Image.new("L", (w, ch), 0)
        draw = ImageDraw.Draw(mask)
        try:
            left, _top, right, _bottom = draw.textbbox((0, fonts.baseline), text, font=font,
                                                       anchor="ls")
        except Exception:
            left, right = 0, w
        x = 0
        if right - left > w and right > left and font is not fonts.regular \
                and font is not fonts.bold:
            # A fallback glyph wider than its cells: drawn smaller, as
            # terminals constrain symbols to the cell.
            try:
                font = font.font_variant(size=max(4, int(font.size * w / (right - left))))
                left, _t, right, _b = draw.textbbox((0, fonts.baseline), text, font=font,
                                                    anchor="ls")
            except Exception:
                pass
        if font is not fonts.regular and font is not fonts.bold:
            x = (w - (right - left)) // 2 - left      # fallbacks are centred
        try:
            draw.text((x, fonts.baseline), text, font=font, fill=255, anchor="ls")
            if bold and (fonts.synthetic_bold or font is not fonts.bold):
                draw.text((x + 1, fonts.baseline), text, font=font, fill=255, anchor="ls")
        except Exception:
            return
        if flags & ITALIC:
            mask = mask.transform(mask.size, Image.AFFINE,
                                  (1, 0.2, -0.2 * fonts.baseline, 0, 1, 0),
                                  resample=Image.BILINEAR)
        tile.paste(colour, (0, 0), mask)

    def _emoji(self, tile: Image.Image, text: str, font, w: int) -> None:
        ch = self.cell[1]
        size = int(getattr(font, "size", ch)) or ch
        canvas = Image.new("RGBA", (size * 2, size * 2), (0, 0, 0, 0))
        try:
            ImageDraw.Draw(canvas).text((size // 2, size // 2), text, font=font,
                                        embedded_color=True)
        except Exception:
            return
        box = canvas.getbbox()
        if not box:
            return
        picture = canvas.crop(box)
        scale = min(w / picture.width, ch / picture.height)
        target = (max(1, round(picture.width * scale)), max(1, round(picture.height * scale)))
        picture = picture.resize(target, Image.LANCZOS)
        tile.paste(picture, ((w - target[0]) // 2, (ch - target[1]) // 2), picture)

    # ------------------------------------------------------------ images
    def _placed(self, screen: Screen, image_id: int):
        """The image scaled into its placement's cells, as kitty fits it
        (aspect kept, centred); None when there is no such image."""
        image = screen.images.get(image_id)
        if image is None:
            return None
        cw, ch = self.cell
        cols = image.cols or max(1, round(image.image.width / cw))
        rows = image.rows or max(1, round(image.image.height / ch))
        key = (image_id, image.serial, cols, rows, cw, ch)
        placed = self._scaled.get(key)
        if placed is not None:
            return placed
        box_w, box_h = cols * cw, rows * ch
        picture = image.image
        if picture.size != (box_w, box_h):
            scale = min(box_w / picture.width, box_h / picture.height)
            size = (max(1, round(picture.width * scale)), max(1, round(picture.height * scale)))
            resized = picture.resize(size, Image.LANCZOS)
            picture = Image.new("RGBA", (box_w, box_h), (0, 0, 0, 0))
            picture.paste(resized, ((box_w - size[0]) // 2, (box_h - size[1]) // 2))
        if len(self._scaled) > 256:
            self._scaled.clear()
        self._scaled[key] = picture
        return picture

    def _paint_placeholders(self, screen: Screen, y: int, x: int, last: int,
                            images_here: set) -> int:
        """Paint a run of placeholder cells from x; returns the next column."""
        chars, styles = screen.chars[y], screen.styles[y]
        cw, ch = self.cell
        cols = screen.cols
        prev_row = prev_col = prev_id = None
        run_start = x
        run_id = run_row = run_col = None
        run_bg = None
        while x <= last and x < cols and chars[x][:1] == PLACEHOLDER:
            text, style = chars[x], styles[x]
            row = _DIACRITIC.get(text[1]) if len(text) > 1 else None
            col = _DIACRITIC.get(text[2]) if len(text) > 2 else None
            high = _DIACRITIC.get(text[3]) if len(text) > 3 else None
            image_id = (style.fg or 0) | ((high or 0) << 24)
            if row is None:
                row = prev_row if prev_id == image_id and prev_row is not None else 0
            if col is None:
                col = prev_col + 1 if prev_id == image_id and prev_col is not None else 0
            _fg, bg = self._colours(style._replace(fg=None, flags=0))
            continues = (run_id == image_id and run_row == row and run_bg == bg
                         and col == run_col + (x - run_start))
            if not continues:
                if run_id is not None:
                    self._image_strip(screen, y, run_start, x, run_id, run_row, run_col, run_bg)
                run_start, run_id, run_row, run_col, run_bg = x, image_id, row, col, bg
            images_here.add(style.fg or 0)
            prev_row, prev_col, prev_id = row, col, image_id
            x += 1
        if run_id is not None:
            self._image_strip(screen, y, run_start, x, run_id, run_row, run_col, run_bg)
        return x

    def _image_strip(self, screen: Screen, y: int, start: int, end: int, image_id: int,
                     row: int, col: int, bg: int) -> None:
        cw, ch = self.cell
        box = (start * cw, y * ch, end * cw, (y + 1) * ch)
        self.base.paste(rgb(bg), box)
        picture = self._placed(screen, image_id)
        if picture is None:
            return
        piece = picture.crop((col * cw, row * ch, (col + end - start) * cw, (row + 1) * ch))
        self.base.paste(piece, box[:2], piece)

    # ------------------------------------------------------------ CRT
    @property
    def glow_sigma(self) -> float:
        return max(2.0, self.cell[1] * 0.28)

    def _reach(self, box):
        """`box` grown by how far its glow spreads, inside the frame."""
        grow = int(self.glow_sigma * 3) + 2
        w, h = self.size
        x0, y0, x1, y1 = box
        return max(0, x0 - grow), max(0, y0 - grow), min(w, x1 + grow), min(h, y1 + grow)

    def _crt(self, box) -> None:
        """Glow and scanlines for the part of the frame `box` affects."""
        sigma = self.glow_sigma
        scale = max(2, min(GLOW_SCALE, int(sigma)))
        inner = self._reach(box)
        grow = int(sigma * 3) + 2
        w, h = self.size
        ox0 = max(0, (inner[0] - grow) // scale * scale)
        oy0 = max(0, (inner[1] - grow) // scale * scale)
        ox1 = min(w, inner[2] + grow)
        oy1 = min(h, inner[3] + grow)
        source = self.base.crop((ox0, oy0, ox1, oy1))
        lit = source.point(_GLOW_LUT)
        small = lit.reduce(scale) if min(lit.size) >= scale else lit
        glow = small.filter(ImageFilter.GaussianBlur(sigma / scale)).resize(
            source.size, Image.BILINEAR)
        out = ImageChops.screen(source, glow)
        out = ImageChops.multiply(out, self._scan.crop((ox0, oy0, ox1, oy1)))
        ix0, iy0, ix1, iy1 = inner
        self.frame.paste(out.crop((ix0 - ox0, iy0 - oy0, ix1 - ox0, iy1 - oy0)), (ix0, iy0))


# What of a pixel glows: nothing below a dim threshold, then a soft rise —
# so lit text and graphs bloom and the theme's dark backgrounds don't.
GLOW_FLOOR = 48
GLOW_SCALE = 4          # the glow is blurred at a quarter of the size: soft anyway, 2.5x cheaper
GLOW_STRENGTH = 0.55
_GLOW_LUT = [0 if v < GLOW_FLOOR else min(255, round((v - GLOW_FLOOR) * GLOW_STRENGTH))
             for v in range(256)] * 3


def _bands(dirty: dict) -> list[tuple[int, int, int, int]]:
    """Consecutive dirty rows grouped: (top, bottom, first col, last col)."""
    out = []
    for y in sorted(dirty):
        first, last = dirty[y]
        if out and out[-1][1] == y - 1:
            top, _bottom, f, l_ = out[-1]
            out[-1] = (top, y, min(f, first), max(l_, last))
        else:
            out.append((y, y, first, last))
    return out


def _merge(boxes: list) -> list:
    """Overlapping boxes joined, so no part of the frame is redone twice."""
    boxes = sorted(boxes)
    merged: list = []
    for box in boxes:
        for index, other in enumerate(merged):
            if not (box[2] <= other[0] or other[2] <= box[0] or box[3] <= other[1]
                    or other[3] <= box[1]):
                merged[index] = (min(box[0], other[0]), min(box[1], other[1]),
                                 max(box[2], other[2]), max(box[3], other[3]))
                break
        else:
            merged.append(box)
    if len(merged) != len(boxes):
        return _merge(merged)
    return merged


def screenshot(screen: Screen, fonts: FontSet, crt: bool = True,
               default_fg: int = 0xC8C8C8, default_bg: int = 0) -> Image.Image:
    """The whole screen as one picture (tests, docs, `--screenshot`)."""
    painter = Painter(fonts, crt=crt, default_fg=default_fg, default_bg=default_bg)
    screen.mark_all()
    painter.paint(screen)
    return painter.frame.copy()


__all__ = ["Painter", "screenshot", "rgb", "mix", "char_width"]
