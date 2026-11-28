"""The characters the window draws itself instead of taking from a font.

Box drawing (U+2500-U+257F), block elements (U+2580-U+259F), sextants
(U+1FB00-U+1FB3B) and braille (U+2800-U+28FF) are drawn from the cell's own
size, the way Ghostty and kitty draw them: lines meet exactly at cell edges,
blocks tile without seams, and the DASH banner's sextant pictures and the
braille spectrum look the same at any text size. Fonts only supply letters.

Every function returns an 8-bit mask ("L" image, 255 = foreground) of one
cell, w x h pixels; the painter colours it with the cell's foreground over
its background.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache

from PIL import Image, ImageDraw

BOX = range(0x2500, 0x2580)
BLOCKS = range(0x2580, 0x25A0)
SEXTANTS = range(0x1FB00, 0x1FB3C)
BRAILLE = range(0x2800, 0x2900)

LIGHT, HEAVY, DOUBLE = 1, 2, 3
_WEIGHTS = {"LIGHT": LIGHT, "SINGLE": LIGHT, "HEAVY": HEAVY, "DOUBLE": DOUBLE}
_DIRECTIONS = {"UP": "U", "DOWN": "D", "LEFT": "L", "RIGHT": "R",
               "VERTICAL": "UD", "HORIZONTAL": "LR"}
_SUPER = 4                    # supersampling for arcs, diagonals and dots


def drawn(char: str) -> bool:
    """True when the window draws `char` itself."""
    if len(char) != 1:
        return False
    code = ord(char)
    return code in BOX or code in BLOCKS or code in SEXTANTS or code in BRAILLE


def thickness(cell_h: int) -> int:
    """A light line's thickness for this cell height (heavy is twice it)."""
    return max(1, round(cell_h / 20))


@lru_cache(maxsize=4096)
def mask(char: str, w: int, h: int) -> Image.Image:
    """The cell-sized mask for one of the characters drawn() accepts."""
    code = ord(char)
    if code in BLOCKS:
        return _block(code, w, h)
    if code in SEXTANTS:
        bits = code - 0x1FB00 + 1
        bits += (bits >= 21) + (bits >= 41)        # 21 and 42 are ▌ and ▐
        return _sextant(bits, w, h)
    if code in BRAILLE:
        return _braille(code - 0x2800, w, h)
    return _box(code, w, h)


# ------------------------------------------------------------------ blocks
def _rect(w: int, h: int, box, value: int = 255) -> Image.Image:
    image = Image.new("L", (w, h), 0)
    x0, y0, x1, y1 = box
    if x1 > x0 and y1 > y0:
        ImageDraw.Draw(image).rectangle([x0, y0, x1 - 1, y1 - 1], fill=value)
    return image


def _block(code: int, w: int, h: int) -> Image.Image:
    def eighths(n: int, size: int) -> int:
        return max(1, round(size * n / 8)) if n else 0

    if code == 0x2580:                                   # ▀ upper half
        return _rect(w, h, (0, 0, w, round(h / 2)))
    if 0x2581 <= code <= 0x2588:                         # ▁▂▃▄▅▆▇█ lower n/8
        top = h - eighths(code - 0x2580, h)
        return _rect(w, h, (0, top, w, h))
    if 0x2589 <= code <= 0x258F:                         # ▉▊▋▌▍▎▏ left n/8
        return _rect(w, h, (0, 0, eighths(0x2590 - code, w), h))
    if code == 0x2590:                                   # ▐ right half
        return _rect(w, h, (round(w / 2), 0, w, h))
    if 0x2591 <= code <= 0x2593:                         # ░▒▓ shades
        return Image.new("L", (w, h), (64, 128, 192)[code - 0x2591])
    if code == 0x2594:                                   # ▔ upper 1/8
        return _rect(w, h, (0, 0, w, eighths(1, h)))
    if code == 0x2595:                                   # ▕ right 1/8
        return _rect(w, h, (w - eighths(1, w), 0, w, h))
    # Quadrants ▖▗▘▙▚▛▜▝▞▟: bit 1 upper left, 2 upper right, 4 lower left,
    # 8 lower right.
    quads = {0x2596: 4, 0x2597: 8, 0x2598: 1, 0x2599: 1 | 4 | 8, 0x259A: 1 | 8,
             0x259B: 1 | 2 | 4, 0x259C: 1 | 2 | 8, 0x259D: 2, 0x259E: 2 | 4,
             0x259F: 2 | 4 | 8}[code]
    mx, my = round(w / 2), round(h / 2)
    image = Image.new("L", (w, h), 0)
    draw = ImageDraw.Draw(image)
    for bit, (x0, y0, x1, y1) in ((1, (0, 0, mx, my)), (2, (mx, 0, w, my)),
                                  (4, (0, my, mx, h)), (8, (mx, my, w, h))):
        if quads & bit and x1 > x0 and y1 > y0:
            draw.rectangle([x0, y0, x1 - 1, y1 - 1], fill=255)
    return image


def _sextant(bits: int, w: int, h: int) -> Image.Image:
    """A 2 x 3 pattern: bit 0 top-left, bit 1 top-right, bit 2 middle-left …
    bit 5 bottom-right (graphics/banner.py's order)."""
    xs = (0, round(w / 2), w)
    ys = (0, round(h / 3), round(2 * h / 3), h)
    image = Image.new("L", (w, h), 0)
    draw = ImageDraw.Draw(image)
    for index in range(6):
        if bits & (1 << index):
            col, row = index % 2, index // 2
            x0, x1, y0, y1 = xs[col], xs[col + 1], ys[row], ys[row + 1]
            if x1 > x0 and y1 > y0:
                draw.rectangle([x0, y0, x1 - 1, y1 - 1], fill=255)
    return image


def _braille(bits: int, w: int, h: int) -> Image.Image:
    """Eight round dots, 2 across and 4 down (Unicode's dot numbering)."""
    if not bits:
        return Image.new("L", (w, h), 0)
    big_w, big_h = w * _SUPER, h * _SUPER
    image = Image.new("L", (big_w, big_h), 0)
    draw = ImageDraw.Draw(image)
    step_x, step_y = big_w / 2, big_h / 4
    radius = max(_SUPER * 0.6, min(step_x, step_y) * 0.34)
    # dots 1-3 down the left, 4-6 down the right, then 7 and 8 at the bottom
    places = ((0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2), (0, 3), (1, 3))
    for index, (col, row) in enumerate(places):
        if bits & (1 << index):
            cx, cy = step_x * (col + 0.5), step_y * (row + 0.5)
            draw.ellipse([cx - radius, cy - radius, cx + radius, cy + radius], fill=255)
    return image.resize((w, h), Image.BOX)


# ------------------------------------------------------------------ box drawing
@lru_cache(maxsize=None)
def box_spec(code: int) -> tuple:
    """What a box-drawing character is made of, read from its Unicode name:
    ("lines", {"U": weight, ...}), ("dash", n, weight, vertical),
    ("arc", "DR"|"DL"|"UL"|"UR") or ("diagonal", "/"|"\\\\"|"X")."""
    name = unicodedata.name(chr(code), "").replace("BOX DRAWINGS ", "")
    words = name.split()
    if "DASH" in words:
        count = {"DOUBLE": 2, "TRIPLE": 3, "QUADRUPLE": 4}[words[1]]
        return ("dash", count, _WEIGHTS[words[0]], words[-1] == "VERTICAL")
    if "ARC" in words:
        vertical = "D" if "DOWN" in words else "U"
        horizontal = "R" if "RIGHT" in words else "L"
        return ("arc", vertical + horizontal)
    if "DIAGONAL" in words:
        if "CROSS" in words:
            return ("diagonal", "X")
        return ("diagonal", "/" if words[2] == "RIGHT" else "\\")
    arms: dict[str, int] = {}
    weight = LIGHT
    for group in name.split(" AND "):
        tokens = group.split()
        found = [_WEIGHTS[t] for t in tokens if t in _WEIGHTS]
        if found:
            weight = found[0]
        for token in tokens:
            for arm in _DIRECTIONS.get(token, ""):
                arms[arm] = weight
    return ("lines", arms)


def _box(code: int, w: int, h: int) -> Image.Image:
    spec = box_spec(code)
    t = thickness(h)
    kind = spec[0]
    if kind == "lines":
        return _lines(spec[1], w, h, t)
    if kind == "dash":
        return _dashes(spec[1], spec[2], spec[3], w, h, t)
    if kind == "arc":
        return _arc(spec[1], w, h, t)
    return _diagonal(spec[1], w, h, t)


def _lines(arms: dict, w: int, h: int, t: int) -> Image.Image:
    """Light, heavy and double lines from the centre to the edges, joined
    the way box-drawing fonts join them (double lines leave the inside of
    a corner open)."""
    image = Image.new("L", (w, h), 0)
    draw = ImageDraw.Draw(image)

    def fill(x0, y0, x1, y1) -> None:
        x0, y0, x1, y1 = max(0, x0), max(0, y0), min(w, x1), min(h, y1)
        if x1 > x0 and y1 > y0:
            draw.rectangle([x0, y0, x1 - 1, y1 - 1], fill=255)

    U, R, D, L = (arms.get(k, 0) for k in "URDL")
    weight_px = {LIGHT: t, HEAVY: 2 * t}
    # Single (light or heavy) bands, centred.
    def band(size: int, px: int) -> tuple[int, int]:
        start = (size - px) // 2
        return start, start + px

    # Double lines: two light lines with a light gap between them.
    dx0 = (w - 3 * t) // 2
    dy0 = (h - 3 * t) // 2
    x1l, x1r, x2l, x2r = dx0, dx0 + t, dx0 + 2 * t, dx0 + 3 * t
    y1t, y1b, y2t, y2b = dy0, dy0 + t, dy0 + 2 * t, dy0 + 3 * t
    cx, cy = w // 2, h // 2
    vertical_px = max([weight_px[a] for a in (U, D) if a in weight_px] or [0])
    horizontal_px = max([weight_px[a] for a in (L, R) if a in weight_px] or [0])
    any_v_double = DOUBLE in (U, D)
    any_h_double = DOUBLE in (L, R)

    # --- horizontal arms
    for arm, side in ((R, "R"), (L, "L")):
        if not arm:
            continue
        if arm == DOUBLE:
            if side == "R":
                top = x2l if U == DOUBLE else (x1l if D == DOUBLE else cx)
                bottom = x2l if D == DOUBLE else (x1l if U == DOUBLE else cx)
                fill(top, y1t, w, y1b)
                fill(bottom, y2t, w, y2b)
            else:
                top = x1r if U == DOUBLE else (x2r if D == DOUBLE else cx)
                bottom = x1r if D == DOUBLE else (x2r if U == DOUBLE else cx)
                fill(0, y1t, top, y1b)
                fill(0, y2t, bottom, y2b)
            continue
        px = weight_px[arm]
        y0, y1 = band(h, px)
        across = max(px, vertical_px)
        bx0, bx1 = band(w, across)
        other = L if side == "R" else R
        if any_v_double and not other:
            both = U == DOUBLE and D == DOUBLE
            if side == "R":
                fill(x2l if both else x1l, y0, w, y1)
            else:
                fill(0, y0, x1r if both else x2r, y1)
        elif side == "R":
            fill(bx0, y0, w, y1)
        else:
            fill(0, y0, bx1, y1)

    # --- vertical arms
    for arm, side in ((D, "D"), (U, "U")):
        if not arm:
            continue
        if arm == DOUBLE:
            if side == "D":
                left = y2t if L == DOUBLE else (y1t if R == DOUBLE else cy)
                right = y2t if R == DOUBLE else (y1t if L == DOUBLE else cy)
                fill(x1l, left, x1r, h)
                fill(x2l, right, x2r, h)
            else:
                left = y1b if L == DOUBLE else (y2b if R == DOUBLE else cy)
                right = y1b if R == DOUBLE else (y2b if L == DOUBLE else cy)
                fill(x1l, 0, x1r, left)
                fill(x2l, 0, x2r, right)
            continue
        px = weight_px[arm]
        x0, x1 = band(w, px)
        across = max(px, horizontal_px)
        by0, by1 = band(h, across)
        other = U if side == "D" else D
        if any_h_double and not other:
            both = L == DOUBLE and R == DOUBLE
            if side == "D":
                fill(x0, y2t if both else y1t, x1, h)
            else:
                fill(x0, 0, x1, y1b if both else y2b)
        elif side == "D":
            fill(x0, by0, x1, h)
        else:
            fill(x0, 0, x1, by1)
    return image


def _dashes(count: int, weight: int, vertical: bool, w: int, h: int, t: int) -> Image.Image:
    image = Image.new("L", (w, h), 0)
    draw = ImageDraw.Draw(image)
    px = t if weight == LIGHT else 2 * t
    length = h if vertical else w
    segment = length / count
    dash = max(1.0, segment * 0.6)
    for index in range(count):
        start = round(index * segment + (segment - dash) / 2)
        end = max(start + 1, round(index * segment + (segment + dash) / 2))
        if vertical:
            x0 = (w - px) // 2
            draw.rectangle([x0, start, x0 + px - 1, end - 1], fill=255)
        else:
            y0 = (h - px) // 2
            draw.rectangle([start, y0, end - 1, y0 + px - 1], fill=255)
    return image


def _arc(corner: str, w: int, h: int, t: int) -> Image.Image:
    """A rounded corner (╭╮╯╰): straight to the edges, a quarter circle
    where the two lines meet, joining the light lines of its neighbours."""
    S = _SUPER
    big = Image.new("L", (w * S, h * S), 0)
    draw = ImageDraw.Draw(big)
    x0 = (w - t) // 2
    y0 = (h - t) // 2
    # centre lines of the neighbours' light strokes, in supersampled pixels
    cx = (x0 + t / 2) * S
    cy = (y0 + t / 2) * S
    radius = min(w * S - cx, cx, h * S - cy, cy)
    width = max(1, t * S)
    half = width / 2
    vertical, horizontal = corner[0], corner[1]
    # the corner circle's centre sits `radius` away from both strokes
    ox = cx + radius if horizontal == "R" else cx - radius
    oy = cy + radius if vertical == "D" else cy - radius
    # straight runs from the arc's ends to the cell edges
    if vertical == "D":
        draw.rectangle([cx - half, oy, cx + half - 1, h * S], fill=255)
    else:
        draw.rectangle([cx - half, 0, cx + half - 1, oy], fill=255)
    if horizontal == "R":
        draw.rectangle([ox, cy - half, w * S, cy + half - 1], fill=255)
    else:
        draw.rectangle([0, cy - half, ox, cy + half - 1], fill=255)
    start = {"DR": 180, "DL": 270, "UL": 0, "UR": 90}[corner]
    draw.arc([ox - radius - half, oy - radius - half, ox + radius + half - 1,
              oy + radius + half - 1], start, start + 90, fill=255, width=int(width))
    return big.resize((w, h), Image.BOX)


def _diagonal(which: str, w: int, h: int, t: int) -> Image.Image:
    S = _SUPER
    big = Image.new("L", (w * S, h * S), 0)
    draw = ImageDraw.Draw(big)
    width = max(1, int(t * S * 1.2))
    if which in ("/", "X"):
        draw.line([(w * S, 0), (0, h * S)], fill=255, width=width)
    if which in ("\\", "X"):
        draw.line([(0, 0), (w * S, h * S)], fill=255, width=width)
    return big.resize((w, h), Image.BOX)


__all__ = ["drawn", "mask", "box_spec", "thickness", "BOX", "BLOCKS", "SEXTANTS", "BRAILLE"]
