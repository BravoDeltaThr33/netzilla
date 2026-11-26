"""DASH's banner art, either side of the NETZILLA title.

On the left, the beast: a horned, armour-backed monster with a spiked tail,
breathing a storm of energy at the title. Its breath is alive — it rolls
through the theme's own bright colours (primary, accent, success, warning,
error, one of each hue, in hue order) in waves that leave its jaws and run
out to the title, its brightness rippling as they go: FIRE_FRAMES frames,
one every FIRE_EVERY seconds, a seamless loop. On the right, Tokyo at night:
Tokyo Tower, the Skytree, the towers of the bay and the Rainbow Bridge.

Both are pictures shipped with netzilla (data/beast.png, data/tokyo.png;
their brightness alone, plus data/beast-fire.png marking the breath),
coloured from the theme as they are drawn: dark parts fall away to the
background, the rest takes the primary colour and the hottest parts burn
towards white, touched with the accent. They are shown

  * in a terminal that can show images (kitty, Ghostty) as part of the
    banner image, with the same phosphor glow and scanlines as the letters;
    the breath's cells are a separate small image per frame (fire_window,
    fire_png), so the loop only swaps which image those cells show;
  * anywhere else as sextants — each character cell split into 2 × 3 —
    shaded: a cell wholly inside a picture takes two colours, its bright
    sixths in one and the rest in the other.

The sides need room: a window too narrow for them gets the title alone.
"""

from __future__ import annotations

import colorsys
import io
import math
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from . import plot

try:
    from PIL import Image, ImageChops, ImageFilter
    HAVE_PIL = True
except Exception:  # pragma: no cover - exercised only without Pillow
    HAVE_PIL = False

GAP = 2              # cells between a picture and the title
MIN_SIDE = 22        # narrower than this, the pictures are left out
MAX_SIDE = 46
DATA = Path(__file__).resolve().parent.parent / "data"
FIRE_FRAMES = 24     # the breath's loop, frame by frame
FIRE_EVERY = 0.1     # seconds a frame stays up: a 2.4-second loop
SHAPE_LIT = 60       # brightness (of 255) that counts as part of a picture's shape
SHAPE_CLOSE = 7      # gaps in a picture's dotted drawing this small are closed up

KINDS = ("beast", "city")
# The palette roles the pictures are drawn in, in this order (see colours()).
ROLES = ("background", "primary", "secondary", "accent", "success", "warning",
         "error", "muted", "foreground")


@dataclass(frozen=True)
class Picture:
    file: str            # in data/: the picture's brightness, greyscale
    stretch: float       # drawn this much wider than the picture
    anchor: str          # "right" or "left": the edge it keeps to, by the title


PICTURES = {
    "beast": Picture("beast.png", 1.3, "right"),
    "city": Picture("tokyo.png", 1.3, "left"),
}
FIRE_MASK = "beast-fire.png"     # where the beast's breath is, on beast.png
BEAST = DATA / PICTURES["beast"].file


def side_cols(available: int, title: int) -> int:
    """How many cells wide each picture is, beside a title `title` cells
    wide in `available` cells (0: no room for them)."""
    room = (available - title - 2 * GAP - 2) // 2
    return 0 if room < MIN_SIDE else min(MAX_SIDE, room)


def colours(palette) -> tuple[str, ...]:
    """A palette's colours in ROLES order — hashable, for the caches."""
    return tuple(getattr(palette, role) for role in ROLES)


def _role(scheme: tuple[str, ...], role: str) -> tuple[int, int, int]:
    return plot.rgb(scheme[ROLES.index(role)])


# ---------------------------------------------------------------- pictures
@lru_cache(maxsize=4)
def _load(name: str):
    """A greyscale picture from data/."""
    with Image.open(DATA / name) as picture:
        return picture.convert("L")


@lru_cache(maxsize=4)
def _shape(kind: str):
    """Where a picture is, as a solid shape: its dotted drawing closed up, so
    in sextants a body is whole and the sky and the gaps stay open."""
    lit = _load(PICTURES[kind].file).point(lambda v: 255 if v >= SHAPE_LIT else 0)
    return lit.filter(ImageFilter.MaxFilter(SHAPE_CLOSE)).filter(
        ImageFilter.MinFilter(SHAPE_CLOSE))


def _box(kind: str, width: int, height: int) -> tuple[int, int, int, int]:
    """Where a picture goes in a width × height space: (x, y, w, h). As tall
    as the space and `stretch` times wider than the picture, against its
    anchor edge; a narrower space gets a smaller picture, never a squashed
    one."""
    picture = _load(PICTURES[kind].file)
    aspect = picture.width / picture.height * PICTURES[kind].stretch
    w, h = round(height * aspect), height
    if w > width:
        w, h = width, max(1, round(width / aspect))
    x = width - w if PICTURES[kind].anchor == "right" else 0
    return x, (height - h) // 2, w, h


@lru_cache(maxsize=8)
def _sized(name: str, w: int, h: int):
    return _load(name).resize((w, h), Image.LANCZOS)


@lru_cache(maxsize=32)
def _gradient(scheme: tuple[str, ...]) -> tuple[tuple[int, int, int], ...]:
    """256 colours, dark to bright: the background, the primary colour, then
    on to white-hot, the hottest touched with the accent."""
    background, primary = _role(scheme, "background"), _role(scheme, "primary")
    accent, foreground = _role(scheme, "accent"), _role(scheme, "foreground")
    stops = ((0.0, background), (0.22, plot.mix(primary, background, 0.5)), (0.5, primary),
             (0.8, plot.mix(primary, foreground, 0.45)), (0.93, plot.mix(accent, foreground, 0.35)),
             (1.0, plot.mix(accent, foreground, 0.7)))
    out = []
    for i in range(256):
        b = i / 255
        for (b0, c0), (b1, c1) in zip(stops, stops[1:]):
            if b <= b1:
                out.append(plot.mix(c0, c1, (b - b0) / (b1 - b0)))
                break
    return tuple(out)


# -------------------------------------------------------------------- fire
def _hue(colour: tuple[int, int, int]) -> float:
    return colorsys.rgb_to_hls(*(v / 255 for v in colour))[0]


def _luma(colour: tuple[int, int, int]) -> float:
    return 0.2126 * colour[0] + 0.7152 * colour[1] + 0.0722 * colour[2]


@lru_cache(maxsize=32)
def fire_palette(scheme: tuple[str, ...]) -> tuple[tuple[int, int, int], ...]:
    """The colours the breath rolls through: the theme's own bright colours,
    one of each (too dark or too like another one left out), in hue order so
    each melts into the next. At least three: a one-colour theme gets its
    primary, lighter and lighter."""
    picks: list[tuple[int, int, int]] = []
    for role in ("primary", "accent", "success", "warning", "error"):
        colour = _role(scheme, role)
        if _luma(colour) < 70:
            continue
        if any(sum((a - b) ** 2 for a, b in zip(colour, pick)) < 60 ** 2 for pick in picks):
            continue
        picks.append(colour)
    primary, foreground = _role(scheme, "primary"), _role(scheme, "foreground")
    if not picks:
        picks.append(primary)
    while len(picks) < 3:
        picks.append(plot.mix(primary, foreground, 0.35 * len(picks)))
    return tuple(sorted(picks, key=_hue))


def _fire_at(scheme: tuple[str, ...], frame: int, d: float) -> tuple[tuple[int, int, int], float]:
    """The breath's colour and brightness `d` of the way from the jaws to
    the title (0 to 1) in `frame`: the colours roll outwards, half the
    palette along the breath at once, the whole palette once a loop; two
    ripples of brightness run out with them."""
    palette = fire_palette(scheme)
    k = len(palette)
    phase = (frame % FIRE_FRAMES) / FIRE_FRAMES
    position = (phase - 0.5 * d) * k
    step = math.floor(position)
    colour = plot.mix(palette[step % k], palette[(step + 1) % k], position - step)
    pulse = (0.8 + 0.13 * math.sin(2 * math.pi * (3 * phase - 2.0 * d))
             + 0.07 * math.sin(2 * math.pi * (5 * phase - 4.5 * d + 0.3)))
    return colour, pulse


def _white_hot(scheme: tuple[str, ...]) -> tuple[int, int, int]:
    return plot.mix(_role(scheme, "foreground"), (255, 255, 255), 0.35)


FLAME_FULL = 140      # brightness at which the breath shows its colour fully
FLAME_HOT = 0.5       # how far its brightest parts go towards white-hot


def _flame(scheme: tuple[str, ...], colour, value: float) -> tuple[int, int, int]:
    """One spot of breath: dark to the background, then the colour, then on
    towards white-hot (never all the way: the colour stays in it)."""
    if value < FLAME_FULL:
        return plot.mix(_role(scheme, "background"), colour, value / FLAME_FULL)
    return plot.mix(colour, _white_hot(scheme),
                    min(FLAME_HOT, (value - FLAME_FULL) / (255 - FLAME_FULL)))


def _fire_span(mask) -> tuple[int, int]:
    """The breath's first and last column on its mask (jaws to title)."""
    box = mask.getbbox() or (0, 0, mask.width, mask.height)
    return box[0], max(box[0] + 1, box[2])


# ------------------------------------------------------------------ pixels
@lru_cache(maxsize=16)
def _art(kind: str, cols: int, rows: int, cell_w: int, cell_h: int,
         scheme: tuple[str, ...], frame: int = 0):
    """A picture at its size on screen in the theme's colours, transparent
    where it isn't; the beast with its breath as in `frame`."""
    W, H = cols * cell_w, rows * cell_h
    x, y, w, h = _box(kind, W, H)
    brightness = _sized(PICTURES[kind].file, w, h)
    table = _gradient(scheme)
    colour = Image.merge("RGB", [brightness.point([c[k] for c in table]) for k in range(3)])
    alpha = brightness.point(lambda v: min(255, int(v * 1.8)))
    if kind == "beast":
        colour, alpha = _with_fire(colour, alpha, brightness, scheme, frame)
    picture = colour.convert("RGBA")
    picture.putalpha(alpha)
    art = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    art.paste(picture, (x, y))
    return art


def _with_fire(colour, alpha, brightness, scheme, frame: int):
    """The beast's colours and alpha with its breath recoloured for `frame`."""
    w, h = brightness.size
    mask = _sized(FIRE_MASK, w, h)
    start, end = _fire_span(mask)
    hues, pulses = [], []
    for col in range(w):
        hue, pulse = _fire_at(scheme, frame, max(0.0, (col - start) / (end - start)))
        hues.append(hue)
        pulses.append(max(0, min(255, int(pulse * 255))))
    field = Image.new("RGB", (w, 1))
    field.putdata(hues)
    field = field.resize((w, h), Image.NEAREST)
    ripple = Image.new("L", (w, 1))
    ripple.putdata(pulses)
    value = ImageChops.multiply(brightness, ripple.resize((w, h), Image.NEAREST))
    low = value.point(lambda v: min(255, v * 255 // FLAME_FULL))
    high = value.point(lambda v: int(min(FLAME_HOT, max(0, v - FLAME_FULL) / (255 - FLAME_FULL)) * 255))
    flame = Image.composite(field, Image.new("RGB", (w, h), _role(scheme, "background")), low)
    flame = Image.composite(Image.new("RGB", (w, h), _white_hot(scheme)), flame, high)
    return (Image.composite(flame, colour, mask),
            Image.composite(value.point(lambda v: min(255, int(v * 1.8))), alpha, mask))


def _glow(art, scheme: tuple[str, ...], cell_h: int):
    """The art over the background, with the phosphor glow (RGB)."""
    background = Image.new("RGBA", art.size, plot.rgb(scheme[0]) + (255,))
    lit = Image.alpha_composite(background, art)
    glow = lit.filter(ImageFilter.GaussianBlur(radius=_glow_radius(cell_h)))
    out = Image.blend(background.convert("RGB"), glow.convert("RGB"), 0.55).convert("RGBA")
    out.alpha_composite(art)
    return out.convert("RGB")


def _glow_radius(cell_h: int) -> float:
    return max(2.5, cell_h * 0.30)


@lru_cache(maxsize=16)
def pixels(kind: str, cols: int, rows: int, cell_w: int, cell_h: int,
           scheme: tuple[str, ...], frame: int = 0):
    """A picture at its size on screen, over the background, with glow (an
    RGB image, cols × cell_w by rows × cell_h)."""
    return _glow(_art(kind, cols, rows, cell_w, cell_h, scheme, frame), scheme, cell_h)


def banner_png(lines, title_cols: int, rows: int, side: int, cell_w: int, cell_h: int,
               scheme: tuple[str, ...], letter_colours) -> bytes:
    """The whole banner in pixels: the beast (its breath as in frame 0), the
    lit letters and the city side by side (the letters alone when `side` is
    0), with scanlines over it all."""
    theme = plot.Theme(background=scheme[0], grid=scheme[ROLES.index("muted")],
                       text=scheme[ROLES.index("foreground")],
                       accent=scheme[ROLES.index("accent")])
    letters = plot.logo_image(lines, plot.Frame(title_cols, rows, cell_w, cell_h), theme,
                              letter_colours, scanlines=False)
    cols = title_cols + (2 * (side + GAP) if side else 0)
    out = Image.new("RGB", (cols * cell_w, rows * cell_h), plot.rgb(scheme[0]))
    x = 0
    if side:
        out.paste(pixels("beast", side, rows, cell_w, cell_h, scheme), (0, 0))
        x = (side + GAP) * cell_w
    out.paste(letters.convert("RGB"), (x, 0))
    if side:
        out.paste(pixels("city", side, rows, cell_w, cell_h, scheme),
                  ((side + GAP + title_cols + GAP) * cell_w, 0))
    return plot.png_with_scanlines(out)


def fire_window(cols: int, rows: int, cell_w: int, cell_h: int) -> tuple[int, int, int, int]:
    """The cells of the beast's picture (`cols` × `rows`) that its breath and
    the breath's glow cover: (col, row, width, height), always running to
    the picture's right edge, by the title."""
    W, H = cols * cell_w, rows * cell_h
    x, y, w, h = _box("beast", W, H)
    box = _sized(FIRE_MASK, w, h).getbbox() or (0, 0, w, h)
    margin = 2 * _glow_radius(cell_h)
    left = max(0, int((x + box[0] - margin) // cell_w))
    top = max(0, int((y + box[1] - margin) // cell_h))
    bottom = min(rows, math.ceil((y + box[3] + margin) / cell_h))
    return left, top, cols - left, max(1, bottom - top)


def fire_png(cols: int, rows: int, cell_w: int, cell_h: int, scheme: tuple[str, ...],
             frame: int) -> bytes:
    """One frame of the breath: the fire_window's cells of the beast's
    picture, glow and scanlines as in banner_png (the scanlines laid over
    the whole picture first, so they line up with the rest)."""
    art = _art.__wrapped__("beast", cols, rows, cell_w, cell_h, scheme, frame)
    lit = plot.add_scanlines(_glow(art, scheme, cell_h))
    col, row, width, height = fire_window(cols, rows, cell_w, cell_h)
    crop = lit.crop((col * cell_w, row * cell_h, (col + width) * cell_w, (row + height) * cell_h))
    buffer = io.BytesIO()
    crop.convert("RGB").save(buffer, "PNG", compress_level=1)
    return buffer.getvalue()


# -------------------------------------------------------------------- text
def sextant(bits: int) -> str:
    """The character for a 2 × 3 pattern: bit 0 top-left, bit 1 top-right,
    bit 2 middle-left … bit 5 bottom-right (Unicode's sextant order). The
    four patterns Unicode already had — empty, full, left half, right half —
    are a space, █, ▌ and ▐."""
    bits &= 63
    if bits == 0:
        return " "
    if bits == 63:
        return "█"
    if bits == 21:
        return "▌"
    if bits == 42:
        return "▐"
    return chr(0x1FB00 + bits - 1 - (bits > 21) - (bits > 42))


def _grid(kind: str, picture, cols: int, rows: int, cell_w: int, cell_h: int):
    """`picture` (a picture's brightness, shape or breath) on the sextant
    grid: one value per sixth, laid out as _art lays the picture out."""
    W, H = cols * cell_w, rows * cell_h
    x, y, w, h = _box(kind, W, H)
    grid_w, grid_h = cols * 2, rows * 3
    small = picture.resize((max(1, round(w / W * grid_w)), max(1, round(h / H * grid_h))),
                           Image.BOX)
    grid = Image.new("L", (grid_w, grid_h), 0)
    left = grid_w - small.width if PICTURES[kind].anchor == "right" else 0
    grid.paste(small, (left, (grid_h - small.height) // 2))
    return grid


def _hex(colour: tuple[int, int, int]) -> str:
    return "#" + "".join(f"{v:02x}" for v in colour)


@lru_cache(maxsize=64)
def cells(kind: str, cols: int, rows: int, scheme: tuple[str, ...],
          cell_w: int = 10, cell_h: int = 20,
          frame: int = 0) -> tuple[tuple[tuple[str, str, str], ...], ...]:
    """A picture as sextants: rows of (character, colour, background) cells
    — the colour "" where a cell is empty, the background "" unless the cell
    is wholly inside the picture. A cell on a picture's edge lights the
    sixths inside it; a cell wholly inside lights its bright sixths in one
    colour and fills the rest with the colour of its dark ones. The beast's
    breath is as in `frame`."""
    table = _gradient(scheme)
    picture = PICTURES[kind].file
    bright = _grid(kind, _load(picture), cols, rows, cell_w, cell_h).load()
    shape = _grid(kind, _shape(kind), cols, rows, cell_w, cell_h).load()
    fire = None
    if kind == "beast":
        fire_grid = _grid(kind, _load(FIRE_MASK), cols, rows, cell_w, cell_h)
        fire = fire_grid.load()
        start, end = _fire_span(fire_grid.point(lambda v: 255 if v >= 128 else 0))
        flames = [_fire_at(scheme, frame, max(0.0, (x - start) / (end - start)))
                  for x in range(cols * 2)]

    def shade(x: int, y: int) -> tuple[int, int, int]:
        value = min(255, int(bright[x, y] * 1.05) + 12)
        if fire is not None and fire[x, y] >= 128:
            colour, pulse = flames[x]
            return _flame(scheme, colour, value * pulse)
        return table[min(228, value)]

    def mean(spots) -> str:
        shades = [shade(x, y) for x, y in spots]
        return _hex(tuple(sum(c[k] for c in shades) // len(shades) for k in range(3)))

    out = []
    for row in range(rows):
        line = []
        for col in range(cols):
            spots = [(col * 2 + k % 2, row * 3 + k // 2) for k in range(6)]
            inside = [shape[x, y] >= 128 for x, y in spots]
            values = [bright[x, y] for x, y in spots]
            if not any(inside):
                line.append((" ", "", ""))
                continue
            if not all(inside) or max(values) - min(values) < 18:
                lit = [k for k in range(6) if inside[k]]
                line.append((sextant(sum(1 << k for k in lit)), mean([spots[k] for k in lit]), ""))
                continue
            # Wholly inside: split the six into dark and bright where they
            # differ most, the bright ones lit.
            order = sorted(range(6), key=lambda k: values[k])
            split = max(range(1, 6), key=lambda n: n * (6 - n) * (
                sum(values[k] for k in order[n:]) / (6 - n)
                - sum(values[k] for k in order[:n]) / n) ** 2)
            lit, dark = order[split:], order[:split]
            line.append((sextant(sum(1 << k for k in lit)), mean([spots[k] for k in lit]),
                         mean([spots[k] for k in dark])))
        out.append(tuple(line))
    return tuple(out)
