"""Pixel graphs, drawn with Pillow, for terminals that can show images.

Every graph here is the pixel twin of a text graph netzilla already draws:
the same samples, the same scale, the same "newest on the right", with the
axis labels left in the terminal's own font beside it (text stays crisp, and
the layout is identical in both modes). Each frame is drawn at twice its
size and scaled down, which anti-aliases the lines, then given a soft glow —
a phosphor trace on a CRT, in the active theme's colours.

Colours follow colours.py: a signal graph is coloured by the one signal scale
(very weak red → excellent green) so a −45 dBm stretch is green on the
graph exactly as it is in the tables.
"""

from __future__ import annotations

import io
import math
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Sequence

from ..colours import SEMANTIC, channel_colour

try:  # Pillow is a dependency, but a broken install must only cost the pixels.
    from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont
    HAVE_PIL = True
except Exception:  # pragma: no cover - exercised only without Pillow
    HAVE_PIL = False

SS = 2                       # supersampling factor


# ------------------------------------------------------------------ colours
def rgb(colour: str) -> tuple[int, int, int]:
    colour = colour.lstrip("#")
    if len(colour) == 3:
        colour = "".join(c * 2 for c in colour)
    return int(colour[0:2], 16), int(colour[2:4], 16), int(colour[4:6], 16)


def mix(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    t = max(0.0, min(1.0, t))
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))  # type: ignore


_SIGNAL_STOPS = (
    (-85.0, "very weak"), (-75.0, "weak"), (-65.0, "fair"), (-55.0, "good"),
    (-45.0, "excellent"),
)


_SIGNAL_RGB = [(v, rgb(SEMANTIC[key])) for v, key in _SIGNAL_STOPS]


def signal_rgb(dbm: float) -> tuple[int, int, int]:
    """The signal scale as a smooth gradient: red at −85, green from −45."""
    stops = _SIGNAL_RGB
    if dbm <= stops[0][0]:
        return stops[0][1]
    for (v0, c0), (v1, c1) in zip(stops, stops[1:]):
        if dbm <= v1:
            return mix(c0, c1, (dbm - v0) / (v1 - v0))
    return stops[-1][1]


def _png(image) -> bytes:
    buffer = io.BytesIO()
    image.convert("RGB").save(buffer, "PNG", compress_level=1)
    return buffer.getvalue()


@lru_cache(maxsize=8)
def _font(size: int):
    try:
        return ImageFont.load_default(size=size)
    except Exception:            # Pillow without FreeType: the bitmap font
        return ImageFont.load_default()


# ------------------------------------------------------------------ geometry
@dataclass(frozen=True)
class Frame:
    """The plot area, in cells and pixels."""

    cols: int
    rows: int
    cell_w: int
    cell_h: int

    @property
    def width(self) -> int:
        return max(8, self.cols * self.cell_w)

    @property
    def height(self) -> int:
        return max(8, self.rows * self.cell_h)

    def row_centre(self, row: int, scale: int = 1) -> float:
        return (row + 0.5) * self.cell_h * scale


@dataclass
class Series:
    values: Sequence[float | None]
    colour: str = "#62b6ff"          # hex, or "signal" for the dBm scale
    fill: bool = True
    width: float = 2.0                # line width in pixels
    marker: bool = True               # a dot on the newest sample
    label: str = ""


@dataclass
class Theme:
    background: str
    grid: str
    text: str
    accent: str = "#ffffff"
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_palette(cls, palette) -> "Theme":
        return cls(background=palette.background, grid=palette.muted,
                   text=palette.foreground, accent=palette.accent)


# ------------------------------------------------------------------ line chart
def line_chart(
    series: Sequence[Series],
    frame: Frame,
    theme: Theme,
    *,
    floor: float,
    ceil: float,
    slots: int | None = None,
    grid_rows: Sequence[int] = (),
    align: str = "right",
) -> bytes:
    """A live line/area chart: one sample per slot, newest on the right
    (align="left": the first sample on the left, filling rightwards).

    `slots` is how many samples fit across (the text chart's width); the
    value scale maps `ceil` to the middle of the top row and `floor` to the
    middle of the bottom row, so the text labels beside each labelled row
    line up with the grid lines drawn here.
    """
    if not HAVE_PIL:
        raise RuntimeError("Pillow is not installed")
    slots = max(2, slots or frame.cols)
    width, height = frame.width, frame.height
    bg = rgb(theme.background)
    base = Image.new("RGBA", (width, height), bg + (255,))
    draw = ImageDraw.Draw(base)

    # -- grid: dashed lines at the labelled rows, faint ticks every 10 samples
    grid = rgb(theme.grid)
    for row in grid_rows:
        y = int(frame.row_centre(row))
        for x in range(0, width, 10):
            draw.line([(x, y), (x + 5, y)], fill=grid + (90,), width=1)
    step = width / slots
    for k in range(10, slots, 10):
        x = int(width - (k - 0.5) * step)
        draw.line([(x, 0), (x, height)], fill=grid + (24,), width=1)

    top, bottom = frame.row_centre(0), height - frame.row_centre(0)
    span = (ceil - floor) or 1.0

    def y_of(value: float) -> float:
        v = max(floor, min(ceil, float(value)))
        return top + (ceil - v) / span * (bottom - top)

    lines = Image.new("RGBA", (width * SS, height * SS), (0, 0, 0, 0))
    line_draw = ImageDraw.Draw(lines)

    for one in series:
        shown = list(one.values)[-slots:]
        offset = 0 if align == "left" else slots - len(shown)
        runs: list[list[tuple[float, float, float]]] = [[]]
        for index, value in enumerate(shown):
            if value is None:
                if runs[-1]:
                    runs.append([])
                continue
            x = (offset + index + 0.5) * step
            runs[-1].append((x, y_of(value), float(value)))
        runs = [r for r in runs if r]
        if not runs:
            continue
        fixed = None if one.colour == "signal" else rgb(one.colour)

        # -- fill under the line: a vertical gradient, strongest at the top
        if one.fill:
            column = Image.new("RGBA", (1, height))
            pixels = column.load()
            for y in range(height):
                if fixed is None:
                    value = ceil - (y - top) / max(1.0, bottom - top) * span
                    colour = signal_rgb(value)
                else:
                    colour = fixed
                # Strong under the line, fading to nothing at the floor.
                fade = (1.0 - y / height) ** 1.35
                pixels[0, y] = colour + (int(12 + 150 * fade),)
            gradient = column.resize((width, height), Image.NEAREST)
            mask = Image.new("L", (width, height), 0)
            mask_draw = ImageDraw.Draw(mask)
            for run in runs:
                if len(run) == 1:
                    x, y, _v = run[0]
                    mask_draw.rectangle([x - step / 2, y, x + step / 2, height], fill=255)
                    continue
                points = [(x, y) for x, y, _v in run]
                mask_draw.polygon([(run[0][0], height)] + points + [(run[-1][0], height)],
                                  fill=255)
            gradient.putalpha(ImageChops.multiply(gradient.getchannel("A"), mask))
            base.alpha_composite(gradient)

        # -- the trace itself, drawn at SS x and scaled down (anti-aliasing)
        width_px = max(1, int(round(one.width * SS)))
        scaled = [[(x * SS, y * SS, v) for x, y, v in run] for run in runs]
        for run in scaled:
            if len(run) == 1:
                x, y, value = run[0]
                colour = fixed or signal_rgb(value)
                line_draw.line([(x - step * SS / 2, y), (x + step * SS / 2, y)],
                               fill=colour + (255,), width=width_px)
                continue
            for (x0, y0, v0), (x1, y1, v1) in zip(run, run[1:]):
                colour = fixed or signal_rgb((v0 + v1) / 2)
                line_draw.line([(x0, y0), (x1, y1)], fill=colour + (255,), width=width_px)
                r = width_px / 2
                line_draw.ellipse([x1 - r, y1 - r, x1 + r, y1 + r], fill=colour + (255,))
        if one.marker:
            x, y, value = scaled[-1][-1]
            colour = fixed or signal_rgb(value)
            r = 3.2 * SS
            line_draw.ellipse([x - r * 1.9, y - r * 1.9, x + r * 1.9, y + r * 1.9],
                              fill=colour + (70,))
            line_draw.ellipse([x - r, y - r, x + r, y + r], fill=colour + (255,),
                              outline=(255, 255, 255, 200), width=max(1, SS))

    trace = lines.reduce(SS)
    # Two glows: a wide faint halo and a tight bright one — a phosphor trace.
    wide = trace.filter(ImageFilter.GaussianBlur(radius=max(3.0, frame.cell_h / 3.5)))
    tight = trace.filter(ImageFilter.GaussianBlur(radius=max(1.5, frame.cell_h / 9)))
    base.alpha_composite(wide)
    base.alpha_composite(tight)
    base.alpha_composite(tight)
    base.alpha_composite(trace)
    return _png(base)


# ------------------------------------------------------------------ spectrum
BAND_RANGES = {
    # channel-number axis for each band: (lowest shown, highest shown)
    "2.4 GHz": (-1.0, 15.0),
    "5 GHz": (31.0, 170.0),
    "6 GHz": (-3.0, 237.0),
}


def band_ticks(band: str) -> list[int]:
    if band == "2.4 GHz":
        return list(range(1, 15))
    if band == "5 GHz":
        return [36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157, 165]
    return [1, 33, 65, 97, 129, 161, 193, 225]


def channel_x(channel: float, band: str, width: float) -> float:
    low, high = BAND_RANGES.get(band, BAND_RANGES["2.4 GHz"])
    return (channel - low) / (high - low) * width


def half_span(ap: dict) -> float:
    """Half the channel's width in channel numbers (5 MHz each)."""
    try:
        mhz = float(ap.get("width_mhz") or 20)
    except (TypeError, ValueError):
        mhz = 20.0
    return max(2.0, mhz / 10.0)


def hump(t: float) -> float:
    """Height of a channel's shape at t ∈ [-1, 1]: a rounded plateau."""
    if abs(t) >= 1:
        return 0.0
    return math.cos(t * math.pi / 2) ** 0.55


def spectrum_chart(
    aps: Sequence[dict],
    band: str,
    frame: Frame,
    theme: Theme,
    *,
    floor: float = -95.0,
    ceil: float = -25.0,
    grid_rows: Sequence[int] = (),
    label_size: int | None = None,
) -> bytes:
    """The Wi-Fi analyser view: every network a hump over the channels it
    occupies, as tall as its signal, in its channel's colour; the network
    you're on is drawn last and brightest. SSIDs label the peaks."""
    if not HAVE_PIL:
        raise RuntimeError("Pillow is not installed")
    width, height = frame.width, frame.height
    big_w, big_h = width * SS, height * SS
    bg = rgb(theme.background)
    base = Image.new("RGBA", (big_w, big_h), bg + (255,))
    draw = ImageDraw.Draw(base)
    grid = rgb(theme.grid)
    for row in grid_rows:
        # Snapped to the supersampling grid so every line comes out equally
        # bright after scaling down.
        y = int(frame.row_centre(row)) * SS
        for x in range(0, big_w, 10 * SS):
            draw.line([(x, y), (x + 5 * SS - 1, y)], fill=grid + (80,), width=SS)
    for channel in band_ticks(band):
        x = int(channel_x(channel, band, width)) * SS
        draw.line([(x, 0), (x, big_h)], fill=grid + (30,), width=SS)

    # ceil at the middle of the top row and floor at the middle of the
    # bottom row — exactly where the labelled grid lines are — so a network
    # at -60 dBm peaks on the -60 line and every hump stands on the floor.
    top, bottom = frame.row_centre(0, SS), frame.row_centre(frame.rows - 1, SS)
    span = (ceil - floor) or 1.0
    shapes = Image.new("RGBA", (big_w, big_h), (0, 0, 0, 0))
    shape_draw = ImageDraw.Draw(shapes)
    labels: list[tuple[float, float, str, tuple[int, int, int], bool]] = []
    on_band = [a for a in aps if a.get("band") == band and a.get("channel")]
    on_band.sort(key=lambda a: (bool(a.get("in_use")), a.get("signal_dbm", -100)))
    for ap in on_band:
        try:
            centre = float(ap.get("centre_channel") or ap["channel"])
            signal = float(ap.get("signal_dbm", -100))
        except (TypeError, ValueError):
            continue
        height_frac = max(0.0, min(1.0, (signal - floor) / span))
        peak_y = bottom - height_frac * (bottom - top)
        half = half_span(ap)
        colour = rgb(channel_colour(int(ap["channel"])))
        mine = bool(ap.get("in_use"))
        points = []
        steps = 48
        for i in range(steps + 1):
            t = -1 + 2 * i / steps
            x = channel_x(centre + t * half, band, big_w)
            y = bottom - hump(t) * (bottom - peak_y)
            points.append((x, y))
        fill_alpha = 70 if mine else 46
        shape_draw.polygon(points + [points[-1]], fill=colour + (fill_alpha,))
        shape_draw.line(points, fill=colour + (255,), width=(3 if mine else 2) * SS,
                        joint="curve")
        if mine:
            shape_draw.line(points, fill=(255, 255, 255, 120), width=SS, joint="curve")
        name = ap.get("ssid") or "<hidden>"
        labels.append((channel_x(centre, band, big_w), peak_y, name, colour, mine))

    base.alpha_composite(shapes)
    # SSID labels at the peaks, strongest first, skipping any that collide.
    size = (label_size or max(9, int(frame.cell_h * 0.68))) * SS
    font = _font(size)
    text_draw = ImageDraw.Draw(base)
    placed: list[tuple[float, float, float, float]] = []
    # Every label is the height of a capital plus descender, whatever its
    # letters, so two labels stacked on one channel never touch.
    try:
        _l, cap_top, _r, cap_bottom = text_draw.textbbox((0, 0), "Hg", font=font)
        line_h = cap_bottom - cap_top
    except Exception:
        line_h = size
    gap = 3 * SS
    for x, y, name, colour, mine in sorted(labels, key=lambda l: (not l[4], l[1])):
        label = name if len(name) <= 22 else name[:21] + "…"
        try:
            left, top_px, right, bottom_px = text_draw.textbbox((0, 0), label, font=font)
        except Exception:
            continue
        w, h = right - left, max(line_h, bottom_px - top_px)
        dot = h * 0.6 if mine else 0.0           # a lit dot marks your network
        full = w + (dot * 1.6 if mine else 0)
        box_x = max(2, min(big_w - full - 2, x - full / 2))
        for attempt in range(4):
            # Above the peak, then higher still: never inside another hump.
            box_y = y - h - 6 * SS - attempt * (h + gap)
            if box_y < 2:
                box_y = 2 + attempt * (h + gap)
            box = (box_x, box_y, box_x + full, box_y + h)
            if all(box[2] + gap < p[0] or box[0] > p[2] + gap
                   or box[3] + gap < p[1] or box[1] > p[3] + gap for p in placed):
                break
        else:
            continue
        placed.append(box)
        bright = mix(colour, (255, 255, 255), 0.25) + (255,)
        if mine:
            cy = box_y + h / 2
            text_draw.ellipse([box_x, cy - dot / 2, box_x + dot, cy + dot / 2], fill=bright)
            box_x += dot * 1.6
        text_draw.text((box_x - left, box_y - top_px), label, font=font, fill=bright)

    small = base.reduce(SS)
    glow = shapes.reduce(SS).filter(
        ImageFilter.GaussianBlur(radius=max(2.0, frame.cell_h / 7)))
    out = Image.alpha_composite(small, glow)
    out.alpha_composite(small, dest=(0, 0))
    return _png(Image.blend(out, small, 0.45))


def tick_columns(band: str, cols: int) -> list[tuple[int, int]]:
    """(channel, column) for labelling the channel axis in text below a
    spectrum image `cols` cells wide."""
    out = []
    for channel in band_ticks(band):
        column = int(channel_x(channel, band, cols))
        if 0 <= column < cols:
            out.append((channel, column))
    return out


# ------------------------------------------------------------------ logo
def logo(lines: Sequence[str], frame: Frame, theme: Theme, colours: Sequence[str]) -> bytes:
    """The DASH banner redrawn in pixels: the block letters as solid, lit
    phosphor in a gradient across the theme's colours, the box-drawing
    shadow as a dim extrusion behind them, then glow and fine scanlines."""
    return _png(logo_image(lines, frame, theme, colours))


def add_scanlines(image):
    """Fine dark lines every third pixel row, faintly, for the CRT."""
    image = image.convert("RGBA")
    width, height = image.size
    scan = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    scan_draw = ImageDraw.Draw(scan)
    for y in range(1, height, 3):
        scan_draw.line([(0, y), (width, y)], fill=(0, 0, 0, 46))
    image.alpha_composite(scan)
    return image


def png_with_scanlines(image) -> bytes:
    return _png(add_scanlines(image))


def logo_image(lines: Sequence[str], frame: Frame, theme: Theme, colours: Sequence[str],
               scanlines: bool = True):
    """logo() as an image — without its scanlines when it is one part of a
    bigger picture that gets them all at once (graphics/banner.py)."""
    if not HAVE_PIL:
        raise RuntimeError("Pillow is not installed")
    width, height = frame.width, frame.height
    big_w, big_h = width * SS, height * SS
    cw, ch = big_w / max(1, frame.cols), big_h / max(1, frame.rows)
    bg = rgb(theme.background)
    stops = [rgb(c) for c in colours] or [rgb(theme.accent)]

    def colour_at(fx: float) -> tuple[int, int, int]:
        if len(stops) == 1:
            return stops[0]
        pos = max(0.0, min(1.0, fx)) * (len(stops) - 1)
        i = min(len(stops) - 2, int(pos))
        return mix(stops[i], stops[i + 1], pos - i)

    letters = Image.new("L", (big_w, big_h), 0)          # where the blocks are
    shadow = Image.new("L", (big_w, big_h), 0)           # the box-drawing extrusion
    draw_letters = ImageDraw.Draw(letters)
    draw_shadow = ImageDraw.Draw(shadow)
    rail = max(2, int(ch * 0.22))
    for row, line in enumerate(lines[: frame.rows]):
        for col, char in enumerate(line[: frame.cols]):
            if char == " ":
                continue
            x0, y0 = col * cw, row * ch
            if char == "█":
                draw_letters.rectangle([x0, y0, x0 + cw, y0 + ch], fill=255)
                continue
            mid_x, mid_y = x0 + cw / 2, y0 + ch / 2
            if char in "═╔╗╚╝":
                left = x0 if char in "═╗╝" else mid_x - rail / 2
                right = x0 + cw if char in "═╔╚" else mid_x + rail / 2
                draw_shadow.rectangle([left, mid_y - rail / 2, right, mid_y + rail / 2], fill=255)
            if char in "║╔╗╚╝":
                upper = y0 if char in "║╚╝" else mid_y - rail / 2
                lower = y0 + ch if char in "║╔╗" else mid_y + rail / 2
                draw_shadow.rectangle([mid_x - rail / 2, upper, mid_x + rail / 2, lower], fill=255)

    # Colour fields: a left-to-right gradient for the letters (brighter at the
    # top of each row of text, like light falling on raised type), and the
    # same hues sunk towards the background for the extrusion.
    gradient = Image.new("RGB", (big_w, 1))
    for x in range(big_w):
        gradient.putpixel((x, 0), colour_at(x / max(1, big_w - 1)))
    gradient = gradient.resize((big_w, big_h), Image.NEAREST)
    shade = Image.new("L", (1, big_h))
    for y in range(big_h):
        within = (y % max(1, int(ch))) / max(1.0, ch)
        shade.putpixel((0, y), int(255 - 70 * within))
    shade = shade.resize((big_w, big_h), Image.NEAREST)
    lit = Image.composite(gradient, Image.new("RGB", (big_w, big_h), bg), letters)
    lit = Image.composite(lit, Image.new("RGB", (big_w, big_h), (0, 0, 0)), shade)
    sunk = Image.blend(gradient, Image.new("RGB", (big_w, big_h), bg), 0.68)

    out = Image.new("RGBA", (big_w, big_h), bg + (255,))
    out.paste(sunk, (0, 0), shadow)
    glow = Image.composite(gradient, Image.new("RGB", (big_w, big_h), bg), letters)
    glow = glow.filter(ImageFilter.GaussianBlur(radius=max(4.0, ch * 0.45)))
    out = Image.blend(out.convert("RGB"), glow, 0.55).convert("RGBA")
    out.paste(sunk, (0, 0), shadow)
    out.paste(lit, (0, 0), letters)
    small = out.reduce(SS)
    return add_scanlines(small) if scanlines else small


# ------------------------------------------------------------------ gauge
def bar_gauge(fraction: float, frame: Frame, theme: Theme, colour: str,
              ticks: int = 10) -> bytes:
    """A horizontal meter (SPEED's live throughput): a glowing bar over a
    segmented track."""
    if not HAVE_PIL:
        raise RuntimeError("Pillow is not installed")
    width, height = frame.width, frame.height
    big_w, big_h = width * SS, height * SS
    bg = rgb(theme.background)
    base = Image.new("RGBA", (big_w, big_h), bg + (255,))
    draw = ImageDraw.Draw(base)
    pad = big_h * 0.22
    track = [pad, pad, big_w - pad, big_h - pad]
    draw.rounded_rectangle(track, radius=(big_h - 2 * pad) / 2,
                           fill=mix(rgb(theme.grid), bg, 0.7) + (255,))
    fraction = max(0.0, min(1.0, fraction))
    lit = Image.new("RGBA", (big_w, big_h), (0, 0, 0, 0))
    lit_draw = ImageDraw.Draw(lit)
    if fraction > 0:
        right = track[0] + (track[2] - track[0]) * fraction
        lit_draw.rounded_rectangle([track[0], track[1], max(track[0] + big_h * 0.2, right),
                                    track[3]], radius=(big_h - 2 * pad) / 2,
                                   fill=rgb(colour) + (255,))
    for k in range(1, ticks):
        x = track[0] + (track[2] - track[0]) * k / ticks
        draw.line([(x, track[1]), (x, track[3])], fill=bg + (255,), width=SS)
    small = base.reduce(SS)
    glow_src = lit.reduce(SS)
    glow = glow_src.filter(ImageFilter.GaussianBlur(radius=max(2.0, frame.cell_h / 4)))
    small.alpha_composite(glow)
    small.alpha_composite(glow_src)
    return _png(small)


__all__ = ["HAVE_PIL", "Frame", "Series", "Theme", "line_chart", "spectrum_chart",
           "logo", "bar_gauge", "tick_columns", "band_ticks", "channel_x",
           "signal_rgb", "rgb", "mix", "half_span", "hump"]
