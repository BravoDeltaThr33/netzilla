"""Graphs that draw themselves in pixels or in text — same layout either way.

A graph is described once (a LineGraph or a SpectrumGraph) and rendered by
`render()` in whichever mode the terminal supports:

  text   block characters (the line graphs netzilla has always drawn, every
         full block outlined in the theme background) and braille dots for
         the spectrum — works in any terminal with a Unicode font;
  pixel  an anti-aliased image drawn by plot.py and shown through the kitty
         graphics protocol (kitty, Ghostty) or as Sixel (Windows Terminal,
         WezTerm), sitting exactly where the text graph would: the y-axis
         labels, the axis line and the channel numbers stay as text either
         side of it.

If anything about drawing pixels fails, the text form is returned instead,
so a graph can never take a view down.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Sequence

from rich.text import Text

from ..colours import channel_colour
from . import plot


@dataclass
class LineGraph:
    """A scrolling graph: `width` samples across, newest on the right."""

    values: Sequence[float | None]
    floor: float
    ceil: float
    width: int = 60
    height: int = 8
    label: Callable[[float], str] = lambda v: f"{v:.0f}"
    colour: str = "signal"            # "signal" = coloured by the dBm scale
    extra: Sequence[plot.Series] = field(default_factory=tuple)
    # A fixed number of samples stretched across `width` (a speed test's
    # 32 quarter-seconds) instead of one sample per column; None = per column.
    slots: int | None = None
    align: str = "right"              # "left": fill from the left edge


@dataclass
class SpectrumGraph:
    """Every network as a hump over the channels it occupies."""

    aps: Sequence[dict]
    band: str = "2.4 GHz"
    width: int = 60
    height: int = 8
    floor: float = -95.0
    ceil: float = -25.0


@dataclass
class Context:
    """How to draw: pixel or text, and with what."""

    pixel: bool
    palette: object
    canvas: object | None = None          # pixels.Canvas() for pixel mode
    cell_px: tuple[int, int] = (10, 20)
    colour: str = "#62b6ff"               # text-mode block colour
    edge: str = "#000000"                 # text-mode block outline colour
    scaffold: str | None = None           # text-mode axis colour


# ------------------------------------------------------------------ helpers
def _odd(height: int) -> int:
    """Line graphs are an odd number of rows tall, so the middle label sits
    on a row of its own: ceil, middle and floor are then exactly the values
    at the centres of the top, middle and bottom rows (where the pixel
    graph draws its grid lines), not half a row out."""
    height = max(3, int(height))
    return height if height % 2 else height + 1


def _labels(graph_height: int, ceil: float, floor: float,
            label: Callable[[float], str]) -> dict[int, str]:
    height = max(2, int(graph_height))
    return {0: label(ceil), height // 2: label((ceil + floor) / 2),
            height - 1: label(floor)}


def _gutter(labels: dict[int, str]) -> int:
    return max(len(text) for text in labels.values())


def _frame(cols: int, rows: int, ctx: Context) -> plot.Frame:
    cell_w, cell_h = ctx.cell_px
    return plot.Frame(cols=cols, rows=rows, cell_w=max(4, cell_w), cell_h=max(8, cell_h))


def _image_rows(png: bytes, cols: int, rows: int, ctx: Context) -> list[Text]:
    from . import pixels

    image_id = ctx.canvas.upload(png, cols, rows)
    return pixels.placeholder_rows(image_id, cols, rows)


# ------------------------------------------------------------------ line graphs
def text_line(graph: LineGraph, ctx: Context) -> Text:
    from ..local.wifitools import chart_lines
    from ..render import block_text

    values, width = list(graph.values), graph.width
    if graph.slots and graph.slots < width:
        # Each sample gets the same whole number of columns.
        factor = max(1, width // graph.slots)
        values = [v for v in values[-graph.slots:] for _ in range(factor)]
        width = factor * graph.slots
    lines = chart_lines(values, height=_odd(graph.height), width=width,
                        floor=graph.floor, ceil=graph.ceil, label=graph.label,
                        align=graph.align)
    return block_text(lines, ctx.colour, ctx.edge, scaffold=ctx.scaffold)


def pixel_line(graph: LineGraph, ctx: Context) -> Text:
    height = _odd(graph.height)
    width = max(4, int(graph.width))
    labels = _labels(height, graph.ceil, graph.floor, graph.label)
    gutter = _gutter(labels)
    theme = plot.Theme.from_palette(ctx.palette)
    series = [plot.Series(list(graph.values), colour=graph.colour)] + list(graph.extra)
    slots = graph.slots if graph.slots and graph.slots < width else width
    if graph.slots and graph.slots < width:
        width = max(1, width // graph.slots) * graph.slots     # as text mode
    png = plot.line_chart(series, _frame(width, height, ctx), theme,
                          floor=graph.floor, ceil=graph.ceil, slots=slots,
                          grid_rows=sorted(labels), align=graph.align)
    rows = _image_rows(png, width, height, ctx)
    scaffold = ctx.scaffold or ctx.palette.muted
    out = Text(no_wrap=True, overflow="crop")
    for index, row in enumerate(rows):
        out.append(f"{labels.get(index, ''):>{gutter}} ┤", style=scaffold)
        out.append_text(row)
        out.append("\n")
    out.append(" " * gutter + " └" + "─" * width, style=scaffold)
    return out


# ------------------------------------------------------------------ spectrum
_BRAILLE = ((0x01, 0x08), (0x02, 0x10), (0x04, 0x20), (0x40, 0x80))


def text_spectrum(graph: SpectrumGraph, ctx: Context) -> Text:
    """The spectrum in braille dots: 2 x 4 dots per cell, every network's
    outline in its channel's colour, SSIDs at the peaks where there's room."""
    cols, rows = max(8, graph.width), _odd(graph.height)
    dots_w, dots_h = cols * 2, rows * 4
    cells = [[0] * cols for _ in range(rows)]
    colours: list[list[str | None]] = [[None] * cols for _ in range(rows)]
    bottom = dots_h - 1
    span = (graph.ceil - graph.floor) or 1.0
    low, high = plot.BAND_RANGES.get(graph.band, plot.BAND_RANGES["2.4 GHz"])
    on_band = [a for a in graph.aps if a.get("band") == graph.band and a.get("channel")]
    on_band.sort(key=lambda a: (bool(a.get("in_use")), a.get("signal_dbm", -100)))
    peaks = []
    for ap in on_band:
        try:
            centre = float(ap.get("centre_channel") or ap["channel"])
            signal = float(ap.get("signal_dbm", -100))
        except (TypeError, ValueError):
            continue
        frac = max(0.0, min(1.0, (signal - graph.floor) / span))
        peak = bottom - frac * bottom
        half = plot.half_span(ap)
        colour = channel_colour(int(ap["channel"]))
        previous = None
        for x in range(dots_w):
            channel = low + (x + 0.5) / dots_w * (high - low)
            t = (channel - centre) / half
            if abs(t) >= 1:
                previous = None
                continue
            y = int(round(bottom - plot.hump(t) * (bottom - peak)))
            span_from = y if previous is None else min(y, previous)
            span_to = y if previous is None else max(y, previous)
            for yy in range(span_from, span_to + 1):
                row, sub_y = divmod(yy, 4)
                col, sub_x = divmod(x, 2)
                if 0 <= row < rows:
                    cells[row][col] |= _BRAILLE[sub_y][sub_x]
                    colours[row][col] = colour
            previous = y
        peak_col = int((centre - low) / (high - low) * cols)
        peaks.append((int(peak) // 4, peak_col, ap.get("ssid") or "<hidden>", colour,
                      bool(ap.get("in_use"))))

    # Labels go in blank cells just above each peak, strongest first.
    grid: list[list[tuple[str, str | None]]] = [
        [(chr(0x2800 + bits) if bits else " ", colours[r][c])
         for c, bits in enumerate(cells[r])] for r in range(rows)]
    for row, col, name, colour, mine in sorted(peaks, key=lambda p: (not p[4], p[0])):
        label = ("● " if mine else "") + (name if len(name) <= 16 else name[:15] + "…")
        row = max(0, row - 1)
        start = max(0, min(cols - len(label), col - len(label) // 2))
        if all(cells[row][c] == 0 and grid[row][c][0] == " "
               for c in range(start, start + len(label))):
            for i, char in enumerate(label):
                grid[row][start + i] = (char, colour)

    labels = {0: f"{graph.ceil:.0f} dBm", rows // 2: f"{(graph.ceil + graph.floor) / 2:.0f} dBm",
              rows - 1: f"{graph.floor:.0f} dBm"}
    gutter = _gutter(labels)
    scaffold = ctx.scaffold or ctx.palette.muted
    out = Text(no_wrap=True, overflow="crop")
    for r in range(rows):
        out.append(f"{labels.get(r, ''):>{gutter}} ┤", style=scaffold)
        for char, colour in grid[r]:
            out.append(char, style=colour or scaffold)
        out.append("\n")
    out.append(" " * gutter + " └" + "─" * cols + "\n", style=scaffold)
    out.append_text(channel_axis(graph.band, cols, gutter, scaffold))
    return out


def channel_axis(band: str, cols: int, gutter: int, scaffold: str) -> Text:
    """Channel numbers under a spectrum, each in its channel's colour."""
    axis = [" "] * cols
    owners: list[int | None] = [None] * cols
    for channel, column in plot.tick_columns(band, cols):
        label = str(channel)
        start = max(0, min(cols - len(label), column - len(label) // 2))
        if any(axis[c] != " " for c in range(max(0, start - 1), min(cols, start + len(label) + 1))):
            continue
        for i, char in enumerate(label):
            axis[start + i] = char
            owners[start + i] = channel
    out = Text(" " * (gutter + 2), style=scaffold)
    for char, channel in zip(axis, owners):
        out.append(char, style=channel_colour(channel) if channel else scaffold)
    return out


def pixel_spectrum(graph: SpectrumGraph, ctx: Context) -> Text:
    cols, rows = max(8, graph.width), _odd(graph.height)
    labels = {0: f"{graph.ceil:.0f} dBm", rows // 2: f"{(graph.ceil + graph.floor) / 2:.0f} dBm",
              rows - 1: f"{graph.floor:.0f} dBm"}
    gutter = _gutter(labels)
    theme = plot.Theme.from_palette(ctx.palette)
    png = plot.spectrum_chart(graph.aps, graph.band, _frame(cols, rows, ctx), theme,
                              floor=graph.floor, ceil=graph.ceil,
                              grid_rows=sorted(labels))
    image = _image_rows(png, cols, rows, ctx)
    scaffold = ctx.scaffold or ctx.palette.muted
    out = Text(no_wrap=True, overflow="crop")
    for r, row in enumerate(image):
        out.append(f"{labels.get(r, ''):>{gutter}} ┤", style=scaffold)
        out.append_text(row)
        out.append("\n")
    out.append(" " * gutter + " └" + "─" * cols + "\n", style=scaffold)
    out.append_text(channel_axis(graph.band, cols, gutter, scaffold))
    return out


# ------------------------------------------------------------------ entry point
def render(graph, ctx: Context) -> Text:
    """The graph as Text: pixels when the context allows, text otherwise."""
    if ctx.pixel and ctx.canvas is not None and plot.HAVE_PIL:
        try:
            if isinstance(graph, SpectrumGraph):
                return pixel_spectrum(graph, ctx)
            return pixel_line(graph, ctx)
        except Exception:
            pass                    # fall through to the text form
    if isinstance(graph, SpectrumGraph):
        return text_spectrum(graph, ctx)
    return text_line(graph, ctx)


__all__ = ["LineGraph", "SpectrumGraph", "Context", "render", "text_line",
           "pixel_line", "text_spectrum", "pixel_spectrum", "channel_axis"]
