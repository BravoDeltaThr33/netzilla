"""Helpers that turn client data into themed Rich renderables.

Result panels are built as Rich renderables rather than Textual markup so the
colours come straight from the active Palette — no dependence on which
Textual content-markup dialect is installed.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from rich.box import SQUARE
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .colours import style_cell
from .themes import Palette

# Square single-line borders with the title embedded in the top edge, as in
# the reference terminal screenshots.
PANEL_BOX = SQUARE


def kv_panel(
    palette: Palette,
    title: str,
    rows: Sequence[tuple[str, object]],
    *,
    subtitle: str | None = None,
    border: str | None = None,
) -> RenderableType:
    """A titled panel of key/value rows."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="left", style=palette.secondary, no_wrap=True)
    grid.add_column(justify="left", style=palette.foreground, overflow="fold")
    for key, value in rows:
        grid.add_row(Text(str(key).upper(), style=palette.secondary),
                     _value(palette, value, str(key)))
    return Panel(
        grid,
        title=Text(f" {title.upper()} ", style=f"bold {palette.primary}"),
        title_align="left",
        subtitle=Text(f" {subtitle} ", style=palette.muted) if subtitle else None,
        subtitle_align="right",
        border_style=border or palette.secondary,
        box=PANEL_BOX,
        padding=(0, 1),
    )


def table_panel(
    palette: Palette,
    title: str,
    columns: Sequence[str],
    rows: Iterable[Sequence[object]],
    *,
    subtitle: str | None = None,
    border: str | None = None,
    row_styles: Sequence[object] | None = None,
    one_line: bool = False,
    shrink: Sequence[str] = (),
) -> RenderableType:
    """A titled panel wrapping a column table.

    `row_styles` gives each row a style of its own (a picked row's highlight,
    the click action that picks it — screens/picking.py). With one_line=True
    no cell wraps, so every row is exactly one line: a live list you click
    on keeps its rows where they are. When the table is too wide, the
    columns named in `shrink` (names, kinds, makers) give up their width
    first, cut short with "…"; the rest (addresses, readings, times) keep
    theirs.
    """
    table = Table(
        box=None,
        expand=True,
        show_edge=False,
        header_style=f"bold {palette.accent}",
        pad_edge=False,
    )
    shrinkable = {name.upper() for name in shrink}
    for column in columns:
        if one_line:
            # A shrinkable column counts as wrappable when Rich shares out
            # the width, but its header and cells are each kept to one line.
            table.add_column(Text(column.upper(), no_wrap=True, overflow="ellipsis"),
                             no_wrap=column.upper() not in shrinkable, overflow="ellipsis")
        else:
            table.add_column(column.upper(), overflow="fold")
    count = 0
    for row in rows:
        style = row_styles[count] if row_styles and count < len(row_styles) else None
        cells = [_value(palette, cell, columns[i] if i < len(columns) else None)
                 for i, cell in enumerate(row)]
        if one_line and shrinkable:
            for index, cell in enumerate(cells):
                if (isinstance(cell, Text) and index < len(columns)
                        and columns[index].upper() in shrinkable):
                    cell.no_wrap, cell.overflow = True, "ellipsis"
        table.add_row(*cells, style=style)
        count += 1
    body: RenderableType = table if count else Text("No results.", style=palette.muted)
    return Panel(
        body,
        title=Text(f" {title.upper()} ", style=f"bold {palette.primary}"),
        title_align="left",
        subtitle=Text(f" {subtitle} ", style=palette.muted) if subtitle else None,
        subtitle_align="right",
        border_style=border or palette.secondary,
        box=PANEL_BOX,
        padding=(0, 1),
    )


def text_panel(
    palette: Palette,
    title: str,
    body: str,
    *,
    style: str | None = None,
    border: str | None = None,
    subtitle: str | None = None,
) -> RenderableType:
    return Panel(
        Text(body, style=style or palette.foreground),
        title=Text(f" {title.upper()} ", style=f"bold {palette.primary}"),
        title_align="left",
        subtitle=Text(f" {subtitle} ", style=palette.muted) if subtitle else None,
        subtitle_align="right",
        border_style=border or palette.secondary,
        box=PANEL_BOX,
        padding=(0, 1),
    )


def error_panel(palette: Palette, title: str, message: str) -> RenderableType:
    return text_panel(
        palette, title, message, style=palette.error, border=palette.error
    )


def warn_panel(palette: Palette, title: str, message: str) -> RenderableType:
    return text_panel(
        palette, title, message, style=palette.warning, border=palette.warning
    )


def verdict_line(palette: Palette, label: str, verdict: str, state: str) -> Text:
    """A single bold verdict line, coloured by state."""
    colour = {
        "ok": palette.success,
        "warn": palette.warning,
        "bad": palette.error,
        "info": palette.accent,
    }.get(state, palette.foreground)
    text = Text()
    text.append(f"{label.upper()}  ", style=palette.secondary)
    text.append(verdict, style=f"bold {colour}")
    return text


def rule(palette: Palette, label: str = "") -> Text:
    """A full-width separator with an optional inline label."""
    if label:
        return Text(f"── {label.upper()} ", style=palette.secondary)
    return Text("─" * 40, style=palette.secondary)


def group(*renderables: RenderableType) -> RenderableType:
    return Group(*[r for r in renderables if r is not None])


# ------------------------------------------------------------ panel grids
def grid_layout(width: int, spans: Sequence[int], *, min_width: int = 44,
                max_cols: int = 4, gap: int = 1) -> list[list[tuple[int, int]]]:
    """Rows of (item index, width in cells) for panels laid out in columns.

    As many columns as fit at `min_width` each (at most `max_cols`); an item
    with span 2 takes two columns. Every row fills the whole width, so a row
    that isn't full shares it out rather than leaving a hole on the right.
    The same function sizes graphs before they are drawn, so a graph built
    for a cell is exactly as wide as the cell it lands in.
    """
    width = max(1, int(width))
    cols = max(1, min(max_cols, (width + gap) // (min_width + gap)))
    rows: list[list[tuple[int, int]]] = []
    row: list[tuple[int, int]] = []
    used = 0
    for index, span in enumerate(spans):
        span = max(1, min(int(span), cols))
        if row and used + span > cols:
            rows.append(row)
            row, used = [], 0
        row.append((index, span))
        used += span
    if row:
        rows.append(row)
    out = []
    for row in rows:
        units = sum(span for _, span in row) or 1
        available = width - gap * (len(row) - 1)
        sized, done = [], 0
        for index, span in row:
            start = available * done // units
            done += span
            sized.append((index, max(1, available * done // units - start)))
        out.append(sized)
    return out


class PanelGrid:
    """Panels side by side in columns, each row's panels the same height so
    their borders line up — the columns a wide terminal has room for, one
    column on a narrow one. Items are renderables, or (renderable, span)."""

    def __init__(self, items: Sequence, *, min_width: int = 44, max_cols: int = 4,
                 gap: int = 1, row_gap: int = 0) -> None:
        self.items = [item if isinstance(item, tuple) else (item, 1)
                      for item in items if item is not None]
        self.min_width = min_width
        self.max_cols = max_cols
        self.gap = gap
        self.row_gap = row_gap

    def layout(self, width: int) -> list[list[tuple[int, int]]]:
        return grid_layout(width, [span for _, span in self.items],
                           min_width=self.min_width, max_cols=self.max_cols, gap=self.gap)

    def __rich_console__(self, console, options):
        from copy import copy

        from rich.segment import Segment

        width = options.max_width
        rows = self.layout(width)
        for row_number, row in enumerate(rows):
            if row_number and self.row_gap:
                for _ in range(self.row_gap):
                    yield Segment.line()
            sized = []
            for index, cell in row:
                renderable = self.items[index][0]
                lines = console.render_lines(
                    renderable, options.update_width(cell).update(height=None), pad=True)
                sized.append((renderable, cell, lines))
            height = max(len(lines) for _, _, lines in sized)
            columns = []
            for renderable, cell, lines in sized:
                if len(lines) < height and isinstance(renderable, Panel):
                    stretched = copy(renderable)
                    stretched.height = height
                    lines = console.render_lines(
                        stretched, options.update_width(cell).update(height=None), pad=True)
                columns.append((cell, lines))
            for line_number in range(height):
                for position, (cell, lines) in enumerate(columns):
                    if position:
                        yield Segment(" " * self.gap)
                    if line_number < len(lines):
                        yield from lines[line_number]
                    else:
                        yield Segment(" " * cell)
                yield Segment.line()

    def __rich_measure__(self, console, options):
        from rich.measure import Measurement

        return Measurement(min(self.min_width, options.max_width), options.max_width)


def _value(palette: Palette, value: object, column: str | None = None) -> RenderableType:
    """Render one cell: booleans and empties helpfully, everything else
    coloured by what it is (colours.py) — the column or key name, and any
    addresses, dBm readings, bands and the like inside it."""
    if isinstance(value, Text):
        return value
    if value is None or value == "":
        return Text("—", style=palette.muted)
    if isinstance(value, bool):
        return Text(
            "YES" if value else "no",
            style=palette.warning if value else palette.muted,
        )
    if isinstance(value, (list, tuple)):
        if not value:
            return Text("—", style=palette.muted)
        value = ", ".join(str(v) for v in value)
    styled = style_cell(column, value, palette.foreground, palette.muted)
    if styled is not None:
        return styled
    return Text(str(value), style=palette.foreground)


# ------------------------------------------------------------ block graphs
# Glyphs that draw part of a cell: the eighth blocks, the half/quarter blocks
# and the sextants (U+1FB00–U+1FB3B). Everything else in a chart — axis
# labels, ticks, the dots of an empty bar — is scaffolding.
_BLOCK_GLYPHS = set("▁▂▃▄▅▆▇▌▐▀▄▖▗▘▝▚▞▙▛▜▟") | {chr(c) for c in range(0x1FB00, 0x1FB3C)}
FULL_BLOCK = "█"


def block_text(
    lines: str | Sequence[str],
    colour: str,
    edge: str,
    scaffold: str | None = None,
    outline: bool = True,
) -> Text:
    """Chart or bar text with every full block outlined.

    Terminal cells have no borders, so a column of full blocks paints as one
    solid slab. Each full block is drawn instead as a cell filled with
    `colour` whose right edge (the "▕" glyph) and bottom (an underline) are in
    `edge` — the theme's background — so every block reads as its own
    outlined square: stacked blocks are split by the underline of the one
    above, neighbours by the right edge of the one to their left. Partial
    blocks and sextants already leave background showing and are simply
    coloured. `scaffold` colours everything that isn't a block. With
    outline=False full blocks are drawn plain (LIVE AIR's HISTORY column).
    """
    text = Text(no_wrap=True, overflow="crop")
    outlined = f"underline {edge} on {colour}"
    rows = lines.splitlines() if isinstance(lines, str) else list(lines)
    for index, line in enumerate(rows):
        if index:
            text.append("\n")
        for char in line:
            if char == FULL_BLOCK and outline:
                text.append("▕", style=outlined)
            elif char in _BLOCK_GLYPHS or char == FULL_BLOCK:
                text.append(char, style=colour)
            else:
                text.append(char, style=scaffold or colour)
    return text


def short_path(path, limit: int = 0) -> str:
    """A path with the home directory written as ~, and — given a limit —
    its middle elided so it stays on one line."""
    from pathlib import Path

    text = str(path)
    try:
        home = str(Path.home())
        if home not in ("", "/") and text.startswith(home + "/"):
            text = "~" + text[len(home):]
    except Exception:
        pass
    if limit and len(text) > limit:
        keep = max(2, limit - 1)
        text = text[: keep // 2] + "…" + text[len(text) - (keep - keep // 2):]
    return text


def human_int(value) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def truncate(value, limit: int = 96) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"
