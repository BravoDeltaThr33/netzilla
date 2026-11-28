"""Which image protocol pixel graphs use in this run: kitty or Sixel.

Everything that draws a picture asks this module, never kitty.py or sixel.py
directly, so a graph, the DASH banner and its breath work the same through
either: an image is uploaded (show / Canvas.upload) and the text where it
belongs is built from cells (placeholder_text / _rows / _span) — kitty's
Unicode placeholders, or Sixel's marker cells that the overlay draws over.
"""

from __future__ import annotations

from . import kitty, sixel

KITTY = "kitty"
SIXEL = "sixel"
_protocol = KITTY


def use(protocol: str) -> None:
    global _protocol
    _protocol = SIXEL if protocol == SIXEL else KITTY


def protocol() -> str:
    return _protocol


def module():
    return sixel if _protocol == SIXEL else kitty


def set_writer(writer, tmux: bool = False) -> None:
    """Point the protocol in use at the terminal; the other one is switched
    off, so nothing is ever drawn twice."""
    if _protocol == SIXEL:
        sixel.set_writer(writer)
        if writer is not None:
            kitty.set_writer(None)
    else:
        kitty.set_writer(writer, tmux=tmux)
        if writer is not None:
            sixel.set_writer(None)


def active() -> bool:
    return module().active()


def Canvas():
    return module().Canvas()


def show(png, cols: int, rows: int) -> int:
    return module().show(png, cols, rows)


def delete(image_id: int) -> None:
    module().delete(image_id)


def delete_all() -> None:
    kitty.delete_all()
    sixel.delete_all()


def placeholder_text(image_id: int, cols: int, rows: int):
    return module().placeholder_text(image_id, cols, rows)


def placeholder_rows(image_id: int, cols: int, rows: int):
    return module().placeholder_rows(image_id, cols, rows)


def placeholder_span(image_id: int, row: int, first: int, last: int):
    return module().placeholder_span(image_id, row, first, last)


__all__ = ["KITTY", "SIXEL", "use", "protocol", "module", "set_writer", "active", "Canvas",
           "show", "delete", "delete_all", "placeholder_text", "placeholder_rows",
           "placeholder_span"]
