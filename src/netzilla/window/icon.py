"""netzilla's icon: the N of the DASH banner, drawn the way DASH draws its
title in pixels (lit block letters, their box-drawing shadow, phosphor glow
and scanlines) in the phosphor-green theme, on a dark rounded square.

The same picture is the window's icon and, saved as an .ico, the Windows
.exe's (packaging/build_exe.py writes it at build time, so no picture
file has to live in the repository).
"""

from __future__ import annotations

from functools import lru_cache

from PIL import Image, ImageDraw

from ..graphics import plot
from ..themes import DEFAULT_THEME, get_palette

# The first letter of the DASH banner (screens/dashboard.py _ART).
LETTER = (
    "███╗   ██╗",
    "████╗  ██║",
    "██╔██╗ ██║",
    "██║╚██╗██║",
    "██║ ╚████║",
    "╚═╝  ╚═══╝",
)
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)


@lru_cache(maxsize=8)
def icon_image(size: int = 256, theme: str = DEFAULT_THEME) -> Image.Image:
    """The icon as an RGBA square `size` pixels across."""
    palette = get_palette(theme)
    big = 512
    cols, rows = len(LETTER[0]), len(LETTER)
    cell_w, cell_h = 36, 72                      # 10 x 6 cells: 360 x 432
    frame = plot.Frame(cols, rows, cell_w, cell_h)
    art = plot.logo_image(list(LETTER), frame,
                          plot.Theme(background=palette.background, grid=palette.muted,
                                     text=palette.foreground, accent=palette.accent),
                          [palette.primary, palette.accent, palette.success])
    art = art.convert("RGB")
    square = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    plate = Image.new("RGBA", (big, big), plot.rgb(palette.background) + (255,))
    shape = Image.new("L", (big, big), 0)
    ImageDraw.Draw(shape).rounded_rectangle([0, 0, big - 1, big - 1], radius=big // 7,
                                            fill=255)
    square.paste(plate, (0, 0), shape)
    # the letter, centred a little high (its shadow row hangs below)
    x = (big - art.width) // 2
    y = (big - art.height) // 2
    inner = Image.new("L", art.size, 255)
    square.paste(art, (x, y), inner)
    square.putalpha(Image.composite(shape, Image.new("L", (big, big), 0), shape))
    return square.resize((size, size), Image.LANCZOS)


def save_ico(path, theme: str = DEFAULT_THEME) -> None:
    """The icon as a Windows .ico with every size Windows asks for."""
    image = icon_image(256, theme)
    image.save(path, format="ICO", sizes=[(s, s) for s in ICO_SIZES])


__all__ = ["icon_image", "save_ico", "LETTER", "ICO_SIZES"]
