"""The window's fonts and its cell size.

Letters come from JetBrains Mono — Ghostty's own default font, bundled in
data/fonts (SIL Open Font License, its text is beside the files) — so the
window looks like netzilla in Ghostty on every PC. Anything JetBrains Mono
has no glyph for (✔ ✘ ☞, other scripts, emoji) comes from the system's own
symbol fonts, the way terminals fall back: Segoe UI Symbol and Segoe UI
Emoji on Windows, DejaVu and Noto on Linux, Apple Symbols on macOS.

Box drawing, blocks, sextants and braille never come from a font: glyphs.py
draws them to the cell.

The cell is measured from the font as Ghostty measures it: the advance of
"M" across, ascender + descender down (not the rounded-up FreeType metrics,
which make every line a pixel taller than Ghostty's).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from .. import hostos

DATA = Path(__file__).resolve().parent.parent / "data" / "fonts"
BUNDLED = {
    # The "NL" files: the same letters without the ligature tables, which a
    # terminal draws one cell at a time anyway.
    "regular": DATA / "JetBrainsMonoNL-Regular.ttf",
    "bold": DATA / "JetBrainsMonoNL-Bold.ttf",
}

# Fallback fonts by file name, best first, for characters the main font
# lacks. Missing files are skipped.
FALLBACKS = {
    "windows": ("seguisym.ttf", "consola.ttf", "cambria.ttc", "segoeui.ttf",
                "arialuni.ttf", "msgothic.ttc", "YuGothR.ttc", "msyh.ttc", "simsun.ttc",
                "malgun.ttf", "Nirmala.ttf", "ebrima.ttf", "arial.ttf"),
    "linux": ("DejaVuSansMono.ttf", "DejaVuSans.ttf", "NotoSansMono-Regular.ttf",
              "NotoSansSymbols2-Regular.ttf", "NotoSansSymbols-Regular.ttf",
              "NotoSans-Regular.ttf", "FreeMono.ttf", "FreeSerif.ttf",
              "NotoSansCJK-Regular.ttc", "wqy-zenhei.ttc", "fonts-japanese-gothic.ttf",
              "LiberationMono-Regular.ttf"),
    "macos": ("Menlo.ttc", "Apple Symbols.ttf", "Arial Unicode.ttf", "STHeiti Light.ttc",
              "Hiragino Sans GB.ttc", "Geneva.ttf"),
}
EMOJI = {
    "windows": ("seguiemj.ttf",),
    "linux": ("NotoColorEmoji.ttf",),
    "macos": ("Apple Color Emoji.ttc",),
}

MIN_PX, MAX_PX = 8, 64


def font_dirs() -> list[Path]:
    """Where this system keeps its fonts."""
    home = Path.home()
    if hostos.is_windows():
        windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
        dirs = [windir / "Fonts"]
        local = os.environ.get("LOCALAPPDATA")
        if local:
            dirs.append(Path(local) / "Microsoft" / "Windows" / "Fonts")
        return dirs
    if hostos.is_macos():
        return [Path("/System/Library/Fonts"), Path("/System/Library/Fonts/Supplemental"),
                Path("/Library/Fonts"), home / "Library" / "Fonts"]
    data_home = Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share")
    return [Path("/usr/share/fonts"), Path("/usr/local/share/fonts"),
            data_home / "fonts", home / ".fonts"]


@lru_cache(maxsize=1)
def _index() -> dict[str, Path]:
    """Every font file on the system, by lower-case file name."""
    found: dict[str, Path] = {}
    for root in font_dirs():
        if not root.is_dir():
            continue
        for folder, _dirs, files in os.walk(root):
            for name in files:
                if name.lower().endswith((".ttf", ".ttc", ".otf")):
                    found.setdefault(name.lower(), Path(folder) / name)
    return found


def find(name: str) -> Path | None:
    """A font by path or by file name ('consola.ttf', 'DejaVuSans.ttf')."""
    if not name:
        return None
    path = Path(name).expanduser()
    if path.is_file():
        return path
    return _index().get(path.name.lower())


def _system() -> str:
    return hostos.NAME if hostos.NAME in FALLBACKS else "linux"


@lru_cache(maxsize=64)
def _load(path: str, px: int):
    try:
        return ImageFont.truetype(path, px)
    except Exception:
        return None


@lru_cache(maxsize=16)
def _ratios(path: str) -> tuple[float, float, float]:
    """(advance of M, ascender, descender) per pixel of font size, read at a
    large size so rounding doesn't creep in."""
    font = _load(path, 1000)
    if font is None:
        return 0.6, 1.02, 0.30
    ascent, descent = font.font.ascent, font.font.descent
    return font.getlength("M") / 1000, ascent / 1000, abs(descent) / 1000


@lru_cache(maxsize=64)
def _notdef(font) -> bytes:
    """What `font` draws for a character it doesn't have."""
    return _draw_probe(font, "\U0010FFFF")


def _draw_probe(font, char: str) -> bytes:
    size = max(8, int(getattr(font, "size", 16)))
    image = Image.new("L", (size * 2, size * 2), 0)
    try:
        ImageDraw.Draw(image).text((size // 2, size // 2), char, font=font, fill=255)
    except Exception:
        return b"\x00"
    return image.tobytes()


def has_glyph(font, char: str) -> bool:
    """True when `font` has a glyph of its own for `char` (not the
    missing-glyph box): Pillow has no character-map lookup, so the two
    drawings are compared."""
    drawn = _draw_probe(font, char)
    if drawn == _notdef(font):
        return char.isspace()
    return True


class FontSet:
    """The fonts at one pixel size, the cell they make, and which font draws
    each character."""

    def __init__(self, px: int, main: str = "") -> None:
        self.px = max(MIN_PX, min(MAX_PX, int(px)))
        custom = find(main) if main else None
        regular = str(custom or BUNDLED["regular"])
        bold = str(BUNDLED["bold"]) if custom is None else regular
        self.regular = _load(regular, self.px) or ImageFont.load_default(self.px)
        self.bold = _load(bold, self.px) or self.regular
        self.synthetic_bold = bold == regular and custom is not None
        advance, ascent, descent = _ratios(regular)
        self.cell_w = max(1, round(advance * self.px))
        self.cell_h = max(2, round((ascent + descent) * self.px))
        self.baseline = self.cell_h - round(descent * self.px)
        self.underline_y = min(self.cell_h - 1, self.baseline + max(1, round(self.px * 0.1)))
        self.line_px = max(1, round(self.px / 15))
        system = _system()
        self._fallback_names = FALLBACKS[system]
        self._emoji_names = EMOJI[system]
        self._fallbacks: list | None = None
        self._emoji: list | None = None
        self._choice: dict[tuple[str, bool], tuple] = {}

    @property
    def cell(self) -> tuple[int, int]:
        return self.cell_w, self.cell_h

    def _fallback_fonts(self) -> list:
        if self._fallbacks is None:
            fonts = []
            for name in self._fallback_names:
                path = find(name)
                font = _load(str(path), self.px) if path else None
                if font is not None:
                    fonts.append(font)
            self._fallbacks = fonts
        return self._fallbacks

    def _emoji_fonts(self) -> list:
        if self._emoji is None:
            fonts = []
            for name in self._emoji_names:
                path = find(name)
                if not path:
                    continue
                # Colour bitmap fonts (Noto Color Emoji) come in one size.
                font = _load(str(path), self.px) or _load(str(path), 109)
                if font is not None:
                    fonts.append(font)
            self._emoji = fonts
        return self._emoji

    def pick(self, cluster: str, bold: bool = False) -> tuple:
        """(font, colour?) to draw `cluster` with: the main font when it has
        the character, else the first fallback that does."""
        key = (cluster, bold)
        choice = self._choice.get(key)
        if choice is not None:
            return choice
        base = cluster[0]
        main = self.bold if bold else self.regular
        emoji_wanted = "\ufe0f" in cluster or (ord(base) >= 0x1F000 and ord(base) not in
                                               range(0x1FB00, 0x1FC00))
        choice = None
        if emoji_wanted:
            for font in self._emoji_fonts():
                if has_glyph(font, base):
                    choice = (font, True)
                    break
        if choice is None and has_glyph(main, base):
            choice = (main, False)
        if choice is None:
            for font in self._fallback_fonts():
                if has_glyph(font, base):
                    choice = (font, False)
                    break
        if choice is None and not emoji_wanted:
            for font in self._emoji_fonts():
                if has_glyph(font, base):
                    choice = (font, True)
                    break
        if choice is None:
            choice = (main, False)
        self._choice[key] = choice
        return choice


def fit_px(cols: int, rows: int, width: int, height: int, main: str = "",
           ceiling: int = MAX_PX) -> int:
    """The largest font size whose cells fit cols x rows into width x height
    pixels (at least MIN_PX)."""
    regular = str(find(main) or BUNDLED["regular"]) if main else str(BUNDLED["regular"])
    advance, ascent, descent = _ratios(regular)
    best = MIN_PX
    for px in range(MIN_PX, max(MIN_PX, ceiling) + 1):
        cell_w = max(1, round(advance * px))
        cell_h = max(2, round((ascent + descent) * px))
        if cell_w * cols <= width and cell_h * rows <= height:
            best = px
    return best


__all__ = ["FontSet", "BUNDLED", "FALLBACKS", "EMOJI", "find", "has_glyph", "fit_px",
           "font_dirs", "MIN_PX", "MAX_PX"]
