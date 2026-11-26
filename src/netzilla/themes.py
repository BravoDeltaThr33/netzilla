"""netzilla colour themes.

Seventeen retro CRT-inspired palettes. Every one uses a dark background;
they differ by which colour dominates. The hex values live here once and are
used two ways:

  1. Registered with Textual as real Theme objects so widget chrome
     (borders, tabs, inputs, buttons) follows the active theme.
  2. Read directly when building Rich renderables for result panels, so
     report text matches the chrome without depending on Textual internals.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class Palette:
    """A single netzilla colour scheme."""

    name: str
    label: str
    background: str   # screen background (always dark)
    surface: str      # input / inner element background
    panel: str        # panel + header/footer background
    primary: str      # the dominant colour of this theme
    secondary: str    # dimmed variant of primary, for labels and rules
    accent: str       # bright highlight, for focused elements and values
    foreground: str   # default body text
    success: str
    warning: str      # consistent gold across all themes for scannability
    error: str
    muted: str        # de-emphasised text (units, footnotes)

    def as_textual_kwargs(self) -> dict:
        data = asdict(self)
        data.pop("label")
        data.pop("muted")
        return data


PALETTES: dict[str, Palette] = {
    "phosphor-green": Palette(
        name="phosphor-green",
        label="Phosphor Green — classic green CRT",
        background="#0A0F0A",
        surface="#0F160E",
        panel="#10160F",
        primary="#33FF33",
        secondary="#1F7A2E",
        accent="#8CFF8C",
        foreground="#C8F5C8",
        success="#33FF33",
        warning="#FFD23F",
        error="#FF4444",
        muted="#4E8055",
    ),
    "amber-phosphor": Palette(
        name="amber-phosphor",
        label="Amber Phosphor — vintage amber monitor",
        background="#120C05",
        surface="#1A1206",
        panel="#1A1206",
        primary="#FFB000",
        secondary="#8C5E00",
        accent="#FFD866",
        foreground="#F2D9A0",
        success="#9EE04A",
        warning="#FF8800",
        error="#FF4444",
        muted="#8A6A2E",
    ),
    "ice-cyan": Palette(
        name="ice-cyan",
        label="Ice Cyan — cold blue terminal",
        background="#060F12",
        surface="#0A171B",
        panel="#0A171B",
        primary="#3DDCFF",
        secondary="#1C6E82",
        accent="#A6F0FF",
        foreground="#C4EBF5",
        success="#4AE0A8",
        warning="#FFD23F",
        error="#FF5C7A",
        muted="#4E8794",
    ),
    "vhs-magenta": Palette(
        name="vhs-magenta",
        label="VHS Magenta — synthwave tape deck",
        background="#0E0714",
        surface="#160C1E",
        panel="#160C1E",
        primary="#D06BFF",
        secondary="#6E3A8C",
        accent="#FF9CEB",
        foreground="#E2CFF0",
        success="#6BFFB8",
        warning="#FFD23F",
        error="#FF4D6D",
        muted="#8460A0",
    ),
    "ember-rust": Palette(
        name="ember-rust",
        label="Ember Rust — burnt orange dashboard",
        background="#120705",
        surface="#1A0B08",
        panel="#1A0B08",
        primary="#FF6A33",
        secondary="#8C3B1E",
        accent="#FFB088",
        foreground="#F0CDBC",
        success="#9EE04A",
        warning="#FFD23F",
        error="#FF2D55",
        muted="#9A5A40",
    ),
    # Carried over from the kwkpass password-manager build so the two tools
    # match: Sapphire Blue, Blue and Ice Blue on a solid black background.
    # All three of those colours appear here exactly, each in the role that
    # suits it — sapphire for titles, blue for labels and borders, ice for
    # the values your eye should land on.
    "sapphire-ice": Palette(
        name="sapphire-ice",
        label="Sapphire Ice — kwkpass blue on black",
        background="#000000",
        surface="#05080F",
        panel="#05080F",
        primary="#0F52BA",
        secondary="#0000FF",
        accent="#D8EBF2",
        foreground="#C7DCE8",
        success="#3DDC84",
        warning="#FFD23F",
        error="#FF4D5E",
        muted="#4A6B85",
    ),
    # ----------------------------------------------------------------------
    # Palettes built from colour strips and retro posters. In every one of
    # these the darkest colour of the source palette is the background, the
    # most saturated is the dominant (primary), and the lightest is body text
    # — washed toward white first when it was a saturated yellow or cyan, so
    # paragraphs do not glow. Every role was checked for contrast against
    # both the background and the panel colour before being written down.
    "sunset-mesa": Palette(
        name="sunset-mesa",
        label="Sunset Mesa — orange, gold and teal",
        background="#1d1b27",
        surface="#2d2b36",
        panel="#2d2b36",
        primary="#ff9f68",
        secondary="#a0684d",
        accent="#ffd07b",
        foreground="#f7f5f2",
        success="#3ddc84",
        warning="#ffd07b",
        error="#ff4d5e",
        muted="#7f7d82",
    ),
    "desert-sage": Palette(
        name="desert-sage",
        label="Desert Sage — coral, cream and sage",
        background="#231f20",
        surface="#322f30",
        panel="#322f30",
        primary="#e3655b",
        secondary="#a3645f",
        accent="#f2d5bf",
        foreground="#f4f1e8",
        success="#3ddc84",
        warning="#ffd23f",
        error="#ff4d5e",
        muted="#817d7a",
    ),
    "miami-night": Palette(
        name="miami-night",
        label="Miami Night — hot pink on deep navy",
        background="#070814",
        surface="#262a3b",
        panel="#262a3b",
        primary="#32e8ff",
        secondary="#208a9c",
        accent="#ff6ec7",
        foreground="#f1f2f6",
        success="#3ddc84",
        warning="#ffd23f",
        error="#ff4d5e",
        muted="#70717a",
    ),
    "arcade-pop": Palette(
        name="arcade-pop",
        label="Arcade Pop — primary red, blue and gold",
        background="#05040f",
        surface="#161620",
        panel="#161620",
        primary="#00c2ff",
        secondary="#02729a",
        accent="#ff3864",
        foreground="#fff6d7",
        success="#3ddc84",
        warning="#ffd447",
        error="#ff4d5e",
        muted="#767169",
    ),
    "neon-mint": Palette(
        name="neon-mint",
        label="Neon Mint — pink and mint on black",
        background="#050611",
        surface="#161722",
        panel="#161722",
        primary="#00f5d4",
        secondary="#029182",
        accent="#ff3c7d",
        foreground="#f5f5f5",
        success="#3ddc84",
        warning="#ffd23f",
        error="#ff4d5e",
        muted="#717278",
    ),
    "vapor-pop": Palette(
        name="vapor-pop",
        label="Vapor Pop — pink, cyan and violet",
        background="#05030b",
        surface="#16151c",
        panel="#16151c",
        primary="#ff4b81",
        secondary="#9e3e5d",
        accent="#866eff",
        foreground="#c7f9ff",
        success="#3ddc84",
        warning="#ffd23f",
        error="#ff4d5e",
        muted="#5c7279",
    ),
    "crt-neon": Palette(
        name="crt-neon",
        label="CRT Neon — pink, mint and yellow",
        background="#111111",
        surface="#222222",
        panel="#222222",
        primary="#ff3366",
        secondary="#aa465f",
        accent="#ffdd33",
        foreground="#d2fff4",
        success="#33ffcc",
        warning="#ffdd33",
        error="#ff4d5e",
        muted="#687c77",
    ),
    "cyber-coral": Palette(
        name="cyber-coral",
        label="Cyber Coral — coral and teal on slate",
        background="#050716",
        surface="#252a34",
        panel="#252a34",
        primary="#08d9d6",
        secondary="#078185",
        accent="#ff2e63",
        foreground="#f8f3ff",
        success="#3ddc84",
        warning="#ffd23f",
        error="#ff4d5e",
        muted="#72717f",
    ),
    "route-66": Palette(
        name="route-66",
        label="Route 66 — brick red and roadside tan",
        background="#37342d",
        surface="#45423c",
        panel="#45423c",
        primary="#e6867b",
        secondary="#ab7b73",
        accent="#c4ae8e",
        foreground="#eacea7",
        success="#3ddc84",
        warning="#ffd23f",
        error="#ff7482",
        muted="#928470",
    ),
    "space-1975": Palette(
        name="space-1975",
        label="Space 1975 — rocket orange on deep teal",
        background="#1d313c",
        surface="#2d3f4a",
        panel="#2d3f4a",
        primary="#f6723a",
        secondary="#aa7059",
        accent="#6bb1b8",
        foreground="#fadac1",
        success="#3ddc84",
        warning="#ffd23f",
        error="#d87d7c",
        muted="#807d78",
    ),
    "disco-70s": Palette(
        name="disco-70s",
        label="Disco 70s — mint, cream and burnt orange",
        background="#383431",
        surface="#46423f",
        panel="#46423f",
        primary="#e98352",
        secondary="#ae7b61",
        accent="#79c39e",
        foreground="#ead1b5",
        success="#3ddc84",
        warning="#ffd23f",
        error="#ff7482",
        muted="#928678",
    ),
}



DEFAULT_THEME = "phosphor-green"

THEME_NAMES = list(PALETTES)


def get_palette(name: str | None) -> Palette:
    """Return a palette by name, falling back to the default."""
    if name and name in PALETTES:
        return PALETTES[name]
    return PALETTES[DEFAULT_THEME]


def build_textual_themes():
    """Build Textual Theme objects from the palettes.

    Imported lazily so that non-TUI entry points (``--no-tui``) never need
    Textual loaded.
    """
    from textual.theme import Theme

    themes = []
    for palette in PALETTES.values():
        kwargs = palette.as_textual_kwargs()
        themes.append(
            Theme(
                dark=True,
                variables={
                    "border": palette.secondary,
                    "border-blurred": palette.secondary,
                    "block-cursor-foreground": palette.background,
                    "block-cursor-background": palette.primary,
                    "input-selection-background": f"{palette.accent} 35%",
                    "footer-key-foreground": palette.accent,
                    "footer-description-foreground": palette.foreground,
                },
                **kwargs,
            )
        )
    return themes
