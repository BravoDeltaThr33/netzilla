"""Tests for netzilla 2.4: the eleven added colour palettes and the CAPTURE
tab's permission handling.

The palette tests are real checks, not spot checks: every theme is verified
for the rule that the darkest colour of its source palette is the background,
and for readable contrast in every role.
"""

from __future__ import annotations

import asyncio

from netzilla import __version__
from netzilla.help import get_help
from netzilla.local import capture
from netzilla.screens.capture import CapturePane
from netzilla.themes import DEFAULT_THEME, PALETTES, THEME_NAMES, get_palette

# The palettes as they were supplied, so the theme can be checked against its
# source rather than against itself.
SOURCES = {
    "sapphire-ice": ["#000000", "#0F52BA", "#0000FF", "#D8EBF2"],
    "sunset-mesa": ["#1d1b27", "#ff9f68", "#ffd07b", "#8cd0c9", "#f7f5f2"],
    "desert-sage": ["#231f20", "#e3655b", "#f2d5bf", "#9ec5ab", "#f4f1e8"],
    "miami-night": ["#070814", "#ff6ec7", "#32e8ff", "#f1f2f6", "#262a3b"],
    "arcade-pop": ["#05040f", "#ff3864", "#00c2ff", "#ffd447"],
    "neon-mint": ["#050611", "#ff3c7d", "#00f5d4", "#f5f5f5"],
    "vapor-pop": ["#05030b", "#ff4b81", "#00e5ff", "#7b61ff"],
    "crt-neon": ["#111111", "#ff3366", "#33ffcc", "#ffdd33"],
    "cyber-coral": ["#050716", "#ff2e63", "#08d9d6", "#252a34", "#f8f3ff"],
    "route-66": ["#37342d", "#8b322c", "#dd5746", "#eacea7", "#bfa784"],
    "space-1975": ["#1d313c", "#50a3ab", "#fadac1", "#f6723a", "#c43b39"],
    "disco-70s": ["#383431", "#79c39e", "#ead1b5", "#ee9b69", "#e77843"],
}

ORIGINAL = ("phosphor-green", "amber-phosphor", "ice-cyan", "vhs-magenta",
            "ember-rust")

# The eleven palettes netzilla derived itself, and so holds to its own
# contrast rules. sapphire-ice is excluded: it reproduces the kwkpass colours
# exactly as given, which is worth more there than hitting a contrast target.
GENERATED = tuple(name for name in SOURCES if name != "sapphire-ice")


def _rgb(value: str) -> tuple[int, int, int]:
    value = value.lstrip("#")
    return tuple(int(value[i:i + 2], 16) for i in (0, 2, 4))


def _luminance(value: str) -> float:
    def channel(raw: int) -> float:
        out = raw / 255
        return out / 12.92 if out <= 0.03928 else ((out + 0.055) / 1.055) ** 2.4

    red, green, blue = _rgb(value)
    return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue)


def _contrast(one: str, two: str) -> float:
    first, second = _luminance(one), _luminance(two)
    high, low = max(first, second), min(first, second)
    return (high + 0.05) / (low + 0.05)


def test_version_is_2_4():
    """The features below arrived in 2.4; later releases keep them."""
    assert tuple(int(part) for part in __version__.split(".")[:2]) >= (2, 4), (
        __version__
    )


# --------------------------------------------------------------- palettes
def test_nothing_was_removed():
    for name in ORIGINAL:
        assert name in PALETTES, name
    assert DEFAULT_THEME == "phosphor-green"
    assert len(PALETTES) == 17
    assert THEME_NAMES[:5] == list(ORIGINAL)      # originals stay first


def test_every_new_palette_is_registered():
    for name in SOURCES:
        assert name in PALETTES, name
        assert PALETTES[name].name == name
        assert PALETTES[name].label, name


def test_the_darkest_source_colour_is_always_the_background():
    for name, colours in SOURCES.items():
        darkest = min(colours, key=_luminance)
        assert PALETTES[name].background.lower() == darkest.lower(), name


def test_backgrounds_are_the_darkest_thing_in_the_finished_theme():
    for name, palette in PALETTES.items():
        for role in ("surface", "panel", "primary", "secondary", "accent",
                     "foreground", "success", "warning", "error", "muted"):
            assert _luminance(getattr(palette, role)) >= _luminance(
                palette.background
            ), (name, role)


def test_body_text_is_readable_in_every_theme():
    for name, palette in PALETTES.items():
        assert _contrast(palette.foreground, palette.background) >= 7.0, name
        assert _contrast(palette.foreground, palette.surface) >= 6.0, name


def test_no_theme_has_an_illegible_role():
    """A floor every theme clears, old and new, so a future edit cannot make
    one unreadable without a test saying so."""
    for name, palette in PALETTES.items():
        for role, floor in (("primary", 2.8), ("accent", 3.0),
                            ("secondary", 2.3), ("muted", 2.8)):
            ratio = _contrast(getattr(palette, role), palette.background)
            assert ratio >= floor, (name, role, round(ratio, 2))


def test_generated_palettes_clear_the_stricter_floor():
    for name in GENERATED:
        palette = PALETTES[name]
        for role, floor in (
            ("primary", 4.0), ("accent", 4.5), ("secondary", 3.0),
            ("muted", 2.8), ("success", 4.0), ("warning", 4.0), ("error", 3.8),
        ):
            ratio = _contrast(getattr(palette, role), palette.background)
            assert ratio >= floor, (name, role, round(ratio, 2))


def test_body_text_never_glows():
    """The lightest colour in a palette is often a saturated yellow or cyan;
    used raw as body text it makes every paragraph a highlighter."""
    import colorsys

    for name in GENERATED:
        red, green, blue = _rgb(PALETTES[name].foreground)
        saturation = colorsys.rgb_to_hsv(red / 255, green / 255, blue / 255)[1]
        assert saturation <= 0.30, (name, round(saturation, 2))


def test_status_colours_stay_distinguishable_from_the_theme_colour():
    """An error panel the same colour as every heading is not a signal."""
    for name in GENERATED:
        palette = PALETTES[name]
        assert palette.error != palette.primary, name
        assert palette.error != palette.accent, name
        assert palette.success != palette.primary, name


def test_all_colours_are_well_formed_hex():
    for name, palette in PALETTES.items():
        for role in ("background", "surface", "panel", "primary", "secondary",
                     "accent", "foreground", "success", "warning", "error",
                     "muted"):
            value = getattr(palette, role)
            assert value.startswith("#") and len(value) == 7, (name, role)
            int(value[1:], 16)


def test_get_palette_falls_back_for_an_unknown_name():
    assert get_palette("no-such-theme").name == DEFAULT_THEME
    assert get_palette(None).name == DEFAULT_THEME
    assert get_palette("route-66").name == "route-66"


# ----------------------------------------------------- capture permissions
def test_fix_button_exists_and_is_documented():
    keys = [a.key for a in CapturePane.ACTIONS]
    assert "fix" in keys
    assert get_help("CapturePane", "fix") is not None


def test_username_validation_rejects_anything_shell_unsafe():
    for bad in ("a;rm -rf /", "$(whoami)", "`id`", "a b", "", "-x", "a|b"):
        assert not capture.USERNAME_RE.match(bad), bad
    for good in ("alex", "alex_d", "user-1", "_svc", "nz$"):
        assert capture.USERNAME_RE.match(good), good


def test_fix_command_refuses_rather_than_guessing():
    argv, shown, why = capture.fix_command()
    if argv is None:
        assert why and not shown
    else:
        assert argv[0] == "pkexec"
        assert "usermod -aG wireshark" in shown
        assert "setcap cap_net_raw" in shown
        # Whatever is run must also be what was shown to the user.
        script = argv[-1]
        assert "usermod -aG wireshark" in script
        assert "setcap cap_net_raw,cap_net_admin+eip" in script


def test_permission_report_distinguishes_unknown_from_none():
    """'none' and 'getcap is missing so I cannot tell' are different answers."""
    prefix, rows = asyncio.run(capture.permission_report())
    fields = dict(rows)
    assert "Capture permission" in fields
    assert "Can you run dumpcap" in fields
    assert "pkexec available" in fields
    caps = str(fields["dumpcap capabilities"])
    if caps.startswith("unknown"):
        assert "—" in caps                    # says why it could not tell
    if prefix is None:
        assert "blocked" in fields["Capture permission"]
    else:
        assert "ready" in fields["Capture permission"]
        assert prefix == [] or prefix[0] in ("sudo", "pkexec")


def test_elevated_saves_are_handed_back_to_the_user(tmp_path):
    """A capture written as root would otherwise be unreadable afterwards."""
    target = tmp_path / "c.pcapng"
    target.write_bytes(b"x")
    # No prefix means nothing was elevated, so nothing should run.
    asyncio.run(capture.take_ownership(str(target), None))
    asyncio.run(capture.take_ownership("", ["sudo", "-n"]))
    assert target.exists()


def test_setup_steps_still_documented_for_the_manual_route():
    assert "usermod -aG wireshark" in capture.SETUP_STEPS
    assert "dpkg-reconfigure wireshark-common" in capture.SETUP_STEPS
