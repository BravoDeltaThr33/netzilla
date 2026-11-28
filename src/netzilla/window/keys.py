"""Keyboard and mouse, from tkinter's events to what a terminal would send.

The window turns every key press and mouse action into the bytes Ghostty
sends Textual — the kitty keyboard protocol for keys with modifiers and for
the special keys, SGR mouse reports for the mouse — and hands them to
Textual's own input parser. Keys therefore reach netzilla with the same
names they have on Linux (ctrl+t, shift+tab, f3, escape…).

A few keys belong to the window itself: Ctrl + and Ctrl − change the text
size, Ctrl 0 puts it back, F11 and Alt+Enter switch full screen, and Ctrl+V,
Shift+Insert and Ctrl+Shift+V paste from the clipboard.

Nothing here touches tkinter: events are passed in as keysym, character and
modifier state, so it is all tested headless.
"""

from __future__ import annotations

from typing import NamedTuple

SHIFT, ALT, CTRL, SUPER = 1, 2, 4, 8          # kitty modifier bits

# Tk's event.state bits per system: (shift, ctrl, alt, super).
_TK_MASKS = {
    "windows": (0x0001, 0x0004, 0x20000, 0x0040),
    "macos": (0x0001, 0x0004, 0x0010, 0x0008),
    "linux": (0x0001, 0x0004, 0x0008, 0x0040),
}
BUTTON_MASKS = {1: 0x0100, 2: 0x0200, 3: 0x0400}

# Keys with a kitty "CSI number ; modifiers ~" or "CSI 1 ; modifiers <letter>"
# form; the letter forms drop the 1 when there are no modifiers.
_FUNCTIONAL = {
    "Up": "A", "Down": "B", "Right": "C", "Left": "D", "Home": "H", "End": "F",
    "KP_Up": "A", "KP_Down": "B", "KP_Right": "C", "KP_Left": "D",
    "KP_Home": "H", "KP_End": "F", "KP_Begin": "E",
    "F1": "P", "F2": "Q", "F3": "R", "F4": "S",
    "Insert": 2, "KP_Insert": 2, "Delete": 3, "KP_Delete": 3,
    "Prior": 5, "Page_Up": 5, "KP_Prior": 5, "KP_Page_Up": 5,
    "Next": 6, "Page_Down": 6, "KP_Next": 6, "KP_Page_Down": 6,
    "F5": 15, "F6": 17, "F7": 18, "F8": 19, "F9": 20, "F10": 21, "F11": 23, "F12": 24,
}
# Keys sent as "CSI codepoint ; modifiers u".
_CODEPOINT = {
    "Return": 13, "KP_Enter": 13, "Tab": 9, "ISO_Left_Tab": 9, "BackSpace": 127,
    "Escape": 27, "Menu": 57363, "App": 57363,
    **{f"F{n}": 57376 + n - 13 for n in range(13, 36)},
}
# Plain keys whose legacy byte Textual reads the same way as the kitty form.
_LEGACY = {"Return": "\r", "KP_Enter": "\r", "Tab": "\t", "BackSpace": "\x7f"}
_MODIFIER_KEYS = {
    "Shift_L", "Shift_R", "Control_L", "Control_R", "Alt_L", "Alt_R", "Meta_L", "Meta_R",
    "Super_L", "Super_R", "Hyper_L", "Hyper_R", "Caps_Lock", "Num_Lock", "Scroll_Lock",
    "ISO_Level3_Shift", "ISO_Level5_Shift", "Mode_switch", "Win_L", "Win_R",
}


class KeyAction(NamedTuple):
    """What a key press does: kind is "text" (type it), "keys" (an escape
    sequence for Textual's parser), "window" (a window action: zoom_in,
    zoom_out, zoom_reset, fullscreen, paste) or "" (nothing)."""

    kind: str
    value: str = ""


NOTHING = KeyAction("")


def modifiers(state: int, system: str = "linux") -> int:
    """Kitty modifier bits from a Tk event.state."""
    shift, ctrl, alt, super_ = _TK_MASKS.get(system, _TK_MASKS["linux"])
    bits = 0
    if state & shift:
        bits |= SHIFT
    if state & ctrl:
        bits |= CTRL
    if state & alt:
        bits |= ALT
    if state & super_:
        bits |= SUPER
    return bits


def _printable(char: str) -> bool:
    return bool(char) and all(c >= " " and c != "\x7f" for c in char)


def window_action(keysym: str, mods: int) -> str:
    """A key the window handles itself, or ''."""
    ctrl_only = mods & CTRL and not mods & (ALT | SUPER)
    if ctrl_only and keysym in ("plus", "equal", "KP_Add"):
        return "zoom_in"
    if ctrl_only and keysym in ("minus", "underscore", "KP_Subtract"):
        return "zoom_out"
    if ctrl_only and keysym in ("0", "KP_0", "KP_Insert"):
        return "zoom_reset"
    if keysym == "F11" and not mods:
        return "fullscreen"
    if keysym in ("Return", "KP_Enter") and mods == ALT:
        return "fullscreen"
    if keysym in ("v", "V") and mods in (CTRL, CTRL | SHIFT):
        return "paste"
    if keysym in ("Insert", "KP_Insert") and mods == SHIFT:
        return "paste"
    return ""


def key_action(keysym: str, char: str, state: int, system: str = "linux",
               keysym_num: int = 0) -> KeyAction:
    """What one Tk <KeyPress> means."""
    if keysym in _MODIFIER_KEYS:
        return NOTHING
    mods = modifiers(state, system)
    action = window_action(keysym, mods)
    if action:
        return KeyAction("window", action)
    # AltGr (Ctrl+Alt on Windows) and macOS's Option compose characters:
    # what they produce is typed, not treated as a shortcut.
    composed = (system == "windows" and mods & CTRL and mods & ALT) or \
        (system == "macos" and mods & ALT and not mods & CTRL)
    if keysym == "ISO_Left_Tab":
        mods |= SHIFT
    if keysym in _FUNCTIONAL:
        code = _FUNCTIONAL[keysym]
        if isinstance(code, int):
            return KeyAction("keys", f"\x1b[{code};{mods + 1}~" if mods else f"\x1b[{code}~")
        return KeyAction("keys", f"\x1b[1;{mods + 1}{code}" if mods else f"\x1b[{code}")
    if keysym in _CODEPOINT:
        code = _CODEPOINT[keysym]
        if not mods and keysym in _LEGACY:
            return KeyAction("keys", _LEGACY[keysym])
        return KeyAction("keys", f"\x1b[{code};{mods + 1}u" if mods else f"\x1b[{code}u")
    text_mods = mods & ~SHIFT
    if _printable(char) and (not text_mods or composed):
        return KeyAction("text", char)
    if mods & (CTRL | ALT | SUPER):
        base = _base_codepoint(keysym, char, keysym_num)
        if base:
            return KeyAction("keys", f"\x1b[{base};{mods + 1}u")
    if _printable(char):
        return KeyAction("text", char)
    return NOTHING


_KEYSYM_CHARS = {
    "space": " ", "minus": "-", "equal": "=", "plus": "+", "comma": ",", "period": ".",
    "slash": "/", "backslash": "\\", "semicolon": ";", "apostrophe": "'", "grave": "`",
    "bracketleft": "[", "bracketright": "]", "underscore": "_", "exclam": "!",
    "at": "@", "numbersign": "#", "dollar": "$", "percent": "%", "asciicircum": "^",
    "ampersand": "&", "asterisk": "*", "parenleft": "(", "parenright": ")",
    "colon": ":", "quotedbl": '"', "less": "<", "greater": ">", "question": "?",
    "bar": "|", "braceleft": "{", "braceright": "}", "asciitilde": "~",
    "KP_Add": "+", "KP_Subtract": "-", "KP_Multiply": "*", "KP_Divide": "/",
    "KP_Decimal": ".", "KP_Equal": "=",
    **{f"KP_{n}": str(n) for n in range(10)},
}


def _base_codepoint(keysym: str, char: str, keysym_num: int = 0) -> int:
    """The codepoint kitty reports for a key pressed with Ctrl or Alt: the
    key's own (lower-case) character, not the control code Ctrl makes."""
    if len(keysym) == 1:
        return ord(keysym.lower())
    if keysym in _KEYSYM_CHARS:
        return ord(_KEYSYM_CHARS[keysym])
    if 0x20 <= keysym_num < 0x100:
        return ord(chr(keysym_num).lower())
    if _printable(char) and len(char) == 1:
        return ord(char.lower())
    return 0


# ------------------------------------------------------------------ mouse
def mouse_sequence(kind: str, button: int, col: int, row: int, mods: int = 0) -> str:
    """An SGR mouse report. kind: press, release, move (button 0 = none
    held), wheel_up, wheel_down, wheel_left, wheel_right; button 1 left,
    2 middle, 3 right; col and row from 0."""
    code = 0
    if kind.startswith("wheel_"):
        code = 64 + ("up", "down", "left", "right").index(kind[6:])
    elif kind == "move":
        code = 32 + (button - 1 if button else 3)
    else:
        code = max(0, button - 1)
    if mods & SHIFT:
        code |= 4
    if mods & ALT:
        code |= 8
    if mods & CTRL:
        code |= 16
    final = "m" if kind == "release" else "M"
    return f"\x1b[<{code};{max(0, col) + 1};{max(0, row) + 1}{final}"


def held_button(state: int) -> int:
    """The mouse button held during a motion event (0 for none)."""
    for button, mask in BUTTON_MASKS.items():
        if state & mask:
            return button
    return 0


__all__ = ["KeyAction", "key_action", "window_action", "modifiers", "mouse_sequence",
           "held_button", "SHIFT", "ALT", "CTRL", "SUPER"]
