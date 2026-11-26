"""Static checks on netzilla.tcss, for the errors Textual only finds at launch.

Textual abandons the whole stylesheet at the first bad value, so one wrong
declaration stops the application from starting — which is how 2.5.0 shipped
with `align: horizontal center` (that property takes a horizontal AND a
vertical keyword) and died at launch.

tests/test_smoke.py catches this properly by starting the app, but it needs
Textual installed. These checks are pure text parsing and run anywhere, which
means they also run in environments where the real thing cannot be installed.
"""

from __future__ import annotations

import re
from pathlib import Path

import netzilla

STYLESHEET = Path(netzilla.__file__).with_name("netzilla.tcss")

HORIZONTAL = {"left", "center", "right"}
VERTICAL = {"top", "middle", "bottom"}
BORDERS = {
    "none", "hidden", "ascii", "blank", "dashed", "double", "heavy", "hkey",
    "inner", "outer", "round", "solid", "tall", "thick", "vkey", "wide",
    "panel", "tab",
}
TEXT_STYLES = {
    "none", "bold", "italic", "reverse", "strike", "underline", "blink", "dim",
}
SIZE = re.compile(r"^(auto|\d+(\.\d+)?(fr|%|w|h|vw|vh)?)$")


def declarations() -> list[tuple[str, str, str]]:
    """[(selector, property, value)] for every declaration in the stylesheet."""
    text = re.sub(r"/\*.*?\*/", "", STYLESHEET.read_text(), flags=re.S)
    found = []
    for block in re.finditer(r"([^{}]+)\{([^{}]*)\}", text):
        selector = block.group(1).strip().splitlines()[-1].strip()
        for line in block.group(2).splitlines():
            line = line.strip().rstrip(";")
            if not line or ":" not in line:
                continue
            prop, _, value = line.partition(":")
            found.append((selector, prop.strip(), value.strip()))
    return found


def check(selector: str, prop: str, value: str) -> str:
    """"" when the declaration looks valid, otherwise what is wrong with it."""
    tokens = value.split()
    if not tokens:
        return "no value"
    if prop in ("align", "content-align"):
        if len(tokens) != 2:
            return "needs exactly two values: <horizontal> <vertical>"
        if tokens[0] not in HORIZONTAL:
            return f"'{tokens[0]}' is not left/center/right"
        if tokens[1] not in VERTICAL:
            return f"'{tokens[1]}' is not top/middle/bottom"
    elif prop in ("align-horizontal", "content-align-horizontal"):
        if len(tokens) != 1 or tokens[0] not in HORIZONTAL:
            return "needs one of left/center/right"
    elif prop in ("align-vertical", "content-align-vertical"):
        if len(tokens) != 1 or tokens[0] not in VERTICAL:
            return "needs one of top/middle/bottom"
    elif prop in ("border", "outline", "border-top", "border-bottom",
                  "border-left", "border-right"):
        if tokens[0] not in BORDERS:
            return f"'{tokens[0]}' is not a border type"
    elif prop.endswith(("-title-align", "-subtitle-align")):
        if tokens[0] not in HORIZONTAL:
            return "needs one of left/center/right"
    elif prop == "text-style" or prop.endswith(("-title-style", "-subtitle-style")):
        for token in tokens:
            if token not in TEXT_STYLES:
                return f"'{token}' is not a text style"
    elif prop == "display":
        if tokens not in (["block"], ["none"]):
            return "display is block or none"
    elif prop == "visibility":
        if tokens[0] not in ("visible", "hidden"):
            return "visibility is visible or hidden"
    elif prop in ("overflow-x", "overflow-y"):
        if tokens[0] not in ("auto", "hidden", "scroll"):
            return "overflow is auto/hidden/scroll"
    elif prop in ("width", "height", "min-width", "min-height", "max-width",
                  "max-height"):
        if len(tokens) != 1 or not SIZE.match(tokens[0]):
            return f"'{value}' is not a size"
    elif prop in ("padding", "margin"):
        if len(tokens) not in (1, 2, 4):
            return "padding/margin takes 1, 2 or 4 values"
        if not all(token.lstrip("-").isdigit() for token in tokens):
            return "padding/margin values are whole numbers"
    elif prop.startswith(("padding-", "margin-")):
        if len(tokens) != 1 or not tokens[0].lstrip("-").isdigit():
            return "needs a single whole number"
    elif prop == "dock":
        if tokens[0] not in ("top", "right", "bottom", "left"):
            return "dock is top/right/bottom/left"
    elif prop.startswith("scrollbar-size"):
        if not all(token.isdigit() for token in tokens):
            return "scrollbar sizes are whole numbers"
    return ""


def test_the_stylesheet_has_declarations():
    found = declarations()
    assert len(found) > 100, f"only found {len(found)} declarations"


def test_no_declaration_has_a_bad_value():
    broken = [
        f"{selector}  {prop}: {value}   ({why})"
        for selector, prop, value in declarations()
        if (why := check(selector, prop, value))
    ]
    assert not broken, "\n".join(broken)


def test_braces_are_balanced():
    text = re.sub(r"/\*.*?\*/", "", STYLESHEET.read_text(), flags=re.S)
    assert text.count("{") == text.count("}")


def test_the_checker_catches_the_bug_that_shipped_in_2_5_0():
    """The check is only worth having if it fails on the real mistake."""
    assert check("PasswordPrompt", "align", "horizontal center")
    assert check("PasswordPrompt", "align", "center")
    assert check("X", "align", "middle center")        # right words, wrong order
    assert check("X", "display", "flex")
    assert check("X", "height", "tall")
    assert check("X", "border", "fancy $accent")
    # And passes on the corrected version, and on values already in the file.
    assert not check("PasswordPrompt", "align", "center middle")
    assert not check("X", "border", "tall $accent")
    assert not check("X", "height", "1fr")
    assert not check("X", "max-height", "65%")
    assert not check("X", "padding", "0 1")
