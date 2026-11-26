"""Picking one entry of a live list — and showing only it.

The live views that list what is heard on the air — WIFI → BLUETOOTH and
BT TRACKERS (Bluetooth devices) and LIVE AIR (Wi-Fi networks) — let you pick
one entry:

  * click its row, or Tab to the list and use ↑ ↓ — the view's big signal
    graph follows it;
  * click it again, or press Enter — the whole view shows only it: its row,
    its graph and everything known about it, the rest hidden;
  * Esc steps back (only it → picked → nothing); LET GO lets go at once.

A pick belongs to a family of lists — "bt" (Bluetooth devices, by address)
and "air" (Wi-Fi networks, by BSSID) — so a device picked in BLUETOOTH is
still picked in BT TRACKERS, and a network picked in LIVE AIR is the one
SIGNAL watches when the GRAPH box is empty. Typing in the GRAPH box drops
the picks: whatever you did last wins.

A list is a Static showing an ordinary netzilla table panel whose rows carry
a click action, so it looks like every other table. The pointer lights up
the row under it, and while the pointer is over the list its rows hold
still — newcomers join at the bottom — so a row cannot move away just as you
click it.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Group
from rich.style import Style
from rich.text import Text
from textual.binding import Binding
from textual.geometry import Region, Spacing
from textual.message import Message
from textual.widgets import Static

# What one entry of each family is called, for the hints.
FAMILIES = {"bt": ("device", "devices"), "air": ("network", "networks")}


@dataclass(frozen=True)
class Pick:
    """The picked entry of one family, and whether the view shows only it."""

    key: str = ""
    only: bool = False


class Picks:
    """The pick in each family of live lists."""

    def __init__(self) -> None:
        self._picks: dict[str, Pick] = {}

    def get(self, family: str) -> Pick:
        return self._picks.get(family, Pick())

    def key(self, family: str) -> str:
        return self.get(family).key

    def only(self, family: str) -> bool:
        pick = self.get(family)
        return bool(pick.key and pick.only)

    def apply(self, family: str, gesture: str, key: str = "") -> Pick:
        """One gesture on a list:

        click  a row: pick it — or, when it is already picked, switch
               between showing only it and showing everything
        move   ↑ ↓: pick this one instead, still showing only it if that
               was on
        only   Enter / SHOW ONLY IT / SHOW ALL: switch showing only it
        back   Esc: one step back — only it → picked → nothing
        clear  LET GO: nothing picked
        """
        pick = self.get(family)
        if gesture == "click" and key:
            pick = Pick(key, not pick.only) if key == pick.key else Pick(key, pick.only)
        elif gesture == "move" and key:
            pick = Pick(key, pick.only)
        elif gesture == "only" and pick.key:
            pick = Pick(pick.key, not pick.only)
        elif gesture == "back":
            pick = Pick(pick.key, False) if pick.only else Pick()
        elif gesture == "clear":
            pick = Pick()
        if pick.key:
            self._picks[family] = pick
        else:
            self._picks.pop(family, None)
        return pick

    def clear(self) -> None:
        self._picks.clear()


class PickGesture(Message):
    """What was done to a live list (or the line over it), for the tab."""

    def __init__(self, family: str, gesture: str, key: str = "") -> None:
        super().__init__()
        self.family = family
        self.gesture = gesture
        self.key = key


def blend(colour: str, onto: str, amount: float) -> str:
    """`colour` laid over `onto` at `amount` (0–1), as #rrggbb."""
    def rgb(value: str) -> list[int]:
        value = value.strip().lstrip("#")
        return [int(value[i:i + 2], 16) for i in (0, 2, 4)]

    try:
        top, bottom = rgb(colour), rgb(onto)
    except (ValueError, IndexError):
        return onto
    mixed = [round(b + (t - b) * amount) for t, b in zip(top, bottom)]
    return "#" + "".join(f"{max(0, min(255, c)):02x}" for c in mixed)


def picked_background(palette) -> str:
    return blend(palette.accent, palette.background, 0.30)


def hover_background(palette) -> str:
    return blend(palette.accent, palette.background, 0.16)


def row_styles(palette, keys, picked: str = "") -> list[Style]:
    """One style per row of a list: the click that picks it, and — for the
    picked one — its highlight."""
    styles = []
    for key in keys:
        meta = {"@click": ("pick", (key,))}
        if key and key == picked:
            styles.append(Style(bgcolor=picked_background(palette), bold=True, meta=meta))
        else:
            styles.append(Style(meta=meta))
    return styles


def marked(palette, cell, picked: bool) -> object:
    """A row's first cell, with ▶ in front when it is the picked row."""
    if not picked:
        return cell
    text = Text("▶ ", style=f"bold {palette.accent}")
    if isinstance(cell, Text):
        text.append_text(cell)
    elif cell in (None, ""):
        text.append("—", style=palette.muted)
    else:
        text.append(str(cell), style=f"bold {palette.foreground}")
    return text


def steady_order(keys, previous, hold: bool) -> list[str]:
    """The order to list `keys` in: as given — or, while the pointer is over
    the list (`hold`), the order last shown, with newcomers at the bottom."""
    keys = list(keys)
    if not hold or not previous:
        return keys
    present = set(keys)
    kept = [key for key in previous if key in present]
    held = set(kept)
    return kept + [key for key in keys if key not in held]


def bar(palette, family: str, *, label: str = "", only: bool = False, lost: bool = False,
        focused: bool = False, typed: str = "", hidden: int = 0,
        noun: tuple[str, str] | None = None) -> Text:
    """The line over a live list: how to pick, or what is picked with the
    buttons to show only it / show everything / let go. `noun` names the
    entries when the family's word doesn't fit the view ("tracker")."""
    one, many = noun or FAMILIES.get(family, ("entry", "entries"))
    text = Text(no_wrap=True, overflow="ellipsis")
    if not label:
        text.append("☞ ", style=f"bold {palette.accent}")
        text.append(f"Click a {one} below to graph it — click it again to show only it",
                    style=palette.secondary)
        if typed:
            text.append(f" · until then the graph follows the GRAPH box ({typed})",
                        style=palette.muted)
        text.append(" · ↑ ↓ to pick, Enter for only it" if focused
                    else " · or Tab to the list and use ↑ ↓", style=palette.muted)
        return text

    def button(caption: str, action: str) -> None:
        text.append(f"[ {caption} ]",
                    style=Style(color=palette.accent, bold=True, meta={"@click": (action, ())}))

    text.append("◉ SHOWING ONLY  " if only else "▶ GRAPHING  ", style=f"bold {palette.primary}")
    text.append(label, style=f"bold {palette.accent}")
    if lost:
        text.append("  — not heard for a while", style=palette.warning)
    elif only and hidden:
        text.append(f"  ({hidden} other {one if hidden == 1 else many} hidden)",
                    style=palette.muted)
    text.append("   ")
    button("SHOW ALL" if only else "SHOW ONLY IT", "only")
    text.append("  ")
    button("LET GO", "clear")
    if focused:
        hint = (f"↑ ↓ the next {one} on its own · Esc: show all" if only
                else "Enter: show only it · ↑ ↓ another · Esc: let go")
    else:
        hint = "click its row to show all" if only else "click it again to show only it"
    text.append(f"   {hint}", style=palette.muted)
    return text


class _NoLinkLook:
    """Rows and buttons carry click actions, which Textual would draw as
    underlined links in one colour: keep each cell's own colours instead,
    and light up only what is under the pointer."""

    @property
    def link_style(self) -> Style:
        return Style()

    @property
    def link_style_hover(self) -> Style:
        try:
            return Style(bgcolor=hover_background(self.app.palette))  # type: ignore[attr-defined]
        except Exception:
            return Style(reverse=True)


class PickBar(_NoLinkLook, Static):
    """The line over a live list (see `bar`)."""

    def __init__(self, family: str) -> None:
        super().__init__(classes="pick-bar")
        self.family = family

    def update(self, content="", **kwargs) -> None:
        # Drawn by Rich like the panels (Textual would otherwise turn a Rich
        # Text into its own content, which needs the running app).
        if isinstance(content, Text):
            content = Group(content)
        super().update(content, **kwargs)

    def _send(self, gesture: str) -> None:
        self.post_message(PickGesture(self.family, gesture))

    def action_only(self) -> None:
        self._send("only")

    def action_clear(self) -> None:
        self._send("clear")


class PickList(_NoLinkLook, Static, can_focus=True):
    """A live list whose rows can be picked: click a row (or ↑ ↓ once the
    list has the focus) to pick it; click it again or press Enter to show
    only it; Esc steps back."""

    BINDINGS = [
        Binding("up", "step(-1)", "Previous", show=False),
        Binding("down", "step(1)", "Next", show=False),
        Binding("pageup", "step(-10)", show=False),
        Binding("pagedown", "step(10)", show=False),
        Binding("home", "edge(0)", show=False),
        Binding("end", "edge(1)", show=False),
        Binding("enter,space", "only", "Only this", show=False),
        Binding("escape", "back", "Back", show=False),
    ]

    # Lines above the first row: the panel's top border, then the header.
    FIRST_ROW = 2

    def __init__(self, family: str) -> None:
        super().__init__(classes="result-panel pick-list")
        self.family = family
        self.keys: list[str] = []    # every entry in order — what ↑ ↓ walk through
        self.shown: list[str] = []   # the rows on screen, in order
        self.picked = ""
        self._reveal = False
        self._lines = 0              # its height, when every row is one line

    @property
    def holding(self) -> bool:
        """The pointer is over the list, so its rows should hold still."""
        return bool(getattr(self, "mouse_hover", False))

    def show(self, renderable, *, keys, shown, picked: str = "", one_line: bool = False) -> None:
        """Draw the list. `keys` is every entry in order, `shown` the rows
        drawn (just one when the view shows only the picked entry);
        one_line says every row is one line (render.table_panel's one_line)."""
        self.keys = list(keys)
        self.shown = list(shown)
        self.picked = picked or ""
        # Top border, header, the rows, bottom border — or, with no rows, the
        # borders round "No results.".
        if one_line:
            self._lines = self.FIRST_ROW + len(self.shown) + 1 if self.shown else 3
        else:
            self._lines = 0
        self.update(renderable)
        if self._reveal:
            self._reveal = False
            if self.is_mounted:
                self.call_after_refresh(self.reveal)

    def get_content_height(self, container, viewport, width: int) -> int:
        # A live list is redrawn every second and on every pick: when each
        # row is one line its height is known, so it isn't drawn just to be
        # measured (about a third of a redraw's time for 40 rows).
        if self._lines and width:
            return self._lines
        return super().get_content_height(container, viewport, width)

    def reveal(self) -> None:
        """Scroll the results so the picked row is on screen (after ↑ ↓)."""
        parent = self.parent
        if parent is None or self.picked not in self.shown:
            return
        line = self.FIRST_ROW + self.shown.index(self.picked)
        region = self.virtual_region
        try:
            parent.scroll_to_region(  # type: ignore[attr-defined]
                Region(region.x, region.y + line, max(1, region.width), 1),
                animate=False, spacing=Spacing(1, 0, 1, 0))
        except Exception:
            pass

    def _send(self, gesture: str, key: str = "") -> None:
        self.post_message(PickGesture(self.family, gesture, key))

    def action_pick(self, key: str) -> None:
        """A row was clicked (its click action)."""
        self._send("click", key)

    def action_step(self, delta: int) -> None:
        if not self.keys:
            return
        if self.picked in self.keys:
            index = self.keys.index(self.picked) + delta
        else:
            index = 0 if delta > 0 else len(self.keys) - 1
        self._move_to(self.keys[max(0, min(len(self.keys) - 1, index))])

    def action_edge(self, last: int) -> None:
        """Home / End: the first or the last entry."""
        if self.keys:
            self._move_to(self.keys[-1] if last else self.keys[0])

    def _move_to(self, key: str) -> None:
        if key == self.picked:
            return
        self.picked = key            # a second press before the redraw moves on from here
        self._reveal = True
        self._send("move", key)

    def action_only(self) -> None:
        if self.picked:
            self._send("only")
        elif self.keys:              # nothing picked yet: pick the first
            self._move_to(self.keys[0])

    def action_back(self) -> None:
        self._send("back")

    def on_focus(self, event) -> None:
        self._send("redraw")         # the line over the list now shows the keys

    def on_blur(self, event) -> None:
        self._send("redraw")


class Picking:
    """A tab's side of picking, mixed into the tab: the picks, what a
    gesture on a list does, and drawing the running live view again at once
    so a click shows straight away rather than at the next refresh."""

    def _init_picking(self) -> None:
        self.picks = Picks()
        self._redraw = None          # draws the running (or last) live view again
        self._typed: str | None = None
        self._orders: dict[str, list[str]] = {}

    def on_pick_gesture(self, event: PickGesture) -> None:
        event.stop()
        if event.gesture != "redraw":
            self.picks.apply(event.family, event.gesture, event.key)
        self.redraw_live()

    def redraw_live(self) -> None:
        draw = self._redraw
        if draw is None:
            return
        try:
            draw()
        except Exception:
            pass

    def typed_target(self, key: str = "target") -> str:
        """The GRAPH box, read live. Typing a name in it drops the picks
        (whatever was done last wins); emptying it does not — an empty box
        is how you say "not the box"."""
        typed = self.field(key)  # type: ignore[attr-defined]
        if typed and self._typed is not None and typed != self._typed:
            self.picks.clear()
        self._typed = typed
        return typed

    def steady(self, family: str, keys, widget) -> list[str]:
        """`keys` in the order to list them (see steady_order)."""
        order = steady_order(keys, self._orders.get(family),
                             bool(getattr(widget, "holding", False)))
        self._orders[family] = order
        return order

    @staticmethod
    def show_list(widget, renderable, *, keys, shown, picked: str = "",
                  one_line: bool = False) -> None:
        show = getattr(widget, "show", None)
        if show is not None:
            show(renderable, keys=keys, shown=shown, picked=picked, one_line=one_line)
        else:                        # a plain panel (the tests' stand-ins)
            widget.update(renderable)

    @staticmethod
    def list_focused(widget) -> bool:
        return bool(getattr(widget, "has_focus", False))
