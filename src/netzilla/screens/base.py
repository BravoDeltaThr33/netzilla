"""Shared machinery for every netzilla tab.

A pane declares its title, its input fields and its buttons, then implements
one async `execute()` method. The base class handles layout, validation
errors, worker dispatch, progress and result rendering, so each tab stays
short and consistent.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import RenderableType
from rich.text import Text
from textual import events
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.widgets import Button, Input, Label, Select, Static

from ..help import get_help, help_panel
from ..render import error_panel, warn_panel
from ..themes import Palette
from ..validators import ValidationError


@dataclass(frozen=True)
class Field:
    """One input on a pane: a text box, or a dropdown when `choices` is set."""

    key: str
    label: str
    placeholder: str = ""
    value: str = ""
    width: int = 0  # 0 = share the row evenly
    choices: tuple[str, ...] | None = None  # not None = render a Select
    # The action Enter runs from this box; "" = the tab's first action.
    submit: str = ""
    # Mask what is typed (CREDS' password box).
    password: bool = False


@dataclass(frozen=True)
class Action:
    """One button on a pane."""

    key: str
    label: str
    primary: bool = True


# Textual's "nothing selected" sentinel: Select.BLANK in older releases,
# Select.NULL (a NoSelection instance) in newer ones. Either way an empty
# dropdown must read as "" — not as the text "Select.NULL".
_BLANKS = tuple(
    sentinel for sentinel in (getattr(Select, "BLANK", None), getattr(Select, "NULL", None))
    if sentinel is not None
)


def _is_blank(value) -> bool:
    if value is None or any(value is sentinel for sentinel in _BLANKS):
        return True
    return type(value).__name__ in ("NoSelection", "_NoSelection")

IDLE_HINT = (
    "Hover over a button, or Tab to it, for instructions, example uses and "
    "public test targets."
)


class ActionButton(Button):
    """A tool button that reports when it is hovered or keyboard-focused."""

    class Highlighted(Message):
        """Posted when the pointer or focus arrives at / leaves the button."""

        def __init__(self, button: "ActionButton", active: bool) -> None:
            super().__init__()
            self.button = button
            self.active = active

    def on_enter(self, event: events.Enter) -> None:
        self.post_message(self.Highlighted(self, True))

    def on_leave(self, event: events.Leave) -> None:
        self.post_message(self.Highlighted(self, False))

    def on_focus(self, event: events.Focus) -> None:
        self.post_message(self.Highlighted(self, True))

    def on_blur(self, event: events.Blur) -> None:
        self.post_message(self.Highlighted(self, False))


# ------------------------------------------------------------ button rows
# Every row of buttons on a tab is a grid with the same number of equal
# columns, so the buttons in one row sit exactly over the buttons in the next
# and a full row runs edge to edge. A tab with only a few buttons still gets
# MIN_ACTION_COLUMNS columns (its buttons keep a sensible width, from the
# left); on a terminal too narrow for a row's labels the columns drop until
# every label fits, and a row wraps — still on the same columns.
MIN_ACTION_COLUMNS = 6
ACTION_GUTTER = 2           # blank columns between two buttons
BUTTON_CHROME = 4           # a button's left and right border and padding


class ActionRow(Grid):
    """One row of a tab's buttons (see fit_action_rows)."""


def action_columns(row_lengths: list[int], labels: list[str], width: int,
                   floor: int = MIN_ACTION_COLUMNS, gutter: int = ACTION_GUTTER) -> int:
    """How many equal columns a tab's button rows share at `width` cells:
    the longest row (at least `floor`), fewer if a label would not fit."""
    longest = max(row_lengths, default=0)
    columns = max(floor, longest)
    if width <= 0:
        return columns
    widest = max((len(label) for label in labels), default=0) + BUTTON_CHROME

    def fits(count: int) -> bool:
        return (width - gutter * (count - 1)) // count >= widest

    # Too narrow for one line per row: split the longest row evenly (8 -> 4
    # + 4, 7 -> 4 + 3) rather than leaving one button alone on a line.
    # A tab with few buttons keeps as many (narrower) columns as fit first.
    candidates = list(range(columns, max(longest, 1) - 1, -1))
    candidates += sorted({-(-longest // k) for k in range(2, longest + 1)}, reverse=True)
    for count in candidates:
        if count >= 1 and fits(count):
            return count
    return 1


def fit_action_rows(rows, floor: int = MIN_ACTION_COLUMNS) -> int:
    """Give every row in `rows` (ActionRow widgets of one tab) the same
    column count for the width they have now. Returns the count."""
    rows = list(rows)
    if not rows:
        return 0
    width = 0
    for row in rows:
        width = max(width, int(row.size.width or 0))
    lengths = [len(row.children) for row in rows]
    labels = [str(getattr(button, "label", "")) for row in rows for button in row.children]
    columns = action_columns(lengths, labels, width, floor=floor)
    for row in rows:
        if row.styles.grid_size_columns != columns:
            row.styles.grid_size_columns = columns
    return columns


# ------------------------------------------------------ collapsible controls
COLLAPSED_NOTE = "controls hidden — press ▼ (or F3) to bring them back"


class CollapseToggle(Button):
    """The ▲ / ▼ in the top-right corner of a tab's control box."""

    def __init__(self) -> None:
        super().__init__("▲", id="collapse-toggle", classes="collapse-toggle")
        self.tooltip = "Hide the controls and give the output the screen (F3)"


def control_head(description: str) -> Horizontal:
    """The first line(s) of a control box: its description, the note shown
    instead while the controls are rolled up, and the ▲ / ▼ toggle."""
    return Horizontal(
        Static(description, classes="pane-desc"),
        Static(COLLAPSED_NOTE, classes="collapsed-note"),
        CollapseToggle(),
        classes="control-head",
    )


class CollapsibleControls:
    """Rolling a tab's controls up, and back down.

    The state is one CSS class on the tab; the stylesheet hides the
    description, fields, buttons (and DASH's banner) under it, so the results
    area below grows into the space. Each tab remembers its own state.
    """

    @property
    def controls_collapsed(self) -> bool:
        return self.has_class("-controls-collapsed")  # type: ignore[attr-defined]

    def toggle_controls(self, collapse: bool | None = None) -> bool:
        collapsed = (not self.controls_collapsed) if collapse is None else collapse
        self.set_class(collapsed, "-controls-collapsed")  # type: ignore[attr-defined]
        for toggle in self.query(CollapseToggle):  # type: ignore[attr-defined]
            toggle.label = "▼" if collapsed else "▲"
            toggle.tooltip = (
                "Show the controls again (F3)" if collapsed
                else "Hide the controls and give the output the screen (F3)"
            )
        if collapsed and hasattr(self, "hide_help"):
            self.hide_help()
        return collapsed


class LookupPane(CollapsibleControls, Vertical):
    """Base class for every functional tab."""

    PANE_TITLE = "PANE"
    DESCRIPTION = ""
    FIELDS: tuple[Field, ...] = ()
    ACTIONS: tuple[Action, ...] = (Action("run", "RUN"),)
    MAX_ACTIONS_PER_ROW = 8

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._canvases: dict = {}
        self._status: Static | None = None
        # Help-card state: which action's card is up, whether a run is waiting
        # for its first output (the card stays until then), and whether the
        # next push is a validation message (the card stays for those too).
        self._help_key: str | None = None
        self._awaiting_output = False
        self._keep_help = False
        self._run_id = 0

    # ------------------------------------------------------------- layout
    def compose(self):
        control = Vertical(classes="control-bar")
        control.border_title = self.PANE_TITLE
        with control:
            yield control_head(self.DESCRIPTION)
            if self.FIELDS:
                # A row of boxes always fills the width, like the buttons
                # under it: boxes without a width share what the sized ones
                # leave; when every box has a width, the widths become
                # proportions of the row.
                flexible = any(not spec.width for spec in self.FIELDS)
                with Horizontal(classes="field-row"):
                    for index, spec in enumerate(self.FIELDS):
                        # The last box ends flush with the buttons under it.
                        last = index == len(self.FIELDS) - 1
                        holder = Vertical(classes="field field-last" if last else "field")
                        if spec.width:
                            holder.styles.width = spec.width if flexible else f"{spec.width}fr"
                        with holder:
                            yield Label(spec.label.upper(), classes="field-label")
                            if spec.choices is not None:
                                yield self._select_for(spec)
                            else:
                                yield Input(
                                    value=spec.value,
                                    placeholder=spec.placeholder,
                                    id=f"in-{spec.key}",
                                    classes="field-input",
                                    password=spec.password,
                                )
            rows = self._action_rows()
            if rows:
                with Vertical(classes="action-grid"):
                    for row in rows:
                        with ActionRow(classes="action-row"):
                            for action in row:
                                yield ActionButton(
                                    action.label,
                                    id=f"act-{action.key}",
                                    classes="action primary" if action.primary else "action",
                                )
        yield from self.compose_output()

    def on_mount(self) -> None:
        self.call_after_refresh(self.fit_actions)

    def on_resize(self, event) -> None:
        self.fit_actions()

    def fit_actions(self) -> int:
        """Line this tab's buttons up in equal columns (see ActionRow)."""
        try:
            return fit_action_rows(self.query(ActionRow))
        except Exception:
            return 0

    @classmethod
    def _action_rows(cls) -> list[list[Action]]:
        """Buttons, split across rows when one row would run off the screen.

        Eight buttons is about what fits on a wide terminal; past that they
        are dealt into two balanced rows instead of being cut off at the
        right-hand edge. Either way every row shares the same columns
        (fit_action_rows), so the rows line up.
        """
        actions = list(cls.ACTIONS)
        if len(actions) <= cls.MAX_ACTIONS_PER_ROW:
            return [actions] if actions else []
        half = -(-len(actions) // 2)       # ceiling, so row one is the longer
        return [actions[:half], actions[half:]]

    @staticmethod
    def _select_for(spec: Field) -> Select:
        """A dropdown whose options may be filled in later (interfaces, etc.)."""
        options = [(choice, choice) for choice in (spec.choices or ())]
        select: Select = Select(
            options, id=f"in-{spec.key}", classes="field-select",
            prompt=spec.placeholder or "Select…",
        )
        if spec.value and spec.value in (spec.choices or ()):
            select.value = spec.value
        return select

    def compose_output(self):
        """The help card and the results area, shared by custom layouts."""
        yield Static(classes="action-help")
        yield VerticalScroll(
            Static(Text(IDLE_HINT, style=self.palette.muted), classes="idle-hint"),
            classes="results",
        )

    # -------------------------------------------------------- convenience
    @property
    def palette(self) -> Palette:
        return self.app.palette  # type: ignore[attr-defined]

    @property
    def services(self):
        return self.app.services  # type: ignore[attr-defined]

    @property
    def results(self) -> VerticalScroll:
        return self.query_one(".results", VerticalScroll)

    def field(self, key: str) -> str:
        """The current value of a text box or dropdown; "" when unset."""
        try:
            widget = self.query_one(f"#in-{key}")
        except Exception:
            return ""
        value = getattr(widget, "value", "")
        if _is_blank(value):
            return ""
        return str(value).strip()

    # ------------------------------------------------------ refresh interval
    # Every live view reads its refresh interval from a field keyed "every"
    # (REFRESH EVERY), so the box means the same thing on every tab: blank is
    # the view's own default, anything else is seconds between updates.
    def _every(self, default: float, low: float = 0.5, high: float = 3600.0) -> float:
        raw = self.field("every")
        if not raw:
            return float(default)
        try:
            value = float(raw)
        except ValueError:
            raise ValidationError(
                "REFRESH EVERY is a number of seconds, e.g. 3 or 0.5 — or leave "
                "it blank for this view's default."
            )
        if not low <= value <= high:
            raise ValidationError(
                f"REFRESH EVERY must be between {low:g} and {high:g} seconds for "
                "this view."
            )
        return value

    def set_field(self, key: str, value: str) -> None:
        try:
            widget = self.query_one(f"#in-{key}")
        except Exception:
            return
        if isinstance(widget, Select):
            try:
                widget.value = value
            except Exception:      # not one of the current options
                pass
            return
        try:
            widget.value = value
        except Exception:
            pass

    def set_choices(
        self, key: str, choices: list[str], value: str | None = None
    ) -> None:
        """Refill a dropdown (the INT tab rebuilds its interface list this way)."""
        try:
            select = self.query_one(f"#in-{key}", Select)
        except Exception:
            return
        try:
            select.set_options((choice, choice) for choice in choices)
        except Exception:
            return
        if value and value in choices:
            try:
                select.value = value
            except Exception:
                pass

    # -------------------------------------------------------------- graphs
    def _app_setting(self, name: str, default):
        """An attribute of the running app, or `default` outside one (tests
        build panes without an app)."""
        try:
            return getattr(self.app, name, default)
        except Exception:
            return default

    @property
    def pixel_graphics(self) -> bool:
        """True when graphs on this tab are drawn as images (kitty, Ghostty)."""
        return self._app_setting("graphics_mode", "text") == "pixel"

    def graph(self, key: str, graph, colour: str | None = None):
        """A LineGraph or SpectrumGraph as Text — in pixels when the terminal
        can show them, in text otherwise. `key` names the spot on this tab
        the graph occupies, so a live graph replaces its own last frame."""
        from ..graphics import charts

        canvas = None
        if self.pixel_graphics:
            canvas = self._canvases.get(key)
            if canvas is None:
                from ..graphics.kitty import Canvas

                canvas = self._canvases[key] = Canvas()
        ctx = charts.Context(
            pixel=canvas is not None,
            palette=self.palette,
            canvas=canvas,
            cell_px=self._app_setting("cell_px", (10, 20)),
            colour=colour or self.palette.accent,
            edge=self.palette.background,
            scaffold=self.palette.muted,
        )
        return charts.render(graph, ctx)

    def graph_width(self, reserve: int = 22, fallback: int = 60) -> int:
        """Samples across for a graph filling this tab's width, leaving room
        for the axis labels and the panel border."""
        try:
            width = int(self.size.width)
        except Exception:
            width = 0
        return max(24, min(180, width - reserve)) if width > reserve + 24 else fallback

    def graphs_panel(self, title: str, items, subtitle: str = ""):
        """A panel of one or more graphs, each under its own caption.
        `items` is (caption, key, graph, colour) per graph."""
        from rich.panel import Panel

        from ..render import PANEL_BOX

        palette = self.palette
        body = Text(no_wrap=True, overflow="crop")
        for index, (caption, key, graph, colour) in enumerate(items):
            if index:
                body.append("\n\n")
            if caption:
                body.append(f"{caption}\n", style=f"bold {palette.secondary}")
            body.append_text(self.graph(key, graph, colour=colour))
        return Panel(
            body,
            title=Text(f" {title.upper()} ", style=f"bold {palette.primary}"),
            title_align="left",
            subtitle=Text(f" {subtitle} ", style=palette.muted) if subtitle else None,
            subtitle_align="right",
            border_style=palette.secondary,
            box=PANEL_BOX,
            padding=(0, 1),
        )

    def release_graphics(self) -> None:
        """Free this tab's images in the terminal (its results were cleared)."""
        for canvas in self._canvases.values():
            canvas.clear()
        self._canvases.clear()

    def on_unmount(self) -> None:
        self.release_graphics()

    # ---------------------------------------------------------------- help
    def _action_label(self, key: str) -> str:
        try:
            return str(self.query_one(f"#act-{key}", Button).label)
        except Exception:
            return key

    def show_help(self, key: str) -> None:
        tool = get_help(type(self).__name__, key)
        try:
            card = self.query_one(".action-help", Static)
        except Exception:
            return
        if tool is None:
            self.hide_help()
            return
        card.update(help_panel(self.palette, self._action_label(key), tool))
        card.display = True
        self._help_key = key

    def hide_help(self) -> None:
        self._help_key = None
        try:
            self.query_one(".action-help", Static).display = False
        except Exception:
            pass

    def on_action_button_highlighted(self, event: ActionButton.Highlighted) -> None:
        event.stop()
        key = (event.button.id or "")[4:]
        if self._awaiting_output:
            return  # the running tool's card stays until its output arrives
        if event.active:
            self.show_help(key)
        elif self._help_key == key:
            self.hide_help()

    # ------------------------------------------------------------ results
    async def begin(self, message: str = "Working…") -> None:
        await self.results.remove_children()
        self.release_graphics()
        self._status = Static(
            Text(f"▸ {message}", style=self.palette.accent), classes="status-line"
        )
        await self.results.mount(self._status)

    def progress(self, message: str) -> None:
        if self._status is not None:
            self._status.update(Text(f"▸ {message}", style=self.palette.accent))

    async def finish(self, message: str = "") -> None:
        if self._status is None:
            return
        if message:
            self._status.update(Text(f"▪ {message}", style=self.palette.muted))
        else:
            await self._status.remove()
            self._status = None

    async def push(self, renderable: RenderableType) -> None:
        await self.push_widget(Static(renderable, classes="result-panel"))

    async def push_widget(self, widget: Static) -> None:
        """Mount a widget the caller keeps a handle on, so it can be updated
        in place afterwards (the INT tab's live view refreshes this way)."""
        if self._keep_help:
            self._awaiting_output = False  # validation note: keep the card up
        else:
            self._output_arrived()
        await self.results.mount(widget)
        self.results.scroll_end(animate=False)

    async def push_error(self, title: str, message: str) -> None:
        await self.push(error_panel(self.palette, title, message))

    async def push_warning(self, title: str, message: str) -> None:
        await self.push(warn_panel(self.palette, title, message))

    async def push_result(self, result, title: str, renderer) -> bool:
        """Mount a client result, or a readable error panel. Returns ok."""
        if not result.ok:
            await self.push_error(f"{title} — unavailable", result.error or "Unknown error.")
            return False
        await self.push(renderer(result))
        return True

    def _output_arrived(self) -> None:
        if self._awaiting_output or self._help_key is not None:
            self._awaiting_output = False
            self.hide_help()

    # ------------------------------------------------------------ events
    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "collapse-toggle":
            event.stop()
            self.toggle_controls()
            return
        if button_id.startswith("act-"):
            event.stop()
            self.dispatch(button_id[4:])

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter in a box runs the action that box belongs to — the field's
        own `submit`, or the tab's first action."""
        event.stop()
        if not self.ACTIONS:
            return
        self.dispatch(self.submit_action_for(event.input.id or ""))

    @classmethod
    def submit_action_for(cls, input_id: str) -> str:
        key = input_id[3:] if input_id.startswith("in-") else input_id
        keys = {action.key for action in cls.ACTIONS}
        for spec in cls.FIELDS:
            if spec.key == key and spec.submit in keys:
                return spec.submit
        return cls.ACTIONS[0].key

    def dispatch(self, action: str) -> None:
        # Show this tool's card while it works; push() hides it on first output.
        self.show_help(action)
        self._awaiting_output = self._help_key is not None
        self._run_id += 1
        self.run_worker(
            self._guarded(action, self._run_id),
            exclusive=True,
            group=f"pane-{id(self)}",
        )

    async def _guarded(self, action: str, run_id: int = 0) -> None:
        """Run execute() with validation and crash handling around it."""
        import time

        started = time.monotonic()
        try:
            await self.execute(action)
            if run_id == self._run_id:
                self._notify_finished(action, time.monotonic() - started)
        except ValidationError as exc:
            # Leave the instructions up: they explain what the input should be.
            await self.begin("Input rejected")
            await self.finish()
            self._keep_help = True
            try:
                await self.push_warning("Invalid input", str(exc))
            finally:
                self._keep_help = False
        except Exception as exc:  # never let one tab take the app down
            await self.finish()
            await self.push_error(
                "Unexpected error",
                f"{exc.__class__.__name__}: {exc}\n\n"
                "This is a netzilla bug rather than an API problem.",
            )
        finally:
            # A tool that ended without pushing anything must not strand its
            # card, but a run cancelled by a newer click must not clear the
            # newer run's state.
            if run_id == self._run_id:
                self._awaiting_output = False

    def _notify_finished(self, action: str, seconds: float) -> None:
        """A desktop notification when a long run ends while the terminal
        window is in the background (see notify.py)."""
        from .. import notify

        try:
            notify.finished(self.app, self.PANE_TITLE, self._action_label(action), seconds)
        except Exception:
            pass

    # -------------------------------------------------------- to override
    async def execute(self, action: str) -> None:
        raise NotImplementedError

    def refresh_theme(self) -> None:
        """Called after a theme change so panes can re-render static content."""
        return None
