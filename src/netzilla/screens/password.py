"""A modal password prompt.

netzilla is drawing on the terminal, so a tool that prompts for a password on
stdin cannot be seen or answered. This asks inside the interface instead, and
hands the typed string straight back to the caller — it is never stored on the
screen object, never logged, and the input is masked.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from .base import ActionRow


class PasswordPrompt(ModalScreen[str | None]):
    """Returns the typed password, or None when cancelled."""

    BINDINGS = [("escape", "dismiss_prompt", "Cancel")]

    def __init__(
        self,
        title: str = "AUTHENTICATE",
        note: str = "",
        confirm: str = "UNLOCK",
    ) -> None:
        super().__init__()
        self.prompt_title = title
        self.note = note
        self.confirm = confirm

    def compose(self) -> ComposeResult:
        box = Vertical(classes="password-box")
        box.border_title = self.prompt_title
        with box:
            if self.note:
                yield Static(self.note, classes="password-note")
            yield Input(
                password=True,
                placeholder="password",
                id="password-input",
                classes="field-input",
            )
            # Two equal buttons spanning the box (the same grid as a tab's).
            row = ActionRow(classes="action-row password-actions")
            row.styles.grid_size_columns = 2
            with row:
                yield Button(self.confirm, id="password-ok", classes="action primary")
                yield Button("CANCEL", id="password-cancel", classes="action")

    def on_mount(self) -> None:
        self.query_one("#password-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self.dismiss(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "password-ok":
            self.dismiss(self.query_one("#password-input", Input).value)
        else:
            self.dismiss(None)

    def action_dismiss_prompt(self) -> None:
        self.dismiss(None)
