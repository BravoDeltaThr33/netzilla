"""SETTINGS — credentials, theme, timeouts and cache.

Every credential netzilla can use gets its own input here.

netzilla ships with no keys, so every field starts empty:

  * type a key and SAVE            -> it is saved to
                                      ~/.config/netzilla/config.toml
  * clear a field and SAVE         -> that key is removed
  * NETZILLA_<KEY> env variables   -> win over a saved key, and are labelled
                                      as such

Every service netzilla uses is free: the four keys are free accounts, and
the one optional key (NVD) only raises a rate limit. Nothing needs a paid
plan.

On shared secrets: none of the services netzilla talks to use an HMAC-style
secret-key pair. They are all single-token schemes. abuse.ch calls its token
an "Auth-Key", so it appears below under that name. The schema keeps a
shared-secret field type so a future service that needs one drops straight in.

DISPLAY holds the graphics mode — pixel graphs in terminals that can show
them (kitty, Ghostty), text everywhere else — and desktop notifications.
"""

from __future__ import annotations

from rich.text import Text
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Input, Label, Select, Static, Switch

from ..config import CREDENTIAL_FIELDS, GRAPHICS_MODES
from .base import ActionRow, CollapsibleControls, control_head, fit_action_rows
from ..render import short_path, table_panel
from ..themes import DEFAULT_THEME, PALETTES

GRAPHICS_LABELS = {
    "auto": "Auto — pixels where the terminal can show them",
    "pixel": "Pixel — always draw graphs as images",
    "text": "Text — always draw graphs with characters",
}


SOURCE_LABELS = {
    "env": ("● ENVIRONMENT VARIABLE — overrides this field", "accent"),
    "custom": ("● CUSTOM KEY — your own saved value", "success"),
    "none": ("○ NOT SET", "warning"),
}


_short_path = short_path


class SettingsPane(CollapsibleControls, Vertical):
    """Credential and preference editor."""

    # Two columns from this width up; one below it.
    TWO_COLUMNS_AT = 118

    def compose(self):
        config = self.app.services.config
        scroll = VerticalScroll(classes="settings-scroll")
        with scroll:
            yield control_head(
                "Keys arrive pre-filled from the defaults bundled with netzilla. Type "
                "a new value and SAVE to override one; clear a box and SAVE to fall "
                "back to its default. Overrides are kept (0600) in "
                f"{_short_path(config.path)}; NETZILLA_<KEY> environment variables "
                "win over both."
            )

            # The buttons first, so SAVE and TEST KEYS are always on screen.
            with ActionRow(classes="action-row settings-actions"):
                yield Button("SAVE SETTINGS", id="act-save", classes="action primary")
                yield Button("TEST KEYS", id="act-test", classes="action")
                yield Button("SHOW / HIDE KEYS", id="act-reveal", classes="action")
                yield Button("CLEAR CACHE", id="act-clear", classes="action")
            yield Static("", id="settings-feedback", classes="toast-ok")

            with Horizontal(classes="settings-columns", id="settings-columns"):
                with Vertical(classes="settings-col", id="settings-left"):
                    # ------------------------------------------------ keys
                    required = Vertical(classes="settings-group collapsible")
                    required.border_title = "API KEYS — FREE ACCOUNTS"
                    with required:
                        for spec in CREDENTIAL_FIELDS:
                            if spec.required:
                                yield from self._credential_row(spec)

                    optional = Vertical(classes="settings-group collapsible")
                    optional.border_title = "API KEY — OPTIONAL"
                    with optional:
                        for spec in CREDENTIAL_FIELDS:
                            if not spec.required:
                                yield from self._credential_row(spec)

                    # TEST KEYS answers here, next to the keys it tested.
                    with VerticalScroll(classes="results", id="settings-results"):
                        yield Static(
                            "TEST KEYS checks every key in the boxes above — saved or "
                            "not — with one live, uncached call each, and lists the "
                            "verdicts here. It spends one of GreyNoise's 50 weekly "
                            "lookups; the other services barely notice.",
                            classes="settings-hint",
                        )

                with Vertical(classes="settings-col", id="settings-right"):
                    # ---------------------------------------------- theme
                    appearance = Vertical(classes="settings-group collapsible")
                    appearance.border_title = "APPEARANCE — COLOUR THEME"
                    with appearance:
                        yield Select(
                            [(palette.label, name) for name, palette in PALETTES.items()],
                            value=(
                                config.theme if config.theme in PALETTES else DEFAULT_THEME
                            ),
                            allow_blank=False,
                            id="theme-select",
                        )
                        yield Static(
                            "Seventeen dark palettes. T cycles them anywhere (Ctrl+T "
                            "while typing in a box); Ctrl+P and 'theme' lists them.",
                            classes="cred-note",
                        )

                    # -------------------------------------------- display
                    display = Vertical(classes="settings-group collapsible")
                    display.border_title = "DISPLAY — GRAPHS AND NOTIFICATIONS"
                    with display:
                        yield Select(
                            [(GRAPHICS_LABELS[m], m) for m in GRAPHICS_MODES],
                            value=config.graphics if config.graphics in GRAPHICS_MODES
                            else "auto",
                            allow_blank=False,
                            id="graphics-select",
                        )
                        yield Static("", id="graphics-note", classes="cred-note")
                        with Horizontal(classes="switch-row"):
                            yield Switch(value=config.notify, id="sw-notify")
                            yield Static(
                                "Desktop notification when a long run ends while the "
                                "terminal is in the background",
                                classes="switch-note",
                            )

                    # ------------------------------------------ behaviour
                    behaviour = Vertical(classes="settings-group collapsible")
                    behaviour.border_title = "BEHAVIOUR"
                    with behaviour:
                        with Horizontal(classes="switch-row"):
                            yield Input(
                                value=str(config.timeout_seconds),
                                placeholder="12",
                                id="in-timeout",
                                classes="cred-input timeout-input",
                            )
                            yield Static("Request timeout, in seconds (1–120)",
                                         classes="switch-note")
                        with Horizontal(classes="switch-row"):
                            yield Switch(value=config.cache_enabled, id="sw-cache")
                            yield Static(
                                "Cache API responses (strongly recommended — several "
                                "free tiers are tight)",
                                classes="switch-note",
                            )

                    # -------------------------------- status and storage
                    yield Static("", id="settings-status", classes="result-panel")

    def _credential_row(self, spec):
        holder = Vertical(classes="cred-row")
        with holder:
            tag = "SHARED SECRET" if spec.kind == "shared_secret" else "API KEY"
            with Horizontal(classes="cred-head"):
                yield Label(f"{spec.label}   [{tag}]", classes="cred-label")
                yield Static("", id=f"src-{spec.key}", classes="cred-source")
            yield Input(
                value=self._field_value(spec.key),
                placeholder=f"paste your {spec.service} credential here",
                password=True,
                id=f"cred-{spec.key}",
                classes="cred-input",
            )
            note = spec.note
            if spec.signup_url:
                note = f"{note}  ·  {spec.signup_url}"
            yield Static(note, classes="cred-note")

    def _field_value(self, key: str) -> str:
        """What the input box should show: the saved key, if any.

        An environment variable is deliberately NOT copied into the box — it
        would then be written to disk on the next SAVE.
        """
        return self.app.services.config.credentials.get(key, "")

    # ------------------------------------------------------------- events
    def on_mount(self) -> None:
        self._refresh_states()
        self._graphics_note()
        self._status_panel()
        self.call_after_refresh(self._fit_columns)

    def on_resize(self, event) -> None:
        self._fit_columns()

    def _fit_columns(self) -> None:
        """Side by side on a wide terminal; stacked on a narrow one."""
        try:
            columns = self.query_one("#settings-columns", Horizontal)
        except Exception:
            return
        wide = int(self.size.width or 0) >= self.TWO_COLUMNS_AT
        columns.styles.layout = "horizontal" if wide else "vertical"
        for column in columns.query(".settings-col"):
            column.styles.width = "1fr" if wide else "100%"
        columns.set_class(wide, "-wide")
        # The buttons: one equal column each, edge to edge.
        rows = list(self.query(ActionRow))
        fit_action_rows(rows, floor=max((len(r.children) for r in rows), default=1))

    def refresh_theme(self) -> None:
        self._refresh_states()
        self._graphics_note()
        self._status_panel()

    def _status_panel(self) -> None:
        """What is set, where everything is kept, and what netzilla is running
        on — the facts this tab's choices change."""
        try:
            widget = self.query_one("#settings-status", Static)
        except Exception:
            return
        from .. import __version__
        from ..render import kv_panel

        app = self.app
        services = app.services  # type: ignore[attr-defined]
        config = services.config
        palette = app.palette  # type: ignore[attr-defined]
        rows = []
        for spec in CREDENTIAL_FIELDS:
            source = config.credential_source(spec.key)
            word, colour = {
                "custom": ("your own key", "success"),
                "env": ("environment variable", "accent"),
                "none": ("not set" + ("" if spec.required else " (optional)"),
                         "warning" if spec.required else "muted"),
            }[source]
            rows.append((spec.service, Text(word, style=getattr(palette, colour))))
        info = getattr(app, "terminal", None)
        mode = getattr(app, "graphics_mode", "text")
        rows += [
            ("Config file", _short_path(config.path, 56)),
            ("Cache", f"{_short_path(services.store.path, 40)} · "
                      f"{services.store.cache_size():,} answers"
                      + ("" if services.store.enabled else " · OFF")),
            ("Exports (F4)", "~/netzilla-exports"),
            ("netzilla", f"{__version__} · {info.label if info else '?'} · {mode} graphs"),
        ]
        widget.update(kv_panel(palette, "Keys and storage", rows,
                               subtitle="changes here take effect at once"))


    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "graphics-select":
            event.stop()
            value = str(event.value)
            if value in GRAPHICS_MODES and value != self.app.config_obj.graphics:
                self.app.set_graphics(value)  # type: ignore[attr-defined]
            self._graphics_note()
            return
        if event.select.id != "theme-select":
            return
        event.stop()
        value = str(event.value)
        if value in PALETTES:
            self.app.apply_theme(value)  # type: ignore[attr-defined]

    def _graphics_note(self) -> None:
        """What the terminal is, and how graphs are being drawn because of it."""
        app = self.app
        info = getattr(app, "terminal", None)
        try:
            note = self.query_one("#graphics-note", Static)
        except Exception:
            return
        if info is None:
            return
        palette = app.palette  # type: ignore[attr-defined]
        mode = getattr(app, "graphics_mode", "text")
        setting = getattr(app, "graphics_setting", "auto")
        text = Text()
        text.append(f"Terminal: {info.where} · ", style=palette.muted)
        text.append(f"graphs drawn as {mode.upper()}", style=palette.accent)
        text.append(" — ", style=palette.muted)
        why = app.graphics_why() if hasattr(app, "graphics_why") else info.graphics_reason()
        if setting == "pixel" and mode == "pixel" and not info.pixel_capable():
            text.append("forced on — if graphs show as blank boxes, this terminal "
                        "can't draw them: choose Auto.", style=palette.warning)
        elif setting == "pixel" and mode != "pixel":
            text.append(why, style=palette.warning)
        else:
            text.append(why, style=palette.muted)
        note.update(text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        event.stop()
        if button_id == "collapse-toggle":
            self.toggle_controls()
        elif button_id == "act-save":
            self._save()
        elif button_id == "act-reveal":
            self._toggle_reveal()
        elif button_id == "act-clear":
            removed = self.app.services.store.clear_cache()
            self._say(f"Cache cleared — {removed} stored responses removed.")
            self._status_panel()
        elif button_id == "act-test":
            self.run_worker(self._test_keys(), exclusive=True, group="settings")

    # ------------------------------------------------------------ actions
    def _apply_inputs(self) -> None:
        """Copy the credential boxes into the in-memory config (no disk write)."""
        config = self.app.services.config
        for spec in CREDENTIAL_FIELDS:
            try:
                widget = self.query_one(f"#cred-{spec.key}", Input)
            except Exception:
                continue
            config.set_credential(spec.key, widget.value)

    def _save(self) -> None:
        config = self.app.services.config
        self._apply_inputs()

        try:
            raw = self.query_one("#in-timeout", Input).value.strip()
            timeout = float(raw)
            if not 1 <= timeout <= 120:
                raise ValueError
            config.timeout_seconds = timeout
        except Exception:
            self._say("Timeout must be a number between 1 and 120.", ok=False)
            return

        try:
            config.cache_enabled = self.query_one("#sw-cache", Switch).value
        except Exception:
            pass

        try:
            config.notify = self.query_one("#sw-notify", Switch).value
        except Exception:
            pass

        try:
            selected = self.query_one("#theme-select", Select).value
            if isinstance(selected, str) and selected in PALETTES:
                config.theme = selected
        except Exception:
            pass

        try:
            config.save()
        except OSError as exc:
            self._say(f"Could not write {config.path}: {exc}", ok=False)
            return

        self.app.services.store.enabled = config.cache_enabled
        self._refill_inputs()
        self._refresh_states(prefix=f"Saved to {_short_path(config.path)}. ")
        self._status_panel()

    def _refill_inputs(self) -> None:
        for spec in CREDENTIAL_FIELDS:
            try:
                widget = self.query_one(f"#cred-{spec.key}", Input)
            except Exception:
                continue
            widget.value = self._field_value(spec.key)

    def _toggle_reveal(self) -> None:
        for spec in CREDENTIAL_FIELDS:
            try:
                widget = self.query_one(f"#cred-{spec.key}", Input)
            except Exception:
                continue
            widget.password = not widget.password

    async def _test_keys(self) -> None:
        """Make one live, uncached call per credential currently in the boxes.

        The boxes are applied in memory first, so an edited key can be tested
        before it is saved. The cache is bypassed — a cached success from an
        older key would otherwise prove nothing.
        """
        from ..clients import abuseipdb, greynoise, urlhaus, virustotal

        self._apply_inputs()
        services = self.app.services
        results = self.query_one("#settings-results", VerticalScroll)
        await results.remove_children()
        palette = self.app.palette  # type: ignore[attr-defined]
        await results.mount(
            Static(Text("▸ Testing credentials with live calls…", style=palette.accent))
        )

        probe_ip = "8.8.8.8"
        checks = [
            ("AbuseIPDB", "abuseipdb_api_key",
             lambda: abuseipdb.check(services, probe_ip)),
            ("VirusTotal", "virustotal_api_key",
             lambda: virustotal.check_ip(services, probe_ip)),
            ("GreyNoise", "greynoise_api_key",
             lambda: greynoise.check(services, probe_ip)),
            ("URLhaus", "abusech_auth_key",
             lambda: urlhaus.check_host(services, "example.com", allow_offline=False)),
        ]

        rows = []
        services.bypass_cache = True
        try:
            for label, key, call in checks:
                source = services.config.credential_source(key)
                if source == "none":
                    rows.append([label, "—", Text("no credential set", style=palette.muted)])
                    continue
                outcome = await call()
                if outcome.ok and outcome.meta.get("key_rejected"):
                    verdict = Text(
                        "KEY REJECTED (401) — only anonymous lookups work",
                        style=palette.error,
                    )
                elif outcome.ok:
                    verdict = Text("WORKING", style=palette.success)
                else:
                    first_line = str(outcome.error).splitlines()[0] if outcome.error else "failed"
                    verdict = Text(first_line[:90], style=palette.error)
                rows.append([label, source, verdict])
        finally:
            services.bypass_cache = False

        await results.remove_children()
        await results.mount(
            Static(
                table_panel(
                    palette, "Credential test", ["Service", "Key source", "Result"],
                    rows,
                    subtitle="one live call each · GreyNoise counts 1 of 50 weekly",
                ),
                classes="result-panel",
            )
        )
        self._refresh_states()

    # ----------------------------------------------------------- feedback
    def _say(self, message: str, ok: bool = True) -> None:
        palette = self.app.palette  # type: ignore[attr-defined]
        widget = self.query_one("#settings-feedback", Static)
        widget.update(
            Text(
                ("✔ " if ok else "✘ ") + message,
                style=palette.success if ok else palette.error,
            )
        )

    def _refresh_states(self, prefix: str = "") -> None:
        config = self.app.services.config
        palette = self.app.palette  # type: ignore[attr-defined]

        for spec in CREDENTIAL_FIELDS:
            try:
                label = self.query_one(f"#src-{spec.key}", Static)
            except Exception:
                continue
            text, colour_attr = SOURCE_LABELS[config.credential_source(spec.key)]
            label.update(Text(text, style=getattr(palette, colour_attr)))

        configured = sum(1 for f in CREDENTIAL_FIELDS if config.has(f.key))
        missing_required = [
            f.label for f in CREDENTIAL_FIELDS if f.required and not config.has(f.key)
        ]
        widget = self.query_one("#settings-feedback", Static)
        if not missing_required:
            widget.update(
                Text(
                    f"✔ {prefix}{configured}/{len(CREDENTIAL_FIELDS)} credentials "
                    "set — every tab is unlocked.",
                    style=palette.success,
                )
            )
        else:
            widget.update(
                Text(
                    f"{prefix}{configured}/{len(CREDENTIAL_FIELDS)} credentials set. "
                    f"Still needed: {', '.join(missing_required)}",
                    style=palette.warning,
                )
            )
