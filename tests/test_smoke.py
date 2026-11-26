"""Does netzilla actually start?

2.5.0 shipped with one invalid CSS value (`align: horizontal center`, which
needs a horizontal AND a vertical keyword). Textual stops parsing the whole
stylesheet at the first bad value, so the app died at launch with a CSS error
before drawing anything — and every other test still passed, because none of
them started the app.

These do. They parse the stylesheet, boot the real application, open every
tab, apply every theme and push the password dialog. They need Textual
installed, which is exactly the situation that matters: if these pass, the
app runs.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import netzilla
from netzilla.app import TABS, NetzillaApp
from netzilla.themes import THEME_NAMES

STYLESHEET = Path(netzilla.__file__).with_name("netzilla.tcss")


def _app(tmp_path) -> NetzillaApp:
    return NetzillaApp(
        config_path=tmp_path / "config.toml",
        offline=True,
    )


def test_the_stylesheet_file_is_shipped():
    assert STYLESHEET.is_file(), STYLESHEET
    assert STYLESHEET.read_text().strip()


def test_the_stylesheet_parses():
    """Catches a bad property or value without starting the whole app."""
    from textual.css.stylesheet import Stylesheet

    sheet = Stylesheet()
    # Theme variables ($background and friends) come from the app at run
    # time; newer Textual refuses to parse a sheet that uses them without.
    try:
        variables = NetzillaApp().get_css_variables()
    except Exception:
        variables = {}
    if variables and hasattr(sheet, "set_variables"):
        sheet.set_variables(variables)
    text = STYLESHEET.read_text()
    if hasattr(sheet, "add_source"):
        try:
            sheet.add_source(text, str(STYLESHEET))
        except TypeError:                      # signature varies by version
            sheet.add_source(text)
    else:                                       # older Textual
        sheet.read(str(STYLESHEET))
    sheet.parse()


def test_the_app_starts(tmp_path):
    """The test that 2.5.0 needed: boot it and see."""

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            assert app.screen is not None

    asyncio.run(go())


def test_every_tab_opens(tmp_path):
    from textual.widgets import TabbedContent

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            tabs = app.query_one("#tabs", TabbedContent)
            for tab_id, _label, pane_class in TABS:
                tabs.active = tab_id
                await pilot.pause()
                assert tabs.active == tab_id, tab_id
                assert app.query(pane_class), tab_id

    asyncio.run(go())


def test_every_theme_applies(tmp_path):
    """A malformed colour in any palette would surface here."""

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            for name in THEME_NAMES:
                app.apply_theme(name, persist=False)
                await pilot.pause()
                assert app.config_obj.theme == name
                assert app.palette.name == name

    asyncio.run(go())


def test_the_password_dialog_opens_and_closes(tmp_path):
    """Where the broken CSS lived: the modal has to mount and render."""
    from netzilla.screens.password import PasswordPrompt

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            app.push_screen(PasswordPrompt(title="TEST", note="a note"))
            await pilot.pause()
            assert isinstance(app.screen, PasswordPrompt)
            assert app.screen.query("#password-input")
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, PasswordPrompt)

    asyncio.run(go())


def test_the_capture_tab_lays_its_buttons_out(tmp_path):
    """Every button present, across two rows — thirteen of them since 2.6."""
    from netzilla.screens.capture import CapturePane

    async def go():
        from textual.widgets import TabbedContent

        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            app.query_one("#tabs", TabbedContent).active = "capture"
            await pilot.pause()
            pane = app.query_one(CapturePane)
            assert len(pane.query(".action-row")) == 2
            for action in CapturePane.ACTIONS:
                assert pane.query(f"#act-{action.key}"), action.key
            # The 2.6 additions specifically.
            assert pane.query("#act-stop") and pane.query("#act-held")

    asyncio.run(go())


def test_the_new_wifi_and_flow_tabs_open_and_lay_out(tmp_path):
    """3.0 added WIFI and FLOW; make sure both mount with all their buttons."""
    from textual.widgets import TabbedContent

    from netzilla.screens.flows import FlowPane
    from netzilla.screens.wifi import WifiPane

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            tabs = app.query_one("#tabs", TabbedContent)
            for tab_id, pane_class in (("wifi", WifiPane), ("flow", FlowPane)):
                tabs.active = tab_id
                await pilot.pause()
                pane = app.query_one(pane_class)
                for action in pane_class.ACTIONS:
                    assert pane.query(f"#act-{action.key}"), action.key

    asyncio.run(go())


def test_pressing_stop_with_nothing_running_is_harmless(tmp_path):
    """STOP LIVE bypasses the worker machinery, so it gets its own check."""
    from netzilla.screens.capture import CapturePane

    async def go():
        from textual.widgets import TabbedContent

        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            app.query_one("#tabs", TabbedContent).active = "capture"
            await pilot.pause()
            pane = app.query_one(CapturePane)
            await pilot.click("#act-stop")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert not pane._stop_live, "the flag must not be left latched"
            assert pane.results.children, "it should still say something"

    asyncio.run(go())
