"""netzilla in a window of its own — the Windows .exe, and `netzilla --window`
on any system with tkinter.

No terminal is involved. netzilla (Textual) draws into a terminal netzilla
keeps itself (screen.py), fed through a Textual driver of its own
(driver.py); Pillow paints that terminal's cells (paint.py) with the
bundled JetBrains Mono, draws box drawing, blocks, sextants and braille to
the cell (glyphs.py), shows the pixel graphs and the DASH banner the way
Ghostty does (the kitty graphics protocol with Unicode placeholders), and
lays a CRT over the whole window: phosphor glow and scanlines. tkinter
(tkwindow.py) shows the picture and sends the keyboard and mouse back.

Start it with `netzilla --window`, the `netzilla-window` command pipx
installs, or netzilla.exe.
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys

from .. import __version__


def build_parser() -> argparse.ArgumentParser:
    from ..themes import THEME_NAMES

    parser = argparse.ArgumentParser(
        prog="netzilla-window",
        description="netzilla in its own window, drawn exactly as in a pixel-graphics "
                    "terminal, with a CRT glow and scanlines.",
    )
    parser.add_argument("--theme", choices=THEME_NAMES, type=str.lower,
                        help="start with a specific colour theme")
    parser.add_argument("--tab", help="open on a specific tab, by name in any case")
    parser.add_argument("--graphics", choices=("auto", "pixel", "text"), type=str.lower,
                        help="draw graphs as pixels (the default here) or as text")
    parser.add_argument("--config", help="path to an alternative config.toml")
    parser.add_argument("--offline", action="store_true",
                        help="disable all network calls; local tools keep working")
    parser.add_argument("--font-size", type=int, default=0, metavar="PX",
                        help="text size in pixels (default: the size you last chose, "
                             "or the size at which DASH's 160 x 50 fits the screen)")
    crt = parser.add_mutually_exclusive_group()
    crt.add_argument("--crt", dest="crt", action="store_true", default=None,
                     help="phosphor glow and scanlines over the whole window (the default)")
    crt.add_argument("--no-crt", dest="crt", action="store_false",
                     help="no glow or scanlines: cells exactly as Ghostty draws them")
    # The Windows build's smoke test: run for N seconds, save a picture of
    # the window and a JSON report, then quit.
    parser.add_argument("--selftest", type=float, default=0.0, help=argparse.SUPPRESS)
    parser.add_argument("--report", default="", help=argparse.SUPPRESS)
    parser.add_argument("--screenshot", default="", help=argparse.SUPPRESS)
    parser.add_argument("--press", default="", help=argparse.SUPPRESS)
    parser.add_argument("--window", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-probe", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version", version=f"netzilla {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point of `netzilla-window` and of netzilla.exe."""
    log = _streams()
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as stop:
        return int(stop.code or 0)
    from .tkwindow import Options

    options = Options(theme=args.theme, tab=args.tab, graphics=args.graphics,
                      config_path=args.config, offline=args.offline,
                      font_size=max(0, args.font_size), crt=args.crt,
                      selftest=max(0.0, args.selftest), report=args.report,
                      screenshot=args.screenshot,
                      press=[key for key in args.press.split(",") if key])
    return run(options, log)


# The .exe has no console: it says what went wrong in a message box, except
# in the self-test, which must never wait for a click.
_DIALOGS = True


def run(options, log=None) -> int:
    """Open the window and run netzilla in it; returns the exit status."""
    global _DIALOGS
    log = log or sys.stderr
    _DIALOGS = not options.selftest
    prepare_process()
    try:
        importlib.import_module("tkinter")
    except ImportError:
        _say(log, "netzilla's window needs tkinter, which this Python doesn't have. "
                  "On Linux: sudo apt install python3-tk (Debian, Ubuntu, Mint) or "
                  "sudo dnf install python3-tkinter (Fedora).")
        return 1

    from .. import termcaps
    from ..app import NetzillaApp, resolve_tab
    from ..config import Config
    from ..graphics import plot
    from ..themes import DEFAULT_THEME, PALETTES
    from .tkwindow import Window

    config = Config.load(options.config_path)
    if options.theme:
        config.theme = options.theme
    if config.theme not in PALETTES:
        config.theme = DEFAULT_THEME
    if options.tab and resolve_tab(options.tab) is None:
        _say(log, f"netzilla: unknown tab '{options.tab}' — opening DASH.")
        options.tab = None
    try:
        window = Window(options, config)
    except Exception as error:      # no display, or Tk refused to start
        _say(log, f"netzilla could not open its window: {error}")
        return 1
    window.log = log
    termcaps.set_current(termcaps.window_info(window.cell_px))
    plot.SCANLINES = not window.painter.crt
    app = NetzillaApp(config_path=options.config_path, theme_name=options.theme,
                      offline=options.offline, start_tab=options.tab,
                      graphics=options.graphics)
    truecolour(app)
    window.start(app)
    if window.error is not None:
        _report_crash(window, log, repr(window.error))
        return 1
    if getattr(app, "return_code", 0) not in (0, None):
        _report_crash(window, log, "")
        return int(app.return_code or 1)
    if options.selftest and not window.report:
        return 1
    return 0


def truecolour(app) -> None:
    """Textual must write 24-bit colour into the window (the theme's colours,
    and the image ids in pixel-graph placeholders) whatever the console it
    was started from could do."""
    try:
        from rich.color import ColorSystem

        if app.console.color_system != "truecolor":
            app.console._color_system = ColorSystem.TRUECOLOR
    except Exception:
        pass


def prepare_process() -> None:
    """Settings that must be in place before Textual starts."""
    os.environ["TEXTUAL_COLOR_SYSTEM"] = "truecolor"
    os.environ["COLORTERM"] = "truecolor"
    os.environ.pop("NO_COLOR", None)
    os.environ["NETZILLA_NO_PROBE"] = "1"
    from .. import hostos

    if hostos.is_windows():
        _windows_setup()


def _windows_setup() -> None:
    from .. import hostos

    try:
        import ctypes

        # Crisp pixels on scaled displays: draw at the screen's real
        # resolution rather than letting Windows stretch a blurry bitmap.
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
        # Our own taskbar button and icon, not python's.
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("netzilla.window")
    except Exception:
        pass
    # The tools netzilla runs (ping, tracert, netsh…) must not each open a
    # console window of their own.
    hostos.hide_console_windows()


def _streams():
    """Where messages go. The .exe has no console (sys.stderr is None):
    then they go to netzilla-window.log next to config.toml."""
    if sys.stderr is not None and sys.stdout is not None:
        return sys.stderr
    try:
        from .. import hostos

        folder = hostos.config_dir()
        folder.mkdir(parents=True, exist_ok=True)
        log = open(folder / "netzilla-window.log", "w", encoding="utf-8", buffering=1)
    except Exception:
        log = open(os.devnull, "w", encoding="utf-8")
    if sys.stdout is None:
        sys.stdout = log
    if sys.stderr is None:
        sys.stderr = log
    return log


def _say(log, message: str) -> None:
    try:
        print(message, file=log)
    except Exception:
        pass
    if _DIALOGS and getattr(sys, "frozen", False):
        try:
            import tkinter
            from tkinter import messagebox

            root = tkinter.Tk()
            root.withdraw()
            messagebox.showerror("netzilla", message)
            root.destroy()
        except Exception:
            pass


def _report_crash(window, log, detail: str) -> None:
    where = getattr(log, "name", "")
    message = "netzilla stopped with an error."
    if detail:
        message += f"\n\n{detail}"
    if where and where not in ("<stderr>", os.devnull):
        message += f"\n\nThe details are in {where}"
    _say(log, message)


__all__ = ["main", "run", "build_parser", "prepare_process", "truecolour"]
