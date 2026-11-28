"""The Textual driver behind the window.

Textual normally writes to a terminal and reads keys from it through a
driver (LinuxDriver, WindowsDriver; its web version uses a WebDriver that
sends the same output down a pipe). WindowDriver is netzilla's: everything
Textual writes goes to the window's own terminal (screen.py), and the
window's keyboard and mouse come back in as the bytes a terminal would send,
through Textual's own input parser.

Textual runs in a thread of its own; the window (tkinter) in the main one.
write() only queues text for the window, and input reaches the app with
run_coroutine_threadsafe, so neither side ever waits for the other.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

from textual import events, messages
from textual._xterm_parser import XTermParser
from textual.driver import Driver
from textual.geometry import Size


class WindowDriver(Driver):
    """Textual's output into the window, the window's input into Textual."""

    window: Any = None            # set on the class bind() makes

    def __init__(self, app, *, debug: bool = False, mouse: bool = True,
                 size: tuple[int, int] | None = None) -> None:
        super().__init__(app, debug=debug, mouse=mouse, size=size)
        self._window = self.window
        self._parser = XTermParser()
        self._input_lock = threading.Lock()
        self._closed = False

    # ------------------------------------------------------------ identity
    @property
    def is_window(self) -> bool:
        """netzilla's own window (app.py and clipboard.py ask)."""
        return True

    @property
    def cell_px(self) -> tuple[int, int] | None:
        """The window's cell size in pixels, which pixel graphs are drawn at."""
        window = self._window
        return window.cell_px if window is not None else None

    def window_command(self, action: str, *args) -> None:
        """Ask the window to do something (from the command palette)."""
        if self._window is not None:
            self._window.request(action, *args)

    # ------------------------------------------------------------ output
    def write(self, data: str) -> None:
        if self._window is not None and data:
            self._window.output(data)

    def flush(self) -> None:
        pass

    # ------------------------------------------------------------ lifecycle
    def start_application_mode(self) -> None:
        loop = asyncio.get_running_loop()
        window = self._window
        if window is not None:
            window.attach(self)
            cols, rows = window.grid
            cell_w, cell_h = window.cell_px
        else:                    # pragma: no cover - always bound in use
            cols, rows = self._size or (80, 24)
            cell_w, cell_h = 10, 20
        event = self._resize_event(cols, rows, cell_w, cell_h)
        asyncio.run_coroutine_threadsafe(self._app._post_message(event), loop=loop)

    def disable_input(self) -> None:
        self._closed = True

    def stop_application_mode(self) -> None:
        self._closed = True
        if self._window is not None:
            self._window.app_stopped()

    # ------------------------------------------------------------ input
    # These run on the window's thread.
    def feed(self, data: str) -> None:
        """Bytes as a terminal would send them: keys, mouse reports."""
        if self._closed or not data:
            return
        with self._input_lock:
            for event in self._parser.feed(data):
                self.process_message(event)

    def post(self, message) -> None:
        """An event built by the window (paste, focus, resize)."""
        if not self._closed:
            self.process_message(message)

    def resize(self, cols: int, rows: int, cell_w: int, cell_h: int) -> None:
        self.post(self._resize_event(cols, rows, cell_w, cell_h))

    def quit(self) -> None:
        """The window's close button: the app exits as if Q were pressed."""
        if not self._closed:
            self.send_message(messages.ExitApp())

    @staticmethod
    def _resize_event(cols: int, rows: int, cell_w: int, cell_h: int) -> events.Resize:
        size = Size(cols, rows)
        return events.Resize(size, size, size, Size(cols * cell_w, rows * cell_h))


def bind(window) -> type[WindowDriver]:
    """A WindowDriver class that talks to `window` (Textual builds the
    driver itself, from a class)."""
    return type("BoundWindowDriver", (WindowDriver,), {"window": window})


__all__ = ["WindowDriver", "bind"]
