"""The window: tkinter on the main thread, netzilla (Textual) on another.

Textual's output is queued by the driver and picked up here every few
milliseconds: the terminal (screen.py) takes it in, the painter redraws the
cells that changed, and only those parts of the picture are copied to the
window. Keys, the mouse, focus, pasting and resizing go the other way,
through the driver.

Window keys: Ctrl + / Ctrl − text size (remembered), Ctrl 0 the size that
fits DASH, F11 or Alt+Enter full screen, Ctrl+V / Shift+Insert paste,
Ctrl+click a link to open it.
"""

from __future__ import annotations

import collections
import json
import os
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field

from PIL import Image

from .. import __version__, hostos
from ..themes import get_palette
from . import keys
from .driver import bind
from .fonts import MAX_PX, MIN_PX, FontSet, fit_px
from .paint import Painter, rgb
from .screen import Screen

DASH_GRID = (160, 50)        # DASH is laid out for 160 x 50 and must fit it
POINTERS = {
    "default": "arrow", "pointer": "hand2", "text": "xterm", "crosshair": "crosshair",
    "help": "question_arrow", "wait": "watch", "progress": "watch", "move": "fleur",
    "grab": "fleur", "grabbing": "fleur", "not-allowed": "X_cursor",
    "ew-resize": "sb_h_double_arrow", "col-resize": "sb_h_double_arrow",
    "ns-resize": "sb_v_double_arrow", "row-resize": "sb_v_double_arrow",
}


@dataclass
class Options:
    """How the window was asked to start."""

    theme: str | None = None
    tab: str | None = None
    graphics: str | None = None
    config_path: str | None = None
    offline: bool = False
    font_size: int = 0                 # pixels; 0 = the saved size, else fit DASH
    crt: bool | None = None            # None = the saved choice
    selftest: float = 0.0              # seconds to run before saving a report and leaving
    report: str = ""                   # where the self-test writes its JSON
    screenshot: str = ""               # where the self-test saves the window as PNG
    press: list = field(default_factory=list)  # self-test: keys to press, half-way through


def hex_colour(value: int) -> str:
    return "#%02x%02x%02x" % rgb(value)


class Window:
    POLL_BUSY = 8          # ms between looks at Textual's output while it is drawing
    POLL_IDLE = 25

    def __init__(self, options: Options, config) -> None:
        import tkinter as tk

        from PIL import ImageTk

        self.tk = tk
        self.ImageTk = ImageTk
        self.options = options
        self.config = config
        self.system = hostos.NAME
        self.app = None
        self._driver = None
        self._thread: threading.Thread | None = None
        self._output: collections.deque = collections.deque()
        self._actions: collections.deque = collections.deque()
        self._images_dirty = False
        self._stopped = False
        self._closing_since = 0.0
        self._fullscreen = False
        self._focused = True
        self._title = "netzilla"
        self._last_cell = (-1, -1)
        self._buttons_down: set[int] = set()
        self._after_id = None
        self._regrid_id = None
        self._started = time.monotonic()
        self.error: BaseException | None = None
        self.report: dict = {}
        # Textual swaps sys.stderr while it runs, so errors are written to
        # the stream that was in place when the window opened.
        self.log = sys.stderr

        root = self.root = tk.Tk(className="netzilla")
        root.withdraw()
        root.title(self._title)
        palette = get_palette(config.theme)
        self.default_bg = int(palette.background.lstrip("#"), 16)
        self.default_fg = int(palette.foreground.lstrip("#"), 16)
        crt = config.window_crt if options.crt is None else options.crt
        self._fit = self._fit_px()
        px = options.font_size or config.window_font_size or self._fit
        self.fonts = FontSet(max(MIN_PX, min(MAX_PX, px)))
        self.painter = Painter(self.fonts, crt=crt, default_fg=self.default_fg,
                               default_bg=self.default_bg)
        cols, rows = self._start_grid()
        self.grid = (cols, rows)
        self.screen = Screen(cols, rows)
        self._wire_screen()
        cw, ch = self.fonts.cell
        width, height = cols * cw, rows * ch
        self._canvas_size = (width, height)
        self._pad = (0, 0)
        self.canvas = tk.Canvas(root, width=width, height=height, highlightthickness=0,
                                borderwidth=0, background=hex_colour(self.default_bg),
                                cursor="arrow", takefocus=1)
        self.canvas.pack(fill="both", expand=True)
        self.photo = ImageTk.PhotoImage(Image.new("RGB", (width, height),
                                                  rgb(self.default_bg)))
        self._photo_size = (width, height)
        self.item = self.canvas.create_image(0, 0, anchor="nw", image=self.photo)
        self._set_icon()
        self._bind()
        root.minsize(cw * 40, ch * 10)
        root.geometry(f"{width}x{height}")
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        root.deiconify()
        self.canvas.focus_set()

    # ------------------------------------------------------------ sizing
    def _screen_area(self) -> tuple[int, int]:
        """The usable part of the screen for a new window, in pixels."""
        root = self.root
        width, height = root.winfo_screenwidth(), root.winfo_screenheight()
        area = _work_area() if self.system == "windows" else None
        if area:
            width, height = area
        # Room for the title bar and window border.
        return max(320, width - 16), max(240, height - 48)

    def _fit_px(self) -> int:
        """The text size at which DASH's 160 x 50 fills at most the screen,
        and no bigger than a comfortable 13 pt."""
        width, height = self._screen_area()
        try:
            dpi = float(self.root.winfo_fpixels("1i"))
        except Exception:
            dpi = 96.0
        ceiling = max(MIN_PX, round(13 * dpi / 72))
        return fit_px(*DASH_GRID, width, height, ceiling=ceiling)

    def _start_grid(self) -> tuple[int, int]:
        cw, ch = self.fonts.cell
        width, height = self._screen_area()
        cols = min(DASH_GRID[0], max(40, width // cw))
        rows = min(DASH_GRID[1], max(10, height // ch))
        return cols, rows

    @property
    def cell_px(self) -> tuple[int, int]:
        return self.fonts.cell

    # ------------------------------------------------------------ wiring
    def _wire_screen(self) -> None:
        screen = self.screen
        screen.on_clipboard = self._set_clipboard
        screen.on_bell = self._bell
        screen.on_notify = self._notify
        screen.on_pointer = self._pointer
        screen.on_reply = self._reply
        screen.on_images = self._images_changed

    def _bind(self) -> None:
        root, canvas = self.root, self.canvas
        root.bind("<KeyPress>", self._on_key)
        canvas.bind("<Configure>", self._on_configure)
        for button in (1, 2, 3):
            canvas.bind(f"<ButtonPress-{button}>", self._on_press)
            canvas.bind(f"<ButtonRelease-{button}>", self._on_release)
        canvas.bind("<Motion>", self._on_motion)
        canvas.bind("<MouseWheel>", self._on_wheel)
        canvas.bind("<Shift-MouseWheel>", self._on_wheel)
        # X11 reports the wheel as buttons 4 and 5 (6 and 7 sideways, where
        # this Tk knows those buttons).
        for button in (4, 5, 6, 7):
            try:
                canvas.bind(f"<Button-{button}>", self._on_wheel)
            except self.tk.TclError:
                pass
        root.bind("<FocusIn>", self._on_focus_in)
        root.bind("<FocusOut>", self._on_focus_out)

    def _set_icon(self) -> None:
        try:
            from .icon import icon_image

            self._icons = [self.ImageTk.PhotoImage(icon_image(size)) for size in (64, 32, 16)]
            self.root.iconphoto(True, *self._icons)
        except Exception:
            self._icons = []

    # ------------------------------------------------------------ from the app thread
    def output(self, data: str) -> None:
        self._output.append(data)

    def attach(self, driver) -> None:
        self._driver = driver

    def app_stopped(self) -> None:
        self._stopped = True

    def request(self, action: str, *args) -> None:
        self._actions.append((action, args))

    # ------------------------------------------------------------ running
    def start(self, app) -> None:
        """Run netzilla in this window until it quits or the window closes."""
        self.app = app
        app.driver_class = bind(self)
        self._thread = threading.Thread(target=self._run_app, name="netzilla-app",
                                        daemon=True)
        self._thread.start()
        self._after_id = self.root.after(1, self._tick)
        self.root.mainloop()

    def _run_app(self) -> None:
        try:
            self.app.run()
        except BaseException as error:           # reported by the window
            self.error = error
        finally:
            self._stopped = True

    def _tick(self) -> None:
        busy = False
        chunks = []
        output = self._output
        while output:
            chunks.append(output.popleft())
        try:
            if chunks:
                busy = True
                self.screen.feed("".join(chunks))
            while self._actions:
                action, args = self._actions.popleft()
                self._do(action, *args)
                busy = True
            if self._images_dirty:
                self._images_dirty = False
                self.painter.images_changed(self.screen, self.screen.take_changed_images())
            self._render()
        except Exception as error:               # never let one bad frame stop the window
            self._log_error(error)
        if self.options.selftest:
            self._selftest_step()
        if self._thread is not None and not self._thread.is_alive():
            self._finish()
            return
        if self._closing_since and time.monotonic() - self._closing_since > 4.0:
            self._finish()
            return
        self._after_id = self.root.after(self.POLL_BUSY if busy else self.POLL_IDLE,
                                         self._tick)

    def _render(self) -> None:
        boxes = self.painter.paint(self.screen)
        if not boxes:
            return
        frame = self.painter.frame
        if frame.size != self._photo_size:
            self.photo = self.ImageTk.PhotoImage(frame)
            self._photo_size = frame.size
            self.canvas.itemconfigure(self.item, image=self.photo)
        else:
            area = sum((x1 - x0) * (y1 - y0) for x0, y0, x1, y1 in boxes)
            if area * 3 > frame.size[0] * frame.size[1]:
                self.photo.paste(frame)
            else:
                for box in boxes:
                    piece = self.ImageTk.PhotoImage(frame.crop(box))
                    self.photo.tk.call(str(self.photo), "copy", str(piece), "-to",
                                       box[0], box[1])
        self._edge_colour()

    def _edge_colour(self) -> None:
        """The margin round the cells takes the app's background colour."""
        screen = self.screen
        style = screen.styles[screen.rows // 2][0]
        bg = self.default_bg if style.bg is None else style.bg
        colour = hex_colour(bg)
        if colour != str(self.canvas.cget("background")):
            self.canvas.configure(background=colour)

    def _finish(self) -> None:
        if self._after_id is not None:
            try:
                self.root.after_cancel(self._after_id)
            except Exception:
                pass
        try:
            self.root.destroy()
        except Exception:
            pass

    # ------------------------------------------------------------ actions
    def _do(self, action: str, *args) -> None:
        if action == "zoom_in":
            self._zoom(+1)
        elif action == "zoom_out":
            self._zoom(-1)
        elif action == "zoom_reset":
            self._zoom(0)
        elif action == "fullscreen":
            self._toggle_fullscreen()
        elif action == "crt":
            on = (not self.painter.crt) if not args else bool(args[0])
            self._set_crt(on)
        elif action == "paste":
            self._paste()

    def _zoom(self, step: int) -> None:
        px = self._fit if step == 0 else max(MIN_PX, min(MAX_PX, self.fonts.px + step))
        if px == self.fonts.px:
            return
        self.fonts = FontSet(px)
        self.painter.set_fonts(self.fonts)
        self.screen.mark_all()
        self._regrid(force=True)
        self._save_setting("window_font_size", 0 if step == 0 else px)

    def _set_crt(self, on: bool) -> None:
        from ..graphics import plot

        self.painter.set_crt(on)
        plot.SCANLINES = not on
        self.screen.mark_all()
        self._save_setting("window_crt", on)
        self._in_app(self._refresh_graphics)

    def _refresh_graphics(self) -> None:
        refresh = getattr(self.app, "_refresh_static_graphics", None)
        if refresh is not None:
            refresh()

    def _toggle_fullscreen(self) -> None:
        self._fullscreen = not self._fullscreen
        try:
            self.root.attributes("-fullscreen", self._fullscreen)
        except Exception:
            self._fullscreen = False

    def _save_setting(self, name: str, value) -> None:
        """Remember a window setting in config.toml — saved on the app's
        thread, which owns the config."""
        config = getattr(self.app, "config_obj", None) or self.config
        setattr(config, name, value)

        def save() -> None:
            try:
                config.save()
            except OSError:
                pass

        self._in_app(save)

    def _in_app(self, callback) -> None:
        driver = self._driver
        loop = getattr(driver, "_loop", None)
        if loop is None:
            return
        try:
            loop.call_soon_threadsafe(callback)
        except RuntimeError:
            pass                                    # the app has already stopped

    # ------------------------------------------------------------ screen callbacks
    def _set_clipboard(self, text: str) -> None:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
        except Exception:
            pass

    def _bell(self) -> None:
        try:
            self.root.bell()
        except Exception:
            pass

    def _notify(self, title: str, body: str) -> None:
        """A long run finished while the window was in the background: say so
        in the title bar (and flash the taskbar button on Windows)."""
        if self._focused:
            return
        text = f"{title}: {body}" if body else title
        self.root.title(f"netzilla — {text}"[:120])
        if self.system == "windows":
            _flash(self.root)

    def _pointer(self, shape: str) -> None:
        cursor = POINTERS.get(shape.strip().lower(), "arrow")
        try:
            self.canvas.configure(cursor=cursor)
        except Exception:
            pass

    def _reply(self, text: str) -> None:
        if self._driver is not None:
            self._driver.feed(text)

    def _images_changed(self) -> None:
        self._images_dirty = True

    # ------------------------------------------------------------ input
    def _on_key(self, event):
        action = keys.key_action(event.keysym, event.char or "", int(event.state),
                                 self.system, int(getattr(event, "keysym_num", 0) or 0))
        if action.kind == "window":
            self._do(action.value)
        elif action.kind in ("text", "keys") and self._driver is not None:
            self._driver.feed(action.value)
        return "break"

    def _paste(self) -> None:
        try:
            text = self.root.clipboard_get()
        except Exception:
            return
        if text and self._driver is not None:
            from textual import events

            self._driver.post(events.Paste(text.replace("\r\n", "\n")))

    def _cell_at(self, event) -> tuple[int, int]:
        cw, ch = self.fonts.cell
        cols, rows = self.grid
        col = (int(event.x) - self._pad[0]) // cw
        row = (int(event.y) - self._pad[1]) // ch
        return max(0, min(cols - 1, col)), max(0, min(rows - 1, row))

    def _mods(self, event) -> int:
        return keys.modifiers(int(event.state), self.system)

    def _mouse(self, sequence: str) -> None:
        if self._driver is not None:
            self._driver.feed(sequence)

    def _on_press(self, event):
        self.canvas.focus_set()
        col, row = self._cell_at(event)
        mods = self._mods(event)
        if event.num == 1 and mods & keys.CTRL:
            link = self.screen.styles[row][col].link if row < self.screen.rows else None
            if link:
                try:
                    webbrowser.open(link)
                except Exception:
                    pass
                return "break"
        self._buttons_down.add(event.num)
        self._last_cell = (col, row)
        self._mouse(keys.mouse_sequence("press", event.num, col, row, mods))
        return "break"

    def _on_release(self, event):
        col, row = self._cell_at(event)
        if event.num not in self._buttons_down:
            return "break"
        self._buttons_down.discard(event.num)
        self._mouse(keys.mouse_sequence("release", event.num, col, row, self._mods(event)))
        return "break"

    def _on_motion(self, event):
        col, row = self._cell_at(event)
        if (col, row) == self._last_cell:
            return
        self._last_cell = (col, row)
        button = keys.held_button(int(event.state))
        self._mouse(keys.mouse_sequence("move", button, col, row, self._mods(event)))

    def _on_wheel(self, event):
        col, row = self._cell_at(event)
        mods = self._mods(event)
        num = getattr(event, "num", None)
        if num in (4, 5, 6, 7) and not getattr(event, "delta", 0):
            kind = {4: "wheel_up", 5: "wheel_down", 6: "wheel_left", 7: "wheel_right"}[num]
            count = 1
        else:
            delta = int(getattr(event, "delta", 0) or 0)
            if not delta:
                return "break"
            sideways = bool(mods & keys.SHIFT)
            kind = ("wheel_left" if delta > 0 else "wheel_right") if sideways else \
                ("wheel_up" if delta > 0 else "wheel_down")
            mods &= ~keys.SHIFT if sideways else ~0
            count = max(1, abs(delta) // 120) if self.system == "windows" else 1
        for _ in range(min(count, 10)):
            self._mouse(keys.mouse_sequence(kind, 0, col, row, mods))
        return "break"

    def _on_focus_in(self, event):
        if event.widget is not self.root and event.widget is not self.canvas:
            return
        if not self._focused:
            self._focused = True
            self.root.title(self._title)
            if self._driver is not None:
                from textual import events

                self._driver.post(events.AppFocus())

    def _on_focus_out(self, event):
        if event.widget is not self.root and event.widget is not self.canvas:
            return
        if self._focused:
            self._focused = False
            if self._driver is not None:
                from textual import events

                self._driver.post(events.AppBlur())

    def _on_configure(self, event):
        if event.widget is not self.canvas:
            return
        self._canvas_size = (int(event.width), int(event.height))
        if self._regrid_id is not None:
            self.root.after_cancel(self._regrid_id)
        self._regrid_id = self.root.after(40, self._regrid)

    def _regrid(self, force: bool = False) -> None:
        self._regrid_id = None
        cw, ch = self.fonts.cell
        width, height = self._canvas_size
        cols = max(20, width // cw)
        rows = max(6, height // ch)
        self._pad = (max(0, (width - cols * cw) // 2), max(0, (height - rows * ch) // 2))
        self.canvas.coords(self.item, *self._pad)
        if force or (cols, rows) != self.grid:
            self.grid = (cols, rows)
            self.screen.resize(cols, rows)
            self.screen.mark_all()
            if self._driver is not None:
                self._driver.resize(cols, rows, cw, ch)

    def _on_close(self) -> None:
        if self._driver is not None and self._thread is not None and self._thread.is_alive():
            if not self._closing_since:
                self._closing_since = time.monotonic()
                self._driver.quit()
            return
        self._finish()

    # ------------------------------------------------------------ self-test
    def _selftest_step(self) -> None:
        """The self-test presses its keys half-way through, then reports."""
        elapsed = time.monotonic() - self._started
        total = self.options.selftest
        if self.options.press and elapsed >= total / 2:
            self.press(self.options.press.pop(0))
        if elapsed >= total:
            self._finish_selftest()

    def press(self, name: str) -> None:
        """Press a key as if typed, by name: "F2", "q", "ctrl+p", "shift+Tab"."""
        *held, keysym = name.split("+") if len(name) > 1 else [name]
        masks = keys._TK_MASKS.get(self.system, keys._TK_MASKS["linux"])
        state = 0
        for mod in held:
            index = ("shift", "ctrl", "alt", "super").index(mod.lower())
            state |= masks[index]
        char = keysym if len(keysym) == 1 and not state & masks[1] else ""

        class Event:
            pass

        event = Event()
        event.keysym, event.char, event.state, event.keysym_num = keysym, char, state, 0
        self._on_key(event)

    def ask_app(self, question, timeout: float = 2.0):
        """Run `question()` on the app's thread and return its answer (None
        when the app does not answer in time)."""
        import asyncio

        loop = getattr(self._driver, "_loop", None)
        if loop is None:
            return None

        async def ask():
            return question()

        try:
            return asyncio.run_coroutine_threadsafe(ask(), loop).result(timeout)
        except Exception:
            return None

    def _finish_selftest(self) -> None:
        """Save what the window shows and a short report, then quit (the
        Windows build's smoke test runs this on a real Windows machine)."""
        if self.report:
            return
        try:
            self.report = self.describe()
            if self.options.screenshot:
                self.painter.frame.save(self.options.screenshot)
            if self.options.report:
                with open(self.options.report, "w", encoding="utf-8") as handle:
                    json.dump(self.report, handle, indent=2)
        except Exception as error:
            self._log_error(error)
        self._on_close()

    def describe(self) -> dict:
        screen = self.screen
        cells = [c for row in screen.chars for c in row]
        from ..graphics.kitty import PLACEHOLDER

        main = getattr(self.fonts.regular, "path", "")
        return {
            "version": __version__,
            "system": hostos.NAME,
            "python": sys.version.split()[0],
            "frozen": bool(getattr(sys, "frozen", False)),
            "font": os.path.basename(str(main)),
            "font_px": self.fonts.px,
            "cell": list(self.fonts.cell),
            "grid": list(self.grid),
            "crt": self.painter.crt,
            "frame": list(self.painter.frame.size) if self.painter.frame else None,
            "images": len(screen.images),
            "placeholder_cells": sum(1 for c in cells if c[:1] == PLACEHOLDER),
            "sextant_cells": sum(1 for c in cells if c[:1] and 0x1FB00 <= ord(c[0]) <= 0x1FB3B),
            "text": screen.text().splitlines()[:3],
            "pixel_graphs": getattr(self.app, "graphics_mode", "") == "pixel",
            "tab": self.ask_app(self._active_tab),
            "uptime": round(time.monotonic() - self._started, 1),
        }

    def _active_tab(self) -> str:
        try:
            return str(self.app.query_one("#tabs").active)
        except Exception:
            return ""

    def _log_error(self, error: BaseException) -> None:
        import traceback

        try:
            traceback.print_exception(type(error), error, error.__traceback__, file=self.log)
        except Exception:
            pass


def _work_area() -> tuple[int, int] | None:
    """The Windows desktop minus the taskbar, in pixels."""
    try:
        import ctypes
        from ctypes import wintypes

        rect = wintypes.RECT()
        if ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0):
            return rect.right - rect.left, rect.bottom - rect.top
    except Exception:
        pass
    return None


def _flash(root) -> None:
    """Flash the window's taskbar button until it is brought forward."""
    try:
        import ctypes
        from ctypes import wintypes

        class FLASHWINFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("hwnd", wintypes.HWND),
                        ("dwFlags", wintypes.DWORD), ("uCount", wintypes.UINT),
                        ("dwTimeout", wintypes.DWORD)]

        hwnd = int(root.wm_frame(), 16)
        info = FLASHWINFO(ctypes.sizeof(FLASHWINFO), hwnd, 0x3 | 0xC, 0, 0)
        ctypes.windll.user32.FlashWindowEx(ctypes.byref(info))
    except Exception:
        pass


__all__ = ["Window", "Options", "DASH_GRID"]
