"""Copying a tab's results as plain text (F4).

The output is re-rendered without colour at the width it is shown, so
tables keep their columns when pasted into a ticket or a chat. Where it
goes, best first:

  1. the desktop clipboard through the usual tool — wl-copy (Wayland),
     xclip or xsel (X11), pbcopy (macOS), clip.exe (Windows and WSL) — when
     netzilla runs on the machine whose screen you are looking at;
  2. the terminal's own clipboard, via OSC 52 — the way that also works
     over SSH (kitty, Ghostty, WezTerm, iTerm2, foot, Windows Terminal…);
  3. and, when neither can be relied on, a text file as well, whose path is
     shown, so the output is never simply lost.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import time
from pathlib import Path

from rich.console import Console

from . import termcaps
from .graphics.kitty import PLACEHOLDER
from .graphics.sixel import MARKER

# Kept short: a clipboard tool that hangs must not freeze the interface.
TOOL_TIMEOUT = 2.0


def plain(renderables, width: int = 120) -> str:
    """Render Rich renderables to plain text at `width` columns."""
    buffer = io.StringIO()
    console = Console(file=buffer, width=max(40, width), color_system=None,
                      force_terminal=False, legacy_windows=False, record=False,
                      soft_wrap=False, emoji=False)
    for renderable in renderables:
        console.print(renderable)
    return _strip_graphics(buffer.getvalue())


def _strip_graphics(text: str) -> str:
    """Pixel graphs are placeholder characters underneath (Sixel graphs,
    blank marker cells); a pasted graph becomes a plain shaded block of the
    same size."""
    if MARKER in text:
        text = text.replace(MARKER, "░")
    if PLACEHOLDER not in text:
        return text
    lines = []
    for line in text.splitlines():
        if PLACEHOLDER in line:
            out = []
            for char in line:
                if char == PLACEHOLDER:
                    out.append("░")
                elif 0x300 <= ord(char) <= 0x1D244 and _combining(char):
                    continue
                else:
                    out.append(char)
            line = "".join(out)
        lines.append(line)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _combining(char: str) -> bool:
    import unicodedata

    return unicodedata.combining(char) != 0 or unicodedata.category(char) == "Mn"


def pane_text(pane) -> str:
    """Everything in a tab's results area, as plain text."""
    try:
        results = pane.query_one(".results")
    except Exception:
        return ""
    try:
        width = max(40, int(results.size.width) - 2)
    except Exception:
        width = 120
    renderables = []
    for widget in results.children:
        if not widget.display:
            continue
        content = getattr(widget, "content", None)
        if content is None or content == "":
            continue
        if "idle-hint" in widget.classes:
            continue
        renderables.append(content)
    return plain(renderables, width).rstrip() + "\n" if renderables else ""


def _local_session() -> bool:
    env = os.environ
    return not (env.get("SSH_CONNECTION") or env.get("SSH_TTY") or env.get("SSH_CLIENT"))


def _tool_command() -> list[str] | None:
    env = os.environ
    if env.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
        return ["wl-copy"]
    if env.get("DISPLAY"):
        if shutil.which("xclip"):
            return ["xclip", "-selection", "clipboard"]
        if shutil.which("xsel"):
            return ["xsel", "--clipboard", "--input"]
    if shutil.which("pbcopy"):
        return ["pbcopy"]
    if shutil.which("clip.exe"):
        return ["clip.exe"]
    return None


def tool_input(command: list[str], text: str) -> tuple[bytes, dict | None]:
    """What to feed a clipboard tool, and the environment to run it in.
    clip.exe reads UTF-16 when the text starts with a byte-order mark (and
    the console's code page otherwise, which mangles '—' and '·'); pbcopy
    reads the locale's encoding, so it is told the text is UTF-8."""
    name = os.path.basename(command[0]).lower()
    if name == "clip.exe":
        return ("\ufeff" + text).encode("utf-16-le"), None
    if name == "pbcopy":
        return text.encode("utf-8"), dict(os.environ, LC_CTYPE="UTF-8")
    return text.encode("utf-8"), None


def _via_tool(text: str) -> str | None:
    command = _tool_command()
    if command is None:
        return None
    payload, env = tool_input(command, text)
    try:
        subprocess.run(command, input=payload, env=env, timeout=TOOL_TIMEOUT,
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    return f"to the clipboard with {command[0]}"


def save_file(text: str, directory: Path | None = None) -> Path:
    directory = directory or Path.home() / "netzilla-exports"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / time.strftime("output-%Y%m%d-%H%M%S.txt")
    path.write_text(text, encoding="utf-8")
    return path


def copy(text: str, app=None, directory: Path | None = None) -> str:
    """Put text on a clipboard; returns a short description of where."""
    if getattr(getattr(app, "_driver", None), "is_window", False):
        # netzilla's own window puts it straight on the desktop clipboard
        # (no clip.exe console flashing up).
        try:
            app.copy_to_clipboard(text)
        except Exception:
            pass
        else:
            return "to the clipboard"
    if _local_session():
        done = _via_tool(text)
        if done:
            return done
    info = termcaps.current()
    if app is not None and getattr(app, "_driver", None) is not None:
        try:
            app.copy_to_clipboard(text)
        except Exception:
            pass
        else:
            if info.clipboard:
                return f"to {info.label}'s clipboard (OSC 52)"
    try:
        path = save_file(text, directory)
    except OSError as exc:
        return f"could not copy or save ({exc})"
    return f"saved to {path}"


__all__ = ["plain", "pane_text", "copy", "save_file"]
