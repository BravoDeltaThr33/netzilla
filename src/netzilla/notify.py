"""Desktop notifications through the terminal, when a long run finishes.

If a lookup takes a while (an SSL Labs grade, a speed test, a LAN sweep) and
you switch to another window, netzilla taps you on the shoulder when it is
done — through the terminal's own notification escape, so it works over
SSH too:

  kitty            OSC 99   (title and body)
  Ghostty, foot,   OSC 777  (notify;title;body)
  WezTerm
  iTerm2           OSC 9    (one line)

Only when the terminal window is not focused (terminals report focus to the
app), only for runs of NOTIFY_AFTER seconds or more, and never if switched
off on SETTINGS.
"""

from __future__ import annotations

import re

from . import termcaps

NOTIFY_AFTER = 8.0

_UNSAFE = re.compile(r"[\x00-\x1f\x7f;]")


def _clean(text: str, limit: int = 180) -> str:
    return _UNSAFE.sub(" ", text or "").strip()[:limit]


def sequence(kind: str, title: str, body: str) -> str:
    """The escape sequence for one notification, or '' if `kind` is none."""
    title, body = _clean(title, 80), _clean(body)
    if kind == "osc99":
        return (f"\x1b]99;i=netzilla:d=0;{title}\x1b\\"
                f"\x1b]99;i=netzilla:p=body;{body}\x1b\\")
    if kind == "osc777":
        return f"\x1b]777;notify;{title};{body}\x07"
    if kind == "osc9":
        return f"\x1b]9;{title}: {body}\x07"
    return ""


def desktop(app, title: str, body: str) -> bool:
    """Send a notification if the terminal supports one. True if sent."""
    info = termcaps.current()
    escape = sequence(info.notify, title, body)
    driver = getattr(app, "_driver", None)
    if not escape or driver is None or getattr(app, "is_headless", False):
        return False
    if info.passthrough:
        escape = termcaps.wrap_tmux(escape)
    try:
        driver.write(escape)
    except Exception:
        return False
    return True


def finished(app, pane_title: str, action: str, seconds: float) -> bool:
    """Notify that a run finished, if it was long and nobody was watching."""
    config = getattr(app, "config_obj", None)
    if config is not None and not getattr(config, "notify", True):
        return False
    if seconds < NOTIFY_AFTER or getattr(app, "app_focus", True):
        return False
    return desktop(app, f"netzilla — {pane_title.title()}",
                   f"{action} finished after {seconds:.0f}s")


__all__ = ["sequence", "desktop", "finished", "NOTIFY_AFTER"]
