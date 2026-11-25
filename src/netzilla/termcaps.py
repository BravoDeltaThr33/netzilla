"""Knowing the terminal: which one it is, which version, and what it can draw.

netzilla asks the terminal directly, once, just before the interface starts
(the same handshake kitty, Ghostty and xterm document), and falls back to the
environment variables terminals set when it cannot ask:

  XTVERSION      CSI > 0 q   -> DCS > | kitty(0.36.4) ST, "ghostty 1.1.3" …
  kitty graphics APC G a=q   -> "OK" if the graphics protocol is understood
  feature query  APC G e=T,U=1 -> echoes U=1 when Unicode placeholders work
                 (kitty 0.50+; older terminals simply don't answer it)
  cell size      CSI 16 t    -> CSI 6 ; height ; width t, in pixels
  DA1            CSI c       -> every terminal answers this one, last, so its
                                reply means "nothing else is coming"

Pixel graphics need the kitty graphics protocol *with Unicode placeholders*:
the image is drawn wherever special placeholder characters appear, so it
moves and redraws with the text like any other cell — the only image method
that coexists with a full-screen text interface. kitty has it since 0.28.0
and Ghostty since its 1.0 release; WezTerm, Konsole and iTerm2 speak other
parts of the protocol (or other protocols) but not this one, so they get
netzilla's text graphs. Inside tmux it works when tmux passes the graphics
commands through (`set -g allow-passthrough on`) to kitty or Ghostty — the
probe tries exactly that.

Nothing here is required: a terminal that answers nothing is simply treated
as a capable text terminal, and every graph has a text form.
"""

from __future__ import annotations

import os
import re
import sys
import time
from dataclasses import dataclass, field, replace

# ------------------------------------------------------------------ queries
XTVERSION_Q = "\x1b[>0q"
KITTY_Q = "\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\"
FEATURE_Q = "\x1b_Ga=q,i=32,e=T,U=1\x1b\\"
CELL_Q = "\x1b[16t"
DA1_Q = "\x1b[c"
# Inside tmux the same two graphics questions, addressed past tmux to the
# terminal outside it (ids 33 and 34, so their answers can't be confused).
TMUX_KITTY_Q = "\x1b_Gi=33,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\"
TMUX_FEATURE_Q = "\x1b_Ga=q,i=34,e=T,U=1\x1b\\"

_XTVERSION_RE = re.compile(rb"\x1bP>\|([^\x1b]*)\x1b\\")
_APC_RE = re.compile(rb"\x1b_G([^;\x1b]*);?([^\x1b]*)\x1b\\")
_CELL_RE = re.compile(rb"\x1b\[6;(\d+);(\d+)t")
_DA1_RE = re.compile(rb"\x1b\[\?[\d;]*c")

# Minimum versions with Unicode-placeholder support.
PLACEHOLDER_SINCE = {"kitty": (0, 28, 0), "ghostty": (1, 0, 0)}

PRETTY = {
    "kitty": "kitty", "ghostty": "Ghostty", "wezterm": "WezTerm",
    "iterm2": "iTerm2", "konsole": "Konsole", "vte": "VTE-based terminal",
    "foot": "foot", "alacritty": "Alacritty", "windows-terminal": "Windows Terminal",
    "apple-terminal": "Apple Terminal", "vscode": "VS Code terminal",
    "xterm": "xterm", "tmux": "tmux", "screen": "GNU screen", "rio": "Rio",
    "contour": "Contour", "mintty": "mintty", "warp": "Warp", "tabby": "Tabby",
    "unknown": "unknown terminal",
}


@dataclass(frozen=True)
class TerminalInfo:
    """Everything netzilla knows about the terminal it is running in."""

    name: str = "unknown"            # key into PRETTY
    version: str = ""
    identified_by: str = "environment"
    multiplexer: str = ""            # tmux / screen / zellij, if inside one
    multiplexer_version: str = ""
    remote: bool = False             # over SSH
    truecolor: bool = False
    probed: bool = False             # the terminal was asked directly
    kitty_graphics: bool = False     # answered the kitty graphics query
    feature_query: bool = False      # answered the e= feature query
    placeholders: bool = False       # Unicode placeholders will work
    passthrough: bool = False        # graphics must be wrapped for tmux
    cell_px: tuple[int, int] | None = None   # (width, height) of one cell
    hyperlinks: bool = False
    clipboard: bool = False
    notify: str = ""                 # "osc99" | "osc777" | "osc9" | ""
    reasons: tuple[str, ...] = field(default_factory=tuple)

    # -------------------------------------------------------------- labels
    @property
    def label(self) -> str:
        base = PRETTY.get(self.name, self.name)
        return f"{base} {self.version}".strip()

    @property
    def where(self) -> str:
        """'kitty 0.36.4 · inside tmux 3.4 · over SSH'"""
        parts = [self.label]
        if self.multiplexer:
            parts.append(f"inside {self.multiplexer} {self.multiplexer_version}".strip())
        if self.remote:
            parts.append("over SSH")
        return " · ".join(parts)

    def pixel_capable(self) -> bool:
        return self.placeholders and self.truecolor

    def graphics_mode(self, setting: str = "auto") -> str:
        """'pixel' or 'text' for a SETTINGS choice of auto / pixel / text."""
        setting = (setting or "auto").lower()
        if setting == "text":
            return "text"
        if setting == "pixel":
            return "pixel"
        return "pixel" if self.pixel_capable() else "text"

    def graphics_reason(self) -> str:
        """One sentence: why auto chose what it chose."""
        if self.pixel_capable():
            how = " through tmux passthrough" if self.passthrough else ""
            return (f"{self.label} draws kitty-protocol images with Unicode "
                    f"placeholders{how} — graphs are drawn in pixels.")
        if self.reasons:
            return self.reasons[0]
        return f"{self.label} has no pixel-graphics support netzilla can use."


# ------------------------------------------------------------------ parsing
def version_tuple(text: str) -> tuple[int, ...]:
    """'0.36.4' -> (0, 36, 4); '1.2.0-dev+abc' -> (1, 2, 0); '' -> ()."""
    numbers = re.findall(r"\d+", (text or "").split("-")[0].split("+")[0])
    return tuple(int(n) for n in numbers[:4])


def parse_xtversion(reply: str) -> tuple[str, str]:
    """('kitty', '0.36.4') from 'kitty(0.36.4)', 'ghostty 1.1.3', 'XTerm(390)'…"""
    text = reply.strip()
    match = re.match(r"^([A-Za-z][\w .+-]*?)\s*[( ]\s*v?([\d][\w.+-]*)\)?\s*$", text)
    if match:
        raw_name, version = match.group(1), match.group(2)
    else:
        raw_name, version = text, ""
    low = raw_name.lower()
    for needle, name in (
        ("kitty", "kitty"), ("ghostty", "ghostty"), ("wezterm", "wezterm"),
        ("iterm", "iterm2"), ("konsole", "konsole"), ("foot", "foot"),
        ("alacritty", "alacritty"), ("xterm", "xterm"), ("tmux", "tmux"),
        ("vte", "vte"), ("mintty", "mintty"), ("contour", "contour"),
        ("rio", "rio"), ("windows terminal", "windows-terminal"),
        ("screen", "screen"),
    ):
        if needle in low:
            return name, version
    return (low.split()[0] if low else "unknown"), version


def parse_replies(data: bytes) -> dict:
    """Pull every reply netzilla asked for out of what the terminal sent."""
    found: dict = {"xtversion": "", "kitty_ok": False, "feature": None,
                   "cell_px": None, "da1": False, "passthrough_ok": False}
    match = _XTVERSION_RE.search(data)
    if match:
        found["xtversion"] = match.group(1).decode("utf-8", "replace")
    for keys, message in _APC_RE.findall(data):
        params = dict(
            part.split("=", 1) for part in keys.decode("ascii", "replace").split(",")
            if "=" in part
        )
        ok = message.decode("ascii", "replace").startswith("OK")
        if params.get("i") == "31" and ok:
            found["kitty_ok"] = True
        elif params.get("i") in ("32", "34"):
            found["feature"] = params
        elif params.get("i") == "33" and ok:
            found["passthrough_ok"] = True
    cell = _CELL_RE.search(data)
    if cell:
        height, width = int(cell.group(1)), int(cell.group(2))
        if width > 0 and height > 0:
            found["cell_px"] = (width, height)
    found["da1"] = bool(_DA1_RE.search(data))
    return found


# ------------------------------------------------------------------ probing
def wrap_tmux(sequence: str) -> str:
    """An escape sequence wrapped so tmux passes it to the outer terminal."""
    return "\x1bPtmux;" + sequence.replace("\x1b", "\x1b\x1b") + "\x1b\\"


def probe_query(in_tmux: bool = False, graphics: bool = True) -> str:
    """Everything the probe asks, in order — DA1 last, as the sentinel."""
    if in_tmux:
        return (XTVERSION_Q + wrap_tmux(TMUX_KITTY_Q) + wrap_tmux(TMUX_FEATURE_Q)
                + CELL_Q + DA1_Q)
    if graphics:
        return XTVERSION_Q + KITTY_Q + FEATURE_Q + CELL_Q + DA1_Q
    return XTVERSION_Q + CELL_Q + DA1_Q


def probe(timeout: float = 0.35, in_tmux: bool = False, graphics: bool = True) -> bytes:
    """Ask the terminal who it is. Returns whatever it answered (b"" if it
    could not be asked: not a terminal, not POSIX, or nothing came back).

    Inside tmux, tmux itself answers XTVERSION and DA1 at once; the graphics
    questions go *through* tmux (wrapped for passthrough) and are answered,
    a little later, by the terminal outside — or never, when tmux doesn't
    allow passthrough. They are never sent bare there: tmux would take them
    for a window title. `graphics=False` (GNU screen, Zellij) leaves them out
    entirely, as screen would show them in its status line.
    """
    if os.name != "posix":
        return b""
    try:
        import select
        import termios
    except ImportError:          # pragma: no cover - non-POSIX
        return b""
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        return b""
    data = b""
    try:
        try:
            old = termios.tcgetattr(fd)
        except termios.error:
            return b""
        new = termios.tcgetattr(fd)
        new[3] &= ~(termios.ICANON | termios.ECHO)
        new[6][termios.VMIN] = 0
        new[6][termios.VTIME] = 0
        try:
            termios.tcsetattr(fd, termios.TCSANOW, new)
            os.write(fd, probe_query(in_tmux, graphics).encode())
            deadline = time.monotonic() + timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                ready, _, _ = select.select([fd], [], [], left)
                if not ready:
                    break
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                data += chunk
                if not _DA1_RE.search(data):
                    continue
                if in_tmux and not re.search(rb"\x1b_Gi=33[;,]", data):
                    # tmux answered for itself; the outside terminal's
                    # answers (if passthrough is on) are still on their way.
                    continue
                # Everything asked for is in, DA1 last; a straggler (the
                # feature reply from outside tmux) gets one more moment.
                more, _, _ = select.select([fd], [], [], 0.05 if in_tmux else 0.02)
                if more:
                    data += os.read(fd, 4096)
                break
        finally:
            # Anything half-arrived is dropped here rather than typed into
            # the app as keystrokes.
            try:
                termios.tcflush(fd, termios.TCIFLUSH)
            except termios.error:
                pass
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    finally:
        os.close(fd)
    return data


def tmux_client_info(timeout: float = 1.0) -> dict:
    """What tmux knows about the terminal the user is attached from — more
    reliable than environment variables, which a tmux server keeps from
    whichever terminal started it: {"termtype": "kitty(0.36.4)" (tmux 3.3+,
    tmux's own XTVERSION answer), "termname": "xterm-kitty", "features":
    "256,RGB,clipboard,…"}. Empty if tmux can't be asked."""
    import subprocess

    fmt = "#{client_termtype}\t#{client_termname}\t#{client_termfeatures}"
    try:
        done = subprocess.run(["tmux", "display-message", "-p", fmt],
                              capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return {}
    if done.returncode != 0:
        return {}
    termtype, termname, features = (done.stdout.rstrip("\n").split("\t") + ["", "", ""])[:3]
    if not (termtype or termname):
        return {}
    return {"termtype": termtype, "termname": termname, "features": features}


def cell_size_from_ioctl(fd: int | None = None) -> tuple[int, int] | None:
    """(width, height) of one cell in pixels from TIOCGWINSZ, if reported."""
    try:
        import fcntl
        import struct
        import termios
    except ImportError:          # pragma: no cover - non-POSIX
        return None
    if fd is None:
        try:
            fd = sys.__stdout__.fileno()
        except (AttributeError, ValueError, OSError):
            return None
    try:
        packed = fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 8)
        rows, cols, xpix, ypix = struct.unpack("HHHH", packed)
    except OSError:
        return None
    if rows and cols and xpix and ypix:
        return max(1, xpix // cols), max(1, ypix // rows)
    return None


# ------------------------------------------------------------------ detection
def _from_env(env) -> tuple[str, str]:
    term = env.get("TERM", "")
    program = env.get("TERM_PROGRAM", "")
    program_version = env.get("TERM_PROGRAM_VERSION", "")
    low_program = program.lower()
    if env.get("KITTY_WINDOW_ID") or term == "xterm-kitty":
        return "kitty", ""
    if low_program == "ghostty" or term == "xterm-ghostty" or env.get("GHOSTTY_RESOURCES_DIR"):
        return "ghostty", program_version if low_program == "ghostty" else ""
    if low_program == "wezterm" or env.get("WEZTERM_EXECUTABLE") or term == "wezterm":
        return "wezterm", program_version
    if low_program == "iterm.app" or env.get("ITERM_SESSION_ID"):
        return "iterm2", program_version
    if low_program == "apple_terminal":
        return "apple-terminal", program_version
    if low_program == "vscode":
        return "vscode", program_version
    if low_program == "warpterminal":
        return "warp", program_version
    if low_program == "tabby":
        return "tabby", program_version
    if low_program == "rio" or term == "rio":
        return "rio", program_version
    if env.get("KONSOLE_VERSION"):
        raw = env["KONSOLE_VERSION"]        # 230804 -> 23.08.04
        pretty = f"{raw[:2]}.{raw[2:4]}.{raw[4:]}" if raw.isdigit() and len(raw) == 6 else raw
        return "konsole", pretty
    if env.get("WT_SESSION"):
        return "windows-terminal", ""
    if env.get("ALACRITTY_SOCKET") or env.get("ALACRITTY_WINDOW_ID") or term == "alacritty":
        return "alacritty", ""
    if term.startswith("foot"):
        return "foot", ""
    if env.get("VTE_VERSION"):
        raw = env["VTE_VERSION"]            # 7600 -> 0.76.0
        pretty = f"0.{int(raw) // 100}.{int(raw) % 100}" if raw.isdigit() else raw
        return "vte", pretty
    if env.get("XTERM_VERSION"):
        return "xterm", re.sub(r"\D", "", env["XTERM_VERSION"]) or ""
    if term.startswith("xterm"):
        return "xterm", ""
    return "unknown", ""


def detect(env=None, replies: bytes | None = None,
           cell_px: tuple[int, int] | None = None,
           tmux: dict | None = None) -> TerminalInfo:
    """Combine the environment, the terminal's own replies and (inside tmux)
    what tmux says about the terminal outside it."""
    env = os.environ if env is None else env
    multiplexer, mux_version = "", ""
    if env.get("TMUX"):
        multiplexer = "tmux"
        if env.get("TERM_PROGRAM", "").lower() == "tmux":
            mux_version = env.get("TERM_PROGRAM_VERSION", "")
    elif env.get("ZELLIJ"):
        multiplexer = "zellij"
    elif env.get("STY"):
        multiplexer = "screen"
    remote = bool(env.get("SSH_CONNECTION") or env.get("SSH_TTY") or env.get("SSH_CLIENT"))

    name, version = _from_env(env)
    identified_by = "environment"
    found = parse_replies(replies) if replies else {}
    probed = bool(replies)
    if found.get("xtversion"):
        xt_name, xt_version = parse_xtversion(found["xtversion"])
        if xt_name == "tmux":
            multiplexer, mux_version = "tmux", xt_version or mux_version
        elif xt_name != "unknown":
            name, version = xt_name, xt_version or version
            identified_by = "XTVERSION reply"
    # Inside tmux the environment can describe whichever terminal started
    # the tmux server, not the one attached now; tmux itself knows better.
    tmux_known = False
    tmux_rgb: bool | None = None
    if multiplexer == "tmux":
        if tmux:
            # client_termtype is the outside terminal's own XTVERSION answer
            # (tmux 3.3+); client_termname is its $TERM.
            t_name, t_version = ("unknown", "")
            if tmux.get("termtype"):
                t_name, t_version = parse_xtversion(tmux["termtype"])
            if t_name == "unknown" and tmux.get("termname"):
                t_name, t_version = _from_env({"TERM": tmux["termname"]})
            if t_name not in ("unknown", "tmux"):
                name, version = t_name, t_version
                identified_by = "tmux (the terminal it is attached to)"
                tmux_known = True
            features = [f.strip() for f in (tmux.get("features") or "").split(",")]
            if any(features):
                tmux_rgb = "RGB" in features

    colorterm = env.get("COLORTERM", "").lower()
    truecolor = colorterm in ("truecolor", "24bit") or name in (
        "kitty", "ghostty", "wezterm", "iterm2", "konsole", "foot", "alacritty",
        "windows-terminal", "vscode", "rio", "contour", "warp", "tabby", "mintty",
    ) or (name == "vte" and version_tuple(version) >= (0, 36))
    if tmux_rgb is not None:
        # tmux re-encodes colours for the outside terminal: 24-bit colour
        # survives only when tmux knows that terminal has it (RGB).
        truecolor = tmux_rgb

    kitty_ok = bool(found.get("kitty_ok"))
    passthrough_ok = bool(found.get("passthrough_ok"))
    feature = found.get("feature")
    feature_query = feature is not None and "e" in feature
    reasons: list[str] = []

    placeholders = False
    passthrough = False
    vt = version_tuple(version)
    if feature_query:
        placeholders = feature.get("U") == "1"
        if not placeholders:
            reasons.append(f"{PRETTY.get(name, name)} reports no Unicode-placeholder "
                           "support for images.")
    elif name in PLACEHOLDER_SINCE:
        minimum = PLACEHOLDER_SINCE[name]
        new_enough = not vt or vt >= minimum
        answered = kitty_ok or passthrough_ok or not probed
        placeholders = new_enough and answered
        if not new_enough:
            reasons.append(
                f"{PRETTY[name]} {version} predates Unicode-placeholder images "
                f"(added in {'.'.join(map(str, minimum))}) — update it for pixel graphs.")
        elif not answered:
            reasons.append(f"{PRETTY[name]} did not answer the graphics query.")
    else:
        if kitty_ok:
            reasons.append(f"{PRETTY.get(name, name)} speaks the kitty graphics "
                           "protocol but not the Unicode-placeholder part pixel "
                           "graphs need.")
        else:
            reasons.append(f"{PRETTY.get(name, name)} has no kitty-protocol image "
                           "support — graphs are drawn with text.")

    if multiplexer == "tmux":
        # Every graphics command has to be wrapped for tmux to forward it.
        passthrough = True
        if not passthrough_ok:
            if placeholders or name in PLACEHOLDER_SINCE or feature_query:
                reasons.insert(0, "Inside tmux, graphics need `set -g allow-passthrough "
                                  "on` in tmux.conf (tmux 3.3+) — text graphs until then.")
            placeholders = False
        elif feature_query:
            pass                  # the terminal outside tmux answered for itself
        elif tmux_known and name in PLACEHOLDER_SINCE:
            placeholders = not vt or vt >= PLACEHOLDER_SINCE[name]
        else:
            placeholders = False
            reasons.insert(0, "Inside tmux the outer terminal could not be identified "
                              "— choose Pixel on SETTINGS if it is kitty or Ghostty.")
        if placeholders and not truecolor:
            placeholders = False
            reasons.insert(0, "tmux is not passing 24-bit colour, which pixel graphs "
                              "need — add  set -as terminal-features ',*:RGB'  to "
                              "tmux.conf.")
    elif multiplexer in ("screen", "zellij"):
        if placeholders or name in PLACEHOLDER_SINCE:
            reasons.insert(0, f"{multiplexer} does not pass image commands through "
                              "— text graphs.")
        placeholders = False

    if env.get("NO_COLOR") is not None and placeholders:
        # Textual turns every colour grey under NO_COLOR, image ids included.
        placeholders = False
        reasons.insert(0, "NO_COLOR is set, and pixel graphs need colour — text graphs.")

    hyperlinks = name in ("kitty", "ghostty", "wezterm", "iterm2", "foot", "konsole",
                          "windows-terminal", "alacritty", "vscode", "contour", "rio") \
        or (name == "vte" and vt >= (0, 50))
    clipboard = name in ("kitty", "ghostty", "wezterm", "iterm2", "foot", "alacritty",
                         "windows-terminal", "contour", "rio", "mintty") \
        or multiplexer == "tmux"
    notify = {"kitty": "osc99", "ghostty": "osc777", "foot": "osc777",
              "wezterm": "osc777", "iterm2": "osc9", "konsole": "",
              "rio": "osc9"}.get(name, "")

    return TerminalInfo(
        name=name, version=version, identified_by=identified_by,
        multiplexer=multiplexer, multiplexer_version=mux_version, remote=remote,
        truecolor=truecolor, probed=probed, kitty_graphics=kitty_ok or passthrough_ok,
        feature_query=feature_query, placeholders=placeholders,
        passthrough=passthrough, cell_px=found.get("cell_px") or cell_px,
        hyperlinks=hyperlinks, clipboard=clipboard, notify=notify,
        reasons=tuple(reasons),
    )


# ------------------------------------------------------------------ the one instance
_CURRENT = TerminalInfo()


def current() -> TerminalInfo:
    return _CURRENT


def set_current(info: TerminalInfo) -> None:
    global _CURRENT
    _CURRENT = info


def startup(allow_probe: bool = True) -> TerminalInfo:
    """Detect once, before the interface takes the screen; cached for the run."""
    env = os.environ
    replies = b""
    in_tmux = bool(env.get("TMUX"))
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if allow_probe and interactive and env.get("NETZILLA_NO_PROBE", "") in ("", "0"):
        remote = bool(env.get("SSH_CONNECTION") or env.get("SSH_TTY"))
        replies = probe(timeout=1.2 if remote else 0.35, in_tmux=in_tmux,
                        graphics=not (env.get("STY") or env.get("ZELLIJ")))
    tmux = tmux_client_info() if in_tmux else None
    info = detect(env, replies, cell_size_from_ioctl(), tmux=tmux)
    use_truecolour(info, env)
    set_current(info)
    return info


def use_truecolour(info: TerminalInfo, env=None) -> None:
    """Tell Textual about 24-bit colour when the terminal has it but
    $COLORTERM doesn't say so — usual over SSH, which doesn't pass
    COLORTERM on. Without it Textual draws in 256 (or 16) colours: duller
    themes, and pixel graphs whose image ids no longer match."""
    env = os.environ if env is None else env
    if (info.truecolor and env.get("NO_COLOR") is None
            and env.get("COLORTERM", "").lower() not in ("truecolor", "24bit")):
        env["COLORTERM"] = "truecolor"


def with_cell_px(info: TerminalInfo, cell_px: tuple[int, int] | None) -> TerminalInfo:
    return replace(info, cell_px=cell_px) if cell_px else info


__all__ = ["TerminalInfo", "detect", "probe", "startup", "current", "set_current",
           "parse_xtversion", "parse_replies", "version_tuple", "wrap_tmux",
           "cell_size_from_ioctl", "with_cell_px", "tmux_client_info", "probe_query",
           "use_truecolour", "PRETTY"]
