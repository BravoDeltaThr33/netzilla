"""The operating system netzilla runs on, and everything that differs by it.

netzilla started on Linux and runs on Windows and macOS too. Which commands
exist, which flags they take, where settings live, how a missing tool is
installed and what "run it as root" means all depend on the system — and
every one of those questions is answered here, so the rest of netzilla asks
in one place. A test can be any of the three by setting `hostos.NAME`.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

LINUX = "linux"
MACOS = "macos"
WINDOWS = "windows"
SYSTEMS = (LINUX, MACOS, WINDOWS)


def detect(platform_name: str | None = None) -> str:
    """'linux', 'macos' or 'windows' for a sys.platform value.

    The other Unixes (FreeBSD, Cygwin, MSYS…) are POSIX systems with the same
    kind of command line, so they are treated like Linux.
    """
    name = (sys.platform if platform_name is None else platform_name).lower()
    if name == "win32":
        return WINDOWS
    if name == "darwin":
        return MACOS
    return LINUX


NAME = detect()


def is_linux() -> bool:
    return NAME == LINUX


def is_macos() -> bool:
    return NAME == MACOS


def is_windows() -> bool:
    return NAME == WINDOWS


def label() -> str:
    return {LINUX: "Linux", MACOS: "macOS", WINDOWS: "Windows"}.get(NAME, "Linux")


# ---------------------------------------------------------------- settings
def config_dir(env=None) -> Path:
    """Where config.toml, the cache and the downloaded tables live.

    $XDG_CONFIG_HOME/netzilla when that is set, otherwise ~/.config/netzilla
    on Linux and macOS (where kitty and Ghostty keep theirs too) and
    %APPDATA%\\netzilla on Windows.
    """
    env = os.environ if env is None else env
    xdg = (env.get("XDG_CONFIG_HOME") or "").strip()
    if xdg:
        return Path(xdg) / "netzilla"
    if NAME == WINDOWS:
        appdata = (env.get("APPDATA") or "").strip()
        if appdata:
            return Path(appdata) / "netzilla"
    return Path.home() / ".config" / "netzilla"


# ------------------------------------------------------------------- tools
# Where a tool can be when it is installed but not on PATH. Wireshark's
# Windows installer never adds itself to PATH, Homebrew's folders are only on
# PATH when the shell profile says so, and Git for Windows carries an openssl.
def _program_dirs(env) -> list[str]:
    seen: list[str] = []
    for var in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
        base = (env.get(var) or "").strip()
        if base and base not in seen:
            seen.append(base)
    return seen or [r"C:\Program Files"]


# macOS's Wi-Fi tool, inside a private framework rather than on PATH.
AIRPORT_DIR = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
               "Versions/Current/Resources")


def extra_tool_dirs(tool: str, env=None) -> list[str]:
    """Folders to look in for `tool` after PATH has been searched."""
    env = os.environ if env is None else env
    if NAME == MACOS:
        dirs = ["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin",
                "/usr/local/sbin", "/usr/sbin", "/sbin"]
        if tool in ("tshark", "dumpcap", "capinfos", "editcap"):
            dirs.append("/Applications/Wireshark.app/Contents/MacOS")
        if tool == "airport":
            dirs.append(AIRPORT_DIR)
        return dirs
    if NAME == WINDOWS:
        bases = _program_dirs(env)
        if tool in ("tshark", "dumpcap", "capinfos", "editcap"):
            return [os.path.join(base, "Wireshark") for base in bases]
        if tool == "openssl":
            dirs = []
            for base in bases:
                dirs += [os.path.join(base, "OpenSSL-Win64", "bin"),
                         os.path.join(base, "OpenSSL", "bin"),
                         os.path.join(base, "Git", "usr", "bin"),
                         os.path.join(base, "Git", "mingw64", "bin")]
            return dirs
        if tool in ("snmpget", "snmpbulkwalk", "snmpwalk"):
            return [r"C:\usr\bin"] + [os.path.join(base, "Net-SNMP", "bin") for base in bases]
        return []
    return []


def locate(tool: str, env=None) -> str | None:
    """The full path of an installed tool, or None."""
    found = shutil.which(tool)
    if found:
        return found
    dirs = [d for d in extra_tool_dirs(tool, env) if os.path.isdir(d)]
    if not dirs:
        return None
    return shutil.which(tool, path=os.pathsep.join(dirs))


# ------------------------------------------------------------ installing
BUILT_IN = ""        # ships with the system: nothing to install

# How to get each tool: the package (Linux, apt), the formula or cask (macOS,
# Homebrew) and the winget id (Windows). BUILT_IN means it comes with the
# system; None means the tool does not exist there, and the note in UNAVAILABLE
# says what netzilla does instead.
PACKAGES: dict[str, tuple[str | None, str | None, str | None]] = {
    "ping":         ("iputils-ping", BUILT_IN, BUILT_IN),
    "traceroute":   ("traceroute", BUILT_IN, None),
    "tracert":      (None, None, BUILT_IN),
    "pathping":     (None, None, BUILT_IN),
    "tracepath":    ("iputils-tracepath", None, None),
    "mtr":          ("mtr-tiny", "mtr", None),
    "dig":          ("dnsutils", BUILT_IN, None),
    "whois":        ("whois", BUILT_IN, None),
    "openssl":      ("openssl", BUILT_IN, "ShiningLight.OpenSSL.Light"),
    "tshark":       ("tshark", "--cask wireshark-app", "WiresharkFoundation.Wireshark"),
    "dumpcap":      ("tshark", "--cask wireshark-app", "WiresharkFoundation.Wireshark"),
    "tcpdump":      ("tcpdump", BUILT_IN, None),
    "arp":          ("net-tools", BUILT_IN, BUILT_IN),
    "arping":       ("arping", "arping", None),
    "nmcli":        ("network-manager", None, None),
    "iw":           ("iw", None, None),
    "netsh":        (None, None, BUILT_IN),
    "system_profiler": (None, BUILT_IN, None),
    "networksetup": (None, BUILT_IN, None),
    "airport":      (None, BUILT_IN, None),
    "ip":           ("iproute2", None, None),
    "ss":           ("iproute2", None, None),
    "netstat":      ("net-tools", BUILT_IN, BUILT_IN),
    "lsof":         ("lsof", BUILT_IN, None),
    "ifconfig":     ("net-tools", BUILT_IN, None),
    "snmpget":      ("snmp", BUILT_IN, None),
    "snmpbulkwalk": ("snmp", BUILT_IN, None),
    "iftop":        ("iftop", "iftop", None),
    "vnstat":       ("vnstat", "vnstat", None),
    "bmon":         ("bmon", "bmon", None),
    "nload":        ("nload", "nload", None),
    "getcap":       ("libcap2-bin", None, None),
    "bluetoothctl": ("bluez", None, None),
    "rfkill":       ("rfkill", None, None),
    "sudo":         ("sudo", BUILT_IN, None),
}

# What happens instead where a tool does not exist.
UNAVAILABLE: dict[str, str] = {
    "traceroute": "Windows has tracert instead, and netzilla uses it",
    "tracepath": "traceroute does the same job",
    "mtr": "netzilla runs Windows' own pathping instead",
    "dig": "ALL RECORDS and REVERSE ask Cloudflare over DNS-over-HTTPS instead",
    "whois": "netzilla's own WHOIS client is used instead",
    "tcpdump": "tshark (with Wireshark) does the same job",
    "arping": "the LAN tab falls back to ping and the ARP table",
    "nmcli": "NetworkManager is Linux-only",
    "iw": "iw is Linux-only",
    "ip": "iproute2 is Linux-only",
    "ss": "netzilla reads the connection table another way",
    "lsof": "netzilla reads the connection table another way",
    "snmpget": "Net-SNMP has no current Windows release",
    "snmpbulkwalk": "Net-SNMP has no current Windows release",
    "iftop": "LIVE RATES covers the same ground",
    "vnstat": "LIVE RATES covers the same ground",
    "bmon": "LIVE RATES covers the same ground",
    "nload": "LIVE RATES covers the same ground",
    "getcap": "file capabilities are a Linux feature",
    "bluetoothctl": "BLUETOOTH scans through the system's own Bluetooth stack",
    "rfkill": "turn the radio on in the system settings instead",
    "sudo": "run netzilla from a terminal opened as Administrator instead",
}


def _package(tool: str) -> str | None:
    entry = PACKAGES.get(tool)
    if entry is None:
        return tool if NAME != WINDOWS else None
    return entry[SYSTEMS.index(NAME)]


def available_here(tool: str) -> bool:
    """False when the tool simply does not exist on this system."""
    return _package(tool) is not None


def install_hint(tool: str) -> str:
    """One line: how to get `tool` on this system, or why there is no need."""
    package = _package(tool)
    if package is None:
        instead = UNAVAILABLE.get(tool, "")
        return f"{tool} is not available on {label()}" + (f" — {instead}." if instead else ".")
    if package == BUILT_IN:
        return f"{tool} is built into {label()}."
    if NAME == MACOS:
        return f"brew install {package}"
    if NAME == WINDOWS:
        return f"winget install {package}"
    return f"sudo apt install {package}"


def install_commands(tools) -> list[str]:
    """The commands that install every tool in `tools` that can be installed
    here, one line each (apt and brew take them all in one line)."""
    packages: list[str] = []
    for tool in tools:
        package = _package(tool)
        if package and package not in packages:
            packages.append(package)
    if not packages:
        return []
    if NAME == WINDOWS:
        return [f"winget install {package}" for package in packages]
    if NAME == MACOS:
        casks = [p for p in packages if p.startswith("--cask")]
        formulas = [p for p in packages if not p.startswith("--cask")]
        lines = [f"brew install {' '.join(formulas)}"] if formulas else []
        return lines + [f"brew install {cask}" for cask in casks]
    return [f"sudo apt install {' '.join(packages)}"]


def missing_tool_text(tool: str) -> str:
    """The body of a 'tool not installed' message."""
    package = _package(tool)
    if package is None:
        return install_hint(tool)
    if package == BUILT_IN:
        return (f"{tool} normally comes with {label()}, but netzilla could not "
                "find it on this PATH.")
    return f"Install it with:\n    {install_hint(tool)}"


# ------------------------------------------------------------- privilege
def is_admin() -> bool:
    """Running as root (Linux, macOS) or elevated as Administrator (Windows)."""
    if NAME == WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def admin_hint() -> str:
    """How to run netzilla with full privilege here."""
    if NAME == WINDOWS:
        return ("start netzilla from a terminal opened with "
                "'Run as administrator'")
    return "run it as root:  sudo netzilla"


def has_sudo() -> bool:
    """sudo as Linux and macOS have it. Windows 11 can have a 'sudo' too, but
    it takes none of the options netzilla's unlock relies on."""
    return NAME != WINDOWS and shutil.which("sudo") is not None


# ------------------------------------------------------------ tool output
_OEM: str | None = None


def _oem_encoding() -> str:
    """The console code page Windows tools write in (cp437, cp850, cp1252…)."""
    global _OEM
    if _OEM is None:
        name = ""
        try:
            import codecs
            import ctypes

            name = f"cp{int(ctypes.windll.kernel32.GetOEMCP())}"
            codecs.lookup(name)
        except Exception:
            name = "cp437"
        _OEM = name
    return _OEM


def decode(data: bytes | None) -> str:
    """A tool's output as text. UTF-8 when it is; on Windows, where tools
    write in the console's code page, that code page otherwise."""
    if not data:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if NAME == WINDOWS:
        return data.decode(_oem_encoding(), "replace")
    return data.decode("utf-8", "replace")


def safe_filename(text: str, fallback: str = "capture") -> str:
    """A piece of a file name that every system accepts (Windows refuses
    \\ / : * ? " < > | and names ending in a dot or a space)."""
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (text or ""))
    cleaned = cleaned.strip("._ ")
    return cleaned[:60] or fallback


__all__ = [
    "LINUX", "MACOS", "WINDOWS", "NAME", "detect", "is_linux", "is_macos",
    "is_windows", "label", "config_dir", "extra_tool_dirs", "locate",
    "install_hint", "install_commands", "missing_tool_text", "available_here",
    "is_admin", "admin_hint", "has_sudo", "decode", "safe_filename",
]
