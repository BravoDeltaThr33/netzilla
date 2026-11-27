"""Packet capture: tshark and tcpdump, driven from inside netzilla.

Both tools are used in the modes that print and stop, so their output lands in
a netzilla panel instead of taking over the terminal:

  tshark   -c N -a duration:S      capture N packets or S seconds, whichever
                                   comes first, then exit
  tshark   -q -z io,phs            protocol hierarchy for that capture
  tshark   -q -z conv,ip           who talked to whom, by bytes
  tshark   -r file.pcap            read a capture back
  tcpdump  -c N -nn                the same idea, raw and lightweight

tshark's default output is parsed positionally rather than through `-T fields`
on purpose: the column field names (_ws.col.Info and friends) were renamed
between Wireshark releases, while the printed layout — number, time, source,
arrow, destination, protocol, length, info — has been stable for years.

Capturing needs privilege. On Debian/Ubuntu/Mint the usual arrangement is the
`wireshark` group plus capabilities on dumpcap rather than running as root,
and permission_report() explains which of those are in place. On macOS it is
read access to /dev/bpf*, which Wireshark's ChmodBPF gives the access_bpf
group (or root, through a sudo session); on Windows it is Npcap, which
Wireshark installs and which lets every account capture unless it was
installed for Administrators only. tcpdump is not available on Windows.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from .. import hostos
from .elevation import SESSION
from .runner import CommandResult, LiveProcess, have, run, run_for

# "    1 0.000000000 192.168.1.5 → 142.250.191.78 TCP 74 51234 → 443 [SYN] ..."
# With -t a the time column is the wall clock instead: "14:03:22.918472".
# Older tshark prints "->" instead of "→"; both forms are accepted.
_PACKET_RE = re.compile(
    r"^\s*(?P<no>\d+)\s+(?P<time>[\d.:]+)\s+(?P<src>\S+)\s+(?:→|->)\s+"
    r"(?P<dst>\S+)\s+(?P<proto>\S+)\s+(?P<len>\d+)\s+(?P<info>.*)$"
)

# tshark prints TCP/UDP ports at the front of the info column:
#   "51234 → 443 [SYN] Seq=0 Win=64240 ..."
_PORT_RE = re.compile(r"^(?P<sport>\d{1,5})\s*(?:→|->)\s*(?P<dport>\d{1,5})\b")

# "14:03:22.918472" — tshark's -t a (absolute time of day) column.
_CLOCK_RE = re.compile(
    r"^(?P<h>\d{1,2}):(?P<m>\d{2}):(?P<s>\d{2})(?:\.(?P<frac>\d+))?$"
)

# Ask tshark for wall-clock timestamps rather than seconds since the first
# packet, so every packet can be lined up against a log entry.
ABSOLUTE_TIME = ["-t", "a"]

# One list of columns, used by every packet table, so the headings and the
# rows underneath them cannot drift apart.
PACKET_COLUMNS = [
    "#", "Systime", "Δt", "Source", "Destination", "Protocol", "Bytes", "Info",
]


def _parse_time(raw: str) -> tuple[float, str]:
    """A tshark time column -> (seconds, "HH:MM:SS.mmm" or "").

    Accepts both forms tshark can print: the wall clock it gives with -t a,
    and the seconds-since-the-first-packet it gives by default. Seconds are
    returned in both cases so elapsed time still works either way; the clock
    string is empty when the output carried no wall clock to show.
    """
    raw = (raw or "").strip()
    match = _CLOCK_RE.match(raw)
    if match:
        hours = int(match.group("h"))
        minutes = int(match.group("m"))
        whole = int(match.group("s"))
        frac = float(f"0.{match.group('frac')}") if match.group("frac") else 0.0
        seconds = hours * 3600 + minutes * 60 + whole + frac
        return seconds, f"{hours:02d}:{minutes:02d}:{whole:02d}.{int(frac * 1000):03d}"
    try:
        return float(raw), ""
    except ValueError:
        return 0.0, ""


# ------------------------------------------------------------- permissions
def have_both() -> bool:
    """Both capture tools present? Used to decide whether to show setup help."""
    return have("tshark") and have("tcpdump")


def is_root() -> bool:
    """Root — or, on Windows, an elevated Administrator."""
    if hostos.is_windows():
        return hostos.is_admin()
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def groups() -> list[str]:
    """The current user's group names, without shelling out."""
    try:
        import grp

        gids = os.getgroups()
        names = []
        for gid in gids:
            try:
                names.append(grp.getgrgid(gid).gr_name)
            except KeyError:
                continue
        return names
    except Exception:
        return []


# Where a tool can be when `which` will not find it: either it lives in an
# sbin directory that is not on this user's PATH, or — the usual case for
# dumpcap — it is root:wireshark 0750 and this user is not in that group, so
# it has no execute bit for them and PATH lookup skips it entirely.
_ALSO_LOOK_IN = (
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/usr/local/bin", "/usr/local/sbin",
    "/usr/lib/wireshark",                      # some distributions hide it here
    "/opt/homebrew/bin", "/usr/local/opt/wireshark/bin",          # macOS
    "/Applications/Wireshark.app/Contents/MacOS",
)


def find_tool(name: str) -> str:
    """The path to a tool, whether or not this user may run it.

    shutil.which() answers "can I execute this", not "is this installed", and
    the difference is the whole of the dumpcap story: a dumpcap you are not
    allowed to run is not a dumpcap that is missing, and saying so sends
    people off installing something they already have.
    """
    found = shutil.which(name) or hostos.locate(name)
    if found:
        return found
    if hostos.is_windows():
        return ""
    for directory in _ALSO_LOOK_IN:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
    return ""


def dumpcap_path() -> str:
    return find_tool("dumpcap")


def dumpcap_executable() -> bool:
    """False is the classic 'answered No during the tshark install' state:
    dumpcap exists but is root:wireshark 0750, so a non-member cannot run it."""
    path = dumpcap_path()
    return bool(path) and os.access(path, os.X_OK)


def dumpcap_details() -> str:
    """How dumpcap is installed, in the terms that explain a refusal."""
    path = dumpcap_path()
    if not path:
        return "not installed"
    try:
        import grp
        import pwd
        import stat as stat_module

        info = os.stat(path)
        mode = stat_module.filemode(info.st_mode)
        try:
            owner = pwd.getpwuid(info.st_uid).pw_name
        except KeyError:
            owner = str(info.st_uid)
        try:
            group = grp.getgrgid(info.st_gid).gr_name
        except KeyError:
            group = str(info.st_gid)
    except Exception:
        return path
    runnable = "you may run it" if os.access(path, os.X_OK) else "you may NOT run it"
    return f"{path}  ({mode} {owner}:{group}) — {runnable}"


def graphical_session() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def pkexec_available() -> bool:
    """pkexec asks for the password in a desktop dialog rather than on the
    terminal netzilla is drawing on, so it is the one interactive elevation
    that can work from inside a TUI."""
    return have("pkexec") and graphical_session()


async def dumpcap_caps() -> tuple[str, str]:
    """(capabilities, why-not). Missing getcap is reported as unknown rather
    than as 'none', which would read as a definite answer it is not."""
    path = dumpcap_path()
    if not path:
        return "", "dumpcap is not installed"
    if not hostos.is_linux():
        return "", "file capabilities are a Linux feature"
    # getcap lives in /usr/sbin, which is not on every user's PATH, so it is
    # looked up the same way dumpcap is and then run by its full path.
    getcap = find_tool("getcap")
    if not getcap:
        return "", "getcap is not installed (sudo apt install libcap2-bin)"
    result = await run([getcap, path], timeout=5)
    if not result.ok:
        return "", result.error or "getcap could not read it"
    # getcap prints nothing at all for a file with no capabilities.
    return result.output or "none", ""


def can_unlock() -> bool:
    """Is a one-time in-netzilla sudo unlock worth offering?

    Only when there is a sudo to unlock, this is not already root, and the
    session has not been unlocked already — otherwise the offer is noise.
    """
    return hostos.has_sudo() and not is_root() and not SESSION.active


def unlock_instead() -> bool:
    """When capturing is blocked, should netzilla offer its one-password sudo
    session straight away? On macOS, yes: there is no pkexec to fall back
    on, and a session is the usual way to capture without ChmodBPF."""
    return hostos.is_macos()


def password_hint() -> str:
    """Which password `sudo` wants, in the words of this system."""
    return "your Mac login password" if hostos.is_macos() else (
        "your login password on Mint and Ubuntu")


async def sudo_without_password() -> bool:
    if not hostos.has_sudo():
        return False
    return (await run(["sudo", "-n", "true"], timeout=5)).ok


# Checking permission runs getcap and `sudo -n true` — two subprocesses, and
# sudo is not a fast program. Every capture button asks first, so pressing two
# in a row paid for it twice. The answer cannot meaningfully change in a few
# seconds, so it is remembered for a moment; the key carries the session and
# root state, which means unlocking or locking can never be served a stale
# answer even if someone forgets to invalidate it.
_REPORT_TTL = 4.0
_report_cache: tuple[object, float, tuple] | None = None


def invalidate_permissions() -> None:
    """Forget the cached permission check — after changing anything it saw."""
    global _report_cache
    _report_cache = None


async def permission_report(
    fresh: bool = False,
) -> tuple[list[str] | None, list[tuple[str, object]]]:
    """(prefix, rows). prefix is [] to run directly, ["sudo","-n"] to elevate,
    or None when capturing is not possible without a password prompt.

    `fresh=True` skips the cache, for TOOL CHECK, whose entire job is to say
    what is true right now.
    """
    global _report_cache
    import time as _time

    key = (SESSION.active, is_root())
    if not fresh and _report_cache is not None:
        cached_key, when, answer = _report_cache
        if cached_key == key and _time.monotonic() - when < _REPORT_TTL:
            prefix, rows = answer
            return (list(prefix) if prefix is not None else None), list(rows)

    result = await _permission_report()
    _report_cache = (key, _time.monotonic(), result)
    prefix, rows = result
    return (list(prefix) if prefix is not None else None), list(rows)


# ------------------------------------------------------- Windows, macOS
def npcap_installed(env=None) -> bool:
    """Npcap (or the old WinPcap) — the capture driver tshark needs on
    Windows. Wireshark's installer offers it."""
    env = os.environ if env is None else env
    system = os.path.join(env.get("SystemRoot") or env.get("windir") or r"C:\Windows",
                          "System32")
    return any(os.path.isfile(os.path.join(system, *parts))
               for parts in (("Npcap", "wpcap.dll"), ("wpcap.dll",)))


def npcap_admin_only() -> bool:
    """Was Npcap installed with "restrict to Administrators only"?"""
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\npcap\Parameters") as key:
            value, _kind = winreg.QueryValueEx(key, "AdminOnly")
        return bool(value)
    except Exception:
        return False


def bpf_readable(dev: str = "/dev") -> bool:
    """Can this account open the packet filter devices (macOS)? Wireshark's
    ChmodBPF makes /dev/bpf* readable by the access_bpf group."""
    try:
        candidates = sorted(Path(dev).glob("bpf*"))
    except OSError:
        return False
    return any(os.access(path, os.R_OK) for path in candidates)


def _windows_permission() -> tuple[list[str] | None, list[tuple[str, object]]]:
    admin = hostos.is_admin()
    npcap = npcap_installed()
    admin_only = npcap and npcap_admin_only()
    if not npcap:
        prefix: list[str] | None = None
        verdict = "blocked — Npcap is not installed (npcap.com, or tick it in Wireshark's installer)"
    elif admin_only and not admin:
        prefix = None
        verdict = ("blocked — Npcap was installed for Administrators only; run netzilla "
                   "from a terminal opened as Administrator")
    else:
        prefix = []
        verdict = "ready — Npcap lets this account capture" + (
            " (running as Administrator)" if admin else "")
    return prefix, [
        ("Capture permission", verdict),
        ("Npcap installed", npcap),
        ("Npcap limited to Administrators", admin_only),
        ("Running as Administrator", admin),
        ("tshark installed", bool(find_tool("tshark"))),
        ("tcpdump", "not available on Windows — tshark does the same job"),
        ("dumpcap", dumpcap_path() or "not installed"),
    ]


async def _macos_permission() -> tuple[list[str] | None, list[tuple[str, object]]]:
    root = is_root()
    bpf = bpf_readable()
    sudo_ok = False if root or bpf or SESSION.active else await sudo_without_password()
    if root:
        prefix: list[str] | None = []
        verdict = "ready — netzilla is running as root"
    elif SESSION.active:
        prefix = SESSION.prefix()
        verdict = "ready — unlocked for this session, no more prompts"
    elif bpf:
        prefix = []
        verdict = "ready — /dev/bpf is readable (Wireshark's ChmodBPF)"
    elif sudo_ok:
        prefix = ["sudo", "-n"]
        verdict = "ready — using passwordless sudo"
    else:
        prefix = None
        verdict = "blocked — no root, no ChmodBPF access, no sudo session yet"
    return prefix, [
        ("Capture permission", verdict),
        ("Session unlocked", SESSION.active or SESSION.status()),
        ("Running as root", root),
        ("/dev/bpf readable (ChmodBPF)", bpf),
        ("In 'access_bpf' group", "access_bpf" in groups()),
        ("tshark installed", bool(find_tool("tshark"))),
        ("tcpdump installed", have("tcpdump")),
        ("dumpcap", dumpcap_path() or "not installed"),
    ]


async def _permission_report() -> tuple[list[str] | None, list[tuple[str, object]]]:
    if hostos.is_windows():
        return _windows_permission()
    if hostos.is_macos():
        return await _macos_permission()
    in_group = "wireshark" in groups()
    caps, caps_why = await dumpcap_caps()
    has_caps = "cap_net_raw" in caps.lower()
    root = is_root()
    runnable = dumpcap_executable()
    sudo_ok = False if root else await sudo_without_password()
    pkexec_ok = False if root else pkexec_available()

    if root:
        prefix: list[str] | None = []
        verdict = "ready — netzilla is running as root"
    elif SESSION.active:
        prefix = SESSION.prefix()
        verdict = "ready — unlocked for this session, no more prompts"
    elif has_caps and runnable:
        prefix = []
        verdict = "ready — dumpcap has cap_net_raw and you may run it"
    elif sudo_ok:
        prefix = ["sudo", "-n"]
        verdict = "ready — using passwordless sudo"
    elif pkexec_ok:
        prefix = ["pkexec"]
        verdict = "ready — pkexec asks for your password each time (AUTHENTICATE once instead)"
    else:
        prefix = None
        verdict = "blocked — no root, no capture capability, no sudo, no pkexec"

    rows: list[tuple[str, object]] = [
        ("Capture permission", verdict),
        ("Session unlocked", SESSION.active or SESSION.status()),
        ("Running as root", root),
        ("In 'wireshark' group", in_group),
        (
            "dumpcap capabilities",
            caps.strip() or (f"unknown — {caps_why}" if caps_why else "none"),
        ),
        (
            "Can you run dumpcap",
            runnable if dumpcap_path() else "dumpcap not installed",
        ),
        ("pkexec available", pkexec_ok or ("no" if have("pkexec") else "not installed")),
        ("tshark installed", have("tshark")),
        ("tcpdump installed", have("tcpdump")),
        ("dumpcap", dumpcap_details()),
    ]
    if dumpcap_path() and not runnable:
        rows.append((
            "Why dumpcap is refused",
            "it is installed but has no execute permission for you — that is "
            "the wireshark-group arrangement. FIX PERMISSIONS sorts it out.",
        ))
    return prefix, rows


# ------------------------------------------------------------- fixing it up
USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]*\$?$")


def current_user() -> str:
    import getpass

    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", "")


def fix_command() -> tuple[list[str] | None, str, str]:
    """(argv, shown, why-not) for the one-time capture-permission setup.

    Runs through pkexec so the password prompt is a desktop dialog rather
    than something typed into the terminal netzilla is drawing on.
    """
    if hostos.is_windows():
        return None, "", ("Windows needs no permission fix — Npcap, installed "
                          "with Wireshark, lets every account capture")
    if hostos.is_macos():
        return None, "", ("macOS has no pkexec; Wireshark's ChmodBPF does this "
                          "job, or AUTHENTICATE for a sudo session")
    user = current_user()
    if not USERNAME_RE.match(user or ""):
        return None, "", f"could not work out a safe username (got {user!r})"
    path = dumpcap_path()
    if not path:
        return None, "", "dumpcap is not installed (sudo apt install tshark)"
    if not pkexec_available():
        missing = "pkexec is not installed" if not have("pkexec") else (
            "there is no desktop session for pkexec to prompt in"
        )
        return None, "", missing
    import shlex

    script = (
        f"groupadd -f wireshark && "
        f"usermod -aG wireshark {shlex.quote(user)} && "
        f"chgrp wireshark {shlex.quote(path)} && "
        f"chmod 750 {shlex.quote(path)} && "
        f"setcap cap_net_raw,cap_net_admin+eip {shlex.quote(path)}"
    )
    shown = (
        f"sudo groupadd -f wireshark\n"
        f"sudo usermod -aG wireshark {user}\n"
        f"sudo chgrp wireshark {path}\n"
        f"sudo chmod 750 {path}\n"
        f"sudo setcap cap_net_raw,cap_net_admin+eip {path}"
    )
    return ["pkexec", "/bin/sh", "-c", script], shown, ""


async def apply_fix() -> CommandResult:
    argv, _shown, why = fix_command()
    if argv is None:
        return CommandResult(False, "", why, "")
    result = await run(argv, timeout=120)
    invalidate_permissions()      # it just changed what the report reads
    return result


async def take_ownership(path: str, prefix: list[str] | None) -> None:
    """A file written by an elevated tshark belongs to root; hand it back."""
    if not prefix or not path:
        return
    try:
        owner = f"{os.getuid()}:{os.getgid()}"
    except AttributeError:
        return
    await run(list(prefix) + ["chown", owner, path], timeout=20)


SETUP_STEPS = (
    "sudo apt install -y tshark tcpdump\n"
    "    During the tshark install, answer YES to\n"
    "    'Should non-superusers be able to capture packets?'\n\n"
    "If you already installed it and said no, or want to set it up by hand:\n"
    "    sudo dpkg-reconfigure wireshark-common\n"
    "    sudo usermod -aG wireshark $USER\n"
    "    sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)\n\n"
    "Then log out and back in — group membership only applies to new sessions.\n"
    "Check it worked with:  id -nG | grep wireshark"
)

MACOS_SETUP_STEPS = (
    "Install Wireshark, which brings tshark and ChmodBPF:\n"
    "    brew install --cask wireshark-app\n"
    "    (or the installer from wireshark.org — run its 'Install ChmodBPF'\n"
    "    package too)\n\n"
    "ChmodBPF lets the access_bpf group capture without sudo. Log out and\n"
    "back in afterwards so the group applies. Until then, AUTHENTICATE opens\n"
    "a sudo session that captures for the rest of this netzilla run.\n\n"
    "tcpdump is built into macOS and needs the same access."
)

WINDOWS_SETUP_STEPS = (
    "Install Wireshark, which brings tshark, and Npcap, the capture driver:\n"
    "    winget install WiresharkFoundation.Wireshark\n"
    "    then Npcap from https://npcap.com — a winget install leaves it out\n"
    "    (the installer from wireshark.org offers it: keep it ticked)\n\n"
    "Leave Npcap's 'Restrict driver access to Administrators only' unticked\n"
    "and any account can capture. If it was ticked, start netzilla from a\n"
    "terminal opened with 'Run as administrator'.\n\n"
    "tcpdump is not available on Windows; tshark does the same job."
)


def setup_steps() -> str:
    """How to set capturing up on this system."""
    if hostos.is_windows():
        return WINDOWS_SETUP_STEPS
    if hostos.is_macos():
        return MACOS_SETUP_STEPS
    return SETUP_STEPS


# ------------------------------------------------------------------ tshark
def _source_args(iface: str, pcap: str) -> list[str]:
    return ["-r", pcap] if pcap else ["-i", iface]


async def tshark_capture(
    iface: str = "", count: int = 50, display_filter: str = "",
    seconds: int = 30, pcap: str = "", prefix: list[str] | None = None,
) -> CommandResult:
    """Live capture (or a read of `pcap`), bounded by count and duration."""
    argv = list(prefix or []) + ["tshark"] + ABSOLUTE_TIME + _source_args(iface, pcap)
    argv += ["-c", str(int(count))]
    if not pcap:
        argv += ["-a", f"duration:{int(seconds)}"]
    if display_filter:
        argv += ["-Y", display_filter]
    return await run(argv, timeout=seconds + 30, ok_returncodes=(0, 1, 2))


async def tshark_write(
    iface: str, count: int, path: str, seconds: int = 30,
    capture_filter: str = "", prefix: list[str] | None = None,
) -> CommandResult:
    """Capture straight to a .pcapng the full Wireshark can open later."""
    argv = list(prefix or []) + [
        "tshark", "-i", iface, "-c", str(int(count)),
        "-a", f"duration:{int(seconds)}", "-w", path,
    ]
    if capture_filter:
        argv += ["-f", capture_filter]
    return await run(argv, timeout=seconds + 30, ok_returncodes=(0, 1, 2))


async def tshark_stats(
    what: str, iface: str = "", count: int = 200, seconds: int = 20,
    pcap: str = "", display_filter: str = "", prefix: list[str] | None = None,
) -> CommandResult:
    """`-z io,phs` (protocol hierarchy) or `-z conv,ip` (top talkers)."""
    argv = list(prefix or []) + ["tshark"] + _source_args(iface, pcap)
    if not pcap:
        argv += ["-c", str(int(count)), "-a", f"duration:{int(seconds)}"]
    if display_filter:
        argv += ["-Y", display_filter]
    argv += ["-q", "-z", what]
    return await run(argv, timeout=seconds + 40, ok_returncodes=(0, 1, 2))


def parse_packets(text: str) -> list[dict]:
    """tshark's printed lines -> structured packets. Unmatched lines are lost
    on purpose; the caller keeps the raw text for anything unparsed."""
    packets = []
    for line in (text or "").splitlines():
        match = _PACKET_RE.match(line)
        if not match:
            continue
        data = match.groupdict()
        seconds, clock = _parse_time(data["time"])
        info = data["info"].strip()
        ports = _PORT_RE.match(info)
        packets.append({
            "no": int(data["no"]),
            "time": seconds,
            "clock": clock,
            "src": data["src"],
            "dst": data["dst"],
            "protocol": data["proto"],
            "length": int(data["len"]),
            "info": info,
            "sport": int(ports.group("sport")) if ports else None,
            "dport": int(ports.group("dport")) if ports else None,
        })
    return packets


def stamp_arrival(packets: list[dict]) -> None:
    """Give packets with no wall clock of their own the time they got here.

    tshark is asked for absolute timestamps, so this only matters for output
    from a build that ignored -t a — better a systime accurate to the moment
    netzilla read the line than an empty column.
    """
    if not packets:
        return
    from datetime import datetime

    now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    for packet in packets:
        if not packet.get("clock"):
            packet["clock"] = now


def packet_rows(packets: list[dict], limit: int = 200) -> list[list[object]]:
    """Rows for PACKET_COLUMNS.

    Systime is the wall clock each packet arrived at; Δt is its offset from
    the earliest packet in this list, which stays meaningful when the live
    view shows them newest first.
    """
    shown = packets[:limit]
    if not shown:
        return []
    base = min(p["time"] for p in shown)
    rows = []
    for packet in shown:
        delta = packet["time"] - base
        if delta < 0:                       # the capture ran across midnight
            delta += 86400.0
        rows.append([
            packet["no"],
            packet.get("clock") or "—",
            f"+{delta:.3f}",
            packet["src"],
            packet["dst"],
            packet["protocol"],
            packet["length"],
            packet["info"][:64],
        ])
    return rows


def protocol_mix(packets: list[dict]) -> list[list[object]]:
    """Which protocols showed up, by packet count and bytes."""
    tally: dict[str, list[int]] = {}
    for packet in packets:
        entry = tally.setdefault(packet["protocol"], [0, 0])
        entry[0] += 1
        entry[1] += packet["length"]
    total = sum(e[0] for e in tally.values()) or 1
    rows = [
        [proto, count, f"{100 * count / total:.1f}%", f"{byte_count:,} B"]
        for proto, (count, byte_count) in tally.items()
    ]
    rows.sort(key=lambda row: row[1], reverse=True)
    return rows


def talkers(packets: list[dict], limit: int = 15) -> list[list[object]]:
    """Busiest address pairs in the capture, by bytes."""
    tally: dict[tuple[str, str], list[int]] = {}
    for packet in packets:
        pair = tuple(sorted((packet["src"], packet["dst"])))
        entry = tally.setdefault(pair, [0, 0])
        entry[0] += 1
        entry[1] += packet["length"]
    rows = [
        [f"{a}  ↔  {b}", count, f"{byte_count:,} B"]
        for (a, b), (count, byte_count) in tally.items()
    ]
    rows.sort(key=lambda row: int(str(row[2]).replace(",", "").replace(" B", "")),
              reverse=True)
    return rows[:limit]


def capture_summary(packets: list[dict], source: str) -> list[tuple[str, object]]:
    if not packets:
        return [("Source", source), ("Packets", 0)]
    # Timestamps only subtract meaningfully within one basis, and a build that
    # ignored -t a leaves some lines on the clock and some on seconds-since-
    # the-first-packet. Prefer the clocked ones when there are any.
    timed = [p for p in packets if p.get("clock")] or packets
    span = max(p["time"] for p in timed) - min(p["time"] for p in timed)
    if span < 0:                               # captured across midnight
        span += 86400.0
    total_bytes = sum(p["length"] for p in packets)
    first, last = timed[0].get("clock"), timed[-1].get("clock")
    return [
        ("Source", source),
        ("Packets", len(packets)),
        ("Bytes", f"{total_bytes:,}"),
        ("First packet", first or "—"),
        ("Last packet", last or "—"),
        ("Time span", f"{span:.2f}s"),
        ("Average size", f"{total_bytes // len(packets):,} B"),
        ("Rate", f"{len(packets) / span:.1f} packets/s" if span > 0 else "—"),
        ("Protocols seen", ", ".join(
            sorted({p["protocol"] for p in packets})
        )[:80]),
    ]


# ----------------------------------------------------------------- tcpdump
async def tcpdump_capture(
    iface: str, count: int = 50, bpf: str = "", seconds: int = 30,
    pcap: str = "", prefix: list[str] | None = None,
) -> CommandResult:
    """tcpdump with numeric output; -c stops it, and the window caps the wait."""
    argv = list(prefix or []) + ["tcpdump", "-nn", "-c", str(int(count))]
    argv += ["-r", pcap] if pcap else ["-i", iface]
    if bpf:
        argv += bpf.split()
    if pcap:
        return await run(argv, timeout=60, ok_returncodes=(0, 1))
    # A live capture on a quiet link would otherwise wait for -c packets
    # forever, so it is stopped at the window and its output kept.
    return await run_for(argv, seconds=seconds)


def tcpdump_line_count(output: str) -> int:
    return sum(
        1 for line in (output or "").splitlines()
        if line.strip() and not line.startswith(("tcpdump:", "listening on"))
    )


# ------------------------------------------------------------- pcap files
def resolve_pcap(raw: str) -> str:
    return str(Path(raw.strip()).expanduser()) if raw.strip() else ""


def pcap_exists(path: str) -> bool:
    try:
        return bool(path) and Path(path).is_file()
    except OSError:
        return False


def default_pcap_path(iface: str) -> str:
    from datetime import datetime

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    # Windows names an interface "Wi-Fi 2" or "\\Device\\NPF_{…}": keep the
    # file name to characters every system accepts.
    return str(Path.home() / f"netzilla-{hostos.safe_filename(iface)}-{stamp}.pcapng")


def pcap_details(path: str) -> list[tuple[str, object]]:
    try:
        stat = Path(path).stat()
    except OSError:
        return [("File", path)]
    from datetime import datetime

    return [
        ("File", path),
        ("Size", f"{stat.st_size:,} bytes"),
        ("Written", datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")),
        ("Open in Wireshark", f"wireshark {path}"),
        ("Read it back here", "put this path in the PCAP FILE box and press READ PCAP"),
    ]


# ------------------------------------------------------------- filter help
# tshark uses Wireshark DISPLAY filter syntax (-Y); tcpdump uses BPF CAPTURE
# filter syntax. They are different languages for the same job, which is the
# single most common thing to trip over, so both are shown side by side.
FILTER_ROWS: list[list[str]] = [
    [
        "By protocol",
        "dns",
        "udp port 53",
        "Only packets of one protocol. Try http, dns, tcp, arp, icmp, tls.",
    ],
    [
        "By IP address",
        "ip.addr == 192.168.1.1",
        "host 192.168.1.1",
        "Everything to and from one address. ip.src / ip.dst for one direction.",
    ],
    [
        "By port",
        "tcp.port == 80",
        "tcp port 80",
        "Traffic on a service port. udp.port == 53 for DNS.",
    ],
    [
        "By content",
        'frame contains "password"',
        "—  (BPF cannot search text)",
        "Search payload bytes for a string. http.request shows web requests.",
    ],
    [
        "By combining",
        "http and tcp.port == 80",
        "tcp port 80 and host 10.0.0.5",
        "Join rules with and / or / not.",
    ],
    [
        "By network",
        "ip.addr == 10.0.0.0/8",
        "net 10.0.0.0/8",
        "A whole subnet rather than one host.",
    ],
    [
        "Exclude noise",
        "not arp and not icmp",
        "not arp and not icmp",
        "Drop the chatter you are not looking for.",
    ],
]

FILTER_EXAMPLES: list[tuple[str, str]] = [
    ("See DNS lookups as they happen", "dns"),
    ("Watch one machine's whole conversation", "ip.addr == 192.168.1.50"),
    ("Web traffic only", "http or tls"),
    ("Find cleartext logins", 'frame contains "password"'),
    ("TCP problems", "tcp.analysis.flags"),
    ("Connection attempts (SYN, no ACK)", "tcp.flags.syn == 1 and tcp.flags.ack == 0"),
    ("Everything except your own SSH session", "not tcp.port == 22"),
    ("DHCP handshakes", "dhcp or bootp"),
]

FILTER_NOTES = (
    "CAPTURE box = tshark display filter (-Y). TCPDUMP CAPTURE box = BPF.\n"
    "A display filter decides what is shown after decoding, so it can reach "
    "inside protocols; a BPF capture filter decides what is recorded at all, "
    "so it is faster but far more limited. Wireshark's full display-filter "
    "reference:  https://www.wireshark.org/docs/dfref/"
)


# --------------------------------------------------------- live capture
def live_argv(
    iface: str, display_filter: str = "", prefix: list[str] | None = None
) -> list[str]:
    """tshark with no count and no duration: it runs until it is stopped.

    -l flushes each packet as it is decoded rather than buffering a block at
    a time, which is what makes the view feel live on a quiet link.
    """
    argv = list(prefix or []) + ["tshark"] + ABSOLUTE_TIME + ["-i", iface, "-l"]
    if display_filter:
        argv += ["-Y", display_filter]
    return argv


class LiveCapture:
    """A tshark that keeps running, handing packets over as they arrive."""

    def __init__(
        self, iface: str, display_filter: str = "",
        prefix: list[str] | None = None, keep: int = 300,
    ) -> None:
        self.iface = iface
        self.display_filter = display_filter
        self.keep = keep
        self._trim_at = keep + max(keep // 4, 1)
        self.packets: list[dict] = []
        self.total = 0
        self.unparsed = 0
        self._process = LiveProcess(live_argv(iface, display_filter, prefix))
        self.command = self._process.command

    async def start(self) -> str:
        return await self._process.start()

    async def packets_as_they_arrive(self, idle: float = 0.5):
        """Yield True for each packet parsed, None on an idle tick."""
        async for line in self._process.lines(idle=idle):
            if line is None:
                yield None
                continue
            parsed = parse_packets(line)
            if not parsed:
                # tshark's own chatter ("Capturing on ...") is not a packet.
                if line.strip() and not _is_chatter(line):
                    self.unparsed += 1
                continue
            for packet in parsed:
                self.total += 1
                self.packets.append(packet)
            # Trimming to `keep` on every packet means shuffling the whole
            # list down by one each time, which is the single most expensive
            # thing a busy capture can do. Let it overshoot by a quarter and
            # then cut that back in one go: the same ceiling, amortised.
            if len(self.packets) > self._trim_at:
                del self.packets[: len(self.packets) - self.keep]
            yield True

    async def stop(self) -> str:
        return await self._process.stop()


_CHATTER_RE = re.compile(r"^\d+\s+packets?\s+(captured|dropped)", re.I)


def _is_chatter(line: str) -> bool:
    """tshark's own status lines, which are not packets.

    The counts it prints when stopping ("12 packets captured") begin with a
    number, so a prefix match alone misses them and they end up counted as
    unrecognised output.
    """
    lowered = line.strip().lower()
    if _CHATTER_RE.match(lowered):
        return True
    return lowered.startswith((
        "capturing on", "** (tshark", "running as user", "capturing stopped",
        "tshark:", "please turn off", "dropped privs",
    ))


def live_summary(
    capture: "LiveCapture", seconds: float, permission: str = ""
) -> list[tuple[str, object]]:
    rate = capture.total / seconds if seconds > 0 else 0.0
    window = capture.packets
    bytes_held = sum(p["length"] for p in window)
    rows: list[tuple[str, object]] = [
        ("Interface", capture.iface),
        ("Filter", capture.display_filter or "none — everything"),
        ("Running for", f"{seconds:.0f}s"),
        ("Packets seen", f"{capture.total:,}"),
        ("Rate", f"{rate:.1f} packets/s"),
        ("Held for display", f"{len(window):,} most recent ({bytes_held:,} bytes)"),
    ]
    if permission:
        rows.append(("Running as", permission))
    if capture.unparsed:
        rows.append(("Lines not recognised", capture.unparsed))
    return rows


# ------------------------------------------------- filtering held packets
# Once a capture has stopped, its packets are still in memory, and narrowing
# them down should not mean capturing all over again. tshark is gone by then,
# so netzilla applies the filter itself — over the columns it parsed, which is
# a real subset of Wireshark's display-filter language rather than all of it.
#
# What works here: a bare protocol or word, the address/port/length/protocol
# fields below with == != > < >= <=, `contains`, CIDR networks, and terms
# joined with and / or / not, evaluated left to right. What does not: anything
# needing the decoded packet itself (tcp.analysis.flags, tls.handshake.type),
# and brackets. Anything not understood is reported rather than silently
# dropped, and the packets are still there to re-filter.

LOCAL_FILTER_NOTE = (
    "This filter was applied by netzilla to the packets already in memory, "
    "not by tshark. It understands: a bare word (protocol name, address or "
    "any text in the line); ip.addr / ip.src / ip.dst; tcp.port / udp.port / "
    "srcport / dstport; frame.len; protocol; frame contains \"text\"; the "
    "operators == != > < >= <=; CIDR networks such as 10.0.0.0/8; and terms "
    "joined with and / or / not, read left to right.\n\n"
    "Filters that need the decoded packet — tcp.analysis.flags, "
    "tls.handshake.type and the like — cannot be applied after the fact. Put "
    "those in the FILTER box and run a fresh capture instead.\n\n"
    "'!=' means none of the values match, so 'ip.addr != 10.0.0.1' excludes "
    "that host in both directions, which is the thing people usually want and "
    "the thing Wireshark famously does not do."
)

_TOKEN_RE = re.compile(r'"[^"]*"|\'[^\']*\'|\S+')
# A dotted name whose first part names a protocol — tcp.analysis.flags,
# tls.handshake.type — is a Wireshark field, not free text. A hostname looks
# the same (example.com), so the first part has to be a protocol netzilla
# recognises before the term is treated as a field reference.
_FIELD_NAME_RE = re.compile(r"^(?P<head>[A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
_PROTOCOL_PREFIXES = {
    "_ws", "ah", "arp", "bgp", "bootp", "cdp", "dhcp", "dhcpv6", "dns", "eap",
    "eapol", "eth", "esp", "frame", "ftp", "gre", "gtp", "http", "http2",
    "icmp", "icmpv6", "igmp", "ip", "ipv6", "ipx", "iscsi", "isakmp",
    "kerberos", "l2tp", "ldap", "llc", "lldp", "llmnr", "mdns", "modbus",
    "mpls", "mysql", "nbns", "nfs", "ntp", "ospf", "pop", "pppoe", "quic",
    "radius", "rip", "rtcp", "rtp", "sctp", "sip", "smb", "smb2", "smtp",
    "snmp", "ssh", "ssl", "stp", "syslog", "tcp", "telnet", "tftp", "tls",
    "udp", "vlan", "vrrp", "wlan", "x509", "xml",
}


def _looks_like_a_field(text: str) -> bool:
    match = _FIELD_NAME_RE.match(text)
    return bool(match) and match.group("head").lower() in _PROTOCOL_PREFIXES
_COMPARE_RE = re.compile(
    r"^(?P<field>[A-Za-z_][A-Za-z0-9_.]*)\s*"
    r"(?P<op>==|!=|>=|<=|>|<|=|\beq\b|\bne\b|\bcontains\b)\s*"
    r"(?P<value>.+)$",
    re.I,
)

# Field name -> which parsed values it looks at.
_FIELD_ALIASES = {
    "ip.addr": "addr", "addr": "addr", "host": "addr", "ipv6.addr": "addr",
    "ip.src": "src", "src": "src", "eth.src": "src", "ipv6.src": "src",
    "ip.dst": "dst", "dst": "dst", "eth.dst": "dst", "ipv6.dst": "dst",
    "tcp.port": "port", "udp.port": "port", "port": "port",
    "tcp.srcport": "sport", "udp.srcport": "sport", "srcport": "sport",
    "tcp.dstport": "dport", "udp.dstport": "dport", "dstport": "dport",
    "frame.len": "length", "ip.len": "length", "length": "length",
    "len": "length", "bytes": "length",
    "frame": "info", "info": "info", "frame.info": "info",
    "protocol": "protocol", "proto": "protocol",
    "_ws.col.protocol": "protocol", "_ws.col.info": "info",
    "frame.number": "no", "no": "no", "number": "no",
    "frame.time": "clock", "clock": "clock", "systime": "clock",
}


def _values(packet: dict, kind: str) -> list:
    if kind == "addr":
        return [packet["src"], packet["dst"]]
    if kind == "port":
        return [p for p in (packet.get("sport"), packet.get("dport"))
                if p is not None]
    if kind == "sport":
        return [packet["sport"]] if packet.get("sport") is not None else []
    if kind == "dport":
        return [packet["dport"]] if packet.get("dport") is not None else []
    if kind == "length":
        return [packet["length"]]
    if kind == "no":
        return [packet["no"]]
    if kind == "protocol":
        return [packet["protocol"]]
    if kind == "info":
        return [packet["info"]]
    if kind == "clock":
        return [packet.get("clock") or ""]
    return [packet.get(kind, "")]


def _as_number(value) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _in_network(values: list, target: str) -> bool:
    import ipaddress

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    for value in values:
        try:
            if ipaddress.ip_address(str(value)) in network:
                return True
        except ValueError:
            continue
    return False


def _compare(values: list, op: str, target: str) -> bool:
    """One field test. `!=` means none of the values match, not any of them."""
    if op in ("!=", "ne"):
        return not _compare(values, "==", target)
    if not values:
        return False
    if op == "contains":
        return any(target.lower() in str(value).lower() for value in values)
    if op in ("==", "eq", "="):
        if "/" in target and _in_network(values, target):
            return True
        number = _as_number(target)
        if number is not None:
            return any(
                (parsed := _as_number(value)) is not None and parsed == number
                for value in values
            )
        return any(str(value).lower() == target.lower() for value in values)

    number = _as_number(target)
    if number is None:
        return False
    for value in values:
        parsed = _as_number(value)
        if parsed is None:
            continue
        if ((op == ">" and parsed > number)
                or (op == "<" and parsed < number)
                or (op == ">=" and parsed >= number)
                or (op == "<=" and parsed <= number)):
            return True
    return False


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _bare_test(word: str):
    """A term with no operator: a protocol name, an address, or any text."""
    needle = _unquote(word).lower()

    def test(packet: dict) -> bool:
        if packet["protocol"].lower() == needle:
            return True
        blob = " ".join((
            packet["protocol"], packet["src"], packet["dst"], packet["info"]
        )).lower()
        return needle in blob

    return test


def _term_test(text: str):
    """(callable, label) for one term, or (None, text) when unrecognised."""
    text = text.strip()
    if not text:
        return None, text
    match = _COMPARE_RE.match(text)
    if match:
        field = match.group("field").lower()
        kind = _FIELD_ALIASES.get(field)
        if kind is None:
            return None, text
        op = match.group("op").lower().strip()
        target = _unquote(match.group("value"))
        return (
            lambda packet: _compare(_values(packet, kind), op, target),
            f"{field} {op} {target}",
        )
    if any(char in text for char in "()[]"):
        return None, text            # brackets are not supported, say so
    if _looks_like_a_field(text):
        # A field name on its own means "this field is present" in Wireshark.
        # netzilla only kept the printed columns, so it cannot answer that —
        # and searching for the text "tcp.analysis.flags" would quietly match
        # nothing at all, which is worse than saying so.
        return None, text
    return _bare_test(text), _unquote(text)


def _split_terms(expression: str) -> list[tuple[str, bool, str]]:
    """-> [(joiner, negated, term)], joiner being 'and' or 'or'."""
    terms: list[tuple[str, bool, str]] = []
    joiner, negated, words = "and", False, []

    def close() -> None:
        nonlocal negated, words
        if words:
            terms.append((joiner, negated, " ".join(words)))
        negated, words = False, []

    for token in _TOKEN_RE.findall(expression or ""):
        lowered = token.lower()
        if lowered in ("and", "&&") and words:
            close()
            joiner = "and"
        elif lowered in ("or", "||") and words:
            close()
            joiner = "or"
        elif lowered in ("not", "!") and not words:
            negated = True
        else:
            words.append(token)
    close()
    return terms


def compile_filter(expression: str):
    """(predicate or None, understood terms, terms that were not understood)."""
    tests: list[tuple[str, bool, object]] = []
    understood: list[str] = []
    unknown: list[str] = []
    for joiner, negated, text in _split_terms(expression):
        test, label = _term_test(text)
        if test is None:
            unknown.append(label)
            continue
        understood.append(("not " if negated else "") + label)
        tests.append((joiner, negated, test))
    if not tests:
        return None, understood, unknown

    def predicate(packet: dict) -> bool:
        result: bool | None = None
        for joiner, negated, test in tests:
            value = bool(test(packet))
            if negated:
                value = not value
            if result is None:
                result = value
            elif joiner == "or":
                result = result or value
            else:
                result = result and value
        return bool(result)

    return predicate, understood, unknown


def filter_packets(
    packets: list[dict], expression: str
) -> tuple[list[dict], list[str]]:
    """Narrow packets already in memory. Also returns what netzilla made of
    the filter, because a silent mismatch is worse than no filter at all."""
    expression = (expression or "").strip()
    if not expression:
        return list(packets), ["No filter — every held packet is shown."]
    predicate, understood, unknown = compile_filter(expression)
    notes: list[str] = []
    if understood:
        notes.append("Applied: " + "; ".join(understood))
    if unknown:
        notes.append(
            "Could not be applied to packets already captured, so ignored: "
            + "; ".join(unknown)
        )
    if predicate is None:
        notes.append(
            "Nothing in that filter could be applied here, so every held "
            "packet is shown. Put it in the FILTER box and capture again to "
            "let tshark do it properly."
        )
        return list(packets), notes
    return [packet for packet in packets if predicate(packet)], notes


# A line pasted out of FILTER HELP's first column — "By protocol: dns",
# "TCPDUMP: port 80" — is not a filter, and tshark's complaint about it
# ("\"UDP\" was unexpected in this context") does not explain that at all.
_PASTED_LABEL_RE = re.compile(r"^(?P<label>[A-Za-z][A-Za-z ]*?)\s*:\s*(?P<rest>\S.*)$")


def check_filter(expression: str) -> str:
    """"" when the filter looks usable, otherwise what is wrong with it."""
    expression = (expression or "").strip()
    if not expression:
        return ""
    match = _PASTED_LABEL_RE.match(expression)
    if match:
        label = match.group("label")
        rest = match.group("rest").strip()
        # A real display filter never has a bare word and a space before a
        # colon; IPv6 literals (ipv6.addr == ::1) do not match this shape.
        if " " in label or label.isupper():
            return (
                f"That looks like a whole line copied out of FILTER HELP: the "
                f"{label!r} part is the heading, not part of the filter.\n\n"
                f"Use just the filter itself:\n\n    {rest}\n\n"
                "The left-hand column of FILTER HELP says what each filter is "
                "for; the middle columns are what to type here."
            )
    return ""
