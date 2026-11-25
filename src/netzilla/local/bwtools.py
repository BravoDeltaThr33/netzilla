"""Bandwidth tools that already exist on the box: iftop, vnstat, bmon.

Each one is used in the mode that prints and stops, never the full-screen
curses mode, because netzilla's own interface owns the terminal:

  iftop   -t -s N     its built-in text mode: run N seconds, print a report
  vnstat  --json      structured history; falls back to its plain text output
  bmon    -o format   its scriptable output module, captured for N seconds

nload has no such mode at all, so netzilla does not shell out to it; the INT
tab's LIVE RATES action reads /proc/net/dev directly instead (see netif.py).
"""

from __future__ import annotations

import json
import os

from .runner import CommandResult, have, run, run_for

TOOLS = ("iftop", "vnstat", "bmon", "nload")

INSTALL_HINTS = {
    "iftop": "sudo apt install -y iftop",
    "vnstat": "sudo apt install -y vnstat && sudo systemctl enable --now vnstat",
    "bmon": "sudo apt install -y bmon",
    "nload": "sudo apt install -y nload",
}

PURPOSE = {
    "iftop": "per-connection live bandwidth (needs root)",
    "vnstat": "historical daily/monthly totals (needs its service running)",
    "bmon": "per-interface rates and counters",
    "nload": "optional — netzilla's LIVE RATES covers the same ground",
}


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:      # non-POSIX; netzilla targets Linux/macOS
        return False


def tools_status() -> list[tuple[str, bool, str, str]]:
    """[(tool, installed, purpose, install hint)] for the TOOL CHECK action."""
    return [(t, have(t), PURPOSE[t], INSTALL_HINTS[t]) for t in TOOLS]


def needs_root_error(result: CommandResult) -> bool:
    """Did this fail because it could not open the interface?"""
    blob = f"{result.error} {result.output}".lower()
    return any(
        marker in blob
        for marker in (
            "operation not permitted", "permission denied", "must be run as root",
            "run as root", "you must be root", "pcap_open_live", "no suitable device",
        )
    )


# ------------------------------------------------------------------- iftop
async def binary_caps(tool: str) -> str:
    """File capabilities on a binary, via getcap. "" when it has none."""
    if not have("getcap") or not have(tool):
        return ""
    import shutil

    path = shutil.which(tool) or tool
    result = await run(["getcap", path], timeout=5)
    return result.output if result.ok else ""


async def sudo_without_password() -> bool:
    """True when sudo will run this without prompting (NOPASSWD or a live
    timestamp). `sudo -n` never prompts, so this cannot hang the interface."""
    if not have("sudo"):
        return False
    result = await run(["sudo", "-n", "true"], timeout=5)
    return result.ok


async def elevation(tool: str) -> tuple[list[str] | None, str]:
    """How to run a tool that needs CAP_NET_RAW.

    ([], why)          already permitted — run it as-is
    (["sudo","-n"], w) run it through passwordless sudo
    (None, why)        not possible right now; `why` explains what was checked
    """
    if is_root():
        return [], "netzilla is running as root"
    caps = await binary_caps(tool)
    if "cap_net_raw" in caps.lower():
        return [], f"{tool} carries cap_net_raw"
    if await sudo_without_password():
        # An unlocked CAPTURE session shows up here too: it primes sudo's own
        # timestamp, so `sudo -n` succeeds for every tool, not just tshark.
        from .elevation import SESSION

        return ["sudo", "-n"], (
            "using the sudo session unlocked on the CAPTURE tab"
            if SESSION.active else "using passwordless sudo"
        )
    checked = (
        "netzilla is not running as root, "
        f"{tool} has no cap_net_raw capability, "
        "and sudo would ask for a password"
    )
    return None, checked


async def iftop_snapshot(
    iface: str, seconds: int = 10, prefix: list[str] | None = None
) -> CommandResult:
    """iftop's own text mode: -t prints a report instead of drawing a screen."""
    argv = list(prefix or []) + ["iftop", "-t", "-s", str(int(seconds)), "-n", "-N"]
    if iface:
        argv += ["-i", iface]
    result = await run(argv, timeout=seconds + 20, ok_returncodes=(0, 1))
    if result.missing_tool in ("sudo",):
        result.missing_tool = None
    return result


# ------------------------------------------------------------------ vnstat
VNSTAT_MODES = {
    "summary": [],
    "daily": ["-d"],
    "monthly": ["-m"],
    "hourly": ["-h"],
    "top days": ["-t"],
}

_JSON_MODE = {
    "summary": "",
    "daily": "d",
    "monthly": "m",
    "hourly": "h",
    "top days": "t",
}


async def vnstat_json(iface: str, mode: str = "summary") -> tuple[dict | None, str]:
    """(payload, error). vnstat 2.x speaks JSON; 1.x is handled by the caller."""
    argv = ["vnstat", "--json"]
    letter = _JSON_MODE.get(mode, "")
    if letter:
        argv.append(letter)
    if iface:
        argv += ["-i", iface]
    result = await run(argv, timeout=30)
    if not result.ok or not result.output:
        return None, result.error or "vnstat returned nothing."
    try:
        return json.loads(result.output), ""
    except ValueError:
        return None, "vnstat did not return JSON (very old version?)."


async def vnstat_text(iface: str, mode: str = "summary") -> CommandResult:
    argv = ["vnstat"] + VNSTAT_MODES.get(mode, [])
    if iface:
        argv += ["-i", iface]
    return await run(argv, timeout=30)


def _iface_block(payload: dict, iface: str) -> dict | None:
    blocks = payload.get("interfaces") or []
    for block in blocks:
        name = block.get("name") or block.get("id") or ""
        if not iface or name == iface:
            return block
    return blocks[0] if blocks else None


def _scale(payload: dict) -> int:
    """jsonversion 1 reports KiB; version 2 and later report bytes."""
    return 1024 if str(payload.get("jsonversion", "2")).strip() == "1" else 1


def _period_list(traffic: dict, mode: str) -> list[dict]:
    keys = {
        "daily": ("day", "days"),
        "monthly": ("month", "months"),
        "hourly": ("hour", "hours"),
        "top days": ("top", "tops"),
        "summary": ("day", "days"),
    }.get(mode, ("day", "days"))
    for key in keys:
        value = traffic.get(key)
        if isinstance(value, list):
            return value
    return []


def _stamp(entry: dict, mode: str) -> str:
    date = entry.get("date") or {}
    time_of = entry.get("time") or {}
    year, month, day = date.get("year"), date.get("month"), date.get("day")
    if year and month and day:
        stamp = f"{year:04d}-{month:02d}-{day:02d}"
    elif year and month:
        return f"{year:04d}-{month:02d}"
    else:
        return str(entry.get("id", "—"))
    if mode == "hourly":
        hour = time_of.get("hour", entry.get("hour"))
        if hour is not None:
            stamp += f" {int(hour):02d}:00"
    return stamp


def vnstat_rows(payload: dict, iface: str, mode: str) -> list[list[object]]:
    """[[when, rx, tx, total], ...] from either vnstat JSON dialect."""
    block = _iface_block(payload, iface)
    if not block:
        return []
    traffic = block.get("traffic") or {}
    scale = _scale(payload)
    rows = []
    for entry in _period_list(traffic, mode)[-40:]:
        if not isinstance(entry, dict):
            continue
        rx = int(entry.get("rx", 0)) * scale
        tx = int(entry.get("tx", 0)) * scale
        rows.append([_stamp(entry, mode), _human(rx), _human(tx), _human(rx + tx)])
    rows.reverse()      # newest first, like every other table in netzilla
    return rows


def vnstat_summary(payload: dict, iface: str) -> list[tuple[str, object]]:
    block = _iface_block(payload, iface)
    if not block:
        return []
    traffic = block.get("traffic") or {}
    scale = _scale(payload)
    total = traffic.get("total") or {}
    rx = int(total.get("rx", 0)) * scale
    tx = int(total.get("tx", 0)) * scale
    return [
        ("Interface", block.get("name") or block.get("id") or iface),
        ("vnstat version", payload.get("vnstatversion", "—")),
        ("Collecting since", _when(block.get("created"))),
        ("Last update", _when(block.get("updated"))),
        ("Total received", _human(rx)),
        ("Total sent", _human(tx)),
        ("Total combined", _human(rx + tx)),
    ]


def _when(stamp) -> str:
    if not isinstance(stamp, dict):
        return "—"
    date = stamp.get("date") or {}
    time_of = stamp.get("time") or {}
    if not date.get("year"):
        return "—"
    out = f'{date["year"]:04d}-{date.get("month", 1):02d}-{date.get("day", 1):02d}'
    if time_of.get("hour") is not None:
        out += f' {time_of["hour"]:02d}:{time_of.get("minute", 0):02d}'
    return out


def _human(value: float) -> str:
    step = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if step < 1024 or unit == "TiB":
            return f"{step:,.1f} {unit}" if unit != "B" else f"{step:,.0f} B"
        step /= 1024
    return f"{step:,.1f} TiB"


def vnstat_service_hint(output: str) -> str:
    """vnstat says different things when it has no data yet; normalise them."""
    blob = (output or "").lower()
    if "not found" in blob or "unable to" in blob or "no data available" in blob:
        return (
            "vnstat has no database for this interface yet. Its service has to "
            "run for a while before there is history to show:\n"
            "    sudo systemctl enable --now vnstat\n"
            "    sudo vnstat --add -i <interface>     (older versions)\n"
            "Give it five minutes, then try again."
        )
    return ""


# -------------------------------------------------------------------- bmon
async def bmon_snapshot(iface: str, seconds: int = 10) -> CommandResult:
    """bmon's scriptable output module, captured for a fixed window.

    `-o format` streams one machine-readable line per interface per interval
    and never exits, so it is stopped after `seconds`. Some builds ship
    without the format module; `-o ascii` is tried before giving up.
    """
    base = ["bmon", "-o", "format", "-r", "1"]
    if iface:
        base += ["-p", iface]
    result = await run_for(base, seconds=seconds)
    if result.ok and result.output:
        return result
    fallback = ["bmon", "-o", "ascii", "-r", "1"]
    if iface:
        fallback += ["-p", iface]
    second = await run_for(fallback, seconds=seconds)
    if second.ok:
        return second
    return second if second.error else result


def bmon_samples(output: str) -> dict[str, list[list[int]]]:
    """{interface: [[n, n, ...], ...]} from bmon's `-o format` stream.

    bmon prints an interface name followed by bare numbers and no header, and
    the exact columns differ between builds, so nothing is assumed here beyond
    "first token names the interface, the rest are numbers".
    """
    samples: dict[str, list[list[int]]] = {}
    for line in (output or "").splitlines():
        tokens = line.replace(";", " ").replace(",", " ").split()
        if len(tokens) < 2:
            continue
        name = tokens[0].strip()
        if not name or _is_number(name):
            continue
        numbers = []
        for token in tokens[1:]:
            if _is_number(token):
                numbers.append(int(float(token)))
        if numbers:
            samples.setdefault(name, []).append(numbers)
    return samples


def _is_number(token: str) -> bool:
    try:
        float(token)
        return True
    except ValueError:
        return False


def label_columns(
    samples: list[list[int]], known: dict[int, str]
) -> dict[int, str]:
    """Name bmon's columns by matching their values against /proc/net/dev.

    The kernel counters netzilla already reads identify the same numbers, so
    column 1 can be called "rx_bytes" as a fact rather than a guess. Columns
    that match nothing are left unnamed.
    """
    if not samples:
        return {}
    labels: dict[int, str] = {}
    last = samples[-1]
    for index, value in enumerate(last):
        for candidate in (value, *(row[index] for row in samples[-3:]
                                   if index < len(row))):
            if candidate in known:
                labels[index] = known[candidate]
                break
    return labels


# Positional fallback: bmon's default format module prints the cumulative
# byte counters first, receive before transmit.
ASSUMED_COLUMNS = ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")


def bmon_report(
    output: str, iface: str, seconds: float, known: dict[int, str] | None = None
) -> tuple[list[tuple[str, object]], str]:
    """(rows, how_columns_were_identified) — bmon's numbers, in real units."""
    samples = bmon_samples(output)
    series = samples.get(iface) or (
        list(samples.values())[0] if len(samples) == 1 else []
    )
    if not series:
        return [], ""

    labels = label_columns(series, known or {})
    if labels:
        how = "columns identified by matching /proc/net/dev counters"
    else:
        labels = {i: name for i, name in enumerate(ASSUMED_COLUMNS)
                  if i < len(series[-1])}
        how = "columns assumed from bmon's default output order (no match "
        how += "against /proc/net/dev — treat the labels as best effort)"

    first, last = series[0], series[-1]
    by_name: dict[str, tuple[int, int]] = {}
    for index, name in labels.items():
        if index < len(first) and index < len(last):
            by_name[name] = (first[index], last[index])

    seconds = seconds if seconds > 0 else 1.0
    rows: list[tuple[str, object]] = [
        ("Interface", iface),
        ("Samples", f"{len(series)} lines over ~{seconds:.0f}s"),
    ]
    for direction, byte_key, packet_key in (
        ("Received", "rx_bytes", "rx_packets"),
        ("Sent", "tx_bytes", "tx_packets"),
    ):
        if byte_key in by_name:
            start, end = by_name[byte_key]
            moved = max(0, end - start)
            rows.append((
                f"{direction} — total since boot",
                f"{_human(end)}  ({end:,} bytes)",
            ))
            rows.append((
                f"{direction} — during this capture",
                f"{_human(moved)} → {(moved * 8) / seconds / 1_000_000:.2f} Mbit/s",
            ))
        if packet_key in by_name:
            start, end = by_name[packet_key]
            rows.append((
                f"{direction} — packets in capture",
                f"{max(0, end - start):,}  ({(max(0, end - start)) / seconds:,.0f}/s)",
            ))
    return rows, how


def bmon_rows(output: str, iface: str = "") -> list[list[object]]:
    """Kept for the key=value style some bmon builds emit."""
    latest: dict[str, dict] = {}
    for line in (output or "").splitlines():
        if "=" not in line:
            continue
        fields: dict[str, str] = {}
        for token in line.split():
            key, sep, value = token.partition("=")
            if sep:
                fields[key.strip().lower()] = value.strip()
        name = fields.get("name") or fields.get("interface") or fields.get("element")
        if not name:
            continue
        if iface and name != iface:
            continue
        latest[name] = fields
    rows = []
    for name, fields in latest.items():
        rows.append([
            name,
            _num(fields, "rxrate.bytes", "rx.bytes", "rxbytes"),
            _num(fields, "txrate.bytes", "tx.bytes", "txbytes"),
            _num(fields, "rxrate.packets", "rx.packets", "rxpackets"),
            _num(fields, "txrate.packets", "tx.packets", "txpackets"),
        ])
    return rows


def _num(fields: dict, *keys: str) -> str:
    for key in keys:
        if key in fields:
            try:
                return f"{float(fields[key]):,.0f}"
            except ValueError:
                return fields[key]
    return "—"
