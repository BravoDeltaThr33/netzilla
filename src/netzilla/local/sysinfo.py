"""This machine at a glance, for DASH — every fact local and quick to read.

Linux reads /proc and /etc; elsewhere (macOS) the same keys come back with
whatever the platform module knows and "—" for the rest, so DASH always has
something to show.
"""

from __future__ import annotations

import os
import platform
import socket
from pathlib import Path

RESOLV_CONF = Path("/etc/resolv.conf")
# systemd-resolved points /etc/resolv.conf at its own stub (127.0.0.53); the
# servers it really forwards to are listed here.
RESOLVED_UPSTREAM = Path("/run/systemd/resolve/resolv.conf")


def _read(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def os_name() -> str:
    """'Linux Mint 22.1' from /etc/os-release, else the platform's own name."""
    for line in _read("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    if platform.system() == "Darwin":
        release = platform.mac_ver()[0]
        return f"macOS {release}".strip()
    return platform.platform(terse=True) or "—"


def uptime_text(seconds: float | None) -> str:
    """'3d 04h 12m', '5h 07m', '42m'."""
    if seconds is None or seconds < 0:
        return "—"
    minutes = int(seconds // 60)
    days, minutes = divmod(minutes, 1440)
    hours, minutes = divmod(minutes, 60)
    if days:
        return f"{days}d {hours:02d}h {minutes:02d}m"
    if hours:
        return f"{hours}h {minutes:02d}m"
    return f"{minutes}m"


def uptime_seconds() -> float | None:
    text = _read("/proc/uptime").split()
    try:
        return float(text[0])
    except (IndexError, ValueError):
        return None


def parse_meminfo(text: str) -> tuple[int, int] | None:
    """(used, total) in bytes from /proc/meminfo, 'used' meaning not available."""
    values: dict[str, int] = {}
    for line in text.splitlines():
        name, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            values[name.strip()] = int(parts[0]) * 1024
    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if not total or available is None:
        return None
    return total - available, total


def memory_text(used_total: tuple[int, int] | None) -> str:
    if not used_total:
        return "—"
    used, total = used_total
    gib = 1024 ** 3
    return f"{used / gib:.1f} / {total / gib:.1f} GiB used ({used / total * 100:.0f}%)"


def load_text() -> str:
    try:
        one, five, fifteen = os.getloadavg()
    except (OSError, AttributeError):
        return "—"
    cpus = os.cpu_count() or 0
    return f"{one:.2f} {five:.2f} {fifteen:.2f}" + (f" · {cpus} CPUs" if cpus else "")


def parse_nameservers(text: str) -> list[str]:
    servers = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver" and parts[1] not in servers:
            servers.append(parts[1])
    return servers


def dns_servers() -> tuple[list[str], str]:
    """(servers, note): the resolvers this machine uses. Behind systemd-
    resolved's stub, the upstream servers it forwards to."""
    servers = parse_nameservers(_read(RESOLV_CONF))
    if servers and all(s.startswith("127.0.0.53") or s == "127.0.0.54" for s in servers):
        upstream = parse_nameservers(_read(RESOLVED_UPSTREAM))
        if upstream:
            return upstream, "via systemd-resolved"
        return servers, "systemd-resolved stub"
    return servers, ""


def package_version(name: str) -> str:
    try:
        from importlib.metadata import version

        return version(name)
    except Exception:
        return "—"


def facts() -> dict:
    """Everything THIS MACHINE shows (call it in a thread: it reads files)."""
    from .. import __version__

    try:
        host = socket.gethostname()
    except OSError:
        host = ""
    return {
        "host": host or "—",
        "os": os_name(),
        "kernel": f"{platform.system()} {platform.release()}".strip() or "—",
        "uptime": uptime_text(uptime_seconds()),
        "load": load_text(),
        "memory": memory_text(parse_meminfo(_read("/proc/meminfo"))),
        "python": platform.python_version(),
        "textual": package_version("textual"),
        "netzilla": __version__,
    }


__all__ = ["facts", "dns_servers", "parse_meminfo", "parse_nameservers",
           "uptime_text", "memory_text", "os_name"]
