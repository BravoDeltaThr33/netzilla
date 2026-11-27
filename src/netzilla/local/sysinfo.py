"""This machine at a glance, for DASH — every fact local and quick to read.

Linux reads /proc and /etc; macOS answers through sysctl and vm_stat, and
Windows through its own API (winapi.py). Anything a system cannot say comes
back as "—", so DASH always has something to show.
"""

from __future__ import annotations

import os
import platform
import re
import socket
import subprocess
import time
from pathlib import Path

from .. import hostos

RESOLV_CONF = Path("/etc/resolv.conf")
# systemd-resolved points /etc/resolv.conf at its own stub (127.0.0.53); the
# servers it really forwards to are listed here.
RESOLVED_UPSTREAM = Path("/run/systemd/resolve/resolv.conf")


def _read(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def windows_name(release: str, version: str, edition: str = "") -> str:
    """'Windows 11 Pro (build 22631)'. Windows 11 still calls itself release
    "10" to older Pythons; its build number (22000 and up) is what tells."""
    try:
        build = int(version.split(".")[2])
    except (IndexError, ValueError):
        build = 0
    if release == "10" and build >= 22000:
        release = "11"
    name = f"Windows {release}".strip()
    if edition and edition not in ("", "Core"):
        name += f" {edition}"
    return name + (f" (build {build})" if build else "")


def os_name() -> str:
    """'Linux Mint 22.1' from /etc/os-release, else the platform's own name."""
    if hostos.is_windows():
        try:
            edition = platform.win32_edition() or ""
        except Exception:
            edition = ""
        edition = {"Professional": "Pro", "Enterprise": "Enterprise",
                   "Education": "Education"}.get(edition, "")
        return windows_name(platform.release(), platform.version(), edition)
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


def _sysctl(name: str) -> str:
    """One sysctl value on macOS ('' when it cannot be read)."""
    try:
        done = subprocess.run(["sysctl", "-n", name], capture_output=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return ""
    return hostos.decode(done.stdout).strip() if done.returncode == 0 else ""


def parse_boottime(text: str, now: float | None = None) -> float | None:
    """Seconds since boot from macOS's kern.boottime:
    '{ sec = 1732600000, usec = 123456 } Tue Nov 26 08:26:40 2024'."""
    match = re.search(r"sec\s*=\s*(\d+)", text or "")
    if not match:
        return None
    now = time.time() if now is None else now
    return max(0.0, now - int(match.group(1)))


def uptime_seconds() -> float | None:
    if hostos.is_windows():
        from . import winapi

        return winapi.uptime_seconds()
    if hostos.is_macos():
        return parse_boottime(_sysctl("kern.boottime"))
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


def parse_vm_stat(text: str, total: int) -> tuple[int, int] | None:
    """(used, total) from macOS's `vm_stat`: free, inactive, speculative and
    purgeable pages count as available — roughly what Activity Monitor
    calls memory that is not in use."""
    if not total:
        return None
    size = re.search(r"page size of (\d+) bytes", text or "")
    page = int(size.group(1)) if size else 4096
    pages: dict[str, int] = {}
    for line in (text or "").splitlines():
        name, _, value = line.partition(":")
        value = value.strip().rstrip(".")
        if value.isdigit():
            pages[name.strip().lower()] = int(value)
    available = sum(pages.get(key, 0) for key in (
        "pages free", "pages inactive", "pages speculative", "pages purgeable"))
    if not pages:
        return None
    used = max(0, total - available * page)
    return min(used, total), total


def memory() -> tuple[int, int] | None:
    """(used, total) RAM in bytes on this system, or None."""
    if hostos.is_windows():
        from . import winapi

        return winapi.memory()
    if hostos.is_macos():
        try:
            total = int(_sysctl("hw.memsize") or 0)
        except ValueError:
            total = 0
        try:
            done = subprocess.run(["vm_stat"], capture_output=True, timeout=3)
            text = hostos.decode(done.stdout)
        except (OSError, subprocess.SubprocessError):
            text = ""
        return parse_vm_stat(text, total)
    return parse_meminfo(_read("/proc/meminfo"))


def memory_text(used_total: tuple[int, int] | None) -> str:
    if not used_total:
        return "—"
    used, total = used_total
    gib = 1024 ** 3
    return f"{used / gib:.1f} / {total / gib:.1f} GiB used ({used / total * 100:.0f}%)"


def load_text() -> str:
    cpus = os.cpu_count() or 0
    try:
        one, five, fifteen = os.getloadavg()
    except (OSError, AttributeError):
        # Windows keeps no load average; the CPU count is still worth showing.
        return f"— · {cpus} CPUs" if cpus else "—"
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
    if hostos.is_windows():
        from . import netif

        return netif.windows_dns(netif._windows_adapters()), ""
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
        "memory": memory_text(memory()),
        "python": platform.python_version(),
        "textual": package_version("textual"),
        "netzilla": __version__,
    }


__all__ = ["facts", "dns_servers", "parse_meminfo", "parse_nameservers",
           "uptime_text", "memory_text", "os_name", "windows_name", "memory",
           "parse_vm_stat", "parse_boottime"]
