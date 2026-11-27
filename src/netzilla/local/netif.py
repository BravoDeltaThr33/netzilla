"""Local network interfaces: what exists, and how fast each one is moving.

On Linux, interfaces are enumerated with iproute2 (`ip -o link show` / `ip -o
addr show`) because net-tools' ifconfig is no longer installed by default on
Ubuntu, Mint or Debian. If ifconfig happens to be present and ip is not, its
output is parsed as a fallback; failing both, /proc/net/dev at least yields
the names. macOS has `ifconfig -a`, `route -n get default` and `networksetup
-listallhardwareports` (which says which enX is the Wi-Fi); Windows answers
through its IP Helper API (see winapi.py).

LIVE RATES is netzilla's own stand-in for nload: nload has no batch mode and
cannot be embedded in a Textual pane, so instead of shelling out to it, the
interface byte counters are sampled twice a few seconds apart and the deltas
are turned into per-interface Mbit/s, packets/s and error counts — the same
two-sample technique the LAN tab already uses for SNMP interface rates. The
counters come from /proc/net/dev on Linux, `netstat -ibn` on macOS and
GetIfTable2 on Windows, all in the same shape.

Every parser here is a pure function over command output, so the whole module
is unit-testable without a network, root, or any of the tools installed.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import subprocess
import time

from .. import hostos
from .runner import have, run

PROC_NET_DEV = "/proc/net/dev"


def counter_source() -> str:
    """Where the interface counters come from on this system, for subtitles."""
    if hostos.is_windows():
        return "Windows interface counters"
    if hostos.is_macos():
        return "netstat -ib"
    return PROC_NET_DEV

# "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP ..."
_LINK_RE = re.compile(
    r"^\d+:\s+(?P<name>[^:@]+)[^:]*:\s+<(?P<flags>[^>]*)>(?P<rest>.*)$"
)


def parse_ip_link(text: str) -> list[dict]:
    """Interfaces from `ip -o link show`."""
    found = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = _LINK_RE.match(line)
        if not match:
            continue
        rest = match.group("rest")
        flags = [f for f in match.group("flags").split(",") if f]
        state = _after(rest, "state") or ("UP" if "UP" in flags else "UNKNOWN")
        mac = _after(rest, "link/ether") or _after(rest, "link/loopback") or ""
        found.append({
            "name": match.group("name").strip(),
            "state": state,
            "mtu": _after(rest, "mtu") or "",
            "mac": mac,
            "flags": flags,
            "addresses": [],
            "default_route": False,
            "kind": _kind(match.group("name").strip(), flags),
        })
    return found


def parse_ip_addr(text: str) -> dict[str, list[str]]:
    """{interface: ['192.0.2.5/24', 'fe80::1/64']} from `ip -o addr show`."""
    addresses: dict[str, list[str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[1]
        try:
            family_at = parts.index("inet") if "inet" in parts else parts.index("inet6")
        except ValueError:
            continue
        if family_at + 1 >= len(parts):
            continue
        addresses.setdefault(name, []).append(parts[family_at + 1])
    return addresses


def parse_default_routes(text: str) -> list[str]:
    """Interface names carrying a default route, from `ip route show default`."""
    names = []
    for line in text.splitlines():
        parts = line.split()
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                names.append(parts[idx + 1])
    return names


def parse_default_gateways(text: str) -> list[str]:
    """Gateway addresses, from `ip route show default` ("default via X dev …")."""
    gateways = []
    for line in text.splitlines():
        parts = line.split()
        if "via" in parts:
            idx = parts.index("via")
            if idx + 1 < len(parts) and parts[idx + 1] not in gateways:
                gateways.append(parts[idx + 1])
    return gateways


async def default_gateways() -> list[str]:
    if hostos.is_windows():
        return windows_gateways(_windows_adapters())
    if hostos.is_macos():
        route = await macos_default_route()
        return [route["gateway"]] if route.get("gateway") else []
    if not have("ip"):
        return []
    result = await run(["ip", "route", "show", "default"], timeout=10)
    return parse_default_gateways(result.output) if result.ok else []


def parse_ifconfig(text: str) -> list[dict]:
    """Interfaces from `ifconfig -a`, for systems where that is all there is."""
    found: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            name = line.split(":")[0].split()[0].strip()
            flags = re.search(r"<([^>]*)>", line)
            mtu = re.search(r"mtu\s+(\d+)", line)
            current = {
                "name": name,
                "state": "UP" if flags and "UP" in flags.group(1) else "DOWN",
                "mtu": mtu.group(1) if mtu else "",
                "mac": "",
                "flags": [f for f in (flags.group(1).split(",") if flags else []) if f],
                "addresses": [],
                "default_route": False,
                "kind": _kind(name, []),
            }
            found.append(current)
        elif current is not None:
            ether = re.search(r"ether\s+([0-9a-fA-F:]{17})", line)
            if ether:
                current["mac"] = ether.group(1)
            inet = re.search(r"inet\s+(\S+)", line)
            if inet:
                current["addresses"].append(inet.group(1))
            inet6 = re.search(r"inet6\s+(\S+)", line)
            if inet6:
                current["addresses"].append(inet6.group(1))
    return found


def _after(text: str, key: str) -> str:
    parts = text.split()
    if key in parts:
        idx = parts.index(key)
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


def _kind(name: str, flags: list[str]) -> str:
    """A rough human label, so the picker is not just a list of bare names."""
    if name in ("lo", "lo0") or "LOOPBACK" in flags:
        return "loopback"
    for prefix, label in (
        ("wl", "wireless"), ("wlan", "wireless"), ("wlp", "wireless"),
        ("en", "ethernet"), ("eth", "ethernet"), ("em", "ethernet"),
        ("tun", "tunnel/VPN"), ("tap", "tunnel/VPN"), ("wg", "WireGuard"),
        ("ppp", "PPP"), ("br", "bridge"), ("virbr", "virtual bridge"),
        ("docker", "docker"), ("veth", "container veth"), ("bond", "bond"),
    ):
        if name.startswith(prefix):
            return label
    return "other"


async def interfaces() -> tuple[list[dict], str]:
    """(interfaces, source). Never raises: an empty list means nothing found."""
    if hostos.is_windows():
        found = windows_interfaces(_windows_adapters())
        return (found, "Windows adapters (IP Helper API)") if found else ([], "unavailable")
    if hostos.is_macos():
        return await _macos_interfaces()
    if have("ip"):
        link = await run(["ip", "-o", "link", "show"], timeout=10)
        if link.ok and link.output:
            found = parse_ip_link(link.output)
            addr = await run(["ip", "-o", "addr", "show"], timeout=10)
            if addr.ok:
                by_name = parse_ip_addr(addr.output)
                for iface in found:
                    iface["addresses"] = by_name.get(iface["name"], [])
            route = await run(["ip", "route", "show", "default"], timeout=10)
            if route.ok:
                defaults = parse_default_routes(route.output)
                for iface in found:
                    iface["default_route"] = iface["name"] in defaults
            if found:
                return found, "ip (iproute2)"
    if have("ifconfig"):
        result = await run(["ifconfig", "-a"], timeout=10)
        if result.ok and result.output:
            found = parse_ifconfig(result.output)
            if found:
                return found, "ifconfig (net-tools)"
    # Last resort: names only, straight from the kernel.
    try:
        with open(PROC_NET_DEV, "r", encoding="utf-8", errors="replace") as handle:
            counters = parse_proc_net_dev(handle.read())
    except OSError:
        return [], "unavailable"
    found = [
        {
            "name": name, "state": "UNKNOWN", "mtu": "", "mac": "", "flags": [],
            "addresses": [], "default_route": False, "kind": _kind(name, []),
        }
        for name in counters
    ]
    return found, PROC_NET_DEV


def pick_default(found: list[dict]) -> str:
    """The interface to preselect: default route first, then first non-loopback."""
    for iface in found:
        if iface.get("default_route"):
            return iface["name"]
    for iface in found:
        if iface["kind"] != "loopback" and iface.get("addresses"):
            return iface["name"]
    for iface in found:
        if iface["kind"] != "loopback":
            return iface["name"]
    return found[0]["name"] if found else ""


INTERFACE_COLUMNS = ["Interface", "Kind", "State", "MTU", "MAC", "NIC vendor",
                     "Addresses"]


def nic_vendor(mac: str) -> str:
    """The maker of the interface's chip, from the offline IEEE registry."""
    from . import devices

    if not mac or mac.replace(":", "").strip("0") == "":
        return "—"
    vendor, kind = devices.vendor_for(mac)
    if vendor:
        return devices.short_vendor(vendor, width=20)
    return {"random": "random / virtual"}.get(kind, "—")


def interface_rows(found: list[dict]) -> list[list[object]]:
    rows = []
    for iface in found:
        rows.append([
            iface["name"] + ("  ◂ default route" if iface.get("default_route") else ""),
            iface.get("kind", ""),
            iface.get("state", ""),
            iface.get("mtu", ""),
            iface.get("mac") or "—",
            nic_vendor(iface.get("mac") or ""),
            ", ".join(iface.get("addresses") or []) or "—",
        ])
    return rows


# --------------------------------------------------------------- live rates
COUNTER_FIELDS = (
    "rx_bytes", "rx_packets", "rx_errs", "rx_drop", "rx_fifo", "rx_frame",
    "rx_compressed", "rx_multicast",
    "tx_bytes", "tx_packets", "tx_errs", "tx_drop", "tx_fifo", "tx_colls",
    "tx_carrier", "tx_compressed",
)


def parse_proc_net_dev(text: str) -> dict[str, dict]:
    """{'eth0': {'rx_bytes': 1234, ...}} from the raw /proc/net/dev text."""
    counters: dict[str, dict] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue          # the two header lines
        name, _, rest = line.partition(":")
        name = name.strip()
        values = rest.split()
        if not name or len(values) < len(COUNTER_FIELDS):
            continue
        try:
            numbers = [int(v) for v in values[: len(COUNTER_FIELDS)]]
        except ValueError:
            continue
        counters[name] = dict(zip(COUNTER_FIELDS, numbers))
    return counters


def read_counters() -> dict[str, dict]:
    """{interface: counters} right now, in /proc/net/dev's terms on every
    system; {} when they cannot be read."""
    if hostos.is_windows():
        from . import winapi

        return winapi.counters() or {}
    if hostos.is_macos():
        return _macos_counters()
    try:
        with open(PROC_NET_DEV, "r", encoding="utf-8", errors="replace") as handle:
            return parse_proc_net_dev(handle.read())
    except OSError:
        return {}


def rates_between(first: dict, second: dict, seconds: float) -> list[dict]:
    """Per-interface throughput from two counter samples."""
    if seconds <= 0:
        seconds = 1.0
    rates = []
    for name, now in second.items():
        was = first.get(name)
        if not was:
            continue
        rx_bytes = max(0, now["rx_bytes"] - was["rx_bytes"])
        tx_bytes = max(0, now["tx_bytes"] - was["tx_bytes"])
        rates.append({
            "name": name,
            "rx_mbps": (rx_bytes * 8) / seconds / 1_000_000,
            "tx_mbps": (tx_bytes * 8) / seconds / 1_000_000,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "rx_pps": max(0, now["rx_packets"] - was["rx_packets"]) / seconds,
            "tx_pps": max(0, now["tx_packets"] - was["tx_packets"]) / seconds,
            "errors": (
                max(0, now["rx_errs"] - was["rx_errs"])
                + max(0, now["tx_errs"] - was["tx_errs"])
            ),
            "drops": (
                max(0, now["rx_drop"] - was["rx_drop"])
                + max(0, now["tx_drop"] - was["tx_drop"])
            ),
            "total_rx": now["rx_bytes"],
            "total_tx": now["tx_bytes"],
            "seconds": seconds,
        })
    rates.sort(key=lambda r: r["rx_mbps"] + r["tx_mbps"], reverse=True)
    return rates


async def sample_rates(seconds: float = 5.0, progress=None) -> list[dict]:
    """Two counter samples `seconds` apart -> live per-interface rates."""
    first = read_counters()
    if not first:
        return []
    started = time.monotonic()
    remaining = seconds
    while remaining > 0:
        if progress:
            progress(f"Sampling {counter_source()} — {remaining:.0f}s to go…")
        await asyncio.sleep(min(1.0, remaining))
        remaining = seconds - (time.monotonic() - started)
    elapsed = time.monotonic() - started
    return rates_between(first, read_counters(), elapsed)


def human_bytes(value: float) -> str:
    step = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if step < 1024 or unit == "TiB":
            return f"{step:,.1f} {unit}" if unit != "B" else f"{step:,.0f} B"
        step /= 1024
    return f"{step:,.1f} TiB"


def bar(mbps: float, peak: float, width: int = 14) -> str:
    """A tiny text meter, so the table reads at a glance like nload's graph."""
    if peak <= 0:
        return "·" * width
    filled = int(round((mbps / peak) * width))
    filled = max(0, min(width, filled))
    return "█" * filled + "·" * (width - filled)


def rate_rows(rates: list[dict], highlight: str = "") -> list[list[object]]:
    peak = max([r["rx_mbps"] + r["tx_mbps"] for r in rates], default=0.0)
    rows = []
    for r in rates:
        name = r["name"]
        if highlight and name == highlight:
            name = f"▸ {name}"
        rows.append([
            name,
            f'{r["rx_mbps"]:.2f}',
            f'{r["tx_mbps"]:.2f}',
            bar(r["rx_mbps"] + r["tx_mbps"], peak),
            f'{r["rx_pps"]:.0f} / {r["tx_pps"]:.0f}',
            str(r["errors"]) if r["errors"] else "0",
            str(r["drops"]) if r["drops"] else "0",
        ])
    return rows


def rate_summary(rate: dict) -> list[tuple[str, object]]:
    return [
        ("Interface", rate["name"]),
        ("Download", f'{rate["rx_mbps"]:.2f} Mbit/s'),
        ("Upload", f'{rate["tx_mbps"]:.2f} Mbit/s'),
        ("In this window", f'{human_bytes(rate["rx_bytes"])} in / '
                           f'{human_bytes(rate["tx_bytes"])} out'),
        ("Packets/s", f'{rate["rx_pps"]:.0f} in / {rate["tx_pps"]:.0f} out'),
        ("Errors / drops", f'{rate["errors"]} / {rate["drops"]}'),
        ("Since boot", f'{human_bytes(rate["total_rx"])} in / '
                       f'{human_bytes(rate["total_tx"])} out'),
        ("Sample window", f'{rate["seconds"]:.1f}s'),
    ]


def window_summary(
    first: dict, last: dict, seconds: float, name: str,
    peak_rx: float = 0.0, peak_tx: float = 0.0,
) -> list[tuple[str, object]]:
    """Averages and peaks across a whole live window, not just one tick."""
    was, now = first.get(name), last.get(name)
    if not was or not now:
        return []
    rx = max(0, now["rx_bytes"] - was["rx_bytes"])
    tx = max(0, now["tx_bytes"] - was["tx_bytes"])
    seconds = seconds if seconds > 0 else 1.0
    return [
        ("Interface", name),
        ("Watched for", f"{seconds:.0f}s"),
        ("Average down", f"{(rx * 8) / seconds / 1_000_000:.2f} Mbit/s"),
        ("Average up", f"{(tx * 8) / seconds / 1_000_000:.2f} Mbit/s"),
        ("Peak down", f"{peak_rx:.2f} Mbit/s"),
        ("Peak up", f"{peak_tx:.2f} Mbit/s"),
        ("Moved in total", f"{human_bytes(rx)} in / {human_bytes(tx)} out"),
    ]


def counter_labels(counters: dict, name: str) -> dict[int, str]:
    """{value: 'rx_bytes'} for one interface, to identify another tool's columns.

    bmon prints bare numbers with no header. Since /proc/net/dev holds the same
    counters for the same interface, matching the values tells netzilla which
    column is which instead of guessing.
    """
    entry = counters.get(name) or {}
    labels: dict[int, str] = {}
    for field in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                  "rx_errs", "tx_errs", "rx_drop", "tx_drop"):
        value = entry.get(field)
        if isinstance(value, int):
            labels.setdefault(value, field)
    return labels


# ================================================================= Windows
def _windows_adapters() -> list[dict] | None:
    from . import winapi

    return winapi.adapters()


def windows_interfaces(adapters: list[dict] | None) -> list[dict]:
    """Interface records, in the Linux shape, from winapi.adapters()."""
    from . import winapi

    found = []
    for adapter in adapters or []:
        name = adapter.get("name") or adapter.get("description") or ""
        if not name:
            continue
        up = bool(adapter.get("up"))
        found.append({
            "name": name,
            "state": "UP" if up else "DOWN",
            "mtu": str(adapter["mtu"]) if adapter.get("mtu") else "",
            "mac": adapter.get("mac") or "",
            "flags": ["UP"] if up else [],
            "addresses": list(adapter.get("addresses") or []),
            "default_route": up and bool(adapter.get("gateways")),
            "kind": winapi.adapter_kind(adapter.get("if_type", 0),
                                        adapter.get("description", ""), name),
            "description": adapter.get("description", ""),
        })
    return found


def windows_gateways(adapters: list[dict] | None) -> list[str]:
    """Default gateways of the adapters that are up, IPv4 first."""
    found: list[str] = []
    for adapter in adapters or []:
        if not adapter.get("up"):
            continue
        for gateway in adapter.get("gateways") or []:
            if gateway not in found:
                found.append(gateway)
    return sorted(found, key=lambda g: ":" in g)


def windows_dns(adapters: list[dict] | None) -> list[str]:
    """The DNS servers the adapters that are up actually use."""
    found: list[str] = []
    for adapter in adapters or []:
        if not adapter.get("up"):
            continue
        for server in adapter.get("dns") or []:
            if server not in found and not server.lower().startswith("fec0:"):
                found.append(server)
    return found


# =================================================================== macOS
_BSD_HEAD_RE = re.compile(r"^(?P<name>[^\s:]+):\s+flags=\w+<(?P<flags>[^>]*)>(?:.*?\bmtu\s+(?P<mtu>\d+))?")
_BSD_INET_RE = re.compile(r"^\s+inet\s+(?P<ip>[\d.]+)(?:\s+-->\s+\S+)?\s+netmask\s+(?P<mask>\S+)")
_BSD_INET6_RE = re.compile(r"^\s+inet6\s+(?P<ip>[0-9a-fA-F:.]+)(?:%\S+)?\s+prefixlen\s+(?P<len>\d+)")
_BSD_ETHER_RE = re.compile(r"^\s+ether\s+(?P<mac>[0-9a-fA-F:]+)")
_BSD_STATUS_RE = re.compile(r"^\s+status:\s+(?P<status>\w+)")


def _mask_bits(mask: str) -> int | None:
    """0xffffff00 or 255.255.255.0 -> 24."""
    try:
        value = int(mask, 16) if mask.lower().startswith("0x") else \
            int(ipaddress.IPv4Address(mask))
    except ValueError:
        return None
    return bin(value & 0xFFFFFFFF).count("1")


def _full_mac(mac: str) -> str:
    """macOS writes '0:1b:2c:3:4:5'; everything else writes two digits."""
    parts = mac.split(":")
    if len(parts) != 6:
        return mac.lower()
    return ":".join(part.zfill(2) for part in parts).lower()


def _bsd_kind(name: str, flags: list[str]) -> str:
    if name.startswith("lo") or "LOOPBACK" in flags:
        return "loopback"
    for prefix, label in (
        ("utun", "tunnel/VPN"), ("ipsec", "tunnel/VPN"), ("ppp", "PPP"),
        ("gif", "tunnel/VPN"), ("stf", "tunnel/VPN"), ("bridge", "bridge"),
        ("vmenet", "virtual bridge"), ("vnic", "virtual bridge"),
        ("awdl", "other"), ("llw", "other"), ("anpi", "other"), ("ap", "other"),
        ("en", "ethernet"),
    ):
        if name.startswith(prefix):
            return label
    return "other"


def parse_ifconfig_bsd(text: str) -> list[dict]:
    """Interfaces from macOS's `ifconfig -a`, addresses written as CIDR
    (netmask 0xffffff00 -> /24) the way `ip addr` writes them."""
    found: list[dict] = []
    current: dict | None = None
    for line in (text or "").splitlines():
        head = _BSD_HEAD_RE.match(line)
        if head:
            flags = [f for f in head.group("flags").split(",") if f]
            name = head.group("name")
            current = {
                "name": name,
                "state": "UP" if "UP" in flags and "RUNNING" in flags else "DOWN",
                "mtu": head.group("mtu") or "",
                "mac": "",
                "flags": flags,
                "addresses": [],
                "default_route": False,
                "kind": _bsd_kind(name, flags),
            }
            found.append(current)
            continue
        if current is None:
            continue
        match = _BSD_ETHER_RE.match(line)
        if match:
            current["mac"] = _full_mac(match.group("mac"))
            continue
        match = _BSD_INET_RE.match(line)
        if match:
            bits = _mask_bits(match.group("mask"))
            ip = match.group("ip")
            current["addresses"].append(f"{ip}/{bits}" if bits is not None else ip)
            continue
        match = _BSD_INET6_RE.match(line)
        if match:
            current["addresses"].append(f"{match.group('ip')}/{match.group('len')}")
            continue
        match = _BSD_STATUS_RE.match(line)
        if match:
            current["state"] = "UP" if match.group("status").lower() == "active" else "DOWN"
    return found


def parse_hardware_ports(text: str) -> dict[str, str]:
    """{device: port} from `networksetup -listallhardwareports`:
    {'en0': 'Wi-Fi', 'en1': 'Thunderbolt Ethernet Slot 1', …}."""
    ports: dict[str, str] = {}
    port = ""
    for line in (text or "").splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip().lower(), value.strip()
        if key == "hardware port":
            port = value
        elif key == "device" and port and value:
            ports[value] = port
            port = ""
    return ports


def port_kind(port: str) -> str:
    low = (port or "").lower()
    if "wi-fi" in low or "airport" in low or "wifi" in low:
        return "wireless"
    if "bridge" in low:
        return "bridge"
    if "ethernet" in low or " lan" in low or low.endswith("lan"):
        return "ethernet"
    if "iphone" in low or "ipad" in low:
        return "phone tether"
    if "bluetooth" in low:
        return "Bluetooth PAN"
    return ""


def parse_route_get(text: str) -> dict[str, str]:
    """{'gateway': …, 'interface': …} from `route -n get default`."""
    found: dict[str, str] = {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower()
        if key in ("gateway", "interface") and value.strip():
            found[key] = value.strip()
    return found


async def macos_default_route() -> dict[str, str]:
    if not have("route"):
        return {}
    result = await run(["route", "-n", "get", "default"], timeout=8, ok_returncodes=(0, 1))
    return parse_route_get(result.output) if result.ok else {}


async def macos_hardware_ports() -> dict[str, str]:
    if not have("networksetup"):
        return {}
    result = await run(["networksetup", "-listallhardwareports"], timeout=8)
    return parse_hardware_ports(result.output) if result.ok else {}


async def _macos_interfaces() -> tuple[list[dict], str]:
    if not have("ifconfig"):
        return [], "unavailable"
    result = await run(["ifconfig", "-a"], timeout=10)
    found = parse_ifconfig_bsd(result.output) if result.ok else []
    if not found:
        return [], "unavailable"
    ports, route = await asyncio.gather(macos_hardware_ports(), macos_default_route())
    for iface in found:
        port = ports.get(iface["name"])
        if port:
            iface["kind"] = port_kind(port) or iface["kind"]
            iface["description"] = port
        iface["default_route"] = iface["name"] == route.get("interface")
    return found, "ifconfig"


def parse_netstat_ib(text: str) -> dict[str, dict]:
    """{interface: counters} from macOS's `netstat -ibn`, in /proc/net/dev's
    terms. Only each interface's <Link#n> row carries its totals."""
    counters: dict[str, dict] = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 9 or not parts[2].startswith("<Link#"):
            continue
        name = parts[0].rstrip("*")         # a trailing * marks a down interface
        values = parts[3:]
        if values and ":" in values[0]:     # the link-layer address, when it has one
            values = values[1:]
        try:
            numbers = [int(v) for v in values[:7]]
        except ValueError:
            continue
        if len(numbers) < 6 or name in counters:
            continue
        ipkts, ierrs, ibytes, opkts, oerrs, obytes = numbers[:6]
        entry = dict.fromkeys(COUNTER_FIELDS, 0)
        entry.update(rx_packets=ipkts, rx_errs=ierrs, rx_bytes=ibytes,
                     tx_packets=opkts, tx_errs=oerrs, tx_bytes=obytes,
                     tx_colls=numbers[6] if len(numbers) > 6 else 0)
        counters[name] = entry
    return counters


def _macos_counters() -> dict[str, dict]:
    try:
        done = subprocess.run(["netstat", "-ibn"], capture_output=True, timeout=4)
    except (OSError, subprocess.SubprocessError):
        return {}
    return parse_netstat_ib(hostos.decode(done.stdout))
