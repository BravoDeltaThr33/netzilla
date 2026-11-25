"""Local network interfaces: what exists, and how fast each one is moving.

Interfaces are enumerated with iproute2 (`ip -o link show` / `ip -o addr show`)
because net-tools' ifconfig is no longer installed by default on Ubuntu, Mint
or Debian. If ifconfig happens to be present and ip is not, its output is
parsed as a fallback; failing both, /proc/net/dev at least yields the names.

LIVE RATES is netzilla's own stand-in for nload: nload has no batch mode and
cannot be embedded in a Textual pane, so instead of shelling out to it,
/proc/net/dev is sampled twice a few seconds apart and the deltas are turned
into per-interface Mbit/s, packets/s and error counts — the same two-sample
technique the LAN tab already uses for SNMP interface rates.

Every parser here is a pure function over command output, so the whole module
is unit-testable without a network, root, or any of the tools installed.
"""

from __future__ import annotations

import asyncio
import re
import time

from .runner import have, run

PROC_NET_DEV = "/proc/net/dev"

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
    if name == "lo" or "LOOPBACK" in flags:
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
    try:
        with open(PROC_NET_DEV, "r", encoding="utf-8", errors="replace") as handle:
            return parse_proc_net_dev(handle.read())
    except OSError:
        return {}


def rates_between(first: dict, second: dict, seconds: float) -> list[dict]:
    """Per-interface throughput from two /proc/net/dev samples."""
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
    """Two /proc/net/dev samples `seconds` apart -> live per-interface rates."""
    first = read_counters()
    if not first:
        return []
    started = time.monotonic()
    remaining = seconds
    while remaining > 0:
        if progress:
            progress(f"Sampling /proc/net/dev — {remaining:.0f}s to go…")
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
