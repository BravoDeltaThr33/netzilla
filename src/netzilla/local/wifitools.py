"""Wi-Fi troubleshooting, netscanner-style.

netscanner puts the whole "what is going on with my Wi-Fi" picture in one
place: the networks on the air with live signal bars and graphs, your own
link, the devices on the Wi-Fi you are joined to and their open ports, the
packets crossing your interface, and traffic counts with the DNS names behind
them — all exportable to CSV. This module is the logic behind the WIFI tab's
versions of those, kept as pure functions and small state-keeping classes
over tool output, so all of it can be tested without a radio:

  iw dev <if> link           which AP you are on, frequency, signal, bitrates
  iw dev <if> station dump   retries, failures, beacon loss, connected time
  nmcli device show <if>     addresses, gateway and DNS for that interface
  /proc/net/dev              bytes in and out of the wireless interface
  ss                         this machine's own connections over the Wi-Fi
  tshark (Info column)       packets, and the DNS names looked up

Several of these views also exist on other tabs (LAN, FLOW, CAPTURE, INT).
The WIFI tab reuses those tabs' own code rather than a second copy — it just
points them at the wireless interface and its subnet, so everything needed
for a Wi-Fi problem is in one place.

netscanner itself runs as root and speaks raw sockets. netzilla gets the same
answers without root wherever it can (nmcli, iw link, ping, the neighbour
table, TCP connect, /proc, ss) and only needs privilege to capture packets,
through the same one-time session the CAPTURE tab uses.
"""

from __future__ import annotations

import csv
import ipaddress
import math
import re
import time
from pathlib import Path

from . import devices, netif, wifi
from .runner import have, run


# ================================================================ the link
def _kv_lines(text: str) -> dict[str, str]:
    """'key: value' lines (tab- or space-indented) -> {key: value}."""
    found: dict[str, str] = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, _, value = line.strip().partition(":")
        found.setdefault(key.strip().lower(), value.strip())
    return found


def _num(text: str, cast=float):
    match = re.search(r"-?\d+(?:\.\d+)?", text or "")
    if not match:
        return None
    try:
        return cast(float(match.group(0)))
    except ValueError:
        return None


def parse_iw_link(text: str) -> dict:
    """`iw dev <if> link` -> {connected, bssid, ssid, freq, channel, band,
    signal_dbm, rx_bitrate, tx_bitrate, rx_bytes, tx_bytes}."""
    text = text or ""
    head = re.search(r"Connected to ([0-9a-fA-F:]{17})", text)
    if not head:
        return {"connected": False}
    fields = _kv_lines(text)
    freq = _num(fields.get("freq", ""), int) or 0
    return {
        "connected": True,
        "bssid": head.group(1).lower(),
        "ssid": fields.get("ssid", ""),
        "freq": freq,
        "channel": wifi.channel_of(freq) if freq else 0,
        "band": wifi.band_of(freq) if freq else "",
        "signal_dbm": _num(fields.get("signal", ""), int),
        "rx_bitrate": _rate(fields.get("rx bitrate", "")),
        "tx_bitrate": _rate(fields.get("tx bitrate", "")),
        "rx_bytes": _num(fields.get("rx", ""), int),
        "tx_bytes": _num(fields.get("tx", ""), int),
        "width": _width(fields.get("rx bitrate", "") + " " + fields.get("tx bitrate", "")),
    }


def _rate(text: str) -> float | None:
    return _num(text.split("MBit")[0], float) if "MBit" in (text or "") else None


def _width(text: str) -> str:
    match = re.search(r"(\d+)\s*MHz", text or "")
    return f"{match.group(1)} MHz" if match else ""


def parse_station_dump(text: str) -> dict:
    """The counters that say whether a link is healthy, from
    `iw dev <if> station dump` (the AP you are associated with)."""
    fields = _kv_lines(text)
    if not fields:
        return {}
    keys = {
        "tx_packets": "tx packets", "tx_retries": "tx retries",
        "tx_failed": "tx failed", "rx_packets": "rx packets",
        "beacon_loss": "beacon loss", "rx_drop_misc": "rx drop misc",
        "connected_s": "connected time", "inactive_ms": "inactive time",
    }
    out: dict = {name: _num(fields.get(key, ""), int) for name, key in keys.items()}
    out["signal_avg"] = _num(fields.get("signal avg", ""), int)
    out["expected_mbps"] = _num(fields.get("expected throughput", ""), float)
    return out


def retry_rate(station: dict) -> float | None:
    """Share of transmitted frames that had to be sent again, in percent."""
    sent, retries = station.get("tx_packets"), station.get("tx_retries")
    if not sent or retries is None:
        return None
    return 100.0 * retries / (sent + retries)


def parse_nmcli_device_show(text: str) -> dict:
    """`nmcli -t device show <if>` -> {connection, ipv4[], gateway, dns[],
    ipv6[], hwaddr, state}."""
    info: dict = {"ipv4": [], "ipv6": [], "dns": []}
    for line in (text or "").splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        value = value.replace("\\:", ":").strip()
        key = key.strip().upper()
        if not value or value == "--":
            continue
        if key.startswith("IP4.ADDRESS"):
            info["ipv4"].append(value)
        elif key.startswith("IP6.ADDRESS"):
            info["ipv6"].append(value)
        elif key.startswith("IP4.DNS") or key.startswith("IP6.DNS"):
            info["dns"].append(value)
        elif key == "IP4.GATEWAY":
            info["gateway"] = value
        elif key == "GENERAL.CONNECTION":
            info["connection"] = value
        elif key == "GENERAL.HWADDR":
            info["hwaddr"] = value.lower()
        elif key == "GENERAL.STATE":
            info["state"] = value
    return info


async def link_info(iface: str) -> dict:
    """Everything about the current Wi-Fi association. No root needed."""
    info: dict = {"iface": iface, "link": {"connected": False}, "station": {},
                  "device": {}, "sources": []}
    if not iface:
        return info
    if have("iw"):
        link = await run(["iw", "dev", iface, "link"], timeout=8, ok_returncodes=(0, 1))
        info["link"] = parse_iw_link(link.output)
        if info["link"].get("connected"):
            info["sources"].append("iw link")
            dump = await run(["iw", "dev", iface, "station", "dump"], timeout=8,
                             ok_returncodes=(0, 1))
            info["station"] = parse_station_dump(dump.output)
    if have("nmcli"):
        shown = await run(["nmcli", "-t", "device", "show", iface], timeout=8,
                          ok_returncodes=(0, 1, 10))
        info["device"] = parse_nmcli_device_show(shown.output)
        if info["device"].get("state"):
            info["sources"].append("nmcli")
    return info


async def link_now(iface: str) -> dict:
    """Just `iw dev <if> link` — the signal of the AP you're joined to, as the
    driver has it right now. One quick command, for views that read it every
    tick."""
    if not iface or not have("iw"):
        return {"connected": False}
    result = await run(["iw", "dev", iface, "link"], timeout=5, ok_returncodes=(0, 1))
    return parse_iw_link(result.output)


def link_rows(info: dict, ap: dict | None = None, vendor: str = "") -> list[tuple[str, object]]:
    link, station, device = info.get("link", {}), info.get("station", {}), info.get("device", {})
    ap = ap or {}
    signal = link.get("signal_dbm")
    if signal is None:
        signal = ap.get("signal_dbm")
    rate = retry_rate(station)
    rows: list[tuple[str, object]] = [
        ("SSID", link.get("ssid") or ap.get("ssid") or device.get("connection") or "—"),
        ("Access point", (link.get("bssid") or ap.get("bssid") or "—")
         + (f"  ({vendor})" if vendor else "")),
        ("Channel / band", _channel_text(link, ap)),
        ("Signal", f"{signal} dBm — {wifi.signal_label(signal)}" if signal is not None else "—"),
        ("Link rate", _rates(link)),
        ("Security", ap.get("security") or "—"),
    ]
    if station:
        rows += [
            ("Retransmitted", f"{rate:.1f}% of frames" if rate is not None else "—"),
            ("Failed to send", station.get("tx_failed") if station.get("tx_failed") is not None else "—"),
            ("Beacons missed", station.get("beacon_loss") if station.get("beacon_loss") is not None else "—"),
            ("Connected for", _duration(station.get("connected_s"))),
        ]
        if station.get("expected_mbps"):
            rows.append(("Expected throughput", f"{station['expected_mbps']:.0f} Mbit/s"))
    rows += [
        ("IPv4", ", ".join(device.get("ipv4", [])) or "—"),
        ("IPv6", ", ".join(device.get("ipv6", [])[:2]) or "—"),
        ("Gateway", device.get("gateway") or "—"),
        ("DNS", ", ".join(device.get("dns", [])[:3]) or "—"),
    ]
    return rows


def _channel_text(link: dict, ap: dict) -> str:
    channel = link.get("channel") or ap.get("channel")
    band = link.get("band") or ap.get("band")
    if not channel:
        return "—"
    extra = []
    if link.get("freq"):
        extra.append(f"{link['freq']} MHz")
    if link.get("width"):
        extra.append(f"{link['width']} wide")
    return f"{channel} · {band}" + (f"  ({', '.join(extra)})" if extra else "")


def _rates(link: dict) -> str:
    rx, tx = link.get("rx_bitrate"), link.get("tx_bitrate")
    if rx is None and tx is None:
        return "—"
    return f"down {rx:.0f} / up {tx:.0f} Mbit/s" if rx is not None and tx is not None else (
        f"{(rx or tx):.0f} Mbit/s")


def _duration(seconds) -> str:
    if seconds is None:
        return "—"
    hours, rest = divmod(int(seconds), 3600)
    minutes = rest // 60
    return f"{hours}h {minutes:02d}m" if hours else f"{minutes}m {int(seconds) % 60:02d}s"


def link_advice(info: dict, ap: dict | None, aps: list[dict]) -> list[tuple[str, str]]:
    """(state, sentence) findings about the link — what a person would
    check first when "the Wi-Fi is slow"."""
    link, station = info.get("link", {}), info.get("station", {})
    ap = ap or {}
    findings: list[tuple[str, str]] = []
    if not link.get("connected") and not ap:
        return [("warn", "Not associated with any access point.")]
    signal = link.get("signal_dbm") if link.get("signal_dbm") is not None else ap.get("signal_dbm")
    if signal is not None:
        if signal >= -60:
            findings.append(("ok", f"Signal is {wifi.signal_label(signal)} ({signal} dBm)."))
        elif signal >= -70:
            findings.append(("warn", f"Signal is only {wifi.signal_label(signal)} ({signal} dBm) — "
                                     "fine for browsing, marginal for calls and streaming."))
        else:
            findings.append(("bad", f"Signal is {wifi.signal_label(signal)} ({signal} dBm). Move closer "
                                    "to the access point, or add one nearer this spot."))
    rate = retry_rate(station)
    if rate is not None:
        if rate > 15:
            findings.append(("bad", f"{rate:.0f}% of frames had to be sent again — heavy interference "
                                    "or a weak link. Check CHANNELS for a quieter channel."))
        elif rate > 8:
            findings.append(("warn", f"{rate:.0f}% of frames were retransmitted — some interference."))
        else:
            findings.append(("ok", f"Retransmissions are low ({rate:.1f}%)."))
    if station.get("beacon_loss"):
        findings.append(("warn", f"{station['beacon_loss']} beacons missed — the link has dropped "
                                 "out briefly."))
    channel = link.get("channel") or ap.get("channel")
    band = link.get("band") or ap.get("band")
    mine = link.get("bssid") or ap.get("bssid")
    if channel and band == "2.4 GHz":
        same = [a for a in aps
                if a.get("band") == "2.4 GHz" and a.get("bssid") != mine
                and a.get("channel")
                and (a["channel"] == channel or wifi.overlaps_24(a["channel"], channel))]
        if same:
            findings.append(("warn", f"{len(same)} other network(s) share or overlap channel "
                                     f"{channel}. CHANNELS suggests a better one."))
        ssid = link.get("ssid") or ap.get("ssid")
        if any(a.get("ssid") == ssid and a.get("band") in ("5 GHz", "6 GHz") for a in aps):
            findings.append(("info", f"'{ssid}' is also on 5/6 GHz — faster and less crowded "
                                     "when you are near the router."))
    elif channel:
        same = [a for a in aps if a.get("channel") == channel and a.get("bssid") != mine]
        if same:
            findings.append(("info", f"{len(same)} other network(s) on channel {channel}."))
    if (ap.get("security") or "").lower() in ("open", "wep", "wpa"):
        findings.append(("bad", f"This network uses {ap['security']} — weak or no encryption. "
                                "Use WPA2 or WPA3."))
    return findings


_ADVICE_LABEL = {"bad": "PROBLEM", "warn": "CHECK", "info": "INFO", "ok": "OK"}


def advice_rows(findings: list[tuple[str, str]]) -> list[list[object]]:
    return [[_ADVICE_LABEL.get(state, state.upper()), text] for state, text in findings]


def interface_rows(found: list[dict], wifi_iface: str = "") -> list[list[object]]:
    """netscanner's Interfaces pane: name, kind, MAC, IPv4, IPv6."""
    rows = []
    for iface in found:
        addresses = iface.get("addresses") or []
        v4 = [a for a in addresses if ":" not in a]
        v6 = [a for a in addresses if ":" in a]
        rows.append([
            ("* " if iface["name"] == wifi_iface else "") + iface["name"],
            iface.get("kind", ""),
            iface.get("state", ""),
            iface.get("mac") or "—",
            ", ".join(v4) or "—",
            ", ".join(v6[:2]) or "—",
        ])
    return rows


# ========================================================== watching the air
def signal_bar(dbm, width: int = 10) -> str:
    """-30 dBm fills the bar, -90 leaves it empty."""
    if dbm is None:
        return "·" * width
    filled = max(0, min(width, round((float(dbm) + 90) / 60 * width)))
    return "█" * filled + "·" * (width - filled)


class AirWatch:
    """Networks seen across repeated scans: first and last seen, and a
    signal history per BSSID — netscanner's WiFi Networks pane and graph.
    HISTORY is enough to fill a wide terminal's graph: at LIVE AIR's pace of
    one sample every two seconds, eight minutes of the air."""

    HISTORY = 240
    # Two reads of the same cached result can differ by the time it took to
    # read them; real scans are seconds apart.
    SAME_READING = 0.25
    # dB a network's signal must move before it changes place in the list,
    # so rows don't swap on every flicker of a reading.
    STEADY = 3

    def __init__(self, gone_after: float = 20.0) -> None:
        self.gone_after = gone_after
        self.seen: dict[str, dict] = {}
        self.scans = 0

    @staticmethod
    def key_of(ap: dict) -> str:
        return ap.get("bssid") or f"{ap.get('ssid')}/{ap.get('channel')}"

    def update(self, aps: list[dict], now: float | None = None) -> None:
        now = time.time() if now is None else now
        self.scans += 1
        for ap in aps:
            key = self.key_of(ap)
            entry = self.seen.get(key)
            if entry is None:
                entry = self.seen[key] = {"first_seen": now, "history": [], "key": key,
                                          "level": None}
            # seen_at: when the radio actually heard this AP (a cached scan
            # result carries its age). The same result read again on the next
            # tick is not a new reading, so it isn't added to the history
            # twice; with no age known (NetworkManager), every read counts.
            seen_at = ap.get("seen_at")
            fresh = (seen_at is None or entry.get("seen_at") is None
                     or abs(seen_at - entry["seen_at"]) > self.SAME_READING)
            entry.update(
                ssid=ap.get("ssid", ""), bssid=ap.get("bssid", ""),
                channel=ap.get("channel", 0), band=ap.get("band", ""),
                security=ap.get("security", ""), signal_dbm=ap.get("signal_dbm"),
                in_use=bool(ap.get("in_use")),
                last_seen=seen_at if seen_at is not None else now,
            )
            if fresh:
                entry["seen_at"] = seen_at
                entry["history"].append(ap.get("signal_dbm"))
                del entry["history"][:-self.HISTORY]
            signal = ap.get("signal_dbm")
            if signal is not None and (entry.get("level") is None
                                       or abs(signal - entry["level"]) >= self.STEADY):
                entry["level"] = signal

    def present(self, now: float | None = None) -> list[dict]:
        """On the air now, strongest first — by each network's steady level,
        so two at much the same strength keep their order."""
        now = time.time() if now is None else now
        live = [e for e in self.seen.values() if now - e["last_seen"] <= self.gone_after]

        def strength(entry: dict) -> float:
            level = entry.get("level")
            if level is None:
                level = entry.get("signal_dbm")
            return level if level is not None else -999

        return sorted(live, key=lambda e: (-strength(e), e.get("first_seen", 0)))

    def get(self, key: str) -> dict | None:
        """A network by its key (BSSID) — a BSSID typed any way matches."""
        if not key:
            return None
        entry = self.seen.get(key)
        if entry is not None:
            return entry
        wanted = wifi.bssid_key(key)
        if wanted:
            for entry in self.seen.values():
                if wifi.bssid_key(entry.get("bssid") or "") == wanted:
                    return entry
        return None

    def ordered(self, now: float | None = None, limit: int = 24) -> list[dict]:
        """LIVE AIR's rows: on the air, strongest first, then — until the
        table fills — the ones that dropped off it, most recent first."""
        rows = self.present(now)[:limit]
        return rows + self.gone(now)[: max(0, limit - len(rows))]

    def gone(self, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        old = [e for e in self.seen.values() if now - e["last_seen"] > self.gone_after]
        return sorted(old, key=lambda e: e["last_seen"], reverse=True)

    def rows(self, now: float | None = None, vendor=None) -> list[list[object]]:
        rows = []
        for entry in self.present(now):
            rows.append(self._row(entry, vendor, live=True))
        for entry in self.gone(now):
            rows.append(self._row(entry, vendor, live=False))
        return rows

    @staticmethod
    def _row(entry: dict, vendor, live: bool) -> list[object]:
        signal = entry.get("signal_dbm")
        return [
            time.strftime("%H:%M:%S", time.localtime(entry["last_seen"])),
            ("* " if entry.get("in_use") else "") + (entry.get("ssid") or "<hidden>"),
            entry.get("channel") or "—",
            entry.get("band") or "—",
            entry.get("bssid") or "—",
            vendor(entry.get("bssid", "")) if vendor else "",
            (f"{signal:>4} {signal_bar(signal)}" if live and signal is not None
             else "gone"),
            entry.get("security") or "—",
        ]

    def graph_rows(self, limit: int = 10, now: float | None = None) -> list[list[object]]:
        rows = []
        for entry in self.present(now)[:limit]:
            history = [v for v in entry["history"] if v is not None]
            if not history:
                continue
            rows.append([
                (entry.get("ssid") or "<hidden>")[:22],
                entry.get("channel") or "—",
                wifi.sparkline(history[-40:]),
                f"{min(history)} / {max(history)}",
                f"{history[-1]}",
            ])
        return rows

    def live_rows(self, now: float | None = None, vendor=None, limit: int = 24,
                  values: int = 10) -> list[list[object]]:
        """LIVE_COLUMNS rows: every network on the air with its signal bar
        and its last `values` readings in dBm, strongest first; ones that
        dropped off the air stay at the bottom, marked gone, until the table
        fills."""
        now = time.time() if now is None else now
        return [self.live_row(entry, vendor, values, self.on_air(entry, now))
                for entry in self.ordered(now, limit)]

    def on_air(self, entry: dict, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return now - entry["last_seen"] <= self.gone_after

    @staticmethod
    def live_row(entry: dict, vendor, values: int, live: bool) -> list[object]:
        history = [v for v in entry["history"] if v is not None]
        signal = entry.get("signal_dbm")
        return [
            ("* " if entry.get("in_use") else "") + (entry.get("ssid") or "<hidden>")[:24],
            entry.get("channel") or "—",
            entry.get("band") or "—",
            (vendor(entry.get("bssid", "")) if vendor else entry.get("bssid")) or "—",
            (f"{signal}" if signal is not None else "—") if live else "gone",
            signal_bar(signal if live else None),
            history_text(history, values),
            range_text(history),
            entry.get("security") or "—",
        ]

    def focus(self, target: str = "", now: float | None = None) -> dict | None:
        """The network to draw the big graph for: the one named, else the one
        this machine is joined to, else the strongest."""
        present = self.present(now)
        if not present:
            return None
        if target:
            wanted = target.strip().lower()
            wanted_bssid = wifi.bssid_key(target)
            for entry in present:
                if wanted_bssid and wifi.bssid_key(entry.get("bssid") or "") == wanted_bssid:
                    return entry
                if wanted == (entry.get("ssid") or "").lower():
                    return entry
        for entry in present:
            if entry.get("in_use"):
                return entry
        return present[0]

    def summary(self, now: float | None = None) -> list[tuple[str, object]]:
        present = self.present(now)
        bands: dict[str, int] = {}
        for entry in present:
            bands[entry.get("band") or "?"] = bands.get(entry.get("band") or "?", 0) + 1
        return [
            ("Scans", self.scans),
            ("On the air now", len(present)),
            ("Seen, now gone", len(self.gone(now))),
            ("By band", ", ".join(f"{k}: {v}" for k, v in sorted(bands.items())) or "—"),
        ]

    def export(self) -> tuple[list[str], list[list[object]]]:
        columns = ["first_seen", "last_seen", "ssid", "bssid", "channel", "band",
                   "last_signal_dbm", "min_dbm", "max_dbm", "security"]
        rows = []
        for entry in self.seen.values():
            history = [v for v in entry["history"] if v is not None]
            rows.append([
                _iso(entry["first_seen"]), _iso(entry["last_seen"]),
                entry.get("ssid", ""), entry.get("bssid", ""), entry.get("channel", ""),
                entry.get("band", ""), entry.get("signal_dbm", ""),
                min(history) if history else "", max(history) if history else "",
                entry.get("security", ""),
            ])
        return columns, rows


LIVE_COLUMNS = ["SSID", "Ch", "Band", "AP vendor", "dBm", "Signal", "History",
                "Range", "Security"]


def network_rows(entry: dict, others: list[dict], vendor=None,
                 now: float | None = None) -> list[tuple[str, object]]:
    """Everything known about one network, for LIVE AIR when it shows only
    that network: who made the AP, its channel, its signal over the run, and
    which other networks share or overlap its channel."""
    now = time.time() if now is None else now
    history = [v for v in entry.get("history", []) if v is not None]
    signal = entry.get("signal_dbm")
    bssid = entry.get("bssid") or ""
    band, channel = entry.get("band") or "", entry.get("channel") or 0
    rows: list[tuple[str, object]] = [
        ("Network", (entry.get("ssid") or "<hidden>")
         + ("  · the one you're joined to" if entry.get("in_use") else "")),
        ("BSSID", f"{bssid}  ({vendor(bssid)})" if vendor and bssid else bssid or "—"),
        ("Channel / band", f"{channel or '—'} · {band or '—'}"),
        ("Security", entry.get("security") or "—"),
        ("Signal now", f"{signal} dBm ({wifi.signal_label(signal)})" if signal is not None
         else "—"),
    ]
    if history:
        rows.append(("Lowest / average / highest",
                     f"{min(history)} / {sum(history) / len(history):.0f} / {max(history)} dBm"
                     f"  ({len(history)} readings)"))
    rows.append(("First seen", time.strftime("%H:%M:%S", time.localtime(entry["first_seen"]))))
    age = max(0.0, now - entry.get("last_seen", now))
    rows.append(("Last heard", "now" if age < 3 else f"{age:.0f}s ago"))

    def name(other: dict) -> str:
        label = other.get("ssid") or "<hidden>"
        return f"{label} ({other['signal_dbm']} dBm)" if other.get("signal_dbm") is not None else label

    neighbours = [o for o in others if o is not entry and o.get("band") == band
                  and o.get("channel")]
    same = [o for o in neighbours if o.get("channel") == channel]
    rows.append(("Sharing its channel", ", ".join(name(o) for o in same[:6])
                 + (f" … +{len(same) - 6}" if len(same) > 6 else "") if same else "none"))
    if band == "2.4 GHz" and channel:
        near = [o for o in neighbours if wifi.overlaps_24(int(channel), int(o["channel"]))]
        rows.append(("Overlapping its channel", ", ".join(
            f"{name(o)} on {o['channel']}" for o in near[:6])
            + (f" … +{len(near) - 6}" if len(near) > 6 else "") if near else "none"))
    return rows


def _iso(stamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stamp))


# ================================================================== charts
_EIGHTHS = " ▁▂▃▄▅▆▇█"


def nice_ceiling(value: float) -> float:
    """The next round number at or above value: 0.7 -> 1, 3.2 -> 4, 17 -> 20."""
    if value <= 0:
        return 1.0
    scale = 10 ** math.floor(math.log10(value))
    for step in (1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10):
        if value <= step * scale + 1e-9:
            return step * scale
    return 10 * scale


def chart_lines(values, *, height: int = 8, width: int = 60,
                floor: float = -90.0, ceil: float = -30.0,
                label=lambda v: f"{v:.0f}", align: str = "right") -> list[str]:
    """A block chart, newest sample on the right, `height` rows tall.

    Each column is one sample, drawn in eighths of a row so small changes
    still show. Fewer samples than `width` are padded on the left, so a new
    run fills in from the right and then scrolls — the live-feed look
    (align="left" pads on the right instead: a run that fills in from the
    left, like a speed test's fixed time axis). The y axis is labelled at the
    top, middle and bottom rows.
    """
    shown = [v for v in values if v is not None][-width:]
    height = max(2, int(height))
    span = (ceil - floor) or 1.0
    levels = []
    for value in shown:
        level = round((float(value) - floor) / span * height * 8)
        level = max(0, min(height * 8, level))
        if value > floor and level == 0:
            level = 1                      # anything above the floor shows
        levels.append(level)
    pad = width - len(levels)
    labels = {0: label(ceil), height // 2: label((ceil + floor) / 2),
              height - 1: label(floor)}
    gutter = max(len(text) for text in labels.values())
    lines = []
    for row in range(height):
        base = (height - 1 - row) * 8
        cells = []
        for level in levels:
            part = level - base
            cells.append("█" if part >= 8 else " " if part <= 0 else _EIGHTHS[part])
        tag = labels.get(row, "")
        if align == "left":
            lines.append(f"{tag:>{gutter}} ┤" + "".join(cells) + " " * pad)
        else:
            lines.append(f"{tag:>{gutter}} ┤" + " " * pad + "".join(cells))
    lines.append(" " * gutter + " └" + "─" * width)
    return lines


def history_text(history, count: int = 10) -> str:
    """HISTORY: the last `count` readings in dBm, oldest first, newest on the
    right, one space apart — "-52 -51 -50 -53"."""
    readings = [v for v in history if v is not None][-count:]
    return " ".join(str(int(round(v))) for v in readings) or "—"


def range_text(history) -> str:
    """RANGE: the weakest and strongest reading, "-62 / -48"."""
    readings = [v for v in history if v is not None]
    return f"{min(readings)} / {max(readings)}" if readings else "—"


def signal_chart(history, width: int = 60, height: int = 8) -> list[str]:
    return chart_lines(history, width=width, height=height, floor=-90, ceil=-30,
                       label=lambda v: f"{v:.0f} dBm")


def rate_chart(history, width: int = 60, height: int = 6) -> list[str]:
    peak = nice_ceiling(max([v for v in history if v is not None] or [0.0]))
    return chart_lines(history, width=width, height=height, floor=0.0, ceil=peak,
                       label=lambda v: f"{round(v, 2):g} Mb/s")


def signal_state(dbm) -> str:
    """ok / warn / bad for colouring a signal reading."""
    if dbm is None:
        return "info"
    return "ok" if dbm >= -67 else "warn" if dbm >= -75 else "bad"


# ============================================================= link, live
class LinkWatch:
    """The link sampled over and over: signal and bitrate history, and the
    retry rate over each interval rather than since the association began —
    a burst of interference shows up as it happens instead of being averaged
    away by hours of good traffic."""

    HISTORY = 240

    def __init__(self) -> None:
        self.samples: list[dict] = []
        self.signal: list = []
        self.rx: list = []
        self.tx: list = []
        self.retry: list = []
        self.beacons_lost = 0
        self.roams: list[tuple[float, str, str]] = []
        self._station: dict | None = None
        self._bssid = ""

    def update(self, info: dict, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        link, station = info.get("link", {}), info.get("station", {})
        sample = {
            "time": now,
            "bssid": link.get("bssid", ""),
            "signal": link.get("signal_dbm"),
            "rx": link.get("rx_bitrate"),
            "tx": link.get("tx_bitrate"),
            "retry": None,
        }
        previous = self._station
        if previous and station:
            sent = _delta(previous, station, "tx_packets")
            retried = _delta(previous, station, "tx_retries")
            if sent is not None and retried is not None and sent + retried > 0:
                sample["retry"] = 100.0 * retried / (sent + retried)
            lost = _delta(previous, station, "beacon_loss")
            if lost:
                self.beacons_lost += lost
        if station:
            self._station = station
        bssid = sample["bssid"]
        if bssid and self._bssid and bssid != self._bssid:
            self.roams.append((now, self._bssid, bssid))
            self._station = station or None    # new AP, new counters
        if bssid:
            self._bssid = bssid
        self.samples.append(sample)
        del self.samples[:-self.HISTORY]
        for name in ("signal", "rx", "tx", "retry"):
            series = getattr(self, name)
            series.append(sample[name])
            del series[:-self.HISTORY]
        return sample

    def rows(self) -> list[tuple[str, object]]:
        signal = [v for v in self.signal if v is not None]
        rx = [v for v in self.rx if v is not None]
        tx = [v for v in self.tx if v is not None]
        retry = [v for v in self.retry if v is not None]
        rows: list[tuple[str, object]] = [("Samples", len(self.samples))]
        if signal:
            rows.append(("Signal now / avg / worst",
                         f"{signal[-1]} / {sum(signal) / len(signal):.0f} / {min(signal)} dBm"))
        if rx or tx:
            rows.append(("Bitrate now  down / up",
                         f"{rx[-1] if rx else 0:.0f} / {tx[-1] if tx else 0:.0f} Mbit/s"))
        if retry:
            rows.append(("Retries, last interval / worst",
                         f"{retry[-1]:.1f}% / {max(retry):.1f}%"))
        rows.append(("Beacons missed while watching", self.beacons_lost))
        rows.append(("Roamed to another AP",
                     f"{len(self.roams)}× — last to {self.roams[-1][2]}" if self.roams else "no"))
        return rows

    def export(self) -> tuple[list[str], list[list[object]]]:
        return (["time", "bssid", "signal_dbm", "rx_mbps", "tx_mbps", "retry_pct"],
                [[_iso(s["time"]), s["bssid"], s["signal"], s["rx"], s["tx"],
                  "" if s["retry"] is None else f"{s['retry']:.2f}"] for s in self.samples])


def _delta(before: dict, after: dict, key: str):
    """Counter growth between two readings; None when a counter went
    backwards (the driver reset it on reconnect) or is missing."""
    a, b = before.get(key), after.get(key)
    if a is None or b is None or b < a:
        return None
    return b - a


# ======================================================= traffic, live
class RateWatch:
    """One interface's throughput from successive /proc/net/dev readings —
    the INT tab's arithmetic (netif.rates_between), kept as a history."""

    HISTORY = 240

    def __init__(self, iface: str) -> None:
        self.iface = iface
        self.down: list[float] = []
        self.up: list[float] = []
        self.samples: list[dict] = []
        self.total_down = 0
        self.total_up = 0
        self.errors = 0
        self.drops = 0
        self._last: dict | None = None
        self._last_at = 0.0

    def update(self, counters: dict, now: float | None = None) -> dict | None:
        now = time.monotonic() if now is None else now
        current = counters.get(self.iface)
        if current is None:
            return None
        previous, previous_at = self._last, self._last_at
        self._last, self._last_at = current, now
        if previous is None:
            return None
        rates = netif.rates_between({self.iface: previous}, {self.iface: current},
                                    now - previous_at)
        if not rates:
            return None
        rate = rates[0]
        self.down.append(rate["rx_mbps"])
        self.up.append(rate["tx_mbps"])
        del self.down[:-self.HISTORY]
        del self.up[:-self.HISTORY]
        self.total_down += rate["rx_bytes"]
        self.total_up += rate["tx_bytes"]
        self.errors += rate["errors"]
        self.drops += rate["drops"]
        self.samples.append({"time": time.time(), **rate})
        del self.samples[:-self.HISTORY]
        return rate

    def rows(self) -> list[tuple[str, object]]:
        if not self.down:
            return [("Interface", self.iface), ("Status", "waiting for a second reading…")]
        return [
            ("Interface", self.iface),
            ("Down now / peak", f"{self.down[-1]:.2f} / {max(self.down):.2f} Mbit/s"),
            ("Up now / peak", f"{self.up[-1]:.2f} / {max(self.up):.2f} Mbit/s"),
            ("Moved while watching",
             f"{netif.human_bytes(self.total_down)} down · {netif.human_bytes(self.total_up)} up"),
            ("Errors / drops", f"{self.errors} / {self.drops}"),
        ]

    def export(self) -> tuple[list[str], list[list[object]]]:
        return (["time", "down_mbps", "up_mbps", "rx_bytes", "tx_bytes", "errors", "drops"],
                [[_iso(s["time"]), f"{s['rx_mbps']:.3f}", f"{s['tx_mbps']:.3f}",
                  s["rx_bytes"], s["tx_bytes"], s["errors"], s["drops"]] for s in self.samples])


async def iface_addresses(iface: str) -> set[str]:
    """This machine's own IPs on one interface, without prefix lengths."""
    found, _source = await netif.interfaces()
    own: set[str] = set()
    for entry in found:
        if entry.get("name") != iface:
            continue
        for addr in entry.get("addresses") or []:
            try:
                own.add(str(ipaddress.ip_interface(addr).ip))
            except ValueError:
                continue
    return own


def connections_on(conns: list[dict], addresses: set[str]) -> list[dict]:
    """The sockets that actually go over this interface: bound to one of its
    addresses. Listening sockets on 0.0.0.0 belong to every interface and are
    left to the FLOW tab."""
    return [c for c in conns if c.get("local_ip") in addresses]


def talker_rows(hosts: list[dict], names: dict[str, str] | None = None,
                limit: int = 15) -> list[list[object]]:
    """flows.by_remote_host() output as rows, LAN peers named if known."""
    names = names or {}
    rows = []
    for host in hosts[:limit]:
        ip = host["remote_ip"]
        rows.append([
            ip,
            names.get(ip) or ("internet" if host.get("external") else "LAN"),
            host["connections"],
            ", ".join(str(p) for p in host["ports"][:4]),
            ", ".join(host["processes"][:2]) or "—",
        ])
    return rows


# ================================================================== ports
# The ports worth a second look when they turn up open on a home or small-
# office Wi-Fi, and why. Every one is also in devices.PROBE_PORTS, the set the
# LAN tab's IDENTIFY already checks — PORTS runs that same check across every
# device DEVICES found, rather than a separate, wider scan.
WORTH_A_LOOK: dict[int, str] = {
    23: "Telnet sends everything, passwords included, in clear text — turn it off",
    445: "SMB file sharing — expected on a PC or NAS, odd on a TV, plug or camera",
    554: "a camera's video stream — check it needs a password",
    1883: "MQTT without TLS — smart-home messages readable by anyone on the Wi-Fi",
    3389: "Remote Desktop — make sure it is meant to be on",
    5900: "VNC screen sharing — often weakly protected",
}


def port_label(port: int) -> str:
    service = devices.PROBE_PORTS.get(port, ("",))[0]
    return f"{port} {service}".strip()


def port_rows(results: list[dict]) -> list[list[object]]:
    """results: [{ip, name, device, open: [ports]}]."""
    rows = []
    for item in results:
        rows.append([
            item["ip"], item.get("name") or "—", item.get("device") or "—",
            len(item.get("open", [])),
            ", ".join(port_label(p) for p in item.get("open", [])) or "none open",
        ])
    return rows


def port_findings(results: list[dict]) -> list[list[object]]:
    rows = []
    for item in results:
        for port in item.get("open", []):
            if port in WORTH_A_LOOK:
                rows.append([item["ip"], item.get("name") or item.get("device") or "—",
                             port_label(port), WORTH_A_LOOK[port]])
    return rows


# ========================================================= packets + DNS
_DNS_QUERY_RE = re.compile(
    r"^Standard query (?P<id>0x[0-9a-f]+) (?P<qtype>[A-Z0-9]+) (?P<name>\S+)", re.I)
_DNS_REPLY_RE = re.compile(
    r"^Standard query response (?P<id>0x[0-9a-f]+) "
    r"(?:(?P<error>No such name|Server failure|Refused) )?"
    r"(?P<qtype>[A-Z0-9]+) (?P<name>\S+)(?P<rest>.*)$", re.I,
)


def dns_records(packets: list[dict]) -> list[dict]:
    """DNS questions and answers seen in a capture (tshark's Info column).
    [{name, type, queries, answers: [...], cname: [...], error}]"""
    records: dict[tuple[str, str], dict] = {}
    for packet in packets:
        if (packet.get("protocol") or "").upper() not in ("DNS", "MDNS", "LLMNR"):
            continue
        info = packet.get("info", "")
        reply = _DNS_REPLY_RE.match(info)
        query = None if reply else _DNS_QUERY_RE.match(info)
        match = reply or query
        if not match:
            continue
        name = match.group("name").rstrip(",.")
        qtype = match.group("qtype").upper()
        entry = records.setdefault((name.lower(), qtype), {
            "name": name, "type": qtype, "queries": 0, "answers": [],
            "cname": [], "error": "",
        })
        if query:
            entry["queries"] += 1
            continue
        if reply.group("error"):
            entry["error"] = reply.group("error")
        tokens = reply.group("rest").replace(",", " ").split()
        for i, token in enumerate(tokens[:-1]):
            value = tokens[i + 1]
            if token in ("A", "AAAA") and _is_ip(value) and value not in entry["answers"]:
                entry["answers"].append(value)
            elif token == "CNAME" and value not in entry["cname"]:
                entry["cname"].append(value)
    return sorted(records.values(), key=lambda r: (-(r["queries"] or 0), r["name"]))


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def names_from_dns(records: list[dict]) -> dict[str, str]:
    """{ip: name} from the answers seen — so traffic to 142.250.1.2 reads as
    the name that was looked up to reach it."""
    names: dict[str, str] = {}
    for record in records:
        for ip in record["answers"]:
            names.setdefault(ip, record["name"])
    return names


def dns_rows(records: list[dict], limit: int = 40) -> list[list[object]]:
    rows = []
    for record in records[:limit]:
        answer = ", ".join(record["answers"][:3]) + ("…" if len(record["answers"]) > 3 else "")
        rows.append([
            record["name"], record["type"], record["queries"],
            record["error"] or answer or ("→ " + record["cname"][0] if record["cname"] else "—"),
        ])
    return rows


def traffic_by_host(packets: list[dict], own: set[str],
                    names: dict[str, str] | None = None) -> list[dict]:
    """Packets and bytes per remote endpoint, split into in and out relative
    to this machine — netscanner's traffic counting."""
    names = names or {}
    tally: dict[str, dict] = {}
    for packet in packets:
        src, dst = packet.get("src", ""), packet.get("dst", "")
        length = packet.get("length") or 0
        if src in own:
            remote, direction = dst, "out"
        elif dst in own:
            remote, direction = src, "in"
        else:
            remote, direction = src, "other"
        entry = tally.setdefault(remote, {
            "host": remote, "packets": 0, "in": 0, "out": 0, "other": 0,
            "protocols": {}, "name": names.get(remote, ""),
        })
        entry["packets"] += 1
        entry[direction] += length
        proto = packet.get("protocol") or "?"
        entry["protocols"][proto] = entry["protocols"].get(proto, 0) + 1
    rows = list(tally.values())
    rows.sort(key=lambda e: e["in"] + e["out"] + e["other"], reverse=True)
    return rows


def traffic_rows(hosts: list[dict], limit: int = 15) -> list[list[object]]:
    rows = []
    for entry in hosts[:limit]:
        protocols = sorted(entry["protocols"].items(), key=lambda kv: -kv[1])
        rows.append([
            entry["host"], (entry.get("name") or "—")[:36], entry["packets"],
            netif.human_bytes(entry["in"]), netif.human_bytes(entry["out"]),
            ", ".join(p for p, _ in protocols[:3]),
        ])
    return rows


# ============================================================= who's on it
async def iface_subnet(iface: str) -> tuple[str, str]:
    """(cidr, note) for the subnet actually configured on this wireless
    interface — DEVICES sweeps this, not the machine's default route, so it
    still asks about the right network when the Wi-Fi isn't the way this
    machine reaches the internet (a wired uplink, a VPN)."""
    if not iface:
        return "", ""
    found, _source = await netif.interfaces()
    for entry in found:
        if entry.get("name") != iface:
            continue
        for addr in entry.get("addresses") or []:
            try:
                interface = ipaddress.ip_interface(addr)
            except ValueError:
                continue
            if interface.version != 4 or not interface.ip.is_private:
                continue
            if interface.network.num_addresses <= 2:      # point-to-point
                continue
            network = interface.network
            if network.prefixlen < 22:
                narrowed = ipaddress.ip_interface(f"{interface.ip}/24").network
                return str(narrowed), (
                    f"{iface} is on {network}, too big to sweep in one go; "
                    f"swept the /24 around it ({narrowed}) instead."
                )
            return str(network), ""
    return "", ""


# ================================================================ export
def export_dir(base: Path | None = None) -> Path:
    base = base or Path.home() / "netzilla-exports"
    return base / time.strftime("wifi-%Y%m%d-%H%M%S")


def export_csv(directory: Path, datasets: dict[str, tuple[list[str], list[list[object]]]]) -> list[tuple[Path, int]]:
    """Write one CSV per non-empty dataset. Returns [(path, rows)]."""
    written = []
    directory.mkdir(parents=True, exist_ok=True)
    for name, (columns, rows) in datasets.items():
        if not rows:
            continue
        path = directory / f"{name}.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(columns)
            for row in rows:
                writer.writerow(["" if cell is None else str(cell) for cell in row])
        written.append((path, len(rows)))
    return written
