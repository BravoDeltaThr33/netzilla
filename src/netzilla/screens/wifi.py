"""WIFI — RF analysis and Wi-Fi troubleshooting, netscanner-style.

Everything needed for a Wi-Fi problem, in one tab:

  SCAN          every access point in range: maker, band, channel, signal,
                encryption
  LIVE AIR      the same, live: every network's signal bar and scrolling
                history, a big graph of your own network, and 2.4 GHz channel
                load — refreshing on its own until another button is pressed
  CHANNELS      2.4 GHz congestion, counting overlap, and which of 1/6/11 to use
  SIGNAL        one network's signal graphed live, for walking a site
  LINK HEALTH   this machine's own association, live: signal, bitrate,
                retries per interval, missed beacons, roaming
  DEVICES       who else is on this Wi-Fi — the LAN tab's sweep and identify,
                pointed at the subnet this wireless interface is on
  PORTS         the LAN tab's identifying-port check across every device found
  TRAFFIC       live throughput of the wireless interface and this machine's
                connections over it (the INT and FLOW tabs' code)
  PACKETS       live capture on the wireless interface: packet rate, protocols,
                busiest hosts named by the DNS lookups seen (CAPTURE's code and
                permission — unlock once, both tabs are unlocked)
  BLUETOOTH     every Bluetooth device broadcasting nearby, live: its name,
                maker, a best guess at what it is, signal with a history graph,
                rough distance, first and last heard — trackers flagged
  BT TRACKERS   the tracker safety check: item trackers nearby, how long each
                has been near you, and any heard on more than one network you
                have been on (the last seven days are remembered)
  EXPORT        everything gathered so far, as CSV

The live views never need re-running: they keep updating in place until you
press another button, or for as many seconds as the STOP AFTER box says.
In LIVE AIR, BLUETOOTH and BT TRACKERS a row can be picked — click it, or Tab
to the list and use the arrow keys — and the big graph follows it; click it
again (or Enter) and the view shows only that network or device, with
everything known about it (screens/picking.py). SIGNAL watches the network
picked in LIVE AIR when the GRAPH box is empty.
Nothing here associates, deauthenticates or transmits on anyone else's
network — scanning is a passive read of the beacons every AP broadcasts.
Bluetooth scanning listens to broadcasts and never pairs or connects.
"""

from __future__ import annotations

import asyncio
import contextlib
import time

from rich.console import Group
from rich.text import Text
from textual.widgets import Static

from ..local import bluetooth, capture, devices, flows, lan, netif, wifi, wifitools
from ..colours import signal_colour
from ..graphics.charts import LineGraph, SpectrumGraph
from ..local.elevation import SESSION
from ..render import (PanelGrid, block_text, kv_panel, table_panel, text_panel,
                      verdict_line)
from ..validators import ValidationError, valid_network
from .base import Action, Field, LookupPane
from .capture import CaptureAccess
from .picking import PickBar, Picking, PickList, marked, row_styles
from .picking import bar as pick_bar


class WifiPane(Picking, CaptureAccess, LookupPane):
    PANE_TITLE = "WI-FI / RF ANALYSIS"
    DESCRIPTION = (
        "Everything for a Wi-Fi problem in one place, and Bluetooth. SCAN lists "
        "what is on the air; LIVE AIR graphs every network live; CHANNELS picks "
        "the quietest 2.4 GHz channel; SIGNAL graphs one network as you walk; "
        "LINK HEALTH watches your own connection; DEVICES and PORTS show who else "
        "is on it; TRAFFIC and PACKETS show what crosses it. BLUETOOTH lists every "
        "Bluetooth device broadcasting nearby; BT TRACKERS checks for a tracker "
        "that keeps showing up near you. Live views run until you press another "
        "button — click a network or device in one to graph it, click it again to "
        "show only it."
    )
    FIELDS = (
        Field("iface", "Wireless interface", "press TOOL CHECK", choices=(), width=30),
        Field(
            "target", "Graph  (Wi-Fi network or BT device)",
            "blank = yours (Wi-Fi) / nearest (BT)", width=44,
        ),
        Field(
            "filter", "PACKETS filter  (tshark)", "blank = all · e.g. dns",
            width=30,
        ),
        Field("every", "Refresh every (s)", "blank = 3 air · 1 others", width=28),
        Field("secs", "Stop after (s)", "blank = never", width=22),
    )
    ACTIONS = (
        Action("scan", "SCAN"),
        Action("air", "LIVE AIR"),
        Action("channels", "CHANNELS"),
        Action("signal", "SIGNAL"),
        Action("link", "LINK HEALTH"),
        Action("devices", "DEVICES"),
        Action("bluetooth", "BLUETOOTH"),
        # Second row; Bluetooth's two buttons share the right-hand column.
        Action("traffic", "TRAFFIC"),
        Action("packets", "PACKETS"),
        Action("ports", "PORTS", primary=False),
        Action("export", "EXPORT CSV", primary=False),
        Action("iwscan", "DEEP SCAN (iw)", primary=False),
        Action("tools", "TOOL CHECK", primary=False),
        Action("bttrackers", "BT TRACKERS"),
    )

    # How often each live view refreshes, start to start: a scan that takes
    # two seconds is followed by a one-second wait, not a three-second one.
    # LIVE AIR and SIGNAL ask for a fresh scan every tick; iw always does one,
    # and when NetworkManager declines (it rate-limits rescans) its latest
    # list is used, with your own network read from the driver regardless.
    AIR_EVERY = 3.0           # LIVE AIR, SIGNAL — REFRESH EVERY overrides
    # LIVE AIR and SIGNAL read the latest finished scan every tick — that
    # costs nothing — while new scans are requested in the background every
    # REFRESH EVERY seconds, but never more often than this.
    RESCAN_EVERY = 1.0
    HISTORY_VALUES = 10       # readings shown in LIVE AIR's HISTORY column
    LINK_EVERY = 1.0
    TRAFFIC_EVERY = 1.0
    PACKET_REPAINT = 1.0
    # Tests set this to stop a live view after a few ticks; None = no limit.
    MAX_TICKS: int | None = None
    # Packets kept in memory by PACKETS, for its tables and EXPORT.
    PACKET_KEEP = 3000
    EXPORT_BASE = None      # tests point EXPORT somewhere temporary
    # Bluetooth: one history point a second; the table lists this many
    # devices; "where am I" is re-read, and each tracker logged, this often.
    BT_EVERY = 1.0
    BT_ROWS = 40
    BT_PLACE_EVERY = 60.0
    BT_LOG_EVERY = 60.0
    # Tests replace the scanner: a callable(on_advert) -> object with async
    # start() and stop(). None = the real one (bleak).
    BT_SCANNER = None

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._interfaces: list[str] = []
        self._last: list[dict] = []
        self._air = wifitools.AirWatch()
        self._link_watch: wifitools.LinkWatch | None = None
        self._rates: wifitools.RateWatch | None = None
        self._found: list[dict] = []
        self._found_cidr = ""
        self._ports: list[dict] = []
        self._packets: list[dict] = []
        self._dns: list[dict] = []
        self._bt = bluetooth.Watch(oui_lookup=lambda mac: devices.vendor_for(mac)[0])
        self._bt_logged: dict[str, float] = {}
        self._bt_backend = ""
        self._bt_place: bluetooth.Place | None = None
        # One scan at a time: switching BLUETOOTH -> BT TRACKERS waits for the
        # old scan to let go of the radio before the new one starts.
        self._bt_lock = asyncio.Lock()
        # The picked network ("air") and device ("bt"), and redrawing a live
        # view the moment one is picked (screens/picking.py).
        self._init_picking()

    async def on_mount(self) -> None:
        self.run_worker(self._load_interfaces(), group=f"wifi-{id(self)}")

    async def begin(self, message: str = "Working…") -> None:
        self._redraw = None              # the last live view's panels are going
        await super().begin(message)

    def refresh_theme(self) -> None:
        """A new theme or graphics mode: draw the live view in it now, rather
        than at its next refresh (or never, once it has stopped)."""
        self.redraw_live()

    async def _load_interfaces(self) -> list[str]:
        names = await wifi.wireless_interfaces()
        self._interfaces = names
        self.set_choices("iface", names, names[0] if names else None)
        return names

    # ------------------------------------------------------------ dispatch
    async def execute(self, action: str) -> None:
        handler = {
            "scan": lambda: self._scan("auto"),
            "iwscan": lambda: self._scan("iw"),
            "air": self._live_air,
            "channels": self._channels,
            "signal": self._signal,
            "link": self._link,
            "devices": self._devices,
            "ports": self._ports_check,
            "traffic": self._traffic,
            "packets": self._packets_live,
            "export": self._export,
            "tools": self._tools,
            "bluetooth": self._bluetooth,
            "bttrackers": lambda: self._bluetooth(trackers_only=True),
        }.get(action)
        if handler is not None:
            await handler()

    # ------------------------------------------------------------- helpers
    def _panel(self) -> Static:
        """A result panel a live view mounts once and then updates in place."""
        return Static(classes="result-panel")

    def _pick_list(self, family: str) -> PickList:
        """A live list whose rows can be picked ("air" networks, "bt" devices)."""
        return PickList(family)

    def _pick_bar(self, family: str) -> PickBar:
        """The line over a live list saying what is picked."""
        return PickBar(family)

    def _run_state(self, running: bool, elapsed: float) -> str:
        return f"running {self._clock(elapsed)}" if running else f"stopped after {self._clock(elapsed)}"

    def _scroll_home(self) -> None:
        """Live views mount their panels and then update them in place, so
        start at the top where the headline and graph are, whatever the last
        mount scrolled to."""
        try:
            self.results.scroll_home(animate=False)
        except Exception:
            pass

    def _require_iface(self) -> str:
        iface = self.field("iface")
        if not iface:
            raise ValidationError(
                "No wireless interface selected — press TOOL CHECK to list them."
            )
        return iface

    def _limit(self) -> float | None:
        """STOP AFTER, in seconds; None means run until another button."""
        raw = self.field("secs")
        if not raw or raw.strip() in ("0", "-"):
            return None
        try:
            value = int(float(raw))
        except ValueError:
            raise ValidationError(
                "STOP AFTER must be a whole number of seconds, or blank to keep "
                "going until you press another button."
            )
        if not 4 <= value <= 24 * 3600:
            raise ValidationError("STOP AFTER must be between 4 and 86400 seconds.")
        return float(value)

    def _chart_width(self, reserve: int = 16, fallback: int = 72) -> int:
        try:
            width = int(self.size.width)
        except Exception:
            width = 0
        return max(24, min(180, width - reserve)) if width > reserve + 24 else fallback

    def _state_style(self, state: str) -> str:
        """A theme colour for ok/warn/bad/info/gone, or a colour passed
        straight through (the signal scale in colours.py)."""
        if state.startswith("#"):
            return state
        palette = self.palette
        return {
            "ok": palette.success, "warn": palette.warning, "bad": palette.error,
            "gone": palette.muted,
        }.get(state, palette.accent)

    def _chart(self, title: str, lines, state: str = "info",
               subtitle: str | None = None, key: str = "chart"):
        """A graph panel. `lines` mixes text lines and graphs (LineGraph,
        SpectrumGraph): text is drawn as before, every full block outlined in
        the theme's own background colour; graphs are drawn in pixels when
        the terminal can show them (kitty, Ghostty) and in text otherwise.
        `key` names the panel, so a live graph replaces its own last frame."""
        from rich.panel import Panel

        from ..render import PANEL_BOX

        palette = self.palette
        colour = self._state_style(state)
        parts = lines if isinstance(lines, list) else [lines]
        if all(isinstance(part, str) for part in parts):
            body = block_text(parts, colour, palette.background, scaffold=palette.muted)
        else:
            body = Text(no_wrap=True, overflow="crop")
            pending: list[str] = []
            graphs = 0

            def flush() -> None:
                if pending:
                    if body.plain:
                        body.append("\n")
                    body.append_text(block_text(pending, colour, palette.background,
                                                scaffold=palette.muted))
                    pending.clear()

            for part in parts:
                if isinstance(part, str):
                    pending.append(part)
                    continue
                flush()
                if body.plain:
                    body.append("\n")
                body.append_text(self.graph(f"{key}-{graphs}", part, colour=colour))
                graphs += 1
            flush()
        return Panel(
            body,
            title=Text(f" {title.upper()} ", style=f"bold {palette.primary}"),
            title_align="left",
            subtitle=Text(f" {subtitle} ", style=palette.muted) if subtitle else None,
            subtitle_align="right",
            border_style=palette.secondary,
            box=PANEL_BOX,
            padding=(0, 1),
        )

    def _signal_graph(self, history, height: int = 8) -> LineGraph:
        """A dBm history as a graph: −90 to −30, coloured by the signal scale."""
        return LineGraph(list(history), floor=-90, ceil=-30,
                         width=self._chart_width(), height=height,
                         label=lambda v: f"{v:.0f} dBm", colour="signal")

    def _rate_graph(self, history, label, height: int = 6, floor: float = 0.0) -> LineGraph:
        """A throughput or packet-rate history, scaled to its own peak."""
        peak = wifitools.nice_ceiling(max([v for v in history if v is not None] or [0.0]))
        return LineGraph(list(history), floor=floor, ceil=peak,
                         width=self._chart_width(), height=height, label=label,
                         colour=self.palette.accent)

    def _spectrum_panel(self, aps: list[dict], key: str, subtitle: str = ""):
        """The channel graph for each band that has networks on it."""
        from rich.panel import Panel

        from ..render import PANEL_BOX

        bands = [b for b in ("2.4 GHz", "5 GHz", "6 GHz")
                 if any(a.get("band") == b and a.get("channel") for a in aps)]
        if not bands:
            return None
        body = Text(no_wrap=True, overflow="crop")
        width = self._chart_width(reserve=14)
        for index, band in enumerate(bands):
            if index:
                body.append("\n\n")
            count = sum(1 for a in aps if a.get("band") == band)
            body.append(f"{band} · {count} network{'s' if count != 1 else ''}\n",
                        style=f"bold {self.palette.secondary}")
            body.append_text(self.graph(
                f"{key}-{band}",
                SpectrumGraph(aps, band, width=width, height=9 if band == "2.4 GHz" else 7),
            ))
        return Panel(
            body,
            title=Text(" CHANNELS, AS THE AIR SEES THEM ", style=f"bold {self.palette.primary}"),
            title_align="left",
            subtitle=Text(f" {subtitle} ", style=self.palette.muted) if subtitle else None,
            subtitle_align="right",
            border_style=self.palette.secondary,
            box=PANEL_BOX,
            padding=(0, 1),
        )

    def _blocks(self, text: str, state: str = "info", outline: bool = True) -> Text:
        """A bar or sparkline for a table cell, outlined like the graphs
        unless outline=False (LIVE AIR's HISTORY column)."""
        return block_text(text, self._state_style(state), self.palette.background,
                          scaffold=self.palette.muted, outline=outline)

    def _history(self, text: str, live: bool = True) -> Text:
        """HISTORY: each dBm reading in its own signal colour, one space
        apart; a network that has gone off the air is muted."""
        out = Text(no_wrap=True, overflow="crop")
        for index, token in enumerate(text.split()):
            if index:
                out.append(" ")
            try:
                colour = signal_colour(int(token)) if live else self.palette.muted
            except ValueError:
                colour = self.palette.muted
            out.append(token, style=colour)
        return out

    @staticmethod
    def _clock(seconds: float) -> str:
        minutes, secs = divmod(int(seconds), 60)
        hours, minutes = divmod(minutes, 60)
        return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"

    async def _run_live(self, tick, every: float, what: str) -> str:
        """Call `tick(elapsed, n)` every `every` seconds until STOP AFTER runs
        out or another button cancels this run. Returns why it stopped."""
        limit = self._limit()
        started = time.monotonic()
        count = 0
        while True:
            count += 1
            tick_started = time.monotonic()
            elapsed = tick_started - started
            await tick(elapsed, count)
            if self.MAX_TICKS is not None and count >= self.MAX_TICKS:
                return "finished"
            elapsed = time.monotonic() - started
            if limit is not None and elapsed >= limit:
                return f"stopped after {limit:.0f}s, as asked"
            left = f" — {limit - elapsed:.0f}s left" if limit is not None else ""
            self.progress(f"● {what} is live{left}. Any other button stops it.")
            # Fixed cadence: subtract however long this tick took.
            wait = max(0.05, every - (time.monotonic() - tick_started))
            if limit is not None:
                wait = min(wait, max(0.05, limit - elapsed))
            await asyncio.sleep(wait)

    @staticmethod
    def ap_vendor(bssid: str) -> str:
        """Who made the access point. Routers that broadcast several SSIDs
        (a guest network, a second band) derive the extra BSSIDs by setting
        the locally-administered bit, so those have no registry entry —
        they are marked 'virtual BSSID' rather than left blank."""
        vendor, kind = devices.vendor_for(bssid)
        if vendor:
            return devices.short_vendor(vendor, width=22)
        return "virtual BSSID" if kind == "random" else "—"

    # --------------------------------------------------------------- scan
    async def _scan(self, prefer: str) -> tuple[list[dict], str]:
        iface = self.field("iface")
        await self.begin("Scanning the air…")
        aps, backend, error = await wifi.scan(iface, prefer=prefer)
        await self.finish()
        if error:
            await self.push_warning("Scan found nothing", error)
            return [], backend
        self._last = aps
        self._air.update(aps)
        await self.push(
            verdict_line(
                self.palette, "Scan",
                f"{len(aps)} access points via {backend}"
                + (" (approx. dBm from link quality)" if backend == "nmcli" else "")
                + " — LIVE AIR keeps this updating",
                "ok",
            )
        )
        await self.push(
            kv_panel(self.palette, "What's on the air", wifi.band_summary(aps))
        )
        await self.push(
            table_panel(
                self.palette, "Access points",
                ["SSID", "BSSID", "AP vendor", "Band", "Ch", "Signal", "Quality",
                 "Security", "Rate"],
                self._ap_rows(aps),
                subtitle="sorted by signal · '*' marks the one you're on · "
                         "vendor from the offline IEEE registry",
            )
        )
        return aps, backend

    def _ap_rows(self, aps: list[dict]) -> list[list[object]]:
        rows = []
        for ap in sorted(aps, key=lambda a: a["signal_dbm"], reverse=True):
            marker = "* " if ap["in_use"] else ""
            rows.append([
                marker + (ap["ssid"] or "<hidden>"),
                ap["bssid"],
                self.ap_vendor(ap["bssid"]),
                ap["band"],
                ap["channel"] or "—",
                f'{ap["signal_dbm"]} dBm',
                wifi.signal_label(ap["signal_dbm"]),
                ap["security"],
                f'{ap["rate_mbps"]} Mb/s' if ap["rate_mbps"] else "—",
            ])
        return rows

    # ------------------------------------------------------------ live air
    async def _air_read(self, iface: str) -> tuple[list[dict], str, str, float | None]:
        """One tick's reading of the air, without waiting for the radio:
        (access points, backend, error, age of the newest scan result in s).

        Every other network comes from the latest *finished* scan, which is
        free to read; new scans run in the background (_keep_scanning). The
        network you're joined to is then overwritten with the driver's own
        live signal from `iw dev link`, so it moves on every tick."""
        aps, used, error = await wifi.scan_cached(iface)
        now = time.time()
        ages = []
        for ap in aps:
            ms = ap.get("last_seen_ms")
            if ms is not None:
                ap["seen_at"] = now - ms / 1000.0
                ages.append(ms / 1000.0)
        if iface and have_iw():
            link = await wifitools.link_now(iface)
            if link.get("connected") and link.get("signal_dbm") is not None:
                mine = (link.get("bssid") or "").lower()
                for ap in aps:
                    if (ap.get("bssid") or "").lower() == mine:
                        ap["signal_dbm"] = link["signal_dbm"]
                        ap["in_use"] = True
                        ap["seen_at"] = None     # a live read: always a new reading
        return aps, used, error, (min(ages) if ages else None)

    async def _keep_scanning(self, iface: str, use_iw: bool, every: float) -> None:
        """Ask for a fresh scan every `every` seconds for as long as a live
        view runs. A request made while the radio is still busy with the last
        scan is simply refused, so at a short interval the radio scans back
        to back — as fast as the hardware allows, typically every 2–4 s."""
        period = max(self.RESCAN_EVERY, every)
        while True:
            try:
                await wifi.scan_trigger(iface, use_iw)
            except Exception:
                pass
            await asyncio.sleep(period)

    async def _with_background_scans(self, iface: str, every: float, run):
        """Run `run()` with _keep_scanning going alongside; stop it after."""
        use_iw = await wifi.can_trigger_with_iw(iface)
        scanner = asyncio.create_task(self._keep_scanning(iface, use_iw, every))
        try:
            return await run()
        finally:
            scanner.cancel()
            with contextlib.suppress(BaseException):
                await scanner

    async def _live_air(self) -> None:
        iface = self.field("iface")
        every = self._air_every = self._every(self.AIR_EVERY, low=1.0)
        await self.begin("Starting the live view of the air…")
        headline, graph = self._panel(), self._panel()
        bar, table = self._pick_bar("air"), self._pick_list("air")
        spectrum, load = self._panel(), self._panel()
        for widget in (headline, graph, bar, table, spectrum, load):
            await self.push_widget(widget)
        self._scroll_home()
        state = {"backend": "nmcli", "error": "", "age": None, "running": True,
                 "started": time.monotonic(), "ended": None}

        def draw() -> None:
            ended = state["ended"] or time.monotonic()
            self._render_air(headline, graph, table, load, self.typed_target(),
                             state["backend"], ended - state["started"],
                             state["error"], state["age"], spectrum=spectrum, bar=bar,
                             running=state["running"])

        async def tick(elapsed: float, count: int) -> None:
            aps, used, error, age = await self._air_read(iface)
            if aps:
                self._last = aps
                self._air.update(aps)
            state.update(backend=used or "nmcli", error=error, age=age)
            draw()

        self._redraw = draw
        why = await self._with_background_scans(
            iface, every, lambda: self._run_live(tick, every, "LIVE AIR"))
        # The panels stay up: a network picked now is still shown, as stopped.
        state.update(running=False, ended=time.monotonic())
        await self.finish()
        await self.push(
            verdict_line(self.palette, "LIVE AIR", f"{why} — {self._air.scans} updates, "
                         f"{len(self._air.seen)} networks seen", "info")
        )

    def _air_picked(self) -> tuple[dict | None, bool]:
        """The network picked in LIVE AIR (or None), and whether the view
        shows only it."""
        key = self.picks.key("air")
        entry = self._air.get(key) if key else None
        return entry, entry is not None and self.picks.only("air")

    def _render_air(self, headline, graph, table, load, target: str, backend: str,
                    elapsed: float, error: str, age: float | None = None,
                    spectrum=None, bar=None, running: bool = True) -> None:
        now = time.time()
        present = self._air.present(now)
        picked, only = self._air_picked()
        key = picked["key"] if picked is not None else ""
        lit = "● LIVE AIR" if running else "■ LIVE AIR"
        scans = (f"update {self._air.scans} via {backend}"
                 + (f" · newest scan {age:.1f}s old" if age is not None and running else "")
                 + f" · {self._run_state(running, elapsed)}")
        if only:
            on_air = self._air.on_air(picked, now)
            dbm = picked.get("signal_dbm")
            others = len(present) - (1 if on_air else 0)
            headline.update(verdict_line(
                self.palette, lit,
                f"showing only {picked.get('ssid') or '<hidden>'} ({picked.get('bssid') or '—'}) · "
                f"ch {picked.get('channel') or '—'} {picked.get('band') or ''} · "
                + (f"now {dbm} dBm ({wifi.signal_label(dbm)})" if on_air and dbm is not None
                   else "off the air")
                + f" · {others} other network{'s' if others != 1 else ''} hidden · {scans}",
                wifitools.signal_state(dbm) if on_air and dbm is not None else "warn"))
        else:
            headline.update(verdict_line(
                self.palette, lit,
                (f"{len(present)} networks on the air · {len(self._air.gone(now))} gone · "
                 + scans if present else f"nothing on the air yet — {error or 'waiting'}"),
                "ok" if present else "warn"))
        focus = picked if picked is not None else self._air.focus(target, now)
        if focus is not None:
            graph.update(self._air_chart(focus, now, chosen=picked is not None, tall=only))

        every = getattr(self, "_air_every", self.AIR_EVERY)
        entries = self._air.ordered(now)
        keys = self.steady("air", [entry["key"] for entry in entries], table)
        by_key = {entry["key"]: entry for entry in entries}
        entries = [by_key[k] for k in keys]
        if picked is not None and key not in by_key:      # past the end of the table
            entries.append(picked)
            keys.append(key)
        shown = [picked] if only else entries
        rows = []
        for entry in shown:
            row = self._air.live_row(entry, self.ap_vendor, self.HISTORY_VALUES,
                                     self._air.on_air(entry, now))
            live = row[4] not in ("gone", "—")
            colour = signal_colour(int(row[4])) if live else "gone"
            row[5] = self._blocks(row[5], colour)
            # HISTORY: the readings themselves, each in its own signal colour.
            row[6] = self._history(row[6], live)
            row[0] = marked(self.palette, row[0], entry["key"] == key)
            rows.append(row)
        shown_keys = [entry["key"] for entry in shown]
        self.show_list(table, table_panel(
            self.palette, "Every network, live" + (" — showing only one" if only else ""),
            wifitools.LIVE_COLUMNS, rows,
            subtitle=f"'*' = the one you're on · updated every {every:g}s · "
                     f"history = the last {self.HISTORY_VALUES} readings, newest "
                     "on the right" + (" · order held while the pointer is over the list"
                                       if getattr(table, "holding", False) else ""),
            row_styles=row_styles(self.palette, shown_keys, key), one_line=True,
            shrink=("SSID", "AP vendor"),
        ), keys=keys, shown=shown_keys, picked=key, one_line=True)
        if bar is not None:
            bar.update(pick_bar(
                self.palette, "air",
                label=f"{picked.get('ssid') or '<hidden>'} · {picked.get('bssid') or key}"
                if picked is not None else "",
                only=only, lost=picked is not None and not self._air.on_air(picked, now),
                focused=self.list_focused(table), typed=target,
                hidden=len(present) - 1 if only else 0))

        aps = self._last
        if only:
            mine = [a for a in aps if wifitools.AirWatch.key_of(a) == key] or [picked]
            aps_drawn = [a for a in mine if a.get("signal_dbm")]
        else:
            aps_drawn = [a for a in aps if a.get("signal_dbm")]
        if spectrum is not None:
            panel = self._spectrum_panel(
                aps_drawn, key="air-spectrum",
                subtitle=(f"live · every {every:g}s · " if running else "")
                + ("only the network you picked" if only
                   else "each network drawn over the channels it occupies"))
            spectrum.update(panel if panel is not None else "")
        if only:
            load.update(kv_panel(
                self.palette, f"About {picked.get('ssid') or 'this network'}",
                wifitools.network_rows(picked, present, vendor=self.ap_vendor, now=now),
                subtitle="everything LIVE AIR has seen of it"))
        elif any(a.get("band") == "2.4 GHz" for a in aps):
            congestion = wifi.congestion_by_channel(aps)
            peak = max(congestion.values() or [1])
            best, _why = wifi.recommend_channel_24(aps)
            load.update(
                table_panel(
                    self.palette, "2.4 GHz load, counting overlap",
                    ["Channel", "APs overlapping it", "Load"],
                    [[f"ch {c}" + ("  ← best" if c == best else ""), congestion[c],
                      self._meter(congestion[c], peak)]
                     for c in wifi.NON_OVERLAPPING_24],
                    subtitle="CHANNELS explains the pick",
                )
            )
        else:
            load.update("")

    def _air_chart(self, entry: dict, now: float, chosen: bool = False, tall: bool = False):
        """LIVE AIR's big graph, of one network — taller when the view shows
        only that network."""
        history = [v for v in entry["history"] if v is not None]
        dbm = entry.get("signal_dbm")
        on_air = self._air.on_air(entry, now)
        reading = (f"now {dbm} dBm ({wifi.signal_label(dbm)})" if on_air and dbm is not None
                   else "off the air")
        return self._chart(
            f"Signal — {entry.get('ssid') or '<hidden>'}  ·  ch {entry.get('channel')} "
            f"{entry.get('band')}  ·  {reading}",
            [self._signal_graph(history, height=12 if tall else 8)],
            signal_colour(dbm) if on_air and dbm is not None else "gone",
            subtitle="newest on the right · "
                     + ("the network you picked — click another row to graph it" if chosen
                        else "click a network below to graph it"),
            key="air",
        )

    # ----------------------------------------------------------- channels
    async def _channels(self) -> None:
        if self._last:
            # Reuse the last scan — but replace whatever is on screen, so
            # pressing CHANNELS twice shows one answer, not two stacked.
            await self.begin("Working out the channels from the last scan…")
            await self.finish()
        aps, _backend = await self._ensure_scan()
        if not aps:
            return
        panel = self._spectrum_panel(
            aps, key="channels-spectrum",
            subtitle="every network over the channels it occupies, as tall as its "
                     "signal · '●' = yours")
        if panel is not None:
            await self.push(panel)
        rows = []
        for entry in wifi.channel_usage(aps, "2.4 GHz"):
            rows.append([
                f'ch {entry["channel"]}',
                entry["count"],
                f'{entry["strongest"]} dBm',
                "clean" if entry["channel"] in wifi.NON_OVERLAPPING_24 else "overlaps",
            ])
        await self.push(
            table_panel(
                self.palette, "2.4 GHz channel usage",
                ["Channel", "APs on it", "Strongest", "1/6/11?"],
                rows, subtitle="every AP sitting directly on each channel",
            )
        )
        congestion = wifi.congestion_by_channel(aps)
        await self.push(
            table_panel(
                self.palette, "2.4 GHz congestion, counting overlap",
                ["Channel", "APs overlapping it", "Load"],
                [[f"ch {c}", congestion[c], self._meter(congestion[c], max(congestion.values() or [1]))]
                 for c in wifi.NON_OVERLAPPING_24],
                subtitle="an AP on ch 4 still interferes with ch 6",
            )
        )
        best, why = wifi.recommend_channel_24(aps)
        five = [a for a in aps if a["band"] == "5 GHz"]
        await self.push(
            text_panel(
                self.palette,
                f"Recommended 2.4 GHz channel: {best}" if best else "2.4 GHz",
                why + (
                    f"\n\n{len(five)} networks are on 5 GHz, which has far more "
                    "non-overlapping channels and less range — move to 5 GHz "
                    "where you can, and keep 2.4 GHz for reach and older gear."
                    if five else ""
                ),
                style=self.palette.accent,
            )
        )

    def _meter(self, value: int, peak: int, width: int = 12) -> str:
        if peak <= 0:
            return "·" * width
        filled = max(0, min(width, int(round(value / peak * width))))
        return "█" * filled + "·" * (width - filled)

    # ------------------------------------------------------ signal, live
    async def _signal(self) -> None:
        target = self.typed_target()
        if not target:
            # The GRAPH box is empty: the network picked in LIVE AIR, if any.
            picked, _only = self._air_picked()
            if picked is not None:
                target = picked.get("bssid") or picked.get("ssid") or ""
        if not target:
            raise ValidationError(
                "Put a BSSID or SSID in the GRAPH box first — or pick a network in "
                "LIVE AIR by clicking its row — the network you want to watch. Run "
                "SCAN to see the names."
            )
        iface = self.field("iface")
        every = self._every(self.AIR_EVERY, low=1.0)
        await self.begin(f"Watching {target}…")
        headline, graph, detail = (self._panel() for _ in range(3))
        for widget in (headline, graph, detail):
            await self.push_widget(widget)
        self._scroll_home()
        history: list[float] = []
        seen = {"once": False, "seen_at": None}

        async def tick(elapsed: float, count: int) -> None:
            aps, _used, _error, _age = await self._air_read(iface)
            if aps:
                self._last = aps
                self._air.update(aps)
            ap = wifi.pick_ap(aps, target)
            if not ap:
                headline.update(verdict_line(
                    self.palette, target,
                    f"not seen in this scan · running {self._clock(elapsed)}", "warn"))
                return
            seen["once"] = True
            # A new reading only when the radio has actually heard it again
            # (the same cached scan result read twice is one reading).
            at = ap.get("seen_at")
            if at is None or seen["seen_at"] is None or \
                    abs(at - seen["seen_at"]) > wifitools.AirWatch.SAME_READING:
                seen["seen_at"] = at
                history.append(ap["signal_dbm"])
                del history[:-wifitools.LinkWatch.HISTORY]
            now = ap["signal_dbm"]
            headline.update(verdict_line(
                self.palette, f"● {ap['ssid'] or '<hidden>'}",
                f"{now} dBm ({wifi.signal_label(now)}) · ch {ap['channel']} "
                f"{ap['band']} · running {self._clock(elapsed)}",
                wifitools.signal_state(now),
            ))
            graph.update(self._chart(
                "Signal, live — newest on the right",
                # Taller than LIVE AIR's: this view is for walking around
                # with, and every dB of movement should show.
                [self._signal_graph(history, height=13)],
                signal_colour(now), key="signal",
                subtitle=f"{len(history)} samples · a scan every {every:g}s · "
                         f"best {max(history)} · worst "
                         f"{min(history)} dBm",
            ))
            detail.update(kv_panel(
                self.palette, "Right now", [
                    ("BSSID", f"{ap['bssid']}  ({self.ap_vendor(ap['bssid'])})"),
                    ("Channel / band", f'{ap["channel"]} · {ap["band"]}'),
                    ("Security", ap["security"]),
                    ("Signal now", f"{now} dBm ({wifi.signal_label(now)})"),
                    ("Best / worst seen", f"{max(history)} / {min(history)} dBm"),
                    ("Trend", self._blocks(wifi.sparkline(history[-50:]),
                                           signal_colour(now))),
                ],
                subtitle="walk around — the graph follows you",
            ))

        why = await self._with_background_scans(
            iface, every, lambda: self._run_live(tick, every, f"SIGNAL for {target}"))
        await self.finish()
        if not seen["once"]:
            await self.push_warning(
                "Never saw that network",
                f"{target!r} did not appear in any scan. Check the name with "
                "SCAN — names are matched ignoring case but must otherwise be "
                "exact, a BSSID may be typed with any separators, and a hidden "
                "network shows as <hidden> with no name to match.",
            )
            return
        await self.push(verdict_line(
            self.palette, "Done",
            f"{why} · {len(history)} samples · best {max(history)} dBm · "
            f"worst {min(history)} dBm", "info"))

    # ------------------------------------------------------- link health
    async def _link(self) -> None:
        iface = self._require_iface()
        every = self._every(self.LINK_EVERY)
        await self.begin(f"Reading {iface}'s link…")
        info = await wifitools.link_info(iface)
        if not info["link"].get("connected") and not info["device"].get("state"):
            await self.finish()
            await self.push_warning(
                "Not associated",
                f"{iface} doesn't look connected to any access point right now "
                "— nmcli and iw both came back empty. Check TOOL CHECK if "
                "that's unexpected.",
            )
            return
        watch = self._link_watch = wifitools.LinkWatch()
        headline, charts, stats, advice, health = (
            self._panel() for _ in range(5))
        for widget in (headline, charts, stats, advice, health):
            await self.push_widget(widget)
        self._scroll_home()
        first = {"info": info}

        async def tick(elapsed: float, count: int) -> None:
            current = first.pop("info", None) or await wifitools.link_info(iface)
            watch.update(current)
            self._render_link(iface, current, watch, elapsed,
                              headline, charts, health, stats, advice, every)

        why = await self._run_live(tick, every, "LINK HEALTH")
        await self.finish()
        await self.push(verdict_line(
            self.palette, "LINK HEALTH", f"{why} — {len(watch.samples)} samples", "info"))

    def _render_link(self, iface: str, info: dict, watch, elapsed: float,
                     headline, charts, health, stats, advice,
                     every: float = 1.0) -> None:
        link = info["link"]
        target = link.get("bssid") or link.get("ssid") or ""
        ap = wifi.pick_ap(self._last, target) if target and self._last else None
        vendor = self.ap_vendor(link["bssid"]) if link.get("bssid") else ""
        signal = link.get("signal_dbm")
        if link.get("connected"):
            headline.update(verdict_line(
                self.palette, "● LINK",
                f"{link.get('ssid') or '?'} · {signal if signal is not None else '?'} dBm · "
                f"down {link.get('rx_bitrate') or 0:.0f} / up {link.get('tx_bitrate') or 0:.0f} "
                f"Mbit/s · running {self._clock(elapsed)} · via {' + '.join(info['sources'])}",
                wifitools.signal_state(signal) if signal is not None else "ok",
            ))
        else:
            headline.update(verdict_line(
                self.palette, "● LINK",
                f"not associated right now — still watching · {self._clock(elapsed)}",
                "warn"))
        width = self._chart_width()
        lines: list = []
        if any(v is not None for v in watch.signal):
            lines.append(self._signal_graph(watch.signal, height=6))
        spark = max(10, width - 36)          # room for the label and reading
        rx = [v for v in watch.rx if v is not None]
        if rx:
            lines += ["", "bitrate down  " + wifi.sparkline(
                [min(-30.0, -90 + v / max(rx) * 60) for v in rx[-spark:]])
                + f"  {rx[-1]:.0f} Mbit/s (peak {max(rx):.0f})"]
        retry = [v for v in watch.retry if v is not None]
        if retry:
            lines += ["retries       " + wifi.sparkline(
                [-90 + min(v, 30) / 30 * 60 for v in retry[-spark:]])
                + f"  {retry[-1]:.1f}% of frames, last {every:g}s"]
        charts.update(self._chart(
            "Signal and link, live", lines or ["iw is needed for a live signal graph — "
                                               "TOOL CHECK shows how to add it"],
            signal_colour(signal) if signal is not None else "info",
            subtitle=f"newest on the right · every {every:g}s", key="link",
        ))
        health.update(kv_panel(
            self.palette, f"{iface} — link health",
            wifitools.link_rows(info, ap, vendor),
            subtitle="iw for dBm, bitrate and retries · nmcli for addresses and DNS",
        ))
        stats.update(kv_panel(self.palette, "While watching", watch.rows(),
                              subtitle="retries counted per interval, not since joining"))
        findings = wifitools.link_advice(info, ap, self._last)
        recent = [v for v in watch.retry[-10:] if v is not None]
        if recent and max(recent) > 15:
            findings.append(("warn", f"Retries spiked to {max(recent):.0f}% in the last few "
                                     "seconds — interference, or something moving between "
                                     "you and the AP."))
        if watch.roams:
            findings.append(("info", f"Roamed between access points {len(watch.roams)}× "
                                     "while watching."))
        advice.update(table_panel(
            self.palette, "What this means", ["Level", "Detail"],
            wifitools.advice_rows(findings) or [["OK", "Nothing stands out."]],
            subtitle="run SCAN or LIVE AIR too, and neighbours are checked against it",
        ))

    # --------------------------------------------------- devices on it
    async def _devices(self) -> None:
        iface = self._require_iface()
        cidr, note = await wifitools.iface_subnet(iface)
        if not cidr:
            raise ValidationError(
                f"{iface} has no IPv4 address right now, so there's no subnet "
                "to sweep. Make sure it's associated with an address (TOOL "
                "CHECK), or use LAN → SWEEP with the CIDR typed in by hand."
            )
        network = valid_network(cidr)
        try:
            targets = lan.hosts_for(str(network))
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        await self.begin(f"Pinging {len(targets)} host(s) on {network}…")
        try:
            result = await lan.sweep(str(network), progress=self.progress)
        except FileNotFoundError:
            await self.finish()
            await self.push_error(
                "ping not installed", "Install it with:\n    sudo apt install iputils-ping"
            )
            return
        live = result["live"]
        extra = result.get("arp_only") or []
        found = live + extra
        identified: list[dict] = []
        if found:
            self.progress(
                f"Identifying {len(found)} device(s) — vendor, name, services…"
            )
            context = await devices.local_context()
            identified = await devices.identify(
                found, context=context, progress=self.progress,
                use_ssdp=devices.is_local_network(network, context),
            )
        await self.finish()
        self._found, self._found_cidr = identified, result["cidr"]
        live_devices = identified[: len(live)]
        arp_devices = identified[len(live):]
        ssid = self._current_ssid()
        await self.push(
            verdict_line(
                self.palette, "Devices",
                f"{len(live)} of {result['scanned']} host(s) alive on {result['cidr']}"
                + (f", {len(extra)} more in the ARP cache" if extra else "")
                + (f" — {ssid}" if ssid else "")
                + (" · PORTS checks them next" if identified else ""),
                "ok" if live else "warn",
            )
        )
        if note:
            await self.push_warning("Subnet narrowed", note)
        if identified:
            await self.push(
                kv_panel(
                    self.palette, f"Who's on {result['cidr']}", devices.summary(identified),
                    subtitle="offline vendor registry + what each device says about itself",
                )
            )
        if live_devices:
            await self.push(
                table_panel(
                    self.palette, f"Live hosts — {result['cidr']}",
                    devices.SWEEP_COLUMNS, devices.sweep_rows(live_devices),
                    subtitle="ICMP + neighbour table + DNS / mDNS / NetBIOS / UPnP",
                )
            )
        if arp_devices:
            await self.push(
                table_panel(
                    self.palette, "In ARP cache but did not answer ping",
                    devices.ARP_COLUMNS, devices.arp_rows(arp_devices),
                    subtitle="may be firewalled to ICMP",
                )
            )
        if identified:
            await self.push(
                text_panel(
                    self.palette, "How these were identified",
                    devices.SOURCES_NOTE, style=self.palette.muted,
                )
            )
        if not live and not extra:
            await self.push_warning(
                "Nothing answered",
                "No host replied to ICMP and the ARP cache is empty for this "
                "range. Hosts may block ping, or you may be off-segment.",
            )

    def _current_ssid(self) -> str:
        for ap in self._last:
            if ap.get("in_use"):
                return ap.get("ssid", "")
        return ""

    def _names(self) -> dict[str, str]:
        """ip -> 'name (device)' for everything DEVICES has identified."""
        names = {}
        for dev in self._found:
            label = devices.display_name(dev) or dev.get("device") or ""
            if dev.get("device") and label != dev.get("device"):
                label = f"{label} ({dev['device']})"
            if label:
                names[dev["ip"]] = label
        return names

    # --------------------------------------------------------------- ports
    async def _ports_check(self) -> None:
        if not self._found:
            await self._devices()
            if not self._found:
                return
        targets = [d for d in self._found if d.get("role") != "self"] or self._found
        await self.begin(
            f"Checking {len(devices.PROBE_PORTS)} identifying ports on "
            f"{len(targets)} device(s)…")
        gate = asyncio.Semaphore(8)
        done = {"n": 0}

        async def check(dev: dict) -> dict:
            async with gate:
                open_ports = await devices.port_scan(dev["ip"])
            done["n"] += 1
            self.progress(f"Ports — {done['n']} of {len(targets)} devices checked…")
            return {
                "ip": dev["ip"],
                "name": devices.display_name(dev),
                "device": dev.get("device", ""),
                "open": open_ports,
            }

        results = await asyncio.gather(*(check(d) for d in targets))
        await self.finish()
        self._ports = list(results)
        with_open = [r for r in results if r["open"]]
        await self.push(verdict_line(
            self.palette, "Ports",
            f"{len(with_open)} of {len(results)} device(s) on {self._found_cidr} "
            "have one or more of these ports open", "ok"))
        await self.push(table_panel(
            self.palette, "Open ports, by device",
            ["IP", "Name", "Device", "Open", "Ports"],
            wifitools.port_rows(sorted(results, key=lambda r: -len(r["open"]))),
            subtitle="TCP connect to the same ports IDENTIFY uses — no root, no raw packets",
        ))
        findings = wifitools.port_findings(results)
        if findings:
            await self.push(table_panel(
                self.palette, "Worth a second look",
                ["IP", "Device", "Port", "Why"], findings,
                subtitle="not necessarily wrong — just worth confirming it's meant to be on",
            ))
        await self.push(text_panel(
            self.palette, "Only your own network",
            "PORTS checks the devices DEVICES found on the subnet this Wi-Fi "
            "interface is on — your own network. Checking ports on networks you "
            "don't run can break their terms of use, and on some, the law.",
            style=self.palette.muted,
        ))

    # ------------------------------------------------------------- traffic
    async def _traffic(self) -> None:
        iface = self._require_iface()
        every = self._every(self.TRAFFIC_EVERY)
        if iface not in netif.read_counters():
            await self.begin("Reading interface counters…")
            await self.finish()
            await self.push_error(
                "No counters for that interface",
                f"{netif.PROC_NET_DEV} has no line for {iface}. TRAFFIC is "
                "Linux-only and needs the interface to be up.",
            )
            return
        await self.begin(f"Watching traffic on {iface}…")
        own = await wifitools.iface_addresses(iface)
        watch = self._rates = wifitools.RateWatch(iface)
        headline, down_chart, up_chart, totals, talkers, services = (
            self._panel() for _ in range(6))
        for widget in (headline, down_chart, up_chart, totals, talkers, services):
            await self.push_widget(widget)
        self._scroll_home()
        names = self._names()

        async def tick(elapsed: float, count: int) -> None:
            watch.update(netif.read_counters())
            conns, _error = await flows.snapshot()
            mine = wifitools.connections_on(conns, own)
            hosts = flows.by_remote_host(mine)
            down = watch.down[-1] if watch.down else 0.0
            up = watch.up[-1] if watch.up else 0.0
            headline.update(verdict_line(
                self.palette, "● TRAFFIC",
                f"{iface} · down {down:.2f} · up {up:.2f} Mbit/s · "
                f"{len(flows.established(mine))} connections over the Wi-Fi · "
                f"running {self._clock(elapsed)}",
                "ok"))
            rate_label = (lambda v: f"{round(v, 2):g} Mb/s")
            down_chart.update(self._chart(
                f"Download — {down:.2f} Mbit/s",
                [self._rate_graph(watch.down, rate_label, height=6)],
                "info", subtitle=f"one column every {every:g}s, newest on the right",
                key="down"))
            up_chart.update(self._chart(
                f"Upload — {up:.2f} Mbit/s",
                [self._rate_graph(watch.up, rate_label, height=4)], "info", key="up"))
            totals.update(kv_panel(self.palette, "Totals", watch.rows(),
                                   subtitle="from /proc/net/dev — no root"))
            talkers.update(table_panel(
                self.palette, "Who this machine is talking to over the Wi-Fi",
                ["Remote", "Name / where", "Conns", "Ports", "Process"],
                wifitools.talker_rows(hosts, names),
                subtitle=("LAN names from DEVICES" if names else
                          "run DEVICES first to put names on LAN peers")
                + " · FLOW → TOP TALKERS adds ASN and geo",
            ))
            by_service = flows.by_service(mine)
            total = sum(s["count"] for s in by_service) or 1
            services.update(table_panel(
                self.palette, "By service",
                ["Service", "Proto", "Connections", "Share"],
                [[s["service"], s["proto"].upper(), s["count"],
                  f"{100 * s['count'] / total:.0f}%"] for s in by_service[:10]],
                subtitle="named by the well-known port",
            ))

        why = await self._run_live(tick, every, "TRAFFIC")
        await self.finish()
        await self.push(verdict_line(
            self.palette, "TRAFFIC",
            f"{why} — moved {netif.human_bytes(watch.total_down)} down, "
            f"{netif.human_bytes(watch.total_up)} up", "info"))

    # ------------------------------------------------------------- packets
    async def _packets_live(self) -> None:
        iface = self._require_iface()
        display_filter = self.field("filter")
        if problem := capture.check_filter(display_filter):
            raise ValidationError(problem)
        limit = self._limit()
        repaint = self._repaint = self._every(self.PACKET_REPAINT, low=0.2)
        await self.begin("Checking capture permission…")
        prefix = await self._permission()
        if prefix is None:
            return
        own = await wifitools.iface_addresses(iface)
        live = capture.LiveCapture(iface, display_filter, prefix, keep=self.PACKET_KEEP)
        why = await live.start()
        if why:
            await self.finish()
            if "not installed" in why:
                await self._missing("tshark")
            else:
                await self.push_error("Could not start tshark", why)
            return
        running_as = (
            "sudo — unlocked once for this session" if SESSION.active
            else (" ".join(prefix) if prefix else "no elevation needed")
        )
        panels = [self._panel() for _ in range(6)]
        for widget in panels:
            await self.push_widget(widget)
        self._scroll_home()
        rate: list[float] = []
        started = time.monotonic()
        mark = {"at": started, "total": 0, "renders": 0}
        stopped = "you pressed another button"

        def render(running: bool = True) -> None:
            now = time.monotonic()
            span = now - mark["at"]
            if running and span > 0:
                rate.append((live.total - mark["total"]) / span)
                del rate[:-wifitools.LinkWatch.HISTORY]
                mark["at"], mark["total"] = now, live.total
            self._render_packets(panels, live, own, rate, now - started,
                                 running, running_as, display_filter)

        render()
        self.progress(f"● PACKETS is live on {iface}. Any other button stops it.")
        try:
            async for _packet in live.packets_as_they_arrive(idle=0.5):
                now = time.monotonic()
                if limit is not None and now - started >= limit:
                    stopped = f"stopped after {limit:.0f}s, as asked"
                    break
                if now - mark["at"] < repaint:
                    continue
                render()
                mark["renders"] += 1
                if self.MAX_TICKS is not None and mark["renders"] >= self.MAX_TICKS:
                    stopped = "finished"
                    break
            else:
                stopped = "tshark exited on its own"
        finally:
            # Keep what was seen even when another button cancelled this run.
            self._packets = list(live.packets)
            self._dns = wifitools.dns_records(self._packets)
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await asyncio.shield(live.stop())
                render(running=False)
                await self.finish()
                await self.push(verdict_line(
                    self.palette, "PACKETS",
                    f"{stopped} — {live.total:,} packets in "
                    f"{time.monotonic() - started:.0f}s · EXPORT CSV saves them, "
                    "CAPTURE → SAVE PCAP for Wireshark", "info"))

    def _render_packets(self, panels, live, own: set[str], rate: list[float],
                        elapsed: float, running: bool, running_as: str,
                        display_filter: str) -> None:
        headline, chart, mix, hosts, dns, recent = panels
        held = live.packets
        records = wifitools.dns_records(held)
        names = {**wifitools.names_from_dns(records), **self._names()}
        headline.update(verdict_line(
            self.palette, "● PACKETS" if running else "■ PACKETS",
            f"{live.iface}{'  ·  ' + display_filter if display_filter else ''} · "
            f"{live.total:,} packets · {rate[-1] if rate else 0:.0f}/s now · "
            f"{'running' if running else 'stopped'} {self._clock(elapsed)} · {running_as}",
            "ok" if running else "info"))
        chart.update(self._chart(
            "Packets per second",
            [self._rate_graph(rate, lambda v: f"{v:.0f}/s", height=5)],
            "info", subtitle=f"a column every {getattr(self, '_repaint', 1.0):g}s, "
                             "newest on the right", key="packets"))
        mix.update(table_panel(
            self.palette, "Protocols", ["Protocol", "Packets", "Share", "Bytes"],
            capture.protocol_mix(held)[:10],
            subtitle=f"the last {len(held):,} packets"))
        hosts.update(table_panel(
            self.palette, "Busiest hosts, named by the DNS lookups seen",
            ["Host", "Name", "Packets", "In", "Out", "Protocols"],
            wifitools.traffic_rows(wifitools.traffic_by_host(held, own, names)),
            subtitle="in / out relative to this machine"))
        dns.update(table_panel(
            self.palette, "DNS lookups", ["Name", "Type", "Asked", "Answer"],
            wifitools.dns_rows(records, limit=15),
            subtitle="what devices on this link asked for, busiest first"))
        newest = list(reversed(held[-12:]))
        recent.update(table_panel(
            self.palette, "Newest packets", capture.PACKET_COLUMNS,
            capture.packet_rows(newest, limit=12),
            subtitle="CAPTURE has the full packet list and filtering"))

    # -------------------------------------------------------------- export
    async def _export(self) -> None:
        datasets = {
            "networks": self._air.export(),
            "devices": (["ip", "rtt", "mac", "vendor", "hostname", "device", "details"],
                        devices.sweep_rows(self._found)),
            "ports": (["ip", "name", "device", "open_count", "ports"],
                      wifitools.port_rows(self._ports)),
            "link": self._link_watch.export() if self._link_watch else ([], []),
            "throughput": self._rates.export() if self._rates else ([], []),
            "dns": (["name", "type", "asked", "answer"],
                    wifitools.dns_rows(self._dns, limit=10_000)),
            "packets": (capture.PACKET_COLUMNS,
                        capture.packet_rows(self._packets, limit=len(self._packets))),
            "bluetooth": self._bt.export(),
        }
        if not any(rows for _columns, rows in datasets.values()):
            raise ValidationError(
                "Nothing to export yet. Run SCAN or LIVE AIR, LINK HEALTH, "
                "DEVICES, PORTS, TRAFFIC, PACKETS or BLUETOOTH first — EXPORT "
                "saves what they gathered."
            )
        await self.begin("Writing CSV files…")
        directory = wifitools.export_dir(self.EXPORT_BASE)
        written = wifitools.export_csv(directory, datasets)
        await self.finish()
        await self.push(verdict_line(
            self.palette, "Exported", f"{len(written)} file(s) in {directory}", "ok"))
        await self.push(table_panel(
            self.palette, "Files", ["File", "Rows"],
            [[path.name, rows] for path, rows in written],
            subtitle="opens in any spreadsheet"))

    # ---------------------------------------------------------- bluetooth
    async def _bluetooth(self, trackers_only: bool = False) -> None:
        """BLUETOOTH (everything) and BT TRACKERS (the safety check): one
        listening scan, rendered every REFRESH EVERY seconds until another
        button is pressed or STOP AFTER runs out."""
        what = "BT TRACKERS" if trackers_only else "BLUETOOTH"
        every = self._every(self.BT_EVERY, low=0.5)
        self._limit()                          # a bad STOP AFTER fails before we start
        await self.begin("Starting the Bluetooth scan…")
        async with self._bt_lock:
            await self._bt_session(trackers_only, what, every)

    async def _bt_session(self, trackers_only: bool, what: str, every: float) -> None:
        factory = self.BT_SCANNER or (lambda on_advert: bluetooth.Scanner(on_advert))
        scanner = factory(self._bt.add)
        try:
            await scanner.start()
        except Exception as exc:               # BluetoothUnavailable, or anything bleak raised
            problem = bluetooth.explain(exc)
            await self.finish()
            await self.push_warning(problem.title, problem.message)
            await self.push(text_panel(self.palette, "Getting Bluetooth going",
                                       bluetooth.INSTALL_HINTS, style=self.palette.accent))
            return
        self._bt_backend = getattr(scanner, "backend", "") or "bleak"
        state = {"running": True, "started": time.monotonic(), "ended": None}
        try:
            headline, graph = self._panel(), self._panel()
            bar, table = self._pick_bar("bt"), self._pick_list("bt")
            rest = [self._panel() for _ in range(2 if trackers_only else 1)]
            for widget in (headline, graph, bar, table, *rest):
                await self.push_widget(widget)
            self._scroll_home()
            render = self._render_bt_trackers if trackers_only else self._render_bt

            def draw(now: float | None = None) -> None:
                render(headline, graph, bar, table, *rest,
                       now=time.time() if now is None else now,
                       elapsed=(state["ended"] or time.monotonic()) - state["started"],
                       every=every, running=state["running"])

            place = {"at": -1e9}

            async def tick(elapsed: float, count: int) -> None:
                now = time.time()
                if now - place["at"] >= self.BT_PLACE_EVERY:
                    place["at"] = now
                    try:
                        self._bt_place = await bluetooth.current_place(self.field("iface"))
                    except Exception:
                        self._bt_place = None
                self._bt.tick(now)
                self._bt_log(now)
                draw(now)

            # A click on a row redraws at once; after the scan stops, the
            # panels stay up and a pick still redraws them (as stopped).
            self._redraw = draw
            why = await self._run_live(tick, every, what)
        finally:
            state.update(running=False, ended=time.monotonic())
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(scanner.stop(), 5.0)
        await self.finish()
        await self.push(verdict_line(
            self.palette, what,
            f"{why} — {len(self._bt.devices)} devices heard, "
            f"{self._bt.updates:,} broadcasts", "info"))

    def _bt_log(self, now: float) -> None:
        """Remember each tracker heard, once a minute, with where this machine
        is — and read back everywhere it has been heard, for the flag."""
        store = getattr(self.services, "store", None)
        place = self._bt_place
        for device in self._bt.present(now):
            if not device.guess.tracker:
                continue
            if now - self._bt_logged.get(device.address, -1e9) < self.BT_LOG_EVERY:
                continue
            self._bt_logged[device.address] = now
            # Off every network there is no "where" to compare: not logged.
            if store is None or place is None or place.key == "offline":
                continue
            store.tracker_seen(device.address, place.key, place.label, device.guess.tracker)
            device.places = [(key, label, first, last) for key, label, first, last, _hits
                             in store.tracker_places(device.address)]

    # -- pieces both views use
    def _bt_history(self, history, live: bool = True) -> Text:
        """HISTORY: one glyph per reading, newest on the right, each in its
        signal colour; a gap (not heard that second) is a dot."""
        out = Text(no_wrap=True, overflow="crop")
        for glyph, value in bluetooth.sparkline_cells(history):
            colour = signal_colour(value) if live and value is not None else self.palette.muted
            out.append(glyph, style=colour)
        return out

    def _bt_flag(self, flag) -> Text | str:
        if not flag.level:
            return ""
        style = {"alert": f"bold {self.palette.error}",
                 "watch": f"bold {self.palette.warning}"}.get(flag.level, self.palette.muted)
        return Text(flag.text, style=style)

    def _bt_gone(self, device, now: float) -> bool:
        return now - device.last_seen > bluetooth.Watch.GONE_AFTER

    def _bt_reading(self, device, now: float) -> tuple[object, object]:
        """The dBm and distance cells: as heard; greyed once the device has
        gone quiet (the reading is old news); "gone" once it has gone."""
        if self._bt_gone(device, now):
            return "gone", ""
        rssi = "" if device.rssi is None else device.rssi
        distance = bluetooth.distance_text(device.distance)
        if self._bt.quiet(device, now):
            muted = self.palette.muted
            return Text(str(rssi), style=muted), Text(distance, style=muted)
        return rssi, distance

    def _bt_rows(self, devices_, now: float, picked: str = "") -> list[list[object]]:
        rows = []
        for device in devices_:
            dbm, distance = self._bt_reading(device, now)
            rows.append([
                marked(self.palette, device.name, device.address == picked),
                device.guess.short,
                device.maker,
                device.address,
                dbm,
                self._bt_history(device.history, live=not self._bt_gone(device, now)),
                distance,
                bluetooth.clock(device.first_seen),
                bluetooth.ago(now - device.last_seen),
                self._bt_flag(self._bt.flag(device, now)),
            ])
        return rows

    def _bt_picked(self, trackers_only: bool = False):
        """The picked device (None when nothing is — or, on BT TRACKERS, when
        the device picked in BLUETOOTH isn't a tracker), whether the view
        shows only it, and a picked address no longer held at all."""
        key = self.picks.key("bt")
        device = self._bt.get(key) if key else None
        forgotten = key if key and device is None and not trackers_only else ""
        if device is not None and trackers_only and not device.guess.tracker:
            device = None
        return device, device is not None and self.picks.only("bt"), forgotten

    def _bt_subject(self, typed: str, now: float, trackers_only: bool = False):
        """The device the big graph is for, and why: "pick", "typed",
        "nearest", or "lost" (picked, but no longer held)."""
        picked, _only, forgotten = self._bt_picked(trackers_only)
        if picked is not None:
            return picked, "pick"
        if forgotten:
            return None, "lost"
        if typed:
            return self._bt.find(typed, now), "typed"
        return self._bt.nearest(now, trackers_only=trackers_only), "nearest"

    @staticmethod
    def _bt_label(device) -> str:
        return f"{device.name or device.guess.short} · {device.address}"

    def _bt_graph(self, device, how: str, typed: str, now: float, every: float, key: str,
                  trackers_only: bool = False, tall: bool = False):
        """The big signal graph: the device picked, else the one the GRAPH
        box names, else the nearest one heard lately (the nearest tracker,
        on BT TRACKERS)."""
        if device is None:
            if how == "lost":
                return text_panel(
                    self.palette, "Signal",
                    f"{self.picks.key('bt')} has not been heard for "
                    f"{bluetooth.Watch.FORGET_AFTER / 60:.0f} minutes, so its readings "
                    "have been let go. LET GO (above the list) graphs the nearest "
                    "device again.", style=self.palette.warning)
            if how == "typed":
                return text_panel(
                    self.palette, "Signal",
                    f"Nothing heard matches {typed!r} yet. Type a device's name "
                    "(any part of it), its address (or its last four digits) or "
                    "a kind such as airtag, tile or earbuds — or click a device in "
                    "the list.", style=self.palette.warning)
            return text_panel(self.palette, "Signal",
                              "Waiting for the first broadcast…" if not trackers_only
                              else "No trackers heard yet.", style=self.palette.muted)
        reading = device.rssi
        quiet = self._bt.quiet(device, now)
        if quiet:
            heard = f"last heard {bluetooth.ago(now - device.last_seen)}, at {reading} dBm"
        else:
            label = wifi.signal_label(reading) if reading is not None else "—"
            heard = f"now {reading} dBm ({label})  ·  {bluetooth.distance_text(device.distance)}"
        title = f"Signal — {device.name or device.guess.text}  ·  {device.address}  ·  {heard}"
        # Taller when the view shows only this device: every dB shows.
        graph = LineGraph(list(device.history), floor=-100, ceil=-30,
                          width=self._chart_width(), height=12 if tall else 8,
                          label=lambda v: f"{v:.0f} dBm", colour="signal")
        why = {
            "pick": "the device you picked — click another row to graph it",
            "typed": "the device the GRAPH box names — click a row to graph another",
            "nearest": ("the nearest tracker heard" if trackers_only
                        else "the nearest device heard") + " — click a row to graph another",
        }.get(how, "")
        return self._chart(
            title, [graph], "gone" if quiet or reading is None else signal_colour(reading),
            key=key, subtitle=f"newest on the right · a reading every {every:g}s · {why}")

    def _bt_only_headline(self, lit: str, device, now: float, elapsed: float, running: bool,
                          listed: int, noun: str = "device"):
        """The headline when a view shows only one device."""
        watch = self._bt
        gone = self._bt_gone(device, now)
        flag = watch.flag(device, now)
        bits = [f"showing only {device.name or device.guess.text} ({device.address})"]
        if gone:
            bits.append(f"gone — last heard {bluetooth.ago(now - device.last_seen)}")
        elif watch.quiet(device, now):
            bits.append(f"quiet — last heard {bluetooth.ago(now - device.last_seen)}, "
                        f"at {device.rssi} dBm")
        else:
            bits.append(f"now {device.rssi} dBm · {bluetooth.distance_text(device.distance)}")
        if flag.level in ("alert", "watch"):
            bits.append(flag.text)
        bits.append(f"heard {device.heard:,}×")
        others = max(0, listed - (0 if gone else 1))
        bits.append(f"{others} other {noun}{'s' if others != 1 else ''} hidden")
        bits.append(self._run_state(running, elapsed))
        state = ("bad" if flag.level == "alert" else
                 "warn" if flag.level == "watch" or gone or watch.quiet(device, now) else "ok")
        return verdict_line(self.palette, lit, " · ".join(bits), state)

    def _bt_detail(self, device, now: float):
        """Everything about one device, for a view showing only it."""
        return PanelGrid([
            kv_panel(self.palette, f"About {device.name or device.guess.short}",
                     bluetooth.about_rows(device), subtitle="what its broadcasts say"),
            kv_panel(self.palette, "Its signal", bluetooth.signal_rows(self._bt, device, now),
                     subtitle="distance is rough: walls and bodies halve or double it"),
        ], min_width=60, max_cols=2)

    def _bt_bar(self, bar, table, picked, only: bool, forgotten: str, typed: str, how: str,
                now: float, listed: int, noun: tuple[str, str] | None = None) -> None:
        if picked is not None:
            label, lost = self._bt_label(picked), self._bt_gone(picked, now)
        else:
            label, lost = forgotten, bool(forgotten)
        hidden = max(0, listed - (0 if lost else 1)) if only else 0
        bar.update(pick_bar(
            self.palette, "bt", label=label, only=only, lost=lost,
            focused=self.list_focused(table), typed=typed if how == "typed" else "",
            hidden=hidden, noun=noun))

    # -- BLUETOOTH
    def _render_bt(self, headline, graph, bar, table, middle, *, now: float, elapsed: float,
                   every: float, running: bool = True) -> None:
        watch = self._bt
        typed = self.typed_target()
        subject, how = self._bt_subject(typed, now)
        picked, only, forgotten = self._bt_picked()
        key = picked.address if picked is not None else ""
        present = watch.present(now)
        lit = "● BLUETOOTH" if running else "■ BLUETOOTH"
        if only:
            headline.update(self._bt_only_headline(lit, picked, now, elapsed, running,
                                                   len(present)))
        else:
            flags = [watch.flag(d, now) for d in present]
            flagged = sum(1 for f in flags if f.level in ("alert", "watch"))
            parts = [f"{len(present)} device{'s' if len(present) != 1 else ''} nearby"]
            parts += [f"{count} {label}" for label, count in watch.summary(now)][:4]
            if flagged:
                parts.append(f"⚠ {flagged} tracker{'s' if flagged != 1 else ''} flagged")
            parts.append(f"{watch.updates:,} broadcasts via {self._bt_backend}")
            parts.append(self._run_state(running, elapsed))
            headline.update(verdict_line(
                self.palette, lit,
                " · ".join(parts) if present else
                f"listening — nothing heard yet · {self._run_state(running, elapsed)}",
                "warn" if flagged or not present else "ok"))
        graph.update(self._bt_graph(subject, how, typed, now, every, key="bt", tall=only))

        ordered = watch.ordered(now)
        keys = self.steady("bt", [d.address for d in ordered], table)
        by_key = {d.address: d for d in ordered}
        ordered = [by_key[k] for k in keys]
        if only:
            shown, more = [picked], 0
        else:
            shown = ordered[: self.BT_ROWS]
            if picked is not None and picked not in shown:
                shown.append(picked)
            more = len(ordered) - len(shown)
        shown_keys = [d.address for d in shown]
        holding = getattr(table, "holding", False)
        self.show_list(table, table_panel(
            self.palette, "Bluetooth devices, live" + (" — showing only one" if only else ""),
            BT_COLUMNS, self._bt_rows(shown, now, key),
            subtitle=(f"+{more} more · " if more else "")
            + ("the device you picked" if only
               else "order held while the pointer is over the list" if holding
               else "strongest first")
            + f" · updated every {every:g}s · history = the last 14 readings, newest on "
              "the right · distance is rough",
            row_styles=row_styles(self.palette, shown_keys, key), one_line=True,
            shrink=("Name", "Device", "Vendor"),
        ), keys=keys, shown=shown_keys, picked=key, one_line=True)
        self._bt_bar(bar, table, picked, only, forgotten, typed, how, now, len(present))
        if only:
            middle.update(self._bt_detail(picked, now))
        else:
            middle.update(PanelGrid([self._bt_kinds_panel(now), self._bt_trackers_panel(now)],
                                    min_width=60, max_cols=2))

    def _bt_kinds_panel(self, now: float):
        """What is nearby, counted by kind — two kinds to a row."""
        watch = self._bt
        counts = list(watch.summary(now))
        counts += [("gone quiet", len(watch.gone(now))), ("heard in all", len(watch.devices))]
        half = -(-len(counts) // 2)
        left, right = counts[:half], counts[half:] + [("", "")] * (2 * half - len(counts))
        rows = [[a, b, c, d] for (a, b), (c, d) in zip(left, right)]
        return table_panel(self.palette, "Nearby, by kind", ["Kind", "N", "Kind", "N"], rows,
                           subtitle="best guesses from what each broadcasts")

    def _bt_trackers_panel(self, now: float):
        trackers = [d for d in self._bt.ordered(now) if d.guess.tracker]
        if not trackers:
            return text_panel(self.palette, "Trackers",
                              "No item trackers heard (AirTag, Tile, SmartTag, Chipolo, "
                              "Find My and Find Hub tags).", style=self.palette.success)
        rows = []
        for device in trackers[:8]:
            near = max(0.0, device.last_seen - device.near_since)
            dbm, _distance = self._bt_reading(device, now)
            rows.append([device.guess.short, device.address, dbm,
                         self._clock(near), self._bt_flag(self._bt.flag(device, now))])
        return table_panel(self.palette, "Trackers", ["Tracker", "MAC", "dBm", "Near you",
                                                      "Flag"], rows,
                           subtitle="BT TRACKERS has the detail")

    # -- BT TRACKERS
    def _render_bt_trackers(self, headline, graph, bar, table, history, advice, *,
                            now: float, elapsed: float, every: float,
                            running: bool = True) -> None:
        watch = self._bt
        typed = self.typed_target()
        subject, how = self._bt_subject(typed, now, trackers_only=True)
        picked, only, _forgotten = self._bt_picked(trackers_only=True)
        key = picked.address if picked is not None else ""
        present = [d for d in watch.present(now) if d.guess.tracker]
        flags = {d.address: watch.flag(d, now) for d in present}
        alerts = [d for d in present if flags[d.address].level == "alert"]
        watching = [d for d in present if flags[d.address].level == "watch"]
        place = self._bt_place.label if self._bt_place else "working out where you are"
        lit = "● BT TRACKERS" if running else "■ BT TRACKERS"
        if only:
            headline.update(self._bt_only_headline(lit, picked, now, elapsed, running,
                                                   len(present), noun="tracker"))
        else:
            if alerts:
                verdict, state = (f"⚠ {len(alerts)} tracker{'s' if len(alerts) != 1 else ''} "
                                  "heard on more than one network you were on"), "bad"
            elif watching:
                verdict, state = (f"⚠ {len(watching)} tracker{'s' if len(watching) != 1 else ''} "
                                  f"near you for {watch.LINGER / 60:.0f}+ minutes"), "warn"
            elif present:
                verdict, state = (f"{len(present)} tracker{'s' if len(present) != 1 else ''} "
                                  "nearby, none flagged"), "ok"
            else:
                verdict, state = "no item trackers heard", "ok"
            headline.update(verdict_line(
                self.palette, lit,
                f"{verdict} · {len(watch.present(now))} Bluetooth devices in all · here: {place} "
                f"· {self._run_state(running, elapsed)}", state))
        graph.update(self._bt_graph(subject, how, typed, now, every, key="bt-tracker",
                                    trackers_only=True, tall=only))
        rank = {"alert": 0, "watch": 1}
        listed = sorted(present, key=lambda d: (
            rank.get(flags[d.address].level, 2),
            -(d.level if d.level is not None else -200), d.first_seen))
        keys = self.steady("bt", [d.address for d in listed], table)
        by_key = {d.address: d for d in listed}
        listed = [by_key[k] for k in keys]
        if picked is not None and key not in by_key:        # gone: keep its row
            listed.append(picked)
            keys.append(key)
        shown = [picked] if only else listed
        rows = []
        for device in shown:
            flag = flags.get(device.address) or watch.flag(device, now)
            near = max(0.0, device.last_seen - device.near_since)
            dbm, distance = self._bt_reading(device, now)
            rows.append([
                marked(self.palette, device.guess.short, device.address == key),
                device.address, dbm,
                self._bt_history(device.history, live=not self._bt_gone(device, now)),
                distance, self._clock(near), bluetooth.place_count(device),
                self._bt_flag(flag), flag.why,
            ])
        shown_keys = [d.address for d in shown]
        self.show_list(table, table_panel(
            self.palette, "Trackers nearby" + (" — showing only one" if only else ""),
            ["Tracker", "MAC", "dBm", "History", "Distance", "Near you for", "Places",
             "Flag", "Why"], rows,
            subtitle=f"flagged: near you {watch.LINGER / 60:.0f}+ min, or heard on 2+ "
                     "networks you were on · your own tracker shows here too",
            row_styles=row_styles(self.palette, shown_keys, key),
        ), keys=keys, shown=shown_keys, picked=key)
        self._bt_bar(bar, table, picked, only, "", typed, how, now, len(present),
                     noun=("tracker", "trackers"))
        if only:
            history.update(Group(self._bt_detail(picked, now),
                                 self._bt_history_panel(now, ident=key)))
        else:
            history.update(self._bt_history_panel(now))
        advice.update(text_panel(
            self.palette, "If a tracker is following you", BT_ADVICE,
            style=self.palette.warning if alerts or watching else self.palette.muted))

    def _bt_history_panel(self, now: float, ident: str = ""):
        """The last seven days of trackers, from netzilla's local cache —
        only `ident`'s, when a view shows only that tracker."""
        store = getattr(self.services, "store", None)
        logged = store.trackers_logged() if store is not None else []
        if ident:
            logged = [entry for entry in logged if entry["ident"] == ident.upper()]
        if not logged:
            return text_panel(self.palette, "Trackers remembered (7 days)",
                              ("Not remembered yet — a tracker is remembered once a minute "
                               "while you are on a network, with that network's name."
                               if ident else
                               "None yet — trackers heard by BLUETOOTH or BT TRACKERS are "
                               "remembered here for seven days, with the network you were "
                               "on, so one that turns up in two places is flagged."),
                              style=self.palette.muted)
        rows = [[entry["kind"], entry["ident"], len(set(entry["places"])),
                 ", ".join(entry["labels"][:3]) + (" …" if len(entry["labels"]) > 3 else ""),
                 bluetooth.clock(entry["first"]) if now - entry["first"] < 86400
                 else time.strftime("%a %H:%M", time.localtime(entry["first"])),
                 bluetooth.ago(now - entry["last"])]
                for entry in logged[:15]]
        return table_panel(
            self.palette, "Trackers remembered (7 days)",
            ["Tracker", "MAC", "Places", "Networks", "First seen", "Last seen"], rows,
            subtitle="most trackers change address daily · kept in netzilla's local "
                     "cache only")

    # ------------------------------------------------------------- misc
    async def _ensure_scan(self) -> tuple[list[dict], str]:
        """CHANNELS needs a scan; reuse the last one if there is one,
        otherwise take a new one."""
        if self._last:
            return self._last, "cached"
        return await self._scan("auto")

    async def _tools(self) -> None:
        await self.begin("Checking Wi-Fi tools…")
        names = await self._load_interfaces()
        from ..local.runner import have

        rows = [
            ("Wireless interfaces", ", ".join(names) or "none found"),
            ("nmcli (SCAN, LIVE AIR — no root)", have("nmcli")),
            ("iw (exact dBm, LINK HEALTH)", have("iw")),
            ("rfkill (radio block check)", have("rfkill")),
            ("ping (DEVICES)", have("ping")),
            ("ss (TRAFFIC)", have("ss") or have("netstat")),
            ("tshark (PACKETS)", capture.find_tool("tshark") or False),
        ]
        await self.finish()
        await self.push(
            verdict_line(
                self.palette, "Wi-Fi",
                "ready — SCAN should work" if names and (have("nmcli") or have("iw"))
                else "no wireless interface or scan tool found",
                "ok" if names and (have("nmcli") or have("iw")) else "warn",
            )
        )
        await self.push(kv_panel(self.palette, "What netzilla found", rows))
        bt_rows, bt_problem = await bluetooth.tool_report()
        await self.push(
            verdict_line(
                self.palette, "Bluetooth",
                "ready — BLUETOOTH and BT TRACKERS should work" if not bt_problem
                else f"not ready — {bt_problem}",
                "ok" if not bt_problem else "warn",
            )
        )
        await self.push(kv_panel(self.palette, "Bluetooth", bt_rows))
        await self.push(
            text_panel(self.palette, "Setting up scanning",
                       wifi.INSTALL_HINTS + "\n\nPACKETS uses the CAPTURE tab's "
                       "permission — see CAPTURE → TOOL CHECK / FIX PERMISSIONS.\n\n"
                       + bluetooth.INSTALL_HINTS,
                       style=self.palette.accent)
        )
        await self.push_warning(
            "Only your own networks",
            "A passive Wi-Fi scan is legal and unremarkable anywhere. DEVICES, "
            "PORTS and PACKETS are for networks you run or are allowed to "
            "test — on anyone else's, look, do not act.",
        )


BT_ADVICE = (
    "An iPhone warns on its own about an AirTag or Find My accessory moving with "
    "you. On Android: Settings → Safety & emergency → Unknown tracker alerts → "
    "Scan now finds one nearby and can make it play a sound. A tracker that is "
    "yours — on your keys, bag or car — shows here too. If one that isn't yours "
    "keeps turning up and you feel unsafe, contact the police before disabling "
    "it; they may want it intact."
)

# BLUETOOTH's table.
BT_COLUMNS = ["Name", "Device", "Vendor", "MAC", "dBm", "History", "Distance",
              "First seen", "Last seen", "Flag"]


def have_iw() -> bool:
    from ..local.runner import have

    return have("iw")
