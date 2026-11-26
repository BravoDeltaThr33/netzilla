"""INT — pick a local interface and watch what is moving across it.

Everything here runs inside netzilla's own interface rather than handing the
terminal to a full-screen program:

  LIVE RATES      /proc/net/dev sampled twice — netzilla's stand-in for nload,
                  which has no batch mode and cannot be embedded in a pane
  IFTOP SNAPSHOT  iftop -t: its own text mode, per-connection totals (root)
  VNSTAT REPORT   vnstat's JSON/plain output: history, not a live view
  BMON SNAPSHOT   bmon -o format: its scriptable module, captured for a window

The interface list comes from iproute2 (`ip -o link show`), because ifconfig
is not installed by default on current Ubuntu, Mint or Debian.
"""

from __future__ import annotations

import asyncio
import time

from textual.widgets import Static

from ..graphics.charts import LineGraph
from ..local import bwtools, netif
from ..local.wifitools import nice_ceiling
from ..render import kv_panel, table_panel, text_panel, verdict_line
from ..validators import ValidationError
from .base import Action, Field, LookupPane

VNSTAT_MODES = ("summary", "daily", "monthly", "hourly", "top days")


class InterfacesPane(LookupPane):
    PANE_TITLE = "INTERFACE MONITORING"
    DESCRIPTION = (
        "Pick one of this machine's interfaces and watch it. LIVE RATES is "
        "built in and needs nothing installed; IFTOP, VNSTAT and BMON wrap "
        "those tools in the modes that print a report rather than taking over "
        "the screen. No API, no key — everything here is local."
    )
    FIELDS = (
        Field("iface", "Interface", "press REFRESH INTERFACES", choices=()),
        # Real values, not placeholders: the placeholder looked like a default
        # but left the field empty, so every action fell back to its own.
        Field("secs", "Seconds", "10", value="10", width=16),
        Field("every", "Refresh every (s)", "blank = 1", width=22),
        Field(
            "mode", "vnstat report", "summary", value="summary",
            width=26, choices=VNSTAT_MODES,
        ),
    )
    ACTIONS = (
        Action("rates", "LIVE RATES"),
        Action("iftop", "IFTOP SNAPSHOT", primary=False),
        Action("vnstat", "VNSTAT REPORT", primary=False),
        Action("bmon", "BMON SNAPSHOT", primary=False),
        Action("refresh", "REFRESH INTERFACES", primary=False),
        Action("tools", "TOOL CHECK", primary=False),
    )

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._interfaces: list[dict] = []

    async def on_mount(self) -> None:
        # Fill the dropdown before the user touches anything.
        self.run_worker(self._load_interfaces(), group=f"int-{id(self)}")

    # ----------------------------------------------------------- interfaces
    async def _load_interfaces(self) -> tuple[list[dict], str]:
        found, source = await netif.interfaces()
        self._interfaces = found
        names = [i["name"] for i in found]
        current = self.field("iface")
        self.set_choices(
            "iface", names, current if current in names else netif.pick_default(found)
        )
        return found, source

    def _iface(self) -> str:
        name = self.field("iface")
        if not name:
            raise ValidationError(
                "Pick an interface from the dropdown first. If it is empty, "
                "press REFRESH INTERFACES."
            )
        return name

    def _seconds(self, default: int = 10, low: int = 2, high: int = 120) -> int:
        raw = self.field("secs") or str(default)
        try:
            value = int(float(raw))
        except ValueError:
            raise ValidationError("Seconds must be a number, e.g. 10.")
        if not low <= value <= high:
            raise ValidationError(f"Seconds must be between {low} and {high}.")
        return value

    # -------------------------------------------------------------- dispatch
    async def execute(self, action: str) -> None:
        if action == "refresh":
            await self._refresh()
        elif action == "tools":
            await self._tools()
        elif action == "rates":
            await self._rates()
        elif action == "iftop":
            await self._iftop()
        elif action == "vnstat":
            await self._vnstat()
        elif action == "bmon":
            await self._bmon()

    async def _refresh(self) -> None:
        await self.begin("Reading the interface list…")
        found, source = await self._load_interfaces()
        await self.finish()
        if not found:
            await self.push_error(
                "No interfaces found",
                "Neither 'ip' nor 'ifconfig' could list interfaces, and "
                f"{netif.PROC_NET_DEV} was unreadable. On a normal Linux system "
                "iproute2 is always present:\n    sudo apt install iproute2",
            )
            return
        await self.push(
            verdict_line(
                self.palette, "Interfaces",
                f"{len(found)} found, {sum(1 for i in found if i['state'] == 'UP')} up",
                "ok",
            )
        )
        await self.push(
            table_panel(
                self.palette, "Local interfaces",
                netif.INTERFACE_COLUMNS,
                netif.interface_rows(found),
                subtitle=f"source: {source}",
            )
        )

    # ------------------------------------------------------------ live rates
    async def _rates(self) -> None:
        """A real live view: the same panels, rewritten every second."""
        iface = self._iface()
        seconds = self._seconds(10, 2, 300)
        every = self._every(1.0)
        first = netif.read_counters()
        if not first:
            await self.begin("Reading interface counters…")
            await self.finish()
            await self.push_error(
                "No counters",
                f"{netif.PROC_NET_DEV} could not be read.\n\n"
                "On Linux this should always work. macOS has no /proc/net/dev, "
                "so LIVE RATES is Linux-only — the rest of this tab still works "
                "there.",
            )
            return

        await self.begin(f"Live — updating every {every:g}s for {seconds}s…")
        headline = Static(classes="result-panel")
        graphs = Static(classes="result-panel")
        detail = Static(classes="result-panel")
        table = Static(classes="result-panel")
        for widget in (headline, graphs, detail, table):
            await self.push_widget(widget)

        previous = first
        started = last_at = time.monotonic()
        peak_rx = peak_tx = 0.0
        rates: list[dict] = []
        down_history: list[float] = []
        up_history: list[float] = []
        while True:
            left = seconds - (time.monotonic() - started)
            if left <= 0:
                break
            await asyncio.sleep(min(every, left))
            now_at = time.monotonic()
            window = max(0.001, now_at - last_at)
            last_at = now_at
            current = netif.read_counters()
            rates = netif.rates_between(previous, current, window)
            previous = current
            mine = next((r for r in rates if r["name"] == iface), None)
            if mine:
                peak_rx = max(peak_rx, mine["rx_mbps"])
                peak_tx = max(peak_tx, mine["tx_mbps"])
                down_history.append(mine["rx_mbps"])
                up_history.append(mine["tx_mbps"])
                del down_history[:-600], up_history[:-600]
                graphs.update(self._rate_graphs(iface, down_history, up_history, every))
                headline.update(
                    verdict_line(
                        self.palette, iface,
                        f'{mine["rx_mbps"]:.2f} Mbit/s down · '
                        f'{mine["tx_mbps"]:.2f} Mbit/s up   '
                        f'(peak {peak_rx:.2f} / {peak_tx:.2f})',
                        "ok" if mine["rx_mbps"] + mine["tx_mbps"] > 0.01 else "info",
                    )
                )
                detail.update(
                    kv_panel(
                        self.palette, f"Live throughput — {iface}",
                        netif.rate_summary(mine),
                        subtitle=f"updating every {every:g}s · /proc/net/dev",
                    )
                )
            table.update(
                table_panel(
                    self.palette, "All interfaces, latest interval",
                    ["Interface", "In Mbit/s", "Out Mbit/s", "Load",
                     "Pkts/s in/out", "Errors", "Drops"],
                    netif.rate_rows(rates, highlight=iface),
                    subtitle=f"{left:.0f}s left in this run",
                )
            )
            self.progress(
                f"Live on {iface} — {left:.0f}s left. Press LIVE RATES again to "
                "restart, or any other button to stop."
            )
        await self.finish()

        elapsed = time.monotonic() - started
        summary = netif.window_summary(
            first, previous, elapsed, iface, peak_rx, peak_tx
        )
        if summary:
            await self.push(
                kv_panel(
                    self.palette, f"Over the whole {elapsed:.0f}s window — {iface}",
                    summary, subtitle="averages and peaks, not just the last tick",
                )
            )
        hot = [r for r in rates if r["errors"] or r["drops"]]
        if hot:
            await self.push_warning(
                "Errors or drops during the sample",
                "These counters moved while netzilla watched: "
                + ", ".join(r["name"] for r in hot)
                + ". Rising errors point at cabling, duplex mismatch or a "
                "failing SFP; drops usually mean the queue or the CPU is behind.",
            )

    def _rate_graphs(self, iface: str, down: list[float], up: list[float], every: float):
        width = self.graph_width()

        def graph(values: list[float], height: int) -> LineGraph:
            peak = nice_ceiling(max(values or [0.0]))
            return LineGraph(values, floor=0.0, ceil=peak, width=width, height=height,
                             label=lambda v: f"{round(v, 2):g} Mb/s",
                             colour=self.palette.accent)

        return self.graphs_panel(
            f"Throughput, live — {iface}",
            [(f"Download — {down[-1]:.2f} Mbit/s" if down else "Download", "int-down",
              graph(down, 6), self.palette.accent),
             (f"Upload — {up[-1]:.2f} Mbit/s" if up else "Upload", "int-up",
              graph(up, 4), self.palette.accent)],
            subtitle=f"a column every {every:g}s, newest on the right",
        )

    # ----------------------------------------------------------------- iftop
    async def _iftop(self) -> None:
        iface = self._iface()
        seconds = self._seconds(10, 2, 120)
        await self.begin(f"Checking how iftop can be run…")
        prefix, why = await bwtools.elevation("iftop")
        if prefix is None:
            await self.finish()
            await self._needs_root("iftop", iface, seconds, why)
            return
        self.progress(
            f"iftop -t on {iface} for {seconds}s ({why}) — collecting "
            "per-connection totals…"
        )
        result = await bwtools.iftop_snapshot(iface, seconds, prefix=prefix)
        await self.finish()
        if result.missing_tool:
            await self._missing("iftop")
            return
        if not result.output:
            if bwtools.needs_root_error(result):
                await self._needs_root("iftop", iface, seconds, why)
                return
            await self.push_error(
                "iftop returned nothing",
                result.error or "No output. The interface may have seen no traffic.",
            )
            return
        await self.push(
            text_panel(
                self.palette, f"iftop — {iface} over {seconds}s", result.output,
                subtitle=f"local · iftop -t · {why}",
            )
        )
        if result.error:
            await self.push_warning("iftop also said", result.error)

    async def _needs_root(
        self, tool: str, iface: str, seconds: int, why: str = ""
    ) -> None:
        await self.push_error(
            f"{tool} cannot open the interface",
            f"{tool} puts the interface in promiscuous mode, which an ordinary "
            f"user may not do.\n\nChecked: {why}.\n\n"
            "The one-time fix — after this, netzilla runs it with no sudo at all:\n"
            f"    sudo setcap cap_net_raw+ep $(which {tool})\n\n"
            "Or start the whole app with root:\n"
            "    sudo netzilla\n\n"
            "Or run it yourself in another terminal:\n"
            f"    sudo {tool} -t -s {seconds} -i {iface}\n\n"
            "LIVE RATES needs none of this and shows per-interface throughput now.",
        )

    # ---------------------------------------------------------------- vnstat
    async def _vnstat(self) -> None:
        iface = self._iface()
        mode = self.field("mode") or "summary"
        await self.begin(f"Reading vnstat history for {iface} ({mode})…")
        payload, why = await bwtools.vnstat_json(iface, mode)
        if payload is None:
            # Either vnstat is missing, has no data yet, or predates --json.
            text = await bwtools.vnstat_text(iface, mode)
            await self.finish()
            if text.missing_tool:
                await self._missing("vnstat")
                return
            hint = bwtools.vnstat_service_hint(text.output or text.error or why)
            if text.output:
                await self.push(
                    text_panel(
                        self.palette, f"vnstat — {iface} ({mode})", text.output,
                        subtitle="local · vnstat plain output",
                    )
                )
            if hint:
                await self.push_warning("vnstat has nothing to show yet", hint)
            elif not text.output:
                await self.push_error("vnstat", text.error or why)
            return

        await self.finish()
        summary = bwtools.vnstat_summary(payload, iface)
        if summary:
            await self.push(
                kv_panel(
                    self.palette, f"vnstat totals — {iface}", summary,
                    subtitle="local · vnstat database",
                )
            )
        if mode != "summary":
            rows = bwtools.vnstat_rows(payload, iface, mode)
            if rows:
                await self.push(
                    table_panel(
                        self.palette, f"vnstat {mode} — {iface}",
                        ["Period", "Received", "Sent", "Total"], rows,
                        subtitle="newest first",
                    )
                )
            else:
                await self.push_warning(
                    "No history for that period yet",
                    "vnstat only has data from the moment its service started "
                    "collecting. Daily totals appear the same day; monthly "
                    "totals fill in as the month goes on.",
                )

    # ------------------------------------------------------------------ bmon
    async def _bmon(self) -> None:
        iface = self._iface()
        seconds = self._seconds(10, 2, 120)
        await self.begin(f"bmon on {iface} for {seconds}s…")
        started = time.monotonic()
        result = await bwtools.bmon_snapshot(iface, seconds)
        elapsed = time.monotonic() - started
        # The kernel's own counters name bmon's unlabelled columns.
        known = netif.counter_labels(netif.read_counters(), iface)
        await self.finish()
        if result.missing_tool:
            await self._missing("bmon")
            return
        if not result.output:
            await self.push_error(
                "bmon returned nothing",
                result.error
                or "bmon produced no output in the capture window. Its output "
                "modules vary between builds; LIVE RATES covers the same "
                "ground with no dependency.",
            )
            return

        rows, how = bwtools.bmon_report(result.output, iface, elapsed, known)
        if rows:
            await self.push(
                kv_panel(
                    self.palette, f"bmon — {iface}", rows,
                    subtitle=how,
                )
            )
        else:
            legacy = bwtools.bmon_rows(result.output, iface)
            if legacy:
                await self.push(
                    table_panel(
                        self.palette, f"bmon counters — {iface}",
                        ["Interface", "RX bytes", "TX bytes", "RX packets",
                         "TX packets"],
                        legacy, subtitle="from bmon's key=value output",
                    )
                )
            else:
                await self.push_warning(
                    "bmon's numbers could not be identified",
                    "This build's output does not line up with the kernel "
                    "counters, so netzilla will not guess at what the columns "
                    "mean. The raw capture is below, and LIVE RATES gives the "
                    "same figures with units attached.",
                )
        tail = "\n".join(result.output.splitlines()[-8:])
        await self.push(
            text_panel(
                self.palette, f"bmon raw output — last lines", tail,
                subtitle="cumulative counters, one line per sample",
            )
        )

    # ------------------------------------------------------------ tool check
    async def _tools(self) -> None:
        await self.begin("Checking which bandwidth tools are installed…")
        prefix, why = await bwtools.elevation("iftop")
        await self.finish()
        rows = []
        missing = []
        for tool, present, purpose, hint in bwtools.tools_status():
            rows.append([
                tool, "available" if present else "NOT INSTALLED", purpose,
            ])
            if not present and tool != "nload":
                missing.append(hint)
        await self.push(
            table_panel(
                self.palette, "Bandwidth tools", ["Tool", "Status", "What it adds"],
                rows,
                subtitle="nload is optional — LIVE RATES replaces it",
            )
        )
        await self.push(
            kv_panel(
                self.palette, "This session",
                [
                    ("Running as root", bwtools.is_root()),
                    ("iftop usable", bwtools.is_root() or "only with setcap/sudo"),
                    ("Interfaces found", len(self._interfaces) or "press REFRESH"),
                ],
                subtitle="iftop is the only action here that needs root",
            )
        )
        if missing:
            await self.push(
                text_panel(
                    self.palette, "Install the missing ones",
                    "\n".join(dict.fromkeys(missing)),
                    style=self.palette.accent,
                )
            )

    async def _missing(self, tool: str) -> None:
        await self.push_error(
            f"{tool} is not installed",
            f"Install it with:\n    {bwtools.INSTALL_HINTS[tool]}\n\n"
            "LIVE RATES works without any of these tools.",
        )
