"""FLOW — live connections and traffic, netzilla's take on Sniffnet.

A monitor of this machine's own network activity: which sockets are open, who
they talk to, on what service, and how hard the interfaces are working.
CONNECTIONS lists them; TALKERS ranks remote hosts and resolves the external
ones to ASN and geolocation; SERVICES breaks traffic down by application;
WATCH refreshes live; BLACKLIST flags connections to a list you supply.

For packets on the wire rather than sockets on this host, that is the CAPTURE
tab — SAVE PCAP here hands straight to it.
"""

from __future__ import annotations

import asyncio
import time

from textual.widgets import Static

from .. import hostos
from ..clients import ip_api
from ..local import devices, flows, netif
from ..render import kv_panel, table_panel, text_panel, verdict_line
from ..validators import ValidationError
from .base import Action, Field, LookupPane


class FlowPane(LookupPane):
    PANE_TITLE = "CONNECTIONS & TRAFFIC"
    DESCRIPTION = (
        "This machine's own live connections and throughput. CONNECTIONS lists "
        "every socket; TALKERS ranks remote hosts — external ones get ASN, geo "
        "and reverse DNS, LAN ones get vendor, hostname and device type; "
        "SERVICES groups traffic by application; WATCH refreshes live; "
        "BLACKLIST flags connections to IPs you list. It reads this machine's "
        "own connection table — no key needed. For on-the-wire packets, use "
        "CAPTURE."
    )
    FIELDS = (
        Field(
            "blacklist", "Blacklist file  (IPs / CIDRs)",
            "~/badips.txt", width=40,
        ),
        Field("secs", "WATCH seconds", "20", value="20", width=16),
        Field("every", "Refresh every (s)", "blank = 1", width=22),
        Field(
            "filter", "Filter  (IP or process name)",
            "leave blank for everything", width=34,
        ),
    )
    ACTIONS = (
        Action("connections", "CONNECTIONS"),
        Action("talkers", "TOP TALKERS"),
        Action("services", "SERVICES"),
        Action("watch", "WATCH LIVE"),
        Action("intensity", "BANDWIDTH", primary=False),
        Action("blacklist", "BLACKLIST", primary=False),
        Action("tools", "TOOL CHECK", primary=False),
    )

    WATCH_CAP = 10 * 60

    # ------------------------------------------------------------ dispatch
    async def execute(self, action: str) -> None:
        if action == "connections":
            await self._connections()
        elif action == "talkers":
            await self._talkers()
        elif action == "services":
            await self._services()
        elif action == "watch":
            await self._watch()
        elif action == "intensity":
            await self._intensity()
        elif action == "blacklist":
            await self._blacklist()
        elif action == "tools":
            await self._tools()

    # ------------------------------------------------------------- helpers
    def _filtered(self, conns: list[dict]) -> list[dict]:
        needle = self.field("filter").lower()
        if not needle:
            return conns
        return [
            c for c in conns
            if needle in c["remote_ip"].lower()
            or needle in c["local_ip"].lower()
            or needle in (c["process"] or "").lower()
        ]

    async def _read(self) -> list[dict] | None:
        conns, error = await flows.snapshot()
        if error:
            await self.finish()
            await self.push_error("Could not read connections", error)
            return None
        return conns

    # --------------------------------------------------------- connections
    async def _connections(self) -> None:
        await self.begin("Reading the connection table…")
        conns = await self._read()
        if conns is None:
            return
        shown = self._filtered(conns)
        await self.finish()
        await self.push(
            verdict_line(
                self.palette, "Connections",
                f"{len(shown)} shown of {len(conns)}"
                + (f" (filtered by {self.field('filter')!r})" if self.field("filter") else ""),
                "ok",
            )
        )
        await self.push(kv_panel(self.palette, "Snapshot", flows.summary(conns)))
        await self.push(
            table_panel(
                self.palette, "Sockets",
                ["Proto", "Local", "Remote", "Service", "State", "Process"],
                flows.connection_rows(shown),
                subtitle=f"this host's own sockets, via {flows.source_label()}",
            )
        )

    # ------------------------------------------------------------- talkers
    async def _talkers(self) -> None:
        await self.begin("Finding the busiest remote hosts…")
        conns = await self._read()
        if conns is None:
            return
        hosts = flows.by_remote_host(self._filtered(conns))
        if not hosts:
            await self.finish()
            await self.push_warning(
                "No established connections",
                "Nothing is talking to a remote host right now. Open something "
                "that uses the network and try again.",
            )
            return
        self.progress("Resolving hosts — ASN and geo outside, device identity on the LAN…")
        enriched = await self._resolve(hosts[:12])
        await self.finish()
        await self.push(
            verdict_line(
                self.palette, "Top talkers",
                f"{len(hosts)} remote hosts, {sum(h['connections'] for h in hosts)} "
                "connections", "ok",
            )
        )
        await self.push(
            table_panel(
                self.palette, "Remote hosts, busiest first",
                ["Remote host", "Hostname", "Conns", "Ports", "Owner",
                 "Location / device", "Process"],
                enriched,
                subtitle="external: ASN + geo (ip-api) + reverse DNS · LAN: vendor + name + device",
            )
        )

    async def _resolve(self, hosts: list[dict]) -> list[list[object]]:
        import ipaddress

        def loopback(ip: str) -> bool:
            try:
                return ipaddress.ip_address(ip).is_loopback
            except ValueError:
                return False

        lan_ips = [h["remote_ip"] for h in hosts
                   if not h["external"] and not loopback(h["remote_ip"])]
        known: dict[str, dict] = {}
        if lan_ips:
            try:
                known = await devices.identify_ips(lan_ips)
            except Exception:
                known = {}
        servers = devices.nameservers()
        externals = [h["remote_ip"] for h in hosts if h["external"]]
        names = await asyncio.gather(
            *(devices.reverse_dns(ip, servers) for ip in externals),
            return_exceptions=True,
        )
        ptr = {ip: (name if isinstance(name, str) else "")
               for ip, name in zip(externals, names)}

        rows = []
        for host in hosts:
            ip = host["remote_ip"]
            if host["external"]:
                asn, org, location = await self._geo(ip)
                hostname = ptr.get(ip, "").rstrip(".")
                owner = f"{asn} {org}".strip() or "—"
                where = location or "—"
            elif loopback(ip):
                hostname, owner, where = "localhost", "this machine", "loopback"
            else:
                dev = known.get(ip, {})
                hostname = devices.display_name(dev)
                vendor = devices.vendor_cell(dev)
                owner = f"LAN · {vendor}" if vendor else "LAN"
                where = dev.get("device") or "LAN device"
            rows.append([
                ip,
                hostname[:40] or "—",
                host["connections"],
                ", ".join(str(p) for p in host["ports"][:4]),
                owner,
                where,
                ", ".join(host["processes"][:2]) or "—",
            ])
        return rows

    async def _geo(self, ip: str) -> tuple[str, str, str]:
        try:
            result = await ip_api.lookup(self.services, ip)
        except Exception:
            return "", "", ""
        if not result.ok:
            return "", "", ""
        data = result.data or {}
        asn = (data.get("as") or "").split()[0] if data.get("as") else ""
        org = data.get("isp") or data.get("org") or ""
        location = ", ".join(
            part for part in (data.get("city"), data.get("countryCode")) if part
        )
        return asn, org[:22], location

    # ------------------------------------------------------------ services
    async def _services(self) -> None:
        await self.begin("Grouping by application service…")
        conns = await self._read()
        if conns is None:
            return
        services = flows.by_service(self._filtered(conns))
        await self.finish()
        if not services:
            await self.push_warning(
                "Nothing established", "No active connections to group."
            )
            return
        total = sum(s["count"] for s in services) or 1
        rows = [
            [s["service"], s["proto"].upper(), s["count"],
             f'{100 * s["count"] / total:.0f}%']
            for s in services
        ]
        await self.push(verdict_line(self.palette, "Services", f"{len(services)} in use", "ok"))
        await self.push(
            table_panel(
                self.palette, "Traffic by application service",
                ["Service", "Proto", "Connections", "Share"], rows,
                subtitle="named by the well-known port on either end",
            )
        )

    # ------------------------------------------------------------- watch
    async def _watch(self) -> None:
        seconds = self._seconds(20, 4, self.WATCH_CAP)
        every = self._every(1.0)
        await self.begin(f"Live — refreshing every {every:g}s for {seconds}s…")
        headline = Static(classes="result-panel")
        graph = Static(classes="result-panel")
        summary = Static(classes="result-panel")
        table = Static(classes="result-panel")
        for widget in (headline, graph, summary, table):
            await self.push_widget(widget)

        started = time.monotonic()
        peak = 0
        counts: list[float] = []
        while True:
            left = seconds - (time.monotonic() - started)
            if left <= 0:
                break
            conns, error = await flows.snapshot()
            if error:
                await self.finish()
                await self.push_error("Could not read connections", error)
                return
            shown = self._filtered(conns)
            live = flows.established(shown)
            peak = max(peak, len(live))
            counts.append(float(len(live)))
            graph.update(self._count_graph(counts, every))
            headline.update(
                verdict_line(
                    self.palette, "Live",
                    f"{len(live)} established · {len(shown)} sockets · peak "
                    f"{peak} · {left:.0f}s left",
                    "ok" if live else "info",
                )
            )
            summary.update(
                kv_panel(self.palette, "Now", flows.summary(shown),
                         subtitle=f"refreshing every {every:g}s")
            )
            table.update(
                table_panel(
                    self.palette, "Established connections",
                    ["Proto", "Local", "Remote", "Service", "State", "Process"],
                    flows.connection_rows(live, limit=40),
                    subtitle="newest snapshot",
                )
            )
            self.progress(
                f"Watching — {left:.0f}s left. Any other button stops it."
            )
            await asyncio.sleep(min(every, max(0.1, left)))
        await self.finish()
        await self.push(
            verdict_line(self.palette, "Stopped",
                         f"peaked at {peak} established connections", "info")
        )

    def _count_graph(self, counts: list[float], every: float):
        from ..graphics.charts import LineGraph
        from ..local.wifitools import nice_ceiling

        width = self.graph_width()
        top = nice_ceiling(max(counts or [1.0]))
        return self.graphs_panel(
            "Established connections, live",
            [(f"Now {int(counts[-1]) if counts else 0}", "flow-count",
              LineGraph(counts[-width:], floor=0.0, ceil=top, width=width, height=5,
                        label=lambda v: f"{v:.0f}", colour=self.palette.accent),
              self.palette.accent)],
            subtitle=f"a column every {every:g}s, newest on the right",
        )

    # ---------------------------------------------------------- bandwidth
    async def _intensity(self) -> None:
        await self.begin("Sampling interface throughput…")
        rates = await flows.interface_intensity(seconds=2.0)
        await self.finish()
        if not rates:
            await self.push_warning(
                "No throughput to show",
                f"{netif.counter_source()} gave nothing.",
            )
            return
        await self.push(
            table_panel(
                self.palette, "Bandwidth right now",
                ["Interface", "In Mbit/s", "Out Mbit/s", "Load"],
                flows.intensity_rows(rates),
                subtitle=f"two {netif.counter_source()} samples, two seconds apart",
            )
        )

    # ---------------------------------------------------------- blacklist
    async def _blacklist(self) -> None:
        path = self.field("blacklist")
        if not path:
            raise ValidationError(
                "Put the path of a blacklist file in the BLACKLIST box — one "
                "IP or CIDR per line, # for comments. Then press BLACKLIST."
            )
        from pathlib import Path

        try:
            text = Path(path).expanduser().read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ValidationError(f"Could not read {path}: {exc}")
        blacklist = flows.load_blacklist(text)
        if not blacklist:
            raise ValidationError(
                f"{path} had no usable IPs or CIDRs in it. One per line, e.g.\n"
                "    203.0.113.7\n    198.51.100.0/24"
            )
        await self.begin(f"Checking connections against {len(blacklist)} entries…")
        conns = await self._read()
        if conns is None:
            return
        hits = flows.blacklist_hits(conns, blacklist)
        await self.finish()
        if not hits:
            await self.push(
                verdict_line(
                    self.palette, "Blacklist",
                    f"clean — no connection matched any of the "
                    f"{len(blacklist)} entries", "ok",
                )
            )
            return
        await self.push(
            verdict_line(
                self.palette, "Blacklist",
                f"{len(hits)} connection(s) to blacklisted hosts", "warn",
            )
        )
        await self.push(
            table_panel(
                self.palette, "Connections to blacklisted IPs",
                ["Proto", "Local", "Remote", "Service", "State", "Process"],
                flows.connection_rows(hits),
                subtitle="these matched your list — investigate the process",
            )
        )

    # ------------------------------------------------------------- tools
    async def _tools(self) -> None:
        from ..local.runner import have

        await self.begin("Checking…")
        conns, error = await flows.snapshot()
        await self.finish()
        if hostos.is_windows():
            rows = [
                ("Windows connection table (IP Helper API)", not error),
                ("netstat (fallback)", have("netstat")),
            ]
            names = ("Windows names the process behind every connection, and "
                     "no Administrator is needed for it.")
        elif hostos.is_macos():
            rows = [
                ("netstat (every socket)", have("netstat")),
                ("lsof (process names)", have("lsof")),
            ]
            names = ("lsof names the process behind a connection only for your "
                     "own processes. To see every process, run netzilla as root:\n"
                     "    sudo netzilla")
        else:
            rows = [
                ("ss (iproute2)", have("ss")),
                ("netstat (fallback)", have("netstat")),
            ]
            names = ("ss shows the owning process only for sockets you own. To see "
                     "every process behind a connection, run netzilla with sudo — "
                     "or unlock a session on the CAPTURE tab first, which this tab "
                     "uses too.")
        rows += [
            ("Readable right now", f"{len(conns)} sockets" if not error else error),
            ("Geo/ASN source", "ip-api (keyless, 45 req/min)"),
            ("PCAP export", "use the CAPTURE tab's SAVE PCAP"),
        ]
        await self.push(
            verdict_line(self.palette, "Flow monitor",
                         "ready" if not error else "connection table unreadable",
                         "ok" if not error else "warn")
        )
        await self.push(kv_panel(self.palette, "What netzilla found", rows))
        await self.push(
            text_panel(self.palette, "Reading process names", names,
                       style=self.palette.muted)
        )

    def _seconds(self, default: int, low: int, high: int) -> int:
        raw = self.field("secs") or str(default)
        try:
            value = int(float(raw))
        except ValueError:
            raise ValidationError(f"Seconds must be a whole number, e.g. {default}.")
        if not low <= value <= high:
            raise ValidationError(f"Seconds must be between {low} and {high}.")
        return value
