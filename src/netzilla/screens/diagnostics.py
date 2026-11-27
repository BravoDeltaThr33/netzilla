"""DIAGNOSTICS — ping, traceroute, mtr and TCP port checks. All local."""

from __future__ import annotations

from .. import hostos
from ..local import cymru, history, mtu, netdiag, ntp
from ..render import kv_panel, table_panel, text_panel, verdict_line
from ..validators import ValidationError, valid_host
from .base import Action, Field, LookupPane


class DiagnosticsPane(LookupPane):
    PANE_TITLE = "DIAGNOSTICS"
    DESCRIPTION = (
        "The tools you already reach for, wrapped so they never block the "
        "interface. Mostly local; TRACEROUTE overlays each hop's AS via Team "
        "Cymru's DNS service and remembers the path so it can flag reroutes. "
        "PATH MTU finds tunnel clamping; NTP checks clock drift."
    )
    FIELDS = (
        Field("host", "Host or IP", "1.1.1.1"),
        Field("count", "Ping count", "4", width=16),
        Field("port", "TCP port(s)", "443,80,22", width=20),
    )
    ACTIONS = (
        Action("ping", "PING"),
        Action("trace", "TRACEROUTE +ASN", primary=False),
        Action("mtr", "MTR REPORT", primary=False),
        Action("port", "PORT CHECK", primary=False),
        Action("mtu", "PATH MTU", primary=False),
        Action("ntp", "NTP DRIFT", primary=False),
        Action("tools", "TOOL CHECK", primary=False),
    )

    async def execute(self, action: str) -> None:
        if action == "tools":
            await self._tools()
            return
        if action == "ntp":
            await self._ntp()
            return

        host = valid_host(self.field("host"))

        if action == "mtu":
            await self._mtu(host)
            return

        if action == "ping":
            count = self._int(self.field("count") or "4", "Ping count", 1, 30)
            await self.begin(f"ping {'-n' if hostos.is_windows() else '-c'} {count} {host}…")
            result = await netdiag.ping(host, count)
            await self.finish()
            if result.missing_tool:
                await self._missing("ping", "iputils-ping")
                return
            stats = netdiag.parse_ping(result.output)
            if stats:
                loss = float(stats.get("loss", 100))
                state = "ok" if loss == 0 else "warn" if loss < 50 else "bad"
                avg = stats.get("rtt_avg")
                summary = (
                    f'{stats.get("rx", "?")}/{stats.get("tx", "?")} received · '
                    f"{loss:.0f}% loss"
                    + (f" · avg {avg} ms" if avg else "")
                )
                await self.push(verdict_line(self.palette, host, summary, state))
                await self.push(
                    kv_panel(
                        self.palette,
                        f"Ping statistics — {host}",
                        [
                            ("Transmitted", stats.get("tx")),
                            ("Received", stats.get("rx")),
                            ("Packet loss", f'{stats.get("loss", "?")}%'),
                            ("RTT min", f'{stats.get("rtt_min", "—")} ms'),
                            ("RTT avg", f'{stats.get("rtt_avg", "—")} ms'),
                            ("RTT max", f'{stats.get("rtt_max", "—")} ms'),
                            ("RTT mdev", f'{stats.get("rtt_mdev", "—")} ms'),
                        ],
                        subtitle="local · ping",
                    )
                )
            await self.push(
                text_panel(
                    self.palette, f"ping {host}",
                    result.output or result.error or "No output.",
                )
            )
            return

        if action == "trace":
            await self._traceroute(host)
            return

        if action == "mtr":
            tool = netdiag.mtr_tool()
            await self.begin(
                f"pathping {host} — traces the route, then pings every hop; "
                "takes a minute or two…" if tool == "pathping"
                else f"mtr --report {host} — takes about 10 seconds…")
            result = await netdiag.mtr(host)
            await self.finish()
            if result.missing_tool:
                await self._missing("mtr", "mtr-tiny")
                return
            await self.push(
                text_panel(
                    self.palette,
                    f"pathping report — {host}" if tool == "pathping"
                    else f"MTR report — {host}",
                    result.output or result.error or "No output.",
                    subtitle=f"local · {tool}",
                )
            )
            if netdiag.mtr_needs_root(result):
                await self.push_warning(
                    "mtr needs root on macOS",
                    "Homebrew's mtr cannot send its probes as an ordinary user. "
                    "Press AUTHENTICATE on the CAPTURE tab once and netzilla runs "
                    "mtr through that sudo session, or start netzilla with "
                    f"'sudo netzilla', or run it yourself:\n    sudo mtr --report -n {host}",
                )
            return

        if action == "port":
            await self._ports(host)

    async def _traceroute(self, host: str) -> None:
        import asyncio

        await self.begin(f"{netdiag.traceroute_tool()} {host} — this can take a minute…")
        result = await netdiag.traceroute(host)
        if result.missing_tool:
            await self.finish()
            await self._missing("traceroute", "traceroute")
            return
        hops = netdiag.parse_traceroute(result.output)

        self.progress("Resolving each hop's AS via Team Cymru…")
        ip_hops = [h for h in hops if h["ip"]]
        lookups = await asyncio.gather(
            *(cymru.lookup_ip(h["ip"]) for h in ip_hops), return_exceptions=True
        )
        asn_by_ip: dict[str, dict] = {}
        for h, res in zip(ip_hops, lookups):
            if isinstance(res, tuple) and res[0]:
                asn_by_ip[h["ip"]] = res[0]
        await self.finish()

        rows = []
        for h in hops:
            info = asn_by_ip.get(h["ip"] or "")
            asn = f"AS{info['asns'][0]}" if info and info.get("asns") else "—"
            where = ""
            if info:
                where = ", ".join(x for x in [info.get("registry", "").upper(), info.get("country")] if x)
            rows.append([
                str(h["hop"]),
                h["ip"] or "*",
                f'{h["rtt_ms"]:.1f} ms' if h["rtt_ms"] is not None else "—",
                asn,
                where or "—",
            ])
        await self.push(
            table_panel(
                self.palette, f"Path to {host} (with origin AS)",
                ["Hop", "IP", "RTT", "AS", "Registry / country"], rows,
                subtitle=f"{netdiag.traceroute_tool()} + Team Cymru DNS",
            )
        )

        # Path-change history: snapshot this path and diff against the last one.
        current = netdiag.hop_ips(result.output)
        previous = self.services.store.snapshots("path", host, limit=1)
        self.services.store.add_snapshot("path", host, current)
        if previous:
            diff = history.diff_path(previous[0][1], current)
            text, state = history.path_verdict(diff)
            when = history.ago(previous[0][0])
            await self.push(
                verdict_line(self.palette, f"Path vs {when}", text, state)
            )
            if diff["changed"]:
                await self.push(
                    kv_panel(
                        self.palette, "Path change",
                        [
                            ("New hops", diff["added"] or "—"),
                            ("Gone hops", diff["removed"] or "—"),
                            ("Diverges at hop", diff["diverge_at_hop"] or "—"),
                        ],
                    )
                )
        else:
            await self.push(
                verdict_line(
                    self.palette, "Path history",
                    "First snapshot saved — run again later to detect reroutes",
                    "info",
                )
            )

    async def _ports(self, host: str) -> None:
        import asyncio

        raw = self.field("port") or "443"
        ports = []
        for chunk in raw.replace(" ", "").split(","):
            if not chunk:
                continue
            ports.append(self._int(chunk, "Port", 1, 65535))
        if not ports:
            raise ValidationError("Enter at least one port, e.g. 443 or 443,80,22.")
        if len(ports) > 32:
            raise ValidationError("Check at most 32 ports at once.")
        await self.begin(f"Connecting to {len(ports)} port(s) on {host}…")
        results = await asyncio.gather(
            *(netdiag.port_check(host, p) for p in ports)
        )
        await self.finish()
        open_count = sum(1 for r in results if r.ok)
        await self.push(
            verdict_line(
                self.palette, host,
                f"{open_count}/{len(ports)} port(s) open",
                "ok" if open_count else "warn",
            )
        )
        rows = []
        for port, r in zip(ports, results):
            rows.append([
                str(port),
                "OPEN" if r.ok else "closed/filtered",
                r.output or r.error or "",
            ])
        await self.push(
            table_panel(
                self.palette, f"TCP port check — {host}",
                ["Port", "State", "Detail"], rows,
                subtitle="local · TCP connect",
            )
        )
        await self.push_warning(
            "Scan only what you are authorised to touch",
            "This opens real TCP connections. Only probe hosts you own or have "
            "explicit permission to test.",
        )

    async def _mtu(self, host: str) -> None:
        await self.begin(f"Discovering path MTU to {host} (DF ping binary search)…")
        try:
            result = await mtu.discover(host, progress=self.progress)
        except FileNotFoundError:
            await self.finish()
            await self._missing("ping", "iputils-ping")
            return
        await self.finish()
        text, state = mtu.verdict(result)
        await self.push(verdict_line(self.palette, "Path MTU", text, state))
        await self.push(
            kv_panel(
                self.palette, f"Path MTU — {host}",
                [
                    ("Path MTU", result.get("path_mtu")),
                    ("Reachable", result.get("reachable")),
                    ("Search steps", result.get("steps")),
                    ("Note", result.get("note")),
                ],
                subtitle=f"local · {mtu.df_ping_label()}",
            )
        )

    async def _ntp(self) -> None:
        import asyncio

        server = self.field("host") or ntp.DEFAULT_SERVER
        # If the host field holds an IP/host meant for other tools, still allow
        # an explicit NTP server; default to pool.ntp.org when it looks unset.
        if server in ("1.1.1.1", ""):
            server = ntp.DEFAULT_SERVER
        await self.begin(f"Querying NTP server {server}…")
        try:
            result = await asyncio.to_thread(ntp.check, server)
        except Exception as exc:
            await self.finish()
            await self.push_error(
                "NTP query failed",
                f"{exc.__class__.__name__}: {exc}\n\n"
                "Check the server name and that UDP/123 is not blocked outbound.",
            )
            return
        await self.finish()
        text, state = ntp.verdict(result)
        await self.push(verdict_line(self.palette, "Clock", text, state))
        await self.push(
            kv_panel(
                self.palette, "NTP clock check", ntp.summary(result),
                subtitle="local · SNTP",
            )
        )

    async def _tools(self) -> None:
        await self.begin("Checking which local tools are installed…")
        await self.finish()
        rows = []
        missing = []
        for tool, present in netdiag.tools_status():
            rows.append([tool, "available" if present else "NOT INSTALLED"])
            if not present:
                missing.append(tool)
        await self.push(
            table_panel(
                self.palette, "Local tool availability", ["Tool", "Status"], rows
            )
        )
        if missing and not hostos.is_linux():
            commands = hostos.install_commands(missing)
            notes = [hostos.missing_tool_text(t) for t in missing
                     if not hostos.install_commands([t])]
            await self.push(
                text_panel(
                    self.palette,
                    "Install the missing ones" if commands else "Not needed here",
                    "\n".join(commands + ([""] if commands and notes else []) + notes),
                    style=self.palette.accent,
                )
            )
        elif missing:
            packages = {
                "ping": "iputils-ping", "traceroute": "traceroute",
                "tracepath": "iputils-tracepath", "mtr": "mtr-tiny",
                "dig": "dnsutils", "whois": "whois", "openssl": "openssl",
            }
            wanted = sorted({packages.get(t, t) for t in missing})
            await self.push(
                text_panel(
                    self.palette,
                    "Install the missing ones",
                    "sudo apt install " + " ".join(wanted),
                    style=self.palette.accent,
                )
            )

    def _int(self, raw: str, label: str, low: int, high: int) -> int:
        try:
            value = int(raw)
        except ValueError:
            raise ValidationError(f"{label} must be a whole number.")
        if not low <= value <= high:
            raise ValidationError(f"{label} must be between {low} and {high}.")
        return value

    async def _missing(self, tool: str, package: str) -> None:
        await self.push_error(
            f"{tool} not installed",
            f"Install it with:\n    sudo apt install {package}" if hostos.is_linux()
            else hostos.missing_tool_text(tool),
        )
