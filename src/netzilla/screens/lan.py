"""LAN — active diagnostics for the network you are actually plugged into.

Everything here is local L2/L3 protocol work with no third-party API:
  SWEEP        ping every host in a CIDR, then identify each one: MAC vendor,
               hostname (reverse DNS / mDNS / NetBIOS / UPnP), what kind of
               device it looks like, and why. Blank = this machine's subnet
  IDENTIFY     everything netzilla can learn about one device, with evidence
  ROGUE DHCP   broadcast a DISCOVER, flag if more than one server answers
  DUP-IP       watch who claims an IP, flag two MACs answering for one address
  SNMP POLL    two counter samples -> live per-interface Mbps and error rate
  SYSLOG       stand up a UDP listener (514, or any port typed in the target
               field) and collect device logs, with a live message count

DHCP detection needs root (raw sockets). The syslog listener needs root only
for ports below 1024: without it, the default 514 falls back to 1514 on its
own instead of stopping with an error. Windows and macOS let any user listen
on 514; on Windows the DHCP Client service keeps UDP/68 for itself.
"""

from __future__ import annotations

import asyncio

from textual.widgets import Static

from .. import hostos
from ..local import arpwatch, devices, dhcp, lan, snmp, syslog
from ..render import kv_panel, table_panel, text_panel, verdict_line
from ..validators import ValidationError, valid_host, valid_ip, valid_network
from .base import Action, Field, LookupPane


class LANPane(LookupPane):
    PANE_TITLE = "LAN DIAGNOSTICS"
    DESCRIPTION = (
        "Active diagnostics for your local segment — no API, no key. SWEEP "
        "finds every device and names it: vendor, hostname and what it looks "
        "like (leave the box blank to sweep this machine's own subnet). "
        "IDENTIFY profiles one device. Also: rogue DHCP, duplicate IPs, SNMP, "
        + ("syslog. SYSLOG listens on udp/514 (no administrator rights needed)."
           if hostos.is_windows() else
           "syslog. ROGUE DHCP needs root ('sudo netzilla'); SYSLOG listens on "
           "udp/514 with no root needed." if hostos.is_macos() else
           "syslog. ROGUE DHCP needs root ('sudo netzilla'); SYSLOG uses udp/514 "
           "as root and udp/1514 otherwise.")
    )
    FIELDS = (
        Field(
            "target", "CIDR / host / IP  ·  syslog port",
            "blank = this machine's subnet · e.g. 192.168.1.0/24 · one IP for IDENTIFY",
        ),
        Field("community", "SNMP community", "public", width=22),
        Field("secs", "Seconds", "5", width=22),
        Field("every", "Refresh every (s)", "blank = 1", width=22),
    )
    ACTIONS = (
        Action("sweep", "SWEEP"),
        Action("identify", "IDENTIFY"),
        Action("dhcp", "ROGUE DHCP", primary=False),
        Action("dupip", "DUP-IP WATCH", primary=False),
        Action("snmp", "SNMP POLL", primary=False),
        Action("syslog", "SYSLOG CATCH", primary=False),
    )

    # ------------------------------------------------------------- dispatch
    async def execute(self, action: str) -> None:
        if action == "sweep":
            await self._sweep()
        elif action == "identify":
            await self._identify()
        elif action == "dhcp":
            await self._dhcp()
        elif action == "dupip":
            await self._dupip()
        elif action == "snmp":
            await self._snmp()
        elif action == "syslog":
            await self._syslog()

    def _secs(self, default: float, low: float, high: float) -> float:
        raw = self.field("secs") or str(default)
        try:
            value = float(raw)
        except ValueError:
            raise ValidationError("Seconds must be a number, e.g. 5 or 30.")
        if not low <= value <= high:
            raise ValidationError(f"Seconds must be between {low:g} and {high:g}.")
        return value

    # ---------------------------------------------------------------- sweep
    async def _sweep_target(self) -> tuple[str, str, dict | None]:
        """(cidr, note, context). A blank box means this machine's own LAN."""
        raw = self.field("target")
        if raw:
            return raw, "", None
        context = await devices.local_context()
        cidr, note = devices.suggest_sweep(context)
        if not cidr:
            raise ValidationError(
                "netzilla could not work out this machine's subnet (no "
                "interface with a default route). Type one, e.g. "
                "192.168.1.0/24 — find yours with:  ip -4 addr"
            )
        return cidr, note, context

    async def _sweep(self) -> None:
        cidr, note, context = await self._sweep_target()
        network = valid_network(cidr)
        try:
            targets = lan.hosts_for(str(network))
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        await self.begin(f"Pinging {len(targets)} host(s) in {network}…")
        try:
            result = await lan.sweep(str(network), progress=self.progress)
        except FileNotFoundError:
            await self.finish()
            await self.push_error(
                "ping not installed",
                "Install it with:\n    sudo apt install iputils-ping" if hostos.is_linux()
                else hostos.missing_tool_text("ping"),
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
            if context is None:
                context = await devices.local_context()
            identified = await devices.identify(
                found, context=context, progress=self.progress,
                # One multicast UPnP search, but only of this machine's own
                # segment; a routed or VPN range is asked host by host.
                use_ssdp=devices.is_local_network(network, context),
            )
        await self.finish()
        live_devices = identified[: len(live)]
        arp_devices = identified[len(live):]
        await self.push(
            verdict_line(
                self.palette, "Sweep",
                f"{len(live)} of {result['scanned']} host(s) alive in {result['cidr']}"
                + (f", {len(extra)} more in the ARP cache" if extra else ""),
                "ok" if live else "warn",
            )
        )
        if note:
            await self.push_warning("Subnet narrowed", note)
        if identified:
            await self.push(
                kv_panel(
                    self.palette, f"What's on {result['cidr']}",
                    devices.summary(identified),
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

    # ------------------------------------------------------------- identify
    async def _identify(self) -> None:
        raw = self.field("target")
        if not raw or "/" in raw:
            raise ValidationError(
                "IDENTIFY looks at one device: type its IP in the box, e.g. "
                "10.0.0.185. Run SWEEP first to see every address on the LAN."
            )
        ip = valid_ip(raw)
        await self.begin(f"Identifying {ip}…")
        context = await devices.local_context()
        dev = await devices.profile(ip, context=context, progress=self.progress)
        await self.finish()
        known = dev.get("device") not in (None, "", "Unknown")
        await self.push(
            verdict_line(
                self.palette, "Device",
                f"{ip} looks like: {dev.get('device') or 'Unknown'}"
                + (f"  ({devices.display_name(dev)})" if devices.display_name(dev) else ""),
                "ok" if known else "warn",
            )
        )
        sources = ", ".join(dev.get("sources") or []) or "ping / ARP only"
        await self.push(
            kv_panel(
                self.palette, f"Device profile — {ip}",
                devices.profile_rows(dev), subtitle=f"names from: {sources}",
            )
        )
        if dev.get("evidence"):
            await self.push(
                text_panel(
                    self.palette, "Why netzilla thinks so",
                    "\n".join(f"  • {reason}" for reason in dev["evidence"]),
                    style=self.palette.accent,
                )
            )
        await self.push(
            table_panel(
                self.palette, "Identifying ports that answered",
                ["Port", "Service", "Usually means"], devices.port_rows(dev),
                subtitle=f"{len(devices.PROBE_PORTS)} well-known ports checked (TCP connect)",
            )
        )
        if context.get("networks") and not devices.is_local(ip, context):
            await self.push_warning(
                "Not on this machine's LAN",
                f"{ip} is not on any of this machine's own LAN segments — it "
                "is routed, or behind a VPN. There is no MAC or vendor for it "
                "from here, and the port check went out across that link. "
                "Only point IDENTIFY at networks you own or manage.",
            )
        if not dev.get("reachable"):
            await self.push_warning(
                "Nothing answered",
                f"{ip} did not reply to ping, is not in the neighbour table and "
                "had no identifying port open. It may be off, asleep (phones "
                "doze their Wi-Fi), firewalled, or on another subnet.",
            )

    # ----------------------------------------------------------- rogue DHCP
    async def _dhcp(self) -> None:
        listen = self._secs(5, 2, 30)
        await self.begin(f"Broadcasting DHCPDISCOVER, listening {listen:.0f}s…")
        try:
            offers = await dhcp.detect(listen_seconds=listen)
        except PermissionError as exc:
            await self.finish()
            await self.push_error("UDP/68 is taken" if hostos.is_windows() else "Needs root",
                                  str(exc))
            return
        except OSError as exc:
            await self.finish()
            await self.push_error("DHCP probe failed", str(exc))
            return
        known: dict[str, dict] = {}
        if offers:
            self.progress("Identifying the server(s) that answered…")
            servers = [o.get("server_id") or o.get("from") for o in offers]
            known = await devices.identify_ips([ip for ip in servers if ip])
        await self.finish()
        text, state = dhcp.verdict(offers)
        await self.push(verdict_line(self.palette, "DHCP", text, state))
        if offers:
            rows = []
            for offer, row in zip(offers, dhcp.rows(offers)):
                dev = known.get(offer.get("server_id") or offer.get("from") or "", {})
                rows.append(row[:1] + [
                    devices.mac_cell(dev) if dev else "—",
                    devices.vendor_cell(dev) if dev else "",
                    devices.display_name(dev) if dev else "",
                    dev.get("device", "") if dev else "",
                ] + row[1:])
            await self.push(
                table_panel(
                    self.palette, "DHCP servers that answered",
                    ["Server", "MAC", "Vendor", "Hostname", "Device",
                     "Offered IP", "Mask", "Routers", "DNS", "Lease"],
                    rows,
                    subtitle=f"{len(offers)} distinct server(s)",
                )
            )
        if len(offers) > 1:
            await self.push_warning(
                "More than one DHCP server answered",
                "On a normal segment exactly one server should reply. Identify "
                "any you do not recognise — a rogue server hands out bad gateways "
                "and DNS, and is a common cause of intermittent client failures.",
            )

    # -------------------------------------------------------------- dup-IP
    async def _dupip(self) -> None:
        ip = valid_ip(self.field("target"))
        seconds = self._secs(8, 2, 30)
        every = self._every(1.0)
        await self.begin(
            f"Watching who claims {ip} for {seconds:.0f}s, checking every {every:g}s…")
        result = await arpwatch.watch(ip, seconds=seconds, interval=every)
        await self.finish()
        text, state = arpwatch.verdict(result)
        await self.push(verdict_line(self.palette, "ARP", text, state))
        await self.push(
            kv_panel(
                self.palette, f"ARP observation — {ip}",
                [
                    ("Method", result["method"]),
                    ("Rounds", result["rounds"]),
                    ("MACs seen", result["macs"] or "none"),
                    ("Conflict", result["conflict"]),
                ],
            )
        )
        if result["macs"]:
            await self.push(
                table_panel(
                    self.palette, f"Who claimed {ip}",
                    ["MAC", "Vendor", "Address type", "Likely device"],
                    self._claimant_rows(result["macs"]),
                    subtitle="vendor from the offline IEEE registry",
                )
            )
        if result["conflict"]:
            await self.push_warning(
                "Duplicate IP detected",
                "Two or more MACs answered for this address. Track down the "
                "second device (check switch MAC-address tables for these MACs) "
                "— duplicate IPs cause exactly the intermittent, hard-to-pin "
                "connectivity loss users report.",
            )

    @staticmethod
    def _claimant_rows(macs: list[str]) -> list[list[object]]:
        rows = []
        for mac in macs:
            vendor, kind = devices.vendor_for(mac)
            label, _why = devices.classify({"vendor": vendor, "mac_kind": kind})
            rows.append([
                mac,
                devices.short_vendor(vendor) or ("private MAC" if kind == "random" else "—"),
                {"global": "burned-in", "random": "randomised / local",
                 "multicast": "multicast",
                 "virtual": "virtual (VM / container)"}.get(kind, kind),
                label,
            ])
        return rows

    # ---------------------------------------------------------------- SNMP
    async def _snmp(self) -> None:
        host = valid_host(self.field("target"))
        community = self.field("community") or "public"
        interval = self._secs(5, 2, 30)
        if not snmp.available():
            await self.begin("Checking for the SNMP tools…")
            await self.finish()
            await self.push_error(
                "net-snmp not installed",
                "netzilla uses the system SNMP tools for this.\n\n"
                + ("Install them with:\n    sudo apt install snmp" if hostos.is_linux()
                   else hostos.missing_tool_text("snmpget")),
            )
            return
        await self.begin(f"Polling {host} over SNMP…")
        info = await snmp.system_info(host, community)
        if not info.get("ok"):
            await self.finish()
            await self.push_error(
                "SNMP poll failed",
                f"{info.get('error') or 'No response.'}\n\n"
                "Check the host is reachable, SNMP is enabled, the community "
                f"string ('{community}') is correct, and UDP/161 is open.",
            )
            return
        await self.push(
            kv_panel(
                self.palette, f"System — {host}",
                [
                    ("sysName", info.get("sysName")),
                    ("sysDescr", info.get("sysDescr")),
                    ("Uptime", snmp.uptime_pretty(info.get("sysUpTime"))),
                ],
                subtitle="SNMP v2c",
            )
        )
        rates = await snmp.poll_rates(host, community, interval=interval, progress=self.progress)
        await self.finish()
        if not rates:
            await self.push_warning(
                "No interface counters",
                "The device answered sysDescr but returned no interface counters. "
                "It may not expose IF-MIB, or the community is read-restricted.",
            )
            return
        await self.push(
            table_panel(
                self.palette, f"Live interface rates — {host}",
                ["Interface", "Oper", "In Mbps", "Out Mbps", "Errors Δ"],
                snmp.rate_rows(rates),
                subtitle=f"delta over {interval:.0f}s",
            )
        )
        hot = [r for r in rates if r["in_err_delta"] + r["out_err_delta"] > 0]
        if hot:
            await self.push_warning(
                "Interfaces gaining errors right now",
                "These counters rose during the poll window: "
                + ", ".join(r["name"] for r in hot)
                + ". Rising errors point at cabling, duplex mismatch or a failing SFP.",
            )

    # -------------------------------------------------------------- syslog
    def _syslog_port(self) -> tuple[int, bool]:
        """(port, explicit). A bare number, ':1514' or 'udp/1514' in the
        target field picks the port; anything else means the default 514."""
        raw = self.field("target").strip().lower()
        for prefix in ("udp/", "udp:", ":"):
            if raw.startswith(prefix):
                raw = raw[len(prefix):]
        if raw.isdigit():
            port = int(raw)
            if not 1 <= port <= 65535:
                raise ValidationError("Syslog port must be between 1 and 65535.")
            return port, True
        return syslog.DEFAULT_PORT, False

    async def _syslog_senders(self, messages: list[dict]) -> None:
        """Which devices logged, identified — a switch that logs by IP alone
        is easier to recognise with its vendor and name beside it."""
        counts: dict[str, int] = {}
        for message in messages:
            source = str(message.get("source", ""))
            if source:
                counts[source] = counts.get(source, 0) + 1
        if not counts:
            return
        senders = sorted(counts, key=lambda ip: -counts[ip])[:32]
        known = await devices.identify_ips(senders)
        rows = []
        for ip in senders:
            dev = known.get(ip, {})
            rows.append([
                ip, counts[ip], devices.mac_cell(dev), devices.vendor_cell(dev),
                devices.display_name(dev), dev.get("device", ""),
            ])
        await self.push(
            table_panel(
                self.palette, "Devices that logged",
                ["Source", "Messages", "MAC", "Vendor", "Hostname", "Device"],
                rows, subtitle="identified the same way as SWEEP",
            )
        )

    async def _syslog(self) -> None:
        port, explicit = self._syslog_port()
        seconds = self._secs(20, 5, 300)
        fallback_note = ""

        collector = syslog.SyslogCollector(port=port)
        await self.begin(f"Opening a syslog listener on udp/{port}…")
        try:
            await collector.start()
        except PermissionError as exc:
            if explicit or port >= 1024 or hostos.is_windows():
                await self.finish()
                await self.push_error(
                    f"udp/{port} unavailable" if hostos.is_windows() else "Needs root",
                    str(exc))
                return
            # Not root and the user never asked for 514 specifically: use the
            # unprivileged alternative instead of stopping.
            port = syslog.FALLBACK_PORT
            collector = syslog.SyslogCollector(port=port)
            try:
                await collector.start()
            except OSError as exc2:
                await self.finish()
                await self.push_error("Could not open a syslog listener", str(exc2))
                return
            fallback_note = (
                f"udp/514 needs root, so netzilla listened on udp/{port} instead. "
                f"Point devices at port {port}, or run 'sudo netzilla' to use 514."
            )
        except OSError as exc:
            await self.finish()
            await self.push_error(
                f"udp/{port} unavailable",
                f"{exc}\n\nSomething else (rsyslog, another netzilla) may already "
                "be listening there. Type a different port in the target field.",
            )
            return

        every = self._every(1.0)
        # Live: the newest messages as they arrive, refreshed every `every`.
        live_panel = Static(classes="result-panel")
        await self.push_widget(live_panel)
        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + seconds
            shown = -1
            while (left := deadline - loop.time()) > 0:
                count = len(collector.messages)
                self.progress(
                    f"Listening on udp/{port} — {count} message(s) "
                    f"so far, {left:.0f}s left. Test with:  "
                    f"logger -n 127.0.0.1 -P {port} -d 'hello'"
                )
                if count != shown:
                    shown = count
                    live_panel.update(table_panel(
                        self.palette, f"Live — udp/{port}",
                        ["Time", "Source", "Severity", "Facility", "Message"],
                        [syslog.row(m) for m in reversed(collector.messages[-25:])],
                        subtitle=f"newest first · refreshing every {every:g}s · "
                                 f"{left:.0f}s left",
                    ))
                await asyncio.sleep(min(every, left))
        finally:
            collector.stop()
        await live_panel.remove()
        await self.finish()

        messages = collector.messages
        await self.push(
            verdict_line(
                self.palette, "Syslog",
                f"{len(messages)} message(s) received on udp/{port}",
                "ok" if messages else "warn",
            )
        )
        if fallback_note:
            await self.push_warning("Listened on a high port", fallback_note)
        if messages:
            await self.push(
                table_panel(
                    self.palette, f"Syslog — udp/{port}",
                    ["Time", "Source", "Severity", "Facility", "Message"],
                    [syslog.row(m) for m in messages[-200:]],
                    subtitle=f"last {min(len(messages), 200)} shown",
                )
            )
            await self._syslog_senders(messages)
        else:
            await self.push_warning(
                "Nothing arrived",
                f"No device logged to this host during the {seconds:.0f}s window.\n"
                f"  • Self-test from this machine:  logger -n 127.0.0.1 -P {port} -d 'hello'\n"
                f"  • Cisco IOS:  logging host <this-ip> transport udp port {port}\n"
                f"  • Firewall on? Allow it:  sudo ufw allow {port}/udp",
            )
