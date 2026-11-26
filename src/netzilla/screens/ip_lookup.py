"""IP LOOKUP — one address, five independent opinions, fetched concurrently.

Plus BLOCK CHECK: AbuseIPDB's check-block endpoint across a whole /24 (the
free-plan ceiling), for when one bad address makes you wonder about its
neighbours.
"""

from __future__ import annotations

import asyncio
import ipaddress

from ..clients import abuseipdb, greynoise, ip_api, iplogs, virustotal
from ..render import group, kv_panel, table_panel, text_panel, verdict_line
from ..validators import ValidationError, valid_ip
from .base import Action, Field, LookupPane


class IPLookupPane(LookupPane):
    PANE_TITLE = "IP LOOKUP"
    DESCRIPTION = (
        "Geolocation and ASN (IP-API) · abuse reports (AbuseIPDB) · multi-engine "
        "reputation (VirusTotal) · scanner/business-service classification "
        "(GreyNoise) · VPN/proxy/Tor detection (IPLogs). All five run in "
        "parallel. BLOCK CHECK scans the surrounding /24 on AbuseIPDB."
    )
    FIELDS = (
        Field("ip", "IP address (or a /24 for BLOCK CHECK)",
              "8.8.8.8  ·  leave blank for your own public IP"),
    )
    ACTIONS = (
        Action("full", "FULL REPORT"),
        Action("geo", "GEO ONLY", primary=False),
        Action("threat", "THREAT ONLY", primary=False),
        Action("block", "BLOCK CHECK /24", primary=False),
    )

    async def execute(self, action: str) -> None:
        if action == "block":
            await self._block()
            return

        raw = self.field("ip")
        target = valid_ip(raw) if raw else ""

        await self.begin(f"Querying {target or 'your public IP'}…")

        if action == "threat" and not target:
            await self.finish()
            await self.push_warning(
                "Address required",
                "Threat lookups need an explicit IP. Run FULL REPORT with an "
                "empty field first to discover your own address.",
            )
            return

        # Geolocation first: everything else is keyed off a confirmed address.
        geo = await ip_api.lookup(self.services, target)
        resolved = (geo.data.get("query") if geo.ok else "") or target

        if action != "threat":
            if geo.ok:
                await self.push(
                    kv_panel(
                        self.palette,
                        "Geolocation & network — IP-API",
                        ip_api.summarise(geo.data),
                        subtitle="cached" if geo.cached else "live",
                    )
                )
            else:
                await self.push_error("IP-API", geo.error or "No data.")

        if action == "geo":
            await self.finish()
            return

        if not resolved:
            await self.finish()
            await self.push_warning(
                "No address to enrich",
                "IP-API did not return an address, so the threat panels were skipped.",
            )
            return

        if not ipaddress.ip_address(resolved).is_global:
            await self.push_warning(
                "Private or reserved address",
                f"{resolved} is not on the public internet, so the reputation "
                "services have nothing to say about it. Their answers below "
                "will be empty or skipped — no quota was spent on GreyNoise.",
            )

        self.progress(f"Cross-checking {resolved} against four threat sources…")

        tasks = {
            "abuse": asyncio.create_task(abuseipdb.check(self.services, resolved)),
            "vt": asyncio.create_task(virustotal.check_ip(self.services, resolved)),
            "gn": asyncio.create_task(greynoise.check(self.services, resolved)),
            "vpn": asyncio.create_task(iplogs.check(self.services, resolved)),
        }

        # Awaited in a fixed display order; they are already running together.
        await self._render_abuse(await tasks["abuse"])
        await self._render_vt(await tasks["vt"])
        await self._render_greynoise(await tasks["gn"])
        await self._render_iplogs(await tasks["vpn"])

        await self.finish(f"Report complete for {resolved}.")

    # -------------------------------------------------------------- panels
    async def _render_abuse(self, abuse) -> None:
        if not abuse.ok:
            await self.push_warning("AbuseIPDB unavailable", abuse.error or "")
            return
        text, state = abuseipdb.verdict(abuse.data)
        panels = [
            verdict_line(self.palette, "AbuseIPDB", text, state),
            kv_panel(
                self.palette,
                "Abuse reports — AbuseIPDB",
                abuseipdb.summarise(abuse.data),
                subtitle="cached" if abuse.cached else "live · last 90 days",
            ),
        ]
        categories = abuseipdb.category_counts(abuse.data)
        if categories:
            panels.append(
                table_panel(
                    self.palette, "Reported for", ["Category", "Reports"], categories
                )
            )
        reports = abuseipdb.report_rows(abuse.data)
        if reports:
            panels.append(
                table_panel(
                    self.palette,
                    "Most recent reports",
                    ["When (UTC)", "From", "Categories", "Reporter comment"],
                    reports,
                )
            )
        await self.push(group(*panels))

    async def _render_vt(self, vt) -> None:
        if not vt.ok:
            await self.push_warning("VirusTotal unavailable", vt.error or "")
            return
        text, state = virustotal.verdict(vt.data)
        panels = [
            verdict_line(self.palette, "VirusTotal", text, state),
            kv_panel(
                self.palette,
                "Multi-engine reputation — VirusTotal",
                virustotal.summarise(vt.data),
                subtitle="cached" if vt.cached else "live",
            ),
        ]
        engines = virustotal.flagging_engines(vt.data)
        if engines:
            panels.append(
                table_panel(
                    self.palette, "Engines that flagged it",
                    ["Engine", "Category", "Result"], engines,
                )
            )
        await self.push(group(*panels))

    async def _render_greynoise(self, gn) -> None:
        if not gn.ok:
            await self.push_warning("GreyNoise unavailable", gn.error or "")
            return
        text, state = greynoise.verdict(gn.data)
        subtitle = "cached" if gn.cached else "live · 50 lookups/week"
        if gn.data.get("skipped"):
            subtitle = "not queried · no quota spent"
        panels = [
            verdict_line(self.palette, "GreyNoise", text, state),
            kv_panel(
                self.palette,
                "Noise & business-service check — GreyNoise",
                greynoise.summarise(gn.data),
                subtitle=subtitle,
            ),
        ]
        await self.push(group(*panels))
        if gn.note and not gn.data.get("skipped"):
            await self.push_warning("GreyNoise note", gn.note)

    async def _render_iplogs(self, vpn) -> None:
        if not vpn.ok:
            await self.push_warning("IPLogs unavailable", vpn.error or "")
            return
        text, state = iplogs.verdict(vpn.data)
        panels = [
            verdict_line(self.palette, "IPLogs", text, state),
            kv_panel(
                self.palette,
                "Anonymisation check — IPLogs",
                iplogs.summarise(vpn.data),
                subtitle="cached" if vpn.cached else "live · keyless",
            ),
        ]
        signals = iplogs.matched_signals(vpn.data)
        if signals:
            panels.append(
                table_panel(
                    self.palette, "Signals that fired", ["Signal", "Detail"], signals
                )
            )
        await self.push(group(*panels))

    # --------------------------------------------------------- block check
    async def _block(self) -> None:
        raw = self.field("ip")
        if not raw:
            raise ValidationError("Enter an IP address or a network such as 203.0.113.0/24.")
        if "/" in raw:
            try:
                network = ipaddress.ip_network(raw.strip(), strict=False)
            except ValueError:
                raise ValidationError(f"'{raw}' is not a valid network.")
        else:
            address = ipaddress.ip_address(valid_ip(raw))
            prefix = 24 if address.version == 4 else 64
            network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)

        blocker = abuseipdb.block_blocker(str(network))
        if blocker:
            raise ValidationError(blocker)

        await self.begin(f"Checking every address in {network} on AbuseIPDB…")
        result = await abuseipdb.check_block(self.services, str(network))
        await self.finish()
        if not result.ok:
            await self.push_error("AbuseIPDB block check", result.error or "")
            return

        text, state = abuseipdb.block_verdict(result.data)
        await self.push(
            group(
                verdict_line(self.palette, str(network), text, state),
                kv_panel(
                    self.palette,
                    f"Block reputation — {network}",
                    abuseipdb.block_summary(result.data),
                    subtitle="cached" if result.cached else "live · last 30 days",
                ),
            )
        )
        rows = abuseipdb.block_rows(result.data)
        if rows:
            await self.push(
                table_panel(
                    self.palette,
                    "Reported addresses, worst first",
                    ["Address", "Score", "Reports", "Latest", "Country"],
                    rows,
                    subtitle=f"{len(rows)} shown",
                )
            )
        else:
            await self.push(
                text_panel(
                    self.palette, "Result",
                    "No address in this block has been reported in the last 30 days.",
                    style=self.palette.success, border=self.palette.success,
                )
            )
