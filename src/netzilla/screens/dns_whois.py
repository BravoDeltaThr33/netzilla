"""DNS / WHOIS — local dig and whois, plus DNS-based lookalike hunting."""

from __future__ import annotations

from rich.text import Text

from .. import hostos
from ..clients import doh, rdap, virustotal
from ..local import dns_whois, typosquat
from ..render import group, kv_panel, table_panel, text_panel, verdict_line
from ..validators import (
    ValidationError, valid_domain, valid_host, valid_ip,
)
from .base import Action, Field, LookupPane


class DNSWhoisPane(LookupPane):
    PANE_TITLE = "DNS / WHOIS"
    DESCRIPTION = (
        "dig and whois run locally — no key, no rate limit, and they can see "
        "internal zones no public API can (without dig, ALL RECORDS and REVERSE "
        "fall back to DNS-over-HTTPS and DIG +TRACE walks the tree itself). "
        "TYPOSQUAT SEARCH generates lookalike domains locally and checks which "
        "exist — no key needed."
    )
    FIELDS = (
        Field("target", "Domain or IP", "example.com"),
        Field("server", "DNS server (optional)", "1.1.1.1", width=28),
        Field("zone", "TLD (optional)", "com", width=16),
    )
    ACTIONS = (
        Action("records", "ALL RECORDS"),
        Action("rdap", "RDAP", primary=False),
        Action("whois", "WHOIS", primary=False),
        Action("resolver", "RESOLVER CHECK", primary=False),
        Action("trace", "DIG +TRACE", primary=False),
        Action("reverse", "REVERSE", primary=False),
        Action("squat", "TYPOSQUAT SEARCH", primary=False),
        Action("vt", "VT REPUTATION", primary=False),
    )

    async def execute(self, action: str) -> None:
        if action == "squat":
            await self._typosquat()
            return
        if action == "reverse":
            await self._reverse()
            return
        if action == "vt":
            await self._vt_domain()
            return
        if action == "rdap":
            await self._rdap()
            return
        if action == "resolver":
            await self._resolver_check()
            return

        target = valid_host(self.field("target"))
        server = self.field("server")

        if action == "records":
            await self.begin(f"Querying every common record type for {target}…")
            results = await dns_whois.all_records(target, server)
            if any(result.missing_tool for result in results.values()):
                # No dig on this machine: the same lookups over DNS-over-HTTPS.
                await self._records_over_https(target, server)
                return
            await self.finish()
            rows = []
            for rtype, result in results.items():
                value = result.output.strip()
                # A plain string: addresses and names are coloured by what
                # they are, as everywhere else.
                rows.append([rtype, value or Text("—", style=self.palette.muted)])
            await self.push(
                table_panel(
                    self.palette,
                    f"DNS records — {target}",
                    ["Type", "Answer"],
                    rows,
                    subtitle=f"via {server or 'system resolver'}",
                )
            )
            return

        if action == "whois":
            await self.begin(f"Running whois {target}…")
            result = await dns_whois.whois(target)
            await self.finish()
            if result.missing_tool:
                await self._missing("whois", "whois")
                return
            if not result.output:
                await self.push_error("WHOIS", result.error or "No output returned.")
                return
            await self.push(
                text_panel(
                    self.palette,
                    f"WHOIS — {target}",
                    dns_whois.condense_whois(result.output),
                    subtitle="local whois client" if result.command.startswith("whois ")
                    else result.command,
                )
            )
            return

        if action == "trace":
            domain = valid_domain(self.field("target"))
            await self.begin(f"Tracing delegation for {domain} from the root…")
            result = await dns_whois.trace(domain, progress=self.progress)
            await self.finish()
            if result.missing_tool:
                await self._missing("dig", "dnsutils")
                return
            built_in = result.command.startswith(dns_whois.TRACE_BUILT_IN)
            await self.push(
                text_panel(
                    self.palette,
                    f"Delegation path — {domain}",
                    result.output or result.error or "No output.",
                    subtitle="built-in trace · dig is not installed" if built_in
                    else "dig +trace",
                )
            )
            if built_in and not result.ok and result.error:
                await self.push_warning("The trace stopped", result.error)

    async def _records_over_https(self, target: str, server: str) -> None:
        """ALL RECORDS without dig: every type asked of Cloudflare over HTTPS."""
        self.progress("dig is not installed — asking Cloudflare over DNS-over-HTTPS…")
        answers = await doh.resolve_many(self.services, target, dns_whois.RECORD_TYPES)
        await self.finish()
        rows = []
        failed = 0
        for rtype, result in answers.items():
            if not result.ok:
                failed += 1
                rows.append([rtype, Text(f"error — {result.error}", style=self.palette.error)])
                continue
            values = result.data.get("answers") or []
            status = result.data.get("status_name", "")
            rows.append([
                rtype,
                "\n".join(values) if values
                else Text("—" if status in ("NOERROR", "") else status,
                          style=self.palette.muted),
            ])
        if failed == len(answers):
            await self._missing("dig", "dnsutils")
            return
        await self.push(
            table_panel(
                self.palette,
                f"DNS records — {target}",
                ["Type", "Answer"],
                rows,
                subtitle="via DNS-over-HTTPS (Cloudflare) — dig is not installed",
            )
        )
        if server:
            await self.push_warning(
                "DNS server box ignored",
                f"Without dig, netzilla can't ask {server} directly — these answers "
                "came from Cloudflare (1.1.1.1). "
                + ("Install dig to query a specific server:\n    "
                   + hostos.install_hint("dig") if hostos.available_here("dig")
                   else "dig is not available on this system."),
            )

    async def _reverse(self) -> None:
        ip = valid_ip(self.field("target"))
        server = self.field("server")
        await self.begin(f"Reverse lookup for {ip}…")
        result = await dns_whois.reverse(ip, server)
        if result.missing_tool:
            self.progress("dig is not installed — asking Cloudflare over HTTPS…")
            answer = await doh.ptr(self.services, ip)
            await self.finish()
            if not answer.ok:
                await self._missing("dig", "dnsutils")
                return
            names = answer.data.get("answers") or []
            await self.push(
                kv_panel(
                    self.palette,
                    f"Reverse DNS — {ip}",
                    [("PTR", ", ".join(names) or "no PTR record"),
                     ("Resolver", "Cloudflare, over HTTPS (dig is not installed)")],
                    subtitle="DNS-over-HTTPS",
                )
            )
            return
        await self.finish()
        answer = result.output.strip()
        await self.push(
            kv_panel(
                self.palette,
                f"Reverse DNS — {ip}",
                [("PTR", answer or "no PTR record"), ("Resolver", server or "system")],
                subtitle="dig -x",
            )
        )

    async def _vt_domain(self) -> None:
        domain = valid_domain(self.field("target"))
        await self.begin(f"Asking VirusTotal about {domain}…")
        result = await virustotal.check_domain(self.services, domain)
        await self.finish()
        if not result.ok:
            await self.push_error("VirusTotal", result.error or "")
            return
        text, state = virustotal.verdict(result.data)
        rows = virustotal.summarise(result.data) + [
            ("Registrar", result.data.get("registrar")),
            ("Created", _epoch(result.data.get("creation_date"))),
            ("Last DNS records", _epoch(result.data.get("last_dns_records_date"))),
            ("TLD", result.data.get("tld")),
        ]
        seen = set()
        rows = [r for r in rows if not (r[0] in seen or seen.add(r[0]))]
        panels = [
            verdict_line(self.palette, "VirusTotal", text, state),
            kv_panel(
                self.palette, f"Domain reputation — {domain}", rows,
                subtitle="cached" if result.cached else "live · VirusTotal",
            ),
        ]
        engines = virustotal.flagging_engines(result.data)
        if engines:
            panels.append(
                table_panel(
                    self.palette, "Engines that flagged it",
                    ["Engine", "Category", "Result"], engines,
                )
            )
        await self.push(group(*panels))

    async def _typosquat(self) -> None:
        raw = (self.field("target") or "").strip()
        if not raw:
            raise ValidationError("Enter the domain to protect, e.g. example.com.")
        zone = (self.field("zone") or "").strip()
        name, tld = typosquat.split_domain(raw, zone)
        if not name:
            raise ValidationError(f"Could not find a domain name in '{raw}'.")
        await self.begin(
            f"Generating lookalikes of {name}.{tld} and checking which exist in DNS…"
        )
        try:
            result = await typosquat.scan(raw, zone, progress=self.progress)
        except ValueError as exc:
            await self.finish()
            raise ValidationError(str(exc)) from exc
        await self.finish()

        hits = result["registered"]
        state = "bad" if len(hits) > 10 else "warn" if hits else "ok"
        await self.push(
            verdict_line(
                self.palette,
                "Lookalikes",
                f"{len(hits)} of {result['checked']} permutations of "
                f"{result['original']} resolve in DNS",
                state,
            )
        )
        if result["wildcard_resolver"]:
            await self.push_warning(
                "Your DNS resolver answers for names that don't exist",
                "It returned " + ", ".join(result["wildcard_resolver"])
                + " for a random nonsense name (ISP NXDOMAIN redirection). "
                "Those addresses were filtered out, but for cleaner results "
                "point this machine at 1.1.1.1 or 9.9.9.9.",
            )
        if not hits:
            return
        await self.push(
            table_panel(
                self.palette,
                f"Registered lookalikes of {result['original']}",
                ["Technique", "Domain", "Resolves to"],
                typosquat.rows(result),
                subtitle="live DNS · generated locally, no API",
            )
        )
        await self.push_warning(
            "Read this as leads, not verdicts",
            "Many lookalikes are defensive registrations owned by the brand "
            "itself, or parked pages. Run WHOIS and VT REPUTATION on the ones "
            "that matter before acting.",
        )

    async def _rdap(self) -> None:
        target = valid_host(self.field("target"))
        is_ip = False
        try:
            valid_ip(target)
            is_ip = True
        except ValidationError:
            pass
        await self.begin(f"RDAP lookup for {target}…")
        result = await (rdap.ip(self.services, target) if is_ip
                        else rdap.domain(self.services, target))
        await self.finish()
        if not result.ok:
            await self.push_error("RDAP", result.error or "")
            return
        summary = rdap.ip_summary(result.data) if is_ip else rdap.domain_summary(result.data)
        await self.push(
            kv_panel(
                self.palette, f"RDAP — {target}", summary,
                subtitle="cached" if result.cached else "live · rdap.org",
            )
        )
        abuse = rdap.abuse_email(result.data)
        if abuse:
            await self.push(
                verdict_line(self.palette, "Abuse contact", abuse, "info")
            )

    async def _resolver_check(self) -> None:
        domain = valid_domain(self.field("target"))
        rtype = "A"
        await self.begin(f"Querying {domain} at Cloudflare, Google and Quad9…")
        result = await doh.resolve_all(self.services, domain, rtype)
        await self.finish()
        agree, summary = doh.consensus(result)
        await self.push(
            verdict_line(self.palette, "Resolvers", summary, "ok" if agree else "warn")
        )
        await self.push(
            table_panel(
                self.palette, f"{rtype} records for {domain}",
                ["Resolver", "Status", "Answer"], doh.rows(result),
                subtitle="DNS-over-HTTPS · Cloudflare / Google / Quad9",
            )
        )
        if not agree:
            await self.push_warning(
                "Resolvers disagree",
                "Different resolvers returned different answers for this name. "
                "Common causes: DNS-based CDN steering (often benign), "
                "split-horizon DNS, ISP NXDOMAIN redirection, or — if you did "
                "not expect it — DNS hijacking or filtering. Compare the answers "
                "above against what you expect to be authoritative.",
            )

    async def _missing(self, tool: str, package: str) -> None:
        await self.push_error(
            f"{tool} not installed",
            f"netzilla uses your system's {tool} client for this.\n\n"
            + hostos.missing_tool_text(tool),
        )


def _epoch(value):
    if not isinstance(value, (int, float)):
        return None
    from datetime import datetime, timezone

    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d")
