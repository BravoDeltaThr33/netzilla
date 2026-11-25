"""THREAT INTEL — CVEs (NVD), malware URLs (URLhaus), VirusTotal URL and
file-hash verdicts."""

from __future__ import annotations

from ..clients import abusech, crtsh, epss, kev, nvd, rdap, urlhaus, virustotal
from ..local import urlhaus_offline
from ..render import group, kv_panel, table_panel, verdict_line
from ..validators import (
    ValidationError, valid_domain, valid_host, valid_ip, valid_keyword, valid_url,
)
from .base import Action, Field, LookupPane


class ThreatIntelPane(LookupPane):
    PANE_TITLE = "THREAT INTELLIGENCE"
    DESCRIPTION = (
        "CVE search against the US National Vulnerability Database (keyless), "
        "ranked with FIRST EPSS and CISA KEV · "
        "URLhaus malware-URL listings (live, with an offline snapshot fallback) · "
        "VirusTotal verdicts for URLs and file hashes. netzilla never uploads "
        "files — a hash lookup asks whether a file is already known."
    )
    FIELDS = (
        Field(
            "query",
            "CVE ID, keyword, host, URL or file hash",
            "CVE-2024-3400  ·  cisco ios xe  ·  http://bad.example/x  ·  <sha256>",
        ),
    )
    ACTIONS = (
        Action("cve", "CVE SEARCH"),
        Action("ioc", "IOC LOOKUP", primary=False),
        Action("urlhaus", "URLHAUS CHECK", primary=False),
        Action("vturl", "VIRUSTOTAL URL", primary=False),
        Action("hash", "FILE HASH", primary=False),
        Action("timeline", "FIRST-SEEN TIMELINE", primary=False),
        Action("vtsubmit", "SUBMIT URL TO VT", primary=False),
        Action("snapshot", "URLHAUS SNAPSHOT", primary=False),
    )

    async def execute(self, action: str) -> None:
        if action == "snapshot":
            await self._snapshot_info()
            return

        raw = self.field("query")
        if not raw:
            raise ValidationError(
                "Enter a CVE ID, a keyword, a host, a URL or a file hash."
            )

        if action == "cve":
            await self._cve(raw)
        elif action == "ioc":
            await self._ioc(raw)
        elif action == "urlhaus":
            await self._urlhaus(raw)
        elif action == "vturl":
            await self._vt_url(raw)
        elif action == "vtsubmit":
            await self._vt_submit(raw)
        elif action == "hash":
            await self._hash(raw)
        elif action == "timeline":
            await self._timeline(raw)

    # ------------------------------------------------------------------ nvd
    async def _cve(self, raw: str) -> None:
        term = raw.strip()
        looks_like_id = term.upper().startswith("CVE-")
        await self.begin(
            f'Querying NVD for {"CVE " + term.upper() if looks_like_id else repr(term)}…'
        )
        if not looks_like_id:
            term = valid_keyword(term, "Search term")

        result = (
            await nvd.get_cve(self.services, term)
            if looks_like_id
            else await nvd.search_keyword(self.services, term)
        )
        await self.finish()
        if not result.ok:
            await self.push_error("NVD", result.error or "")
            return

        rows = nvd.cve_rows(result.data)
        if not rows:
            await self.push_warning("No matches", f"NVD returned nothing for '{term}'.")
            return

        # Cross-reference CISA KEV (exploited in the wild?) and FIRST EPSS
        # (how likely in the next 30 days?) — both free, one request each.
        cve_ids = [r[0] for r in rows if str(r[0]).upper().startswith("CVE-")]
        kev_map = await nvd_kev_annotate(self.services, cve_ids)
        scores = await epss.scores(self.services, cve_ids)
        epss_map = scores.data if scores.ok else {}
        columns = ["CVE", "Severity", "CVSS", "Published", "Summary"]
        if epss_map:
            rows = [list(r) + [epss.label(epss_map.get(str(r[0]).upper()))] for r in rows]
            columns.append("EPSS")
        if kev_map:
            rows = [
                list(r) + ["● EXPLOITED" if kev_map.get(str(r[0]).upper()) else ""]
                for r in rows
            ]
            columns.append("KEV")

        await self.push(
            table_panel(
                self.palette,
                f"NVD results — {term}",
                columns,
                rows,
                subtitle=f'{result.data.get("total", len(rows))} total'
                + (" · cached" if result.cached else ""),
            )
        )

        # For a single CVE, show the full KEV detail when it is listed.
        if looks_like_id:
            entry = kev_map.get(term.upper())
            state = "bad" if entry else "ok"
            kevtext, _ = kev.verdict({"listed": bool(entry), "entry": entry})
            await self.push(verdict_line(self.palette, "CISA KEV", kevtext, state))
            if entry:
                await self.push(
                    kv_panel(
                        self.palette, "Known Exploited Vulnerability",
                        kev.entry_summary(entry),
                        subtitle="source: CISA KEV catalog",
                    )
                )
        elif kev_map and any(kev_map.values()):
            exploited = [c for c, e in kev_map.items() if e]
            await self.push_warning(
                "Some of these are being exploited right now",
                "In CISA's KEV catalog: " + ", ".join(sorted(exploited))
                + ". Patch these before anything else in the list, regardless of "
                "CVSS score.",
            )

        if not self.services.config.has("nvd_api_key"):
            await self.push_warning(
                "Running without an NVD key",
                "NVD allows 5 requests per 30 seconds without a key and 50 with "
                "one. A key is free and optional — add it on the SETTINGS tab if "
                "you hit rate limits.",
            )

    # -------------------------------------------------------------- urlhaus
    async def _urlhaus(self, raw: str) -> None:
        if "://" in raw or "/" in raw:
            target = valid_url(raw)
            await self.begin(f"Checking URLhaus for {target}…")
            result = await urlhaus.check_url(self.services, target)
        else:
            target = valid_host(raw)
            await self.begin(f"Checking URLhaus for host {target}…")
            result = await urlhaus.check_host(self.services, target)
        await self.finish()

        if not result.ok:
            await self.push_error("URLhaus", result.error or "")
            return

        source = result.data.get("source", "live")
        text, state = urlhaus.verdict(result.data)
        await self.push(
            verdict_line(
                self.palette,
                "URLhaus" if source == "live" else "URLhaus (snapshot)",
                text, state,
            )
        )
        if result.note and source != "live":
            await self.push_warning("Answered offline", result.note)

        if result.data.get("query_status") == "ok" and result.data.get("url_count") is None:
            await self.push(
                kv_panel(
                    self.palette,
                    "URLhaus entry",
                    [
                        ("URL", result.data.get("url")),
                        ("Status", result.data.get("url_status")),
                        ("Threat", result.data.get("threat")),
                        ("Tags", result.data.get("tags") or []),
                        ("Added", result.data.get("date_added")),
                        ("Last online", result.data.get("last_online")),
                        ("Reporter", result.data.get("reporter")),
                        ("Reference", result.data.get("urlhaus_reference")),
                    ],
                    subtitle="live API" if source == "live" else "offline snapshot",
                )
            )
            return

        rows = urlhaus.url_rows(result.data)
        if rows:
            online = result.data.get("urls_online")
            await self.push(
                table_panel(
                    self.palette,
                    f"Malware URLs — {target}",
                    ["Status", "Threat", "Tags", "Added", "URL"],
                    rows,
                    subtitle=(
                        f'{result.data.get("url_count")} total'
                        + (f", {online} online at capture" if online else "")
                        + (" · live API" if source == "live" else " · offline snapshot")
                    ),
                )
            )

    async def _snapshot_info(self) -> None:
        import asyncio

        await self.begin("Reading the offline URLhaus snapshot…")
        rows = await asyncio.to_thread(lambda: urlhaus_offline.snapshot().describe())
        await self.finish()
        await self.push(
            kv_panel(
                self.palette,
                "Offline URLhaus snapshot",
                rows,
                subtitle="used when the live API is unreachable",
            )
        )
        await self.push_warning(
            "Refreshing it",
            "The snapshot ages from the day it was captured. To refresh:\n"
            "    netzilla --update-urlhaus            (downloads with your Auth-Key)\n"
            "    netzilla --import-urlhaus FILE       (a dump you downloaded yourself;\n"
            "                                          .json, .zip or the plain-text list)",
        )

    # ----------------------------------------------------------- virustotal
    async def _vt_url(self, raw: str) -> None:
        target = valid_url(raw)
        await self.begin(f"Asking VirusTotal about {target}…")
        result = await virustotal.check_url(self.services, target)
        await self.finish()
        if not result.ok:
            if result.meta.get("unknown"):
                await self.push_warning("Not in VirusTotal yet", result.error or "")
            else:
                await self.push_error("VirusTotal", result.error or "")
            return
        await self._render_vt(f"URL reputation — {target[:70]}", result)

    async def _vt_submit(self, raw: str) -> None:
        target = valid_url(raw)
        await self.begin(f"Submitting {target} to VirusTotal for scanning…")
        result = await virustotal.submit_url(self.services, target, progress=self.progress)
        await self.finish()
        if not result.ok:
            await self.push_error("VirusTotal submission", result.error or "")
            return
        await self._render_vt(f"Fresh scan — {target[:70]}", result)

    async def _hash(self, raw: str) -> None:
        value = raw.strip()
        if not virustotal.is_hash(value):
            raise ValidationError(
                "That is not an MD5 (32 hex), SHA-1 (40 hex) or SHA-256 (64 hex) hash. "
                "On Linux: sha256sum FILE"
            )
        await self.begin(f"Looking up {virustotal.hash_kind(value)} on VirusTotal…")
        result = await virustotal.check_file(self.services, value)
        await self.finish()
        if not result.ok:
            if result.meta.get("unknown"):
                await self.push_warning("Unknown file", result.error or "")
            else:
                await self.push_error("VirusTotal", result.error or "")
            return
        text, state = virustotal.verdict(result.data)
        panels = [
            verdict_line(self.palette, "VirusTotal", text, state),
            kv_panel(
                self.palette,
                "File report — VirusTotal",
                virustotal.file_summary(result.data),
                subtitle="cached" if result.cached else "live",
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

    # ---------------------------------------------------------------- IOC
    async def _ioc(self, raw: str) -> None:
        value = raw.strip()
        is_hash = virustotal.is_hash(value)
        is_ip = False
        if not is_hash:
            try:
                valid_ip(value)
                is_ip = True
            except ValidationError:
                pass
        await self.begin(f"Looking up {value} across abuse.ch feeds…")
        # ThreatFox covers IPs, domains and hashes.
        tf = await abusech.threatfox(self.services, value)
        await self.finish()

        if tf.ok:
            text, state = abusech.threatfox_verdict(tf.data)
            await self.push(verdict_line(self.palette, "ThreatFox", text, state))
            rows = abusech.threatfox_rows(tf.data)
            if rows:
                await self.push(
                    table_panel(
                        self.palette, "ThreatFox IOCs",
                        ["IOC", "Type", "Malware", "Confidence", "First seen"], rows,
                        subtitle="source: abuse.ch ThreatFox",
                    )
                )
        else:
            await self.push_error("ThreatFox", tf.error or "")

        if is_ip:
            feodo = await abusech.feodo_check(self.services, value)
            if feodo.ok:
                text, state = abusech.feodo_verdict(feodo.data)
                await self.push(verdict_line(self.palette, "Feodo Tracker", text, state))
            else:
                await self.push_warning("Feodo Tracker", feodo.error or "")

        if is_hash:
            mb = await abusech.malwarebazaar(self.services, value)
            if mb.ok:
                text, state = abusech.malwarebazaar_verdict(mb.data)
                await self.push(verdict_line(self.palette, "MalwareBazaar", text, state))
                if mb.data.get("data"):
                    await self.push(
                        kv_panel(
                            self.palette, "MalwareBazaar sample",
                            abusech.malwarebazaar_summary(mb.data),
                            subtitle="source: abuse.ch MalwareBazaar",
                        )
                    )
            else:
                await self.push_error("MalwareBazaar", mb.error or "")

        if not is_ip and not is_hash:
            await self.push_warning(
                "Tip",
                "IOC LOOKUP also cross-checks the Feodo botnet-C2 list for IPs "
                "and MalwareBazaar for file hashes. This looked like a domain, so "
                "only ThreatFox was queried.",
            )

    # ------------------------------------------------------------- timeline
    async def _timeline(self, raw: str) -> None:
        domain = valid_domain(raw)
        await self.begin(f"Building a first-seen timeline for {domain}…")
        self.progress("RDAP registration date…")
        rd = await rdap.domain(self.services, domain)
        self.progress("Earliest certificate (crt.sh)…")
        ct = await crtsh.search(self.services, domain)
        self.progress("Threat-intel first sightings…")
        uh = await urlhaus.check_host(self.services, domain)
        tf = await abusech.threatfox(self.services, domain)
        await self.finish()

        events: list[tuple[str, str]] = []
        registered = rdap.registration_date(rd.data) if rd.ok else ""
        if registered:
            events.append((registered[:10], "Domain registered (RDAP)"))
        earliest_cert = crtsh.earliest_date(ct.data) if ct.ok else ""
        if earliest_cert:
            events.append((earliest_cert, "First TLS certificate issued (crt.sh)"))
        if uh.ok and uh.data.get("firstseen"):
            events.append((str(uh.data["firstseen"])[:10], "First malware URL on host (URLhaus)"))
        if tf.ok and tf.data.get("data"):
            first = min(
                (d.get("first_seen", "") for d in tf.data["data"] if d.get("first_seen")),
                default="",
            )
            if first:
                events.append((first[:10], "First ThreatFox IOC"))

        events.sort(key=lambda e: e[0])
        if not events:
            await self.push_warning(
                "No dated signals",
                f"None of RDAP, crt.sh, URLhaus or ThreatFox returned a dated "
                f"event for {domain}.",
            )
            return

        flagged = (uh.ok and uh.data.get("query_status") == "ok") or (
            tf.ok and bool(tf.data.get("data"))
        )
        state, note = _timeline_verdict(registered, earliest_cert, flagged)
        await self.push(verdict_line(self.palette, "Timeline", note, state))
        await self.push(
            table_panel(
                self.palette, f"First-seen timeline — {domain}",
                ["Date", "Event"], [[d, label] for d, label in events],
                subtitle="RDAP · crt.sh · URLhaus · ThreatFox",
            )
        )
        if state == "bad":
            await self.push_warning(
                "Fast phishing tell",
                "A domain that was registered recently, got its first certificate "
                "at the same time, and is already in threat feeds is the classic "
                "profile of a throwaway phishing/malware domain.",
            )

    async def _render_vt(self, title: str, result) -> None:
        text, state = virustotal.verdict(result.data)
        panels = [
            verdict_line(self.palette, "VirusTotal", text, state),
            kv_panel(
                self.palette, title, virustotal.summarise(result.data),
                subtitle="cached" if result.cached else "live",
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


# --------------------------------------------------------------- helpers
async def nvd_kev_annotate(services, cve_ids: list) -> dict:
    """Map each CVE id to its CISA KEV entry (or None). One catalog fetch.

    Returns {} when the KEV feed is unavailable, so the CVE table still renders.
    """
    ids = [c for c in cve_ids if str(c).upper().startswith("CVE-")]
    if not ids:
        return {}
    try:
        return await kev.annotate(services, ids)
    except Exception:
        return {}


def _timeline_verdict(registered: str, earliest_cert: str, flagged: bool):
    """Classify a domain from its age and whether it is already in threat feeds."""
    import datetime as _dt

    def age_days(date_str: str):
        try:
            when = _dt.date.fromisoformat(date_str[:10])
        except (ValueError, TypeError):
            return None
        return (_dt.date.today() - when).days

    reg_age = age_days(registered)
    young = reg_age is not None and reg_age <= 60
    if young and flagged:
        return "bad", f"Registered {reg_age}d ago and already in threat feeds — high risk"
    if flagged:
        return "warn", "Appears in threat feeds — investigate"
    if young:
        return "warn", f"Freshly registered ({reg_age}d ago) — treat new domains with care"
    return "ok", "No age/reputation red flags in the dated signals"
