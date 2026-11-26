"""DEVICE DISCOVERY — what the internet can see on an address, from free data.

INTERNETDB SCAN  Shodan InternetDB (keyless): open ports, hostnames, CPEs,
                 tags and known CVEs as Shodan last observed them
HOST PROFILE     everything free sources know about the address, at once:
                 InternetDB + IP-API + RDAP + RIPEstat — the picture Shodan's
                 paid host record gives, without the paid plan
CVE DETAIL       every CVE InternetDB lists, scored three ways: CVSS (NVD),
                 the chance it is exploited soon (FIRST EPSS) and whether it
                 already is (CISA KEV) — worst first
"""

from __future__ import annotations

import asyncio

from rich.text import Text

from ..clients import epss, ip_api, kev, nvd, rdap, ripestat, shodan
from ..colours import SEMANTIC
from ..render import kv_panel, table_panel, text_panel, verdict_line
from ..validators import valid_ip
from .base import Action, Field, LookupPane

# NVD allows 5 requests per 30 s without a key; CVE DETAIL stays inside that.
NVD_DETAIL_LIMIT = 5
# Rows in the CVE DETAIL table; the verdict line still counts every CVE.
TABLE_LIMIT = 50


class DiscoveryPane(LookupPane):
    PANE_TITLE = "DEVICE DISCOVERY"
    DESCRIPTION = (
        "What the internet can see on an address, from free sources only. "
        "INTERNETDB SCAN shows open ports and known CVEs (Shodan InternetDB, "
        "keyless). HOST PROFILE adds who runs it — ASN, prefix, registry, "
        "abuse contact, location. CVE DETAIL ranks its CVEs by CVSS, EPSS and "
        "CISA KEV."
    )
    FIELDS = (
        Field("ip", "IP address", "1.1.1.1"),
    )
    ACTIONS = (
        Action("idb", "INTERNETDB SCAN"),
        Action("profile", "HOST PROFILE", primary=False),
        Action("cves", "CVE DETAIL", primary=False),
    )

    async def execute(self, action: str) -> None:
        ip = valid_ip(self.field("ip"))
        if action == "profile":
            await self._profile(ip)
        elif action == "cves":
            await self._cve_detail(ip)
        else:
            await self._internetdb(ip)

    # ------------------------------------------------------------ InternetDB
    async def _internetdb(self, ip: str) -> None:
        await self.begin(f"Querying Shodan InternetDB for {ip}…")
        result = await shodan.internetdb(self.services, ip)
        await self.finish()
        if not result.ok:
            await self.push_error("Shodan InternetDB", result.error or "")
            return

        payload = result.data
        ports = payload.get("ports") or []
        vulns = payload.get("vulns") or []
        await self.push(self._exposure_verdict(ports, vulns))
        await self.push(
            kv_panel(
                self.palette,
                f"Exposure — {ip}",
                shodan.summarise(payload),
                subtitle="cached" if result.cached else "live · keyless",
            )
        )

        if payload.get("cpes"):
            await self.push(
                text_panel(
                    self.palette,
                    "Detected software (CPE)",
                    "\n".join(str(c) for c in payload["cpes"][:40]),
                )
            )

        if vulns:
            await self.push(
                text_panel(
                    self.palette,
                    f"Known CVEs ({len(vulns)})",
                    ", ".join(sorted(str(v) for v in vulns)[:120]),
                )
            )
            # Enrich the first few CVEs with severity straight from NVD.
            self.progress("Pulling severity for the first CVEs from NVD…")
            rows = []
            for cve_id in sorted(str(v) for v in vulns)[:3]:
                detail = await nvd.get_cve(self.services, cve_id)
                if detail.ok:
                    rows.extend(nvd.cve_rows(detail.data, limit=1))
            if rows:
                await self.push(
                    table_panel(
                        self.palette,
                        "CVE detail (first 3, from NVD)",
                        ["CVE", "Severity", "CVSS", "Published", "Summary"],
                        rows,
                        subtitle="CVE DETAIL ranks all of them by CVSS, EPSS and KEV",
                    )
                )
            await self.push_warning(
                "Confirm before you act",
                "InternetDB reports what Shodan last observed, which can be "
                "stale, and CVEs are inferred from banner versions rather than "
                "confirmed exploitable. Verify against the host itself.",
            )

    def _exposure_verdict(self, ports: list, vulns: list):
        if not ports and not vulns:
            return verdict_line(self.palette, "InternetDB",
                                "NO EXPOSED SERVICES RECORDED for this address", "ok")
        if vulns:
            return verdict_line(self.palette, "InternetDB",
                                f"{len(ports)} open port(s), {len(vulns)} known CVE(s)",
                                "bad")
        return verdict_line(self.palette, "InternetDB",
                            f"{len(ports)} open port(s), no known CVEs", "warn")

    # ---------------------------------------------------------- host profile
    async def _profile(self, ip: str) -> None:
        await self.begin(f"Building a profile of {ip} from four free sources…")
        idb_task = asyncio.create_task(shodan.internetdb(self.services, ip))
        geo_task = asyncio.create_task(ip_api.lookup(self.services, ip))
        rdap_task = asyncio.create_task(rdap.ip(self.services, ip))
        ripe_task = asyncio.create_task(ripestat.network_info(self.services, ip))
        idb, geo, reg, ripe = await asyncio.gather(idb_task, geo_task, rdap_task,
                                                   ripe_task)

        asn = None
        prefix = ""
        holder = ""
        if ripe.ok:
            asns = ripe.data.get("asns") or []
            prefix = ripe.data.get("prefix") or ""
            if asns:
                asn = asns[0]
                self.progress(f"Naming AS{asn}…")
                overview = await ripestat.as_overview(self.services, int(asn))
                if overview.ok:
                    holder = overview.data.get("holder") or ""
        await self.finish()

        geo_data = geo.data if geo.ok else {}
        idb_data = idb.data if idb.ok else {}
        ports = idb_data.get("ports") or []
        vulns = idb_data.get("vulns") or []
        hostnames = idb_data.get("hostnames") or []
        reverse = geo_data.get("reverse") or (hostnames[0] if hostnames else "")
        if asn is None and geo_data.get("as"):
            # "AS13335 Cloudflare, Inc." -> 13335
            first = str(geo_data["as"]).split()[0].upper().lstrip("AS")
            asn = int(first) if first.isdigit() else None
            holder = holder or geo_data.get("asname") or ""

        who = reverse or holder or geo_data.get("org") or "unknown operator"
        exposure = (f"{len(ports)} open port(s), {len(vulns)} known CVE(s)"
                    if idb.ok else "exposure unknown")
        state = "bad" if vulns else "warn" if ports else "ok"
        await self.push(verdict_line(self.palette, ip, f"{who} · {exposure}", state))

        rows: list[tuple[str, object]] = [
            ("Reverse DNS", reverse or None),
            ("Organisation", geo_data.get("org")),
            ("ISP", geo_data.get("isp")),
            ("ASN", f"AS{asn} — {holder}" if asn else None),
            ("Announced prefix", prefix or None),
        ]
        if reg.ok:
            summary = dict(rdap.ip_summary(reg.data))
            rows += [
                ("Registry network", summary.get("Name")),
                ("Registry block", summary.get("CIDR") or summary.get("Address range")),
                ("Registered", summary.get("Registered")),
                ("Abuse contact", summary.get("Abuse contact")),
            ]
        location = ", ".join(
            str(part) for part in (geo_data.get("city"), geo_data.get("regionName"),
                                   geo_data.get("country")) if part
        )
        rows += [
            ("Location", location or None),
            ("Hosting / datacentre", bool(geo_data.get("hosting")) if geo.ok else None),
            ("Mobile network", bool(geo_data.get("mobile")) if geo.ok else None),
            ("Proxy flagged", bool(geo_data.get("proxy")) if geo.ok else None),
        ]
        await self.push(kv_panel(
            self.palette, f"Who runs {ip}", rows,
            subtitle="IP-API · RDAP · RIPEstat — all keyless",
        ))

        if idb.ok:
            await self.push(kv_panel(
                self.palette, "What it exposes",
                shodan.summarise(idb_data)
                + [("Software (CPE)", (idb_data.get("cpes") or [])[:12] or None)],
                subtitle="Shodan InternetDB · last observed, may be stale",
            ))
        failed = [name for name, result in (("InternetDB", idb), ("IP-API", geo),
                                            ("RDAP", reg), ("RIPEstat", ripe))
                  if not result.ok]
        if failed:
            await self.push_warning(
                "Partly answered",
                "No answer from " + ", ".join(failed) + ". The panels above use "
                "the sources that did respond.",
            )
        if vulns:
            await self.push(text_panel(
                self.palette, "Next step",
                f"{len(vulns)} CVE(s) are listed for this address — press CVE "
                "DETAIL to rank them by CVSS, exploit likelihood (EPSS) and "
                "known exploitation (CISA KEV).",
                style=self.palette.accent,
            ))

    # ------------------------------------------------------------ CVE detail
    async def _cve_detail(self, ip: str) -> None:
        await self.begin(f"Reading the CVEs InternetDB lists for {ip}…")
        idb = await shodan.internetdb(self.services, ip)
        if not idb.ok:
            await self.finish()
            await self.push_error("Shodan InternetDB", idb.error or "")
            return
        vulns = sorted({str(v).upper() for v in idb.data.get("vulns") or []})
        if not vulns:
            await self.finish()
            await self.push(verdict_line(
                self.palette, "CVE DETAIL",
                f"InternetDB lists no known CVEs for {ip}", "ok"))
            return

        self.progress(f"Scoring {len(vulns)} CVE(s) with EPSS and CISA KEV…")
        scores_task = asyncio.create_task(epss.scores(self.services, vulns))
        kev_task = asyncio.create_task(kev.annotate(self.services, vulns))
        scores, kev_map = await asyncio.gather(scores_task, kev_task)
        epss_map = scores.data if scores.ok else {}

        # Severity from NVD for the most likely-to-be-exploited few; NVD's
        # keyless limit is 5 requests per 30 seconds.
        ranked = sorted(
            vulns,
            key=lambda c: (bool(kev_map.get(c)), (epss_map.get(c) or {}).get("epss", 0.0)),
            reverse=True,
        )
        cvss: dict[str, tuple[str, str]] = {}
        limit = NVD_DETAIL_LIMIT * (10 if self.services.config.has("nvd_api_key") else 1)
        for index, cve_id in enumerate(ranked[:limit]):
            self.progress(f"NVD severity {index + 1}/{min(limit, len(ranked))}: {cve_id}…")
            detail = await nvd.get_cve(self.services, cve_id)
            if detail.ok:
                for row in nvd.cve_rows(detail.data, limit=1):
                    cvss[cve_id] = (str(row[1]), str(row[2]))
        await self.finish()

        exploited = [c for c in ranked if kev_map.get(c)]
        likely = [c for c in ranked if (epss_map.get(c) or {}).get("epss", 0) >= 0.1]
        state = "bad" if exploited else "warn" if likely else "info"
        await self.push(verdict_line(
            self.palette, "CVE DETAIL",
            f"{len(vulns)} CVE(s) · {len(exploited)} known exploited (KEV) · "
            f"{len(likely)} with ≥10% exploit likelihood (EPSS)", state))

        rows = []
        shown = ranked[:TABLE_LIMIT]
        for cve_id in shown:
            entry = epss_map.get(cve_id)
            severity, score = cvss.get(cve_id, ("—", "—"))
            rows.append([
                cve_id,
                severity,
                score,
                Text(epss.label(entry), style=self._state_colour(epss.state(entry))),
                Text("● EXPLOITED", style=SEMANTIC["very weak"])
                if kev_map.get(cve_id) else Text("—", style=self.palette.muted),
            ])
        await self.push(table_panel(
            self.palette, f"CVEs for {ip}, most urgent first",
            ["CVE", "Severity", "CVSS", "EPSS (30-day)", "KEV"],
            rows,
            subtitle=(f"the {len(shown)} most urgent of {len(ranked)} · " if len(shown) < len(ranked)
                      else "") + "NVD severity for the top "
                     f"{min(limit, len(ranked))} · EPSS from FIRST · KEV from CISA",
        ))
        if not scores.ok:
            await self.push_warning("EPSS unavailable", scores.error or "")
        if exploited:
            await self.push_warning(
                "Patch these first",
                "In CISA's Known Exploited Vulnerabilities catalog: "
                + ", ".join(exploited[:12])
                + ". They are being exploited in the wild today, whatever "
                "their CVSS score says.",
            )
        await self.push_warning(
            "Banner-inferred",
            "InternetDB infers CVEs from software versions seen in banners. A "
            "back-ported fix or a hardened build can make one a false positive "
            "— confirm on the host before acting.",
        )

    def _state_colour(self, state: str) -> str:
        return {"bad": SEMANTIC["very weak"], "warn": SEMANTIC["fair"],
                "ok": SEMANTIC["excellent"]}.get(state, self.palette.muted)
