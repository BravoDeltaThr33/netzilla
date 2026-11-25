"""LIFECYCLE — is it still supported? Hardware and software, both free.

Hardware: end-of-sale / end-of-service-life dates by part number from EOSL.ai
(CC BY 4.0), each linked to the vendor's own bulletin.
Software: release-cycle support dates from endoflife.date (open source) —
IOS XE, PAN-OS, FortiOS, RouterOS, BIND, OpenSSL, ESXi, Windows Server…
"""

from __future__ import annotations

from ..clients import endoflife, eosl
from ..render import kv_panel, table_panel, text_panel, verdict_line
from ..validators import ValidationError, valid_keyword, valid_part_number, valid_slug
from .base import Action, Field, LookupPane


class LifecyclePane(LookupPane):
    PANE_TITLE = "HARDWARE & SOFTWARE LIFECYCLE"
    DESCRIPTION = (
        "End-of-sale and end-of-support dates. Hardware by exact part number "
        "(EOSL.ai, linked to the vendor bulletin — 'Catalyst 3850' needs SEARCH "
        "FAMILIES); software by product and version (endoflife.date). Keyless."
    )
    FIELDS = (
        Field("part", "Part number", "WS-C3850-24T-L"),
        Field("search", "Or search vendor / series", "catalyst 3850", width=34,
              submit="search"),
        Field("software", "Software and version", "cisco-ios-xe 17.9  ·  panos 11.1",
              width=40, submit="software"),
    )
    ACTIONS = (
        Action("part", "CHECK PART"),
        Action("search", "SEARCH FAMILIES", primary=False),
        Action("family", "FAMILY DETAIL", primary=False),
        Action("software", "SOFTWARE EOL"),
    )

    async def execute(self, action: str) -> None:
        if action == "part":
            await self._part()
        elif action == "search":
            await self._search()
        elif action == "software":
            await self._software()
        else:
            await self._family()

    # ------------------------------------------------------------ software
    async def _software(self) -> None:
        raw = (self.field("software") or "").strip()
        if not raw:
            raise ValidationError(
                "Type a product in SOFTWARE AND VERSION, optionally with a "
                "version: cisco-ios-xe 17.9.4, panos 11.1, fortios 7.2, "
                "ubuntu 22.04, openssl 3.0."
            )
        query, version = endoflife.split_query(raw)
        query = valid_keyword(query, "Product")
        await self.begin(f"Finding '{query}' on endoflife.date…")
        index = await endoflife.products(self.services)
        if not index.ok:
            await self.finish()
            await self.push_error("endoflife.date", index.error or "")
            return
        hits = endoflife.find_products(index.data, query)
        if not hits:
            await self.finish()
            await self.push_warning(
                "No such product",
                f"endoflife.date tracks {len(index.data)} products and none "
                f"matches '{query}'. Try the vendor's own name for the OS "
                "(cisco-ios-xe, panos, fortios, routeros, junos) or browse "
                "https://endoflife.date",
            )
            return
        if not endoflife.is_exact(hits[0], query) and len(hits) > 1:
            await self.finish()
            await self.push(table_panel(
                self.palette, f"Products matching '{query}'",
                ["Name (type this)", "Product", "Category"],
                [[h.get("name"), h.get("label"), h.get("category")] for h in hits],
                subtitle=f"{len(hits)} found · put one name in the box, with a version",
            ))
            return

        chosen = hits[0]
        self.progress(f"Reading the release cycles of {chosen.get('label')}…")
        result = await endoflife.product(self.services, chosen["name"])
        await self.finish()
        if not result.ok:
            await self.push_error("endoflife.date", result.error or "")
            return
        data = result.data
        releases = [r for r in data.get("releases") or [] if isinstance(r, dict)]
        label = data.get("label") or chosen.get("label") or chosen["name"]

        release = None
        if version:
            release = endoflife.match_release(releases, version)
            if release is None:
                await self.push_warning(
                    "Version not recognised",
                    f"{label} has no release cycle matching {version}. Its "
                    "cycles are: "
                    + ", ".join(str(r.get("name")) for r in releases[:30]),
                )
            else:
                text, state = endoflife.release_state(release)
                await self.push(verdict_line(
                    self.palette, f"{label} {version}", text, state))
        await self.push(kv_panel(
            self.palette, label, endoflife.product_summary(data),
            subtitle="cached" if result.cached else "live · endoflife.date",
        ))
        await self.push(table_panel(
            self.palette, f"{label} release cycles, newest first",
            ["Release", "Released", "Support ends", "End of life", "Latest", "Status"],
            endoflife.release_rows(releases, mine=release),
            subtitle=f"{len(releases)} cycles · dates from the vendor's own policy",
        ))

    async def _part(self) -> None:
        part = valid_part_number(self.field("part"))
        await self.begin(f"Checking lifecycle status for {part}…")
        result = await eosl.part_status(self.services, part)
        await self.finish()
        if not result.ok:
            await self.push_warning("Not found", result.error or "")
            await self.push(
                text_panel(
                    self.palette,
                    "Try a family search instead",
                    "EOSL.ai matches part numbers exactly and never guesses — "
                    "which is the right behaviour, because a wrong EOL date on "
                    "the wrong device is worse than no date.\n\n"
                    "Put the vendor and series in the second field and press "
                    "SEARCH FAMILIES.",
                )
            )
            return

        line = str(result.data).strip()
        lowered = line.lower()
        if "past" in lowered or "unsupported" in lowered or "eosl" in lowered:
            state = "bad" if "past" in lowered or "unsupported" in lowered else "warn"
        else:
            state = "ok"
        await self.push(verdict_line(self.palette, part.upper(), line, state))
        await self.push(
            kv_panel(
                self.palette,
                f"Lifecycle — {part.upper()}",
                [("Part number", part.upper()), ("EOSL.ai status", line)],
                subtitle="cached" if result.cached else "live · eosl.ai",
            )
        )

    async def _search(self) -> None:
        term = valid_keyword(self.field("search") or self.field("part"), "Search term")
        await self.begin("Loading the EOSL.ai family index…")
        result = await eosl.families(self.services)
        if not result.ok:
            await self.finish()
            await self.push_error("EOSL.ai", result.error or "")
            return
        self.progress(f"Searching {len(result.data):,} families for '{term}'…")
        hits = eosl.search_families(result.data, term)
        await self.finish()
        if not hits:
            await self.push_warning(
                "No matches", f"Nothing in the EOSL.ai index matches '{term}'."
            )
            return
        await self.push(
            table_panel(
                self.palette,
                f"Families matching '{term}'",
                ["Vendor", "Series", "Category", "Status", "EOSL", "Slug"],
                eosl.family_rows(hits),
                subtitle=f"{len(hits)} shown · put a slug in the part field for detail",
            )
        )

    async def _family(self) -> None:
        slug = valid_slug(self.field("part") or self.field("search"))
        await self.begin(f"Fetching family detail for {slug}…")
        result = await eosl.family(self.services, slug)
        await self.finish()
        if not result.ok:
            await self.push_error(
                "EOSL.ai",
                f"{result.error}\n\nFamily detail needs a slug such as "
                "'cisco-catalyst-3850'. Run SEARCH FAMILIES to find one.",
            )
            return

        detail = result.data or {}
        status = detail.get("status") or {}
        lifecycle = detail.get("lifecycle") or {}
        runway = detail.get("supportRunwayScore") or detail.get("exposureScore") or {}

        label = status.get("label") or status.get("key") or "unknown"
        months = status.get("monthsToEosl")
        state = "bad" if isinstance(months, (int, float)) and months < 0 else (
            "warn" if isinstance(months, (int, float)) and months < 12 else "ok"
        )
        await self.push(verdict_line(self.palette, detail.get("slug", slug), label, state))

        await self.push(
            kv_panel(
                self.palette,
                f'{detail.get("vendor", "")} {detail.get("series", "")}'.strip() or slug,
                [
                    ("Vendor", detail.get("vendor")),
                    ("Line / series", f'{detail.get("line", "")} {detail.get("series", "")}'.strip()),
                    ("Category", detail.get("category")),
                    ("General availability", detail.get("generalAvailability")),
                    ("Status", label),
                    ("Months to EOSL", months),
                    ("Supported parts", lifecycle.get("supportedPartCount")),
                    ("Unsupported parts", lifecycle.get("unsupportedPartCount")),
                    ("Earliest EOSL", lifecycle.get("earliestEosl")),
                    ("Latest EOSL", lifecycle.get("latestEosl")),
                    ("Support runway score", f'{runway.get("score", "—")} — {runway.get("band", "")}'),
                    ("Reference", detail.get("url")),
                ],
                subtitle="cached" if result.cached else "live · eosl.ai",
            )
        )

        rows = eosl.sku_group_rows(detail)
        if rows:
            await self.push(
                table_panel(
                    self.palette,
                    "SKU groups",
                    ["Group", "End of sale", "EOSL", "Date source", "Replacement", "SKUs"],
                    rows,
                )
            )
        for group_entry in (detail.get("skuGroups") or [])[:4]:
            source = group_entry.get("sourceUrl")
            if source:
                await self.push(
                    text_panel(
                        self.palette,
                        f'Vendor bulletin — {group_entry.get("label", "group")}',
                        source,
                        style=self.palette.muted,
                    )
                )
