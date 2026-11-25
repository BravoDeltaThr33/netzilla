"""SERVICE STATUS — live vendor status from OutageDeck's normalised feeds."""

from __future__ import annotations

from rich.text import Text

from ..clients import outagedeck
from ..render import kv_panel, table_panel
from ..validators import ValidationError, valid_slug
from .base import Action, Field, LookupPane

DEFAULT_STACK = "aws,azure,cloudflare,github,google-cloud"


class ServiceStatusPane(LookupPane):
    PANE_TITLE = "SERVICE STATUS"
    DESCRIPTION = (
        "Is it us or them? Live status for 180 cloud and SaaS vendors, read "
        "from each vendor's own official status feed rather than guessed from "
        "a ping. Keyless, 120 requests/hour. Unknown slug? Type a name and "
        "use FIND PROVIDER."
    )
    FIELDS = (
        Field("stack", "Provider slugs (comma separated)", DEFAULT_STACK, DEFAULT_STACK),
    )
    ACTIONS = (
        Action("stack", "CHECK STACK"),
        Action("incidents", "ACTIVE INCIDENTS", primary=False),
        Action("find", "FIND PROVIDER", primary=False),
    )

    async def execute(self, action: str) -> None:
        if action == "incidents":
            await self._incidents()
            return
        if action == "find":
            await self._find()
            return

        raw = self.field("stack") or DEFAULT_STACK
        slugs = [valid_slug(s) for s in raw.split(",") if s.strip()]
        if not slugs:
            raise ValidationError("Enter at least one provider slug, e.g. aws.")
        if len(slugs) > 12:
            raise ValidationError("Check at most 12 providers at once.")

        await self.begin(f"Checking {len(slugs)} provider(s)…")
        results = await outagedeck.check_many(self.services, slugs)
        await self.finish()

        rows = []
        problems: list[str] = []
        failed = 0
        details: list[tuple[str, object]] = []
        for slug, result in zip(slugs, results):
            if not result.ok:
                failed += 1
                rows.append([
                    slug,
                    Text("LOOKUP FAILED", style=self.palette.error),
                    result.error or "",
                    "—",
                ])
                continue
            info = outagedeck.normalise(result.data)
            state = outagedeck.state_of(info["status_key"])
            colour = {
                "ok": self.palette.success,
                "warn": self.palette.warning,
                "bad": self.palette.error,
            }.get(state, self.palette.muted)
            name = info["name"] or slug
            label = str(info["status_label"]).upper()
            if state in ("warn", "bad"):
                problems.append(name)
                extra = info["active_titles"][:3] or info["degraded_services"][:5]
                # Every provider with a problem gets a line — with its own
                # status page, the place to read more — even when it has
                # published no incident detail.
                what = "; ".join(extra) if extra else (info["headline"] or label.title())
                if info["url"]:
                    what += f"  ·  {info['url']}"
                details.append((name, what))
            if info["stale"]:
                label += " (STALE)"
            rows.append([
                name,
                Text(label, style=colour),
                info["headline"] or "—",
                info["updated"] or "—",
            ])

        await self.push(
            table_panel(
                self.palette,
                "Stack status",
                ["Provider", "Status", "Headline", "Checked (UTC)"],
                rows,
                subtitle="source: official vendor status feeds via OutageDeck",
            )
        )

        answered = len(slugs) - failed
        if problems:
            summary = f"{len(problems)} of {answered} providers reporting problems"
        elif answered:
            summary = f"All {answered} providers that answered are operational"
        else:
            summary = "No provider could be checked"
        if failed:
            summary += f" · {failed} lookup(s) failed"
        await self.push(
            kv_panel(
                self.palette,
                "Verdict",
                [
                    ("Providers checked", answered),
                    ("Reporting problems", len(problems)),
                    ("Lookups failed", failed),
                    ("Summary", summary),
                ],
            )
        )
        if details:
            await self.push(
                kv_panel(self.palette, "What they are reporting", details)
            )
        if problems:
            await self.push_warning(
                "Before you debug your own code",
                "One or more upstream dependencies is already in an incident. "
                "Check the vendor's status page directly before changing "
                "anything on your side.",
            )

    async def _find(self) -> None:
        term = (self.field("stack") or "").split(",")[0].strip()
        if not term:
            raise ValidationError("Type part of a vendor name, e.g. micro or google.")
        await self.begin(f"Searching OutageDeck for '{term}'…")
        result = await outagedeck.search(self.services, term)
        await self.finish()
        if not result.ok:
            await self.push_error("OutageDeck", result.error or "")
            return
        providers = [p for p in result.data if isinstance(p, dict)]
        if not providers:
            await self.push_warning(
                "No match",
                f"OutageDeck tracks no provider matching '{term}'. "
                "Browse the full list at https://outagedeck.com/providers",
            )
            return
        rows = []
        for p in providers[:40]:
            info = outagedeck.normalise(p)
            rows.append([info["slug"] or "—", info["name"] or "—",
                         str(info["status_label"]).upper()])
        await self.push(
            table_panel(
                self.palette,
                f"Providers matching '{term}'",
                ["Slug (use this)", "Name", "Status"],
                rows,
                subtitle=f"{len(providers)} found",
            )
        )

    async def _incidents(self) -> None:
        await self.begin("Fetching active incidents across the catalogue…")
        result = await outagedeck.active_incidents(self.services)
        await self.finish()
        if not result.ok:
            await self.push_error("OutageDeck", result.error or "")
            return
        incidents = result.data.get("incidents") or []
        if not incidents:
            await self.push(
                kv_panel(
                    self.palette,
                    "Active incidents",
                    [("Result", "No active incidents reported right now.")],
                )
            )
            return
        total = result.data.get("total") or len(incidents)
        shown = min(len(incidents), 40)
        await self.push(
            table_panel(
                self.palette,
                "Active incidents",
                ["Provider", "Severity", "State", "Title", "Started (UTC)"],
                outagedeck.incident_rows(incidents, limit=40),
                subtitle=f"showing {shown} of {total} active",
            )
        )
