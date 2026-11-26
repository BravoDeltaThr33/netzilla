"""BGP / ASN — routing reality from RIPE NCC's RIPEstat."""

from __future__ import annotations

import asyncio

from ..clients import ripestat
from ..local import cymru, history
from ..render import group, kv_panel, table_panel, verdict_line
from ..validators import ValidationError, valid_asn, valid_ip
from .base import Action, Field, LookupPane


class BGPPane(LookupPane):
    PANE_TITLE = "BGP / ASN"
    DESCRIPTION = (
        "Live routing data from RIPE NCC — which prefix and AS originate an "
        "address, what an AS announces, who it peers with, and RPKI validity. "
        "Keyless. Falls back to Team Cymru over DNS when RIPEstat is slow."
    )
    FIELDS = (
        Field("resource", "IP address or ASN", "8.8.8.8  or  AS15169"),
    )
    ACTIONS = (
        Action("auto", "LOOK UP"),
        Action("prefixes", "ANNOUNCED PREFIXES", primary=False),
        Action("neighbours", "AS NEIGHBOURS", primary=False),
        Action("whois", "RIPE WHOIS", primary=False),
        Action("snapshot", "ORIGIN SNAPSHOT", primary=False),
        Action("history", "ORIGIN HISTORY", primary=False),
    )

    async def execute(self, action: str) -> None:
        raw = self.field("resource")
        if not raw:
            raise ValidationError("Enter an IP address or an AS number.")

        asn = None
        ip = None
        try:
            asn = valid_asn(raw)
        except ValidationError:
            ip = valid_ip(raw)

        if action == "auto":
            if ip:
                await self._from_ip(ip)
            else:
                await self._from_asn(asn)
            return

        if action == "snapshot":
            if not ip:
                raise ValidationError(
                    "Origin monitoring works on an IP address (the thing whose "
                    "origin AS can be hijacked), not an AS number."
                )
            await self._snapshot(ip)
            return

        if action == "history":
            await self._history(ip or f"AS{asn}")
            return

        if asn is None:
            # Resolve the address to its origin AS before AS-only calls.
            await self.begin(f"Finding the origin AS for {ip}…")
            info = await ripestat.network_info(self.services, ip)
            if not info.ok:
                await self.finish()
                await self.push_error("RIPEstat", info.error or "")
                return
            asns = info.data.get("asns") or []
            if not asns:
                await self.finish()
                await self.push_warning(
                    "Not routed", f"{ip} is not announced in the global table."
                )
                return
            asn = int(asns[0])
            self.progress(f"{ip} originates from AS{asn}.")
        else:
            await self.begin(f"Querying AS{asn}…")

        if action == "prefixes":
            result = await ripestat.announced_prefixes(self.services, asn)
            await self.finish()
            if not result.ok:
                await self.push_error("RIPEstat", result.error or "")
                return
            prefixes = result.data.get("prefixes") or []
            rows = [
                [i + 1, p.get("prefix", "—")]
                for i, p in enumerate(prefixes[:200])
                if isinstance(p, dict)
            ]
            await self.push(
                table_panel(
                    self.palette,
                    f"Prefixes announced by AS{asn}",
                    ["#", "Prefix"],
                    rows,
                    subtitle=f"{len(prefixes)} total"
                    + (" · truncated at 200" if len(prefixes) > 200 else ""),
                )
            )
        elif action == "neighbours":
            result = await ripestat.as_neighbours(self.services, asn)
            await self.finish()
            if not result.ok:
                await self.push_error("RIPEstat", result.error or "")
                return
            neighbours = result.data.get("neighbours") or []
            rows = [
                [
                    n.get("asn", "—"),
                    n.get("type", "—"),
                    n.get("power", "—"),
                    n.get("v4_peers", "—"),
                    n.get("v6_peers", "—"),
                ]
                for n in neighbours[:100]
                if isinstance(n, dict)
            ]
            await self.push(
                table_panel(
                    self.palette,
                    f"BGP neighbours of AS{asn}",
                    ["ASN", "Relationship", "Power", "v4 peers", "v6 peers"],
                    rows,
                    subtitle=f"{len(neighbours)} observed",
                )
            )
        elif action == "whois":
            result = await ripestat.whois(self.services, raw)
            await self.finish()
            if not result.ok:
                await self.push_error("RIPEstat", result.error or "")
                return
            for record in (result.data.get("records") or [])[:6]:
                rows = [
                    (item.get("key", "—"), item.get("value", "—"))
                    for item in record
                    if isinstance(item, dict)
                ]
                if rows:
                    await self.push(
                        kv_panel(self.palette, "RIPE WHOIS record", rows)
                    )

    async def _from_ip(self, ip: str) -> None:
        await self.begin(
            f"Resolving routing for {ip}… (RIPEstat can take up to 40s when busy)"
        )
        info = await ripestat.network_info(self.services, ip)
        fallback = None
        if info.ok:
            prefix = info.data.get("prefix")
            asns = info.data.get("asns") or []
            subtitle = "cached" if info.cached else "live · RIPEstat"
        else:
            self.progress("RIPEstat unavailable — asking Team Cymru over DNS…")
            fallback, why = await cymru.lookup_ip(ip)
            if fallback is None:
                await self.finish()
                await self.push_error(
                    "RIPEstat",
                    f"{info.error or ''}\n\nTeam Cymru DNS fallback: {why}",
                )
                return
            prefix = fallback.get("prefix")
            asns = fallback.get("asns") or []
            subtitle = "Team Cymru via DNS (RIPEstat unavailable)"
            await self.push_warning(
                "RIPEstat unavailable — using fallback",
                f"{info.error or ''}\nPrefix and origin AS below come from "
                "Team Cymru's IP-to-ASN DNS service.",
            )

        rows = [
            ("Address", ip),
            ("Covering prefix", prefix),
            ("Origin AS", ", ".join(f"AS{a}" for a in asns) or "not routed"),
        ]
        if fallback:
            rows += [
                ("Country", fallback.get("country")),
                ("Registry", (fallback.get("registry") or "").upper() or None),
                ("Allocated", fallback.get("allocated")),
            ]
        await self.push(
            kv_panel(self.palette, f"Routing — {ip}", rows, subtitle=subtitle)
        )
        if not asns:
            await self.finish()
            return

        asn = int(asns[0])
        self.progress(f"Fetching AS{asn} overview and RPKI status…")
        overview, rpki = await asyncio.gather(
            ripestat.as_overview(self.services, asn),
            ripestat.rpki(self.services, asn, prefix) if prefix else _none(),
        )
        await self.finish()

        if overview.ok:
            await self.push(
                kv_panel(
                    self.palette,
                    f"AS{asn} overview",
                    ripestat.overview_rows(overview.data),
                )
            )
        else:
            await self._cymru_overview(asn, overview.error)
        if rpki is not None and not rpki.ok:
            await self.push_warning(
                "RPKI check unavailable", rpki.error or "RIPEstat did not answer."
            )
        if rpki is not None and rpki.ok:
            status = (rpki.data.get("status") or "unknown").upper()
            state = {
                "VALID": "ok", "INVALID": "bad",
                "INVALID_ASN": "bad", "INVALID_LENGTH": "bad",
                "UNKNOWN": "warn", "NOT-FOUND": "warn",
            }.get(status, "info")
            await self.push(
                group(
                    verdict_line(self.palette, "RPKI", status, state),
                    kv_panel(
                        self.palette,
                        "Route origin validation",
                        [
                            ("Prefix", prefix),
                            ("Origin AS", f"AS{asn}"),
                            ("RPKI status", status),
                            ("Description", rpki.data.get("description")),
                        ],
                    ),
                )
            )

    async def _from_asn(self, asn: int) -> None:
        await self.begin(f"Querying AS{asn}…")
        overview, routing = await asyncio.gather(
            ripestat.as_overview(self.services, asn),
            ripestat.routing_status(self.services, f"AS{asn}"),
        )
        await self.finish()
        if overview.ok:
            await self.push(
                kv_panel(
                    self.palette,
                    f"AS{asn} overview",
                    ripestat.overview_rows(overview.data),
                    subtitle="cached" if overview.cached else "live · RIPEstat",
                )
            )
        else:
            await self._cymru_overview(asn, overview.error)
        if routing.ok:
            await self.push(
                kv_panel(
                    self.palette,
                    f"AS{asn} routing status",
                    ripestat.routing_rows(routing.data),
                )
            )

    async def _cymru_overview(self, asn: int, ripe_error: str | None) -> None:
        """AS holder/registry from Team Cymru when RIPEstat can't answer."""
        data, why = await cymru.lookup_asn(asn)
        if data is None:
            await self.push_error(
                "RIPEstat",
                f"{ripe_error or ''}\n\nTeam Cymru DNS fallback: {why}",
            )
            return
        await self.push(
            kv_panel(
                self.palette,
                f"AS{asn} overview",
                [
                    ("Holder", data.get("holder")),
                    ("Country", data.get("country")),
                    ("Registry", (data.get("registry") or "").upper() or None),
                    ("Allocated", data.get("allocated")),
                ],
                subtitle="Team Cymru via DNS (RIPEstat unavailable)",
            )
        )


    async def _origin_now(self, ip: str) -> dict | None:
        """Current {asns, prefix} for an IP, RIPEstat first, Cymru fallback."""
        info = await ripestat.network_info(self.services, ip)
        if info.ok:
            return {
                "asns": [str(a) for a in (info.data.get("asns") or [])],
                "prefix": info.data.get("prefix"),
                "source": "RIPEstat",
            }
        data, _ = await cymru.lookup_ip(ip)
        if data:
            return {
                "asns": [str(a) for a in data.get("asns", [])],
                "prefix": data.get("prefix"),
                "source": "Team Cymru",
            }
        return None

    async def _snapshot(self, ip: str) -> None:
        await self.begin(f"Recording the current origin for {ip}…")
        current = await self._origin_now(ip)
        if current is None:
            await self.finish()
            await self.push_error(
                "Origin lookup failed",
                f"Neither RIPEstat nor Team Cymru could resolve the origin of {ip}.",
            )
            return
        previous = self.services.store.snapshots("origin", ip, limit=1)
        self.services.store.add_snapshot("origin", ip, current)
        await self.finish()
        await self.push(
            kv_panel(
                self.palette, f"Origin now — {ip}",
                [
                    ("Origin AS", ", ".join(f"AS{a}" for a in current["asns"]) or "not routed"),
                    ("Prefix", current["prefix"]),
                    ("Source", current["source"]),
                ],
            )
        )
        if previous:
            diff = history.diff_origin(previous[0][1], current)
            text, state = history.origin_verdict(diff)
            when = history.ago(previous[0][0])
            await self.push(verdict_line(self.palette, f"vs {when}", text, state))
            if diff["changed"] and diff["hijack_suspect"]:
                await self.push_warning(
                    "Origin AS changed completely",
                    "This prefix is now announced from an AS that shares nothing "
                    "with the previous origin. That is the signature of a BGP "
                    "hijack (or a legitimate but major re-homing). Verify against "
                    "RPKI and the operator before trusting routes to it.",
                )
        else:
            await self.push(
                verdict_line(
                    self.palette, "History",
                    "First snapshot saved — snapshot again later to catch changes",
                    "info",
                )
            )

    async def _history(self, target: str) -> None:
        await self.begin(f"Reading origin history for {target}…")
        snaps = self.services.store.snapshots("origin", target, limit=20)
        await self.finish()
        if not snaps:
            await self.push_warning(
                "No history yet",
                f"No origin snapshots stored for {target}. Use ORIGIN SNAPSHOT "
                "on an IP to start recording.",
            )
            return
        rows = []
        for ts, payload in snaps:
            rows.append([
                history.ago(ts),
                ", ".join(f"AS{a}" for a in payload.get("asns", [])) or "—",
                payload.get("prefix") or "—",
                payload.get("source") or "—",
            ])
        await self.push(
            table_panel(
                self.palette, f"Origin history — {target}",
                ["When", "Origin AS", "Prefix", "Source"], rows,
                subtitle=f"{len(snaps)} snapshot(s), newest first",
            )
        )


async def _none():
    return None
