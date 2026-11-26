"""SUBNET CALC — pure local maths. No API, no key, no rate limit, works offline."""

from __future__ import annotations

from ..local import subnet
from ..render import kv_panel, table_panel, text_panel
from ..validators import ValidationError, valid_network, require
from .base import Action, Field, LookupPane


class SubnetPane(LookupPane):
    PANE_TITLE = "SUBNET CALCULATOR"
    DESCRIPTION = (
        "IPv4 and IPv6 CIDR maths done locally with Python's ipaddress module — "
        "instant, offline and rate-limit free."
    )
    FIELDS = (
        Field("network", "Network (CIDR)", "192.168.10.0/24"),
        Field("split", "Split into /", "27", width=20),
        Field("hosts", "Hosts needed", "50", width=20),
    )
    ACTIONS = (
        Action("describe", "ANALYSE"),
        Action("split", "SPLIT", primary=False),
        Action("fit", "FIT HOSTS", primary=False),
        Action("range", "RANGE → CIDR", primary=False),
    )

    async def execute(self, action: str) -> None:
        if action == "range":
            await self._range()
            return

        network = valid_network(self.field("network"))
        await self.begin(f"Calculating {network}…")
        await self.finish()

        if action == "describe":
            await self.push(
                kv_panel(
                    self.palette,
                    f"Network analysis — {network}",
                    subnet.describe(network),
                    subtitle="local · ipaddress",
                )
            )
            return

        if action == "split":
            raw = require(self.field("split"), "New prefix").lstrip("/")
            try:
                new_prefix = int(raw)
            except ValueError:
                raise ValidationError(f"'{raw}' is not a prefix length.")
            try:
                rows = subnet.split_into(network, new_prefix)
            except ValueError as exc:
                raise ValidationError(str(exc))
            await self.push(
                table_panel(
                    self.palette,
                    f"{network} split into /{new_prefix}",
                    ["#", "Subnet", "First host", "Last host", "Usable"],
                    rows,
                    subtitle=f"{len(rows)} shown",
                )
            )
            return

        if action == "fit":
            raw = require(self.field("hosts"), "Host count")
            try:
                wanted = int(raw.replace(",", ""))
            except ValueError:
                raise ValidationError(f"'{raw}' is not a number of hosts.")
            try:
                prefix, note = subnet.hosts_needed(network, wanted)
            except ValueError as exc:
                raise ValidationError(str(exc))
            candidate = valid_network(f"{network.network_address}/{prefix}")
            await self.push(
                kv_panel(
                    self.palette,
                    f"Smallest subnet for {wanted:,} hosts",
                    [("Recommended prefix", f"/{prefix}"), ("Why", note)]
                    + subnet.describe(candidate),
                    subtitle="local · ipaddress",
                )
            )

    async def _range(self) -> None:
        """Turn 'start - end' typed in the network field into CIDR blocks."""
        raw = require(self.field("network"), "Address range")
        import re

        parts = [p.strip() for p in re.split(r"\s*(?:-|–|to)\s*", raw, flags=re.I)
                 if p.strip()]
        if len(parts) != 2:
            raise ValidationError(
                "For RANGE → CIDR, put a range in the Network field, "
                "e.g. 10.0.0.5 - 10.0.3.200"
            )
        await self.begin("Summarising range…")
        await self.finish()
        try:
            blocks = subnet.summarise_range(parts[0], parts[1])
        except ValueError as exc:
            raise ValidationError(str(exc))
        await self.push(
            table_panel(
                self.palette,
                f"{parts[0]} → {parts[1]}",
                ["#", "CIDR block"],
                [[i + 1, block] for i, block in enumerate(blocks)],
                subtitle=f"{len(blocks)} block(s)",
            )
        )
