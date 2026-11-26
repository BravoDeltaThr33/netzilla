"""MAC LOOKUP — offline IEEE registry first, macvendors.com as fallback.

A full MAC that is on this LAN right now is also found in the neighbour table
and identified like LAN > SWEEP does: its IP, hostname and what it looks like.
"""

from __future__ import annotations

from ..clients import macvendors
from ..local import devices, oui
from ..render import kv_panel, table_panel, text_panel
from ..validators import mac_oui, valid_mac
from .base import Action, Field, LookupPane


class MACPane(LookupPane):
    PANE_TITLE = "MAC / OUI LOOKUP"
    DESCRIPTION = (
        "Resolves a MAC address to its vendor. The bundled IEEE registry (all "
        "three block sizes, ~54,000 entries) is checked first — offline and "
        "instant — with macvendors.com as a keyless fallback. A full MAC that "
        "is on your LAN right now is also matched to its IP and identified. "
        "Accepts 00:1A:2B:3C:4D:5E, 001A2B3C4D5E or Cisco-style 0011.2233.4455."
    )
    FIELDS = (Field("mac", "MAC address or OUI", "00:1A:2B:3C:4D:5E"),)
    ACTIONS = (
        Action("lookup", "LOOK UP"),
        Action("offline", "OFFLINE ONLY", primary=False),
        Action("update", "UPDATE OUI TABLE", primary=False),
    )

    async def execute(self, action: str) -> None:
        if action == "update":
            await self._update()
            return

        mac = valid_mac(self.field("mac"))
        prefix = mac_oui(mac)

        await self.begin(f"Resolving {mac}…")
        vendor = oui.lookup_mac(oui.hex_only(mac)) or oui.lookup(prefix)
        source = f"offline IEEE registry ({oui.entry_count():,} entries)"
        full = len(oui.hex_only(mac)) == 12
        randomised = full and oui.mac_kind(mac) == "random"

        if randomised:
            # A locally administered address was never registered to anyone,
            # so asking an online service would only leak it for nothing.
            source = "not looked up — randomised / locally administered address"
        elif vendor is None and action != "offline":
            self.progress("Not in the local table — querying macvendors.com…")
            remote = await macvendors.lookup(self.services, mac)
            if remote.ok:
                vendor = remote.data
                source = "macvendors.com" + (" (cached)" if remote.cached else "")
            else:
                source = f"local table only — {remote.error}"

        where = None
        if full and action != "offline":
            self.progress("Looking for it on this LAN…")
            where = await self._on_lan(mac)
        await self.finish()
        await self.push(
            kv_panel(
                self.palette,
                f"Vendor — {mac}",
                oui.describe(mac, vendor, source),
                subtitle=source,
            )
        )
        if where:
            await self.push(where)

        if randomised:
            await self.push(
                text_panel(
                    self.palette, "Why there is no vendor",
                    "This is a randomised (private) address: the second-lowest "
                    "bit of the first byte is set, which means it was made up "
                    "by the device rather than assigned by a maker. iPhones, "
                    "Android phones, Windows and macOS all use one per Wi-Fi "
                    "network by default, so on a home LAN it is almost always "
                    "a phone, tablet or laptop. Virtual machines and containers "
                    "use them too.\n\nTo name the device, identify it by IP "
                    "instead: LAN > SWEEP, or LAN > IDENTIFY with its address.",
                    style=self.palette.accent,
                )
            )
        elif vendor is None:
            await self.push_warning(
                "No vendor match",
                "Unregistered OUIs are common on virtual machines, randomised "
                "client MACs and locally administered addresses. Check the "
                "'Locally administered' flag above before assuming a lookup "
                "failure.\n\nRun UPDATE OUI TABLE to pull the full IEEE registry.",
            )

    async def _on_lan(self, mac: str):
        """A panel naming this MAC's IP and device, if it is on the LAN now."""
        from ..local.lan import arp_table

        wanted = oui.hex_only(mac)
        try:
            table = await arp_table()
        except Exception:
            return None
        ips = [ip for ip, seen in table.items() if oui.hex_only(seen) == wanted]
        if not ips:
            return None
        known = await devices.identify_ips(ips, progress=self.progress)
        rows = []
        for ip in ips:
            dev = known.get(ip, {})
            rows.append([ip, devices.display_name(dev), dev.get("device", ""),
                         devices.details(dev)])
        return table_panel(
            self.palette, "On your network right now",
            ["IP", "Hostname", "Device", "Details"], rows,
            subtitle="found in this machine's neighbour (ARP) table",
        )

    async def _update(self) -> None:
        import asyncio

        if self.services.offline:
            await self.begin("Update OUI table")
            await self.finish()
            await self.push_warning(
                "Offline mode",
                "Updating the table downloads the IEEE registries, and netzilla "
                f"was started with --offline. The bundled table ({oui.entry_count():,} "
                "entries) is in use — restart without --offline to update it.",
            )
            return
        await self.begin("Downloading the IEEE registries (MA-L, MA-M, MA-S — about 5 MB)…")
        try:
            count = await asyncio.to_thread(oui.update_from_ieee)
        except Exception as exc:
            await self.finish()
            await self.push_error(
                "Update failed",
                f"{exc}\n\nThe bundled table is still in place with "
                f"{oui.entry_count():,} entries.",
            )
            return
        await self.finish()
        await self.push(
            text_panel(
                self.palette,
                "OUI table updated",
                f"Wrote {count:,} vendor prefixes to\n{oui.user_table_path()}\n\n"
                "Lookups now resolve almost everything without leaving your machine.",
                style=self.palette.success,
                border=self.palette.success,
            )
        )
