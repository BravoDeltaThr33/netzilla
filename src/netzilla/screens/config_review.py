"""CONFIG — paste-in config / show-output summarizer.

Paste a `show interfaces`, `show ip route` or a running-config and netzilla
flags interfaces carrying errors, err-disabled or protocol-down ports, and the
route count by protocol. Pure local text parsing — nothing leaves the machine —
so it is safe for production configs and doubles as a CCNA study aid.
"""

from __future__ import annotations

from textual.containers import Horizontal, Vertical
from textual.widgets import Label, Static, TextArea

from ..local import confparse
from ..render import kv_panel, table_panel, verdict_line
from .base import ActionButton, ActionRow, LookupPane, control_head

SAMPLE = "Paste 'show interfaces', 'show ip route', or a running-config here…"


class ConfigPane(LookupPane):
    PANE_TITLE = "CONFIG REVIEW"
    DESCRIPTION = (
        "Paste device output and netzilla flags what you would scan for by eye: "
        "interfaces with error counters, err-disabled or protocol-down ports, "
        "and route counts by protocol. Nothing is sent anywhere."
    )
    ACTIONS = ()  # custom layout below

    def compose(self):
        control = Vertical(classes="control-bar")
        control.border_title = self.PANE_TITLE
        with control:
            yield control_head(self.DESCRIPTION)
            yield Label("PASTE DEVICE OUTPUT", classes="field-label collapsible")
            yield TextArea(id="config-input", classes="config-input collapsible")
            with Vertical(classes="action-grid"):
                with ActionRow(classes="action-row"):
                    yield ActionButton("ANALYSE", id="act-analyse", classes="action primary")
                    yield ActionButton("CLEAR", id="act-clear", classes="action")
        yield from self.compose_output()

    def _text(self) -> str:
        try:
            return self.query_one("#config-input", TextArea).text
        except Exception:
            return ""

    async def execute(self, action: str) -> None:
        if action == "clear":
            try:
                self.query_one("#config-input", TextArea).text = ""
            except Exception:
                pass
            await self.results.remove_children()
            self.hide_help()
            return

        text = self._text().strip()
        if not text:
            await self.begin("Nothing to analyse")
            await self.finish()
            await self.push_warning(
                "Paste some output first",
                "Copy a 'show interfaces', 'show ip route' or running-config into "
                "the box above, then press ANALYSE.",
            )
            return

        await self.begin("Analysing pasted output…")
        result = confparse.summarize(text)
        await self.finish()

        kind_label = {
            "interfaces": "show interfaces",
            "routes": "show ip route",
            "config": "running-config",
            "unknown": "device output",
        }.get(result["kind"], result["kind"])

        worst = _worst_state(result["findings"])
        await self.push(
            verdict_line(
                self.palette, "Detected",
                f"{kind_label} — {len(result['findings'])} finding(s)", worst,
            )
        )
        await self.push(
            table_panel(
                self.palette, "Findings", ["Level", "Detail"],
                confparse.finding_rows(result),
                subtitle="local analysis only",
            )
        )

        interfaces = result.get("interfaces") or []
        if interfaces:
            rows = [
                [i["name"], i["link"], i["protocol"],
                 ", ".join(f"{v} {k}" for k, v in i["errors"].items()) or "—"]
                for i in interfaces
            ]
            await self.push(
                table_panel(
                    self.palette, f"Interfaces ({len(interfaces)})",
                    ["Interface", "Link", "Protocol", "Errors"], rows,
                )
            )

        counts = result.get("route_counts")
        if counts:
            await self.push(
                kv_panel(
                    self.palette, "Routes by protocol",
                    [(proto, n) for proto, n in sorted(counts.items())],
                    subtitle=f"{sum(counts.values())} total",
                )
            )


def _worst_state(findings) -> str:
    order = {"bad": 3, "warn": 2, "info": 1, "ok": 0}
    if not findings:
        return "ok"
    return max((f[0] for f in findings), key=lambda s: order.get(s, 0))
