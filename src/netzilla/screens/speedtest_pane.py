"""SPEED TEST — real throughput from this machine, graphed while it runs.

RUN SPEED TEST   built in, nothing to install: Cloudflare's free speed-test
                 endpoints (the ones speed.cloudflare.com uses). Latency,
                 jitter, download, upload and bufferbloat — latency measured
                 while the line is busy — with live graphs.
OOKLA TEST       Ookla's servers through speedtest-cli or Ookla's own CLI,
                 when one of them is installed.
"""

from __future__ import annotations

import time

from rich.panel import Panel
from rich.text import Text
from textual.widgets import Static

from ..graphics.charts import LineGraph
from ..local import cfspeed, speed
from ..local.wifitools import nice_ceiling
from ..render import PANEL_BOX, kv_panel, text_panel, verdict_line
from .base import Action, LookupPane

PHASES = {
    "latency": "measuring latency",
    "download": "downloading",
    "upload": "uploading",
    "done": "finished",
}


class SpeedTestPane(LookupPane):
    PANE_TITLE = "SPEED TEST"
    DESCRIPTION = (
        "Measures real throughput from this machine. RUN SPEED TEST is built in "
        "— Cloudflare's free test servers, nothing to install — and graphs "
        "download and upload live, with latency, jitter and bufferbloat. OOKLA "
        "TEST uses Ookla's servers when speedtest-cli or Ookla's CLI is installed."
    )
    FIELDS = ()
    ACTIONS = (
        Action("run", "RUN SPEED TEST"),
        Action("ookla", "OOKLA TEST", primary=False),
    )
    # Tests swap the measuring function out.
    RUNNER = staticmethod(cfspeed.run)

    async def execute(self, action: str) -> None:
        if action == "ookla":
            await self._ookla()
        else:
            await self._builtin()

    # ------------------------------------------------------------ built-in
    async def _builtin(self) -> None:
        if self.services.offline:
            await self.begin("Speed test")
            await self.finish()
            await self.push_warning("Offline mode",
                                    "A speed test needs the network — restart without --offline.")
            return
        await self.begin("Starting the speed test — about 15 seconds. It saturates "
                         "the link while it runs…")
        headline, graphs = Static(classes="result-panel"), Static(classes="result-panel")
        for widget in (headline, graphs):
            await self.push_widget(widget)
        started = time.monotonic()
        last = {"at": 0.0, "phase": None}

        def draw(progress: cfspeed.Progress, force: bool = False) -> None:
            now = time.monotonic()
            # At most five repaints a second — but never skip a change of
            # phase: "finished" arrives a moment after the last upload sample
            # and must not be dropped, or the headline stays on "uploading".
            changed = progress.phase != last["phase"]
            if not (force or changed) and now - last["at"] < 0.2:
                return
            last["at"], last["phase"] = now, progress.phase
            phase = PHASES.get(progress.phase, progress.phase)
            ping = (f" · latency {sorted(progress.latency)[len(progress.latency) // 2]:.0f} ms"
                    if progress.latency else "")
            headline.update(verdict_line(
                self.palette, "● SPEED TEST" if progress.phase != "done" else "■ SPEED TEST",
                f"{phase}{' · ' + format(progress.now_mbps, '.1f') + ' Mbit/s now' if progress.phase in ('download', 'upload') else ''}"
                f"{ping} · {now - started:.0f}s",
                "ok"))
            graphs.update(self._graph_panel(progress))
            self.progress(f"Speed test: {phase}…")

        try:
            results = await self.RUNNER(draw, user_agent=self.services.config.user_agent)
        except Exception as exc:
            await self.finish()
            await self.push_error(
                "Speed test failed",
                f"{exc}\n\nThe built-in test talks to speed.cloudflare.com over "
                "HTTPS. If a proxy or firewall blocks it, OOKLA TEST may still work.",
            )
            return
        await self.finish()
        await self._show_results(results)

    def _graph_panel(self, progress: cfspeed.Progress):
        width = self._graph_width()
        parts = Text(no_wrap=True, overflow="crop")
        for index, (label, samples, colour) in enumerate((
            ("Download", progress.down, self.palette.accent),
            ("Upload", progress.up, self.palette.primary),
        )):
            if index:
                parts.append("\n\n")
            now = f"{samples[-1]:.1f} Mbit/s" if samples else "waiting"
            parts.append(f"{label} — {now}\n", style=f"bold {self.palette.secondary}")
            peak = nice_ceiling(max(samples or [1.0]))
            seconds = cfspeed.DOWN_SECONDS if label == "Download" else cfspeed.UP_SECONDS
            parts.append_text(self.graph(
                label.lower(),
                LineGraph(samples, floor=0.0, ceil=peak, width=width,
                          height=6 if label == "Download" else 4,
                          label=lambda v: f"{v:g} Mb/s", colour=colour,
                          # the phase's fixed time axis, filling from the left
                          slots=int(seconds / cfspeed.SAMPLE_EVERY) + 1, align="left"),
                colour=colour,
            ))
        if progress.latency:
            parts.append("\n\n")
            parts.append("Latency — idle ", style=f"bold {self.palette.secondary}")
            parts.append(f"{min(progress.latency):.0f}–{max(progress.latency):.0f} ms",
                         style=self.palette.foreground)
            if progress.loaded:
                parts.append("   under load ", style=f"bold {self.palette.secondary}")
                parts.append(f"{min(progress.loaded):.0f}–{max(progress.loaded):.0f} ms",
                             style=self.palette.foreground)
        return Panel(
            parts,
            title=Text(" THROUGHPUT, LIVE ", style=f"bold {self.palette.primary}"),
            title_align="left",
            subtitle=Text(f" a sample every {cfspeed.SAMPLE_EVERY:g}s · 4 parallel streams ",
                          style=self.palette.muted),
            subtitle_align="right",
            border_style=self.palette.secondary,
            box=PANEL_BOX,
            padding=(0, 1),
        )

    def _graph_width(self) -> int:
        try:
            width = int(self.size.width)
        except Exception:
            width = 0
        return max(24, min(160, width - 22)) if width > 46 else 60

    # ---------------------------------------------------------------- Ookla
    async def _ookla(self) -> None:
        if not speed.available():
            await self.begin("No Ookla backend found")
            await self.finish()
            await self.push_error(
                "Ookla test unavailable",
                speed.diagnosis() + "\n\nRUN SPEED TEST needs none of this — it "
                "is built in.")
            return

        # The instruction card (which carries the saturation warning) stays up
        # while the test runs; results replace it when they arrive.
        await self.begin(
            "Starting the Ookla test — about 30 seconds. It saturates the link while it runs…"
        )
        try:
            results = await speed.run_test(progress=self.progress)
        except Exception as exc:
            await self.finish()
            await self.push_error(
                "Speed test failed",
                f"{exc}\n\n"
                "'HTTP Error 403: Forbidden' means Ookla's servers refused the "
                "unofficial speedtest-cli client — this happens periodically. "
                "Installing Ookla's official CLI "
                "(https://www.speedtest.net/apps/cli) fixes it; netzilla uses "
                "it automatically. RUN SPEED TEST (built in) is unaffected.",
            )
            return
        await self.finish()
        await self._show_results(results)

    # -------------------------------------------------------------- results
    async def _show_results(self, results: dict) -> None:
        down = results.get("download_mbps", 0)
        up = results.get("upload_mbps", 0)
        state = "ok" if down >= 25 else "warn" if down >= 5 else "bad"
        extra = ""
        if results.get("bufferbloat"):
            extra = f" · bufferbloat {results['bufferbloat']}"
        await self.push(
            verdict_line(
                self.palette,
                "Throughput",
                f"{down:.1f} Mbit/s down · {up:.1f} Mbit/s up · "
                f"{results.get('ping_ms') or 0:.0f} ms{extra}",
                state,
            )
        )
        await self.push(
            kv_panel(
                self.palette,
                "Speed test results",
                speed.summarise(results),
                subtitle=f"local measurement · {results.get('backend') or 'Ookla'}",
            )
        )
        grade = results.get("bufferbloat")
        if grade and grade not in ("A+", "A"):
            await self.push_warning(
                f"Bufferbloat grade {grade}",
                f"Latency rose by {results.get('bufferbloat_added_ms', 0):.0f} ms while "
                "the line was busy. Video calls and games stutter whenever someone "
                "else is downloading. Smart queue management on the router (SQM — "
                "fq_codel or CAKE) usually fixes it.",
            )
        if results.get("share_url"):
            await self.push(
                text_panel(
                    self.palette, "Shareable result", results["share_url"],
                    style=self.palette.muted,
                )
            )
