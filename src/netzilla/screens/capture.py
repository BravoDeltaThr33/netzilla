"""CAPTURE — tshark and tcpdump, with their output kept inside netzilla.

Nothing here opens a full-screen program. CAPTURE is bounded by a packet count
and a time window, so it prints and stops; LIVE CAPTURE runs until it is
stopped and renders in place while it does. tshark's printed packets are parsed
into a real table with a systime column, a protocol mix and top talkers
alongside; tcpdump is shown as it prints, since raw tcpdump output is what
people paste into tickets.

Every capture leaves its packets in memory afterwards, so FILTER HELD can
narrow them down without going back to the wire — which matters most for a
live capture, where the traffic that made you look has already gone past.

FILTER HELP is a first-class action rather than a footnote, because the two
tools speak different filter languages — Wireshark display filters for tshark,
BPF for tcpdump — and that is the thing that trips people up.
"""

from __future__ import annotations

import asyncio
import contextlib
import time

from textual.widgets import Static

from ..local import capture, devices, netif
from ..local.elevation import SESSION
from ..render import kv_panel, table_panel, text_panel, verdict_line
from ..validators import ValidationError
from .base import Action, Field, LookupPane
from .password import PasswordPrompt


class CaptureAccess:
    """Getting permission to capture, shared by CAPTURE and WIFI > PACKETS.

    Both tabs open interfaces the same way, so they share one route to
    privilege: an existing capability or group membership if there is one,
    otherwise one sudo password for the whole netzilla session, otherwise
    pkexec. Unlocking on either tab unlocks both.
    """

    _auth_note = ""

    async def _permission(self) -> list[str] | None:
        """The prefix to run capture tools with, or None (already reported).

        When the only route left is pkexec — which puts a desktop password
        dialog in front of every single capture — netzilla asks for the
        password once, here, in its own box, and opens a sudo session with it
        instead. Everything afterwards runs with `sudo -n` and asks nothing,
        which is the difference between authenticating once and authenticating
        on every button press.
        """
        prefix, rows = await capture.permission_report()
        if prefix == ["pkexec"] and capture.can_unlock():
            if await self._unlock_for_session():
                prefix, rows = await capture.permission_report()
        if prefix is None:
            await self.finish()
            argv, shown, why = capture.fix_command()
            await self.push_error(
                "netzilla cannot capture packets yet",
                "Opening an interface in promiscuous mode needs privilege, and "
                "none of the available routes are usable right now.\n\n"
                + (
                    "Press FIX PERMISSIONS and netzilla runs the one-time "
                    "setup for you — your desktop asks for your password:\n\n"
                    f"{shown}\n\n"
                    "Capturing works straight afterwards; only the group "
                    "membership waits for your next login."
                    if argv is not None
                    else "Run this once in a terminal, then log out and back "
                    f"in:\n\n{capture.SETUP_STEPS}\n\n"
                    f"(FIX PERMISSIONS is unavailable here: {why}.)"
                ),
            )
            await self.push(
                kv_panel(self.palette, "What netzilla checked", rows)
            )
        return prefix

    async def _unlock_for_session(self) -> bool:
        """Ask for the sudo password once and open a session with it.

        Returns True when the session is unlocked. Cancelling is not an error:
        the caller falls back to pkexec, which still works, just one dialog at
        a time.
        """
        self._auth_note = ""
        self.progress("Authenticating once for this netzilla session…")
        password = await self.app.push_screen_wait(
            PasswordPrompt(
                title="AUTHENTICATE ONCE FOR THIS SESSION",
                note=(
                    "Your sudo password (your login password on Mint and "
                    "Ubuntu). Enter it once and every capture for the rest of "
                    "this netzilla run goes through with no further prompt — "
                    "including when you move between tabs.\n\n"
                    "It is used once to open a sudo session and then dropped; "
                    "netzilla does not keep it. Cancel to be asked by your "
                    "desktop before each capture instead."
                ),
            )
        )
        if not password:
            return False
        self.progress("Opening a sudo session…")
        ok, why = await SESSION.unlock(password)
        del password
        if not ok:
            self._auth_note = why
        return ok

    async def _missing(self, tool: str) -> None:
        await self.push_error(
            f"{tool} is not installed",
            f"Install it with:\n    sudo apt install -y {tool}\n\n"
            + capture.SETUP_STEPS,
        )


class CapturePane(CaptureAccess, LookupPane):
    PANE_TITLE = "PACKET CAPTURE"
    DESCRIPTION = (
        "tshark and tcpdump, with their output kept here. LIVE CAPTURE runs "
        "until you press STOP LIVE, which ends it and keeps every packet in "
        "memory — FILTER HELD then narrows them down as often as you like, "
        "without capturing again. CAPTURE is the bounded version. Saved files "
        "open in the full Wireshark later. FILTER HELP lists the filters worth "
        "knowing. Capturing needs permission: netzilla asks for your password "
        "once and does not ask again while it is running."
    )
    FIELDS = (
        Field("iface", "Interface", "press TOOL CHECK to refresh", choices=()),
        Field(
            "filter", "Filter  (tshark or tcpdump syntax)",
            "blank = all · e.g. http, port 80",
        ),
        Field("count", "Packets", "50", value="50", width=14),
        Field("every", "Refresh every (s)", "blank = 0.6", width=22),
        Field("pcap", "PCAP file", "~/capture.pcapng", width=30),
    )
    ACTIONS = (
        Action("live", "LIVE CAPTURE"),
        Action("stop", "STOP LIVE"),
        Action("held", "FILTER HELD", primary=False),
        Action("capture", "CAPTURE"),
        Action("tcpdump", "TCPDUMP CAPTURE", primary=False),
        Action("protocols", "PROTOCOL STATS", primary=False),
        Action("talkers", "TOP TALKERS", primary=False),
        Action("save", "SAVE PCAP", primary=False),
        Action("read", "READ PCAP", primary=False),
        Action("filters", "FILTER HELP", primary=False),
        Action("tools", "TOOL CHECK", primary=False),
        Action("auth", "AUTHENTICATE", primary=False),
        Action("fix", "FIX PERMISSIONS", primary=False),
    )

    # How long a bounded capture may wait for its packet count to fill.
    WINDOW = 30
    # A live capture runs until stopped, but not past this, so one left open
    # behind another tab cannot hold an interface all afternoon.
    LIVE_LIMIT = 15 * 60
    # How many packets are kept in memory for filtering after a capture ends.
    # Only the newest HOLD_LIMIT survive, so a busy link cannot grow without
    # bound; 10,000 is a few megabytes and far more than anyone reads by eye.
    HOLD_LIMIT = 10_000
    # How many of them the live table shows while it is running.
    LIVE_ROWS = 40

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._interfaces: list[dict] = []
        # Packets kept after a capture finishes, so FILTER HELD can work
        # through them without capturing again. Replaced by the next capture.
        self._held: list[dict] = []
        self._held_source = ""
        self._held_filter = ""
        # Set while a live capture is running; STOP LIVE raises the flag and
        # the live loop winds itself up, which is what keeps the packets.
        self._live_running = False
        self._stop_live = False
        # Why a one-time unlock did not happen, carried into the result.
        self._auth_note = ""

    async def on_mount(self) -> None:
        self.run_worker(self._load_interfaces(), group=f"cap-{id(self)}")

    async def _load_interfaces(self) -> list[dict]:
        found, _source = await netif.interfaces()
        self._interfaces = found
        names = [i["name"] for i in found]
        current = self.field("iface")
        self.set_choices(
            "iface", names,
            current if current in names else netif.pick_default(found),
        )
        return found

    # ------------------------------------------------------------- helpers
    def _iface(self) -> str:
        name = self.field("iface")
        if not name:
            raise ValidationError(
                "Pick an interface from the dropdown first. If it is empty, "
                "press TOOL CHECK to re-read the interface list."
            )
        return name

    def _count(self, default: int = 50) -> int:
        raw = self.field("count") or str(default)
        try:
            value = int(float(raw))
        except ValueError:
            raise ValidationError("Packets must be a whole number, e.g. 50.")
        if not 1 <= value <= 5000:
            raise ValidationError("Packets must be between 1 and 5000.")
        return value

    def _pcap(self) -> str:
        return capture.resolve_pcap(self.field("pcap"))

    # ------------------------------------------------------------ dispatch
    def dispatch(self, action: str) -> None:
        """STOP LIVE is handled here rather than as a worker.

        Every other button starts an exclusive worker, which cancels whatever
        was running — fine for a lookup, wrong for a live capture, where the
        packets collected so far are the whole point. STOP instead raises a
        flag the running capture watches, so it finishes its own work, keeps
        its packets and renders them.
        """
        if action == "stop" and self._live_running:
            self._stop_live = True
            self.progress("Stopping the capture — keeping everything caught…")
            return
        super().dispatch(action)

    async def execute(self, action: str) -> None:
        if action == "filters":
            await self._filters()
        elif action == "tools":
            await self._tools()
        elif action == "capture":
            await self._capture()
        elif action == "tcpdump":
            await self._tcpdump()
        elif action in ("protocols", "talkers"):
            await self._stats(action)
        elif action == "save":
            await self._save()
        elif action == "read":
            await self._read()
        elif action == "fix":
            await self._fix()
        elif action == "live":
            await self._live()
        elif action == "stop":
            await self._stop()
        elif action == "held":
            await self._held_data()
        elif action == "auth":
            await self._authenticate()

    # --------------------------------------------------------- live capture
    async def _live(self) -> None:
        """tshark with no count and no duration, rendered where it is started.

        The whole results area becomes the live view for as long as this runs:
        a banner saying it is live and on what, the running figures, and the
        packets themselves newest first. Nothing else is mounted underneath,
        so there is no second view to be dropped into.

        STOP LIVE ends it and keeps every packet. Any other button also stops
        it — that cancels this worker — and the packets are kept either way,
        because they are handed over before the cancellation is allowed to
        propagate.
        """
        iface = self._iface()
        display_filter = self.field("filter")
        if problem := capture.check_filter(display_filter):
            raise ValidationError(problem)
        repaint = self._every(0.6, low=0.2)

        await self.begin("Checking capture permission…")
        prefix = await self._permission()
        if prefix is None:
            return

        # A new capture replaces whatever the last one held, as promised.
        self._held, self._held_source, self._held_filter = [], "", ""

        live = capture.LiveCapture(
            iface, display_filter, prefix, keep=self.HOLD_LIMIT
        )
        why = await live.start()
        if why:
            await self.finish()
            if "not installed" in why:
                await self._missing("tshark")
            else:
                await self.push_error("Could not start tshark", why)
            return

        running_as = (
            "sudo — unlocked once for this session" if SESSION.active
            else (" ".join(prefix) if prefix else "no elevation needed")
        )
        banner = Static(classes="result-panel")
        graph = Static(classes="result-panel")
        summary = Static(classes="result-panel")
        table = Static(classes="result-panel")
        for widget in (banner, graph, summary, table):
            await self.push_widget(widget)

        self._live_running = True
        self._stop_live = False
        started = time.monotonic()
        last_render = 0.0
        stopped_because = "you stopped it"
        rate: list[float] = []
        mark = {"at": started, "total": 0}

        def render(running: bool = True) -> None:
            elapsed = time.monotonic() - started
            now = time.monotonic()
            if running and now - mark["at"] > 0:
                rate.append((live.total - mark["total"]) / (now - mark["at"]))
                del rate[:-600]
                mark["at"], mark["total"] = now, live.total
            graph.update(self._rate_graph(rate, repaint))
            target = iface + (f"  ·  {display_filter}" if display_filter else "")
            banner.update(
                verdict_line(
                    self.palette,
                    "● LIVE CAPTURE" if running else "■ LIVE CAPTURE",
                    (f"RUNNING on {target} — {live.total:,} packets in "
                     f"{elapsed:.0f}s.  Press STOP LIVE to end it and keep them."
                     if running else
                     f"STOPPED — {live.total:,} packets from {target}, held in "
                     f"memory for FILTER HELD."),
                    "ok" if running else "info",
                )
            )
            summary.update(
                kv_panel(
                    self.palette,
                    "Live capture" if running else "Live capture (stopped)",
                    capture.live_summary(live, elapsed, running_as),
                    subtitle=("running — STOP LIVE keeps the packets, any "
                              "other button also stops it"
                              if running else "not running"),
                )
            )
            recent = list(reversed(live.packets[-self.LIVE_ROWS:]))
            table.update(
                table_panel(
                    self.palette,
                    "Packets, as they arrive" if running else "Last packets seen",
                    capture.PACKET_COLUMNS,
                    capture.packet_rows(recent, limit=self.LIVE_ROWS),
                    subtitle=(
                        f"newest first — {len(recent)} of {live.total:,}"
                        if recent else "waiting for traffic…"
                    ),
                )
            )

        render()
        self.progress(f"LIVE on {iface} — press STOP LIVE to end and keep.")
        try:
            async for _packet in live.packets_as_they_arrive(idle=0.5):
                now = time.monotonic()
                if self._stop_live:
                    stopped_because = "you pressed STOP LIVE"
                    break
                if now - started > self.LIVE_LIMIT:
                    stopped_because = (
                        f"netzilla stopped it after {self.LIVE_LIMIT // 60} minutes"
                    )
                    break
                if now - last_render < repaint:
                    continue          # coalesce bursts into one repaint
                last_render = now
                render()
                self.progress(
                    f"LIVE on {iface} — {live.total:,} packets. STOP LIVE ends "
                    "it and keeps them."
                )
            else:
                stopped_because = "tshark exited on its own"
        finally:
            # First, and before anything that can be cancelled: keep what was
            # captured. This is the promise STOP LIVE makes, and it has to hold
            # even when the run ends by being cancelled from another button.
            # The rolling buffer is allowed to overshoot between trims, so the
            # cap is applied once here where it is handed over.
            self._held = list(live.packets[-self.HOLD_LIMIT:])
            self._held_source = f"{iface} (live)"
            self._held_filter = display_filter
            self._live_running = False
            self._stop_live = False
            with contextlib.suppress(Exception, asyncio.CancelledError):
                stderr = await asyncio.shield(live.stop())
                render(running=False)
                await self.finish()
                await self._after_live(
                    stopped_because, live.total,
                    time.monotonic() - started, stderr,
                )

    def _rate_graph(self, rate: list[float], every: float):
        """Packets per second, one column per repaint, newest on the right."""
        from ..graphics.charts import LineGraph
        from ..local.wifitools import nice_ceiling

        width = self.graph_width()
        top = nice_ceiling(max(rate or [1.0]))
        return self.graphs_panel(
            "Packets per second",
            [(f"Now {rate[-1]:.0f}/s" if rate else "Waiting for packets", "capture-rate",
              LineGraph(rate[-width:], floor=0.0, ceil=top, width=width, height=5,
                        label=lambda v: f"{v:.0f}/s", colour=self.palette.accent),
              self.palette.accent)],
            subtitle=f"a column every {every:g}s, newest on the right",
        )

    async def _after_live(
        self, stopped_because: str, total: int, elapsed: float, stderr: str
    ) -> None:
        """What is said once a live capture has ended."""
        await self.push(
            verdict_line(
                self.palette, "Stopped",
                f"{stopped_because} — {total:,} packets in {elapsed:.0f}s",
                "info",
            )
        )
        if self._held:
            await self.push(
                text_panel(
                    self.palette,
                    f"{len(self._held):,} packets are held in memory",
                    "The capture has stopped but nothing has been thrown away. "
                    "Type a filter in the FILTER box and press FILTER HELD to "
                    "work through these packets — as many times as you like, "
                    "with a different filter each time.\n\n"
                    "They stay until the next capture replaces them. To keep "
                    "them past this netzilla run, use SAVE PCAP instead: that "
                    "writes a file the full Wireshark can open.",
                    style=self.palette.accent,
                )
            )
        if self._auth_note:
            await self.push_warning(
                "The one-time unlock did not happen",
                f"{self._auth_note}.\n\nThat capture ran through pkexec "
                "instead, which asks your desktop for a password each time. "
                "AUTHENTICATE tries the session unlock again; FIX PERMISSIONS "
                "sets capturing up so that no password is needed at all.",
            )
        if total == 0:
            await self.push_warning(
                "Nothing arrived",
                (f"tshark said: {stderr}\n\n" if stderr else "")
                + "Either the link was quiet or the filter excluded "
                "everything. Clear the FILTER box to see all traffic, "
                "or press FILTER HELP for working examples.",
            )
        elif stderr and "dropped" not in stderr.lower():
            await self.push_warning("tshark also said", stderr)

    # ---------------------------------------------------- stop / held data
    async def _stop(self) -> None:
        """Only reached when nothing was running — dispatch() handles the
        real stop without starting a worker, so that it cannot cancel the
        capture it is meant to be ending politely."""
        await self.begin("Nothing to stop")
        await self.finish()
        if self._held:
            await self.push(
                verdict_line(
                    self.palette, "Already stopped",
                    f"{len(self._held):,} packets are still held — press "
                    "FILTER HELD to work through them", "info",
                )
            )
            return
        await self.push_warning(
            "No live capture is running",
            "STOP LIVE ends a running LIVE CAPTURE and keeps every packet it "
            "collected, so you can filter through them afterwards. There is "
            "nothing running at the moment.",
        )

    async def _held_data(self) -> None:
        """Re-filter the packets a finished capture left in memory."""
        if not self._held:
            await self.begin("Nothing held")
            await self.finish()
            await self.push_warning(
                "No packets are held",
                "FILTER HELD works through packets a finished capture left in "
                "memory. Run LIVE CAPTURE and press STOP LIVE, or run CAPTURE "
                "or READ PCAP — any of them leaves its packets here — then "
                "put a filter in the FILTER box and press FILTER HELD.",
            )
            return

        expression = self.field("filter")
        if problem := capture.check_filter(expression):
            raise ValidationError(problem)

        await self.begin(
            f"Filtering {len(self._held):,} held packets…"
        )
        kept, notes = capture.filter_packets(self._held, expression)
        await self.finish()
        await self.push(
            verdict_line(
                self.palette, "Held",
                f"{len(kept):,} of {len(self._held):,} packets match"
                + (f" {expression!r}" if expression else ""),
                "ok" if kept else "warn",
            )
        )
        await self.push(
            kv_panel(
                self.palette, "What this filter did",
                [("Source", self._held_source or "a previous capture"),
                 ("Captured with", self._held_filter or "no filter"),
                 ("Filtering now on", expression or "nothing — everything held"),
                 ("Matched", f"{len(kept):,} of {len(self._held):,}")]
                + [("Note", note) for note in notes],
                subtitle="applied in memory · nothing was captured again",
            )
        )
        if not kept:
            await self.push_warning(
                "Nothing matched",
                "The packets are still held — only this filter found nothing. "
                "Try a broader one, clear the FILTER box to see everything, or "
                "press FILTER HELP for the syntax.\n\n" + capture.LOCAL_FILTER_NOTE,
            )
            return
        await self.push(
            kv_panel(
                self.palette, "Summary of the matching packets",
                capture.capture_summary(kept, self._held_source or "held"),
                subtitle="in memory · not re-captured",
            )
        )
        await self.push(
            table_panel(
                self.palette, "Protocol mix",
                ["Protocol", "Packets", "Share", "Bytes"],
                capture.protocol_mix(kept),
            )
        )
        await self.push(
            table_panel(
                self.palette, "Matching packets",
                capture.PACKET_COLUMNS,
                capture.packet_rows(kept),
                subtitle=f"{min(len(kept), 200)} of {len(kept):,} shown",
            )
        )
        if (self._held_source or "").endswith("(live)"):
            await self._lan_devices(kept)
        await self.push(
            text_panel(
                self.palette, "How this filter is applied",
                capture.LOCAL_FILTER_NOTE, style=self.palette.muted,
            )
        )

    # -------------------------------------------------------- authenticate
    async def _authenticate(self) -> None:
        """Ask once, then keep sudo alive for as long as netzilla runs."""
        if SESSION.active:
            await self.begin("Locking this session…")
            await SESSION.lock()
            await self.finish()
            await self.push(
                verdict_line(self.palette, "Session", "locked", "info")
            )
            await self.push(
                text_panel(
                    self.palette, "Locked",
                    "sudo's timestamp has been dropped, so the next capture "
                    "will ask for permission again. Press AUTHENTICATE to "
                    "unlock for the session once more.",
                )
            )
            return

        if capture.is_root():
            await self.begin("Checking…")
            await self.finish()
            await self.push(
                verdict_line(
                    self.palette, "Session",
                    "already root — nothing to unlock", "ok",
                )
            )
            return

        password = await self.app.push_screen_wait(
            PasswordPrompt(
                title="AUTHENTICATE FOR THIS SESSION",
                note=(
                    "Your sudo password (your login password on Mint and "
                    "Ubuntu). It is used once to open a sudo session and then "
                    "discarded — netzilla does not keep it. Every capture for "
                    "the rest of this run goes through without a prompt."
                ),
            )
        )
        if not password:
            await self.begin("Cancelled")
            await self.finish()
            await self.push_warning(
                "Not unlocked",
                "No password was entered, so nothing changed. Captures will "
                "keep asking for permission each time.",
            )
            return

        await self.begin("Opening a sudo session…")
        ok, why = await SESSION.unlock(password)
        del password
        await self.finish()
        if not ok:
            await self.push_error(
                "Could not unlock",
                f"{why}.\n\nFIX PERMISSIONS sets capturing up permanently "
                "instead, and needs no password after your next login.",
            )
            return

        prefix, rows = await capture.permission_report(fresh=True)
        await self.push(
            verdict_line(
                self.palette, "Session",
                "unlocked — no more password prompts while netzilla runs", "ok",
            )
        )
        await self.push(kv_panel(self.palette, "Capture readiness now", rows))
        await self.push(
            text_panel(
                self.palette, "What netzilla just did",
                "Your password opened a sudo session and was then dropped — it "
                "is not held in memory. netzilla refreshes that session every "
                "minute so it cannot expire while it is running.\n\n"
                "Press AUTHENTICATE again to lock it immediately. Otherwise it "
                "ends when netzilla exits, and sudo forgets it on its own "
                "(15 minutes by default) — or run 'sudo -k' to clear it now.",
                style=self.palette.muted,
            )
        )

    # ------------------------------------------------------------- capture
    async def _capture(self) -> None:
        iface = self._iface()
        count = self._count()
        display_filter = self.field("filter")
        if problem := capture.check_filter(display_filter):
            raise ValidationError(problem)
        await self.begin("Checking capture permission…")
        prefix = await self._permission()
        if prefix is None:
            return
        self.progress(
            f"tshark on {iface} — up to {count} packets or {self.WINDOW}s"
            + (f", filtered by {display_filter!r}" if display_filter else "")
        )
        result = await capture.tshark_capture(
            iface=iface, count=count, display_filter=display_filter,
            seconds=self.WINDOW, prefix=prefix,
        )
        await self.finish()
        if result.missing_tool:
            await self._missing("tshark")
            return
        await self._render_capture(result, f"{iface} (live)", display_filter)

    async def _read(self) -> None:
        path = self._pcap()
        if not path:
            raise ValidationError(
                "Put the path of a .pcap/.pcapng file in the PCAP FILE box, "
                "e.g. ~/capture.pcapng. SAVE PCAP writes one for you."
            )
        if not capture.pcap_exists(path):
            raise ValidationError(f"No such file: {path}")
        display_filter = self.field("filter")
        if problem := capture.check_filter(display_filter):
            raise ValidationError(problem)
        await self.begin(f"Reading {path}…")
        result = await capture.tshark_capture(
            count=self._count(500), display_filter=display_filter, pcap=path,
        )
        await self.finish()
        if result.missing_tool:
            await self._missing("tshark")
            return
        await self._render_capture(result, path, display_filter)

    async def _render_capture(
        self, result, source: str, display_filter: str
    ) -> None:
        packets = capture.parse_packets(result.output)
        capture.stamp_arrival(packets)
        if packets:
            # Keep them so FILTER HELD can narrow them down afterwards without
            # capturing all over again.
            self._held = packets[-self.HOLD_LIMIT:]
            self._held_source = source
            self._held_filter = display_filter
        if not packets:
            if result.output:
                await self.push(
                    text_panel(
                        self.palette, f"tshark — {source}", result.output[:4000],
                        subtitle="output did not match the expected layout",
                    )
                )
            else:
                await self.push_warning(
                    "No packets captured",
                    (
                        f"Nothing matched {display_filter!r} in the window."
                        if display_filter
                        else "The interface saw no traffic in the window."
                    )
                    + "\n\nOn a quiet link, open a browser or run a ping and "
                    "capture again. If the filter is the problem, press FILTER "
                    "HELP for working examples."
                    + (f"\n\ntshark said: {result.error}" if result.error else ""),
                )
            return

        await self.push(
            verdict_line(
                self.palette, "Captured",
                f"{len(packets)} packets"
                + (f" matching {display_filter!r}" if display_filter else ""),
                "ok",
            )
        )
        await self.push(
            kv_panel(
                self.palette, "Capture summary",
                capture.capture_summary(packets, source),
                subtitle="local · tshark",
            )
        )
        await self.push(
            table_panel(
                self.palette, "Protocol mix",
                ["Protocol", "Packets", "Share", "Bytes"],
                capture.protocol_mix(packets),
            )
        )
        await self.push(
            table_panel(
                self.palette, "Packets",
                capture.PACKET_COLUMNS,
                capture.packet_rows(packets),
                subtitle=f"{min(len(packets), 200)} of {len(packets)} shown",
            )
        )
        if source.endswith("(live)"):
            await self._lan_devices(packets)
        await self.push(
            text_panel(
                self.palette, "These packets are held in memory",
                f"All {len(packets):,} of them. Put a different filter in the "
                "FILTER box and press FILTER HELD to narrow them down without "
                "capturing again. They stay until the next capture replaces "
                "them.",
                style=self.palette.muted,
            )
        )

    # ------------------------------------------------------ LAN devices seen
    LAN_DEVICE_LIMIT = 24

    async def _lan_devices(self, packets: list[dict]) -> None:
        """Name the devices on this machine's own subnets that appear in the
        capture — the same identification SWEEP does. Only for packets off
        the wire just now: a saved pcap may come from another site that
        happens to use the same subnet, and naming its addresses after
        whatever holds them here today would be wrong."""
        try:
            context = await devices.local_context()
        except Exception:
            return
        counts = capture_lan_counts(packets, context)
        if not counts:
            return
        top = sorted(counts, key=lambda ip: (-counts[ip], ip))[: self.LAN_DEVICE_LIMIT]
        holder = Static(classes="result-panel")
        await self.push_widget(holder)
        holder.update(
            text_panel(
                self.palette, "LAN devices in this capture",
                f"Identifying {len(top)} local address(es) — vendor, name, "
                "device type…", style=self.palette.muted,
            )
        )
        try:
            known = await devices.identify_ips(top, context=context)
        except Exception as exc:
            holder.update(
                text_panel(self.palette, "LAN devices in this capture",
                           f"Could not identify them: {exc}",
                           style=self.palette.muted)
            )
            return
        rows = []
        for ip in top:
            dev = known.get(ip, {})
            rows.append([
                ip, counts[ip], devices.mac_cell(dev), devices.vendor_cell(dev),
                devices.display_name(dev), dev.get("device", ""),
            ])
        holder.update(
            table_panel(
                self.palette, "LAN devices in this capture",
                ["IP", "Packets", "MAC", "Vendor", "Hostname", "Device"], rows,
                subtitle="addresses on this machine's own subnets · identified like LAN > SWEEP",
            )
        )

    # ------------------------------------------------------------- tcpdump
    async def _tcpdump(self) -> None:
        count = self._count()
        bpf = self.field("filter")
        path = self._pcap()
        reading = capture.pcap_exists(path)
        iface = "" if reading else self._iface()
        await self.begin("Checking capture permission…")
        prefix = [] if reading else await self._permission()
        if prefix is None:
            return
        self.progress(
            f"tcpdump {'reading ' + path if reading else 'on ' + iface} — "
            f"up to {count} packets"
        )
        result = await capture.tcpdump_capture(
            iface=iface, count=count, bpf=bpf, seconds=self.WINDOW,
            pcap=path if reading else "", prefix=prefix,
        )
        await self.finish()
        if result.missing_tool:
            await self._missing("tcpdump")
            return
        if not result.output:
            await self.push_warning(
                "tcpdump captured nothing",
                (result.error or "No packets arrived in the window.")
                + "\n\nA BPF filter here is not the same language as tshark's "
                "display filter — 'port 80' rather than 'tcp.port == 80'. "
                "Press FILTER HELP for both.",
            )
            return
        await self.push(
            verdict_line(
                self.palette, "tcpdump",
                f"{capture.tcpdump_line_count(result.output)} packet line(s)",
                "ok",
            )
        )
        await self.push(
            text_panel(
                self.palette,
                f"tcpdump — {path if reading else iface}",
                result.output[-6000:],
                subtitle=f"local · tcpdump -nn{f' {bpf}' if bpf else ''}",
            )
        )
        if result.error:
            await self.push_warning("tcpdump also said", result.error)

    # --------------------------------------------------------------- stats
    async def _stats(self, action: str) -> None:
        path = self._pcap()
        reading = capture.pcap_exists(path)
        iface = "" if reading else self._iface()
        count = self._count(200)
        what = "io,phs" if action == "protocols" else "conv,ip"
        title = "Protocol hierarchy" if action == "protocols" else "Top talkers"
        await self.begin("Checking capture permission…")
        prefix = [] if reading else await self._permission()
        if prefix is None:
            return
        self.progress(
            f"tshark -z {what} on {path if reading else iface}…"
        )
        result = await capture.tshark_stats(
            what, iface=iface, count=count, seconds=self.WINDOW,
            pcap=path if reading else "", display_filter=self.field("filter"),
            prefix=prefix,
        )
        await self.finish()
        if result.missing_tool:
            await self._missing("tshark")
            return
        if not result.output:
            await self.push_warning(
                f"No {title.lower()} to show",
                result.error or "Nothing was captured in the window.",
            )
            return
        await self.push(
            text_panel(
                self.palette, f"{title} — {path if reading else iface}",
                result.output[:6000],
                subtitle=f"local · tshark -z {what}",
            )
        )

    # ---------------------------------------------------------------- save
    async def _save(self) -> None:
        iface = self._iface()
        count = self._count()
        path = self._pcap() or capture.default_pcap_path(iface)
        await self.begin("Checking capture permission…")
        prefix = await self._permission()
        if prefix is None:
            return
        self.progress(f"Capturing {count} packets from {iface} into {path}…")
        result = await capture.tshark_write(
            iface=iface, count=count, path=path, seconds=self.WINDOW,
            prefix=prefix,
        )
        await self.finish()
        if result.missing_tool:
            await self._missing("tshark")
            return
        # A file written by an elevated tshark belongs to root; hand it back.
        await capture.take_ownership(path, prefix)
        if not capture.pcap_exists(path):
            await self.push_error(
                "Nothing was written",
                result.error or "tshark exited without creating the file.",
            )
            return
        self.set_field("pcap", path)
        await self.push(
            verdict_line(self.palette, "Saved", path, "ok")
        )
        await self.push(
            kv_panel(
                self.palette, "Capture file", capture.pcap_details(path),
                subtitle="the path is now in the PCAP FILE box",
            )
        )

    # --------------------------------------------------------- filter help
    async def _filters(self) -> None:
        await self.begin("Filter reference")
        await self.finish()
        await self.push(
            table_panel(
                self.palette, "Common ways to filter",
                ["What you want", "tshark  (-Y display filter)",
                 "tcpdump  (BPF)", "Notes"],
                capture.FILTER_ROWS,
                subtitle="type these into the FILTER box above",
            )
        )
        await self.push(
            table_panel(
                self.palette, "Ready-made filters worth trying",
                ["Goal", "Filter"],
                [[goal, expr] for goal, expr in capture.FILTER_EXAMPLES],
                subtitle="tshark display-filter syntax",
            )
        )
        await self.push(
            text_panel(
                self.palette, "Display filter vs capture filter",
                capture.FILTER_NOTES,
            )
        )

    # ---------------------------------------------------------- tool check
    async def _tools(self) -> None:
        await self.begin("Checking capture tools and permission…")
        found = await self._load_interfaces()
        prefix, rows = await capture.permission_report(fresh=True)
        await self.finish()
        rows = list(rows) + [("Interfaces found", len(found) or "none")]
        await self.push(
            verdict_line(
                self.palette, "Capture",
                "ready" if prefix is not None else "not permitted yet",
                "ok" if prefix is not None else "warn",
            )
        )
        await self.push(
            kv_panel(self.palette, "Capture readiness", rows,
                     subtitle="nothing here is sent anywhere")
        )
        if prefix is None or not capture.have_both():
            argv, shown, _why = capture.fix_command()
            if argv is not None and capture.have_both():
                await self.push(
                    text_panel(
                        self.palette, "Press FIX PERMISSIONS to run this for you",
                        shown, style=self.palette.accent,
                    )
                )
            else:
                await self.push(
                    text_panel(
                        self.palette, "Setting this up",
                        capture.SETUP_STEPS, style=self.palette.accent,
                    )
                )
        await self.push_warning(
            "Capture only what you are allowed to capture",
            "A packet capture records other people's traffic on the segment, "
            "including credentials sent in the clear. Capture on networks and "
            "hosts you own or are authorised to test, and treat .pcap files as "
            "sensitive — they are.",
        )

    # ------------------------------------------------------- fix permissions
    async def _fix(self) -> None:
        """Run the one-time capture setup, with the desktop asking for the
        password — a terminal prompt is impossible while netzilla owns it."""
        argv, shown, why = capture.fix_command()
        await self.begin("Preparing the capture-permission fix…")
        if argv is None:
            await self.finish()
            await self.push_error(
                "netzilla cannot run the fix from here",
                f"{why}.\n\nRun this once in a terminal instead, then log out "
                f"and back in:\n\n{capture.SETUP_STEPS}",
            )
            return
        await self.push(
            text_panel(
                self.palette, "Running this, as root", shown,
                subtitle="your desktop will ask for your password",
            )
        )
        self.progress("Waiting for the desktop password prompt…")
        result = await capture.apply_fix()
        await self.finish()
        if not result.ok:
            await self.push_error(
                "The fix did not complete",
                (result.error or "pkexec was cancelled or refused.")
                + "\n\nNothing changed if you dismissed the password dialog. "
                "The commands above can always be run by hand.",
            )
            return
        prefix, rows = await capture.permission_report(fresh=True)
        await self.push(
            verdict_line(
                self.palette, "Capture",
                "ready — try CAPTURE now" if prefix is not None
                else "still blocked — see below",
                "ok" if prefix is not None else "warn",
            )
        )
        await self.push(kv_panel(self.palette, "Capture readiness now", rows))
        await self.push_warning(
            "One part waits for a fresh login",
            "dumpcap now carries the capability, so capturing works straight "
            "away. Membership of the wireshark group only takes effect at your "
            "next login — after that netzilla captures with no password prompt "
            "at all. Check it with:  id -nG | grep wireshark",
        )

def capture_lan_counts(packets: list[dict], context: dict) -> dict[str, int]:
    """{ip: packets} for unicast addresses inside this machine's subnets."""
    import ipaddress

    networks = context.get("networks", ())
    counts: dict[str, int] = {}
    for packet in packets:
        for key in ("src", "dst"):
            ip = packet.get(key, "")
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if address.is_multicast or address.is_unspecified:
                continue
            for net in networks:
                if address in net:
                    if net.num_addresses > 2 and address in (
                        net.network_address, net.broadcast_address
                    ):
                        break
                    counts[ip] = counts.get(ip, 0) + 1
                    break
    return counts
