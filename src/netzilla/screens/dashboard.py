"""DASHBOARD — landing screen: this machine, its network, the terminal,
netzilla's own state and a live pulse of the network, on one screen.

Everything it shows at start-up is local, and the slow parts (reading the
56,000-URL offline URLhaus snapshot, the 54,000-prefix OUI table, looking for
a speed-test backend) run in a background thread after the first frame is on
screen — netzilla never makes you wait for its own bookkeeping. REFRESH adds
the one network fact DASH can't know locally: your public IP.

The panels sit side by side in as many columns as the window has room for
(three on a wide terminal, two on a medium one, one on a narrow one), so the
whole overview fits on one screen without scrolling.

In a terminal that can show images (kitty, Ghostty; Windows Terminal and
WezTerm through Sixel) the banner is redrawn in pixels — lit tubes in the
theme's colours, with a phosphor glow — and the NETWORK PULSE graphs are drawn
as images. When the window has room, the title has a picture either side
(graphics/banner.py): on the left a horned beast breathing a storm of energy
at it, on the right Tokyo at night — as part of the banner image, or as
sextant characters in any other terminal. The breath is alive: while the
banner is on screen, its cells step through a loop of frames (FIRE_EVERY
apart), the colours rolling out from the jaws. With Sixel each frame is laid
over the banner image as a picture of its own (every other frame, to keep
the stream to the terminal small), so the banner's text never changes.
"""

from __future__ import annotations

import asyncio
import time

from rich.text import Text
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Static

from ..clients import ip_api
from ..config import CREDENTIAL_FIELDS
from ..graphics import banner as banner_art
from ..graphics.charts import LineGraph
from ..local import netdiag, netif, oui, speed, sysinfo, urlhaus_offline
from ..render import PanelGrid, grid_layout, kv_panel, table_panel, text_panel
from .base import Action, LookupPane

_ART = r"""
 ███╗   ██╗███████╗████████╗███████╗██╗██╗     ██╗      █████╗
 ████╗  ██║██╔════╝╚══██╔══╝╚══███╔╝██║██║     ██║     ██╔══██╗
 ██╔██╗ ██║█████╗     ██║     ███╔╝ ██║██║     ██║     ███████║
 ██║╚██╗██║██╔══╝     ██║    ███╔╝  ██║██║     ██║     ██╔══██║
 ██║ ╚████║███████╗   ██║   ███████╗██║███████╗███████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
""".strip("\n").splitlines()
# Every line the same width, so centring the banner keeps the letters lined up.
_WIDTH = max(len(line) for line in _ART)
BANNER = "\n".join(line.ljust(_WIDTH) for line in _ART)

# A column is never narrower than this; a wide terminal gets three of them.
MIN_COLUMN = 46
PULSE_EVERY = 1.0          # seconds between NETWORK PULSE samples
PULSE_KEEP = 400           # samples kept (more than the widest graph shows)

# What each credential unlocks, for the API KEYS panel.
UNLOCKS = {
    "abuseipdb_api_key": "abuse reports, /24",
    "virustotal_api_key": "IP/URL/file verdicts",
    "greynoise_api_key": "scanner noise",
    "abusech_auth_key": "URLhaus, ThreatFox",
    "nvd_api_key": "10× CVE rate",
}
SOURCE_WORDS = {
    "custom": ("your own ✔", "success"),
    "env": ("environment ✔", "accent"),
    "none": ("not set", "warning"),
}


def text_banner(lines, side: int, palette, cell_w: int = 10, cell_h: int = 20,
                frame: int = 0) -> Text:
    """The banner in characters: the title as it always was (coloured by the
    stylesheet), with the two pictures beside it as sextants when `side`
    allows, the beast's breath as in `frame`. Every line is the same width,
    so centring keeps them lined up."""
    if not side:
        return Text("\n".join(lines), justify="center")
    scheme = banner_art.colours(palette)
    try:
        left = banner_art.cells("beast", side, len(lines), scheme, cell_w, cell_h, frame)
        right = banner_art.cells("city", side, len(lines), scheme, cell_w, cell_h)
    except Exception:
        return Text("\n".join(lines), justify="center")
    gap = " " * banner_art.GAP
    out = Text(justify="center", no_wrap=True, overflow="crop")
    for row, line in enumerate(lines):
        if row:
            out.append("\n")
        _append_cells(out, left[row])
        out.append(gap + line + gap)
        _append_cells(out, right[row])
    return out


def _append_cells(text: Text, cells) -> None:
    """Sextant cells onto a line, a run of one colour (and background) at a
    time."""
    def style(colour: str, background: str) -> str:
        if not colour:
            return ""
        return f"not bold {colour} on {background}" if background else f"not bold {colour}"

    run, key = [], None
    for char, colour, background in cells:
        if (colour, background) != key and run:
            text.append("".join(run), style=style(*key))
            run = []
        key = (colour, background)
        run.append(char)
    if run:
        text.append("".join(run), style=style(*key))


def pixel_banner(banner_id: int, cols: int, rows: int, window=None, fire_id: int = 0) -> Text:
    """The banner's placeholder cells: the whole banner image, except the
    fire window's cells (col, row, width, height — on the beast, at the
    banner's left), which show the breath's current frame."""
    from ..graphics import pixels

    if window is None or not fire_id:
        art = pixels.placeholder_text(banner_id, cols, rows)
        art.justify = "center"
        return art
    col, top, width, height = window
    out = Text(no_wrap=True, overflow="crop", end="", justify="center")
    for row in range(rows):
        if row:
            out.append("\n")
        if top <= row < top + height:
            out.append(pixels.placeholder_span(banner_id, row, 0, col))
            out.append(pixels.placeholder_span(fire_id, row - top, 0, width))
            out.append(pixels.placeholder_span(banner_id, row, col + width, cols))
        else:
            out.append(pixels.placeholder_span(banner_id, row, 0, cols))
    return out


def local_facts() -> dict:
    """The slow, local half of the dashboard (run in a thread)."""
    snap = urlhaus_offline.snapshot()
    return {
        "tools": netdiag.tools_status(),
        "speed_ok": speed.available(),
        "speed_label": speed.backend_label(),
        "snapshot": (snap.count, snap.newest),
        "oui": oui.entry_count(),
        "system": sysinfo.facts(),
        "dns": sysinfo.dns_servers(),
    }


async def network_facts() -> dict:
    """This machine's side of the network: the default interface, its
    addresses, the gateway and — on Wi-Fi — the network it's joined to."""
    found, _source = await netif.interfaces()
    name = netif.pick_default(found) if found else ""
    iface = next((i for i in found if i.get("name") == name), {}) if name else {}
    gateways = await netif.default_gateways()
    addresses = iface.get("addresses") or []
    facts = {
        "iface": name,
        "kind": iface.get("kind", ""),
        "state": iface.get("state", ""),
        "mac": iface.get("mac", ""),
        "ipv4": [a for a in addresses if ":" not in a],
        "ipv6": [a for a in addresses if ":" in a and not a.lower().startswith("fe80")],
        "gateways": gateways,
        "wifi": {},
        "count": sum(1 for i in found if i.get("kind") != "loopback"),
    }
    if iface.get("kind") == "wireless":
        from ..local import wifitools

        try:
            facts["wifi"] = await wifitools.link_now(name)
        except Exception:
            facts["wifi"] = {}
    return facts


def tagline_text(palette, parts: list[str], width: int) -> Text:
    """The line under the logo: as many of `parts` as fit in `width`, dropped
    from the end so the version always shows."""
    separator = "  ·  "
    parts = list(parts)
    if width > 0:
        while len(parts) > 1 and len(separator.join(parts)) > width:
            parts.pop()
    text = Text(justify="center", no_wrap=True, overflow="ellipsis")
    for index, part in enumerate(parts):
        if index:
            text.append(separator, style=palette.muted)
        text.append(part, style=palette.accent if index == 0 else palette.secondary)
    return text


def _used_fraction(usage: str) -> float:
    """0.25 from '250/1000 in 24h'; 0 when there's no limit to measure by."""
    head = usage.split(" ", 1)[0]
    used, _, limit = head.partition("/")
    try:
        return int(used) / int(limit) if limit else 0.0
    except (ValueError, ZeroDivisionError):
        return 0.0


class DashboardPane(LookupPane):
    PANE_TITLE = "NETZILLA // SYSTEM OVERVIEW"
    DESCRIPTION = (
        "REFRESH re-reads everything and adds your public IP (one call to "
        "ip-api.com) · QUOTA ONLY re-reads the API counters."
    )
    FIELDS = ()
    ACTIONS = (
        Action("refresh", "REFRESH"),
        Action("quota", "QUOTA ONLY", primary=False),
    )

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._facts: dict = {}
        self._network: dict = {}
        self._public = None                 # ip-api result after REFRESH
        self._refreshed_at = ""
        self._pulse_down: list[float] = []
        self._pulse_up: list[float] = []
        self._pulse_prev: tuple[float, dict] | None = None
        self._pulse_iface = ""
        # The banner as last drawn (_draw_logo), for the breath's frames.
        self._logo: dict = {}
        self._fire_frame = 0
        self._fire_stale: list[tuple[float, list[int]]] = []    # (when, image ids)

    # ------------------------------------------------------------ layout
    def compose(self):
        with Vertical(classes="banner", id="banner-box"):
            yield Static(Text(BANNER, justify="center"), classes="banner-art", id="banner")
            yield Static("", classes="banner-tagline", id="tagline")
        yield from super().compose()

    def compose_output(self):
        yield Static(classes="action-help")
        with VerticalScroll(classes="results"):
            yield Static("", classes="dash-status", id="dash-status")
            yield Static("", classes="result-panel", id="dash-row-1")
            yield Static("", classes="result-panel", id="dash-row-2")
            yield Static("", classes="result-panel", id="dash-row-3")

    async def on_mount(self) -> None:
        self.call_after_refresh(self._draw_logo)
        self._tagline()
        self._say("Reading this machine…", busy=True)
        self.set_interval(PULSE_EVERY, self._pulse_tick)
        self.set_interval(banner_art.FIRE_EVERY, self._fire_tick)
        # Same exclusive group as the buttons: pressing REFRESH before this
        # has finished replaces it rather than racing it.
        self.run_worker(self._first_render(), group=f"pane-{id(self)}", exclusive=True)

    async def _first_render(self) -> None:
        await self._gather()
        self._render_rows()
        self._say(self._idle_hint())
        # Open on the first panel, not scrolled to the last one.
        self.results.scroll_home(animate=False)

    def refresh_theme(self) -> None:
        self._draw_logo()
        self._tagline()
        if self._facts:
            self._render_rows()

    def on_resize(self, event) -> None:
        # Columns follow the window; the banner image follows the cell size.
        timer = getattr(self, "_resize_timer", None)
        if timer is not None:
            timer.stop()
        self._resize_timer = self.set_timer(0.25, self._after_resize)

    def _after_resize(self) -> None:
        self._draw_logo()          # the pictures beside the title follow the width
        self._tagline()
        if self._facts:
            self._render_rows()

    # ------------------------------------------------------------ banner
    def _banner_side(self, widget) -> int:
        """How wide each picture beside the title is (0: no room)."""
        width = int(getattr(widget.size, "width", 0) or self.size.width or 0)
        return banner_art.side_cols(width, _WIDTH) if banner_art.HAVE_PIL else 0

    def _draw_logo(self) -> None:
        """The banner, centred: the beast, the title and the city — in
        pixels when the terminal can show them, else in characters."""
        try:
            banner = self.query_one("#banner", Static)
        except Exception:
            return
        lines = BANNER.splitlines()
        rows = len(lines)
        side = self._banner_side(banner)
        cell_w, cell_h = self._app_setting("cell_px", (10, 20))
        palette = self.palette
        scheme = banner_art.colours(palette)
        self._retire_fire()
        self._logo = {"mode": "text", "lines": lines, "rows": rows, "side": side,
                      "cell": (cell_w, cell_h), "palette": palette, "scheme": scheme}
        if not self.pixel_graphics:
            banner.update(text_banner(lines, side, palette, cell_w, cell_h, self._fire_frame))
            return
        from ..graphics import pixels

        try:
            png = banner_art.banner_png(lines, _WIDTH, rows, side, cell_w, cell_h, scheme,
                                        [palette.primary, palette.accent, palette.success])
        except Exception:
            banner.update(text_banner(lines, side, palette, cell_w, cell_h, self._fire_frame))
            return
        cols = _WIDTH + (2 * (side + banner_art.GAP) if side else 0)
        canvas = self._canvases.get("logo")
        if canvas is None:
            canvas = self._canvases["logo"] = pixels.Canvas()
        self._logo.update(mode="pixels", cols=cols, banner_id=canvas.upload(png, cols, rows),
                          window=banner_art.fire_window(side, rows, cell_w, cell_h) if side else None,
                          fire_ids={})
        banner.update(self._logo_frame(self._fire_frame))

    # --------------------------------------------------------- the breath
    def _logo_frame(self, frame: int) -> Text:
        """The banner as drawn last, its breath as in `frame`."""
        logo = self._logo
        lines, side, palette = logo["lines"], logo["side"], logo["palette"]
        cell_w, cell_h = logo["cell"]
        if logo["mode"] == "text":
            return text_banner(lines, side, palette, cell_w, cell_h, frame)
        # With Sixel the breath is laid over the banner image (_fire_tick),
        # so the banner's cells are the whole image.
        fire_id = self._fire_image(frame) if side and not self._sixel_logo() else 0
        return pixel_banner(logo["banner_id"], logo["cols"], logo["rows"], logo["window"], fire_id)

    def _sixel_logo(self) -> bool:
        """True when the banner on screen is a Sixel image."""
        if self._logo.get("mode") != "pixels":
            return False
        from ..graphics import pixels

        return pixels.protocol() == pixels.SIXEL

    def _fire_image(self, frame: int) -> int:
        """The image of the breath in `frame`, uploaded the first time it is
        wanted (so a loop's work is spread over its first pass)."""
        from ..graphics import pixels

        logo = self._logo
        ids = logo["fire_ids"]
        if frame not in ids:
            cell_w, cell_h = logo["cell"]
            try:
                png = banner_art.fire_png(logo["side"], logo["rows"], cell_w, cell_h,
                                          logo["scheme"], frame)
            except Exception:
                return 0
            _, _, width, height = logo["window"]
            ids[frame] = pixels.show(png, width, height)
        return ids[frame]

    def _retire_fire(self) -> None:
        """The breath's images from the last drawing: deleted a moment from
        now, once the screen no longer shows them."""
        old = list((self._logo.get("fire_ids") or {}).values())
        if old:
            self._fire_stale.append((time.monotonic(), old))

    def _fire_tick(self) -> None:
        """The next frame of the breath, while the banner is on screen."""
        if self._fire_stale:
            from ..graphics import pixels

            now = time.monotonic()
            for when, ids in [item for item in self._fire_stale if now - item[0] > 0.3]:
                for image_id in ids:
                    pixels.delete(image_id)
                self._fire_stale.remove((when, ids))
        if not self._logo or not self._logo.get("side"):
            return
        try:
            banner = self.query_one("#banner", Static)
        except Exception:
            return
        if not banner.is_on_screen:
            return
        self._fire_frame = (self._fire_frame + 1) % banner_art.FIRE_FRAMES
        if self._sixel_logo():
            if self._fire_frame % 2 == 0:
                self._sixel_fire(self._fire_frame)
            return
        banner.update(self._logo_frame(self._fire_frame), layout=False)

    def _sixel_fire(self, frame: int) -> None:
        """Lay the breath's `frame` over the Sixel banner where it was last
        drawn; the overlay keeps it there when the banner is redrawn."""
        from ..graphics import sixel

        logo = self._logo
        fire_id = self._fire_image(frame)
        if not fire_id or not logo.get("window"):
            return
        col, top, _width, _height = logo["window"]
        try:
            sixel.draw_over(self.screen, logo["banner_id"], fire_id, col, top)
        except Exception:
            pass

    def _tagline(self) -> None:
        try:
            line = self.query_one("#tagline", Static)
        except Exception:
            return
        from ..app import TABS

        palette = self.palette
        info = self._terminal_info()
        mode = self._app_setting("graphics_mode", "text")
        theme = getattr(getattr(self.app, "config_obj", None), "theme", "")
        parts = [p for p in (f"v{self._version()}", f"{len(TABS)} tabs",
                             "free & open data only", info.label, f"{mode} graphs",
                             theme) if p]
        line.update(tagline_text(palette, parts, int(self.size.width or 0)))

    @staticmethod
    def _version() -> str:
        from .. import __version__

        return __version__

    def _terminal_info(self):
        info = self._app_setting("terminal", None)
        if info is None:
            from .. import termcaps

            info = termcaps.current()
        return info

    def release_graphics(self) -> None:
        # The banner and the pulse outlive any one REFRESH: keep their canvases.
        kept = {key: self._canvases.pop(key) for key in ("logo", "pulse-down", "pulse-up")
                if key in self._canvases}
        super().release_graphics()
        self._canvases.update(kept)

    def on_unmount(self) -> None:
        for canvas in self._canvases.values():
            canvas.clear()
        self._canvases.clear()

    # ------------------------------------------------------------ actions
    async def execute(self, action: str) -> None:
        if action == "quota":
            self._output_arrived()
            self._render_rows()
            full = self._quota_panel(limit=None)
            try:
                holder = self.query_one("#dash-quota-full", Static)
                holder.update(full)
            except Exception:
                holder = Static(full, classes="result-panel", id="dash-quota-full")
                await self.results.mount(holder)
            holder.scroll_visible(animate=False)
            self._say("API quota re-read from this machine's own counters — every "
                      "service is listed at the bottom.")
            return

        self._output_arrived()
        self._say("Checking this machine, its tools and network…", busy=True)
        await self._gather()
        self._render_rows()
        self._say("Resolving your public IP via IP-API…", busy=True)
        self._public = await ip_api.lookup(self.services, "")
        self._refreshed_at = time.strftime("%H:%M:%S")
        self._render_rows()
        self._say(f"Refreshed at {self._refreshed_at}. " + self._idle_hint())

    async def _gather(self) -> None:
        self._facts = await asyncio.to_thread(local_facts)
        try:
            self._network = await network_facts()
        except Exception:
            self._network = {}
        if self._network.get("iface") and self._network["iface"] != self._pulse_iface:
            self._pulse_iface = self._network["iface"]
            self._pulse_down, self._pulse_up = [], []

    def _say(self, message: str, busy: bool = False) -> None:
        try:
            status = self.query_one("#dash-status", Static)
        except Exception:
            return
        palette = self.palette
        status.update(Text(("▸ " if busy else "▪ ") + message,
                           style=palette.accent if busy else palette.muted))

    @staticmethod
    def _idle_hint() -> str:
        return ("F2 settings · Ctrl+P jumps anywhere · F3 hides the controls · "
                "F4 copies this page")

    # ------------------------------------------------------------ the rows
    def _render_rows(self) -> None:
        try:
            first = self.query_one("#dash-row-1", Static)
            second = self.query_one("#dash-row-2", Static)
        except Exception:
            return
        first.update(PanelGrid([self._machine_panel(), self._network_panel(),
                                self._terminal_panel()], min_width=MIN_COLUMN, max_cols=3))
        second.update(PanelGrid([self._tooling_panel(), self._keys_panel(),
                                 self._data_panel()], min_width=MIN_COLUMN, max_cols=3))
        self._render_pulse_row()

    def _row_width(self) -> int:
        try:
            width = self.query_one("#dash-row-3", Static).size.width
        except Exception:
            width = 0
        return width or max(40, int(self.size.width) - 4)

    def _render_pulse_row(self) -> None:
        try:
            third = self.query_one("#dash-row-3", Static)
        except Exception:
            return
        width = self._row_width()
        layout = grid_layout(width, [2, 1], min_width=MIN_COLUMN, max_cols=3)
        pulse_width = layout[0][0][1]
        third.update(PanelGrid([(self._pulse_panel(pulse_width), 2), self._quota_panel()],
                               min_width=MIN_COLUMN, max_cols=3))

    # ------------------------------------------------------------ panels
    def _machine_panel(self):
        system = self._facts.get("system") or {}
        return kv_panel(self.palette, "This machine", [
            ("Host", system.get("host")),
            ("OS", system.get("os")),
            ("Kernel", system.get("kernel")),
            ("Uptime", system.get("uptime")),
            ("Load", system.get("load")),
            ("Memory", system.get("memory")),
            ("Python", f"{system.get('python', '—')} · Textual {system.get('textual', '—')}"),
            ("netzilla", system.get("netzilla")),
        ], subtitle="local")

    def _network_panel(self):
        palette = self.palette
        net = self._network
        name = net.get("iface") or ""
        iface = (f"{name} ({net.get('kind')}) · {net.get('state') or '?'}"
                 if name else "none found")
        servers, note = self._facts.get("dns", ([], ""))
        rows: list[tuple[str, object]] = [
            ("Interface", iface),
            ("IPv4", ", ".join(net.get("ipv4") or []) or None),
        ]
        if net.get("ipv6"):
            rows.append(("IPv6", ", ".join(net["ipv6"][:2])))
        rows += [
            ("Gateway", ", ".join(net.get("gateways") or []) or None),
            ("DNS", (", ".join(servers[:3]) + (f"  ({note})" if note else ""))
             if servers else None),
        ]
        wifi = net.get("wifi") or {}
        if wifi.get("connected"):
            parts = [wifi.get("ssid") or "<hidden>"]
            if wifi.get("signal_dbm") is not None:
                parts.append(f"{wifi['signal_dbm']} dBm")
            if wifi.get("rx_bitrate"):
                parts.append(f"{wifi['rx_bitrate']:g} Mb/s")
            rows.append(("Wi-Fi", " · ".join(str(p) for p in parts)))
        public = self._public
        if public is None:
            rows.append(("Public IP", Text("press REFRESH", style=palette.muted)))
        elif public.ok:
            data = public.data or {}
            rows.append(("Public IP", data.get("query")))
            rows.append(("ISP / AS", " · ".join(str(x) for x in (data.get("isp"), data.get("as"))
                                                 if x) or None))
            place = ", ".join(str(x) for x in (data.get("city"), data.get("regionName"),
                                               data.get("country")) if x)
            rows.append(("Location", place or None))
        else:
            rows.append(("Public IP", Text(f"unavailable — {public.error or 'no answer'}",
                                           style=palette.warning)))
        subtitle = (f"public IP {'cached' if public is not None and public.ok and public.cached else 'live'}"
                    f" · {self._refreshed_at}" if self._refreshed_at else "local")
        return kv_panel(palette, "Network", rows, subtitle=subtitle)

    def _terminal_panel(self):
        """What netzilla knows about the terminal it is drawing on."""
        info = self._terminal_info()
        mode = self._app_setting("graphics_mode", "text")
        setting = self._app_setting("graphics_setting", "auto")
        cell = (f"{info.cell_px[0]} × {info.cell_px[1]} px" if info.cell_px
                else "not reported")
        graphics = Text(mode.upper(), style=self.palette.accent)
        graphics.append(f"  ({setting})", style=self.palette.muted)
        good, muted = self.palette.success, self.palette.muted
        explain = self._app_setting("graphics_why", None)
        why = explain() if callable(explain) else info.graphics_reason()
        window = info.name == "netzilla-window"
        found_by = ("built in" if window else
                    "asked it" if info.identified_by != "environment" else "environment")
        rows = [
            ("Terminal", f"{info.where}  ({found_by})"),
            ("Graphs", graphics),
            ("Why", why),
            ("Colour", ("24-bit" if info.truecolor else "256 colours") + f" · cell {cell}"),
            ("Links · copy", Text.assemble(
                ("clickable" if info.hyperlinks else "plain",
                 good if info.hyperlinks else muted),
                (" · F4 to ", muted),
                ("clipboard" if window else
                 "terminal" if info.clipboard else "clipboard tool / file",
                 good if info.clipboard else muted))),
            ("Notifications", Text(f"yes ({info.notify.upper()})", style=good)
             if info.notify else Text("not supported", style=muted)),
        ]
        return kv_panel(self.palette, "Terminal", rows,
                        subtitle="netzilla --terminal for details")

    def _tooling_panel(self):
        palette = self.palette
        tools = self._facts.get("tools") or []

        def status(present: bool) -> Text:
            return (Text("✔ available", style=palette.success) if present
                    else Text("✘ missing", style=palette.warning))

        rows = []
        half = -(-len(tools) // 2)
        for left, right in zip(tools[:half], tools[half:] + [None] * (2 * half - len(tools))):
            row = [left[0], status(left[1])]
            row += [right[0], status(right[1])] if right else ["", ""]
            rows.append(row)
        ookla = (Text("✔ available", style=palette.success) if self._facts.get("speed_ok")
                 else Text("optional", style=palette.muted))
        rows.append(["speed test", Text("✔ built in", style=palette.success),
                     "Ookla CLI", ookla])
        missing = [name for name, present in tools if not present]
        return table_panel(palette, "Local tooling", ["Tool", "Status", "Tool", "Status"],
                           rows, subtitle=(f"{len(missing)} missing · see DIAG → TOOL CHECK"
                                           if missing
                                           else "no API, no rate limit"))

    def _keys_panel(self):
        palette = self.palette
        config = self.services.config
        rows = []
        for spec in CREDENTIAL_FIELDS:
            word, colour = SOURCE_WORDS[config.credential_source(spec.key)]
            if not spec.required and colour == "warning":
                colour = "muted"
            rows.append([spec.service, Text(word, style=getattr(palette, colour)),
                         UNLOCKS.get(spec.key, "")])
        missing = [f.service for f in CREDENTIAL_FIELDS if f.required and not config.has(f.key)]
        subtitle = (f"{len(missing)} not set · every tab still works · F2 to add"
                    if missing else "all free accounts · F2 to change")
        return table_panel(palette, "API keys", ["Service", "Key", "Unlocks"], rows,
                           subtitle=subtitle)

    def _data_panel(self):
        config = self.services.config
        count, newest = self._facts.get("snapshot", (0, ""))
        snap_text = f"{count:,} URLs, newest {newest[:10]}" if count else "not installed"
        oui_count = self._facts.get("oui")
        from ..render import short_path

        return kv_panel(self.palette, "Data & cache", [
            ("Config", short_path(config.path, 30)),
            ("Theme", config.theme),
            ("URLhaus snapshot", snap_text),
            ("Vendor table", f"{oui_count:,} prefixes" if oui_count else None),
            ("Cached answers", self.services.store.cache_size()),
            ("Cache", "on" if self.services.store.enabled else "off"),
            ("Offline mode", self.services.offline),
        ], subtitle="SETTINGS to edit")

    def _quota_panel(self, limit: int | None = 5):
        """The API quota: on the overview, the five that matter most right now
        (closest to their limit first); QUOTA ONLY lists every service."""
        palette = self.palette
        colours = {"ok": palette.success, "warn": palette.warning, "error": palette.error}
        quota = self.services.quota_rows(active_only=limit is not None)
        if limit is not None:
            order = {"error": 0, "warn": 1, "ok": 2}
            quota = sorted(quota, key=lambda row: (order.get(row[2], 3),
                                                   -_used_fraction(row[1])))
        shown = quota[:limit] if limit is not None else quota
        rows = [[label, Text(usage, style=colours.get(state, palette.foreground))]
                for label, usage, state in shown]
        hidden = len(quota) - len(shown)
        subtitle = (f"+{hidden} more · QUOTA ONLY lists all" if hidden
                    else "counted on this machine")
        return table_panel(palette, "API quota" if limit is not None else "API quota — every service",
                           ["Service", "Used"], rows, subtitle=subtitle)

    # ------------------------------------------------------------ the pulse
    def _pulse_tick(self) -> None:
        """Sample the default interface's counters; redraw when visible."""
        counters = netif.read_counters()
        now = time.monotonic()
        name = self._pulse_iface or (self._network.get("iface") if self._network else "")
        if self._pulse_prev is not None and name and name in counters:
            then, previous = self._pulse_prev
            rates = netif.rates_between(previous, counters, max(0.001, now - then))
            mine = next((r for r in rates if r["name"] == name), None)
            if mine:
                self._pulse_down.append(mine["rx_mbps"])
                self._pulse_up.append(mine["tx_mbps"])
                del self._pulse_down[:-PULSE_KEEP], self._pulse_up[:-PULSE_KEEP]
        self._pulse_prev = (now, counters)
        try:
            row = self.query_one("#dash-row-3", Static)
        except Exception:
            return
        if self._facts and row.is_on_screen:
            self._render_pulse_row()

    def _pulse_panel(self, cell_width: int):
        from ..local.wifitools import nice_ceiling

        palette = self.palette
        name = self._pulse_iface or self._network.get("iface") or ""
        if not name or not netif.read_counters():
            return text_panel(palette, "Network pulse",
                              f"Live rates read {netif.counter_source()}, which "
                              "could not be read here.", style=palette.muted)
        inner = max(20, cell_width - 4)              # panel border and padding
        side_by_side = inner >= 2 * 34 + 3
        each = (inner - 3) // 2 if side_by_side else inner
        graphs = []
        for key, label, arrow, values, colour in (
            ("pulse-down", "Download", "▼", self._pulse_down, palette.accent),
            ("pulse-up", "Upload", "▲", self._pulse_up, palette.primary),
        ):
            peak = nice_ceiling(max(values or [0.0]))

            def unit(v: float) -> str:
                return f"{round(v, 2):g} Mb/s"

            gutter = max(len(unit(v)) for v in (peak, peak / 2, 0.0))
            graph = LineGraph(list(values), floor=0.0, ceil=peak,
                              width=max(8, each - gutter - 2), height=5,
                              label=unit, colour=colour)
            now = values[-1] if values else 0.0
            caption = Text(f"{arrow} {label} ", style=f"bold {palette.secondary}")
            caption.append(f"{now:.2f} Mb/s", style=palette.foreground)
            caption.append(f"  · peak {max(values or [0.0]):.2f}", style=palette.muted)
            graphs.append([caption] + list(self.graph(key, graph, colour=colour).split("\n")))
        body = Text(no_wrap=True, overflow="crop")
        if side_by_side:
            left, right = graphs
            for index in range(max(len(left), len(right))):
                if index:
                    body.append("\n")
                a = left[index] if index < len(left) else Text("")
                b = right[index] if index < len(right) else Text("")
                body.append_text(a)
                body.append(" " * max(0, each - a.cell_len + 3))
                body.append_text(b)
        else:
            for number, lines in enumerate(graphs):
                for index, line in enumerate(lines):
                    if number or index:
                        body.append("\n")
                    body.append_text(line)
        from rich.panel import Panel

        from ..render import PANEL_BOX

        samples = len(self._pulse_down)
        return Panel(
            body,
            title=Text(f" NETWORK PULSE — {name.upper()} ", style=f"bold {palette.primary}"),
            title_align="left",
            subtitle=Text(f" live · one sample a second · {samples} so far ",
                          style=palette.muted),
            subtitle_align="right",
            border_style=palette.secondary,
            box=PANEL_BOX,
            padding=(0, 1),
        )
