"""The netzilla application shell: tab bar, themes, key bindings, lifecycle."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, TabbedContent, TabPane

from . import __version__, termcaps
from .config import GRAPHICS_MODES, Config
from .services import Services
from .themes import DEFAULT_THEME, PALETTES, THEME_NAMES, build_textual_themes, get_palette

from .screens.bgp_asn import BGPPane
from .screens.capture import CapturePane
from .screens.config_review import ConfigPane
from .screens.creds import CredsPane
from .screens.dashboard import DashboardPane
from .screens.diagnostics import DiagnosticsPane
from .screens.discovery import DiscoveryPane
from .screens.dns_whois import DNSWhoisPane
from .screens.flows import FlowPane
from .screens.interfaces import InterfacesPane
from .screens.ip_lookup import IPLookupPane
from .screens.lan import LANPane
from .screens.lifecycle import LifecyclePane
from .screens.mac_lookup import MACPane
from .screens.service_status import ServiceStatusPane
from .screens.settings import SettingsPane
from .screens.speedtest_pane import SpeedTestPane
from .screens.ssl_tls import SSLTLSPane
from .screens.subnet_calc import SubnetPane
from .screens.threat_intel import ThreatIntelPane
from .screens.wifi import WifiPane


TABS = [
    ("dashboard", "DASH", DashboardPane),
    ("ip", "IP LOOKUP", IPLookupPane),
    ("subnet", "SUBNET", SubnetPane),
    ("dns", "DNS/WHOIS", DNSWhoisPane),
    ("tls", "SSL/TLS", SSLTLSPane),
    ("bgp", "BGP/ASN", BGPPane),
    ("threat", "THREAT", ThreatIntelPane),
    ("discovery", "DISCOVERY", DiscoveryPane),
    ("lan", "LAN", LANPane),
    ("int", "INT", InterfacesPane),
    ("wifi", "WIFI", WifiPane),
    ("capture", "CAPTURE", CapturePane),
    ("flow", "FLOW", FlowPane),
    ("mac", "MAC", MACPane),
    ("lifecycle", "LIFECYCLE", LifecyclePane),
    ("status", "STATUS", ServiceStatusPane),
    ("speed", "SPEED", SpeedTestPane),
    ("diag", "DIAG", DiagnosticsPane),
    ("config", "CONFIG", ConfigPane),
    ("creds", "CREDS", CredsPane),
    ("settings", "SETTINGS", SettingsPane),
]
TAB_CLASSES = {tab_id: pane_class for tab_id, _label, pane_class in TABS}


def resolve_tab(name: str | None) -> str | None:
    """A tab id from what someone typed: the id or the label, any case,
    with or without punctuation — 'wifi', 'WIFI', 'Wi-Fi', 'dns/whois',
    'DNS', 'ip lookup'. None when nothing matches."""
    if not name:
        return None

    def norm(text: str) -> str:
        return "".join(ch for ch in text.lower() if ch.isalnum())

    wanted = norm(name)
    if not wanted:
        return None
    for tab_id, label, _cls in TABS:
        if wanted in (norm(tab_id), norm(label)):
            return tab_id
    # A unique prefix of an id or a label: 'dash', 'life', 'thr'.
    hits = {tab_id for tab_id, label, _cls in TABS
            if norm(tab_id).startswith(wanted) or norm(label).startswith(wanted)}
    return hits.pop() if len(hits) == 1 else None


class NetzillaApp(App):
    """Tabbed TUI aggregating free network-administration data sources."""

    CSS_PATH = "netzilla.tcss"
    TITLE = "netzilla"
    SUB_TITLE = f"v{__version__}"

    # Letter keys are bound in both cases, so Q and T work as documented
    # whether or not Shift (or Caps Lock) is down. A letter typed into a text
    # box is just a letter, so each also has a Ctrl form that works anywhere:
    # Ctrl+Q (Textual's own, always on) and Ctrl+T.
    BINDINGS = [
        Binding("q,Q", "quit", "Quit", key_display="Q"),
        Binding("ctrl+c", "quit", "Quit", show=False),
        Binding("t,T", "cycle_theme", "Theme", key_display="T"),
        Binding("ctrl+t", "cycle_theme", "Theme", show=False),
        Binding("f1", "show_tab('dashboard')", "Dash", show=False),
        Binding("f2", "show_tab('settings')", "Settings", show=False),
        Binding("f3", "toggle_controls", "Hide/show controls", key_display="F3"),
        Binding("f4", "copy_output", "Copy output", key_display="F4"),
        Binding("ctrl+r", "clear_cache", "Clear cache"),
    ]

    def __init__(
        self,
        config_path: str | Path | None = None,
        theme_name: str | None = None,
        offline: bool = False,
        start_tab: str | None = None,
        graphics: str | None = None,
    ) -> None:
        super().__init__()
        self.config_obj = Config.load(config_path)
        if theme_name:
            self.config_obj.theme = theme_name.strip().lower()
        # Normalise before anything reads it (a hand-edited config may hold junk).
        if self.config_obj.theme not in PALETTES:
            self.config_obj.theme = DEFAULT_THEME
        # --graphics on the command line wins for this run without being saved.
        self._graphics_override = (graphics or "").strip().lower() or None
        if self._graphics_override not in (None, *GRAPHICS_MODES):
            self._graphics_override = None
        self.services = Services(self.config_obj, offline=offline)
        self._palette = get_palette(self.config_obj.theme)
        self._start_tab = resolve_tab(start_tab) or "dashboard"
        self.terminal = termcaps.current()
        self._pixels_ready = False
        self._cell_px: tuple[int, int] | None = None

    @property
    def palette(self):
        """Active colour palette, used when building Rich renderables."""
        return self._palette

    # ------------------------------------------------------------- layout
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        # Only the opening tab is built now; every other tab is built the
        # first time it is opened — a much faster start, and no tab's
        # interface probing runs until you look at that tab.
        with TabbedContent(initial=self._start_tab, id="tabs"):
            for tab_id, label, pane_class in TABS:
                with TabPane(label, id=tab_id):
                    if tab_id == self._start_tab:
                        yield pane_class()
        yield Footer()

    def on_mount(self) -> None:
        for theme in build_textual_themes():
            try:
                self.register_theme(theme)
            except Exception:
                pass
        self.apply_theme(self.config_obj.theme, persist=False)
        self._start_graphics()
        if self.services.offline:
            self.notify(
                "Offline mode: network tabs are disabled, local tools still work.",
                title="netzilla",
                severity="warning",
            )

    async def on_unmount(self) -> None:
        from .graphics import pixels

        pixels.delete_all()
        pixels.set_writer(None)
        await self.services.aclose()

    async def on_tabbed_content_tab_activated(
        self, event: TabbedContent.TabActivated
    ) -> None:
        await self.ensure_tab(event.pane.id or "")

    async def ensure_tab(self, tab_id: str):
        """Build a tab's pane the first time it is opened; returns the pane."""
        pane_class = TAB_CLASSES.get(tab_id)
        if pane_class is None:
            return None
        try:
            holder = self.query_one(f"#{tab_id}", TabPane)
        except Exception:
            return None
        existing = holder.query(pane_class)
        if existing:
            return existing.first()
        pane = pane_class()
        await holder.mount(pane)
        return pane

    # ------------------------------------------------------------- graphics
    @property
    def graphics_setting(self) -> str:
        return self._graphics_override or self.config_obj.graphics

    @property
    def graphics_mode(self) -> str:
        """'pixel' when graphs are drawn as images right now, else 'text'."""
        if not self._pixels_ready:
            return "text"
        return self.terminal.graphics_mode(self.graphics_setting)

    @property
    def cell_px(self) -> tuple[int, int]:
        return self._cell_px or self.terminal.cell_px or (10, 20)

    @property
    def image_protocol(self) -> str:
        """'kitty' or 'sixel' — how pixel graphs reach this terminal."""
        return self.terminal.image_protocol()

    def _measure_cells(self) -> tuple[int, int] | None:
        """The cell size images are drawn at: Windows Terminal's Sixel cell
        is always 10 x 20; elsewhere what the terminal reports."""
        if self.image_protocol == "sixel" and self.terminal.sixel_cell():
            return self.terminal.sixel_cell()
        return termcaps.cell_size_from_ioctl() or self.terminal.cell_px

    def _pixel_blocker(self) -> str:
        """Why pixel graphs can't be drawn in this run even if the terminal
        could show them — '' when nothing stands in the way."""
        from .graphics import plot

        driver = getattr(self, "_driver", None)
        if self.is_headless or driver is None or not hasattr(driver, "write"):
            return "Pixel graphs need a real terminal."
        if not plot.HAVE_PIL:
            return "Pillow is not installed (pipx runpip netzilla install pillow)."
        if getattr(self, "no_color", False):
            return "NO_COLOR is set, and pixel graphs need colour."
        # The image id travels in each placeholder's 24-bit colour, so
        # Textual must be writing truecolour or every id comes out wrong.
        # (Sixel images carry their own colours.)
        if (getattr(self, "image_protocol", "kitty") == "kitty"
                and getattr(self.console, "color_system", "truecolor") != "truecolor"):
            return ("Textual is drawing in 256 colours here — set COLORTERM=truecolor "
                    "if this terminal has 24-bit colour.")
        return ""

    def _start_graphics(self) -> None:
        """Point the image writer at the terminal when pixels are wanted."""
        from .graphics import pixels, sixel

        wanted = self.terminal.graphics_mode(self.graphics_setting) == "pixel"
        usable = wanted and not self._pixel_blocker()
        if usable:
            driver = self._driver
            pixels.use(self.image_protocol)
            pixels.set_writer(driver.write, tmux=self.terminal.passthrough)
            self._cell_px = self._measure_cells()
            sixel.OVERLAY.reset()
        elif not self._pixels_ready:
            pixels.set_writer(None)
        # Leaving pixel mode keeps the writer: images already on screen stay
        # until their panels are replaced, and are still deleted then — and
        # at exit — rather than left in the terminal's memory.
        self._pixels_ready = usable

    def _display(self, screen, renderable, *args, **kwargs):
        """Every frame Textual writes. With Sixel graphs, the images under
        any cells this frame overwrites are drawn again straight after it,
        in the same write (graphics/sixel.py)."""
        if self._pixels_ready and renderable is not None:
            from .graphics import pixels

            if pixels.protocol() == pixels.SIXEL:
                renderable = _with_sixels(screen, renderable)
        return super()._display(screen, renderable, *args, **kwargs)

    def graphics_why(self) -> str:
        """One sentence for DASH and SETTINGS: why graphs are drawn the way
        they are right now."""
        setting = self.graphics_setting
        if setting == "text":
            return "Set to Text on SETTINGS."
        if self._pixels_ready:
            if setting == "pixel" and not self.terminal.pixel_capable():
                if self.image_protocol == "sixel":
                    return (f"Pixel is chosen on SETTINGS: graphs are drawn as Sixel "
                            f"images, which {self.terminal.label} says it can show.")
                return ("Pixel is chosen on SETTINGS — if graphs show as blank boxes, "
                        "this terminal can't draw them: choose Auto.")
            return self.terminal.graphics_reason()
        if self.terminal.graphics_mode(setting) == "pixel":
            blocker = self._pixel_blocker()
            if blocker:
                return blocker + " Text graphs."
        return self.terminal.graphics_reason()

    def set_graphics(self, setting: str, persist: bool = True) -> str:
        """Switch auto / pixel / text now (SETTINGS, the command palette).
        Returns the mode now in effect."""
        setting = setting if setting in GRAPHICS_MODES else "auto"
        self._graphics_override = None
        self.config_obj.graphics = setting
        if persist:
            try:
                self.config_obj.save()
            except OSError:
                pass
        self._start_graphics()
        self._refresh_static_graphics()
        return self.graphics_mode

    def _refresh_static_graphics(self) -> None:
        for pane in self.query("LookupPane"):
            refresh = getattr(pane, "refresh_theme", None)
            if refresh is not None:
                try:
                    refresh()
                except Exception:
                    pass

    def on_resize(self, event) -> None:
        if self._pixels_ready:
            self._cell_px = self._measure_cells() or self._cell_px

    # ------------------------------------------------------------- themes
    def apply_theme(self, name: str, persist: bool = True) -> None:
        if name not in PALETTES:
            name = DEFAULT_THEME
        self._palette = get_palette(name)
        self.config_obj.theme = name
        try:
            self.theme = name
        except Exception:
            # Older Textual builds without the theme registry: the CSS still
            # renders, it just will not recolour. Never fatal.
            pass
        for pane in self.query(".results"):
            pane.refresh(layout=True)
        self._refresh_static_graphics()
        if persist:
            try:
                self.config_obj.save()
            except OSError:
                pass

    def action_cycle_theme(self) -> None:
        current = self.config_obj.theme
        index = THEME_NAMES.index(current) if current in THEME_NAMES else 0
        nxt = THEME_NAMES[(index + 1) % len(THEME_NAMES)]
        self.apply_theme(nxt)
        self.notify(
            get_palette(nxt).label, title="Theme", severity="information", timeout=2
        )

    # ------------------------------------------------------------ actions
    async def action_show_tab(self, tab_id: str) -> None:
        tab_id = resolve_tab(tab_id) or tab_id
        try:
            self.query_one("#tabs", TabbedContent).active = tab_id
        except Exception:
            return
        await self.ensure_tab(tab_id)

    def _active_pane(self):
        try:
            active = self.query_one("#tabs", TabbedContent).active_pane
        except Exception:
            return None
        if active is None:
            return None
        for child in active.children:
            return child
        return None

    def action_toggle_controls(self) -> None:
        """Roll the active tab's control box up (or back down)."""
        pane = self._active_pane()
        toggle = getattr(pane, "toggle_controls", None)
        if toggle is not None:
            toggle()

    def action_copy_output(self) -> None:
        """Copy the active tab's results as plain text (F4)."""
        from . import clipboard

        pane = self._active_pane()
        text = clipboard.pane_text(pane) if pane is not None else ""
        if not text.strip():
            self.notify("Nothing to copy on this tab yet — run something first.",
                        title="Copy output", severity="warning", timeout=3)
            return
        how = clipboard.copy(text, self)
        lines = text.count("\n") + 1
        self.notify(f"{lines} lines copied — {how}.", title="Copy output",
                    severity="information", timeout=4)

    def action_clear_cache(self) -> None:
        removed = self.services.store.clear_cache()
        self.notify(
            f"{removed} cached responses cleared.",
            title="Cache",
            severity="information",
            timeout=3,
        )

    # ------------------------------------------------------- command palette
    def get_system_commands(self, screen: Screen) -> Iterable[SystemCommand]:
        """Ctrl+P: every tab, every theme, the graphics mode and the actions
        bound to keys — netzilla's own theme list replaces Textual's, which
        would switch the chrome without the results following."""
        for tab_id, label, _cls in TABS:
            yield SystemCommand(
                f"Go to {label}", f"Open the {label} tab",
                lambda tab_id=tab_id: self.run_worker(self.action_show_tab(tab_id)),
            )
        for name, palette in PALETTES.items():
            yield SystemCommand(
                f"Theme: {palette.label.split(' — ')[0]}", palette.label,
                lambda name=name: self.apply_theme(name), discover=False,
            )
        for mode, help_text in (
            ("auto", "Pixel graphs when the terminal can show them, text otherwise"),
            ("pixel", "Always draw graphs as images (kitty graphics protocol or Sixel)"),
            ("text", "Always draw graphs with text characters"),
        ):
            yield SystemCommand(
                f"Graphics: {mode}", help_text,
                lambda mode=mode: self._palette_graphics(mode), discover=False,
            )
        yield SystemCommand("Copy output", "Copy the active tab's results (F4)",
                            self.action_copy_output)
        yield SystemCommand("Hide / show controls", "Roll the control box up or down (F3)",
                            self.action_toggle_controls)
        yield SystemCommand("Clear cache", "Forget every cached API response (Ctrl+R)",
                            self.action_clear_cache)
        yield SystemCommand("Quit", "Quit netzilla (Q)", self.action_quit)
        if screen.query("HelpPanel"):
            yield SystemCommand("Keys", "Hide the keys and widget help panel",
                                self.action_hide_help_panel)
        else:
            yield SystemCommand("Keys", "Show the keys available here",
                                self.action_show_help_panel)
        yield SystemCommand(
            "Screenshot", "Save an SVG screenshot of the current screen",
            lambda: self.set_timer(0.1, self.deliver_screenshot),
        )

    def _palette_graphics(self, mode: str) -> None:
        now = self.set_graphics(mode)
        self.notify(f"Graphics: {mode} — graphs are drawn as {now}.",
                    title="Graphics", timeout=3)


def _with_sixels(screen, update):
    """`update` (a Textual compositor update) with the Sixel overlay's
    redraws appended to what it writes; anything else passes unchanged."""
    try:
        from textual._compositor import CompositorUpdate
    except Exception:
        return update
    if not isinstance(update, CompositorUpdate):
        return update

    class WithSixels(CompositorUpdate):
        def render_segments(self, console) -> str:
            text = update.render_segments(console)
            try:
                from .graphics import sixel

                return text + sixel.overlay(screen, update)
            except Exception:
                return text

        def __rich_console__(self, console, options):
            yield from update.__rich_console__(console, options)

    return WithSixels()
