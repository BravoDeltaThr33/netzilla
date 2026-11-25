"""Tests for netzilla 2.1: per-tool help cards, the syslog port fallback, and
the more forgiving HIBP breach matching.

The help-card behaviour is driven through Textual's Pilot in offline mode, so
nothing touches the network and nothing needs root.
"""

from __future__ import annotations

import asyncio

from netzilla import __version__
from netzilla.app import TABS, NetzillaApp
from netzilla.clients import hibp
from netzilla.help import HELP, get_help, help_panel
from netzilla.local import syslog
from netzilla.screens.config_review import ConfigPane
from netzilla.screens.lan import LANPane
from netzilla.themes import get_palette
from netzilla.validators import ValidationError


def test_version_is_2_1():
    """The features below arrived in 2.1; later releases keep them."""
    assert tuple(int(part) for part in __version__.split(".")[:2]) >= (2, 1), (
        __version__
    )


# ---------------------------------------------------------------- help text
def test_every_button_on_every_tab_has_help():
    missing = []
    for _tab_id, _label, pane_class in TABS:
        keys = [a.key for a in getattr(pane_class, "ACTIONS", ())]
        if pane_class is ConfigPane:
            keys = ["analyse", "clear"]
        for key in keys:
            if get_help(pane_class.__name__, key) is None:
                missing.append(f"{pane_class.__name__}.{key}")
    assert missing == []


def test_help_has_no_orphans():
    known = {cls.__name__: cls for _t, _l, cls in TABS}
    for pane_name, entries in HELP.items():
        assert pane_name in known, pane_name
        cls = known[pane_name]
        valid = {a.key for a in getattr(cls, "ACTIONS", ())}
        if cls is ConfigPane:
            valid = {"analyse", "clear"}
        assert set(entries) <= valid, (pane_name, set(entries) - valid)


def test_help_panel_renders():
    from rich.console import Console

    tool = get_help("SSLTLSPane", "quick")
    console = Console(width=120, record=True)
    console.print(help_panel(get_palette("amber-phosphor"), "QUICK CHECK", tool))
    text = console.export_text()
    assert "HOW TO USE — QUICK CHECK" in text
    assert "expired.badssl.com" in text
    assert "USE IT WHEN" in text


# ------------------------------------------------------------------ syslog
class _FakeLAN:
    def __init__(self, target: str) -> None:
        self._target = target

    def field(self, key: str) -> str:
        return self._target if key == "target" else ""


def test_syslog_port_defaults_to_514_for_non_port_targets():
    for target in ("", "192.168.1.0/24", "10.0.0.1"):
        assert LANPane._syslog_port(_FakeLAN(target)) == (514, False)


def test_syslog_port_accepts_typed_ports():
    for target in ("1514", ":1514", "udp/1514", "UDP:1514"):
        assert LANPane._syslog_port(_FakeLAN(target)) == (1514, True)


def test_syslog_port_rejects_out_of_range():
    try:
        LANPane._syslog_port(_FakeLAN("70000"))
    except ValidationError:
        return
    raise AssertionError("expected ValidationError")


def test_syslog_high_port_collects_without_root():
    async def go():
        collector = syslog.SyslogCollector(port=0)  # 0 = any free port
        await collector.start()
        port = collector._transport.get_extra_info("sockname")[1]
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=("127.0.0.1", port)
        )
        transport.sendto(b"<14>hello netzilla")
        await asyncio.sleep(0.2)
        transport.close()
        collector.stop()
        return collector.messages

    messages = asyncio.run(go())
    assert messages and messages[0]["message"] == "hello netzilla"
    assert messages[0]["severity"] == "info"


# -------------------------------------------------------------------- HIBP
BREACHES = [
    {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com"},
    {"Name": "LinkedIn", "Title": "LinkedIn", "Domain": "linkedin.com"},
    {"Name": "Yahoo", "Title": "Yahoo", "Domain": "yahoo.com"},
    {"Name": "BitTorrent", "Title": "BitTorrent", "Domain": "bittorrent.com"},
]


def _names(term: str) -> list[str]:
    t = hibp.normalise_term(term)
    return [b["Name"] for b in BREACHES if hibp.breach_matches(b, t)]


def test_breach_term_normalisation():
    assert hibp.normalise_term("https://www.LinkedIn.com/login?x=1") == "linkedin.com"
    assert hibp.normalise_term("you@yahoo.com") == "yahoo.com"


def test_breach_matching_is_domain_aware():
    assert _names("adobe") == ["Adobe"]
    assert _names("mail.adobe.com") == ["Adobe"]
    assert _names("https://www.linkedin.com/") == ["LinkedIn"]
    assert _names("you@yahoo.com") == ["Yahoo"]
    assert _names("piratebay.com") == []


# ------------------------------------------------------------- help cards
def _app(tmp_path) -> NetzillaApp:
    return NetzillaApp(
        config_path=tmp_path / "config.toml",
        offline=True,
        start_tab="subnet",
        use_default_keys=False,
    )


def test_help_card_follows_hover_and_gives_way_to_output(tmp_path):
    from netzilla.screens.subnet_calc import SubnetPane

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            pane = app.query_one(SubnetPane)
            card = pane.query_one(".action-help")
            assert not card.display

            await pilot.hover(pane.query_one("#act-split"))
            await pilot.pause()
            assert card.display and pane._help_key == "split"

            await pilot.hover(pane.query_one("#in-network"))
            await pilot.pause()
            assert not card.display

            pane.set_field("network", "192.168.10.0/24")
            await pilot.click(pane.query_one("#act-describe"))
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert not card.display, "card should hide once output arrives"
            assert pane.results.query(".result-panel")

    asyncio.run(go())


def test_help_card_stays_up_on_invalid_input(tmp_path):
    from netzilla.screens.subnet_calc import SubnetPane

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(200, 60)) as pilot:
            pane = app.query_one(SubnetPane)
            pane.set_field("network", "")
            await pilot.click(pane.query_one("#act-describe"))
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert pane.query_one(".action-help").display
            assert not pane._awaiting_output

    asyncio.run(go())
