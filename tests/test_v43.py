"""Tests for netzilla 4.3: pick one device or network in a live list, and
show only it.

  * WIFI -> BLUETOOTH, BT TRACKERS and LIVE AIR: click a row (or Tab to the
    list and use the arrow keys) and the big signal graph follows it; click
    it again (or Enter) and the view shows only it, with everything known
    about it; Esc steps back; the buttons on the line over the list do the
    same; typing in the GRAPH box drops the pick
  * SIGNAL watches the network picked in LIVE AIR when the box is empty
  * the default graph is the nearest device heard *lately* — never one that
    went quiet while its last reading was strong — and quiet readings are
    greyed; rows change places only when a signal has really moved, and hold
    still while the pointer is over the list
"""

from __future__ import annotations

import asyncio
import io
import math
import time

from rich.console import Console

from netzilla import __version__, clipboard
from netzilla.local import bluetooth as bt
from netzilla.local import wifi, wifitools
from netzilla.screens import picking
from netzilla.screens.picking import Pick, PickBar, PickList, Picks

from test_v42 import APPLE, U, FakeScanner, _app, adv


def _text(renderable, width: int = 220) -> str:
    console = Console(width=width, color_system=None, file=io.StringIO())
    console.print(renderable)
    return console.file.getvalue()


def test_version_is_4_3():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (4, 3), __version__


# =========================================================== the picks
def test_a_click_picks_and_a_second_click_shows_only_it():
    picks = Picks()
    assert picks.apply("bt", "click", "AA") == Pick("AA", False)
    assert picks.apply("bt", "click", "AA") == Pick("AA", True)       # again: only it
    assert picks.apply("bt", "click", "AA") == Pick("AA", False)      # again: everything
    assert picks.apply("bt", "click", "BB") == Pick("BB", False)      # another row


def test_arrows_move_the_pick_and_keep_showing_only_it():
    picks = Picks()
    picks.apply("air", "click", "AA")
    picks.apply("air", "only")
    assert picks.apply("air", "move", "BB") == Pick("BB", True)
    assert picks.only("air") and picks.key("air") == "BB"


def test_escape_steps_back_and_let_go_lets_go():
    picks = Picks()
    picks.apply("bt", "click", "AA")
    picks.apply("bt", "only")
    assert picks.apply("bt", "back") == Pick("AA", False)
    assert picks.apply("bt", "back") == Pick()
    picks.apply("bt", "click", "AA")
    picks.apply("bt", "only")
    assert picks.apply("bt", "clear") == Pick()
    assert picks.apply("bt", "only") == Pick()                       # nothing to show only


def test_families_are_picked_separately():
    picks = Picks()
    picks.apply("bt", "click", "AA")
    picks.apply("air", "click", "11")
    assert picks.key("bt") == "AA" and picks.key("air") == "11"
    picks.clear()
    assert not picks.key("bt") and not picks.key("air")


def test_rows_hold_still_while_pointed_at_and_newcomers_join_the_bottom():
    assert picking.steady_order(["B", "A"], ["A", "B"], hold=False) == ["B", "A"]
    assert picking.steady_order(["B", "A", "C"], ["A", "B"], hold=True) == ["A", "B", "C"]
    assert picking.steady_order(["B"], ["A", "B"], hold=True) == ["B"]
    assert picking.steady_order(["B", "A"], None, hold=True) == ["B", "A"]


def test_the_picked_row_is_highlighted_and_every_row_clicks():
    from netzilla.themes import get_palette

    palette = get_palette("phosphor-green")
    styles = picking.row_styles(palette, ["AA", "BB"], picked="BB")
    assert styles[0].meta["@click"] == ("pick", ("AA",)) and styles[0].bgcolor is None
    assert styles[1].meta["@click"] == ("pick", ("BB",)) and styles[1].bgcolor is not None
    assert picking.marked(palette, "Forerunner", True).plain == "▶ Forerunner"
    assert picking.marked(palette, "", True).plain == "▶ —"
    assert picking.marked(palette, "Forerunner", False) == "Forerunner"
    assert picking.blend("#ffffff", "#000000", 0.5) == "#808080"


def test_the_line_over_the_list():
    from netzilla.themes import get_palette

    palette = get_palette("phosphor-green")
    hint = picking.bar(palette, "bt").plain
    assert "Click a device below to graph it" in hint and "Tab to the list" in hint
    assert "Enter" in picking.bar(palette, "bt", focused=True).plain
    picked = picking.bar(palette, "bt", label="Forerunner 265 · F4:3C").plain
    assert "GRAPHING  Forerunner 265" in picked and "[ SHOW ONLY IT ]" in picked
    assert "[ LET GO ]" in picked
    only = picking.bar(palette, "air", label="HomeNet", only=True, hidden=8).plain
    assert "SHOWING ONLY  HomeNet" in only and "(8 other networks hidden)" in only
    assert "[ SHOW ALL ]" in only
    trackers = picking.bar(palette, "bt", label="AirTag", only=True, hidden=1,
                           noun=("tracker", "trackers")).plain
    assert "(1 other tracker hidden)" in trackers
    assert "not heard for a while" in picking.bar(palette, "bt", label="X", lost=True).plain


def test_typing_a_name_drops_the_pick_but_emptying_the_box_does_not():
    class Pane(picking.Picking):
        def __init__(self):
            self._init_picking()
            self.box = ""

        def field(self, key):
            return self.box

    pane = Pane()
    pane.typed_target()
    pane.picks.apply("bt", "click", "AA")
    pane.box = "airtag"
    assert pane.typed_target() == "airtag" and pane.picks.key("bt") == ""
    pane.picks.apply("bt", "click", "AA")
    assert pane.typed_target() == "airtag" and pane.picks.key("bt") == "AA"   # unchanged
    pane.box = ""
    assert pane.typed_target() == "" and pane.picks.key("bt") == "AA"        # emptied


# ================================================ calmer, honest signals
def test_a_steady_level_moves_only_when_the_signal_really_moves():
    watch = bt.Watch()
    t0 = 1000.0
    for second, rssi in enumerate([-60, -62, -59, -61, -63, -60, -58, -61]):
        watch.add(adv(rssi=rssi), now=t0 + second)
        watch.tick(t0 + second)
    device = watch.get("c0:ff:ee:00:00:01")                  # any case
    assert device.level == -60                                # flicker: held
    for second in range(8, 16):
        watch.add(adv(rssi=-75), now=t0 + second)
        watch.tick(t0 + second)
    assert device.level == -75                                # a real move


def test_the_nearest_is_never_a_device_gone_quiet():
    """4.2 graphed a device last heard close by a minute ago as 'nearest'."""
    watch = bt.Watch()
    t0 = 1000.0
    watch.add(adv(address="AA:00:00:00:00:01", rssi=-45), now=t0)       # close, then silent
    for second in range(40):
        watch.add(adv(address="BB:00:00:00:00:02", rssi=-72), now=t0 + second)
        watch.tick(t0 + second)
    now = t0 + 40
    assert watch.find("", now=now).address == "BB:00:00:00:00:02"
    assert watch.nearest(now=now).address == "BB:00:00:00:00:02"
    assert watch.quiet(watch.get("AA:00:00:00:00:01"), now)
    # Quiet ones are listed after every device heard lately.
    assert [d.address for d in watch.ordered(now)] == ["BB:00:00:00:00:02", "AA:00:00:00:00:01"]
    # With nothing heard lately, the most recently heard.
    assert watch.nearest(now=t0 + 55).address == "BB:00:00:00:00:02"


def test_order_changes_only_on_a_real_move():
    watch = bt.Watch()
    t0 = 1000.0
    for second in range(10):
        watch.add(adv(address="AA:00:00:00:00:01", rssi=-60 + (second % 2) * 2), now=t0 + second)
        watch.add(adv(address="BB:00:00:00:00:02", rssi=-61 - (second % 2) * 2), now=t0 + second)
        watch.tick(t0 + second)
    first = [d.address for d in watch.ordered(t0 + 9)]
    for second in range(10, 14):                                 # jitter only
        watch.add(adv(address="AA:00:00:00:00:01", rssi=-62), now=t0 + second)
        watch.add(adv(address="BB:00:00:00:00:02", rssi=-60), now=t0 + second)
        watch.tick(t0 + second)
    assert [d.address for d in watch.ordered(t0 + 13)] == first


def test_names_that_say_what_they_are():
    for name, kind in (("Cast TV 4F2A", "tv"), ("ELK-BLEDOM", "light"),
                       ("8BitDo Zero 2 gamepad", "gaming"), ("LEDBLE-1234", "light")):
        assert bt.classify(adv(name=name)).kind == kind, name


def test_everything_about_one_device():
    watch = bt.Watch()
    t0 = 1000.0
    for second in range(30):
        watch.add(adv(address="F4:3C:91:0A:52:6E", rssi=-63 - second % 3, name="Forerunner 265",
                      manufacturer={0x0087: b"\x01\x02"}, address_type="random",
                      service_uuids=[U("180d")]), now=t0 + second)
        watch.tick(t0 + second)
    device = watch.get("F4:3C:91:0A:52:6E")
    about = dict(bt.about_rows(device))
    assert about["Name"] == "Forerunner 265" and "Garmin" in about["Maker"]
    assert "random, static" in about["Address"]
    assert "0x0087 Garmin" in about["Manufacturer data"]
    assert "Heart Rate (0x180D)" in about["Services"]
    signal = dict(bt.signal_rows(watch, device, now=t0 + 29))
    assert signal["Signal now"].endswith("dBm")
    assert signal["Lowest / average / highest"].startswith("-65 / -64 / -63 dBm")
    assert signal["Broadcasts heard"].startswith("30")
    assert "Tracker check" not in signal
    quiet = dict(bt.signal_rows(watch, device, now=t0 + 60))
    assert "last heard" in quiet["Signal now"]


def test_address_kinds():
    def kind(address, address_type):
        return bt.address_kind(bt.Device(address=address, first_seen=0, last_seen=0,
                                         advert=adv(address=address, address_type=address_type),
                                         guess=bt.Guess()))

    assert kind("C1:00:00:00:00:00", "random").startswith("random, static")
    assert kind("5A:00:00:00:00:00", "random").startswith("random, private — changes")
    assert kind("00:1A:7D:00:00:00", "public").startswith("public")
    assert kind("6B2E419C-0000", "") == "type not reported"


def _ap(ssid, bssid, dbm, channel=6, band="2.4 GHz", in_use=False):
    return {"ssid": ssid, "bssid": bssid, "signal_dbm": dbm, "channel": channel,
            "band": band, "security": "WPA2", "in_use": in_use}


def test_networks_change_places_only_on_a_real_move():
    a, b = "aa:00:00:00:00:01", "bb:00:00:00:00:02"
    watch = wifitools.AirWatch()
    watch.update([_ap("A", a, -60), _ap("B", b, -61)], now=1)
    watch.update([_ap("A", a, -62), _ap("B", b, -60)], now=2)               # flicker
    assert [e["ssid"] for e in watch.present(2)] == ["A", "B"]
    watch.update([_ap("A", a, -70), _ap("B", b, -60)], now=3)               # a real move
    assert [e["ssid"] for e in watch.present(3)] == ["B", "A"]
    assert watch.get("AA-00-00-00-00-01")["ssid"] == "A"                    # any spelling
    assert watch.get("") is None and watch.get("cc:00:00:00:00:03") is None
    assert [e["key"] for e in watch.ordered(3)] == [b, a]


def test_everything_about_one_network():
    watch = wifitools.AirWatch()
    for t in range(5):
        watch.update([_ap("Home", "aa:01", -50 - t, in_use=True), _ap("Next", "bb:02", -70),
                      _ap("Side", "cc:03", -80, channel=3), _ap("Far5", "dd:04", -75, 36, "5 GHz")],
                     now=100 + t)
    rows = dict(wifitools.network_rows(watch.get("aa:01"), watch.present(104), now=104))
    assert "the one you're joined to" in rows["Network"]
    assert rows["Lowest / average / highest"].startswith("-54 / -52 / -50 dBm")
    assert rows["Sharing its channel"] == "Next (-70 dBm)"
    assert rows["Overlapping its channel"] == "Side (-80 dBm) on 3"


def test_a_one_line_list_knows_its_height_without_being_drawn():
    from netzilla.render import table_panel
    from netzilla.themes import get_palette

    palette = get_palette("phosphor-green")
    long = "a name far too long for its column " * 4
    for count in (0, 1, 7, 40):
        rows = [[long, "Watch", "Garmin International", f"AA:00:00:00:00:{i:02X}", -60,
                 "▁▂▃▄", "~1–2 m", "12:00:00", "now", ""] for i in range(count)]
        keys = [row[3] for row in rows]
        panel = table_panel(palette, "Bluetooth devices, live", ["Name", "Device", "Vendor",
                            "MAC", "dBm", "History", "Distance", "First seen",
                            "Last seen", "Flag"], rows, subtitle="a subtitle " * 30,
                            row_styles=picking.row_styles(palette, keys), one_line=True,
                            shrink=("Name", "Device", "Vendor"))
        widget = PickList("bt")
        widget.show(panel, keys=keys, shown=keys, one_line=True)
        for width in (60, 120, 160, 200):
            drawn = _text(panel, width=width).rstrip("\n").count("\n") + 1
            assert widget.get_content_height(None, None, width) == drawn, (count, width)


def test_only_names_kinds_and_makers_give_up_width():
    from netzilla.render import table_panel
    from netzilla.themes import get_palette

    palette = get_palette("phosphor-green")
    columns = ["Name", "Device", "Vendor", "MAC", "dBm", "Distance", "Last seen"]
    row = ["Galaxy Buds2 Pro (5F21) in the kitchen", "Find Hub tag (away from owner)",
           "Nordic Semiconductor ASA", "C9:22:7B:40:15:9E", -92, "~10–20 m", "now"]
    text = _text(table_panel(palette, "Devices", columns, [row], one_line=True,
                             shrink=("Name", "Device", "Vendor")), width=100)
    assert "C9:22:7B:40:15:9E" in text and "-92" in text and "~10–20 m" in text
    assert "…" in text and "DISTANCE" in text and "LAST SEEN" in text


# ====================================================== in a running app
SCENE = [
    adv(address="6B:2E:41:9C:07:12", rssi=-47,
        manufacturer={APPLE: bytes([0x07, 0x19, 0x01, 0x14, 0x20] + [0] * 22)}),
    adv(address="F4:3C:91:0A:52:6E", rssi=-63, name="Forerunner 265",
        manufacturer={0x0087: b"\x01"}),
    adv(address="C1:7A:22:E0:14:8B", rssi=-71, address_type="random",
        manufacturer={APPLE: bytes([0x12, 0x19, 0x10] + [7] * 24)}),
    adv(address="E2:91:0C:55:3D:77", rssi=-78, service_data={U("feed"): b"\x02"}),
]


class Scene(FakeScanner):
    """Keeps hearing SCENE while it runs."""

    async def start(self):
        async def feed():
            while True:
                for advert in SCENE:
                    self.on_advert(advert)
                await asyncio.sleep(0.05)

        self._task = asyncio.get_running_loop().create_task(feed())

    async def stop(self):
        self._task.cancel()
        await super().stop()


def _live(tmp_path, action, script, scanner=Scene, size=(200, 60), ticks=None, prepare=None):
    """Run `action` live in a real app, then `script(app, pane, pilot)`."""
    async def place(iface=""):
        return bt.place_from("192.168.1.1", "aa:bb:cc:00:00:01", "HomeNet")

    async def go():
        app = _app(tmp_path, start_tab="wifi")
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            pane = app._active_pane()
            pane.BT_SCANNER = scanner
            pane.BT_EVERY = 0.25         # often enough, and the app still goes idle
            pane.AIR_EVERY = 1.0
            pane.MAX_TICKS = ticks
            pane.toggle_controls(True)
            original = bt.current_place
            bt.current_place = place
            try:
                if prepare:
                    prepare(app, pane)
                pane.dispatch(action)
                if ticks:
                    await app.workers.wait_for_complete()
                else:
                    await pilot.pause(0.6)
                await pilot.pause()
                result = await script(app, pane, pilot)
                app.workers.cancel_all()
                await pilot.pause()
                return result
            finally:
                bt.current_place = original
    return asyncio.run(go())


async def _click_row(pilot, pane, key):
    table = pane.query_one(PickList)
    await pilot.click(PickList, offset=(12, PickList.FIRST_ROW + table.shown.index(key)))
    await pilot.pause(0.15)


async def _click_button(pilot, pane, caption):
    bar = pane.query_one(PickBar)
    plain = bar.content.renderables[0].plain
    await pilot.click(PickBar, offset=(plain.index(f"[ {caption} ]") + 2, 0))
    await pilot.pause(0.15)


def _graph_title(pane) -> str:
    text = clipboard.pane_text(pane)
    return next(line for line in text.splitlines() if "SIGNAL —" in line)


def test_clicking_a_device_graphs_it_and_clicking_again_shows_only_it(tmp_path):
    seen = {}

    async def script(app, pane, pilot):
        assert "SIGNAL — EARBUDS" in _graph_title(pane)            # nearest, by default
        await _click_row(pilot, pane, "F4:3C:91:0A:52:6E")
        seen["picked"] = clipboard.pane_text(pane)
        seen["focused"] = app.focused
        await _click_row(pilot, pane, "F4:3C:91:0A:52:6E")
        seen["only"] = clipboard.pane_text(pane)
        seen["shown"] = list(pane.query_one(PickList).shown)
        await pilot.press("escape")
        await pilot.pause(0.15)
        seen["back"] = (pane.picks.get("bt"), len(pane.query_one(PickList).shown))
        await pilot.press("escape")
        await pilot.pause(0.15)
        seen["clear"] = (pane.picks.get("bt"), _graph_title(pane))

    _live(tmp_path, "bluetooth", script)
    picked = seen["picked"]
    assert "SIGNAL — FORERUNNER 265" in picked and "the device you picked" in picked
    assert "▶ GRAPHING  Forerunner 265 · F4:3C:91:0A:52:6E" in picked
    assert "▶ Forerunner 265" in picked                            # the row, marked
    assert "AirPods Pro" in picked and "4 devices nearby" in picked  # everything still listed
    assert isinstance(seen["focused"], PickList)                   # ready for the arrow keys
    only = seen["only"]
    assert seen["shown"] == ["F4:3C:91:0A:52:6E"]
    assert "showing only Forerunner 265 (F4:3C:91:0A:52:6E)" in only
    assert "3 other devices hidden" in only
    assert "SHOWING ONLY  Forerunner 265" in only and "[ SHOW ALL ]" in only
    assert "ABOUT FORERUNNER 265" in only and "ITS SIGNAL" in only
    assert "Garmin" in only and "LOWEST / AVERAGE / HIGHEST" in only
    assert "AirPods Pro" not in only and "NEARBY, BY KIND" not in only
    assert seen["back"] == (Pick("F4:3C:91:0A:52:6E", False), 4)
    assert seen["clear"][0] == Pick() and "SIGNAL — EARBUDS" in seen["clear"][1]


def test_arrow_keys_walk_the_list_and_enter_shows_only_one(tmp_path):
    seen = []

    async def script(app, pane, pilot):
        table = pane.query_one(PickList)
        table.focus()
        await pilot.pause(0.1)
        await pilot.press("down")                    # nothing picked yet: the first row
        await pilot.pause(0.15)
        seen.append(pane.picks.get("bt"))
        await pilot.press("down")
        await pilot.pause(0.15)
        seen.append(pane.picks.get("bt"))
        await pilot.press("enter")
        await pilot.pause(0.15)
        seen.append((pane.picks.get("bt"), list(table.shown)))
        await pilot.press("down")                    # the next device, still on its own
        await pilot.pause(0.15)
        seen.append((pane.picks.get("bt"), list(table.shown)))
        await pilot.press("end")
        await pilot.pause(0.15)
        seen.append(pane.picks.get("bt").key)
        await pilot.press("home")
        await pilot.pause(0.15)
        seen.append(pane.picks.get("bt").key)
        seen.append(list(table.keys))

    _live(tmp_path, "bluetooth", script)
    order = seen[-1]
    assert seen[0] == Pick(order[0], False) and seen[1] == Pick(order[1], False)
    assert seen[2] == (Pick(order[1], True), [order[1]])
    assert seen[3] == (Pick(order[2], True), [order[2]])
    assert seen[4] == order[-1] and seen[5] == order[0]      # End, Home


def test_the_buttons_over_the_list(tmp_path):
    seen = []

    async def script(app, pane, pilot):
        await _click_row(pilot, pane, "C1:7A:22:E0:14:8B")
        await _click_button(pilot, pane, "SHOW ONLY IT")
        seen.append(pane.picks.get("bt"))
        await _click_button(pilot, pane, "SHOW ALL")
        seen.append(pane.picks.get("bt"))
        await _click_button(pilot, pane, "LET GO")
        seen.append(pane.picks.get("bt"))

    _live(tmp_path, "bluetooth", script)
    key = "C1:7A:22:E0:14:8B"
    assert seen == [Pick(key, True), Pick(key, False), Pick()]


def test_typing_in_the_graph_box_drops_the_pick(tmp_path):
    seen = {}

    async def script(app, pane, pilot):
        await _click_row(pilot, pane, "E2:91:0C:55:3D:77")
        seen["picked"] = _graph_title(pane)
        pane.set_field("target", "forerunner")
        await pilot.pause(0.3)
        seen["typed"] = (_graph_title(pane), pane.picks.get("bt"))
        await _click_row(pilot, pane, "E2:91:0C:55:3D:77")     # a click wins again
        seen["clicked"] = _graph_title(pane)

    _live(tmp_path, "bluetooth", script)
    assert "SIGNAL — TRACKER · TILE" in seen["picked"]
    title, pick = seen["typed"]
    assert "SIGNAL — FORERUNNER 265" in title and pick == Pick()
    assert "SIGNAL — TRACKER · TILE" in seen["clicked"]


def test_a_tracker_picked_in_bluetooth_is_picked_in_bt_trackers_too(tmp_path):
    seen = {}

    async def script(app, pane, pilot):
        await _click_row(pilot, pane, "E2:91:0C:55:3D:77")
        await _click_row(pilot, pane, "E2:91:0C:55:3D:77")   # only it
        pane.dispatch("bttrackers")
        await pilot.pause(0.6)
        seen["trackers"] = clipboard.pane_text(pane)
        seen["shown"] = list(pane.query_one(PickList).shown)

    _live(tmp_path, "bluetooth", script)
    text = seen["trackers"]
    assert seen["shown"] == ["E2:91:0C:55:3D:77"]
    assert "showing only Tracker · Tile (E2:91:0C:55:3D:77)" in text
    assert "1 other tracker hidden" in text
    assert "TRACKERS REMEMBERED (7 DAYS)" in text and "ITS SIGNAL" in text


def test_bt_trackers_leaves_a_picked_device_that_is_not_a_tracker_alone(tmp_path):
    seen = {}

    async def script(app, pane, pilot):
        await _click_row(pilot, pane, "F4:3C:91:0A:52:6E")
        pane.dispatch("bttrackers")
        await pilot.pause(0.6)
        seen["text"] = clipboard.pane_text(pane)
        seen["pick"] = pane.picks.get("bt")

    _live(tmp_path, "bluetooth", script)
    assert "Click a tracker below to graph it" in seen["text"]   # nothing picked here
    assert "SIGNAL — TRACKER" in seen["text"]                    # the nearest tracker
    assert seen["pick"].key == "F4:3C:91:0A:52:6E"              # still picked for BLUETOOTH


def test_a_pick_after_the_scan_stopped_still_shows(tmp_path):
    seen = {}

    async def script(app, pane, pilot):
        await _click_row(pilot, pane, "F4:3C:91:0A:52:6E")
        seen["first"] = clipboard.pane_text(pane)
        await pilot.pause(1.2)
        await _click_row(pilot, pane, "F4:3C:91:0A:52:6E")
        seen["second"] = clipboard.pane_text(pane)

    _live(tmp_path, "bluetooth", script, ticks=3)
    for key in ("first", "second"):
        text = seen[key]
        assert "■ BLUETOOTH" in text and "SIGNAL — FORERUNNER 265" in text
    stopped = [line for line in seen["second"].splitlines() if "■ BLUETOOTH" in line][0]
    assert stopped.endswith("stopped after 0:00")                # frozen, not still counting


def test_rows_hold_still_under_the_pointer(tmp_path):
    seen = {}

    async def script(app, pane, pilot):
        table = pane.query_one(PickList)
        seen["before"] = list(table.shown)
        await pilot.hover(PickList, offset=(12, PickList.FIRST_ROW + 1))
        SCENE[3] = adv(address="E2:91:0C:55:3D:77", rssi=-35, service_data={U("feed"): b"\x02"})
        await pilot.pause(0.6)
        seen["held"] = list(table.shown)
        seen["subtitle"] = clipboard.pane_text(pane)
        await pilot.hover("#collapse-toggle")
        await pilot.pause(0.6)
        seen["after"] = list(table.shown)

    original = SCENE[3]
    try:
        _live(tmp_path, "bluetooth", script)
    finally:
        SCENE[3] = original
    assert seen["held"] == seen["before"]
    assert "order held while the pointer is over the list" in seen["subtitle"]
    assert seen["after"][0] == "E2:91:0C:55:3D:77"               # now the strongest


def test_quiet_readings_are_greyed_and_never_the_default(tmp_path):
    seen = {}

    def prepare(app, pane):
        # Heard close by twenty seconds ago, nothing since.
        pane._bt.add(adv(address="AB:CD:EF:00:00:01", rssi=-40, name="Old Phone"),
                     now=time.time() - 20)

    async def script(app, pane, pilot):
        table = pane.query_one(PickList)
        seen["title"] = _graph_title(pane)
        seen["last"] = table.shown[-1]
        rendered = table.content.renderable
        dbm = rendered.columns[4]._cells[-1]
        seen["dbm"] = (dbm.plain, str(dbm.style))

    _live(tmp_path, "bluetooth", script, prepare=prepare)
    assert "OLD PHONE" not in seen["title"]                     # not the "nearest"
    assert seen["last"] == "AB:CD:EF:00:00:01"                  # listed after the heard
    from netzilla.themes import get_palette
    assert seen["dbm"] == ("-40", get_palette("phosphor-green").muted)


def test_the_picked_row_is_kept_in_view_with_the_arrow_keys(tmp_path):
    many = [adv(address=f"AA:00:00:00:00:{i:02X}", rssi=-40 - i, name=f"Device {i}")
            for i in range(30)]

    class Many(Scene):
        async def start(self):
            async def feed():
                while True:
                    for advert in many:
                        self.on_advert(advert)
                    await asyncio.sleep(0.05)
            self._task = asyncio.get_running_loop().create_task(feed())

    seen = {}

    async def script(app, pane, pilot):
        table = pane.query_one(PickList)
        table.focus()
        await pilot.pause(0.1)
        start = pane.results.scroll_y
        for _ in range(30):                          # the first press picks the first row
            await pilot.press("down")
        await pilot.pause(0.4)
        seen["scrolled"] = pane.results.scroll_y - start
        seen["pick"] = pane.picks.key("bt")
        seen["row_visible"] = pane.results.region.contains(table.region.x + 2,
                                                           table.region.y + PickList.FIRST_ROW
                                                           + table.shown.index(seen["pick"]))

    _live(tmp_path, "bluetooth", script, scanner=Many, size=(160, 40))
    assert seen["pick"] == "AA:00:00:00:00:1D"
    assert seen["scrolled"] > 0 and seen["row_visible"]


# ============================================================== LIVE AIR
AIR = [("HomeNet", "a4:2b:b0:11:22:33", -48, 6, True), ("Neighbour", "3c:84:6a:aa:bb:01", -63, 6, False),
       ("CoffeeShop", "00:1d:7e:44:55:66", -71, 1, False), ("Upstairs", "a4:2b:b0:99:88:77", -66, 149, False)]


def _air(monkeypatch):
    def aps():
        t = time.time()
        return [{"ssid": s, "bssid": b, "signal_dbm": int(d + math.sin(t + i)), "channel": c,
                 "band": "2.4 GHz" if c < 15 else "5 GHz", "security": "WPA2", "in_use": mine,
                 "rate_mbps": 0, "quality": 0}
                for i, (s, b, d, c, mine) in enumerate(AIR)]

    async def scan_cached(iface=""):
        return aps(), "nmcli", ""

    async def nothing(*a, **k):
        return None

    async def no_iw(iface):
        return False

    async def no_interfaces():
        return []

    monkeypatch.setattr(wifi, "scan_cached", scan_cached)
    monkeypatch.setattr(wifi, "scan_trigger", nothing)
    monkeypatch.setattr(wifi, "can_trigger_with_iw", no_iw)
    monkeypatch.setattr(wifi, "wireless_interfaces", no_interfaces)


def test_live_air_pick_one_network_and_show_only_it(tmp_path, monkeypatch):
    _air(monkeypatch)
    seen = {}

    async def script(app, pane, pilot):
        assert "SIGNAL — HOMENET" in _graph_title(pane)          # yours, by default
        await _click_row(pilot, pane, "3c:84:6a:aa:bb:01")
        seen["picked"] = clipboard.pane_text(pane)
        await _click_row(pilot, pane, "3c:84:6a:aa:bb:01")
        seen["only"] = clipboard.pane_text(pane)
        seen["shown"] = list(pane.query_one(PickList).shown)

    _live(tmp_path, "air", script)
    picked = seen["picked"]
    assert "SIGNAL — NEIGHBOUR" in picked and "the network you picked" in picked
    assert "▶ GRAPHING  Neighbour · 3c:84:6a:aa:bb:01" in picked and "▶ Neighbour" in picked
    assert "CoffeeShop" in picked
    only = seen["only"]
    assert seen["shown"] == ["3c:84:6a:aa:bb:01"]
    assert "showing only Neighbour (3c:84:6a:aa:bb:01)" in only
    assert "3 other networks hidden" in only
    assert "ABOUT NEIGHBOUR" in only and "SHARING ITS CHANNEL" in only
    assert "only the network you picked" in only                 # the spectrum too
    assert "2.4 GHZ LOAD" not in only and "CoffeeShop" not in only


def test_signal_watches_the_network_picked_in_live_air(tmp_path, monkeypatch):
    _air(monkeypatch)
    seen = {}

    async def script(app, pane, pilot):
        await _click_row(pilot, pane, "00:1d:7e:44:55:66")
        pane.MAX_TICKS = 2
        pane.dispatch("signal")
        for _ in range(60):                          # two readings, a second apart
            await pilot.pause(0.1)
            if "DONE" in clipboard.pane_text(pane):
                break
        seen["text"] = clipboard.pane_text(pane)

    _live(tmp_path, "air", script)
    assert "● COFFEESHOP" in seen["text"] and "Never saw that network" not in seen["text"]
