"""Tests for netzilla 4.2.

  * every tab's buttons sit on equal-width columns shared by all its rows,
    full rows run edge to edge, no label is cut off, drop-downs are as tall
    as the text boxes beside them
  * WIFI -> BLUETOOTH: names, makers, best guesses, signal history, rough
    distance, first and last heard; BT TRACKERS: trackers that linger or turn
    up on more than one network you were on
  * no Bluetooth hardware is needed: a fake scanner stands in for bleak
"""

from __future__ import annotations

import asyncio
import io
import os
import time

import pytest
from rich.console import Console

from netzilla import __version__
from netzilla.local import bluetooth as bt
from netzilla.screens.base import action_columns

U = lambda short: f"0000{short}-0000-1000-8000-00805f9b34fb"  # noqa: E731


def _app(tmp_path, **kwargs):
    from netzilla.app import NetzillaApp

    return NetzillaApp(config_path=tmp_path / "config.toml", offline=True,
                       use_default_keys=False, **kwargs)


def _text(renderable, width: int = 220) -> str:
    console = Console(width=width, color_system=None, file=io.StringIO())
    console.print(renderable)
    return console.file.getvalue()


def test_version_is_4_2():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (4, 2), __version__


# ====================================================== buttons lined up
def test_columns_follow_the_longest_row_with_a_floor():
    assert action_columns([7, 6], ["TCPDUMP CAPTURE"], 184) == 7
    assert action_columns([2], ["REFRESH"], 184) == 6          # few buttons: 6 columns
    assert action_columns([8], ["TYPOSQUAT SEARCH"], 184) == 8


def test_columns_drop_evenly_when_a_label_would_not_fit():
    # "FIRST-SEEN TIMELINE" does not fit an eighth of 184: 4 + 4, not 7 + 1
    assert action_columns([8], ["FIRST-SEEN TIMELINE"], 184) == 4
    assert action_columns([7, 6], ["TCPDUMP CAPTURE"], 114) == 4
    assert action_columns([2], ["RUN SPEED TEST"], 114) == 5
    assert action_columns([2], ["RUN SPEED TEST"], 10) == 1


def _tab_layouts(tmp_path, size):
    from netzilla.app import TABS

    async def go():
        app = _app(tmp_path)
        out = {}
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            for tab_id, _label, _cls in TABS:
                app.query_one("#tabs").active = tab_id
                await pilot.pause(0.15)
                pane = app._active_pane()
                for _ in range(40):                     # wait until it is laid out
                    if pane.region.width and all(b.region.width for b in pane.query("Button")):
                        break
                    await pilot.pause(0.05)
                await pilot.pause(0.05)
                rows = []
                for row in pane.query(".action-row"):
                    rows.append((row.styles.grid_size_columns, row.region,
                                 [(b.region, str(b.label)) for b in row.query("Button")]))
                boxes = [(w.region, type(w).__name__) for w in pane.query(".field-input, .field-select")]
                out[tab_id] = (rows, boxes)
        return out
    return asyncio.run(go())


@pytest.mark.parametrize("size", [(190, 50), (120, 40)])
def test_every_tabs_buttons_share_equal_columns(tmp_path, size):
    for tab, (rows, _boxes) in _tab_layouts(tmp_path, size).items():
        if not rows:
            continue
        assert len({cols for cols, _region, _buttons in rows}) == 1, tab
        columns = rows[0][0]
        lefts, widths = set(), set()
        for _cols, region, buttons in rows:
            for button, label in buttons:
                lefts.add(button.x)
                widths.add(button.width)
                assert len(label) <= button.width - 2, (tab, label, button.width)
        assert len(lefts) <= columns, (tab, sorted(lefts))
        assert max(widths) - min(widths) <= 1, (tab, widths)        # equal columns
        # a full row runs to the right-hand edge of its grid
        for cols, region, buttons in rows:
            if len(buttons) >= cols:
                assert buttons[cols - 1][0].right == region.right, (tab, region)


def test_drop_downs_are_as_tall_as_text_boxes(tmp_path):
    for tab, (_rows, boxes) in _tab_layouts(tmp_path, (190, 50)).items():
        heights = {region.height for region, _kind in boxes}
        assert heights <= {3}, (tab, boxes)


def test_wifi_rows_are_flush_with_each_other(tmp_path):
    rows, boxes = _tab_layouts(tmp_path, (190, 50))["wifi"]
    assert [len(buttons) for _c, _r, buttons in rows] == [7, 7]
    right = rows[0][2][-1][0].right
    assert all(buttons[-1][0].right == right for _c, _r, buttons in rows)
    # the last box ends where the buttons do
    assert max(region.right for region, _kind in boxes) == right
    labels = [[label for _region, label in buttons] for _c, _r, buttons in rows]
    assert labels[0][-1] == "BLUETOOTH" and labels[1][-1] == "BT TRACKERS"


def test_rolling_the_controls_up_hides_the_buttons(tmp_path):
    async def go():
        app = _app(tmp_path, start_tab="wifi")
        async with app.run_test(size=(190, 50)) as pilot:
            await pilot.pause()
            pane = app._active_pane()
            pane.toggle_controls(True)
            await pilot.pause()
            grid = pane.query_one(".action-grid")
            return grid.display, grid.region.height
    shown, height = asyncio.run(go())
    assert not shown or height == 0


# ============================================================ decoding
APPLE = 0x004C


def adv(**kwargs) -> bt.Advert:
    kwargs.setdefault("address", "C0:FF:EE:00:00:01")
    kwargs.setdefault("rssi", -60)
    return bt.Advert(**kwargs)


def test_assigned_numbers_ship_with_netzilla():
    assert bt.company_name(APPLE) == "Apple, Inc."
    assert bt.company_name(0x0075).startswith("Samsung")
    assert bt.uuid_name(U("feed")).startswith("Tile")
    assert bt.short_uuid(U("180d")) == 0x180D and bt.short_uuid("FEAA") == 0xFEAA
    assert bt.short_uuid("12345678-1234-5678-1234-567812345678") is None
    assert bt.short_company("Samsung Electronics Co. Ltd.") == "Samsung Electronics"


@pytest.mark.parametrize("advert, kind, label, tracker", [
    (adv(manufacturer={APPLE: bytes([0x12, 0x19, 0x10] + [0] * 24)}), "tracker",
     "AirTag (away from owner)", "AirTag"),
    (adv(manufacturer={APPLE: bytes([0x12, 0x02, 0x14, 0x00])}), "tracker",
     "AirTag (with owner)", "AirTag"),
    (adv(manufacturer={APPLE: bytes([0x12, 0x19, 0x30] + [0] * 24)}), "tracker",
     "Find My accessory (away from owner)", "Find My accessory"),
    (adv(manufacturer={APPLE: bytes([0x07, 0x19, 0x01, 0x0E, 0x20] + [0] * 22)}), "earbuds",
     "AirPods Pro", ""),
    (adv(manufacturer={APPLE: bytes([0x07, 0x19, 0x01, 0x0A, 0x20] + [0] * 22)}), "headphones",
     "AirPods Max", ""),
    (adv(manufacturer={APPLE: bytes([0x10, 0x05, 0x01, 0x18, 0, 0, 0])}), "phone",
     "iPhone/iPad/Mac/Watch", ""),
    (adv(manufacturer={APPLE: bytes([0x0E, 0x02, 0x00, 0x00])}), "phone",
     "iPhone (Instant Hotspot)", ""),
    (adv(service_data={U("feed"): b"\x02\x00"}), "tracker", "Tile", "Tile"),
    (adv(service_uuids=[U("feec")]), "tracker", "Tile", "Tile"),
    (adv(service_data={U("fd5a"): b"\x10"}), "tracker", "Samsung SmartTag", "SmartTag"),
    (adv(service_data={U("fe33"): b"\x01"}), "tracker", "Chipolo", "Chipolo"),
    (adv(service_data={U("feaa"): bytes([0x41] + [0] * 20)}), "tracker",
     "Find Hub tag (away from owner)", "Find Hub tag"),
    (adv(service_data={U("feaa"): bytes([0x00, 0xEC] + [0] * 16)}), "beacon",
     "Eddystone-UID", ""),
    (adv(service_data={U("fe2c"): b"\x00\x01\x02"}), "earbuds", "Fast Pair audio", ""),
    (adv(manufacturer={0x0006: bytes([0x01, 0x09, 0x20, 0x00] + [0] * 20)}), "computer",
     "Windows desktop", ""),
    (adv(manufacturer={0x0006: bytes([0x01, 0x08, 0x20, 0x00] + [0] * 20)}), "phone",
     "Android phone", ""),
    (adv(manufacturer={0x0006: bytes([0x03, 0x00, 0x80])}), "input",
     "Swift Pair accessory", ""),
    (adv(name="Galaxy Buds2 Pro (5F21)", manufacturer={0x0075: b"\x42"}), "earbuds", "", ""),
    (adv(name="Forerunner 265", manufacturer={0x0087: b"\x01"}), "watch", "", ""),
    (adv(appearance=0x03C1), "input", "keyboard", ""),
    (adv(device_class=0x240404), "earbuds", "headset", ""),
    (adv(device_class=0x5A020C), "phone", "smartphone", ""),
    (adv(name="[TV] Living Room", device_class=0x0C043C), "tv", "TV", ""),
    (adv(icon="audio-headphones"), "headphones", "headphones", ""),
    (adv(manufacturer={0x0059: b"\x00"}), "other", "", ""),
])
def test_best_guess(advert, kind, label, tracker):
    guess = bt.classify(advert, bt.maker_of(advert))
    assert (guess.kind, guess.label, guess.tracker) == (kind, label, tracker)


def test_ibeacon_carries_its_own_one_metre_power():
    advert = adv(manufacturer={APPLE: bytes([0x02, 0x15] + [0x11] * 16 + [0, 7, 0, 42, 0xC5])})
    guess = bt.classify(advert)
    assert guess.kind == "beacon" and guess.label == "iBeacon 7/42" and guess.ref_1m == -59


def test_maker_from_manufacturer_id_member_uuid_or_address():
    assert bt.maker_of(adv(manufacturer={APPLE: b"\x10\x00"})) == "Apple"
    assert bt.maker_of(adv(manufacturer={0x0ABC: b""})) .startswith(("ID 0x0ABC", ""))
    assert bt.maker_of(adv(service_data={U("feed"): b""})) == "Tile"
    assert bt.maker_of(adv(service_data={U("fd6f"): b""})) == ""   # shared service
    lookup = lambda mac: "Intel Corporate"  # noqa: E731
    assert bt.maker_of(adv(address_type="public"), lookup) == "Intel Corporate"
    assert bt.maker_of(adv(address_type="random"), lookup) == ""   # private address


def test_rough_distance():
    assert bt.distance_m(-59) == pytest.approx(1.0)
    assert bt.distance_m(-80) > bt.distance_m(-70) > bt.distance_m(-60)
    assert bt.distance_m(-59, ref_1m=-70) < 1
    assert bt.distance_m(None) is None
    assert [bt.distance_text(m) for m in (0.5, 1.5, 3, 7, 15, 40, None)] == [
        "< 1 m", "~1–2 m", "~2–5 m", "~5–10 m", "~10–20 m", "20 m +", "—"]


def test_from_bleak_reads_bluez_properties():
    class Device:
        address = "AA:BB:CC:DD:EE:FF"
        name = "AA-BB-CC-DD-EE-FF"            # BlueZ's stand-in name

    class Data:
        local_name = None
        manufacturer_data = {APPLE: bytearray(b"\x10\x05\x01\x18\x00\x00\x00")}
        service_data = {U("feed"): bytearray(b"\x01")}
        service_uuids = [U("feed")]
        tx_power = 8
        rssi = -63
        platform_data = ("/org/bluez/hci0/dev_AA", {
            "Address": "AA:BB:CC:DD:EE:FF", "AddressType": "random", "Appearance": 64,
            "Class": None, "Icon": "phone", "Paired": False, "Connected": False})

    advert = bt.from_bleak(Device(), Data())
    assert advert.name == "" and advert.rssi == -63 and advert.address_type == "random"
    assert advert.manufacturer[APPLE].startswith(b"\x10") and advert.tx_power == 8
    assert advert.appearance == 64 and advert.icon == "phone"


# =========================================================== the watch
def test_first_last_seen_and_history_with_gaps():
    watch = bt.Watch()
    t0 = 1_000_000.0
    for second in range(30):
        if second < 10 or second >= 20:                 # silent for ten seconds
            watch.add(adv(rssi=-60 - second % 3), now=t0 + second)
        watch.tick(t0 + second)
    device = watch.devices["C0:FF:EE:00:00:01"]
    assert device.first_seen == t0 and device.last_seen == t0 + 29
    history = list(device.history)
    assert len(history) == 30 and None in history       # the silence shows as gaps
    assert history[0] is not None and history[-1] is not None


def test_a_name_heard_once_is_kept():
    watch = bt.Watch()
    watch.add(adv(name="Pixel Buds Pro"), now=1.0)
    watch.add(adv(), now=2.0)                           # a broadcast without the name
    assert watch.devices["C0:FF:EE:00:00:01"].name == "Pixel Buds Pro"


def test_a_property_change_without_a_reading_is_not_a_sighting():
    watch = bt.Watch()
    assert watch.add(adv(rssi=None), now=0.0) is None and not watch.devices
    watch.add(adv(rssi=-60), now=0.0)
    watch.add(adv(rssi=None, name="Late Name"), now=50.0)
    device = watch.devices["C0:FF:EE:00:00:01"]
    assert device.last_seen == 0.0 and device.name == "Late Name"


def test_bluez_no_reading_value_is_dropped():
    class Device:
        address = "AA:BB:CC:DD:EE:FF"
        name = None

    class Data:
        local_name = "Headset"
        manufacturer_data = service_data = {}
        service_uuids = []
        tx_power = None
        rssi = -127
        platform_data = None

    assert bt.from_bleak(Device(), Data()).rssi is None


def test_gone_and_forgotten():
    watch = bt.Watch()
    watch.add(adv(), now=0.0)
    assert len(watch.present(30.0)) == 1 and not watch.gone(30.0)
    assert not watch.present(61.0) and len(watch.gone(61.0)) == 1
    watch.tick(901.0)
    assert not watch.devices


def test_find_by_name_address_suffix_or_kind():
    watch = bt.Watch()
    watch.add(adv(address="11:22:33:44:55:66", name="Kitchen Speaker", rssi=-70), now=1.0)
    watch.add(adv(address="AA:BB:CC:DD:EE:01", rssi=-50,
                  manufacturer={APPLE: bytes([0x12, 0x19, 0x10] + [0] * 24)}), now=1.0)
    watch.tick(1.0)
    assert watch.find("", now=1.0).address == "AA:BB:CC:DD:EE:01"      # nearest
    assert watch.find("kitchen speaker", now=1.0).name == "Kitchen Speaker"
    assert watch.find("55:66", now=1.0).address == "11:22:33:44:55:66"
    assert watch.find("aabbccddee01", now=1.0).address == "AA:BB:CC:DD:EE:01"
    assert watch.find("airtag", now=1.0).address == "AA:BB:CC:DD:EE:01"
    assert watch.find("nothing like it", now=1.0) is None


def test_summary_counts_in_words():
    watch = bt.Watch()
    watch.add(adv(address="A1:00:00:00:00:01", manufacturer={APPLE: bytes([0x10, 0x01, 0x01])}), now=1)
    watch.add(adv(address="A1:00:00:00:00:02", manufacturer={APPLE: bytes([0x10, 0x01, 0x01])}), now=1)
    watch.add(adv(address="A1:00:00:00:00:03", name="Forerunner 265"), now=1)
    watch.add(adv(address="A1:00:00:00:00:04", manufacturer={0x0059: b""}), now=1)
    assert watch.summary(now=1) == [("phones", 2), ("watch", 1), ("other", 1)]


def _tracker(watch, address, start, minutes, separated=True, step=10.0):
    payload = [0x12, 0x19 if separated else 0x02, 0x10] + [0] * (24 if separated else 1)
    t = start
    while t <= start + minutes * 60:
        watch.add(adv(address=address, manufacturer={APPLE: bytes(payload)}), now=t)
        t += step
    return watch.devices[address]


def test_a_tracker_near_you_for_ten_minutes_is_flagged():
    watch = bt.Watch()
    short = _tracker(watch, "C1:00:00:00:00:01", 0.0, 3)
    long = _tracker(watch, "C1:00:00:00:00:02", 0.0, 12)
    assert watch.flag(short, now=180).level == "ok"
    flag = watch.flag(long, now=720)
    assert flag.level == "watch" and "12 min" in flag.text


def test_a_break_restarts_the_clock():
    watch = bt.Watch()
    device = _tracker(watch, "C1:00:00:00:00:03", 0.0, 8)
    _tracker(watch, "C1:00:00:00:00:03", 8 * 60 + 300, 6)       # back after 5 minutes away
    assert watch.flag(device, now=8 * 60 + 300 + 360).level == "ok"


def test_a_tracker_with_its_owner_is_never_flagged():
    watch = bt.Watch()
    device = _tracker(watch, "C1:00:00:00:00:04", 0.0, 30, separated=False)
    device.places = [("home", "Wi-Fi Home", 0, 1), ("work", "Wi-Fi Work", 2, 3)]
    flag = watch.flag(device, now=1800)
    assert flag.level == "ok" and flag.text == "with owner"


def test_a_tracker_heard_on_two_networks_is_an_alert():
    watch = bt.Watch()
    device = _tracker(watch, "C1:00:00:00:00:05", 0.0, 2)
    device.places = [("k1", "Wi-Fi Home", 0, 1), ("k2", "network via 10.0.0.1", 2, 3)]
    flag = watch.flag(device, now=120)
    assert flag.level == "alert" and "2 places" in flag.text
    assert "Wi-Fi Home" in flag.why and "10.0.0.1" in flag.why
    assert watch.ordered(now=120)[0] is device                 # flagged trackers first


def test_non_trackers_carry_no_flag():
    watch = bt.Watch()
    watch.add(adv(name="WH-1000XM5"), now=0)
    assert watch.flag(watch.devices["C0:FF:EE:00:00:01"], now=0).level == ""


def test_history_sparkline_scales_to_the_device():
    steady = bt.sparkline_cells([-70, -70, -71, -70, None, -70])
    assert [glyph for glyph, _ in steady][4] == "·"
    assert len({glyph for glyph, value in steady if value is not None}) <= 2   # flat stays flat
    walking = bt.sparkline_cells([-90, -85, -80, -75, -70, -65, -60, -55])
    assert walking[0][0] == "▁" and walking[-1][0] == "█"


def test_export_rows():
    watch = bt.Watch()
    watch.add(adv(name="Kitchen Speaker", manufacturer={APPLE: b"\x09\x01\x00"}), now=time.time())
    columns, rows = watch.export()
    assert columns[:4] == ["address", "name", "device", "maker"]
    assert rows[0][1] == "Kitchen Speaker" and rows[0][3] == "Apple" and "0x004C" in rows[0][10]


# ============================================================== places
def test_places_from_the_network():
    home = bt.place_from("192.168.1.1", "aa:bb:cc:00:00:01", "HomeNet")
    again = bt.place_from("192.168.1.1", "aa:bb:cc:00:00:01", "HomeNet")
    other = bt.place_from("192.168.1.1", "aa:bb:cc:99:99:99", "")    # same IP, another router
    assert home == again and home.label == "Wi-Fi HomeNet"
    assert other.key != home.key and other.label == "network via 192.168.1.1"
    assert bt.place_from().key == "offline"


def test_the_store_remembers_trackers_per_place(tmp_path):
    from netzilla.cache import TRACKER_RETENTION, Store

    store = Store(tmp_path / "c.sqlite3")
    now = time.time()
    store.tracker_seen("C1:00", "home", "Wi-Fi Home", "AirTag", ts=now - 100)
    store.tracker_seen("C1:00", "home", "Wi-Fi Home", "AirTag", ts=now - 50)
    store.tracker_seen("C1:00", "work", "Wi-Fi Work", "AirTag", ts=now - 10)
    store.tracker_seen("OLD", "home", "Wi-Fi Home", "Tile", ts=now - TRACKER_RETENTION - 10)
    places = store.tracker_places("C1:00")
    assert [p[0] for p in places] == ["work", "home"] and places[1][4] == 2
    logged = store.trackers_logged()
    assert [e["ident"] for e in logged] == ["C1:00"]        # the old one aged out
    assert logged[0]["labels"] == ["Wi-Fi Work", "Wi-Fi Home"]


# ======================================================== errors, tools
class _Reason:
    def __init__(self, name):
        self.name = name


class _NotAvailable(Exception):
    def __init__(self, msg, reason):
        super().__init__(msg)
        self.reason = _Reason(reason)


@pytest.mark.parametrize("exc, title", [
    (_NotAvailable("No Bluetooth adapters found.", "NO_BLUETOOTH"), "No Bluetooth adapter"),
    (_NotAvailable("No powered Bluetooth adapters found.", "POWERED_OFF"), "Bluetooth is off"),
    (Exception("[org.bluez.Error.NotReady] Resource Not Ready"), "Bluetooth is off"),
    (Exception("[org.freedesktop.DBus.Error.ServiceUnknown] The name org.bluez was not "
               "provided by any .service files"), "Bluetooth service not running"),
    (ImportError("No module named 'bleak'"), "Bluetooth library missing"),
    (FileNotFoundError("/run/dbus/system_bus_socket"), "Bluetooth service unreachable"),
    (RuntimeError("something odd"), "Bluetooth scan failed"),
])
def test_errors_are_explained(exc, title):
    problem = bt.explain(exc)
    assert problem.title == title and problem.message


def test_scanner_without_bleak_says_so(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "bleak", None)
    scanner = bt.Scanner(lambda advert: None)
    with pytest.raises(bt.BluetoothUnavailable) as caught:
        asyncio.run(scanner.start())
    assert caught.value.title == "Bluetooth library missing"


def test_scanner_drives_bleak_and_converts_broadcasts(monkeypatch):
    import sys
    import types

    seen, calls = [], {}

    class FakeBleakScanner:
        backend_id = types.SimpleNamespace(value="bluez_dbus")

        def __init__(self, callback, scanning_mode="active", *, bluez=None):
            calls.update(mode=scanning_mode, bluez=bluez)
            self.callback = callback

        async def start(self):
            device = types.SimpleNamespace(address="AA:BB:CC:DD:EE:01", name=None)
            data = types.SimpleNamespace(local_name="Tag", manufacturer_data={}, service_data={},
                                         service_uuids=[], tx_power=None, rssi=-70,
                                         platform_data=None)
            self.callback(device, data)

        async def stop(self):
            calls["stopped"] = True

    monkeypatch.setitem(sys.modules, "bleak", types.SimpleNamespace(BleakScanner=FakeBleakScanner))
    scanner = bt.Scanner(seen.append, adapter="hci1")

    async def go():
        await scanner.start()
        await scanner.stop()
    asyncio.run(go())
    assert calls["mode"] == "active" and calls["stopped"]
    assert calls["bluez"]["filters"] == {"Transport": "auto", "DuplicateData": True}
    assert calls["bluez"]["adapter"] == "hci1" and scanner.backend == "BlueZ (hci1)"
    assert seen[0].name == "Tag" and seen[0].rssi == -70


def test_bluetoothctl_and_rfkill_parsing():
    show = ("Controller 00:1A:7D:DA:71:13 (public)\n\tName: laptop\n\tAlias: laptop\n"
            "\tPowered: no\n\tDiscovering: no\n\tRoles: central\n\tRoles: peripheral\n")
    info = bt.parse_bluetoothctl_show(show)
    assert info == {"address": "00:1A:7D:DA:71:13", "name": "laptop", "alias": "laptop",
                    "powered": False, "discovering": False, "roles": ["central", "peripheral"]}
    assert bt.parse_bluetoothctl_show("No default controller available\n") == {}
    rfkill = ("0: phy0: Wireless LAN\n\tSoft blocked: no\n\tHard blocked: no\n"
              "1: hci0: Bluetooth\n\tSoft blocked: yes\n\tHard blocked: no\n")
    assert bt.parse_rfkill(rfkill) == [{"name": "hci0", "type": "Bluetooth", "soft": True,
                                        "hard": False}]


def test_wifi_down_is_explained(monkeypatch):
    from netzilla.local import runner, wifi

    async def fake_run(argv, timeout=30.0, ok_returncodes=(0,), stdin_text=None):
        return runner.CommandResult(False, "", "command failed: Network is down (-100)")

    monkeypatch.setattr(wifi, "have", lambda tool: tool == "iw")
    monkeypatch.setattr(wifi, "run", fake_run)
    aps, backend, error = asyncio.run(wifi.scan("wlp2s0", prefer="auto"))
    assert not aps and backend == "iw"
    assert "wlp2s0 is down" in error and "nmcli radio wifi on" in error


# ============================================================ the views
SCENE = [
    adv(address="6B:2E:41:9C:07:12", rssi=-47,
        manufacturer={APPLE: bytes([0x07, 0x19, 0x01, 0x14, 0x20] + [0] * 22)}),
    adv(address="F4:3C:91:0A:52:6E", rssi=-63, name="Forerunner 265",
        manufacturer={0x0087: b"\x01"}),
    adv(address="C1:7A:22:E0:14:8B", rssi=-71, address_type="random",
        manufacturer={APPLE: bytes([0x12, 0x19, 0x10] + [7] * 24)}),
    adv(address="E2:91:0C:55:3D:77", rssi=-78, service_data={U("feed"): b"\x02"}),
]


class FakeScanner:
    """Hears SCENE once on start, and again on every `again()`."""
    instances: list = []

    def __init__(self, on_advert):
        self.on_advert = on_advert
        self.backend = "BlueZ (hci0)"
        self.stopped = False
        FakeScanner.instances.append(self)

    async def start(self):
        self.again()

    def again(self):
        for advert in SCENE:
            self.on_advert(advert)

    async def stop(self):
        self.stopped = True


class BrokenScanner(FakeScanner):
    async def start(self):
        raise bt.BluetoothUnavailable("Bluetooth is off", "turn it on")


def _run_view(tmp_path, action, ticks=2, scanner=FakeScanner, prepare=None, then=None):
    from netzilla import clipboard

    async def place(iface=""):
        return bt.place_from("192.168.1.1", "aa:bb:cc:00:00:01", "HomeNet")

    async def go():
        app = _app(tmp_path, start_tab="wifi")
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            pane = app._active_pane()
            pane.BT_SCANNER = scanner
            pane.BT_EVERY = 0.05
            pane.MAX_TICKS = ticks
            original = bt.current_place
            bt.current_place = place
            try:
                if prepare:
                    prepare(app, pane)
                pane.dispatch(action)
                await app.workers.wait_for_complete()
                await pilot.pause()
                if then:
                    await then(app, pane, pilot)
                return pane, clipboard.pane_text(pane)
            finally:
                bt.current_place = original
    return asyncio.run(go())


def test_bluetooth_lists_every_device_with_what_was_asked_for(tmp_path):
    FakeScanner.instances.clear()
    pane, text = _run_view(tmp_path, "bluetooth")
    assert "BLUETOOTH" in text and "4 devices nearby" in text
    assert "BLUETOOTH DEVICES, LIVE" in text
    for column in ("NAME", "DEVICE", "VENDOR", "MAC", "DBM", "HISTORY", "DISTANCE",
                   "FIRST SEEN", "LAST SEEN", "FLAG"):
        assert column in text, column
    assert "Forerunner 265" in text and "Garmin" in text           # name, maker
    assert "AirPods Pro (2nd gen)" in text and "AirTag" in text     # best guesses
    assert "Tile" in text and "< 1 m" in text                       # tracker, distance
    assert "SIGNAL — EARBUDS" in text                               # graph of the nearest
    assert "NEARBY, BY KIND" in text and "TRACKERS" in text
    assert FakeScanner.instances[-1].stopped                       # the radio is let go
    assert "4 devices heard" in text


def test_bluetooth_graphs_the_device_in_the_box(tmp_path):
    pane, text = _run_view(tmp_path, "bluetooth",
                           prepare=lambda app, pane: pane.set_field("target", "forerunner"))
    assert "SIGNAL — FORERUNNER 265" in text


def test_bt_trackers_flags_one_heard_on_two_networks(tmp_path):
    def prepare(app, pane):
        app.services.store.tracker_seen("C1:7A:22:E0:14:8B", "work", "network via 10.20.0.1",
                                        "AirTag", ts=time.time() - 3600)

    logged = []

    async def then(app, pane, pilot):
        logged.extend(app.services.store.trackers_logged())

    pane, text = _run_view(tmp_path, "bttrackers", prepare=prepare, then=then)
    assert "heard on more than one network you were on" in text
    assert "⚠ 2 places" in text and "network via 10.20.0.1" in text
    assert "TRACKERS REMEMBERED (7 DAYS)" in text and "IF A TRACKER IS FOLLOWING YOU" in text
    assert "Forerunner" not in text.split("TRACKERS NEARBY")[1].split("TRACKERS REMEMBERED")[0]
    assert {e["ident"] for e in logged} == {"C1:7A:22:E0:14:8B", "E2:91:0C:55:3D:77"}


def test_bluetooth_explains_why_it_cannot_start(tmp_path):
    pane, text = _run_view(tmp_path, "bluetooth", scanner=BrokenScanner)
    assert "BLUETOOTH IS OFF" in text and "turn it on" in text
    assert "systemctl enable --now bluetooth" in text


def test_another_button_stops_the_scan(tmp_path):
    FakeScanner.instances.clear()

    async def then(app, pane, pilot):
        pane.MAX_TICKS = None
        pane.dispatch("bluetooth")
        await pilot.pause(0.3)
        assert not FakeScanner.instances[-1].stopped
        pane.dispatch("channels")
        await pilot.pause(0.5)

    _run_view(tmp_path, "bluetooth", then=then)
    assert FakeScanner.instances[-1].stopped


def test_switching_views_lets_go_of_the_radio_first(tmp_path):
    events = []

    class Recording(FakeScanner):
        async def start(self):
            events.append("start")
            await super().start()

        async def stop(self):
            await asyncio.sleep(0.05)          # BlueZ takes a moment
            events.append("stop")
            await super().stop()

    async def then(app, pane, pilot):
        events.clear()
        pane.MAX_TICKS = None
        pane.dispatch("bluetooth")
        await pilot.pause(0.3)
        pane.dispatch("bttrackers")
        await pilot.pause(0.5)
        pane.dispatch("channels")
        await pilot.pause(0.5)

    _run_view(tmp_path, "bluetooth", scanner=Recording, then=then)
    assert events == ["start", "stop", "start", "stop"]


def test_export_includes_bluetooth(tmp_path):
    async def then(app, pane, pilot):
        pane.EXPORT_BASE = tmp_path / "exports"
        pane.dispatch("export")
        await app.workers.wait_for_complete()

    pane, text = _run_view(tmp_path, "bluetooth", then=then)
    assert "bluetooth.csv" in text
    files = list((tmp_path / "exports").rglob("bluetooth.csv"))
    assert files and "Forerunner 265" in files[0].read_text()


def test_tool_check_reports_bluetooth(tmp_path, monkeypatch):
    from netzilla.local import wifi

    async def report():
        return [("Bluetooth adapter", "hci0 · powered OFF — bluetoothctl power on")], \
            "Bluetooth is switched off"

    async def no_interfaces():
        return []

    monkeypatch.setattr(bt, "tool_report", report)
    monkeypatch.setattr(wifi, "wireless_interfaces", no_interfaces)
    pane, text = _run_view(tmp_path, "tools")
    assert "not ready — Bluetooth is switched off" in text and "bluetoothctl power on" in text


def test_every_wifi_button_has_help():
    from netzilla.help import get_help
    from netzilla.screens.wifi import WifiPane

    for action in WifiPane.ACTIONS:
        assert get_help("WifiPane", action.key) is not None, action.key
    assert "REFRESH EVERY" in get_help("WifiPane", "bluetooth").note
