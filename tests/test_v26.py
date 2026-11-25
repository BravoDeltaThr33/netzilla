"""Tests for netzilla 2.6: systime, one-time authentication, STOP, held data.

The four things this release changes are all things that only show up when
real programs run, so these tests stand up fake ones — a `sudo` that keeps a
timestamp file the way the real one keeps its session, and a `tshark` that
streams wall-clock packet lines until it is killed — and drive the actual
CapturePane methods against them.

The pane is used with its widget layer replaced (see Harness below) rather
than inside a full application, because what is being tested is the capture
loop: that STOP stops it, that the packets survive, that nothing is left
running. tests/test_smoke.py is what proves the pane mounts and draws.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

from netzilla import __version__
from netzilla.help import get_help
from netzilla.local import capture
from netzilla.local.elevation import SESSION
from netzilla.screens.capture import CapturePane
from netzilla.themes import get_palette
from netzilla.validators import ValidationError

SAMPLE = """Capturing on 'eth0'
    1 14:03:22.918472 192.168.1.5 → 142.250.191.78 TCP 74 51234 → 443 [SYN] Seq=0
    2 14:03:22.951008 142.250.191.78 → 192.168.1.5 TCP 74 443 → 51234 [SYN, ACK]
    3 14:03:23.412990 192.168.1.5 → 10.0.0.53 DNS 86 Standard query A example.com
    4 14:03:24.000001 10.0.0.53 → 192.168.1.5 DNS 140 Standard query response
    5 0.000000000 8.8.8.8 -> 192.168.1.5 ICMP 98 Echo (ping) reply
12 packets captured
"""

FAKE_TSHARK = r"""#!/bin/bash
# Streams tshark-shaped lines with real wall-clock timestamps until killed,
# and records the arguments it was given so the test can check for -t a.
printf '%s\n' "$@" > "$(dirname "$0")/.argv"
echo "Capturing on 'eth0'"
i=0
while true; do
  i=$((i+1))
  printf "%5d %s 192.168.1.42 → 142.250.191.78 TCP 74 51234 → 443 [ACK] Seq=%d\n" \
    "$i" "$(date +%H:%M:%S.%6N)" "$i"
  sleep 0.05
done
"""

FAKE_SUDO = """#!/bin/bash
# -S -v takes one password and writes a timestamp; -n succeeds only while
# that timestamp exists; -k removes it. Exactly sudo's session behaviour.
STAMP="$(dirname "$0")/.stamp"
noninteractive=0; readpw=0; kill=0
for a in "$@"; do
  case "$a" in -n) noninteractive=1;; -S) readpw=1;; -k) kill=1;; esac
done
[ "$kill" = 1 ] && { rm -f "$STAMP"; exit 0; }
if [ "$readpw" = 1 ]; then
  read -r pw
  [ "$pw" = "correct-horse" ] && { touch "$STAMP"; exit 0; }
  echo "sudo: Sorry, try again." >&2; exit 1
fi
[ "$noninteractive" = 1 ] && {
  [ -f "$STAMP" ] || { echo "sudo: a password is required" >&2; exit 1; }
}
exit 0
"""


def _install(tmp_path: Path, name: str, body: str, monkeypatch=None) -> Path:
    """Put a fake tool on PATH for one test.

    monkeypatch puts PATH back afterwards. Without it the directory stays on
    PATH after the test's tmp_path has been deleted, which leaves every later
    test searching a directory that is no longer there — the kind of thing
    that makes one suite pass and the same suite in another checkout fail.
    """
    path = tmp_path / name
    path.write_text(body)
    path.chmod(0o755)
    extended = f"{tmp_path}{os.pathsep}{os.environ['PATH']}"
    if monkeypatch is not None:
        monkeypatch.setenv("PATH", extended)
    else:
        os.environ["PATH"] = extended
    return path


def _running_tsharks() -> list[str]:
    """Any fake tshark still alive — an orphaned capture holds the interface."""
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            command = (entry / "cmdline").read_bytes().decode(errors="replace")
        except OSError:
            continue
        if "tshark" in command and "defunct" not in command:
            found.append(command.replace("\0", " ").strip())
    return found


class _RecordingStatic:
    """Stands in for textual's Static in the live view. Newer Textual needs
    a running app before Static.update() will do anything, and these tests
    drive the pane without one; what matters here is what gets drawn."""

    def __init__(self, renderable=None, **_kwargs) -> None:
        self.renderable = renderable
        self.updates = 0

    def update(self, renderable=None, **_kwargs) -> None:
        self.renderable = renderable
        self.updates += 1


@pytest.fixture(autouse=True)
def _static_without_an_app(monkeypatch):
    import netzilla.screens.capture as module

    monkeypatch.setattr(module, "Static", _RecordingStatic)


class Harness(CapturePane):
    """The real pane with the widget layer replaced by an event list.

    (Named `events`, not `log`: newer Textual makes `log` a read-only
    property on every widget.)
    """

    def __init__(self, fields: dict, password: str | None = None) -> None:
        super().__init__()
        self._fields = fields
        self._password = password
        self.prompts = 0
        self.events: list[tuple] = []
        self.widgets: list[object] = []
        harness = self

        class _App:
            async def push_screen_wait(self, _screen):
                harness.prompts += 1
                return harness._password

        self._fake_app = _App()

    @property
    def app(self):
        return self._fake_app

    @property
    def palette(self):
        return get_palette("amber")

    def field(self, key: str) -> str:
        return self._fields.get(key, "")

    async def begin(self, message: str = "…") -> None:
        self.events.append(("begin", message))

    def progress(self, message: str) -> None:
        self.events.append(("progress", message))

    async def finish(self, message: str = "") -> None:
        self.events.append(("finish", message))

    async def push(self, renderable) -> None:
        self.events.append(("push", renderable))

    async def push_widget(self, widget) -> None:
        self.widgets.append(widget)
        self.events.append(("widget", widget))

    async def push_error(self, title, message) -> None:
        self.events.append(("error", title))

    async def push_warning(self, title, message) -> None:
        self.events.append(("warning", title))

    def run_worker(self, work=None, *args, **kwargs):
        # Nothing runs the coroutine here; close it so Python does not warn
        # about it never being awaited.
        if hasattr(work, "close"):
            work.close()
        return None

    def kinds(self) -> list[str]:
        return [entry[0] for entry in self.events]


class LiveHarness(Harness):
    """Harness with the permission check answered, for the capture tests.

    The authentication tests use Harness itself, because there the real
    _permission() — and which route it picks — is the thing being tested.
    """

    async def _permission(self):
        return []


# ------------------------------------------------------------------ version
def test_version_is_2_6():
    """The features below arrived in 2.6; later releases keep them."""
    assert tuple(int(part) for part in __version__.split(".")[:2]) >= (2, 6), (
        __version__
    )


# ------------------------------------------------- systime and the parser
def test_absolute_timestamps_are_parsed_into_a_clock():
    packets = capture.parse_packets(SAMPLE)
    assert len(packets) == 5
    assert packets[0]["clock"] == "14:03:22.918"
    assert packets[3]["clock"] == "14:03:24.000"


def test_relative_timestamps_still_parse():
    """A build that ignores -t a must not break the table."""
    packets = capture.parse_packets(SAMPLE)
    assert packets[4]["clock"] == ""
    assert packets[4]["time"] == 0.0


def test_tshark_is_asked_for_wall_clock_time():
    assert capture.ABSOLUTE_TIME == ["-t", "a"]
    argv = capture.live_argv("eth0")
    assert argv[:4] == ["tshark", "-t", "a", "-i"], argv


def test_ports_are_pulled_out_of_the_info_column():
    packets = capture.parse_packets(SAMPLE)
    assert (packets[0]["sport"], packets[0]["dport"]) == (51234, 443)
    assert packets[2]["sport"] is None        # DNS line has no port pair


def test_the_packet_table_has_a_systime_column():
    assert capture.PACKET_COLUMNS[1] == "Systime"
    rows = capture.packet_rows(capture.parse_packets(SAMPLE)[:4])
    assert len(rows[0]) == len(capture.PACKET_COLUMNS)
    assert rows[0][1] == "14:03:22.918"
    assert [row[1] for row in rows] == [
        "14:03:22.918", "14:03:22.951", "14:03:23.412", "14:03:24.000",
    ]


def test_the_offset_column_is_relative_to_the_earliest_row_shown():
    """The live view lists packets newest first; Δt must still make sense."""
    packets = capture.parse_packets(SAMPLE)[:4]
    forwards = [row[2] for row in capture.packet_rows(packets)]
    backwards = [row[2] for row in capture.packet_rows(list(reversed(packets)))]
    assert forwards == ["+0.000", "+0.033", "+0.495", "+1.082"]
    assert backwards == list(reversed(forwards))


def test_arrival_is_stamped_only_when_there_is_no_clock():
    packets = capture.parse_packets(SAMPLE)
    capture.stamp_arrival(packets)
    assert packets[0]["clock"] == "14:03:22.918"   # untouched
    assert packets[4]["clock"]                      # filled in


def test_the_summary_reports_the_first_and_last_packet_times():
    summary = dict(capture.capture_summary(capture.parse_packets(SAMPLE), "eth0"))
    assert summary["First packet"] == "14:03:22.918"
    assert summary["Last packet"] == "14:03:24.000"
    # The one relative-time line must not stretch the span to 14 hours.
    assert float(summary["Time span"].rstrip("s")) < 2


# --------------------------------------------------- filtering held packets
@pytest.mark.parametrize(
    "expression,expected",
    [
        ("", [1, 2, 3, 4, 5]),
        ("dns", [3, 4]),
        ("tcp", [1, 2]),
        ("ip.addr == 10.0.0.53", [3, 4]),
        ("ip.src == 192.168.1.5", [1, 3]),
        ("ip.addr == 192.168.1.0/24", [1, 2, 3, 4, 5]),
        ("ip.addr != 10.0.0.53", [1, 2, 5]),
        ("tcp.port == 443", [1, 2]),
        ("srcport == 443", [2]),
        ("tcp.port == 443 and ip.src == 192.168.1.5", [1]),
        ("dns or icmp", [3, 4, 5]),
        ("not dns", [1, 2, 5]),
        ("frame.len > 100", [4]),
        ('frame contains "example.com"', [3]),
        ("example.com", [3]),
        ("protocol == ICMP", [5]),
    ],
)
def test_held_packets_can_be_filtered(expression, expected):
    packets = capture.parse_packets(SAMPLE)
    kept, _notes = capture.filter_packets(packets, expression)
    assert [p["no"] for p in kept] == expected


def test_a_filter_that_cannot_be_applied_says_so_rather_than_matching_nothing():
    """Silently returning zero packets would look like 'there were none'."""
    packets = capture.parse_packets(SAMPLE)
    kept, notes = capture.filter_packets(packets, "tcp.analysis.flags")
    assert len(kept) == len(packets)
    assert any("could not be applied" in note.lower() for note in notes)


def test_a_mixed_filter_applies_the_half_it_understands():
    packets = capture.parse_packets(SAMPLE)
    kept, notes = capture.filter_packets(packets, "dns and tls.handshake.type == 1")
    assert [p["no"] for p in kept] == [3, 4]
    assert any("dns" in note for note in notes)
    assert any("tls.handshake.type" in note for note in notes)


def test_a_hostname_is_searched_for_rather_than_read_as_a_field():
    """example.com and tcp.analysis.flags are the same shape; only one is a
    field name, and getting that wrong makes hostname searches fail."""
    assert capture._looks_like_a_field("tcp.analysis.flags")
    assert capture._looks_like_a_field("tls.handshake.type")
    assert not capture._looks_like_a_field("example.com")
    assert not capture._looks_like_a_field("www.google.com")


# ------------------------------------------- a line pasted out of the help
@pytest.mark.parametrize(
    "pasted",
    ["TCPDUMP: PORT 80", "PROTOCOL: UDP", "By protocol: dns",
     "By IP address: ip.addr == 192.168.1.1"],
)
def test_a_pasted_help_line_is_explained_not_handed_to_tshark(pasted):
    problem = capture.check_filter(pasted)
    assert problem and "FILTER HELP" in problem


@pytest.mark.parametrize(
    "good",
    ["", "dns", "ip.addr == 192.168.1.1", "ipv6.addr == ::1", "tcp.port == 80",
     'frame contains "password"', "not arp and not icmp", "http or tls"],
)
def test_real_filters_are_left_alone(good):
    assert capture.check_filter(good) == ""


# --------------------------------------------------------- the live capture
@pytest.mark.parametrize("stop_by", ["button", "cancel"])
def test_stopping_a_live_capture_keeps_every_packet(tmp_path, stop_by, monkeypatch):
    """The whole point of STOP LIVE: end the capture, keep the traffic.

    Both ways of ending one are checked, because pressing any other button
    cancels the worker and the packets have to survive that too.
    """
    _install(tmp_path, "tshark", FAKE_TSHARK, monkeypatch)

    async def go():
        pane = LiveHarness({"iface": "eth0", "filter": ""})
        task = asyncio.ensure_future(pane._live())
        await asyncio.sleep(1.2)
        assert pane._live_running
        # banner, packets-per-second graph (4.0), summary, packet table
        assert len(pane.widgets) == 4, "the live view owns the results area"

        if stop_by == "button":
            pane.dispatch("stop")             # exactly what the button does
            assert pane._stop_live, "STOP must not start a worker"
            await asyncio.wait_for(task, timeout=10)
        else:
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=10)
            except asyncio.CancelledError:
                pass

        assert pane._held, "the captured packets were thrown away"
        assert all(p["clock"] for p in pane._held), "packets lost their systime"
        assert pane._held_source == "eth0 (live)"
        assert not pane._live_running and not pane._stop_live

        argv = (tmp_path / ".argv").read_text().split()
        assert "-t" in argv and "a" in argv, argv

        await asyncio.sleep(0.4)
        assert not _running_tsharks(), "a capture was left holding the interface"
        return pane

    pane = asyncio.run(go())
    # And what was kept can be narrowed down without capturing again.
    kept, _notes = capture.filter_packets(pane._held, "tcp.port == 443")
    assert len(kept) == len(pane._held)
    kept, _notes = capture.filter_packets(pane._held, "dns")
    assert kept == [] and pane._held, "a miss must not empty the buffer"


def test_a_new_live_capture_replaces_the_held_packets(tmp_path, monkeypatch):
    _install(tmp_path, "tshark", FAKE_TSHARK, monkeypatch)

    async def go():
        pane = LiveHarness({"iface": "eth0", "filter": ""})
        pane._held = [{"no": 999, "clock": "old"}]
        task = asyncio.ensure_future(pane._live())
        await asyncio.sleep(0.8)
        pane.dispatch("stop")
        await asyncio.wait_for(task, timeout=10)
        assert pane._held and pane._held[0]["src"] == "192.168.1.42"
        assert all(p["no"] != 999 for p in pane._held)

    asyncio.run(go())


def test_stop_with_nothing_running_does_not_latch():
    """Otherwise the flag would be waiting to kill the next capture."""
    pane = Harness({})
    pane.dispatch("stop")
    assert not pane._stop_live


def test_a_pasted_filter_is_rejected_before_anything_is_captured():
    async def go():
        pane = LiveHarness({"iface": "eth0", "filter": "TCPDUMP: PORT 80"})
        with pytest.raises(ValidationError):
            await pane._live()
        assert not pane._live_running

    asyncio.run(go())


# ------------------------------------------------------------- FILTER HELD
def test_filter_held_with_nothing_held_says_how_to_get_some():
    async def go():
        pane = LiveHarness({"filter": "dns"})
        await pane._held_data()
        assert "warning" in pane.kinds()

    asyncio.run(go())


def test_a_bounded_capture_also_leaves_its_packets_behind():
    class Result:
        ok, output, error, missing_tool = True, SAMPLE, "", None

    async def go():
        pane = LiveHarness({"filter": ""})
        await pane._render_capture(Result(), "eth0 (live)", "")
        assert len(pane._held) == 5
        assert all(p["clock"] for p in pane._held)

        pane._fields["filter"] = "dns"
        pane.events.clear()
        await pane._held_data()
        assert "warning" not in pane.kinds()
        assert pane.kinds().count("push") >= 5

        pane._fields["filter"] = "arp"
        pane.events.clear()
        await pane._held_data()
        assert "warning" in pane.kinds()
        assert len(pane._held) == 5, "a miss must not empty the buffer"

    asyncio.run(go())


# ------------------------------------------------- authenticating just once
def test_the_pkexec_route_offers_a_one_time_unlock_instead(tmp_path, monkeypatch):
    """The reported problem: every capture asked for the password again.

    pkexec prompts per command, so when that is the only route left netzilla
    trades it for one sudo session — asked for once, used by everything after.
    """
    _install(tmp_path, "sudo", FAKE_SUDO, monkeypatch)
    _install(tmp_path, "pkexec", "#!/bin/bash\nexec \"$@\"\n", monkeypatch)
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(capture, "is_root", lambda: False)
    monkeypatch.setattr(capture, "dumpcap_path", lambda: "")

    async def no_caps():
        return "", "not installed"

    monkeypatch.setattr(capture, "dumpcap_caps", no_caps)

    async def go():
        await SESSION.lock()
        capture.invalidate_permissions()
        prefix, _rows = await capture.permission_report(fresh=True)
        assert prefix == ["pkexec"], prefix
        assert capture.can_unlock()

        pane = Harness({"iface": "eth0"}, password="correct-horse")
        assert await pane._permission() == ["sudo", "-n"]
        assert pane.prompts == 1
        assert SESSION.active

        # Every later capture, on this pane and on a new one (which is what
        # switching tabs and coming back gives you), asks nothing at all.
        pane.prompts = 0
        for _ in range(4):
            assert await pane._permission() == ["sudo", "-n"]
        assert pane.prompts == 0

        elsewhere = Harness({"iface": "eth0"}, password="correct-horse")
        assert await elsewhere._permission() == ["sudo", "-n"]
        assert elsewhere.prompts == 0
        assert not capture.can_unlock()

        await SESSION.lock()

    asyncio.run(go())


def test_cancelling_the_unlock_falls_back_rather_than_failing(tmp_path, monkeypatch):
    _install(tmp_path, "sudo", FAKE_SUDO, monkeypatch)
    _install(tmp_path, "pkexec", "#!/bin/bash\nexec \"$@\"\n", monkeypatch)
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(capture, "is_root", lambda: False)
    monkeypatch.setattr(capture, "dumpcap_path", lambda: "")

    async def no_caps():
        return "", "not installed"

    monkeypatch.setattr(capture, "dumpcap_caps", no_caps)

    async def go():
        await SESSION.lock()
        capture.invalidate_permissions()
        cancelled = Harness({"iface": "eth0"}, password=None)
        assert await cancelled._permission() == ["pkexec"]
        assert "error" not in cancelled.kinds()
        assert cancelled._auth_note == ""

        wrong = Harness({"iface": "eth0"}, password="nope")
        assert await wrong._permission() == ["pkexec"]
        assert "not accepted" in wrong._auth_note
        await SESSION.lock()

    asyncio.run(go())


# ----------------------------------------------------------------- wiring
def test_the_new_buttons_exist_and_are_explained():
    keys = [action.key for action in CapturePane.ACTIONS]
    assert "stop" in keys and "held" in keys
    for key in keys:
        assert get_help("CapturePane", key), f"no help card for {key}"


def test_the_buttons_still_fit_on_two_rows():
    rows = CapturePane._action_rows()
    assert len(rows) == 2
    assert sum(len(row) for row in rows) == len(CapturePane.ACTIONS)
    assert all(len(row) <= CapturePane.MAX_ACTIONS_PER_ROW for row in rows)


def test_the_held_buffer_is_bounded():
    """A live capture on a busy link must not grow without limit."""
    assert 0 < CapturePane.HOLD_LIMIT <= 50_000


@pytest.mark.skipif(sys.platform != "linux", reason="reads /proc")
def test_the_process_check_this_file_relies_on_works():
    assert isinstance(_running_tsharks(), list)


# ------------------------------------------- 2.6.1: finding dumpcap at all
def test_dumpcap_is_found_even_when_you_may_not_run_it(tmp_path, monkeypatch):
    """The reported bug: TOOL CHECK said "dumpcap not installed" for a dumpcap
    that was plainly there.

    shutil.which() answers "can I execute this", not "does this exist". The
    stock Debian/Ubuntu/Mint arrangement is root:wireshark 0750, so for anyone
    outside that group dumpcap has no execute bit, PATH lookup skips it, and
    netzilla reported it missing — sending people to install what they had.
    """
    (tmp_path / "dumpcap").write_text("#!/bin/sh\n")
    (tmp_path / "dumpcap").chmod(0o750)
    monkeypatch.setattr(capture, "_ALSO_LOOK_IN", (str(tmp_path),))
    monkeypatch.setenv("PATH", "/nonexistent")

    assert capture.dumpcap_path() == str(tmp_path / "dumpcap")
    assert "not installed" not in capture.dumpcap_details()
    assert str(tmp_path) in capture.dumpcap_details()


def test_a_tool_off_this_users_path_is_still_found(tmp_path, monkeypatch):
    """The other half: /usr/sbin is not on every user's PATH."""
    (tmp_path / "getcap").write_text("#!/bin/sh\n")
    (tmp_path / "getcap").chmod(0o755)
    monkeypatch.setattr(capture, "_ALSO_LOOK_IN", (str(tmp_path),))
    monkeypatch.setenv("PATH", "/nonexistent")
    assert capture.find_tool("getcap") == str(tmp_path / "getcap")


def test_a_genuinely_missing_tool_is_still_reported_missing(monkeypatch):
    """The fix must not turn "missing" into a false positive."""
    monkeypatch.setattr(capture, "_ALSO_LOOK_IN", ())
    monkeypatch.setenv("PATH", "/nonexistent")
    assert capture.dumpcap_path() == ""
    assert capture.dumpcap_details() == "not installed"
    assert capture.find_tool("definitely-not-a-real-tool") == ""


# --------------------------------------------------- 2.6.1: going faster
def test_the_output_reader_splits_chunks_rather_than_reading_lines(tmp_path):
    """A readline() per packet costs a Task and a timer per packet, which made
    the event loop — not the capture — the limit on a busy link."""
    from netzilla.local.runner import LiveProcess

    script = tmp_path / "spew"
    script.write_text(
        "#!/bin/bash\n"
        "for i in $(seq 1 2000); do echo \"line $i\"; done\n"
    )
    script.chmod(0o755)

    async def go():
        process = LiveProcess([str(script)])
        assert not await process.start()
        seen = []
        async for line in process.lines(idle=2.0):
            if line is not None:
                seen.append(line)
        await process.stop()
        return seen

    seen = asyncio.run(go())
    assert len(seen) == 2000, len(seen)
    assert seen[0] == "line 1" and seen[-1] == "line 2000"


def test_a_last_line_without_a_newline_is_not_swallowed(tmp_path):
    """Chunked reading has to remember the tail; losing it would lose a packet."""
    from netzilla.local.runner import LiveProcess

    script = tmp_path / "partial"
    script.write_text("#!/bin/bash\nprintf 'one\\ntwo\\nthree no newline'\n")
    script.chmod(0o755)

    async def go():
        process = LiveProcess([str(script)])
        assert not await process.start()
        seen = [line async for line in process.lines(idle=2.0) if line is not None]
        await process.stop()
        return seen

    assert asyncio.run(go()) == ["one", "two", "three no newline"]


def test_the_rolling_buffer_has_a_real_ceiling():
    """Trimming in batches must still bound memory, not just delay the cost."""
    live = capture.LiveCapture("eth0", "", keep=100)
    assert live._trim_at > live.keep
    for number in range(5000):
        live.packets.append({"no": number})
        if len(live.packets) > live._trim_at:
            del live.packets[: len(live.packets) - live.keep]
        assert len(live.packets) <= live._trim_at
    assert live.packets[-1]["no"] == 4999, "the newest are the ones kept"
    assert len(live.packets) >= live.keep


def test_the_permission_check_is_cached_but_never_across_a_session_change():
    """It runs two subprocesses, and every capture button asks first.

    Caching it is only safe if unlocking or locking cannot be served a stale
    answer — so the cache key carries that state rather than relying on
    someone remembering to invalidate.
    """
    calls = []

    async def counted():
        calls.append(1)
        return "", "counted"

    import netzilla.local.capture as module

    real = module.dumpcap_caps
    module.dumpcap_caps = counted
    try:
        async def go():
            module.invalidate_permissions()
            await module.permission_report()
            first = len(calls)
            await module.permission_report()
            await module.permission_report()
            assert len(calls) == first, "repeat checks should be served warm"

            await module.permission_report(fresh=True)
            assert len(calls) == first + 1, "TOOL CHECK must not be served warm"

            module.invalidate_permissions()
            await module.permission_report()
            assert len(calls) == first + 2, "invalidation must be honoured"

        asyncio.run(go())
    finally:
        module.dumpcap_caps = real
        module.invalidate_permissions()


def test_the_cached_report_cannot_be_mutated_by_its_caller():
    """Handing out the cached lists themselves would let one panel's edits
    show up in the next one."""
    import netzilla.local.capture as module

    async def go():
        module.invalidate_permissions()
        _prefix, rows = await module.permission_report()
        rows.append(("injected", "nonsense"))
        _prefix2, rows2 = await module.permission_report()
        assert ("injected", "nonsense") not in rows2

    asyncio.run(go())
    module.invalidate_permissions()


def test_httpx_is_not_imported_just_to_start_up():
    """It is about half of netzilla's import time, and a session that only
    uses the local tabs never needs it."""
    import subprocess

    source = Path(capture.__file__).parents[2]
    result = subprocess.run(
        [sys.executable, "-c",
         "import sys, netzilla.services; "
         "print('httpx' in sys.modules)"],
        capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": f"{source}{os.pathsep}"
             + os.environ.get("PYTHONPATH", "")},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False", result.stdout


def test_deferring_httpx_did_not_break_the_client():
    """The import moved; the thing it imports still has to work."""
    from netzilla.config import Config
    from netzilla.services import Services

    async def go():
        services = Services(Config(), offline=False)
        client = await services.client()
        assert client is not None
        await services.aclose()

    asyncio.run(go())
