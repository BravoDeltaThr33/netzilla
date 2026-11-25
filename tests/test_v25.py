"""Tests for netzilla 2.5: unlocking sudo once per session, and live capture.

Both features talk to real programs, so these tests stand up fake ones: a
`sudo` that keeps a timestamp file exactly as the real one keeps its session,
and a `tshark` that streams packet lines until it is killed. That exercises
the actual subprocess paths — stdin, streaming, cancellation, process cleanup
— rather than mocking them away.
"""

from __future__ import annotations

import asyncio
import os
import stat
import sys

import pytest

from netzilla import __version__
from netzilla.help import get_help
from netzilla.local import capture, elevation
from netzilla.local.elevation import SudoSession
from netzilla.local.runner import LiveProcess, run
from netzilla.screens.capture import CapturePane

FAKE_SUDO = """#!/bin/bash
# Stands in for sudo: -S -v accepts one password and writes a timestamp,
# -n succeeds only while that timestamp exists, -k removes it.
STAMP="$(dirname "$0")/.stamp"
noninteractive=0; readpw=0; kill=0
for a in "$@"; do
  case "$a" in
    -n) noninteractive=1;; -S) readpw=1;; -k) kill=1;;
  esac
done
if [ "$kill" = 1 ]; then rm -f "$STAMP"; exit 0; fi
if [ "$readpw" = 1 ]; then
  read -r pw
  if [ "$pw" = "correct-horse" ]; then touch "$STAMP"; exit 0; fi
  echo "sudo: Sorry, try again." >&2; exit 1
fi
if [ "$noninteractive" = 1 ]; then
  [ -f "$STAMP" ] || { echo "sudo: a password is required" >&2; exit 1; }
fi
exit 0
"""

FAKE_TSHARK = """#!/bin/bash
echo "Capturing on 'eth0'"
i=0
while true; do
  i=$((i+1))
  printf "%5d 0.%06d 192.168.1.42 → 142.250.191.78 TCP 74 51234 → 443 [ACK]\\n" "$i" "$i"
  sleep 0.1
done
"""

QUIET_TSHARK = """#!/bin/bash
echo "Capturing on 'eth0'"
sleep 30
"""


@pytest.fixture(autouse=True)
def _restore_path():
    """_install() puts fake tools at the front of PATH; put it back after
    each test so a fake tshark cannot leak into the tests that follow."""
    saved = os.environ.get("PATH", "")
    yield
    os.environ["PATH"] = saved


def _install(tmp_path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    os.environ["PATH"] = f"{tmp_path}{os.pathsep}{os.environ['PATH']}"
    return str(path)


def _running(path: str) -> list[str]:
    """PIDs whose argv contains this exact program — not shells mentioning it."""
    found = []
    if not os.path.isdir("/proc"):
        return found
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                argv = handle.read().decode("utf-8", "replace").split("\0")
        except OSError:
            continue
        if path in argv:
            found.append(pid)
    return found


def test_version_is_2_5():
    """The features below arrived in 2.5; later releases keep them."""
    assert tuple(int(part) for part in __version__.split(".")[:2]) >= (2, 5), (
        __version__
    )


def test_new_buttons_exist_and_are_documented():
    keys = [a.key for a in CapturePane.ACTIONS]
    assert "live" in keys and "auth" in keys
    assert get_help("CapturePane", "live") is not None
    assert get_help("CapturePane", "auth") is not None


def test_buttons_are_split_across_rows_when_there_are_too_many():
    rows = CapturePane._action_rows()
    assert len(rows) == 2, "eleven buttons do not fit on one row"
    assert all(len(row) <= CapturePane.MAX_ACTIONS_PER_ROW for row in rows)
    # Nothing is lost or duplicated in the split.
    flat = [action.key for row in rows for action in row]
    assert flat == [action.key for action in CapturePane.ACTIONS]


def test_panes_with_few_buttons_keep_a_single_row():
    from netzilla.screens.subnet_calc import SubnetPane

    assert len(SubnetPane._action_rows()) == 1


# ------------------------------------------------------------ sudo session
def test_unlock_rejects_a_wrong_password_and_stays_locked(tmp_path):
    _install(tmp_path, "sudo", FAKE_SUDO)
    session = SudoSession()
    ok, why = asyncio.run(session.unlock("hunter2"))
    assert not ok
    assert "not accepted" in why
    assert not session.active
    assert session.prefix() == []


def test_unlock_then_every_later_command_runs_unprompted(tmp_path):
    _install(tmp_path, "sudo", FAKE_SUDO)
    session = SudoSession()

    async def go():
        ok, _why = await session.unlock("correct-horse")
        assert ok and session.active
        assert session.prefix() == ["sudo", "-n"]
        # The point of the feature: no password anywhere in this call.
        result = await run(["sudo", "-n", "true"], timeout=10)
        assert result.ok
        return result

    result = asyncio.run(go())
    assert "correct-horse" not in result.command
    assert "unlocked" in session.status()


def test_the_password_never_reaches_a_command_line(tmp_path):
    """It goes in on stdin: anything in argv is visible to every other user
    on the machine through the process table."""
    _install(tmp_path, "sudo", FAKE_SUDO)
    session = SudoSession()
    captured = {}
    original = elevation.run

    async def spy(argv, **kwargs):
        captured.setdefault("argv", []).append(list(argv))
        captured.setdefault("stdin", []).append(kwargs.get("stdin_text"))
        return await original(argv, **kwargs)

    elevation.run = spy
    try:
        asyncio.run(session.unlock("correct-horse"))
    finally:
        elevation.run = original

    for argv in captured["argv"]:
        assert "correct-horse" not in " ".join(argv), argv
    # It goes to exactly one command, on stdin, and nowhere else.
    assert captured["stdin"].count("correct-horse\n") == 1
    assert captured["stdin"][0] == "correct-horse\n"      # the -S -v call
    assert all(value is None for value in captured["stdin"][1:])


def test_a_session_that_dies_stops_claiming_to_be_unlocked(tmp_path):
    """If the timestamp is lost, the keeper must notice rather than leaving
    netzilla to run captures that will silently fail."""
    _install(tmp_path, "sudo", FAKE_SUDO)
    session = SudoSession()
    original = elevation.REFRESH_SECONDS
    elevation.REFRESH_SECONDS = 0.5
    try:
        async def go():
            assert (await session.unlock("correct-horse"))[0]
            os.remove(tmp_path / ".stamp")     # something cleared it
            await asyncio.sleep(1.6)
            return session.active, session.status()

        active, status = asyncio.run(go())
    finally:
        elevation.REFRESH_SECONDS = original
    assert not active
    assert "expired" in status


def test_locking_drops_the_timestamp(tmp_path):
    _install(tmp_path, "sudo", FAKE_SUDO)
    session = SudoSession()

    async def go():
        await session.unlock("correct-horse")
        assert (tmp_path / ".stamp").exists()
        await session.lock()

    asyncio.run(go())
    assert not session.active
    assert session.prefix() == []
    assert not (tmp_path / ".stamp").exists()


def test_permission_report_prefers_the_unlocked_session(tmp_path):
    _install(tmp_path, "sudo", FAKE_SUDO)
    was = capture.SESSION.active
    try:
        capture.SESSION._active = True
        prefix, rows = asyncio.run(capture.permission_report())
        fields = dict(rows)
        if not capture.is_root():
            assert prefix == ["sudo", "-n"]
            assert "unlocked" in fields["Capture permission"]
        assert "Session unlocked" in fields
    finally:
        capture.SESSION._active = was


# ------------------------------------------------------------ live capture
def test_live_argv_has_no_count_and_no_duration():
    argv = capture.live_argv("eth0", "dns", ["sudo", "-n"])
    assert argv[:2] == ["sudo", "-n"]
    assert "-i" in argv and "eth0" in argv
    assert "-l" in argv, "line buffering is what makes it feel live"
    assert "-Y" in argv and "dns" in argv
    assert "-c" not in argv and "-a" not in argv


def test_live_capture_streams_trims_and_cleans_up(tmp_path):
    path = _install(tmp_path, "tshark", FAKE_TSHARK)

    async def go():
        live = capture.LiveCapture("eth0", "", keep=5)
        assert not await live.start()
        started = asyncio.get_running_loop().time()
        async for _packet in live.packets_as_they_arrive(idle=0.3):
            if asyncio.get_running_loop().time() - started > 1.5:
                break
        assert _running(path), "the capture should still be running here"
        await live.stop()
        return live

    live = asyncio.run(go())
    assert live.total > 3, live.total
    # 2.6 trims in batches rather than on every packet — the list is allowed
    # to overshoot a little and is then cut back in one go, because shuffling
    # the whole list down by one per packet was the most expensive thing a
    # busy capture did. The ceiling is what matters, not an exact length.
    assert 5 <= len(live.packets) <= live._trim_at, len(live.packets)
    assert len(live.packets) < live.total or live.total <= 5, "nothing was trimmed"
    assert live.packets[-1]["no"] == live.total, "the newest are the ones kept"
    assert live.unparsed == 0, "tshark's own chatter is not counted as packets"
    assert not _running(path), "stopping must leave no capture behind"


def test_cancelling_the_live_view_kills_the_capture(tmp_path):
    """Pressing another button cancels the worker; an orphaned tshark would
    otherwise sit holding the interface in promiscuous mode."""
    path = _install(tmp_path, "tshark", FAKE_TSHARK)

    async def go():
        live = capture.LiveCapture("eth0", "")
        await live.start()

        async def consume():
            try:
                async for _packet in live.packets_as_they_arrive(idle=0.3):
                    pass
            finally:
                await asyncio.shield(live.stop())

        task = asyncio.ensure_future(consume())
        await asyncio.sleep(0.8)
        assert _running(path)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await asyncio.sleep(0.5)

    asyncio.run(go())
    assert not _running(path)


def test_a_silent_link_still_ticks(tmp_path):
    """Without idle ticks a quiet capture would look frozen."""
    path = _install(tmp_path, "tshark_quiet", QUIET_TSHARK)

    async def go():
        process = LiveProcess([path])
        assert not await process.start()
        idle = 0
        started = asyncio.get_running_loop().time()
        async for line in process.lines(idle=0.25):
            if line is None:
                idle += 1
            if asyncio.get_running_loop().time() - started > 1.1:
                break
        await process.stop()
        return idle

    assert asyncio.run(go()) >= 3


def test_live_summary_reports_what_is_actually_happening():
    live = capture.LiveCapture("eth0", "dns")
    live.total = 120
    live.packets = capture.parse_packets(
        "    1 0.100000 10.0.0.1 → 10.0.0.2 DNS 90 Standard query A example.com"
    )
    rows = dict(capture.live_summary(live, 60.0, "sudo (unlocked)"))
    assert rows["Interface"] == "eth0"
    assert rows["Filter"] == "dns"
    assert rows["Packets seen"] == "120"
    assert rows["Rate"] == "2.0 packets/s"
    assert rows["Running as"] == "sudo (unlocked)"
    assert "1 most recent" in rows["Held for display"]


def test_tshark_chatter_is_not_mistaken_for_packets():
    for noise in ("Capturing on 'eth0'", "12 packets captured",
                  "** (tshark:1234) WARNING **", "Capturing stopped."):
        assert capture._is_chatter(noise), noise
    assert not capture._is_chatter(
        "    1 0.1 10.0.0.1 → 10.0.0.2 DNS 90 Standard query"
    )
