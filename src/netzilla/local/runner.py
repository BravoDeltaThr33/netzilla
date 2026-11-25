"""Run local command-line tools without blocking the UI.

Everything here shells out through asyncio so a slow traceroute never freezes
the interface, and every call has a hard timeout.
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass


@dataclass
class CommandResult:
    ok: bool
    output: str
    error: str = ""
    command: str = ""
    missing_tool: str | None = None


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


async def _reap(process) -> None:
    """Kill a tool and wait for it, so no process (or its pipes) outlives
    the call that started it."""
    try:
        process.kill()
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(process.wait(), 2.0)
    except BaseException:
        pass


async def run(
    argv: list[str],
    timeout: float = 30.0,
    ok_returncodes: tuple[int, ...] = (0,),
    stdin_text: str | None = None,
) -> CommandResult:
    """Execute a command and capture its output.

    `stdin_text` is written to the process and never appears in the command
    line, which is how a password reaches `sudo -S` without being visible in
    the process table to every other user on the machine.
    """
    tool = argv[0]
    printable = " ".join(argv)
    if not have(tool):
        return CommandResult(
            ok=False,
            output="",
            error=f"'{tool}' is not installed on this system.",
            command=printable,
            missing_tool=tool,
        )
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_text is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as exc:
        return CommandResult(False, "", f"Could not start {tool}: {exc}", printable)

    payload = stdin_text.encode() if stdin_text is not None else None
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input=payload), timeout=timeout
        )
    except asyncio.TimeoutError:
        await _reap(process)
        return CommandResult(
            False, "", f"{tool} timed out after {timeout:.0f}s.", printable
        )
    except asyncio.CancelledError:
        # The view that asked was stopped (another button): don't leave the
        # tool running behind it.
        await _reap(process)
        raise

    out = (stdout or b"").decode("utf-8", "replace").strip()
    err = (stderr or b"").decode("utf-8", "replace").strip()
    ok = process.returncode in ok_returncodes
    # Some tools (ping on an unreachable host) return useful output on failure.
    if not ok and out:
        return CommandResult(False, out, err or f"exit code {process.returncode}", printable)
    return CommandResult(ok, out, err, printable)


async def run_for(
    argv: list[str], seconds: float, grace: float = 3.0
) -> CommandResult:
    """Run a tool that never exits on its own and keep what it printed.

    bmon (and iftop without -t) stream forever, so netzilla lets them run for
    a fixed window, asks them to stop, and returns the captured output rather
    than treating the stop as a failure.
    """
    tool = argv[0]
    printable = " ".join(argv)
    if not have(tool):
        return CommandResult(
            ok=False, output="", error=f"'{tool}' is not installed on this system.",
            command=printable, missing_tool=tool,
        )
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as exc:
        return CommandResult(False, "", f"Could not start {tool}: {exc}", printable)

    chunks: list[bytes] = []

    async def drain() -> None:
        assert process.stdout is not None
        while True:
            block = await process.stdout.read(4096)
            if not block:
                break
            chunks.append(block)

    reader = asyncio.ensure_future(drain())
    try:
        await asyncio.wait_for(asyncio.shield(process.wait()), timeout=seconds)
    except asyncio.TimeoutError:
        for stop in (process.terminate, process.kill):
            try:
                stop()
                await asyncio.wait_for(process.wait(), timeout=grace)
                break
            except asyncio.TimeoutError:
                continue
            except ProcessLookupError:
                break
    try:
        await asyncio.wait_for(reader, timeout=grace)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        reader.cancel()

    out = b"".join(chunks).decode("utf-8", "replace").strip()
    err = ""
    if process.stderr is not None:
        try:
            err = (await asyncio.wait_for(process.stderr.read(), timeout=1.0)).decode(
                "utf-8", "replace"
            ).strip()
        except (asyncio.TimeoutError, Exception):
            err = ""
    # Being stopped by us is the normal ending, so output alone decides success.
    return CommandResult(bool(out), out, err, printable)


class LiveProcess:
    """A long-running tool whose output is read line by line as it appears.

    Used for captures that run until the user stops them: the process is
    always killed in stop(), so cancelling the worker behind a live view can
    never leave a stray tshark holding an interface open.
    """

    def __init__(self, argv: list[str]) -> None:
        self.argv = argv
        self.command = " ".join(argv)
        self._process: asyncio.subprocess.Process | None = None
        self._stderr: list[str] = []

    async def start(self) -> str:
        """"" on success, otherwise why it could not start."""
        if not have(self.argv[0]):
            return f"'{self.argv[0]}' is not installed on this system."
        try:
            self._process = await asyncio.create_subprocess_exec(
                *self.argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as exc:
            return f"Could not start {self.argv[0]}: {exc}"
        return ""

    # Read this much at a time. Bigger than any plausible burst between two
    # event-loop turns, so a busy interface costs one await per chunk.
    CHUNK = 65536

    async def lines(self, idle: float = 0.5):
        """Yield output lines, and None whenever `idle` seconds pass quietly.

        The None ticks let a live view refresh its own counters and countdown
        on a silent link instead of appearing frozen.

        Output is read in chunks and split here rather than with readline():
        asyncio.wait_for() builds a Task and schedules a timer on every call,
        so a readline() per packet made the event loop, not the capture, the
        limit on a busy link — about 60,000 lines a second against 1,000,000
        this way. read() returns as soon as any bytes are there, so a quiet
        link is no slower to respond than it was.
        """
        if self._process is None or self._process.stdout is None:
            return
        stream = self._process.stdout
        partial = b""
        while True:
            try:
                chunk = await asyncio.wait_for(stream.read(self.CHUNK), timeout=idle)
            except asyncio.TimeoutError:
                yield None
                continue
            if not chunk:
                break
            parts = (partial + chunk).split(b"\n")
            partial = parts.pop()          # whatever came after the last newline
            for part in parts:
                yield part.decode("utf-8", "replace").rstrip("\r")
        if partial:                         # a final line with no newline
            yield partial.decode("utf-8", "replace").rstrip("\r")

    async def stop(self) -> str:
        """Kill the process and return whatever it wrote to stderr."""
        process, self._process = self._process, None
        if process is None:
            return "\n".join(self._stderr)
        for finish in (process.terminate, process.kill):
            if process.returncode is not None:
                break
            try:
                finish()
                await asyncio.wait_for(process.wait(), timeout=3)
            except (asyncio.TimeoutError, ProcessLookupError):
                continue
        if process.stderr is not None:
            try:
                blob = await asyncio.wait_for(process.stderr.read(), timeout=1.0)
                if blob:
                    self._stderr.append(blob.decode("utf-8", "replace").strip())
            except Exception:
                pass
        return "\n".join(part for part in self._stderr if part)
