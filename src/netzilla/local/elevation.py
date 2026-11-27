"""Unlock privileged tools once per netzilla session.

The password is used exactly once, to prime sudo's own timestamp, and is then
dropped. A background task refreshes that timestamp every minute for as long
as netzilla is running, so every later command uses `sudo -n` and nothing is
ever asked again — and netzilla never holds the password in memory.

That is deliberately different from keeping the password and replaying it:
sudo already has a session cache built for this, and using it means the secret
exists for the length of one subprocess call rather than the length of an
afternoon. The password reaches sudo on stdin, never on a command line, so it
is not visible in the process table.

The timestamp is dropped with `sudo -k` when the session is locked, and it
expires on its own (15 minutes by default) once netzilla exits.
"""

from __future__ import annotations

import asyncio

from .. import hostos
from .runner import CommandResult, run

REFRESH_SECONDS = 60.0


class SudoSession:
    """Holds whether this netzilla run has been unlocked, and keeps it so."""

    def __init__(self) -> None:
        self._active = False
        self._keeper: asyncio.Task | None = None
        self._reason = ""

    # ------------------------------------------------------------- state
    @property
    def active(self) -> bool:
        return self._active

    @property
    def reason(self) -> str:
        return self._reason

    def prefix(self) -> list[str]:
        """What to put in front of a command that needs root."""
        return ["sudo", "-n"] if self._active else []

    def status(self) -> str:
        if self._active:
            return "unlocked for this session — no further prompts"
        return self._reason or "locked"

    # ------------------------------------------------------------ unlock
    async def unlock(self, password: str) -> tuple[bool, str]:
        """Validate the password once and start keeping the timestamp alive."""
        if not hostos.has_sudo():
            self._reason = ("Windows has no sudo session; " + hostos.admin_hint()
                            if hostos.is_windows() else "sudo is not installed")
            return False, self._reason
        # -S reads the password from stdin, -p '' suppresses sudo's own prompt
        # (netzilla asked for it already), -v validates without running a tool.
        result = await run(
            ["sudo", "-S", "-p", "", "-v"],
            timeout=30,
            stdin_text=(password or "") + "\n",
        )
        del password
        if not result.ok:
            self._reason = _explain(result)
            return False, self._reason

        # Does this machine actually cache the timestamp? With
        # timestamp_timeout=0 in sudoers it does not, and pretending otherwise
        # would mean a silent failure on the next capture.
        check = await run(["sudo", "-n", "true"], timeout=10)
        if not check.ok:
            self._reason = (
                "the password was accepted, but sudo on this machine is set "
                "not to remember it (timestamp_timeout=0 in sudoers), so it "
                "would ask again every time"
            )
            return False, self._reason

        self._active = True
        self._reason = ""
        self._start_keeper()
        return True, "unlocked"

    def _start_keeper(self) -> None:
        if self._keeper is not None and not self._keeper.done():
            return
        try:
            self._keeper = asyncio.ensure_future(self._keep_alive())
        except RuntimeError:          # no running loop (tests, --no-tui)
            self._keeper = None

    async def _keep_alive(self) -> None:
        """Refresh sudo's timestamp before it can expire."""
        try:
            while self._active:
                await asyncio.sleep(REFRESH_SECONDS)
                result = await run(["sudo", "-n", "-v"], timeout=15)
                if not result.ok:
                    self._active = False
                    self._reason = (
                        "the sudo session expired and could not be renewed"
                    )
                    return
        except asyncio.CancelledError:
            raise

    # -------------------------------------------------------------- lock
    async def lock(self) -> None:
        """Forget the timestamp now rather than letting it time out."""
        self._active = False
        self._reason = "locked"
        keeper, self._keeper = self._keeper, None
        if keeper is not None:
            keeper.cancel()
        if hostos.has_sudo():
            await run(["sudo", "-k"], timeout=10)


def _explain(result: CommandResult) -> str:
    blob = f"{result.error} {result.output}".lower()
    if "incorrect password" in blob or "sorry, try again" in blob:
        return "that password was not accepted"
    if "not in the sudoers" in blob or "not allowed" in blob:
        return "this account is not allowed to use sudo"
    if "timed out" in blob:
        return "sudo did not answer in time"
    return result.error or result.output or "sudo refused the password"


# One session per running netzilla.
SESSION = SudoSession()
