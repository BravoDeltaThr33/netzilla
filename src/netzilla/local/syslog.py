"""Instant syslog catcher.

Stands up a UDP (and optional TCP) listener on port 514 for the length of a
troubleshooting session and tails whatever devices send at it — no NMS to
install, no config to persist. Point a switch/router/firewall's logging at this
box's IP for a minute and watch its messages arrive live.

Binding 514 needs root (privileged port), so the listener raises PermissionError
without it; the LAN tab then falls back to FALLBACK_PORT (1514) by itself, or
uses whatever port is typed in its target field. The RFC 3164 / RFC 5424 line parser is pure and unit-tested.
"""

from __future__ import annotations

import asyncio
import re
import time

DEFAULT_PORT = 514
FALLBACK_PORT = 1514  # unprivileged; used automatically without root

FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]
SEVERITIES = [
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
]

_PRI_RE = re.compile(r"^<(\d{1,3})>")


def parse_priority(pri: int) -> tuple[str, str]:
    facility = pri // 8
    severity = pri % 8
    fac = FACILITIES[facility] if facility < len(FACILITIES) else str(facility)
    sev = SEVERITIES[severity] if severity < len(SEVERITIES) else str(severity)
    return fac, sev


def parse_message(raw: str, source: str = "") -> dict:
    """Best-effort parse of one syslog line (RFC 3164 or 5424 or bare text)."""
    raw = raw.rstrip("\r\n")
    facility = severity = ""
    body = raw
    match = _PRI_RE.match(raw)
    if match:
        pri = int(match.group(1))
        if pri <= 191:
            facility, severity = parse_priority(pri)
        body = raw[match.end():]
    return {
        "received": time.strftime("%H:%M:%S"),
        "source": source,
        "facility": facility,
        "severity": severity,
        "message": body.strip(),
    }


SEVERITY_STATE = {
    "emerg": "bad", "alert": "bad", "crit": "bad", "err": "bad",
    "warning": "warn", "notice": "info", "info": "info", "debug": "info",
}


def severity_state(severity: str) -> str:
    return SEVERITY_STATE.get(severity, "info")


class SyslogCollector:
    """Async UDP syslog listener that appends parsed messages to a callback."""

    def __init__(self, port: int = DEFAULT_PORT, on_message=None) -> None:
        self.port = port
        self.on_message = on_message
        self.messages: list[dict] = []
        self._transport = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        collector = self

        class _Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                try:
                    text = data.decode("utf-8", "replace")
                except Exception:
                    return
                for line in text.splitlines() or [text]:
                    if not line.strip():
                        continue
                    msg = parse_message(line, source=addr[0])
                    collector.messages.append(msg)
                    if collector.on_message:
                        collector.on_message(msg)

        try:
            self._transport, _ = await loop.create_datagram_endpoint(
                _Proto, local_addr=("0.0.0.0", self.port)
            )
        except PermissionError as exc:
            raise PermissionError(
                f"Binding UDP/{self.port} needs root. Run `sudo netzilla`, or "
                f"type a port of 1024 or above (e.g. {FALLBACK_PORT}) in the "
                "target field and log your device there."
            ) from exc

    def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None


def row(msg: dict) -> list[object]:
    return [
        msg.get("received", ""),
        msg.get("source", ""),
        (msg.get("severity") or "—"),
        (msg.get("facility") or "—"),
        msg.get("message", ""),
    ]
