"""SSL / TLS — instant local openssl check, plus the graded SSL Labs scan."""

from __future__ import annotations

import asyncio

from .. import hostos
from ..clients import crtsh, ssllabs
from ..local import tls_quick
from ..render import group, kv_panel, table_panel, text_panel, verdict_line
from ..validators import ValidationError, valid_domain
from .base import Action, Field, LookupPane


class SSLTLSPane(LookupPane):
    PANE_TITLE = "SSL / TLS HEALTH"
    DESCRIPTION = (
        "QUICK CHECK inspects the certificate locally in under a second and "
        "works against internal hosts. SSL LABS runs the full graded "
        "assessment — slower, public hosts only, and cached for 24 hours."
    )
    FIELDS = (
        Field("host", "Hostname", "example.com"),
        Field("port", "Port", "443", width=14),
    )
    ACTIONS = (
        Action("quick", "QUICK CHECK"),
        Action("labs", "SSL LABS GRADE", primary=False),
        Action("openssl", "OPENSSL HANDSHAKE", primary=False),
        Action("certs", "CERT SEARCH (CT)", primary=False),
    )

    async def execute(self, action: str) -> None:
        host = valid_domain(self.field("host"))
        if action == "certs":
            await self._certs(host)
            return

        raw_port = self.field("port") or "443"
        try:
            port = int(raw_port)
        except ValueError:
            raise ValidationError(f"'{raw_port}' is not a port number.")
        if not 1 <= port <= 65535:
            raise ValidationError("Port must be between 1 and 65535.")

        if action == "quick":
            await self._quick(host, port)
        elif action == "openssl":
            await self._openssl(host, port)
        else:
            await self._labs(host)

    async def _certs(self, host: str) -> None:
        await self.begin(f"Searching Certificate Transparency logs for {host}…")
        result = await crtsh.search(self.services, host)
        await self.finish()
        if not result.ok:
            await self.push_error("crt.sh", result.error or "")
            return
        info = crtsh.summary(result.data, host)
        await self.push(
            verdict_line(
                self.palette, "CT logs",
                f"{info['certificates']} certificate(s), "
                f"{len(info['unique_names'])} unique name(s), "
                f"earliest {info['earliest'] or 'unknown'}",
                "info",
            )
        )
        names = info["unique_names"]
        if names:
            await self.push(
                table_panel(
                    self.palette, f"Names seen in certificates for {host}",
                    ["Subdomain / name"],
                    [[n] for n in names[:200]],
                    subtitle=(f"{len(names)} unique"
                              + (" · first 200 shown" if len(names) > 200 else "")),
                )
            )
        rows = crtsh.recent_rows(result.data)
        if rows:
            await self.push(
                table_panel(
                    self.palette, "Recent certificates",
                    ["Issued", "Expires", "Issuer", "Names"], rows,
                    subtitle="newest first · source: crt.sh",
                )
            )
        await self.push_warning(
            "Read this as attack surface",
            "Every name above has (or had) a publicly-trusted certificate. Watch "
            "for subdomains you did not know existed (shadow IT) and certificates "
            "from a CA you do not use (possible mis-issuance).",
        )

    async def _quick(self, host: str, port: int) -> None:
        await self.begin(f"Opening TLS connection to {host}:{port}…")
        info = await asyncio.to_thread(tls_quick.inspect_certificate, host, port)
        await self.finish()

        text, state = tls_quick.expiry_verdict(info)
        rows = [
            ("Host", f"{host}:{port}"),
            ("Chain verified", info.get("verified")),
            ("TLS protocol", info.get("protocol")),
            ("Cipher", info.get("cipher")),
            ("Cipher bits", info.get("cipher_bits")),
            ("Subject CN", info.get("subject_cn")),
            ("Subject org", info.get("subject_o")),
            ("Issuer CN", info.get("issuer_cn")),
            ("Issuer org", info.get("issuer_o")),
            ("Serial", info.get("serial")),
            ("Valid from", info.get("not_before")),
            ("Valid until", info.get("not_after")),
            ("Days remaining", info.get("days_remaining")),
            # Populated only when chain verification failed and the public
            # certificate fields are therefore unavailable.
            ("SHA-256 fingerprint", info.get("sha256_fingerprint")),
        ]
        rows = [(k, v) for k, v in rows if v is not None or k != "SHA-256 fingerprint"]
        await self.push(
            group(
                verdict_line(self.palette, "Certificate", text, state),
                kv_panel(
                    self.palette,
                    f"Certificate — {host}:{port}",
                    rows,
                    subtitle="local · python ssl",
                ),
            )
        )
        sans = info.get("sans") or []
        if sans:
            await self.push(
                text_panel(
                    self.palette,
                    f"Subject alternative names ({len(sans)})",
                    "\n".join(sans[:60])
                    + ("\n… truncated" if len(sans) > 60 else ""),
                )
            )
        if info.get("error") and info.get("verified") is False:
            message = info["error"]
            if info.get("sha256_fingerprint"):
                message += (
                    "\n\nThe chain could not be validated, so Python will not "
                    "expose the certificate's fields. The fingerprint above is "
                    "what you compare against a known-good value for a "
                    "self-signed or internal CA cert. For the full certificate, "
                    "use OPENSSL HANDSHAKE."
                )
            await self.push_warning("Verification problem", message)

    async def _openssl(self, host: str, port: int) -> None:
        await self.begin(f"openssl s_client -connect {host}:{port}…")
        result = await tls_quick.openssl_probe(host, port)
        subtitle = "local · openssl s_client"
        if result.missing_tool:
            # No openssl (Windows, unless one was installed): Python's own TLS
            # stack does the handshake instead.
            self.progress("openssl is not installed — handshaking with Python's TLS…")
            result = await tls_quick.python_probe(host, port)
            subtitle = ("local · Python's TLS (openssl is not installed — "
                        + hostos.install_hint("openssl") + ")")
        await self.finish()
        await self.push(
            text_panel(
                self.palette,
                f"TLS handshake — {host}:{port}",
                result.output or result.error or "No output.",
                subtitle=subtitle,
            )
        )

    async def _labs(self, host: str) -> None:
        await self.begin(f"Requesting SSL Labs assessment for {host}…")
        await self.push_warning(
            "This one is slow on purpose",
            "A fresh SSL Labs scan takes one to three minutes. netzilla asks "
            "for their cached result first and only polls when the scan is new. "
            "Results are then cached locally for 24 hours.",
        )
        result = await ssllabs.analyze(self.services, host, progress=self.progress)
        await self.finish()
        if not result.ok:
            await self.push_error("SSL Labs", result.error or "")
            return

        payload = result.data
        text, state = ssllabs.best_grade(payload)
        await self.push(
            group(
                verdict_line(self.palette, "SSL Labs", text, state),
                kv_panel(
                    self.palette,
                    f"Assessment — {host}",
                    [
                        ("Host", payload.get("host")),
                        ("Status", payload.get("status")),
                        ("Endpoints", len(payload.get("endpoints") or [])),
                        ("Engine version", payload.get("engineVersion")),
                        ("Criteria version", payload.get("criteriaVersion")),
                    ],
                    subtitle="cached" if result.cached else "live · Qualys SSL Labs",
                ),
            )
        )
        rows = ssllabs.endpoint_rows(payload)
        if rows:
            await self.push(
                table_panel(
                    self.palette,
                    "Per-endpoint grades",
                    ["IP", "Server name", "Grade", "Trust ignored", "Warnings"],
                    rows,
                )
            )
