"""CREDS — credential hygiene checks (Have I Been Pwned).

PWNED PASSWORD   k-anonymity breach check. netzilla SHA-1s the password
                 locally and sends only the first five hex characters of the
                 hash; the password never leaves the machine and nothing here
                 is cached.
BREACH SEARCH    filter HIBP's public breach directory by name or domain
                 (metadata only — per-account search needs a paid key).
"""

from __future__ import annotations

from ..clients import hibp
from ..render import kv_panel, table_panel, verdict_line
from ..validators import ValidationError
from .base import Action, Field, LookupPane


class CredsPane(LookupPane):
    PANE_TITLE = "CREDENTIAL HYGIENE"
    DESCRIPTION = (
        "Have I Been Pwned, keyless. PWNED PASSWORD checks a password against "
        "breach corpora without ever sending it — only the first 5 characters "
        "of its SHA-1 hash leave this machine. BREACH SEARCH looks up known "
        "breaches by company or domain."
    )
    FIELDS = (
        Field("value", "Password to check (hidden as you type)",
              "never sent — only 5 hash characters leave", password=True),
        Field("term", "Company or domain to search", "adobe  ·  linkedin.com",
              width=40, submit="breach"),
    )
    ACTIONS = (
        Action("password", "PWNED PASSWORD"),
        Action("breach", "BREACH SEARCH", primary=False),
    )

    async def execute(self, action: str) -> None:
        if action == "password":
            await self._password()
        elif action == "breach":
            await self._breach()

    async def _password(self) -> None:
        password = self.field("value")
        if not password:
            raise ValidationError(
                "Type the password to check in the first box — it is masked, "
                "and only the first 5 characters of its SHA-1 hash are sent.")
        await self.begin("Checking against breach corpora (k-anonymity)…")
        result = await hibp.check_password(self.services, password)
        await self.finish()
        if not result.ok:
            await self.push_error("Pwned Passwords", result.error or "")
            return
        text, state = hibp.password_verdict(result.data)
        await self.push(verdict_line(self.palette, "Password", text, state))
        await self.push(
            kv_panel(
                self.palette, "How this check works",
                [
                    ("Times seen in breaches", f'{result.data.get("count", 0):,}'),
                    ("Sent to HIBP", f'SHA-1 prefix {result.data.get("prefix")}… only'),
                    ("Password transmitted", False),
                    ("Cached", False),
                ],
                subtitle="k-anonymity range API",
            )
        )
        if result.data.get("pwned"):
            await self.push_warning(
                "This password is compromised",
                "It appears in public breach corpora, so it is on attacker "
                "wordlists. Anywhere it is in use should be changed. This does "
                "not mean your account was breached — just that the password is "
                "no longer secret.",
            )

    async def _breach(self) -> None:
        term = self.field("term")
        if not term or len(term) < 2:
            raise ValidationError(
                "Type a company name or domain (2+ characters) in COMPANY OR "
                "DOMAIN TO SEARCH.")
        await self.begin(f"Searching known breaches for '{term}'…")
        result = await hibp.find_breaches(self.services, term)
        await self.finish()
        if not result.ok:
            await self.push_error("HIBP", result.error or "")
            return
        matches = result.data.get("matches") or []
        await self.push(
            verdict_line(
                self.palette, "Breaches",
                f"{len(matches)} known breach(es) match '{term}' "
                f"(of {result.data.get('total', 0):,} tracked)",
                "bad" if matches else "ok",
            )
        )
        if matches:
            await self.push(
                table_panel(
                    self.palette, f"Breaches matching '{term}'",
                    ["Name", "Domain", "Date", "Accounts", "Data exposed"],
                    hibp.breach_rows(result.data),
                    subtitle="source: Have I Been Pwned",
                )
            )
        else:
            await self.push_warning(
                "No match",
                "No breach in the public HIBP directory matches that name or "
                "domain. HIBP catalogues about a thousand verified incidents, "
                "not every site that was ever hacked, so this is not proof of "
                "safety — only that HIBP has no public record of one.\n\n"
                "Try the bare company name too (e.g. 'adobe' rather than a "
                "subdomain). Checking a specific email address needs a paid "
                "HIBP key and is not done here.",
            )
