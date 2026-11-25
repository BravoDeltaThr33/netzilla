"""Shared runtime services: HTTP client, cache, quota, config.

Every API client goes through Services.fetch(), which gives us one place for
timeouts, caching, quota accounting, offline mode and error shaping. Clients
never raise on a network failure — they return an ApiResult with ok=False so a
slow or broken third party degrades one panel instead of crashing the app.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

# httpx is imported where it is used rather than here: it pulls in about
# a third of netzilla's start-up time, and a session that only touches the
# local tabs never needs it. local/oui.py and local/urlhaus_offline.py
# already do the same. Annotations below are strings (see __future__
# above), so they cost nothing.

from .cache import QUOTA_COUNTS_AS, QUOTA_LIMITS, Store
from .config import Config


@dataclass
class ApiResult:
    """Uniform result envelope returned by every client function."""

    ok: bool
    source: str = ""
    data: Any = None
    error: str | None = None
    cached: bool = False
    status_code: int | None = None
    note: str | None = None
    meta: dict = field(default_factory=dict)

    @classmethod
    def success(cls, source: str, data: Any, **kw) -> "ApiResult":
        return cls(ok=True, source=source, data=data, **kw)

    @classmethod
    def failure(cls, source: str, error: str, **kw) -> "ApiResult":
        return cls(ok=False, source=source, error=error, **kw)


class MissingCredential(Exception):
    """Raised inside a client when a required key is not configured."""

    def __init__(self, service: str, label: str, signup_url: str = "") -> None:
        self.service = service
        self.label = label
        self.signup_url = signup_url
        message = f"{service} needs a key. Add '{label}' on the SETTINGS tab."
        if signup_url:
            message += f" Get one free at {signup_url}"
        super().__init__(message)


class Services:
    """Holds everything a client needs; one instance lives on the App."""

    def __init__(self, config: Config, offline: bool = False) -> None:
        self.config = config
        self.offline = offline
        self.store = Store(config.cache_path, enabled=config.cache_enabled)
        self._client: httpx.AsyncClient | None = None
        self._client_lock = asyncio.Lock()
        # When True, cached responses are ignored (SETTINGS -> TEST KEYS).
        self.bypass_cache = False
        # Vendor-reported quota, e.g. AbuseIPDB's X-RateLimit-* headers:
        # source -> {"limit": int, "remaining": int, "reset": str}
        self.reported_limits: dict[str, dict] = {}

    # ------------------------------------------------------------- client
    async def client(self) -> httpx.AsyncClient:
        import httpx

        async with self._client_lock:
            if self._client is None or self._client.is_closed:
                self._client = httpx.AsyncClient(
                    timeout=httpx.Timeout(self.config.timeout_seconds),
                    follow_redirects=True,
                    headers={"User-Agent": self.config.user_agent},
                )
            return self._client

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            try:
                await self._client.aclose()
            except Exception:
                pass
        self.store.close()

    # -------------------------------------------------------------- fetch
    async def fetch(
        self,
        *,
        source: str,
        url: str,
        method: str = "GET",
        params: dict | None = None,
        headers: dict | None = None,
        json_body: Any = None,
        form: dict | None = None,
        cache_key: str | None = None,
        ttl: float = 0,
        expect: str = "json",
        ok_statuses: tuple[int, ...] = (200,),
        timeout: float | None = None,
        retries: int = 0,
    ) -> ApiResult:
        """Perform one HTTP call with caching, quota accounting and timeouts.

        `expect` is "json" or "text". `ok_statuses` lists the codes treated as
        success; everything else becomes a readable error. `timeout` overrides
        the global timeout for slow services; `retries` re-attempts timeouts
        and connection errors (never HTTP errors).
        """
        if cache_key and ttl > 0 and not self.bypass_cache:
            hit = self.store.get(cache_key)
            if hit is not None:
                return ApiResult.success(source, hit, cached=True)

        if self.offline:
            return ApiResult.failure(
                source, "Offline mode is on — network lookups are disabled."
            )

        import httpx

        limit = float(timeout or self.config.timeout_seconds)
        response = None
        attempts = max(0, int(retries)) + 1
        for attempt in range(attempts):
            try:
                client = await self.client()
                kwargs = {}
                if timeout:
                    kwargs["timeout"] = httpx.Timeout(limit, connect=min(limit, 10.0))
                response = await client.request(
                    method.upper(),
                    url,
                    params=params,
                    headers=headers,
                    json=json_body,
                    data=form,
                    **kwargs,
                )
                break
            except httpx.TimeoutException:
                if attempt + 1 < attempts:
                    continue
                tried = f" ({attempts} attempts)" if attempts > 1 else ""
                return ApiResult.failure(
                    source, f"Timed out after {limit:.0f}s{tried}."
                )
            except httpx.RequestError as exc:
                if attempt + 1 < attempts:
                    continue
                return ApiResult.failure(
                    source, f"Network error: {exc.__class__.__name__}"
                )
            except Exception as exc:  # defensive: never let a client crash a pane
                return ApiResult.failure(source, f"Unexpected error: {exc}")

        self.store.record_call(source)
        self._capture_rate_headers(source, response.headers)

        if response.status_code not in ok_statuses:
            message = _explain_status(source, response.status_code)
            detail = _vendor_error_detail(response)
            if detail:
                message = f"{message}\nService said: {detail}"
            retry_after = response.headers.get("Retry-After")
            if response.status_code == 429 and retry_after and retry_after.isdigit():
                message += f"\nRetry after {_humanise_seconds(int(retry_after))}."
            return ApiResult.failure(
                source, message, status_code=response.status_code
            )

        if expect == "text":
            payload: Any = response.text
        else:
            try:
                payload = response.json()
            except Exception:
                return ApiResult.failure(
                    source,
                    "Response was not valid JSON.",
                    status_code=response.status_code,
                )

        if cache_key and ttl > 0:
            self.store.set(cache_key, payload, ttl)

        return ApiResult.success(source, payload, status_code=response.status_code)

    # -------------------------------------------------------------- quota
    def _capture_rate_headers(self, source: str, headers) -> None:
        """Remember vendor-reported quota (AbuseIPDB sends X-RateLimit-*)."""
        limit = headers.get("X-RateLimit-Limit")
        remaining = headers.get("X-RateLimit-Remaining")
        if limit is None or remaining is None:
            return
        try:
            self.reported_limits[source] = {
                "limit": int(limit),
                "remaining": int(remaining),
                "reset": headers.get("X-RateLimit-Reset", ""),
            }
        except ValueError:
            pass

    def quota_rows(self, active_only: bool = False) -> list[tuple[str, str, str]]:
        """(service label, usage string, state) for the quota readout.
        active_only: just the services with a hard limit, or that have been
        called in their window — what fits on DASH."""
        rows = []
        for key, (label, window, limit) in QUOTA_LIMITS.items():
            used = self.store.count_calls(QUOTA_COUNTS_AS.get(key, key), window)
            if active_only and limit is None and not used and key not in self.reported_limits:
                continue
            window_label = _window_label(window)
            if limit is None:
                usage = f"{used} in {window_label}"
                state = "ok"
            else:
                usage = f"{used}/{limit} in {window_label}"
                ratio = used / limit if limit else 0
                state = "error" if ratio >= 1 else "warn" if ratio >= 0.75 else "ok"
            reported = self.reported_limits.get(key)
            if reported:
                # The vendor's own count beats ours: it includes calls made
                # from other machines and from the vendor's website.
                usage += f"  · vendor says {reported['remaining']:,}/{reported['limit']:,} left"
                if reported["remaining"] <= 0:
                    state = "error"
                elif reported["remaining"] < reported["limit"] * 0.25:
                    state = "warn"
            rows.append((label, usage, state))
        return rows

    # -------------------------------------------------------- credentials
    def require_credential(self, key: str) -> str:
        from .config import CREDENTIAL_FIELDS

        value = self.config.credential(key)
        if value:
            return value
        spec = next((f for f in CREDENTIAL_FIELDS if f.key == key), None)
        raise MissingCredential(
            spec.service if spec else key,
            spec.label if spec else key,
            spec.signup_url if spec else "",
        )


def _window_label(seconds: float) -> str:
    if seconds >= 7 * 86400:
        return f"{int(seconds // 86400)}d"
    if seconds >= 86400:
        return "24h"
    if seconds >= 3600:
        return f"{int(seconds // 3600)}h"
    if seconds >= 60:
        return f"{int(seconds // 60)}m"
    return f"{int(seconds)}s"


def _explain_status(source: str, code: int) -> str:
    """Turn a bare HTTP status into something a human can act on."""
    generic = {
        400: "Bad request — check the value you entered.",
        401: "Unauthorized — the API key on the SETTINGS tab was rejected.",
        402: "Payment required — that request exceeds the free plan's limits "
             "(for AbuseIPDB block checks, the free tier stops at /24).",
        403: "Forbidden — the key may lack permission for this endpoint, "
             "or this endpoint needs a paid plan.",
        404: "Not found — no record for that target.",
        422: "The service could not process that input.",
        429: "Rate limited — you have hit this API's free-tier ceiling. "
             "Wait a moment and retry.",
        500: "The service returned a server error.",
        502: "Bad gateway from the service.",
        503: "The service is temporarily unavailable.",
        504: "The service timed out upstream.",
    }
    return generic.get(code, f"HTTP {code} from {source}.")


def _vendor_error_detail(response) -> str:
    """Pull the human-readable message out of a vendor error body.

    Shapes documented by the vendors netzilla uses:
      AbuseIPDB   {"errors": [{"detail": "...", "status": 429}]}
      GreyNoise   {"message": "..."}
      VirusTotal  {"error": {"code": "...", "message": "..."}}
    """
    try:
        body = response.json()
    except Exception:
        return ""
    if not isinstance(body, dict):
        return ""
    errors = body.get("errors")
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        detail = errors[0].get("detail") or errors[0].get("title")
        if detail:
            return str(detail)[:240]
    error = body.get("error")
    if isinstance(error, dict):
        text = error.get("message") or error.get("code")
        if text:
            return str(text)[:240]
    if isinstance(error, str) and error:
        return error[:240]
    message = body.get("message") or body.get("detail")
    if message:
        return str(message)[:240]
    return ""


def _humanise_seconds(seconds: int) -> str:
    if seconds >= 3600:
        hours, rem = divmod(seconds, 3600)
        return f"{hours}h {rem // 60}m"
    if seconds >= 60:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds}s"
