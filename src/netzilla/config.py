"""Configuration: API keys, shared secrets, theme choice, timeouts.

Stored as TOML at ~/.config/netzilla/config.toml with 0600 permissions.
The Settings tab reads and writes this file directly.

Credentials resolve in three layers, highest first:

  1. NETZILLA_<KEY> environment variables
  2. values the user saved on the SETTINGS tab (config.toml)
  3. bundled defaults shipped in data/default_credentials.toml

Only values that differ from the bundled default are written to config.toml,
so a user override is always explicit and "RESET TO DEFAULTS" is a clean
delete rather than a copy.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - 3.10 fallback
    import tomli as tomllib

from . import __version__
from .themes import DEFAULT_THEME


DEFAULT_CONFIG_DIR = Path(
    os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")
) / "netzilla"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.toml"
DEFAULT_CACHE_PATH = DEFAULT_CONFIG_DIR / "cache.sqlite3"
BUNDLED_DEFAULTS_PATH = Path(__file__).resolve().parent / "data" / "default_credentials.toml"

# Sent with every API request. Versions before 4.0 wrote their own default
# ("netzilla/2.0 …") into config.toml, so a saved value that is merely an old
# default is replaced by this one on load; only a genuinely custom agent is
# kept and saved.
DEFAULT_USER_AGENT = f"netzilla/{__version__} (+https://github.com/)"
_OLD_DEFAULT_AGENT = re.compile(r"^netzilla/\d+(\.\d+)* \(\+https://github\.com/\)$")

# How graphs are drawn: "auto" picks pixel graphics in a terminal that can
# show them (kitty, Ghostty) and text everywhere else; "pixel" and "text"
# force one or the other.
GRAPHICS_MODES = ("auto", "pixel", "text")


def load_bundled_defaults(path: Path | None = None) -> dict[str, str]:
    """Read the credentials shipped with this copy of netzilla.

    A missing or malformed file simply means "no defaults" — that is the
    expected state for a copy that has been stripped before sharing.
    """
    source = path or BUNDLED_DEFAULTS_PATH
    try:
        with source.open("rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, ValueError):
        return {}
    creds = raw.get("credentials", {})
    if not isinstance(creds, dict):
        return {}
    return {
        k: str(v).strip()
        for k, v in creds.items()
        if k in CREDENTIAL_KEYS and str(v).strip()
    }


@dataclass(frozen=True)
class CredentialField:
    """One credential input rendered on the Settings tab."""

    key: str                 # config key under [credentials]
    label: str               # shown next to the input
    service: str             # which API it belongs to
    required: bool           # False = the service also works keyless
    kind: str = "api_key"    # "api_key" | "shared_secret"
    signup_url: str = ""
    note: str = ""


# Every credential netzilla can use. `required=False` means the related tab
# still does useful work without it.
#
# Every service here is free to use. The four "required" keys are free
# accounts that unlock a free tier; NVD's is optional and only raises a rate
# limit. Nothing netzilla does needs a paid plan — features that did (Shodan's
# host API and search) were removed in 4.0.
#
# Research note on shared secrets: none of these services uses an HMAC-style
# shared secret / secret-key pair; they are all single-token header schemes.
# abuse.ch calls its token an "Auth-Key", so it is surfaced under that name.
# The shared-secret field type is kept in the schema (kind="shared_secret") so
# a future service that needs one drops straight in.
CREDENTIAL_FIELDS: tuple[CredentialField, ...] = (
    CredentialField(
        key="abuseipdb_api_key",
        label="AbuseIPDB API Key",
        service="AbuseIPDB",
        required=True,
        signup_url="https://www.abuseipdb.com/account/api",
        note="Free tier: 1,000 checks/day, 100 block checks/day (up to /24). "
             "Sent as the 'Key' header.",
    ),
    CredentialField(
        key="virustotal_api_key",
        label="VirusTotal API Key",
        service="VirusTotal",
        required=True,
        signup_url="https://www.virustotal.com/gui/my-apikey",
        note="Free tier: 4 req/min, 500/day. Sent as the 'x-apikey' header.",
    ),
    CredentialField(
        key="greynoise_api_key",
        label="GreyNoise Community API Key",
        service="GreyNoise",
        required=True,
        signup_url="https://viz.greynoise.io/signup",
        note="Free Community tier: 50 lookups/week, shared with the GreyNoise "
             "web Visualizer. Sent as the 'key' header.",
    ),
    CredentialField(
        key="abusech_auth_key",
        label="abuse.ch Auth-Key (URLhaus)",
        service="URLhaus",
        required=True,
        kind="shared_secret",
        signup_url="https://auth.abuse.ch/",
        note="Free. abuse.ch calls this an Auth-Key, not an API key. "
             "Sent as the 'Auth-Key' header.",
    ),
    CredentialField(
        key="nvd_api_key",
        label="NVD API Key (optional)",
        service="NVD",
        required=False,
        signup_url="https://nvd.nist.gov/developers/request-an-api-key",
        note="Optional. Raises the limit from 5 req/30s to 50 req/30s.",
    ),
)

CREDENTIAL_KEYS = tuple(f.key for f in CREDENTIAL_FIELDS)


@dataclass
class Config:
    """In-memory view of config.toml."""

    path: Path = DEFAULT_CONFIG_PATH
    theme: str = DEFAULT_THEME
    # User overrides only — values saved on the SETTINGS tab.
    credentials: dict[str, str] = field(default_factory=dict)
    # Bundled defaults from data/default_credentials.toml.
    defaults: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 12.0
    cache_enabled: bool = True
    user_agent: str = DEFAULT_USER_AGENT
    # [display]
    graphics: str = "auto"
    notify: bool = True          # desktop notification when a long run ends

    # ---------------------------------------------------------------- load
    @classmethod
    def load(
        cls,
        path: Path | str | None = None,
        defaults_path: Path | None = None,
        use_defaults: bool = True,
    ) -> "Config":
        cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
        cfg = cls(path=cfg_path)
        if use_defaults:
            cfg.defaults = load_bundled_defaults(defaults_path)
        if not cfg_path.exists():
            return cfg
        try:
            with cfg_path.open("rb") as handle:
                raw = tomllib.load(handle)
        except Exception:
            # A corrupt config must never stop the app from starting.
            return cfg

        theme = raw.get("theme", {})
        if isinstance(theme, dict):
            cfg.theme = str(theme.get("name", cfg.theme))
            # 3.3–3.4 also saved a "graphs" style here; LIVE AIR's history is
            # plain dBm numbers since 3.5, so it is simply ignored.

        creds = raw.get("credentials", {})
        if isinstance(creds, dict):
            # Empty strings mean "no override" and are dropped, so a blank
            # line left by v1.0 does not mask a bundled default.
            cfg.credentials = {
                k: str(v).strip()
                for k, v in creds.items()
                if k in CREDENTIAL_KEYS and str(v).strip()
            }

        general = raw.get("general", {})
        if isinstance(general, dict):
            try:
                cfg.timeout_seconds = float(
                    general.get("timeout_seconds", cfg.timeout_seconds)
                )
            except (TypeError, ValueError):
                pass
            cfg.cache_enabled = bool(general.get("cache_enabled", cfg.cache_enabled))
            agent = str(general.get("user_agent") or "").strip()
            if agent and not _OLD_DEFAULT_AGENT.match(agent):
                cfg.user_agent = agent

        display = raw.get("display", {})
        if isinstance(display, dict):
            mode = str(display.get("graphics", cfg.graphics)).strip().lower()
            cfg.graphics = mode if mode in GRAPHICS_MODES else "auto"
            cfg.notify = bool(display.get("notify", cfg.notify))
        return cfg

    # ---------------------------------------------------------------- save
    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Only genuine overrides are persisted. A value equal to the bundled
        # default is not an override and is left out on purpose.
        overrides = {
            k: v
            for k, v in self.credentials.items()
            if v and v != self.defaults.get(k)
        }
        payload = {
            "theme": {"name": self.theme},
            "credentials": overrides,
            "general": {
                "timeout_seconds": self.timeout_seconds,
                "cache_enabled": self.cache_enabled,
            },
            "display": {
                "graphics": self.graphics if self.graphics in GRAPHICS_MODES else "auto",
                "notify": self.notify,
            },
        }
        if self.user_agent and self.user_agent != DEFAULT_USER_AGENT:
            payload["general"]["user_agent"] = self.user_agent
        tmp = self.path.with_suffix(".toml.tmp")
        tmp.write_text(_dump_toml(payload), encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # ----------------------------------------------------------- accessors
    def credential(self, key: str) -> str:
        """Effective value: env var, then user override, then bundled default."""
        env = os.environ.get(f"NETZILLA_{key.upper()}")
        if env and env.strip():
            return env.strip()
        user = (self.credentials.get(key) or "").strip()
        if user:
            return user
        return (self.defaults.get(key) or "").strip()

    def credential_source(self, key: str) -> str:
        """Where the effective value comes from: env | custom | default | none."""
        env = os.environ.get(f"NETZILLA_{key.upper()}")
        if env and env.strip():
            return "env"
        user = (self.credentials.get(key) or "").strip()
        if user and user != self.defaults.get(key):
            return "custom"
        if self.defaults.get(key) or user:
            return "default"
        return "none"

    def has(self, key: str) -> bool:
        return bool(self.credential(key))

    def has_default(self, key: str) -> bool:
        return bool(self.defaults.get(key))

    def set_credential(self, key: str, value: str) -> None:
        """Store an override. Blank, or equal to the default, clears it."""
        if key not in CREDENTIAL_KEYS:
            return
        value = (value or "").strip()
        if not value or value == self.defaults.get(key):
            self.credentials.pop(key, None)
        else:
            self.credentials[key] = value

    def reset_credential(self, key: str) -> None:
        self.credentials.pop(key, None)

    def reset_all_credentials(self) -> None:
        self.credentials.clear()

    @property
    def cache_path(self) -> Path:
        return self.path.parent / "cache.sqlite3"


def _toml_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    text = str(value)
    escaped = (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _dump_toml(payload: dict) -> str:
    """Serialise our flat two-level config dict to TOML.

    The schema is deliberately simple — string/number/bool values one table
    deep — so a short writer removes a whole runtime dependency.
    """
    lines = [
        "# netzilla configuration",
        "# Written by the SETTINGS tab. Keys may also be supplied via",
        "# environment variables named NETZILLA_<KEY IN UPPERCASE>.",
        "",
    ]
    for table, values in payload.items():
        lines.append(f"[{table}]")
        for key, value in values.items():
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")
    return "\n".join(lines)
