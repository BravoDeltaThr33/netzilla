"""Local input validation.

Every text field is validated here before a network call fires, so a typo
fails instantly instead of burning API quota on a request that cannot work.
"""

from __future__ import annotations

import ipaddress
import re


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?[0-9A-Fa-f]{2}){2,5}$")
ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)
PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+-]{1,63}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class ValidationError(ValueError):
    """Raised when user input cannot be used for a lookup."""


def require(value: str, label: str = "Input") -> str:
    value = (value or "").strip()
    if not value:
        raise ValidationError(f"{label} is required.")
    return value


def valid_ip(value: str) -> str:
    """Return a normalised IPv4/IPv6 address or raise."""
    value = require(value, "IP address")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValidationError(f"'{value}' is not a valid IPv4 or IPv6 address.")


def valid_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse CIDR notation, or a bare address treated as a /32 or /128."""
    value = require(value, "Network")
    value = value.replace(" ", "")
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValidationError(f"'{value}' is not a valid network: {exc}")


def valid_domain(value: str) -> str:
    """Accept a bare hostname, or strip scheme/path from a pasted URL."""
    value = require(value, "Domain")
    value = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", value)
    value = value.split("/")[0].split("?")[0].split("#")[0]
    value = value.split("@")[-1]
    if ":" in value and not value.count(":") > 1:
        value = value.split(":")[0]
    value = value.rstrip(".").lower()
    if not DOMAIN_RE.match(value):
        raise ValidationError(f"'{value}' is not a valid domain name.")
    return value


def valid_host(value: str) -> str:
    """An IP address or a domain — whichever parses."""
    value = require(value, "Host")
    try:
        return valid_ip(value)
    except ValidationError:
        pass
    return valid_domain(value)


def valid_url(value: str) -> str:
    value = require(value, "URL")
    scheme = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://", value)
    if not scheme:
        value = "http://" + value
    else:
        # HTTP://EXAMPLE.COM/x is the same URL as http://EXAMPLE.COM/x.
        value = scheme.group(1).lower() + value[len(scheme.group(1)):]
    if not re.match(r"^https?://[^\s/]+", value):
        raise ValidationError(f"'{value}' is not a usable http(s) URL.")
    return value


def valid_mac(value: str) -> str:
    """Normalise a MAC address or OUI to uppercase colon-separated form."""
    value = require(value, "MAC address")
    cleaned = value.strip().replace(".", "")
    # Cisco-style 0011.2233.4455 becomes 001122334455 above.
    if not MAC_RE.match(cleaned):
        raise ValidationError(
            f"'{value}' is not a valid MAC address or OUI. "
            "Try 00:1A:2B:3C:4D:5E, 001A2B3C4D5E or 0011.2233.4455."
        )
    hexonly = re.sub(r"[^0-9A-Fa-f]", "", cleaned).upper()
    if len(hexonly) % 2:
        raise ValidationError(f"'{value}' has an odd number of hex digits.")
    return ":".join(hexonly[i:i + 2] for i in range(0, len(hexonly), 2))


def mac_oui(value: str) -> str:
    """First three octets of a MAC, without separators (e.g. '001A2B')."""
    normalised = valid_mac(value)
    return normalised.replace(":", "")[:6]


def valid_asn(value: str) -> int:
    value = require(value, "ASN")
    match = ASN_RE.match(value.strip())
    if not match:
        raise ValidationError(f"'{value}' is not a valid AS number (try AS15169).")
    return int(match.group(1))


def valid_part_number(value: str) -> str:
    value = require(value, "Part number")
    value = value.strip()
    if not PART_RE.match(value):
        raise ValidationError(f"'{value}' does not look like a hardware part number.")
    return value


def valid_slug(value: str) -> str:
    value = require(value, "Provider").strip().lower().replace(" ", "-")
    if not SLUG_RE.match(value):
        raise ValidationError(
            f"'{value}' is not a valid provider slug (try 'aws' or 'cloudflare')."
        )
    return value


def valid_keyword(value: str, label: str = "Search term") -> str:
    value = require(value, label)
    if len(value) < 2:
        raise ValidationError(f"{label} must be at least 2 characters.")
    if len(value) > 120:
        raise ValidationError(f"{label} is too long (max 120 characters).")
    return value
