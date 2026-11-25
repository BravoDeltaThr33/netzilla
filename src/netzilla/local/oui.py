"""Offline IEEE OUI registry.

netzilla ships the whole IEEE registry — all three block sizes — compressed in
data/oui.csv.gz, so a MAC resolves to its maker instantly, offline and with no
rate limit:

  MA-L   24-bit prefix (the classic "OUI")           ~40,000 vendors
  MA-M   28-bit prefix, a slice of an MA-L block      ~6,600
  MA-S   36-bit prefix, a smaller slice again         ~7,200

The smaller blocks matter more than their numbers suggest. Cheap IoT gear is
very often built by a company that bought a 28- or 36-bit slice rather than a
whole OUI, and a 24-bit-only lookup names those devices "IEEE Registration
Authority" — true, and no help at all. Lookups here try the longest prefix
first, so a slice resolves to the company that actually owns it.

`netzilla --update-oui` downloads a fresh copy of all three registries on your
machine; it lands in ~/.config/netzilla/oui.csv and wins over the bundled one.
"""

from __future__ import annotations

import csv
import gzip
import io
import re
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
BUNDLED = DATA / "oui.csv.gz"

IEEE_URLS = {
    "MA-L": "https://standards-oui.ieee.org/oui/oui.csv",
    "MA-M": "https://standards-oui.ieee.org/oui28/mam.csv",
    "MA-S": "https://standards-oui.ieee.org/oui36/oui36.csv",
}
# Kept for anything that still refers to the single MA-L file.
IEEE_URL = IEEE_URLS["MA-L"]

# Prefix length in hex digits, longest first, and the registry it belongs to.
PREFIX_LENGTHS = ((9, "MA-S"), (7, "MA-M"), (6, "MA-L"))

# What the registry says for a block that has been cut into MA-M/MA-S slices,
# and for a slice whose owner asked not to be listed. Neither names a maker.
NOT_A_VENDOR = {"ieee registration authority", "private"}


def user_table_path() -> Path:
    from ..config import DEFAULT_CONFIG_DIR

    return DEFAULT_CONFIG_DIR / "oui.csv"


def hex_only(mac: str) -> str:
    """'00:1A:2B:3C:4D:5E', '001a.2b3c.4d5e', '00-1A-2B…' -> '001A2B3C4D5E'."""
    return re.sub(r"[^0-9A-Fa-f]", "", mac or "").upper()


def _read_rows(handle) -> dict[str, str]:
    """Rows of either 'PREFIX,Vendor' or the raw IEEE 'Registry,Assignment,
    Organization Name,…' layout (a table from an older --update-oui)."""
    table: dict[str, str] = {}
    for row in csv.reader(handle):
        if len(row) < 2:
            continue
        prefix = hex_only(row[0])
        if len(prefix) in (6, 7, 9):
            vendor = row[1]
        elif len(row) >= 3:
            prefix = hex_only(row[1])
            vendor = row[2]
        else:
            continue
        vendor = " ".join(vendor.split()).strip('"')
        if len(prefix) in (6, 7, 9) and vendor:
            table[prefix] = vendor
    return table


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    """The bundled registry, overlaid with any user-downloaded one."""
    table: dict[str, str] = {}
    if BUNDLED.exists():
        try:
            with gzip.open(BUNDLED, "rt", encoding="utf-8", errors="replace",
                           newline="") as handle:
                table.update(_read_rows(handle))
        except OSError:
            pass
    user = user_table_path()
    if user.exists():
        try:
            with user.open(newline="", encoding="utf-8", errors="replace") as handle:
                table.update(_read_rows(handle))
        except OSError:
            pass
    return table


def reload() -> None:
    _table.cache_clear()


def entry_count() -> int:
    return len(_table())


def match(mac: str) -> tuple[str | None, str]:
    """(vendor, registry) for a MAC or prefix, longest prefix first.

    vendor is None when nothing matches, or when the only match is a
    placeholder ("IEEE Registration Authority", "Private") that names no
    maker; registry then says which of those it was.
    """
    digits = hex_only(mac)
    table = _table()
    placeholder = ""
    for length, registry in PREFIX_LENGTHS:
        if len(digits) < length:
            continue
        vendor = table.get(digits[:length])
        if vendor is None:
            continue
        if vendor.lower() in NOT_A_VENDOR:
            placeholder = placeholder or (
                "private registration" if vendor.lower() == "private"
                else "IEEE sub-allocated block"
            )
            continue
        return vendor, registry
    return None, placeholder


def lookup(oui: str) -> str | None:
    """Vendor for a MAC or its first 3+ bytes, or None."""
    return match(oui)[0]


def lookup_mac(mac: str) -> str | None:
    return match(mac)[0]


def is_locally_administered(mac: str) -> bool:
    """Bit 1 of the first octet: set means a locally assigned address."""
    first = int(hex_only(mac)[:2], 16)
    return bool(first & 0b00000010)


def is_multicast(mac: str) -> bool:
    """Bit 0 of the first octet: set means group/multicast."""
    first = int(hex_only(mac)[:2], 16)
    return bool(first & 0b00000001)


def mac_kind(mac: str) -> str:
    """'global', 'random', 'multicast', or 'invalid'.

    'random' is any locally administered unicast address. In practice, on a
    LAN, that is almost always a phone, tablet or laptop using a private
    ("randomised") Wi-Fi address — iOS, Android, Windows and macOS all do it
    by default now — though VMs and containers use them too.
    """
    digits = hex_only(mac)
    if len(digits) != 12:
        return "invalid"
    if is_multicast(digits):
        return "multicast"
    if is_locally_administered(digits):
        return "random"
    return "global"


MAC_KIND_TEXT = {
    "global": "Globally unique — burned in by the maker",
    "random": "Randomised / locally administered — no maker to look up. "
              "Usually a phone, tablet or laptop using a private Wi-Fi "
              "address; VMs and containers use these too",
    "multicast": "Multicast / group address — not a single device",
    "invalid": "Not a full 6-byte MAC",
}


def describe(mac: str, vendor: str | None, source: str) -> list[tuple[str, object]]:
    digits = hex_only(mac)
    _found, registry = match(digits)
    kind = mac_kind(digits) if len(digits) == 12 else "invalid"
    rows: list[tuple[str, object]] = [
        ("MAC / OUI", mac),
        ("Vendor", vendor or (
            "— randomised address, no maker" if kind == "random"
            else f"Not in the registry ({registry})" if registry
            else "Not found in the OUI registry"
        )),
        ("Lookup source", source),
        ("Registry block", _block(digits) if vendor else registry or "—"),
        ("OUI", digits[:6]),
        ("Device NIC portion", digits[6:] or "— (OUI only)"),
    ]
    if len(digits) == 12:
        rows.append(("Address type", MAC_KIND_TEXT[kind]))
    rows += [
        ("Locally administered", is_locally_administered(digits)),
        ("Multicast / group", is_multicast(digits)),
        ("Unicast", not is_multicast(digits)),
    ]
    return rows


def _block(digits: str) -> str:
    table = _table()
    for length, registry in PREFIX_LENGTHS:
        vendor = table.get(digits[:length]) if len(digits) >= length else None
        if vendor and vendor.lower() not in NOT_A_VENDOR:
            return f"{registry} ({digits[:length]})"
    return "—"


def parse_ieee_csv(text: str) -> dict[str, str]:
    """Prefix -> vendor from one of the IEEE registry CSVs."""
    return _read_rows(io.StringIO(text))


def update_from_ieee(destination: Path | None = None, timeout: float = 120.0) -> int:
    """Download all three IEEE registries. Returns the entry count.

    Called by `netzilla --update-oui` and the MAC tab; runs on the user's
    machine. A registry that fails to download is skipped rather than
    failing the rest — MA-L on its own is still most of the value.
    """
    import httpx

    destination = destination or user_table_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    table: dict[str, str] = {}
    errors = []
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        for registry, url in IEEE_URLS.items():
            try:
                response = client.get(url)
                response.raise_for_status()
            except Exception as exc:          # one registry down is not fatal
                errors.append(f"{registry}: {exc}")
                continue
            table.update(parse_ieee_csv(response.text))

    if not table:
        raise RuntimeError(
            "IEEE registry download produced no usable rows. "
            + "; ".join(errors)
        )

    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        for prefix in sorted(table):
            writer.writerow([prefix, table[prefix]])
    reload()
    return len(table)
