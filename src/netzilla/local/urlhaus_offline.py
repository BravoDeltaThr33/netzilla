"""Offline URLhaus snapshot.

netzilla ships a compressed copy of the URLhaus database dump so URL and host
checks keep working with no network, no Auth-Key and no rate limit. The live
API (clients/urlhaus.py) is still preferred when it is reachable — the
snapshot is the fallback, and is labelled with its age wherever it is used.

Files, newest wins:
    data/urlhaus_snapshot.csv.gz            bundled with netzilla
    ~/.config/netzilla/urlhaus.csv.gz       written by --import-urlhaus / --update-urlhaus

Accepted import formats (all published by abuse.ch):
    * the full JSON dump   {"<id>": [{"url", "url_status", "threat", "tags",
                                       "dateadded", "last_online", "reporter",
                                       "urlhaus_link"}], ...}
    * the same JSON inside a .zip
    * the plain-text URL list (one URL per line, '#' comments)

Snapshot CSV columns:
    id, url, url_status, threat, tags(|-joined), date_added, last_online, reporter
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import zipfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

BUNDLED = Path(__file__).resolve().parent.parent / "data" / "urlhaus_snapshot.csv.gz"
DOWNLOAD_URL = "https://urlhaus.abuse.ch/downloads/json/"

# Hosts that serve content for millions of unrelated users. A URLhaus hit on
# the host alone says very little — only the exact URL matters there.
SHARED_PLATFORMS = {
    "raw.githubusercontent.com", "github.com", "objects.githubusercontent.com",
    "gitlab.com", "bitbucket.org", "cdn.discordapp.com", "discord.com",
    "drive.google.com", "docs.google.com", "storage.googleapis.com",
    "firebasestorage.googleapis.com", "dropbox.com", "www.dropbox.com",
    "dl.dropboxusercontent.com", "onedrive.live.com", "1drv.ms",
    "img1.wsimg.com", "pastebin.com", "transfer.sh", "files.catbox.moe",
    "s3.amazonaws.com", "blob.core.windows.net", "mediafire.com",
    "www.mediafire.com", "t.me", "cdn.jsdelivr.net",
}


def user_snapshot_path() -> Path:
    from ..config import DEFAULT_CONFIG_DIR

    return DEFAULT_CONFIG_DIR / "urlhaus.csv.gz"


@dataclass(frozen=True)
class Entry:
    id: str
    url: str
    url_status: str
    threat: str
    tags: tuple[str, ...]
    date_added: str
    last_online: str
    reporter: str

    @property
    def host(self) -> str:
        return host_of(self.url)

    def as_api_dict(self) -> dict:
        """Shape it like a URLhaus API url entry so one renderer serves both."""
        return {
            "id": self.id,
            "url": self.url,
            "url_status": self.url_status,
            "threat": self.threat,
            "tags": list(self.tags),
            "date_added": self.date_added,
            "last_online": self.last_online,
            "reporter": self.reporter,
            "urlhaus_reference": (
                f"https://urlhaus.abuse.ch/url/{self.id}/" if self.id else ""
            ),
        }


class Snapshot:
    """The loaded snapshot. Its counts are ready at once; the URL and host
    indexes (two URL parses per entry) are built on the first lookup, so the
    DASH tab's "56,193 URLs, newest …" line costs almost nothing."""

    def __init__(self, entries: list[Entry], path: Path | None) -> None:
        self.path = path
        self._entries = entries
        self._by_url: dict[str, list[Entry]] | None = None
        self._by_host: dict[str, list[Entry]] | None = None
        self.count = len(entries)
        self.online = sum(1 for e in entries if e.url_status == "online")
        dates = [e.date_added for e in entries if e.date_added]
        self.newest = max(dates) if dates else ""
        self.oldest = min(dates) if dates else ""

    def _index(self) -> None:
        by_url: dict[str, list[Entry]] = {}
        by_host: dict[str, list[Entry]] = {}
        for entry in self._entries:
            normal, host = _normal_and_host(entry.url)
            by_url.setdefault(normal, []).append(entry)
            by_host.setdefault(host, []).append(entry)
        self._by_url, self._by_host = by_url, by_host

    @property
    def by_url(self) -> dict[str, list[Entry]]:
        if self._by_url is None:
            self._index()
        return self._by_url  # type: ignore[return-value]

    @property
    def by_host(self) -> dict[str, list[Entry]]:
        if self._by_host is None:
            self._index()
        return self._by_host  # type: ignore[return-value]

    def lookup_url(self, url: str) -> list[Entry]:
        return list(self.by_url.get(normalise_url(url), []))

    def lookup_host(self, host: str) -> list[Entry]:
        return list(self.by_host.get(host.strip().lower().rstrip("."), []))

    def describe(self) -> list[tuple[str, object]]:
        return [
            ("Snapshot file", str(self.path) if self.path else "none"),
            ("URLs recorded", f"{self.count:,}"),
            ("Still online at capture", f"{self.online:,}"),
            ("Distinct hosts", f"{len(self.by_host):,}"),
            ("Newest entry", self.newest or "—"),
            ("Oldest entry", self.oldest or "—"),
        ]


# ---------------------------------------------------------------- helpers
def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _normal_and_host(url: str) -> tuple[str, str]:
    """normalise_url() and host_of() from a single parse."""
    url = (url or "").strip()
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return url, ""
    if not parts.scheme or not parts.netloc:
        return url, host
    normal = f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path or '/'}" + (
        f"?{parts.query}" if parts.query else ""
    )
    return normal, host


def normalise_url(url: str) -> str:
    """Match URLs the way people paste them: scheme and host case-insensitive."""
    url = (url or "").strip()
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.scheme or not parts.netloc:
        return url
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path or '/'}" + (
        f"?{parts.query}" if parts.query else ""
    )


def is_shared_platform(host: str) -> bool:
    host = host.lower()
    return host in SHARED_PLATFORMS or any(
        host.endswith("." + shared) for shared in SHARED_PLATFORMS
    )


# ---------------------------------------------------------------- loading
def active_path() -> Path | None:
    user = user_snapshot_path()
    if user.exists():
        return user
    if BUNDLED.exists():
        return BUNDLED
    return None


@lru_cache(maxsize=1)
def snapshot() -> Snapshot:
    path = active_path()
    if path is None:
        return Snapshot([], None)
    try:
        with gzip.open(path, "rt", encoding="utf-8", newline="") as handle:
            entries = [
                Entry(
                    id=row[0], url=row[1], url_status=row[2], threat=row[3],
                    tags=tuple(t for t in row[4].split("|") if t),
                    date_added=row[5], last_online=row[6], reporter=row[7],
                )
                for row in csv.reader(handle)
                if len(row) >= 8
            ]
    except (OSError, EOFError, csv.Error):
        return Snapshot([], path)
    return Snapshot(entries, path)


def reload() -> None:
    snapshot.cache_clear()


# ---------------------------------------------------------------- importing
def parse_dump(raw: bytes) -> list[Entry]:
    """Parse any supported abuse.ch export into entries."""
    if raw[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = [n for n in archive.namelist() if not n.endswith("/")]
            if not names:
                raise ValueError("The zip archive is empty.")
            raw = archive.read(names[0])

    text = raw.decode("utf-8", "replace").lstrip("﻿")
    stripped = text.lstrip()
    if stripped.startswith("{"):
        return _parse_json_dump(json.loads(stripped))
    return _parse_text_list(text)


def _parse_json_dump(data: dict) -> list[Entry]:
    entries = []
    for entry_id, records in data.items():
        for record in records if isinstance(records, list) else [records]:
            if not isinstance(record, dict) or not record.get("url"):
                continue
            entries.append(
                Entry(
                    id=str(entry_id),
                    url=str(record["url"]),
                    url_status=str(record.get("url_status") or "unknown"),
                    threat=str(record.get("threat") or "malware_download"),
                    tags=tuple(str(t) for t in (record.get("tags") or [])),
                    date_added=str(record.get("dateadded") or "")[:19],
                    last_online=str(record.get("last_online") or "")[:19],
                    reporter=str(record.get("reporter") or ""),
                )
            )
    if not entries:
        raise ValueError("No URL records found in that JSON file.")
    return entries


def _parse_text_list(text: str) -> list[Entry]:
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "://" not in line:
            continue
        entries.append(
            Entry(
                id="", url=line, url_status="listed", threat="malware_download",
                tags=(), date_added="", last_online="", reporter="",
            )
        )
    if not entries:
        raise ValueError("No URLs found — is this a URLhaus export?")
    return entries


def write_snapshot(entries: list[Entry], destination: Path) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_suffix(".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8", newline="", compresslevel=9) as handle:
        writer = csv.writer(handle)
        for e in entries:
            writer.writerow([
                e.id, e.url, e.url_status, e.threat, "|".join(e.tags),
                e.date_added, e.last_online, e.reporter,
            ])
    tmp.replace(destination)
    reload()
    return len(entries)


def import_file(source: Path, destination: Path | None = None) -> int:
    """Import a URLhaus export saved on disk. Returns the entry count."""
    entries = parse_dump(Path(source).read_bytes())
    return write_snapshot(entries, destination or user_snapshot_path())


def update_from_abusech(auth_key: str = "", timeout: float = 180.0) -> int:
    """Download the current dump from abuse.ch and replace the user snapshot."""
    import httpx

    headers = {"Auth-Key": auth_key} if auth_key else {}
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(DOWNLOAD_URL, headers=headers)
        response.raise_for_status()
    return write_snapshot(parse_dump(response.content), user_snapshot_path())
