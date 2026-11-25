"""Response cache and API quota tracking.

Both live in one small SQLite file next to config.toml. Standard library only
— no extra dependency for something this simple.

Caching matters here: several of the free tiers netzilla uses are tight
(IP-API 45/min, VirusTotal ~4/min, NVD 5 per 30s without a key), so repeat
lookups of the same target must not burn quota.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path


# Cache lifetimes by data volatility, not by tab.
TTL = {
    "geolocation": 24 * 3600,
    "reputation": 3600,
    "dns": 300,
    "whois": 24 * 3600,
    "tls": 24 * 3600,
    "bgp": 6 * 3600,
    "internetdb": 6 * 3600,
    "cve": 12 * 3600,
    "eosl": 7 * 24 * 3600,
    "status": 30,
    "mac": 30 * 24 * 3600,
    "domain_search": 3600,
}


_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key        TEXT PRIMARY KEY,
    payload    TEXT NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS quota (
    service TEXT NOT NULL,
    ts      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS quota_service_ts ON quota (service, ts);
CREATE TABLE IF NOT EXISTS snapshots (
    kind    TEXT NOT NULL,
    target  TEXT NOT NULL,
    ts      REAL NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS snapshots_kt ON snapshots (kind, target, ts);
CREATE TABLE IF NOT EXISTS bt_trackers (
    ident    TEXT NOT NULL,
    place    TEXT NOT NULL,
    label    TEXT NOT NULL,
    kind     TEXT NOT NULL,
    first_ts REAL NOT NULL,
    last_ts  REAL NOT NULL,
    hits     INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (ident, place)
);
"""

# Bluetooth trackers are remembered this long (BT TRACKERS' history, and the
# "seen on more than one network you were on" check). Most trackers change
# their address daily anyway; nothing else about anyone is kept.
TRACKER_RETENTION = 7 * 24 * 3600


class Store:
    """Thread-safe SQLite store for cached responses and quota counters."""

    def __init__(self, path: Path, enabled: bool = True) -> None:
        self.path = Path(path)
        self.enabled = enabled
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._broken = False

    # ------------------------------------------------------------ plumbing
    def _connect(self) -> sqlite3.Connection | None:
        if self._broken:
            return None
        if self._conn is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._conn = sqlite3.connect(
                    self.path, check_same_thread=False, timeout=5.0
                )
                self._conn.executescript(_SCHEMA)
                self._conn.commit()
            except Exception:
                # Cache is best-effort. A broken store must never break the app.
                self._broken = True
                self._conn = None
        return self._conn

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None

    # --------------------------------------------------------------- cache
    def get(self, key: str):
        if not self.enabled:
            return None
        with self._lock:
            conn = self._connect()
            if conn is None:
                return None
            try:
                row = conn.execute(
                    "SELECT payload, expires_at FROM cache WHERE key = ?", (key,)
                ).fetchone()
            except Exception:
                return None
        if not row:
            return None
        payload, expires_at = row
        if expires_at < time.time():
            self.delete(key)
            return None
        try:
            return json.loads(payload)
        except (TypeError, ValueError):
            return None

    def set(self, key: str, value, ttl_seconds: float) -> None:
        if not self.enabled or ttl_seconds <= 0:
            return
        try:
            payload = json.dumps(value)
        except (TypeError, ValueError):
            return
        with self._lock:
            conn = self._connect()
            if conn is None:
                return
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO cache (key, payload, expires_at) "
                    "VALUES (?, ?, ?)",
                    (key, payload, time.time() + ttl_seconds),
                )
                conn.commit()
            except Exception:
                pass

    def delete(self, key: str) -> None:
        with self._lock:
            conn = self._connect()
            if conn is None:
                return
            try:
                conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                conn.commit()
            except Exception:
                pass

    def clear_cache(self) -> int:
        with self._lock:
            conn = self._connect()
            if conn is None:
                return 0
            try:
                cur = conn.execute("DELETE FROM cache")
                conn.commit()
                return cur.rowcount or 0
            except Exception:
                return 0

    def cache_size(self) -> int:
        with self._lock:
            conn = self._connect()
            if conn is None:
                return 0
            try:
                row = conn.execute("SELECT COUNT(*) FROM cache").fetchone()
                return int(row[0]) if row else 0
            except Exception:
                return 0

    # --------------------------------------------------------------- quota
    def record_call(self, service: str) -> None:
        with self._lock:
            conn = self._connect()
            if conn is None:
                return
            try:
                now = time.time()
                conn.execute(
                    "INSERT INTO quota (service, ts) VALUES (?, ?)", (service, now)
                )
                # Keep eight days: long enough for GreyNoise's weekly window,
                # short enough that the table never grows unbounded.
                conn.execute("DELETE FROM quota WHERE ts < ?", (now - 8 * 86400,))
                conn.commit()
            except Exception:
                pass

    def count_calls(self, service: str, window_seconds: float) -> int:
        with self._lock:
            conn = self._connect()
            if conn is None:
                return 0
            try:
                row = conn.execute(
                    "SELECT COUNT(*) FROM quota WHERE service = ? AND ts >= ?",
                    (service, time.time() - window_seconds),
                ).fetchone()
                return int(row[0]) if row else 0
            except Exception:
                return 0

    # ----------------------------------------------------------- snapshots
    def add_snapshot(self, kind: str, target: str, payload) -> None:
        """Persist a point-in-time observation (a traceroute, a BGP origin)."""
        try:
            blob = json.dumps(payload)
        except (TypeError, ValueError):
            return
        with self._lock:
            conn = self._connect()
            if conn is None:
                return
            try:
                now = time.time()
                conn.execute(
                    "INSERT INTO snapshots (kind, target, ts, payload) "
                    "VALUES (?, ?, ?, ?)",
                    (kind, target, now, blob),
                )
                # Keep the last 50 snapshots per (kind, target).
                conn.execute(
                    "DELETE FROM snapshots WHERE kind = ? AND target = ? AND ts NOT IN "
                    "(SELECT ts FROM snapshots WHERE kind = ? AND target = ? "
                    "ORDER BY ts DESC LIMIT 50)",
                    (kind, target, kind, target),
                )
                conn.commit()
            except Exception:
                pass

    def snapshots(self, kind: str, target: str, limit: int = 10) -> list[tuple[float, object]]:
        """Most-recent-first list of (timestamp, payload) for a target."""
        with self._lock:
            conn = self._connect()
            if conn is None:
                return []
            try:
                rows = conn.execute(
                    "SELECT ts, payload FROM snapshots WHERE kind = ? AND target = ? "
                    "ORDER BY ts DESC LIMIT ?",
                    (kind, target, limit),
                ).fetchall()
            except Exception:
                return []
        out = []
        for ts, blob in rows:
            try:
                out.append((ts, json.loads(blob)))
            except (TypeError, ValueError):
                continue
        return out

    # -------------------------------------------------- bluetooth trackers
    def tracker_seen(self, ident: str, place: str, label: str, kind: str,
                     ts: float | None = None) -> None:
        """Note that tracker `ident` was heard while this machine was at
        `place` (a network fingerprint; `label` is its readable name)."""
        now = time.time() if ts is None else ts
        with self._lock:
            conn = self._connect()
            if conn is None:
                return
            try:
                conn.execute(
                    "INSERT INTO bt_trackers (ident, place, label, kind, first_ts, last_ts, hits) "
                    "VALUES (?, ?, ?, ?, ?, ?, 1) "
                    "ON CONFLICT(ident, place) DO UPDATE SET last_ts = excluded.last_ts, "
                    "label = excluded.label, kind = excluded.kind, hits = hits + 1",
                    (ident, place, label, kind, now, now),
                )
                conn.execute("DELETE FROM bt_trackers WHERE last_ts < ?",
                             (now - TRACKER_RETENTION,))
                conn.commit()
            except Exception:
                pass

    def tracker_places(self, ident: str) -> list[tuple[str, str, float, float, int]]:
        """(place key, place label, first heard, last heard, sightings) for
        one tracker, most recent first."""
        with self._lock:
            conn = self._connect()
            if conn is None:
                return []
            try:
                rows = conn.execute(
                    "SELECT place, label, first_ts, last_ts, hits FROM bt_trackers "
                    "WHERE ident = ? AND last_ts >= ? ORDER BY last_ts DESC",
                    (ident, time.time() - TRACKER_RETENTION),
                ).fetchall()
            except Exception:
                return []
        return [(str(a), str(b), float(c), float(d), int(e)) for a, b, c, d, e in rows]

    def trackers_logged(self) -> list[dict]:
        """Every tracker remembered: kind, places, first and last heard."""
        with self._lock:
            conn = self._connect()
            if conn is None:
                return []
            try:
                rows = conn.execute(
                    "SELECT ident, kind, place, label, first_ts, last_ts, hits FROM bt_trackers "
                    "WHERE last_ts >= ? ORDER BY ident, last_ts DESC",
                    (time.time() - TRACKER_RETENTION,),
                ).fetchall()
            except Exception:
                return []
        out: dict[str, dict] = {}
        for ident, kind, place, label, first, last, hits in rows:
            entry = out.setdefault(ident, {"ident": ident, "kind": kind, "places": [],
                                           "labels": [], "first": first, "last": last,
                                           "hits": 0})
            entry["places"].append(place)
            if label not in entry["labels"]:
                entry["labels"].append(label)
            entry["first"] = min(entry["first"], first)
            entry["last"] = max(entry["last"], last)
            entry["hits"] += hits
        return sorted(out.values(), key=lambda e: (-len(e["places"]), -e["last"]))

    def snapshot_targets(self, kind: str) -> list[str]:
        with self._lock:
            conn = self._connect()
            if conn is None:
                return []
            try:
                rows = conn.execute(
                    "SELECT DISTINCT target FROM snapshots WHERE kind = ? ORDER BY target",
                    (kind,),
                ).fetchall()
                return [r[0] for r in rows]
            except Exception:
                return []


# Per-service published free-tier limits, used for the quota readout.
# (label, window in seconds, limit or None when the service publishes none)
QUOTA_LIMITS: dict[str, tuple[str, float, int | None]] = {
    "ip-api":       ("IP-API",       60,    45),
    "abuseipdb":    ("AbuseIPDB",    86400, 1000),
    "abuseipdb-block": ("AbuseIPDB /24", 86400, 100),
    "virustotal":   ("VirusTotal",   60,    4),
    "virustotal-day": ("VirusTotal day", 86400, 500),
    # 50 lookups per week, shared with the GreyNoise web Visualizer.
    "greynoise":    ("GreyNoise",    7 * 86400, 50),
    "iplogs":       ("IPLogs",       60,    None),
    "ssllabs":      ("SSL Labs",     3600,  None),
    "ripestat":     ("RIPEstat",     60,    None),
    "urlhaus":      ("URLhaus",      60,    None),
    "nvd":          ("NVD",          30,    5),
    "shodan-idb":   ("Shodan IDB",   60,    None),
    "macvendors":   ("MACVendors",   60,    None),
    "outagedeck":   ("OutageDeck",   3600,  120),
    "eosl":         ("EOSL.ai",      60,    None),
    # v2.0 sources — all keyless or fair-use, no published hard limit.
    "rdap":         ("RDAP",         60,    None),
    "doh":          ("DoH resolvers", 60,   None),
    "crtsh":        ("crt.sh",       60,    None),
    "threatfox":    ("ThreatFox",    60,    None),
    "malwarebazaar": ("MalwareBazaar", 60,  None),
    "feodo":        ("Feodo Tracker", 3600, None),
    "sslbl":        ("SSLBL",        3600,  None),
    "kev":          ("CISA KEV",     3600,  None),
    "pwnedpw":      ("Pwned Passwords", 60, None),
    "hibp":         ("HIBP breaches", 60,   None),
    # 4.0 sources — free and keyless.
    "epss":         ("FIRST EPSS",   60,    None),
    "endoflife":    ("endoflife.date", 60,  None),
    "cloudflare-speed": ("Cloudflare speed", 3600, None),
}

# Quota rows that count another service's calls over a different window.
QUOTA_COUNTS_AS: dict[str, str] = {
    "virustotal-day": "virustotal",
}
