"""Route/path change history — snapshot a target's path or origin, diff it.

Two kinds of snapshot are stored (in the SQLite Store, table `snapshots`):

  kind="path"   the ordered list of traceroute hop IPs to a destination
  kind="origin" the origin AS(es) and covering prefix for an address

Taking a snapshot now and comparing it to the previous one flags silent
reroutes, a new transit provider appearing mid-path, or — for origin — a
prefix suddenly announced from a different AS, the fingerprint of a BGP hijack.
The diff functions are pure and unit-tested; persistence lives in the Store.
"""

from __future__ import annotations

import time


def diff_path(old: list[str], new: list[str]) -> dict:
    """Compare two ordered hop lists (IP strings, '*' for no-reply hops)."""
    changed = old != new
    added = [h for h in new if h not in old and h != "*"]
    removed = [h for h in old if h not in new and h != "*"]
    # First hop where the two paths diverge (ignoring '*' timeouts).
    diverge_at = None
    for i, (a, b) in enumerate(zip(old, new)):
        if a != b and a != "*" and b != "*":
            diverge_at = i + 1
            break
    return {
        "changed": changed,
        "added": added,
        "removed": removed,
        "diverge_at_hop": diverge_at,
        "old_len": len(old),
        "new_len": len(new),
    }


def diff_origin(old: dict, new: dict) -> dict:
    """Compare two origin snapshots ({'asns': [...], 'prefix': '...'})."""
    old_asns = set(str(a) for a in (old.get("asns") or []))
    new_asns = set(str(a) for a in (new.get("asns") or []))
    return {
        "changed": old_asns != new_asns or old.get("prefix") != new.get("prefix"),
        "asn_added": sorted(new_asns - old_asns),
        "asn_removed": sorted(old_asns - new_asns),
        "prefix_changed": old.get("prefix") != new.get("prefix"),
        "old_prefix": old.get("prefix"),
        "new_prefix": new.get("prefix"),
        "hijack_suspect": bool(new_asns and old_asns and not (new_asns & old_asns)),
    }


def path_verdict(diff: dict) -> tuple[str, str]:
    if not diff["changed"]:
        return "UNCHANGED — path matches the previous snapshot", "ok"
    where = f" at hop {diff['diverge_at_hop']}" if diff["diverge_at_hop"] else ""
    return f"PATH CHANGED{where} — {len(diff['added'])} new hop(s)", "warn"


def origin_verdict(diff: dict) -> tuple[str, str]:
    if not diff["changed"]:
        return "UNCHANGED — same origin AS and prefix as before", "ok"
    if diff["hijack_suspect"]:
        return (
            "ORIGIN CHANGED — announced from a completely different AS "
            f"({', '.join(diff['asn_removed'])} → {', '.join(diff['asn_added'])}). "
            "Possible hijack; verify before trusting.",
            "bad",
        )
    return "ORIGIN CHANGED — AS or prefix differs from the previous snapshot", "warn"


def ago(ts: float, now: float | None = None) -> str:
    now = now if now is not None else time.time()
    delta = max(0, now - ts)
    if delta < 90:
        return f"{int(delta)}s ago"
    if delta < 5400:
        return f"{int(delta // 60)}m ago"
    if delta < 129600:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // 86400)}d ago"
