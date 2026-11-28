"""Command-line entry point.

    netzilla                       launch the full TUI
    netzilla --theme amber-phosphor
    netzilla --tab wifi            open on a tab (its name, any case)
    netzilla --graphics text       force text graphs (auto | pixel | text)
    netzilla --terminal            show what netzilla detects about this terminal
    netzilla --window              netzilla in a window of its own (needs tkinter)
    netzilla --offline             local tools only, no network calls
    netzilla ip 8.8.8.8 --json     one-shot scriptable lookup, no TUI
    netzilla subnet 10.0.0.0/22
    netzilla urlhaus example.com   live URLhaus, falling back to the snapshot
    netzilla hash <sha256>         VirusTotal file verdict by hash
    netzilla block 203.0.113.0/24  AbuseIPDB reputation for a whole /24
    netzilla sweep                 every device on this machine's LAN, identified
    netzilla sweep 10.0.0.0/24     … or on a subnet you name
    netzilla identify 10.0.0.185   everything netzilla can learn about one device
    netzilla software "panos 10.2" is that software release still supported?
    netzilla --update-oui          refresh the IEEE OUI table
    netzilla --update-urlhaus      refresh the offline URLhaus snapshot
    netzilla --import-urlhaus F    load a URLhaus dump you downloaded yourself
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from . import __version__
from .config import Config
from .themes import THEME_NAMES

ONE_SHOT = {
    "ip", "subnet", "mac", "dns", "asn", "status", "eol", "software",
    "urlhaus", "hash", "block", "sweep", "identify",
}
# One-shots that work without a target.
NO_TARGET = {"status", "sweep"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netzilla",
        description="Retro terminal toolkit for network administrators.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # Commands, themes and tab names are matched in any case: IP, Ip and ip
    # are the same command, and --tab WIFI opens the WIFI tab.
    parser.add_argument(
        "command", nargs="?", choices=sorted(ONE_SHOT), type=str.lower,
        help="run a single lookup and exit instead of opening the TUI",
    )
    parser.add_argument("target", nargs="?", help="the value to look up")
    parser.add_argument(
        "--theme", choices=THEME_NAMES, type=str.lower,
        help="start with a specific colour theme",
    )
    parser.add_argument(
        "--tab", help="open on a specific tab, by name in any case: wifi, DNS, lifecycle…"
    )
    parser.add_argument(
        "--graphics", choices=("auto", "pixel", "text"), type=str.lower,
        help="draw graphs as pixels (kitty, Ghostty, Windows Terminal, WezTerm), "
             "as text, or decide automatically (the default; also set on the "
             "SETTINGS tab)",
    )
    parser.add_argument(
        "--no-probe", action="store_true",
        help="don't ask the terminal what it is at start-up (environment only)",
    )
    parser.add_argument(
        "--terminal", action="store_true",
        help="print what netzilla detects about this terminal and exit",
    )
    parser.add_argument(
        "--window", action="store_true",
        help="open netzilla in a window of its own instead of this terminal, drawn "
             "as in a pixel-graphics terminal with a CRT glow (needs tkinter; "
             "netzilla --window --help lists its options)",
    )
    parser.add_argument("--config", help="path to an alternative config.toml")
    parser.add_argument(
        "--offline", action="store_true",
        help="disable all network calls; local tools keep working",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="with a one-shot command, print raw JSON for piping",
    )
    parser.add_argument(
        "--update-oui", action="store_true",
        help="download the full IEEE OUI registry and exit",
    )
    parser.add_argument(
        "--update-urlhaus", action="store_true",
        help="download the current URLhaus dump (uses your abuse.ch Auth-Key) and exit",
    )
    parser.add_argument(
        "--import-urlhaus", metavar="FILE",
        help="import a URLhaus dump from disk (.json, .zip or plain-text list) and exit",
    )
    # netzilla no longer bundles API keys, so there is nothing left to ignore.
    # The flag is still accepted, and does nothing, so existing scripts and
    # aliases keep working.
    parser.add_argument(
        "--no-default-keys", action="store_true", help=argparse.SUPPRESS,
    )
    parser.add_argument("--version", action="version", version=f"netzilla {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    words = sys.argv[1:] if argv is None else list(argv)
    if "--window" in words:
        # The window has options of its own (--font-size, --no-crt…).
        from .window import main as window_main

        return window_main([word for word in words if word != "--window"])
    _safe_streams()
    try:
        return _main(argv)
    except BrokenPipeError:
        # Output piped into something that stopped reading early
        # (netzilla dns example.com | head -3): not an error worth a
        # traceback. Point stdout at /dev/null so the final flush is quiet.
        import os

        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return 1


def _safe_streams() -> None:
    """A Windows console or pipe may use a legacy code page that has no '—'
    or '→'; print a '?' for such a character rather than stop with a
    UnicodeEncodeError."""
    from . import hostos

    if not hostos.is_windows():
        return
    for stream in (sys.stdout, sys.stderr):
        try:
            if (stream.encoding or "").lower().replace("-", "") != "utf8":
                stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def _main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.terminal:
        return _terminal_report(args)
    if args.update_oui:
        return _update_oui()
    if args.import_urlhaus:
        return _import_urlhaus(args.import_urlhaus)
    if args.update_urlhaus:
        return _update_urlhaus(args)

    if args.command:
        if not args.target and args.command not in NO_TARGET:
            print(f"netzilla {args.command}: a target is required", file=sys.stderr)
            return 2
        return asyncio.run(_one_shot(args))

    from . import termcaps
    from .app import TABS, NetzillaApp, resolve_tab

    if args.tab and resolve_tab(args.tab) is None:
        names = ", ".join(label.lower() for _id, label, _cls in TABS)
        parser.error(f"unknown tab '{args.tab}' — choose from: {names}")

    # Ask the terminal what it is before the interface takes over the screen.
    termcaps.startup(allow_probe=not args.no_probe)

    app = NetzillaApp(
        config_path=args.config,
        theme_name=args.theme,
        offline=args.offline,
        start_tab=args.tab,
        graphics=args.graphics,
    )
    app.run()
    return 0


def _terminal_report(args) -> int:
    """`netzilla --terminal`: the detection, spelled out."""
    from . import termcaps

    info = termcaps.startup(allow_probe=not args.no_probe)
    config = Config.load(args.config)
    setting = args.graphics or config.graphics
    mode = info.graphics_mode(setting)
    cell = f"{info.cell_px[0]} x {info.cell_px[1]} px" if info.cell_px else "not reported"
    rows = [
        ("Terminal", info.where),
        ("Identified by", info.identified_by + (" (asked the terminal)" if info.probed else
                                                " (it was not asked)")),
        ("Truecolour", "yes" if info.truecolor else "no"),
        ("kitty graphics", "yes" if info.kitty_graphics else "no"),
        ("Unicode placeholders", "yes" if info.placeholders else "no"),
        ("Sixel", "yes" if info.sixel else "no"),
        ("Pixel graphs use", "Sixel" if info.image_protocol() == "sixel"
         else "kitty graphics protocol"),
        ("Cell size", cell),
        ("Hyperlinks", "yes" if info.hyperlinks else "no"),
        ("Clipboard (OSC 52)", "yes" if info.clipboard else "no / unknown"),
        ("Notifications", info.notify or "none"),
        ("Graphics setting", setting),
        ("Graphs will be drawn as", mode),
        ("Why", info.graphics_reason()),
    ]
    width = max(len(k) for k, _v in rows)
    for key, value in rows:
        print(f"{key.ljust(width)}  {value}")
    return 0


# --------------------------------------------------------------- one-shot
async def _one_shot(args) -> int:
    from .services import Services

    config = Config.load(args.config)
    services = Services(config, offline=args.offline)
    try:
        payload = await _dispatch(services, args.command, args.target or "")
    finally:
        await services.aclose()

    if payload is None:
        return 1
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        _print_plain(payload)
    return 0


async def _dispatch(services, command: str, target: str):
    from .clients import (
        abuseipdb, eosl, ip_api, macvendors, outagedeck, ripestat, urlhaus,
        virustotal,
    )
    from .local import dns_whois, oui, subnet
    from .validators import (
        ValidationError, mac_oui, valid_asn, valid_host, valid_ip,
        valid_mac, valid_network, valid_part_number,
    )

    try:
        if command == "ip":
            result = await ip_api.lookup(services, valid_ip(target))
            return result.data if result.ok else _fail(result.error)

        if command == "subnet":
            network = valid_network(target)
            return dict(subnet.describe(network))

        if command == "mac":
            mac = valid_mac(target)
            vendor, registry = oui.match(mac)
            kind = oui.mac_kind(mac) if len(oui.hex_only(mac)) == 12 else "prefix"
            source = f"local ({registry})" if vendor else "local"
            if vendor is None and kind != "random":
                remote = await macvendors.lookup(services, mac)
                vendor = remote.data if remote.ok else None
                source = "macvendors.com" if remote.ok else "not found"
            return {"mac": mac, "oui": mac_oui(mac), "vendor": vendor,
                    "address_type": kind, "source": source}

        if command == "sweep":
            return await _sweep(target)

        if command == "identify":
            from .local import devices

            dev = await devices.profile(valid_ip(target))
            return _device_record(dev) | {
                "open_ports": dev.get("open_ports", []),
                "banners": dev.get("banners", {}),
                "profile": dict(devices.profile_rows(dev)),
            }

        if command == "dns":
            host = valid_host(target)
            from .local.runner import have

            if not have("dig"):
                from .clients import doh

                answers = await doh.resolve_many(services, host, dns_whois.RECORD_TYPES)
                return {
                    rtype: (r.data.get("answers", []) if r.ok else [f"error: {r.error}"])
                    for rtype, r in answers.items()
                } | {"via": "DNS-over-HTTPS (Cloudflare) — dig is not installed"}
            records = await dns_whois.all_records(host)
            return {
                rtype: [line for line in r.output.splitlines() if line]
                for rtype, r in records.items()
            }

        if command == "asn":
            asn = valid_asn(target)
            result = await ripestat.as_overview(services, asn)
            return result.data if result.ok else _fail(result.error)

        if command == "status":
            slugs = [s.strip() for s in (target or "aws,cloudflare,github").split(",")]
            results = await outagedeck.check_many(services, slugs)
            return {
                slug: (outagedeck.normalise(r.data) if r.ok else {"error": r.error})
                for slug, r in zip(slugs, results)
            }

        if command == "software":
            from .clients import endoflife

            query, version = endoflife.split_query(target)
            index = await endoflife.products(services)
            if not index.ok:
                return _fail(index.error)
            hits = endoflife.find_products(index.data, query)
            if not hits:
                return _fail(f"endoflife.date has no product matching '{query}'")
            if not endoflife.is_exact(hits[0], query) and len(hits) > 1:
                return {"matches": [h.get("name") for h in hits],
                        "note": "several products match — name one, e.g. "
                                f"netzilla software \"{hits[0].get('name')} <version>\""}
            result = await endoflife.product(services, hits[0]["name"])
            if not result.ok:
                return _fail(result.error)
            releases = [r for r in result.data.get("releases") or [] if isinstance(r, dict)]
            payload = {"product": result.data.get("label") or hits[0]["name"]}
            if version:
                release = endoflife.match_release(releases, version)
                if release is None:
                    payload["version"] = version
                    payload["status"] = "no matching release cycle"
                else:
                    text, _state = endoflife.release_state(release)
                    payload.update({"version": version, "release": release.get("name"),
                                    "status": text,
                                    "support_ends": release.get("eoasFrom"),
                                    "end_of_life": release.get("eolFrom")})
            payload["releases"] = [
                dict(zip(["release", "released", "support_ends", "end_of_life",
                          "latest", "status"], row))
                for row in endoflife.release_rows(releases, limit=10)
            ]
            return payload

        if command == "eol":
            part = valid_part_number(target)
            result = await eosl.part_status(services, part)
            return (
                {"part": part.upper(), "status": result.data}
                if result.ok
                else _fail(result.error)
            )
        if command == "urlhaus":
            if "://" in target or "/" in target:
                from .validators import valid_url

                result = await urlhaus.check_url(services, valid_url(target))
            else:
                result = await urlhaus.check_host(services, valid_host(target))
            if not result.ok:
                return _fail(result.error)
            verdict, _ = urlhaus.verdict(result.data)
            return {
                "verdict": verdict,
                "source": result.data.get("source", "live"),
                "note": result.note,
                **{k: v for k, v in result.data.items() if k != "source"},
            }

        if command == "hash":
            if not virustotal.is_hash(target):
                return _fail("Expected an MD5, SHA-1 or SHA-256 hash.")
            result = await virustotal.check_file(services, target)
            if not result.ok:
                return _fail(result.error)
            verdict, _ = virustotal.verdict(result.data)
            return {"verdict": verdict, **dict(virustotal.file_summary(result.data))}

        if command == "block":
            result = await abuseipdb.check_block(services, target)
            if not result.ok:
                return _fail(result.error)
            verdict, _ = abuseipdb.block_verdict(result.data)
            return {
                "verdict": verdict,
                **dict(abuseipdb.block_summary(result.data)),
                "reported": [
                    dict(zip(["address", "score", "reports", "latest", "country"], row))
                    for row in abuseipdb.block_rows(result.data)
                ],
            }
    except ValidationError as exc:
        return _fail(str(exc))
    return _fail(f"Unknown command '{command}'.")


async def _sweep(target: str):
    from .local import devices, lan
    from .validators import ValidationError, valid_network

    context = await devices.local_context()
    note = ""
    if not target:
        target, note = devices.suggest_sweep(context)
        if not target:
            return _fail("could not work out this machine's subnet; give one, "
                         "e.g. netzilla sweep 192.168.1.0/24")
    network = valid_network(target)
    try:
        result = await lan.sweep(str(network))
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    except FileNotFoundError:
        from . import hostos

        return _fail("ping is not installed (sudo apt install iputils-ping)"
                     if hostos.is_linux() else "ping was not found on this PATH")
    live = result["live"]
    found = await devices.identify(
        live + result.get("arp_only", []), context=context,
        use_ssdp=devices.is_local_network(network, context),
    )
    records = []
    for index, dev in enumerate(found):
        records.append(_device_record(dev) | {"answered_ping": index < len(live)})
    payload = {"network": result["cidr"], "scanned": result["scanned"],
               "alive": len(live), "devices": records}
    if note:
        payload["note"] = note
    return payload


def _device_record(dev: dict) -> dict:
    from .local import devices

    return {
        "ip": dev["ip"],
        "mac": dev.get("mac") or None,
        "vendor": dev.get("vendor") or None,
        "address_type": dev.get("mac_kind"),
        "hostname": dev.get("hostname") or None,
        "friendly_name": dev.get("friendly") or None,
        "model": dev.get("model") or (dev.get("upnp") or {}).get("modelName") or None,
        "device": dev.get("device"),
        "evidence": dev.get("evidence", []),
        "services": dev.get("services", []),
        "role": dev.get("role") or None,
        "rtt_ms": dev.get("rtt_ms"),
        "ttl": dev.get("ttl"),
        "os_hint": devices.ttl_hint(dev.get("ttl")) or None,
        "names_from": dev.get("sources", []),
    }


def _fail(message: str | None):
    print(f"netzilla: {message or 'lookup failed'}", file=sys.stderr)
    return None


def _print_plain(payload) -> None:
    if not isinstance(payload, dict):
        print(payload)
        return
    width = max((len(str(k)) for k in payload), default=0)
    for key, value in payload.items():
        label = str(key).ljust(width)
        if key == "devices" and isinstance(value, list):
            print(f"{label}  {len(value)}")
            for dev in value:
                print("    " + "  ".join([
                    f"{dev['ip']:<15}", f"{dev.get('mac') or '—':<17}",
                    f"{(dev.get('vendor') or dev.get('address_type') or '')[:24]:<24}",
                    f"{(dev.get('hostname') or '')[:28]:<28}",
                    dev.get("device") or "",
                ]))
            continue
        if key == "releases" and isinstance(value, list) and value \
                and isinstance(value[0], dict):
            # Software releases (netzilla software …) as an aligned table.
            columns = ("release", "released", "support_ends", "end_of_life",
                       "latest", "status")
            shown = value[:10]
            cells = [[str(item.get(c) or "—") for c in columns] for item in shown]
            widths = [max(len(c), *(len(row[i]) for row in cells))
                      for i, c in enumerate(columns)]
            print(f"{label}  {len(value)}")
            print(f"{'':{width}}    " + "  ".join(
                c.replace("_", " ").upper().ljust(w) for c, w in zip(columns, widths)).rstrip())
            for row in cells:
                print(f"{'':{width}}    " + "  ".join(
                    cell.ljust(w) for cell, w in zip(row, widths)).rstrip())
            if len(value) > 10:
                print(f"{'':{width}}    … {len(value) - 10} more (use --json for all)")
            continue
        if isinstance(value, list) and value and isinstance(value[0], dict):
            # Lists of records (URLhaus URLs, reported addresses) read better
            # one per line, capped — --json always gives the full set.
            print(f"{label}  {len(value)} item(s)")
            for item in value[:10]:
                summary = "  ".join(
                    str(v) for k, v in item.items()
                    if k in ("url", "address", "url_status", "score", "threat", "date_added")
                    and v not in (None, "")
                ) or json.dumps(item, default=str)
                print(f"{'':{width}}    - {summary}")
            if len(value) > 10:
                print(f"{'':{width}}    … {len(value) - 10} more (use --json for all)")
            continue
        if isinstance(value, (dict, list)):
            value = json.dumps(value, default=str)
        print(f"{label}  {'—' if value is None else value}")


def _import_urlhaus(path: str) -> int:
    from pathlib import Path

    from .local import urlhaus_offline

    source = Path(path).expanduser()
    if not source.exists():
        print(f"netzilla: {source} does not exist", file=sys.stderr)
        return 1
    print(f"Importing {source}…")
    try:
        entries = urlhaus_offline.parse_dump(source.read_bytes())
    except Exception as exc:
        print(f"netzilla: import failed — {exc}", file=sys.stderr)
        return 1
    if entries and not any(e.date_added for e in entries):
        print(
            "Note: this is the plain-text URL list — it has no status, dates or "
            "tags. The full JSON dump gives richer answers."
        )
    try:
        count = urlhaus_offline.write_snapshot(entries, urlhaus_offline.user_snapshot_path())
    except Exception as exc:
        print(f"netzilla: import failed — {exc}", file=sys.stderr)
        return 1
    snap = urlhaus_offline.snapshot()
    print(
        f"Wrote {count:,} URLhaus entries to {urlhaus_offline.user_snapshot_path()} "
        f"(newest {snap.newest[:10] or 'undated'})."
    )
    return 0


def _update_urlhaus(args) -> int:
    from .local import urlhaus_offline

    config = Config.load(args.config)
    print(f"Downloading {urlhaus_offline.DOWNLOAD_URL} …")
    try:
        count = urlhaus_offline.update_from_abusech(config.credential("abusech_auth_key"))
    except Exception as exc:
        print(
            f"netzilla: URLhaus download failed — {exc}\n"
            "Download the dump in a browser from https://urlhaus.abuse.ch/api/ "
            "and load it with:  netzilla --import-urlhaus FILE",
            file=sys.stderr,
        )
        return 1
    print(f"Wrote {count:,} URLhaus entries to {urlhaus_offline.user_snapshot_path()}")
    return 0


def _update_oui() -> int:
    from .local import oui

    print("Downloading the IEEE registries (MA-L, MA-M, MA-S)…")
    try:
        count = oui.update_from_ieee()
    except Exception as exc:
        print(f"netzilla: OUI update failed — {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {count:,} vendor prefixes to {oui.user_table_path()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
