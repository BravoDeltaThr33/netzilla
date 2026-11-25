"""Bandwidth testing.

RUN SPEED TEST uses the built-in Cloudflare test (local/cfspeed.py): free,
keyless, nothing to install, with latency, jitter and bufferbloat measured
too.

OOKLA TEST uses Ookla's servers through whichever of these is installed,
tried in order:

  1. the `speedtest` Python module (from `pipx inject netzilla speedtest-cli`)
  2. the `speedtest-cli` command, run as a subprocess with --json
  3. Ookla's official `speedtest` command, run with --format=json

All three are optional: netzilla runs fine without them, and when none work
the tab reports exactly why (the real import error, the interpreter netzilla
is running under, and which commands were searched for) instead of a generic
"not installed".
"""

from __future__ import annotations

import asyncio
import importlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

SUBPROCESS_TIMEOUT = 180


# ------------------------------------------------------------ discovery
def import_error() -> str | None:
    """None if `import speedtest` works, else the real reason it doesn't."""
    # A package injected while netzilla is already running is invisible to
    # the import system until its directory caches are refreshed.
    importlib.invalidate_caches()
    try:
        import speedtest  # noqa: F401
    except Exception as exc:  # ImportError, SyntaxError, anything
        return f"{exc.__class__.__name__}: {exc}"
    if not hasattr(speedtest, "Speedtest"):
        where = getattr(speedtest, "__file__", "?")
        return (
            f"a module named 'speedtest' was found at {where}, but it is not "
            "speedtest-cli (no Speedtest class). Something else is shadowing it."
        )
    return None


def _venv_bin() -> Path:
    return Path(sys.executable).parent


def speedtest_cli_command() -> str | None:
    """The `speedtest-cli` script — netzilla's own venv first, then PATH.

    `pipx inject` puts the script in netzilla's venv but does not link it onto
    PATH unless --include-apps is given, so look beside the interpreter too.
    """
    local = _venv_bin() / "speedtest-cli"
    if local.is_file():
        return str(local)
    return shutil.which("speedtest-cli")


def ookla_command() -> str | None:
    """Ookla's official CLI (`speedtest`), if installed system-wide.

    Ookla's binary identifies itself as "Speedtest by Ookla"; speedtest-cli
    also installs a `speedtest` alias, which is skipped here because it is
    already covered by speedtest_cli_command().
    """
    path = shutil.which("speedtest")
    if not path:
        return None
    try:
        out = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=10
        )
    except Exception:
        return None
    return path if "ookla" in (out.stdout + out.stderr).lower() else None


def backend() -> str | None:
    """Which backend will be used: 'library', 'cli', 'ookla' or None."""
    if import_error() is None:
        return "library"
    if speedtest_cli_command():
        return "cli"
    if ookla_command():
        return "ookla"
    return None


def available() -> bool:
    return backend() is not None


def backend_label() -> str:
    return {
        "library": "speedtest-cli (Python module)",
        "cli": "speedtest-cli (command)",
        "ookla": "Ookla speedtest (official CLI)",
    }.get(backend() or "", "not installed (optional)")


def diagnosis() -> str:
    """Everything needed to see why no backend was found."""
    venv_bin = _venv_bin()
    return (
        "No speed-test backend could be loaded.\n\n"
        f"Python module:   {import_error() or 'ok'}\n"
        f"netzilla Python: {sys.executable}\n"
        f"Searched for:    {venv_bin / 'speedtest-cli'}, "
        "speedtest-cli on PATH, Ookla 'speedtest' on PATH\n\n"
        "Fix — install into the SAME environment as the netzilla you launch:\n"
        "    pipx inject netzilla speedtest-cli\n"
        "then quit netzilla (q) and start it again.\n\n"
        "Check that it landed in the right place:\n"
        f"    {venv_bin / 'python'} -c \"import speedtest; print(speedtest.__version__)\"\n"
        "    which -a netzilla      (more than one line = more than one install)\n\n"
        "Alternative: install Ookla's official CLI (https://www.speedtest.net/apps/cli);\n"
        "netzilla picks up its 'speedtest' command automatically."
    )


# Kept for anything that still imports the old name.
INSTALL_HINT = diagnosis


# --------------------------------------------------------------- backends
def _run_library(say: Callable[[str], None]) -> dict:
    import speedtest

    say("Fetching server list…")
    tester = speedtest.Speedtest(secure=True)
    tester.get_servers()

    say("Selecting the closest server…")
    best = tester.get_best_server()

    say("Measuring download…")
    download = tester.download()

    say("Measuring upload…")
    upload = tester.upload(pre_allocate=False)

    results = tester.results.dict()
    return _from_speedtest_cli_dict(results, download, upload, best)


def _from_speedtest_cli_dict(
    results: dict, download: float | None = None, upload: float | None = None,
    best: dict | None = None,
) -> dict:
    best = best or results.get("server") or {}
    client = results.get("client") or {}
    down = download if download is not None else results.get("download") or 0
    up = upload if upload is not None else results.get("upload") or 0
    return {
        "download_mbps": down / 1_000_000,
        "upload_mbps": up / 1_000_000,
        "ping_ms": results.get("ping"),
        "server_name": best.get("sponsor"),
        "server_location": f'{best.get("name", "")}, {best.get("country", "")}'.strip(", "),
        "server_host": best.get("host"),
        "distance_km": best.get("d"),
        "client_isp": client.get("isp"),
        "client_ip": client.get("ip"),
        "share_url": results.get("share"),
    }


def _run_json(cmd: list[str]) -> dict:
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        raise RuntimeError(
            f"{Path(cmd[0]).name} exited with status {proc.returncode}: "
            + (detail[-1] if detail else "no output")
        )
    # Ookla can print log lines before the JSON; take the last JSON line.
    for line in reversed(proc.stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise RuntimeError(f"{Path(cmd[0]).name} produced no JSON result")


def _run_cli(say: Callable[[str], None]) -> dict:
    cmd = speedtest_cli_command()
    say("Running speedtest-cli — about 30 seconds…")
    return _from_speedtest_cli_dict(_run_json([cmd, "--secure", "--json"]))


def _run_ookla(say: Callable[[str], None]) -> dict:
    cmd = ookla_command()
    say("Running Ookla speedtest — about 30 seconds…")
    data = _run_json([
        cmd, "--format=json", "--accept-license", "--accept-gdpr",
    ])
    server = data.get("server") or {}
    # Ookla reports bandwidth in bytes/second.
    down_bps = (data.get("download") or {}).get("bandwidth", 0) * 8
    up_bps = (data.get("upload") or {}).get("bandwidth", 0) * 8
    return {
        "download_mbps": down_bps / 1_000_000,
        "upload_mbps": up_bps / 1_000_000,
        "ping_ms": (data.get("ping") or {}).get("latency"),
        "server_name": server.get("name"),
        "server_location": f'{server.get("location", "")}, {server.get("country", "")}'.strip(", "),
        "server_host": server.get("host"),
        "distance_km": None,
        "client_isp": data.get("isp"),
        "client_ip": (data.get("interface") or {}).get("externalIp"),
        "share_url": (data.get("result") or {}).get("url"),
    }


def _run_blocking(progress: Callable[[str], None] | None = None) -> dict:
    def say(message: str) -> None:
        if progress is not None:
            progress(message)

    order = []
    if import_error() is None:
        order.append(("speedtest-cli module", _run_library))
    if speedtest_cli_command():
        order.append(("speedtest-cli command", _run_cli))
    if ookla_command():
        order.append(("Ookla speedtest", _run_ookla))
    if not order:
        raise RuntimeError(diagnosis())

    failures = []
    for name, runner in order:
        try:
            result = runner(say)
            result["backend"] = name
            return result
        except Exception as exc:
            failures.append(f"{name}: {exc.__class__.__name__}: {exc}")
            say(f"{name} failed — trying the next option…")
    raise RuntimeError("\n".join(failures))


async def run_test(progress: Callable[[str], None] | None = None) -> dict:
    """Run the blocking speedtest in a thread so the UI stays responsive."""
    return await asyncio.to_thread(_run_blocking, progress)


def human_megabytes(count: int | None) -> str | None:
    if not count:
        return None
    return f"{count / 1_000_000:,.0f} MB"


def summarise(results: dict) -> list[tuple[str, object]]:
    rows = [
        ("Download", f'{results.get("download_mbps", 0):.2f} Mbit/s'),
        ("Upload", f'{results.get("upload_mbps", 0):.2f} Mbit/s'),
        ("Latency", f'{results.get("ping_ms") or 0:.1f} ms'),
    ]
    if results.get("jitter_ms") is not None:
        rows.append(("Jitter", f'{results["jitter_ms"]:.1f} ms'))
    if results.get("loaded_ms") is not None:
        rows.append(("Latency while downloading", f'{results["loaded_ms"]:.1f} ms'))
    if results.get("bufferbloat"):
        rows.append(("Bufferbloat",
                     f'{results["bufferbloat"]} — +{results.get("bufferbloat_added_ms", 0):.0f} ms '
                     "under load"))
    rows += [
        ("Test server", results.get("server_name")),
        ("Server location", results.get("server_location")),
        ("Server host", results.get("server_host")),
        ("Distance", f'{results.get("distance_km"):.0f} km'
            if results.get("distance_km") is not None else None),
        ("Your ISP", results.get("client_isp")),
        ("Your IP", results.get("client_ip")),
        ("Your location", results.get("client_place") or None),
        ("Data used", " / ".join(x for x in (
            human_megabytes(results.get("downloaded_bytes")),
            human_megabytes(results.get("uploaded_bytes"))) if x) or None),
        ("Measured with", results.get("backend")),
    ]
    # A backend that doesn't report something (Cloudflare has no distance)
    # leaves that row out rather than showing an empty "—".
    return [(key, value) for key, value in rows if value not in (None, "")]
