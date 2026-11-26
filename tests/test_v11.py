"""Tests for netzilla 1.1: bundled default keys, the offline URLhaus snapshot,
and client behaviour against the response shapes in each vendor's docs.

HTTP is served by httpx.MockTransport — nothing here touches the network and
no real API key is used or printed.

    pip install -e ".[dev]"
    pytest -q
"""

from __future__ import annotations

import asyncio
import sys
import gzip
import io
import json
import zipfile
from urllib.parse import parse_qs

import httpx
import pytest

from netzilla.clients import abuseipdb, greynoise, urlhaus, virustotal
from netzilla.config import (
    BUNDLED_DEFAULTS_PATH, CREDENTIAL_KEYS, Config, load_bundled_defaults,
)
from netzilla.local import urlhaus_offline
from netzilla.services import Services


DEFAULTS = {
    "abuseipdb_api_key": "default-abuse",
    "virustotal_api_key": "default-vt",
    "greynoise_api_key": "default-gn",
    "abusech_auth_key": "default-abusech",
}


def make_services(tmp_path, handler, *, offline=False, defaults=None) -> Services:
    config = Config(path=tmp_path / "config.toml")
    config.defaults = dict(DEFAULTS if defaults is None else defaults)
    services = Services(config, offline=offline)
    services._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return services


def run(coro):
    return asyncio.run(coro)


# ------------------------------------------------------ bundled defaults
@pytest.mark.skipif(
    not BUNDLED_DEFAULTS_PATH.exists(),
    reason="this copy has had its API keys stripped for sharing (README, section 4)",
)
def test_bundled_defaults_file_ships_the_four_keys():
    defaults = load_bundled_defaults()
    assert BUNDLED_DEFAULTS_PATH.exists()
    for key in ("abuseipdb_api_key", "virustotal_api_key",
                "greynoise_api_key", "abusech_auth_key"):
        assert defaults.get(key), f"{key} missing from the bundled defaults"
    assert set(defaults) <= set(CREDENTIAL_KEYS)


def test_missing_defaults_file_means_no_defaults(tmp_path):
    assert load_bundled_defaults(tmp_path / "nope.toml") == {}


def test_no_default_keys_switch(tmp_path):
    config = Config.load(tmp_path / "config.toml", use_defaults=False)
    assert config.credential_source("abuseipdb_api_key") == "none"


def test_precedence_default_then_custom_then_env(tmp_path, monkeypatch):
    monkeypatch.delenv("NETZILLA_ABUSEIPDB_API_KEY", raising=False)
    config = Config(path=tmp_path / "config.toml", defaults=dict(DEFAULTS))

    assert config.credential("abuseipdb_api_key") == "default-abuse"
    assert config.credential_source("abuseipdb_api_key") == "default"

    config.set_credential("abuseipdb_api_key", "mine")
    assert config.credential("abuseipdb_api_key") == "mine"
    assert config.credential_source("abuseipdb_api_key") == "custom"

    monkeypatch.setenv("NETZILLA_ABUSEIPDB_API_KEY", "from-env")
    assert config.credential("abuseipdb_api_key") == "from-env"
    assert config.credential_source("abuseipdb_api_key") == "env"


def test_blank_or_default_value_is_not_an_override(tmp_path):
    config = Config(path=tmp_path / "config.toml", defaults=dict(DEFAULTS))
    config.set_credential("virustotal_api_key", "custom")
    config.set_credential("virustotal_api_key", "")
    assert config.credential("virustotal_api_key") == "default-vt"

    config.set_credential("virustotal_api_key", "default-vt")
    assert "virustotal_api_key" not in config.credentials


def test_only_overrides_are_written_to_disk(tmp_path):
    path = tmp_path / "config.toml"
    config = Config(path=path, defaults=dict(DEFAULTS))
    config.set_credential("greynoise_api_key", "my-own-gn")
    config.save()

    text = path.read_text()
    assert "my-own-gn" in text
    assert "default-abuse" not in text  # defaults never copied into the file

    reloaded = Config.load(path, defaults_path=tmp_path / "none.toml")
    reloaded.defaults = dict(DEFAULTS)
    assert reloaded.credential("greynoise_api_key") == "my-own-gn"
    assert reloaded.credential("abuseipdb_api_key") == "default-abuse"


def test_reset_to_defaults(tmp_path):
    config = Config(path=tmp_path / "config.toml", defaults=dict(DEFAULTS))
    config.set_credential("abuseipdb_api_key", "custom")
    config.reset_all_credentials()
    assert config.credential_source("abuseipdb_api_key") == "default"


def test_v10_config_with_blank_keys_does_not_mask_defaults(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[credentials]\nabuseipdb_api_key = ""\n')
    config = Config.load(path)
    config.defaults = dict(DEFAULTS)
    assert config.credential("abuseipdb_api_key") == "default-abuse"


# ------------------------------------------------------------- abuseipdb
ABUSE_CHECK = {  # from the AbuseIPDB CHECK documentation
    "data": {
        "ipAddress": "118.25.6.39", "isPublic": True, "ipVersion": 4,
        "isWhitelisted": False, "abuseConfidenceScore": 100,
        "countryCode": "CN", "countryName": "China",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
        "domain": "tencent.com", "hostnames": [], "isTor": False,
        "totalReports": 1, "numDistinctUsers": 1,
        "lastReportedAt": "2018-12-20T20:55:14+00:00",
        "reports": [{
            "reportedAt": "2018-12-20T20:55:14+00:00",
            "comment": "Dec 20 20:55:14 srv206 sshd[13937]: Invalid user oracle",
            "categories": [18, 22], "reporterId": 1,
            "reporterCountryCode": "US", "reporterCountryName": "United States",
        }],
    }
}


def test_abuseipdb_check_uses_header_auth_and_parses(tmp_path):
    seen = {}

    def handler(request):
        seen["key"] = request.headers.get("Key")
        seen["accept"] = request.headers.get("Accept")
        seen["path"] = request.url.path
        seen["ip"] = request.url.params.get("ipAddress")
        return httpx.Response(
            200, json=ABUSE_CHECK,
            headers={"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "997"},
        )

    services = make_services(tmp_path, handler)
    result = run(abuseipdb.check(services, "118.25.6.39"))
    assert result.ok
    assert seen == {"key": "default-abuse", "accept": "application/json",
                    "path": "/api/v2/check", "ip": "118.25.6.39"}
    assert abuseipdb.verdict(result.data)[1] == "bad"
    assert abuseipdb.category_counts(result.data)[0][0] == "Brute-Force"
    assert services.reported_limits["abuseipdb"] == {
        "limit": 1000, "remaining": 997, "reset": ""
    }


def test_abuseipdb_rate_limit_error_is_readable(tmp_path):
    def handler(request):
        return httpx.Response(
            429,
            json={"errors": [{
                "detail": "Daily rate limit of 1000 requests exceeded for this endpoint.",
                "status": 429,
            }]},
            headers={"Retry-After": "29241"},
        )

    services = make_services(tmp_path, handler)
    result = run(abuseipdb.check(services, "118.25.6.39"))
    assert not result.ok and result.status_code == 429
    assert "Daily rate limit of 1000" in result.error
    assert "8h 7m" in result.error


def test_abuseipdb_check_block_parses_and_prechecks(tmp_path):
    calls = []

    def handler(request):
        calls.append(request.url.params.get("network"))
        return httpx.Response(200, json={"data": {
            "networkAddress": "127.0.0.0", "netmask": "255.255.255.0",
            "minAddress": "127.0.0.1", "maxAddress": "127.0.0.254",
            "numPossibleHosts": 254, "addressSpaceDesc": "Loopback",
            "reportedAddress": [
                {"ipAddress": "127.0.0.1", "numReports": 631,
                 "mostRecentReport": "2019-03-21T16:35:16+00:00",
                 "abuseConfidenceScore": 0, "countryCode": None},
                {"ipAddress": "127.0.0.2", "numReports": 16,
                 "mostRecentReport": "2019-03-12T20:31:17+00:00",
                 "abuseConfidenceScore": 80, "countryCode": None},
            ],
        }})

    services = make_services(tmp_path, handler)
    too_big = run(abuseipdb.check_block(services, "127.0.0.0/23"))
    assert not too_big.ok and "/24" in too_big.error
    assert calls == []  # refused locally, no quota spent

    result = run(abuseipdb.check_block(services, "127.0.0.1/24"))
    assert result.ok and calls == ["127.0.0.0/24"]
    rows = abuseipdb.block_rows(result.data)
    assert rows[0][0] == "127.0.0.2"  # worst score first
    assert abuseipdb.block_verdict(result.data)[1] == "bad"


# ------------------------------------------------------------- greynoise
def test_greynoise_404_is_a_real_answer(tmp_path):
    def handler(request):
        return httpx.Response(404, json={
            "ip": "196.188.245.219", "noise": False, "riot": False,
            "message": "IP not observed scanning the internet or contained in RIOT data set.",
        })

    services = make_services(tmp_path, handler)
    result = run(greynoise.check(services, "196.188.245.219"))
    assert result.ok
    assert greynoise.verdict(result.data)[0].startswith("NOT OBSERVED")


def test_greynoise_rejected_key_falls_back_to_anonymous(tmp_path):
    keys_sent = []

    def handler(request):
        key = request.headers.get("key")
        keys_sent.append(key)
        if key:
            return httpx.Response(401, json={
                "message": "Authentication Error has Occurred, check your API Key"
            })
        return httpx.Response(200, json={
            "ip": "51.91.185.74", "noise": True, "riot": False,
            "classification": "malicious", "name": "unknown",
            "link": "https://viz.greynoise.io/ip/51.91.185.74",
            "last_seen": "2021-03-18", "message": "Success",
        })

    services = make_services(tmp_path, handler)
    result = run(greynoise.check(services, "51.91.185.74"))
    assert keys_sent == ["default-gn", None]
    assert result.ok and result.meta["key_rejected"] is True
    assert greynoise.verdict(result.data)[1] == "bad"


def test_greynoise_never_spends_a_lookup_on_private_space(tmp_path):
    def handler(request):  # pragma: no cover - must not be called
        raise AssertionError("GreyNoise was called for a private address")

    services = make_services(tmp_path, handler)
    result = run(greynoise.check(services, "192.168.1.10"))
    assert result.ok and result.data["skipped"]


# ------------------------------------------------------------ virustotal
def test_virustotal_unknown_url_is_flagged_not_crashed(tmp_path):
    paths = []

    def handler(request):
        paths.append(request.url.path)
        return httpx.Response(404, json={
            "error": {"code": "NotFoundError", "message": "URL not found"}
        })

    services = make_services(tmp_path, handler)
    result = run(virustotal.check_url(services, "http://example.com/x"))
    assert not result.ok and result.meta.get("unknown")
    assert paths == [f"/api/v3/urls/{virustotal._url_id('http://example.com/x')}"]


def test_virustotal_file_report_by_hash(tmp_path):
    sha256 = "a" * 64

    def handler(request):
        assert request.headers.get("x-apikey") == "default-vt"
        assert request.url.path == f"/api/v3/files/{sha256}"
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 41, "undetected": 20, "harmless": 0},
            "meaningful_name": "invoice.exe", "type_description": "Win32 EXE",
            "size": 123456, "sha256": sha256,
            "popular_threat_classification": {"suggested_threat_label": "trojan.agent"},
            "last_analysis_results": {
                "EngineA": {"category": "malicious", "result": "Trojan.Agent"},
                "EngineB": {"category": "undetected", "result": None},
            },
        }}})

    services = make_services(tmp_path, handler)
    result = run(virustotal.check_file(services, sha256.upper()))
    assert result.ok
    assert virustotal.verdict(result.data)[1] == "bad"
    assert dict(virustotal.file_summary(result.data))["Suggested threat label"] == "trojan.agent"
    assert virustotal.flagging_engines(result.data) == [["EngineA", "malicious", "Trojan.Agent"]]


@pytest.mark.parametrize(
    "value,ok",
    [("d41d8cd98f00b204e9800998ecf8427e", True), ("a" * 40, True),
     ("a" * 64, True), ("xyz", False), ("a" * 63, False)],
)
def test_virustotal_hash_detection(value, ok):
    assert virustotal.is_hash(value) is ok


# --------------------------------------------------------------- urlhaus
def test_urlhaus_live_sends_auth_key_and_form(tmp_path):
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("Auth-Key")
        seen["form"] = parse_qs(request.content.decode())
        return httpx.Response(200, json={"query_status": "ok", "url_count": "2", "urls": []})

    services = make_services(tmp_path, handler)
    result = run(urlhaus.check_host(services, "Bad.Example"))
    assert result.ok and result.data["source"] == "live"
    assert seen == {"auth": "default-abusech", "form": {"host": ["bad.example"]}}


def test_urlhaus_falls_back_to_snapshot_when_api_fails(tmp_path):
    def handler(request):
        raise httpx.ConnectError("unreachable")

    known = next(iter(urlhaus_offline.snapshot().by_host))
    services = make_services(tmp_path, handler)
    result = run(urlhaus.check_host(services, known))
    assert result.ok and result.data["source"] == "offline"
    assert "snapshot" in (result.note or "")
    assert int(result.data["url_count"]) >= 1


def test_urlhaus_offline_mode_never_calls_the_api(tmp_path):
    def handler(request):  # pragma: no cover
        raise AssertionError("network used in offline mode")

    services = make_services(tmp_path, handler, offline=True)
    result = run(urlhaus.check_url(services, "http://definitely-not-listed.invalid/"))
    assert result.ok and result.data["query_status"] == "no_results"


def test_urlhaus_shared_platform_is_a_warning_not_a_verdict():
    payload = {"query_status": "ok", "url_count": "900", "shared_platform": True}
    assert urlhaus.verdict(payload)[1] == "warn"


def test_urlhaus_live_host_on_shared_platform_is_flagged_as_shared(tmp_path):
    def handler(request):
        return httpx.Response(200, json={"query_status": "ok", "url_count": "5696", "urls": []})

    services = make_services(tmp_path, handler)
    result = run(urlhaus.check_host(services, "raw.githubusercontent.com"))
    assert result.data["source"] == "live" and result.data["shared_platform"] is True
    assert urlhaus.verdict(result.data)[1] == "warn"


# ------------------------------------------------------ offline snapshot
DUMP = {
    "3919053": [{
        "dateadded": "2026-09-19 18:35:28 UTC", "url": "http://119.185.241.38:33473/i",
        "url_status": "online", "last_online": "2026-09-19 18:35:28 UTC",
        "threat": "malware_download", "tags": ["32-bit", "elf", "mips", "Mozi"],
        "urlhaus_link": "https://urlhaus.abuse.ch/url/3919053/", "reporter": "geenensp",
    }],
}


def test_bundled_snapshot_is_present_and_loads():
    snap = urlhaus_offline.snapshot()
    assert snap.count > 1000
    assert snap.newest


@pytest.mark.parametrize("wrap", ["json", "zip", "text"])
def test_snapshot_import_formats(tmp_path, wrap):
    raw = json.dumps(DUMP).encode()
    if wrap == "zip":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("urlhaus.json", raw)
        raw = buf.getvalue()
    elif wrap == "text":
        raw = b"# comment\nhttp://119.185.241.38:33473/i\n"
    source = tmp_path / f"dump.{wrap}"
    source.write_bytes(raw)
    dest = tmp_path / "snap.csv.gz"
    assert urlhaus_offline.import_file(source, dest) == 1
    with gzip.open(dest, "rt") as handle:
        assert "119.185.241.38" in handle.read()


def test_snapshot_url_match_ignores_scheme_and_host_case():
    entries = urlhaus_offline._parse_json_dump(DUMP)
    snap = urlhaus_offline.Snapshot(entries, None)
    assert snap.lookup_url("HTTP://119.185.241.38:33473/i")
    assert snap.lookup_host("119.185.241.38")
    assert not snap.lookup_url("http://119.185.241.38:33473/other")


# ------------------------------------------------------------ speed test (1.1.1)
def _fake_exe(path, body):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


def test_speed_reports_the_real_import_error(monkeypatch, tmp_path):
    from netzilla.local import speed
    (tmp_path / "speedtest.py").write_text("raise SyntaxError('broken')\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "speedtest", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "nothing"))
    monkeypatch.setattr(speed, "_venv_bin", lambda: tmp_path / "nothing")
    assert "SyntaxError: broken" in speed.import_error()
    assert speed.backend() is None
    assert "SyntaxError: broken" in speed.diagnosis()


def test_speed_falls_back_to_cli_then_ookla(monkeypatch, tmp_path):
    import json as _json
    from netzilla.local import speed
    monkeypatch.setattr(speed, "import_error", lambda: "ModuleNotFoundError")
    monkeypatch.setattr(speed, "_venv_bin", lambda: tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path))
    _fake_exe(tmp_path / "speedtest-cli", "echo 'HTTP Error 403: Forbidden' >&2; exit 1\n")
    ookla = {"ping": {"latency": 9.8}, "download": {"bandwidth": 31250000},
             "upload": {"bandwidth": 2500000}, "isp": "AT&T",
             "server": {"name": "Windstream"}, "result": {"url": "u"}}
    _fake_exe(tmp_path / "speedtest",
              'if [ "$1" = --version ]; then echo "Speedtest by Ookla"; exit 0; fi\n'
              f"echo '{_json.dumps(ookla)}'\n")
    result = speed._run_blocking()
    assert result["backend"] == "Ookla speedtest"
    assert round(result["download_mbps"]) == 250
    assert round(result["upload_mbps"]) == 20
