"""Unit tests for netzilla's pure logic.

No network, no Textual, no API keys — these cover the parts that must be
correct regardless of what any third party returns.

    pip install pytest
    pytest -q
"""

from __future__ import annotations

import pytest

from netzilla.clients import abuseipdb, eosl, greynoise, iplogs, nvd, urlhaus, virustotal
from netzilla.config import CREDENTIAL_FIELDS, Config, _dump_toml
from netzilla.local import oui, subnet
from netzilla.validators import (
    ValidationError, mac_oui, valid_asn, valid_domain, valid_ip,
    valid_mac, valid_network, valid_url,
)


# ------------------------------------------------------------- validators
def test_valid_ip_accepts_v4_and_v6():
    assert valid_ip("8.8.8.8") == "8.8.8.8"
    assert valid_ip(" 2001:db8::1 ") == "2001:db8::1"


@pytest.mark.parametrize("bad", ["999.1.1.1", "not-an-ip", "", "1.2.3"])
def test_valid_ip_rejects_junk(bad):
    with pytest.raises(ValidationError):
        valid_ip(bad)


def test_valid_domain_strips_url_furniture():
    assert valid_domain("https://Example.COM/some/path?q=1#frag") == "example.com"
    assert valid_domain("user@mail.example.co.uk") == "mail.example.co.uk"


def test_valid_domain_rejects_bare_label():
    with pytest.raises(ValidationError):
        valid_domain("localhost")


@pytest.mark.parametrize(
    "raw",
    ["00:1A:2B:3C:4D:5E", "001A2B3C4D5E", "0011.2233.4455", "00-1a-2b-3c-4d-5e"],
)
def test_valid_mac_normalises_every_common_format(raw):
    assert valid_mac(raw).count(":") >= 2


def test_mac_oui_takes_first_three_octets():
    assert mac_oui("00:1a:2b:3c:4d:5e") == "001A2B"


def test_valid_asn_accepts_both_spellings():
    assert valid_asn("AS15169") == 15169
    assert valid_asn("15169") == 15169


def test_valid_url_adds_a_scheme():
    assert valid_url("example.com/path").startswith("http://")


# ---------------------------------------------------------------- subnet
def test_describe_ipv4_usable_hosts():
    rows = dict(subnet.describe(valid_network("192.168.10.0/24")))
    assert rows["Usable hosts"] == "254"
    assert rows["Broadcast address"] == "192.168.10.255"
    assert rows["First usable"] == "192.168.10.1"
    assert rows["Last usable"] == "192.168.10.254"


def test_rfc3021_slash31_has_two_usable_addresses():
    rows = dict(subnet.describe(valid_network("10.0.0.0/31")))
    assert rows["Usable hosts"] == "2"


def test_slash32_is_a_single_host():
    rows = dict(subnet.describe(valid_network("10.0.0.7/32")))
    assert rows["Usable hosts"] == "1"


def test_ipv6_describe_does_not_invent_a_broadcast():
    rows = dict(subnet.describe(valid_network("2001:db8::/64")))
    assert "Broadcast address" not in rows
    assert rows["IP version"] == "IPv6"


def test_split_produces_the_right_number_of_subnets():
    rows = subnet.split_into(valid_network("10.0.0.0/24"), 26)
    assert len(rows) == 4
    assert rows[0][1] == "10.0.0.0/26"


def test_split_rejects_a_shorter_prefix():
    with pytest.raises(ValueError):
        subnet.split_into(valid_network("10.0.0.0/24"), 16)


def test_hosts_needed_accounts_for_network_and_broadcast():
    # 50 hosts needs 52 addresses, so /26 (64) not /27 (32).
    prefix, _ = subnet.hosts_needed(valid_network("10.0.0.0/8"), 50)
    assert prefix == 26
    prefix, _ = subnet.hosts_needed(valid_network("10.0.0.0/8"), 62)
    assert prefix == 26
    prefix, _ = subnet.hosts_needed(valid_network("10.0.0.0/8"), 63)
    assert prefix == 25


def test_summarise_range_covers_the_whole_span():
    blocks = subnet.summarise_range("10.0.0.5", "10.0.0.10")
    assert blocks[0].startswith("10.0.0.5")
    assert subnet.contains(valid_network(blocks[-1]), "10.0.0.10")


# ------------------------------------------------------------------- oui
def test_bundled_oui_table_resolves_well_known_prefixes():
    assert "Cisco" in (oui.lookup("00000C") or "")
    assert "VMware" in (oui.lookup("000C29") or "")


def test_locally_administered_bit():
    assert oui.is_locally_administered("02:00:00:00:00:01") is True
    assert oui.is_locally_administered("00:1A:2B:00:00:01") is False


def test_multicast_bit():
    assert oui.is_multicast("01:00:5E:00:00:01") is True
    assert oui.is_multicast("00:1A:2B:00:00:01") is False


# ---------------------------------------------------------------- config
def test_every_credential_field_is_unique_and_described():
    keys = [f.key for f in CREDENTIAL_FIELDS]
    assert len(keys) == len(set(keys))
    for field in CREDENTIAL_FIELDS:
        assert field.label and field.service and field.note
        assert field.kind in {"api_key", "shared_secret"}


def test_toml_writer_escapes_quotes():
    out = _dump_toml({"credentials": {"k": 'a"b'}})
    assert '\\"' in out


def test_env_var_overrides_stored_credential(monkeypatch):
    config = Config()
    config.set_credential("abuseipdb_api_key", "from-file")
    assert config.credential("abuseipdb_api_key") == "from-file"
    monkeypatch.setenv("NETZILLA_ABUSEIPDB_API_KEY", "from-env")
    assert config.credential("abuseipdb_api_key") == "from-env"


def test_config_roundtrip(tmp_path):
    path = tmp_path / "config.toml"
    config = Config(path=path)
    config.theme = "ice-cyan"
    config.set_credential("virustotal_api_key", "abc123")
    config.timeout_seconds = 20.0
    config.save()

    reloaded = Config.load(path)
    assert reloaded.theme == "ice-cyan"
    assert reloaded.credential("virustotal_api_key") == "abc123"
    assert reloaded.timeout_seconds == 20.0


def test_corrupt_config_does_not_raise(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("this is not [ valid toml")
    assert Config.load(path).theme  # falls back to the default


# ------------------------------------------------------- client verdicts
def test_abuseipdb_verdict_thresholds():
    # AbuseIPDB recommends 75-100% as the range for blocking.
    assert abuseipdb.verdict({"abuseConfidenceScore": 0})[1] == "ok"
    assert abuseipdb.verdict({"abuseConfidenceScore": 10})[1] == "warn"
    assert abuseipdb.verdict({"abuseConfidenceScore": 50})[1] == "warn"
    assert abuseipdb.verdict({"abuseConfidenceScore": 90})[1] == "bad"


def test_abuseipdb_category_names_and_counts():
    data = {"reports": [
        {"categories": [18, 22]}, {"categories": [18]}, {"categories": [14]},
    ]}
    counts = abuseipdb.category_counts(data)
    assert counts[0] == ["Brute-Force", 2]
    assert abuseipdb.category_names([18, 22]) == "Brute-Force, SSH"


@pytest.mark.parametrize(
    "network,blocked",
    [("203.0.113.0/24", False), ("203.0.113.128/25", False),
     ("203.0.112.0/23", True), ("10.0.0.0/8", True)],
)
def test_abuseipdb_free_plan_block_ceiling(network, blocked):
    assert (abuseipdb.block_blocker(network) is not None) is blocked


def test_virustotal_verdict_prefers_malicious():
    attrs = {"last_analysis_stats": {"malicious": 3, "harmless": 60, "suspicious": 1}}
    text, state = virustotal.verdict(attrs)
    assert state == "bad" and "3" in text


def test_virustotal_clean():
    attrs = {"last_analysis_stats": {"malicious": 0, "harmless": 70, "suspicious": 0}}
    assert virustotal.verdict(attrs)[1] == "ok"


def test_greynoise_verdicts_follow_the_documented_fields():
    # Shapes copied from GreyNoise's Community API documentation.
    not_observed = {"ip": "196.188.245.219", "noise": False, "riot": False}
    malicious = {"ip": "51.91.185.74", "noise": True, "riot": False,
                 "classification": "malicious", "name": "unknown"}
    riot = {"ip": "1.1.1.1", "noise": False, "riot": True,
            "classification": "benign", "name": "Cloudflare"}
    assert greynoise.verdict(not_observed)[1] == "ok"
    assert greynoise.verdict(malicious)[1] == "bad"
    text, state = greynoise.verdict(riot)
    assert state == "ok" and "Cloudflare" in text


@pytest.mark.parametrize(
    "ip,blocked",
    [("8.8.8.8", False), ("10.0.0.1", True), ("2001:4860:4860::8888", True),
     ("127.0.0.1", True)],
)
def test_greynoise_rejects_what_the_api_would_reject(ip, blocked):
    # The API only accepts routable IPv4; netzilla checks locally so it never
    # spends one of the 50 weekly lookups on a guaranteed 400.
    assert (greynoise.lookup_blocker(ip) is not None) is blocked


def test_iplogs_verdict_mapping():
    assert iplogs.verdict({"verdict": "clean", "confidence": 0.9})[1] == "ok"
    assert iplogs.verdict({"verdict": "vpn_detected", "confidence": 0.8})[1] == "bad"


def test_iplogs_only_returns_matched_signals():
    payload = {
        "signals": [
            {"type": "dc_ip", "matched": True, "detail": "datacentre"},
            {"type": "tor_exit", "matched": False, "detail": "no"},
        ]
    }
    matched = iplogs.matched_signals(payload)
    assert len(matched) == 1 and matched[0][0] == "dc_ip"


def test_urlhaus_not_listed_is_a_clean_verdict():
    assert urlhaus.verdict({"query_status": "no_results"})[1] == "ok"
    assert urlhaus.verdict({"query_status": "ok", "url_count": "4"})[1] == "bad"


def test_nvd_rows_prefer_cvss_v31():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "published": "2024-01-02T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "A problem."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ],
                        "cvssMetricV2": [
                            {"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}
                        ],
                    },
                }
            }
        ]
    }
    rows = nvd.cve_rows(payload)
    assert rows[0][0] == "CVE-2024-0001"
    assert rows[0][1] == "CRITICAL"
    assert rows[0][2] == "9.8"


def test_eosl_family_search_is_case_insensitive():
    items = [
        {"slug": "cisco-catalyst-3850", "vendor": "Cisco", "series": "3850 Series"},
        {"slug": "juniper-ex4300", "vendor": "Juniper", "series": "EX4300"},
    ]
    hits = eosl.search_families(items, "CATALYST")
    assert len(hits) == 1 and hits[0]["slug"] == "cisco-catalyst-3850"


def test_virustotal_url_id_is_unpadded_base64url():
    from netzilla.clients.virustotal import _url_id

    assert "=" not in _url_id("http://example.com/")


# ------------------------------------------------------------------- tls
def test_certificate_date_parsing():
    from netzilla.local import tls_quick

    parsed = tls_quick._parse_date("Jun  1 12:00:00 2027 GMT")
    assert parsed is not None and parsed.year == 2027


@pytest.mark.parametrize(
    "days,state",
    [(-5, "bad"), (3, "bad"), (20, "warn"), (200, "ok")],
)
def test_expiry_verdict_bands(days, state):
    from netzilla.local import tls_quick

    assert tls_quick.expiry_verdict({"days_remaining": days})[1] == state


def test_expiry_verdict_treats_connection_failure_as_bad():
    from netzilla.local import tls_quick

    assert tls_quick.expiry_verdict({"error": "Could not connect"})[1] == "bad"


def test_certificate_name_flattening():
    from netzilla.local import tls_quick

    flat = tls_quick._flatten_name(
        ((("commonName", "example.com"),), (("organizationName", "Example Inc"),))
    )
    assert flat["commonName"] == "example.com"
    assert flat["organizationName"] == "Example Inc"


# ------------------------------------------------------------------ misc
def test_ping_output_parsing():
    from netzilla.local import netdiag

    output = (
        "4 packets transmitted, 4 received, 0% packet loss, time 3004ms\n"
        "rtt min/avg/max/mdev = 12.345/13.456/14.567/0.789 ms"
    )
    stats = netdiag.parse_ping(output)
    assert stats["tx"] == "4" and stats["rx"] == "4" and stats["loss"] == "0"
    assert stats["rtt_avg"] == "13.456"


def test_ping_output_parsing_with_loss():
    from netzilla.local import netdiag

    stats = netdiag.parse_ping("4 packets transmitted, 1 received, 75% packet loss")
    assert stats["loss"] == "75"


def test_whois_boilerplate_is_stripped():
    from netzilla.local import dns_whois

    raw = (
        "% This is a comment\n"
        "NOTICE: The expiration date shown...\n"
        "Domain Name: EXAMPLE.COM\n"
        "Registrar: Example Registrar\n"
    )
    condensed = dns_whois.condense_whois(raw)
    assert "Domain Name: EXAMPLE.COM" in condensed
    assert "% This is a comment" not in condensed


def test_every_theme_maps_onto_textual_theme_params():
    from netzilla.themes import PALETTES

    allowed = {
        "name", "primary", "secondary", "warning", "error", "success",
        "accent", "foreground", "background", "surface", "panel",
        "boost", "dark", "luminosity_spread", "text_alpha", "variables",
    }
    for palette in PALETTES.values():
        assert set(palette.as_textual_kwargs()) <= allowed


def test_every_theme_is_dark_and_fully_specified():
    import re

    from netzilla.themes import PALETTES

    hex_colour = re.compile(r"^#[0-9A-Fa-f]{6}$")
    # The original five, plus the palettes added in 2.3 and 2.4.
    assert len(PALETTES) >= 5, "the original five themes must survive"
    for name, palette in PALETTES.items():
        for attr in (
            "background", "surface", "panel", "primary", "secondary",
            "accent", "foreground", "success", "warning", "error", "muted",
        ):
            value = getattr(palette, attr)
            assert hex_colour.match(value), f"{name}.{attr} = {value!r}"
        # Dark background: every channel well below mid-grey.
        r, g, b = (int(palette.background[i:i + 2], 16) for i in (1, 3, 5))
        assert max(r, g, b) < 64, f"{name} background is not dark"
