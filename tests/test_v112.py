"""Tests for netzilla 1.1.2: STATUS (OutageDeck), BGP/ASN (RIPEstat timeout
handling + Team Cymru fallback) and the DNS-based typosquat search that
replaced DomainsDB.

OutageDeck payloads below are copied from live responses of the documented
API (https://outagedeck.com/developers/api), trimmed for length.
"""

from __future__ import annotations

import asyncio

import httpx

from netzilla.clients import outagedeck, ripestat
from netzilla.config import Config
from netzilla.local import cymru, typosquat
from netzilla.services import Services


def make_services(tmp_path, handler) -> Services:
    services = Services(Config(path=tmp_path / "config.toml"))
    services._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return services


def run(coro):
    return asyncio.run(coro)


META = {"version": "v1", "generatedAt": "2026-09-19T20:24:57.275Z"}

GITHUB = {
    "meta": META,
    "data": {
        "id": "provider_github", "slug": "github", "name": "GitHub",
        "currentStatus": {
            "code": "operational", "label": "Operational",
            "headline": "All Systems Operational",
            "summary": "GitHub reports all systems operational.",
            "capturedAt": "2026-09-19T00:00:03.456+00:00",
        },
        "source": {
            "kind": "official_api", "checkedAt": "2026-09-19T20:20:08.399+00:00",
            "stale": False, "statusPageUrl": "https://www.githubstatus.com",
        },
        "counts": {"services": 3, "activeIncidents": 0, "incidents": 112},
        "services": [
            {"slug": "github-actions", "name": "GitHub Actions", "status": "operational"},
        ],
        "activeIncidents": [],
        "access": {"plan": "public", "keyed": False},
    },
}

CLOUDFLARE_DEGRADED = {
    "meta": META,
    "data": {
        "slug": "cloudflare", "name": "Cloudflare",
        "currentStatus": {"code": "degraded", "label": "Degraded",
                          "headline": "Cloudflare is degraded"},
        "source": {"checkedAt": "2026-09-19T20:20:00+00:00", "stale": False},
        "counts": {"activeIncidents": 1},
        "services": [{"slug": "cf-dns", "name": "DNS", "status": "degraded"}],
        "activeIncidents": [
            {"slug": "x", "title": "Elevated DNS errors in ORD",
             "status": "investigating", "severity": "minor"},
        ],
    },
}

INCIDENTS = {
    "meta": META,
    "data": {
        "filters": {"limit": 100}, "count": 2, "page": 1, "totalPages": 1,
        "totalIncidents": 2,
        "incidents": [
            {
                "slug": "slack-trouble-2026-08-13", "title": "Trouble Accessing Historical Messages",
                "status": "monitoring", "severity": "major",
                "startedAt": "2026-08-13T21:21:41+00:00", "resolvedAt": None,
                "provider": {"slug": "slack", "name": "Slack"},
                "affectedServices": [{"slug": "slack-messaging", "name": "Messaging"}],
            },
            {
                "slug": "perplexity-migration", "title": "Status page migration",
                "status": "investigating", "severity": "maintenance",
                "startedAt": "2027-01-01T00:00:00+00:00",
                "provider": {"slug": "perplexity", "name": "Perplexity"},
                "affectedServices": [],
            },
        ],
    },
}

NOT_FOUND = {"error": {"code": "not_found", "message": "Provider not found"}}

SEARCH_GOOGLE = {
    "meta": META,
    "data": {"count": 2, "providers": [
        {"slug": "google-cloud", "name": "Google Cloud",
         "currentStatus": {"code": "operational", "label": "Operational"}},
        {"slug": "google-workspace", "name": "Google Workspace",
         "currentStatus": {"code": "operational", "label": "Operational"}},
    ]},
}


def outagedeck_handler(request):
    path = request.url.path
    if path == "/api/v1/providers/github":
        return httpx.Response(200, json=GITHUB)
    if path == "/api/v1/providers/cloudflare":
        return httpx.Response(200, json=CLOUDFLARE_DEGRADED)
    if path == "/api/v1/providers/google-cloud":
        body = dict(GITHUB["data"], slug="google-cloud", name="Google Cloud")
        return httpx.Response(200, json={"meta": META, "data": body})
    if path == "/api/v1/providers":
        return httpx.Response(200, json=SEARCH_GOOGLE)
    if path == "/api/v1/incidents":
        assert request.url.params.get("state") == "active"
        return httpx.Response(200, json=INCIDENTS)
    return httpx.Response(404, json=NOT_FOUND)


# ------------------------------------------------------------ OutageDeck
def test_outagedeck_unwraps_envelope_and_reads_current_status(tmp_path):
    services = make_services(tmp_path, outagedeck_handler)
    result = run(outagedeck.provider(services, "github"))
    assert result.ok
    info = outagedeck.normalise(result.data)
    assert info["name"] == "GitHub"
    assert info["status_key"] == "operational"
    assert info["status_label"] == "Operational"
    assert info["headline"] == "All Systems Operational"
    assert info["updated"] == "2026-09-19 20:20"
    assert outagedeck.state_of(info["status_key"]) == "ok"


def test_outagedeck_degraded_provider_surfaces_incident_titles(tmp_path):
    services = make_services(tmp_path, outagedeck_handler)
    info = outagedeck.normalise(run(outagedeck.provider(services, "cloudflare")).data)
    assert outagedeck.state_of(info["status_key"]) == "warn"
    assert info["active_titles"] == ["Elevated DNS errors in ORD"]
    assert info["degraded_services"] == ["DNS"]


def test_outagedeck_unknown_slug_suggests_real_ones(tmp_path):
    services = make_services(tmp_path, outagedeck_handler)
    result = run(outagedeck.provider(services, "microsoft-365"))
    assert not result.ok and result.status_code == 404
    assert "not an OutageDeck provider slug" in result.error
    assert "google-cloud" in result.error  # suggestions from the search call


def test_outagedeck_common_aliases_resolve(tmp_path):
    services = make_services(tmp_path, outagedeck_handler)
    result = run(outagedeck.provider(services, "google"))
    assert result.ok and result.data["slug"] == "google-cloud"
    assert outagedeck.resolve_slug("GCP") == "google-cloud"


def test_outagedeck_incidents_is_a_dict_not_a_list(tmp_path):
    """1.1.1 sliced the data dict -> TypeError: unhashable type: 'slice'."""
    services = make_services(tmp_path, outagedeck_handler)
    result = run(outagedeck.active_incidents(services))
    assert result.ok
    assert result.data["total"] == 2
    rows = outagedeck.incident_rows(result.data["incidents"])
    assert rows[0][:3] == ["Slack", "MAJOR", "monitoring"]
    assert rows[0][4] == "2026-08-13 21:21"


def test_outagedeck_search_returns_provider_list(tmp_path):
    services = make_services(tmp_path, outagedeck_handler)
    result = run(outagedeck.search(services, "google"))
    assert [p["slug"] for p in result.data] == ["google-cloud", "google-workspace"]


# ------------------------------------------------------------- RIPEstat
def test_ripestat_retries_a_timeout_then_succeeds(tmp_path):
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.TimeoutException("slow")
        return httpx.Response(200, json={
            "status": "ok", "data": {"prefix": "8.8.8.0/24", "asns": ["15169"]},
        })

    services = make_services(tmp_path, handler)
    result = run(ripestat.network_info(services, "8.8.8.8"))
    assert result.ok and calls["n"] == 2
    assert result.data["prefix"] == "8.8.8.0/24"


def test_ripestat_persistent_timeout_is_explained(tmp_path):
    def handler(request):
        raise httpx.TimeoutException("slow")

    services = make_services(tmp_path, handler)
    result = run(ripestat.network_info(services, "8.8.8.8"))
    assert not result.ok
    assert "Timed out after 20s (2 attempts)" in result.error
    assert "RIPEstat is slow" in result.error


def test_cymru_parsing_prefers_most_specific_prefix():
    out = ('"15169 | 8.8.0.0/16 | US | arin | 1992-12-01"\n'
           '"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"')
    parsed = cymru.parse_origin(out)
    assert parsed["prefix"] == "8.8.8.0/24" and parsed["asns"] == [15169]
    assert cymru.parse_asn('"15169 | US | arin | 2000-03-30 | GOOGLE, US"')["holder"] == "GOOGLE, US"
    assert cymru.origin_name("8.8.4.4") == "4.4.8.8.origin.asn.cymru.com"
    assert cymru.origin_name("2001:db8::1").endswith(".origin6.asn.cymru.com")
    assert cymru.parse_origin("") is None


# ----------------------------------------------------------- typosquat
def test_split_domain_handles_www_urls_and_two_part_suffixes():
    assert typosquat.split_domain("www.google.com") == ("google", "com")
    assert typosquat.split_domain("https://Mail.Example.org/login") == ("example", "org")
    assert typosquat.split_domain("bbc.co.uk") == ("bbc", "co.uk")
    assert typosquat.split_domain("google", "net") == ("google", "net")


def test_permutations_cover_the_classic_families():
    perms = dict((fqdn, kind) for kind, fqdn in typosquat.permutations("google", "com"))
    assert "google.com" not in perms
    assert perms["gogle.com"] == "omission"
    assert perms["googel.com"] == "transposition"
    assert perms["goo-gle.com"] == "hyphenation"
    assert perms["google.net"] == "tld-swap"
    assert perms["goog1e.com"] == "homoglyph"   # 1 for l
    assert "g0ogle.com" in perms                 # 0 for o (also a keyboard slip)
    assert all(len(f.split(".")[0]) <= 63 for f in perms)


def test_scan_reports_only_names_that_resolve_and_drops_wildcard_answers(monkeypatch):
    registered = {"gogle.com": ["142.250.1.1"], "googel.com": ["198.51.100.7"]}

    async def fake_resolve(fqdn, timeout):
        if fqdn.startswith("nz-"):
            return ["203.0.113.66"]           # ISP NXDOMAIN hijack
        if fqdn == "gooogle.com":
            return ["203.0.113.66"]           # only the hijack address
        return registered.get(fqdn, [])

    monkeypatch.setattr(typosquat, "_resolve", fake_resolve)
    result = run(typosquat.scan("www.google.com"))
    found = {h["domain"] for h in result["registered"]}
    assert found == {"gogle.com", "googel.com"}
    assert result["wildcard_resolver"] == ["203.0.113.66"]
    assert result["original"] == "google.com"
    assert result["checked"] > 150
