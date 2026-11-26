"""Tests for netzilla 2.0: the new API clients (RDAP, DoH, crt.sh, abuse.ch
ThreatFox/MalwareBazaar/Feodo, CISA KEV, HIBP) and the local diagnostic
modules (LAN sweep/ARP, DHCP, arpwatch, SNMP, PMTU, NTP, syslog, config parser,
route/path history).

HTTP is served by httpx.MockTransport; local protocol logic is exercised as
pure functions. Nothing here touches the network or needs root.
"""

from __future__ import annotations

import asyncio
import socket
import struct

import httpx

from netzilla.clients import abusech, crtsh, doh, hibp, kev, rdap
from netzilla.config import Config
from netzilla.local import (
    arpwatch, confparse, dhcp, history, lan, mtu, netdiag, ntp, snmp, syslog,
)
from netzilla.services import Services


def make_services(tmp_path, handler) -> Services:
    services = Services(Config(path=tmp_path / "config.toml", credentials={"abusech_auth_key": "k"}))
    services._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return services


def run(coro):
    return asyncio.run(coro)


# =============================================================== API clients
def test_rdap_domain_summary_and_abuse_contact(tmp_path):
    payload = {
        "ldhName": "example.com",
        "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
        "nameservers": [{"ldhName": "a.iana-servers.net"}],
        "secureDNS": {"delegationSigned": True},
        "entities": [{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "ICANN"]]],
            "entities": [{
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["email", {}, "text", "abuse@x.tld"]]],
            }],
        }],
    }

    def handler(request):
        assert request.url.path == "/domain/example.com"
        return httpx.Response(200, json=payload)

    services = make_services(tmp_path, handler)
    result = run(rdap.domain(services, "example.com"))
    assert result.ok
    summary = dict(rdap.domain_summary(result.data))
    assert summary["Registrar"] == "ICANN"
    assert summary["Registered"].startswith("1995-08-14")
    assert rdap.abuse_email(result.data) == "abuse@x.tld"


def test_rdap_404_is_a_clean_not_found(tmp_path):
    services = make_services(tmp_path, lambda r: httpx.Response(404, json={}))
    result = run(rdap.domain(services, "nope.invalid"))
    assert not result.ok and result.status_code == 404


def test_doh_consensus_flags_disagreement():
    result = {"resolvers": {
        "Cloudflare": doh.normalise_answer({"Status": 0, "Answer": [{"data": "1.1.1.1."}]}, "A"),
        "Google": doh.normalise_answer({"Status": 0, "Answer": [{"data": "1.1.1.1"}]}, "A"),
        "Quad9": doh.normalise_answer({"Status": 0, "Answer": [{"data": "9.9.9.9"}]}, "A"),
    }}
    agree, _ = doh.consensus(result)
    assert not agree


def test_doh_consensus_agrees_when_identical():
    a = doh.normalise_answer({"Status": 0, "Answer": [{"data": "1.1.1.1"}]}, "A")
    result = {"resolvers": {"Cloudflare": a, "Google": a, "Quad9": a}}
    agree, _ = doh.consensus(result)
    assert agree


def test_doh_queries_all_three_resolvers(tmp_path):
    seen = set()

    def handler(request):
        seen.add(request.url.host)
        return httpx.Response(200, json={"Status": 0, "Answer": [{"data": "1.2.3.4"}]})

    services = make_services(tmp_path, handler)
    result = run(doh.resolve_all(services, "example.com", "A"))
    assert set(result["resolvers"]) == {"Cloudflare", "Google", "Quad9"}
    assert "cloudflare-dns.com" in seen and "dns.google" in seen


def test_crtsh_names_and_earliest(tmp_path):
    data = [
        {"common_name": "a.example.com", "name_value": "a.example.com\n*.example.com",
         "issuer_name": "O=Let's Encrypt", "not_before": "2020-01-02T00:00:00"},
        {"name_value": "b.example.com", "issuer_name": "O=DigiCert",
         "not_before": "2019-05-01T00:00:00"},
    ]
    services = make_services(tmp_path, lambda r: httpx.Response(200, json=data))
    result = run(crtsh.search(services, "example.com"))
    assert result.ok
    names = crtsh.unique_names(result.data, "example.com")
    assert names == ["a.example.com", "b.example.com", "example.com"]
    assert crtsh.earliest_date(result.data) == "2019-05-01"


def test_crtsh_non_array_is_an_error(tmp_path):
    services = make_services(tmp_path, lambda r: httpx.Response(200, json={"error": "rate"}))
    result = run(crtsh.search(services, "example.com"))
    assert not result.ok


def test_threatfox_lookup_and_verdict(tmp_path):
    def handler(request):
        assert request.url.host == "threatfox-api.abuse.ch"
        assert request.headers.get("Auth-Key") == "k"
        return httpx.Response(200, json={"query_status": "ok", "data": [
            {"ioc": "1.2.3.4:443", "threat_type": "botnet_cc",
             "malware_printable": "Cobalt Strike", "confidence_level": 75,
             "first_seen": "2020-12-06 09:10:23 UTC"},
        ]})

    services = make_services(tmp_path, handler)
    result = run(abusech.threatfox(services, "1.2.3.4"))
    assert result.ok
    text, state = abusech.threatfox_verdict(result.data)
    assert state == "bad" and "Cobalt Strike" in text


def test_threatfox_no_result(tmp_path):
    services = make_services(
        tmp_path, lambda r: httpx.Response(200, json={"query_status": "no_result"})
    )
    result = run(abusech.threatfox(services, "8.8.8.8"))
    assert result.ok
    _, state = abusech.threatfox_verdict(result.data)
    assert state == "ok"


def test_threatfox_needs_auth_key(tmp_path):
    services = Services(Config(path=tmp_path / "c.toml"))  # no defaults
    services._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    result = run(abusech.threatfox(services, "1.2.3.4"))
    assert not result.ok and "Auth-Key" in result.error


def test_malwarebazaar_hash_info(tmp_path):
    def handler(request):
        assert request.url.host == "mb-api.abuse.ch"
        return httpx.Response(200, json={"query_status": "ok", "data": [
            {"signature": "Emotet", "file_type": "exe", "sha256_hash": "a" * 64,
             "first_seen": "2021-01-01", "tags": ["exe"]},
        ]})

    services = make_services(tmp_path, handler)
    result = run(abusech.malwarebazaar(services, "A" * 64))
    text, state = abusech.malwarebazaar_verdict(result.data)
    assert state == "bad" and "Emotet" in text


def test_feodo_membership_check(tmp_path):
    def handler(request):
        return httpx.Response(200, json=[
            {"ip_address": "1.2.3.4", "malware": "Dridex"},
            {"ip_address": "5.6.7.8", "malware": "Emotet"},
        ])

    services = make_services(tmp_path, handler)
    hit = run(abusech.feodo_check(services, "1.2.3.4"))
    assert hit.data["listed"] is True
    assert abusech.feodo_verdict(hit.data)[1] == "bad"
    miss = run(abusech.feodo_check(services, "9.9.9.9"))
    assert miss.data["listed"] is False


def test_kev_cross_reference(tmp_path):
    catalog = {"count": 2, "catalogVersion": "2026.01", "vulnerabilities": [
        {"cveID": "CVE-2024-3400", "vendorProject": "Palo Alto", "product": "PAN-OS",
         "dateAdded": "2024-04-12", "dueDate": "2024-04-19",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j",
         "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
         "knownRansomwareCampaignUse": "Known"},
    ]}
    services = make_services(tmp_path, lambda r: httpx.Response(200, json=catalog))
    result = run(kev.check(services, "CVE-2024-3400"))
    assert result.data["listed"] is True
    assert kev.verdict(result.data)[1] == "bad"
    mapping = run(kev.annotate(services, ["CVE-2024-3400", "CVE-2000-0001"]))
    assert mapping["CVE-2024-3400"] is not None
    assert mapping["CVE-2000-0001"] is None


def test_pwned_password_k_anonymity(tmp_path):
    import hashlib
    suffix = hashlib.sha1(b"password").hexdigest().upper()[5:]
    sent_prefix = {}

    def handler(request):
        sent_prefix["path"] = request.url.path
        return httpx.Response(200, text=f"{suffix}:99\nAAAA:2")

    services = make_services(tmp_path, handler)
    result = run(hibp.check_password(services, "password"))
    assert result.ok and result.data["pwned"] and result.data["count"] == 99
    # Only the 5-char prefix is transmitted, never the password or full hash.
    assert sent_prefix["path"] == "/range/5BAA6"


def test_hibp_breach_search(tmp_path):
    breaches = [
        {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com",
         "BreachDate": "2013-10-04", "PwnCount": 153000000, "DataClasses": ["Emails"]},
        {"Name": "LinkedIn", "Title": "LinkedIn", "Domain": "linkedin.com",
         "BreachDate": "2012-05-05", "PwnCount": 164000000, "DataClasses": ["Emails"]},
    ]
    services = make_services(tmp_path, lambda r: httpx.Response(200, json=breaches))
    result = run(hibp.find_breaches(services, "adobe"))
    assert result.data["total"] == 2
    assert len(result.data["matches"]) == 1
    assert hibp.breach_rows(result.data)[0][0] == "Adobe"


# ============================================================ local diagnostics
def test_lan_hosts_and_neigh_parse():
    assert lan.hosts_for("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]
    table = lan.parse_neigh(
        "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        "192.168.1.9 dev eth0 FAILED\n"
        "10.0.0.5 dev eth0 lladdr 11:22:33:44:55:66 STALE"
    )
    assert table == {"192.168.1.1": "aa:bb:cc:dd:ee:ff", "10.0.0.5": "11:22:33:44:55:66"}


def test_lan_sweep_cap():
    try:
        lan.hosts_for("10.0.0.0/8")
    except ValueError as exc:
        assert "at most" in str(exc)
    else:
        raise AssertionError("expected a cap error for a /8")


def test_dhcp_build_and_parse_roundtrip():
    packet, xid, chaddr = dhcp.build_discover(xid=0x12345678, mac="aa:bb:cc:dd:ee:ff")
    assert len(packet) >= 240 and xid == 0x12345678
    # BOOTP fixed header is 236 bytes; the DHCP magic cookie follows it.
    assert packet[236:240] == dhcp.MAGIC_COOKIE

    offer = bytearray(240)
    struct.pack_into("!BBBBI", offer, 0, 2, 1, 6, 0, xid)
    offer[16:20] = socket.inet_aton("192.168.1.50")
    offer[236:240] = dhcp.MAGIC_COOKIE
    opts = bytes([53, 1, 2, 54, 4]) + socket.inet_aton("192.168.1.1") \
        + bytes([1, 4]) + socket.inet_aton("255.255.255.0") \
        + bytes([51, 4, 0, 1, 81, 128, 255])
    parsed = dhcp.parse_offer(bytes(offer) + opts, expected_xid=xid)
    assert parsed["server_id"] == "192.168.1.1"
    assert parsed["offered_ip"] == "192.168.1.50"
    assert parsed["lease_seconds"] == 86400


def test_dhcp_verdict_flags_multiple_servers():
    one = [{"server_id": "192.168.1.1"}]
    assert dhcp.verdict(one)[1] == "ok"
    two = [{"server_id": "192.168.1.1"}, {"server_id": "192.168.1.99"}]
    assert dhcp.verdict(two)[1] == "bad"
    assert dhcp.verdict([])[1] == "warn"


def test_arpwatch_conflict_logic():
    obs = [("10.0.0.1", "aa:aa:aa:aa:aa:aa"), ("10.0.0.1", "bb:bb:bb:bb:bb:bb"),
           ("10.0.0.2", "cc:cc:cc:cc:cc:cc")]
    conflicts = arpwatch.conflicts(obs)
    assert set(conflicts) == {"10.0.0.1"}
    assert arpwatch.verdict({"ip": "10.0.0.1", "macs": ["a", "b"]})[1] == "bad"
    assert arpwatch.verdict({"ip": "10.0.0.1", "macs": ["a"]})[1] == "ok"


def test_snmp_rate_and_wrap():
    first = {"1": {"in_octets": 1000, "out_octets": 2000, "in_errors": 0, "out_errors": 0}}
    second = {"1": {"in_octets": 1000 + 12_500_000, "out_octets": 2000,
                    "in_errors": 5, "out_errors": 0}}
    rows = snmp.rate_table(first, second, 10.0, {"1": {"name": "Gi0/0", "oper": "up"}})
    assert abs(rows[0]["in_mbps"] - 10.0) < 0.001
    assert rows[0]["in_err_delta"] == 5
    # 64-bit counter wrap correction
    assert snmp._delta(5, snmp.COUNTER_MAX_64 - 5) == 10


def test_snmp_walk_parse():
    out = (".1.3.6.1.2.1.2.2.1.2.1 = STRING: Gi0/0\n"
           ".1.3.6.1.2.1.2.2.1.2.2 = STRING: Gi0/1")
    assert snmp.parse_walk(out, "1.3.6.1.2.1.2.2.1.2") == {"1": "Gi0/0", "2": "Gi0/1"}


def test_mtu_binary_search():
    async def probe(payload):
        return (payload + mtu.IP_ICMP_OVERHEAD) <= 1492

    result = run(mtu.discover("h", probe=probe))
    assert result["path_mtu"] == 1492
    assert mtu.verdict(result)[1] == "warn"


def test_ntp_packet_roundtrip():
    import time
    req = ntp.build_request()
    assert len(req) == 48 and (req[0] & 0x07) == 3
    now = time.time()
    packet = bytearray(48)
    struct.pack_into("!II", packet, 40, int(now) + ntp.NTP_UNIX_DELTA, 0)
    parsed = ntp.parse_transmit_timestamp(bytes(packet))
    assert abs(parsed - now) < 2
    assert ntp.verdict({"offset_seconds": 5.0, "server": "x"})[1] == "bad"
    assert ntp.verdict({"offset_seconds": 0.01, "server": "x"})[1] == "ok"


def test_syslog_priority_and_message():
    assert syslog.parse_priority(165) == ("local4", "notice")
    msg = syslog.parse_message("<34>host su: failed", "10.0.0.1")
    assert msg["facility"] == "auth" and msg["severity"] == "crit"
    assert syslog.severity_state("err") == "bad"


def test_confparse_interfaces_and_routes():
    text = (
        "GigabitEthernet0/1 is up, line protocol is up\n"
        "     123 input errors, 45 CRC, 7 output errors, 2 interface resets\n"
        "GigabitEthernet0/2 is up, line protocol is down\n"
        "FastEthernet0/5 is down (err-disabled)\n"
    )
    result = confparse.summarize(text)
    assert result["kind"] == "interfaces"
    states = {f[0] for f in result["findings"]}
    assert "bad" in states  # error counters + err-disabled
    assert any("err-disabled" in f[1] for f in result["findings"])
    assert any("protocol down" in f[1] for f in result["findings"])

    routes = (
        "Codes: L - local, C - connected, O - OSPF, B - BGP\n"
        "C    10.0.0.0/24 is directly connected, Gi0/0\n"
        "O    10.1.0.0/24 [110/2] via 10.0.0.2\n"
        "O    10.2.0.0/24 [110/3] via 10.0.0.2\n"
        "B    192.0.2.0/24 [20/0] via 203.0.113.1\n"
    )
    counts = confparse.route_counts(routes)
    assert counts == {"connected": 1, "OSPF": 2, "BGP": 1}


def test_traceroute_hop_parse():
    out = " 1  192.168.1.1  1.2 ms  1.1 ms\n 2  * * *\n 3  203.0.113.1  10.5 ms"
    assert netdiag.hop_ips(out) == ["192.168.1.1", "*", "203.0.113.1"]
    hops = netdiag.parse_traceroute(out)
    assert hops[0]["rtt_ms"] == 1.1 and hops[1]["timeout"] is True


def test_history_path_and_origin_diff():
    pd = history.diff_path(["1.1.1.1", "2.2.2.2", "3.3.3.3"],
                           ["1.1.1.1", "9.9.9.9", "3.3.3.3"])
    assert pd["changed"] and pd["diverge_at_hop"] == 2 and pd["added"] == ["9.9.9.9"]
    od = history.diff_origin({"asns": ["15169"], "prefix": "8.8.8.0/24"},
                             {"asns": ["666"], "prefix": "8.8.8.0/24"})
    assert od["changed"] and od["hijack_suspect"]
    assert history.origin_verdict(od)[1] == "bad"


def test_snapshot_store_roundtrip(tmp_path):
    from netzilla.cache import Store
    store = Store(tmp_path / "cache.sqlite3")
    store.add_snapshot("path", "8.8.8.8", ["1.1.1.1", "2.2.2.2"])
    store.add_snapshot("path", "8.8.8.8", ["1.1.1.1", "9.9.9.9"])
    snaps = store.snapshots("path", "8.8.8.8", limit=5)
    assert len(snaps) == 2
    assert snaps[0][1] == ["1.1.1.1", "9.9.9.9"]      # newest first
    assert store.snapshot_targets("path") == ["8.8.8.8"]
