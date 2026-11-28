"""Tests for netzilla 4.7: what Windows was missing, built in.

  * DIG +TRACE without dig: the delegation walked from the root servers in
    Python — DNS wire format, referrals, glue, TCP on truncation, EDNS
    fallback, NXDOMAIN, aliases, lame delegations and networks that
    intercept port 53
  * ROGUE DHCP on Windows: the DISCOVER from an ordinary socket, the offers
    heard on a raw socket (SIO_RCVALL) because the DHCP Client service keeps
    UDP/68; Administrator rights explained
  * pixel graphs in Windows Terminal and WezTerm through Sixel: the encoder,
    marker cells, the overlay that redraws images after every frame (scroll,
    occlusion, dialogs, the bottom row), DASH's breath laid over the banner,
    and the terminal detection that switches it on

Nothing here touches the network or a real terminal: DNS servers, sockets
and the Windows console are fakes, and Textual runs headless.
"""

from __future__ import annotations

import asyncio
import io
import random
import re
import socket
import struct

import pytest
from rich.text import Text

from netzilla import __version__, hostos, termcaps
from netzilla.graphics import kitty, pixels, plot, sixel
from netzilla.local import dhcp, dns_whois, dnstrace

needs_pil = pytest.mark.skipif(not plot.HAVE_PIL, reason="Pillow not installed")


@pytest.fixture(autouse=True)
def _kitty_again():
    """Every test starts and ends in kitty mode with no writers, as 4.6 did."""
    pixels.use(pixels.KITTY)
    kitty.set_writer(None)
    sixel.set_writer(None)
    sixel.OVERLAY.reset()
    yield
    pixels.use(pixels.KITTY)
    kitty.set_writer(None)
    sixel.set_writer(None)
    sixel.delete_all()
    sixel.OVERLAY.reset()


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(hostos, "NAME", hostos.WINDOWS)


def test_version_is_4_7():
    assert tuple(int(p) for p in __version__.split(".")[:2]) >= (4, 7), __version__


# ====================================================== DIG +TRACE: the wire
def _rr(name: str, rtype: int, rdata: bytes, ttl: int = 172800) -> bytes:
    return (dnstrace.encode_name(name) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata))
            + rdata)


def _a(name, address, ttl=172800):
    return _rr(name, dnstrace.A, socket.inet_aton(address), ttl)


def _aaaa(name, address, ttl=172800):
    return _rr(name, dnstrace.AAAA, socket.inet_pton(socket.AF_INET6, address), ttl)


def _ns(name, target, ttl=172800):
    return _rr(name, dnstrace.NS, dnstrace.encode_name(target), ttl)


def _cname(name, target, ttl=300):
    return _rr(name, dnstrace.CNAME, dnstrace.encode_name(target), ttl)


def _soa(name, mname="ns.icann.org.", rname="noc.dns.icann.org.", ttl=3600):
    data = (dnstrace.encode_name(mname) + dnstrace.encode_name(rname)
            + struct.pack("!IIIII", 2024010101, 7200, 3600, 1209600, 3600))
    return _rr(name, dnstrace.SOA, data, ttl)


def _answer(query: bytes, answers=(), authority=(), additional=(), rcode=0,
            aa=False, tc=False, qid=None) -> bytes:
    """A response to `query`, its question echoed."""
    _name, end = dnstrace.read_name(query, 12)
    question = query[12:end + 4]
    flags = 0x8000 | (0x0400 if aa else 0) | (0x0200 if tc else 0) | rcode
    head = (query[:2] if qid is None else struct.pack("!H", qid)) + struct.pack(
        "!HHHHH", flags, 1, len(answers), len(authority), len(additional))
    return head + question + b"".join(answers) + b"".join(authority) + b"".join(additional)


def _question(packet: bytes) -> tuple[str, int, bool]:
    name, end = dnstrace.read_name(packet, 12)
    qtype = struct.unpack("!H", packet[end:end + 2])[0]
    edns = struct.unpack("!H", packet[10:12])[0] == 1
    return name, qtype, edns


ROOTS = {v4 for _name, v4, _v6 in dnstrace.ROOT_HINTS}
GTLD = "192.5.6.30"
IANA = "199.43.135.53"


class FakeDNS:
    """The root, .com and example.com servers, answering by address."""

    def __init__(self, final=None, com=None, root=None, prime=None):
        self.calls: list[tuple[str, str, int, bool, bool]] = []
        self.final = final or self.www
        self.com = com or self.com_referral
        self.root = root or self.root_referral
        self.prime = prime or self.root_list

    def __call__(self, address, packet, tcp=False):
        name, qtype, edns = _question(packet)
        self.calls.append((address, name, qtype, tcp, edns))
        if address in ROOTS:
            if name == "." and qtype == dnstrace.NS:
                return self.prime(packet)
            return self.root(packet)
        if address == GTLD:
            return self.com(packet, tcp=tcp, edns=edns)
        if address == IANA:
            return self.final(packet)
        raise socket.timeout("timed out")

    @staticmethod
    def root_list(packet):
        return _answer(packet, answers=[_ns(".", "a.root-servers.net.", 518400),
                                        _ns(".", "b.root-servers.net.", 518400)],
                       additional=[_a("a.root-servers.net.", "198.41.0.4"),
                                   _a("b.root-servers.net.", "170.247.170.2"),
                                   _aaaa("a.root-servers.net.", "2001:503:ba3e::2:30")])

    @staticmethod
    def root_referral(packet):
        return _answer(packet, authority=[_ns("com.", "a.gtld-servers.net.")],
                       additional=[_a("a.gtld-servers.net.", GTLD)])

    @staticmethod
    def com_referral(packet, tcp=False, edns=True):
        return _answer(packet, authority=[_ns("example.com.", "a.iana-servers.net.")],
                       additional=[_a("a.iana-servers.net.", IANA)])

    @staticmethod
    def www(packet):
        name, _qtype, _edns = _question(packet)
        return _answer(packet, answers=[_a(name, "93.184.215.14", 300)], aa=True)


class Clock:
    def __init__(self, step=0.012):
        self.now, self.step = 100.0, step

    def __call__(self):
        self.now += self.step
        return self.now


def _tracer(dns, name="www.example.com", qtype="A", resolve=None):
    return dnstrace.Tracer(name, qtype, ask=dns, resolve=resolve or (lambda _n: []),
                           rng=random.Random(7), clock=Clock())


def test_names_go_on_the_wire_and_come_back_through_compression():
    assert dnstrace.encode_name("www.example.com") == b"\x03www\x07example\x03com\x00"
    assert dnstrace.encode_name(".") == b"\x00" and dnstrace.encode_name("") == b"\x00"
    assert dnstrace.encode_name("bücher.example") == b"\x0dxn--bcher-kva\x07example\x00"
    with pytest.raises(dnstrace.WireError):
        dnstrace.encode_name("a" * 64 + ".com")
    with pytest.raises(dnstrace.WireError):
        dnstrace.encode_name("a..com")
    # "mail" + a pointer to "example.com" at offset 0.
    data = b"\x07example\x03com\x00" + b"\x04mail\xc0\x00" + b"rest"
    assert dnstrace.read_name(data, 0) == ("example.com.", 13)
    assert dnstrace.read_name(data, 13) == ("mail.example.com.", 20)
    assert dnstrace.read_name(b"\x00", 0) == (".", 1)
    assert dnstrace.read_name(b"\x03a.b\x00", 0)[0] == "a\\.b."
    for broken in (b"\xc0\x00", b"\x05abc", b"\xc0", b"\x40abc"):
        with pytest.raises(dnstrace.WireError):
            dnstrace.read_name(broken, 0)
    assert dnstrace.is_within("www.example.com.", "com.")
    assert dnstrace.is_within("com.", ".") and not dnstrace.is_within("example.org.", "com.")
    assert dnstrace.depth(".") == 0 and dnstrace.depth("example.com.") == 2


def test_a_trace_query_asks_no_recursion_and_offers_edns():
    packet = dnstrace.build_query("example.com", dnstrace.NS, qid=0xBEEF)
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
    assert (qid, flags, qd, an, ns, ar) == (0xBEEF, 0, 1, 0, 0, 1)
    name, end = dnstrace.read_name(packet, 12)
    assert name == "example.com." and struct.unpack("!HH", packet[end:end + 4]) == (2, 1)
    opt = packet[end + 4:]
    assert opt[0] == 0 and struct.unpack("!HH", opt[1:5]) == (41, dnstrace.EDNS_SIZE)
    bare = dnstrace.build_query("example.com", edns=False)
    assert struct.unpack("!H", bare[10:12])[0] == 0 and bare.endswith(b"\x00\x01\x00\x01")


def test_answers_are_parsed_and_printed_the_way_dig_prints_them():
    query = dnstrace.build_query("example.com", dnstrace.A, qid=7)
    txt = b"\x0bv=spf1 -all\x05a\"b\\c"
    mx = struct.pack("!H", 10) + dnstrace.encode_name("mail.example.com")
    caa = b"\x00\x05issue" + b"letsencrypt.org"
    ds = struct.pack("!HBB", 370, 13, 2) + bytes.fromhex("e2d3c916f6deeac7")
    data = _answer(query, answers=[
        _a("example.com.", "93.184.215.14", 300),
        _aaaa("example.com.", "2606:2800:21f:cb07:6820:80da:af6b:8b2c", 300),
        _rr("example.com.", 16, txt, 300),
        _rr("example.com.", 15, mx, 300),
        _rr("example.com.", 257, caa, 300),
        _rr("example.com.", 43, ds, 300),
        _rr("example.com.", 65534, b"\x01\x02\xff", 300),
    ], authority=[_soa("example.com.")])
    message = dnstrace.parse(data)
    assert message.id == 7 and message.is_response and message.rcode_name == "NOERROR"
    assert message.question == ("example.com.", 1)
    shown = [dnstrace.format_record(r) for r in message.answers]
    assert shown[0] == "example.com.            300     IN      A       93.184.215.14"
    assert shown[1].endswith("AAAA    2606:2800:21f:cb07:6820:80da:af6b:8b2c")
    assert shown[2].endswith('TXT     "v=spf1 -all" "a\\"b\\\\c"')
    assert shown[3].endswith("MX      10 mail.example.com.")
    assert shown[4].endswith('CAA     0 issue "letsencrypt.org"')
    assert shown[5].endswith("DS      370 13 2 E2D3C916F6DEEAC7")
    assert shown[6].endswith("TYPE65534       \\# 3 0102FF")
    soa = dnstrace.format_record(message.authority[0])
    assert soa.endswith("SOA     ns.icann.org. noc.dns.icann.org. 2024010101 7200 3600 1209600 3600")
    # A name of 24 characters or more gets one tab, as in dig.
    long = dnstrace.Record("a-rather-long-name.example.", 2, 1, 60, "ns1.example.")
    assert dnstrace.format_record(long) == "a-rather-long-name.example.     60      IN      NS      ns1.example."
    with pytest.raises(dnstrace.WireError):
        dnstrace.parse(data[:40])
    with pytest.raises(dnstrace.WireError):
        dnstrace.parse(b"\x00" * 5)


# ====================================================== DIG +TRACE: the walk
def test_the_walk_goes_root_then_com_then_the_zone_and_prints_each_hop():
    dns = FakeDNS()
    tracer = _tracer(dns).run()
    assert tracer.ok and tracer.done and tracer.status == "NOERROR" and not tracer.error
    assert [s.zone for s in tracer.steps] == [".", ".", "com.", "example.com."]
    assert [s.server for s in tracer.steps] == [
        tracer.steps[0].server, tracer.steps[1].server, "a.gtld-servers.net.",
        "a.iana-servers.net."]
    assert tracer.steps[0].server in ("a.root-servers.net.", "b.root-servers.net.") or \
        tracer.steps[0].server.endswith(".root-servers.net.")
    # Every server was asked without recursion, and only what it knows.
    assert {call[1] for call in dns.calls} == {".", "www.example.com."}
    text = tracer.text()
    assert text.startswith("; <<>> netzilla trace <<>> www.example.com A\n")
    assert "dig is not installed" in text
    assert "com.                    172800  IN      NS      a.gtld-servers.net." in text
    assert "example.com.            172800  IN      NS      a.iana-servers.net." in text
    assert "www.example.com.        300     IN      A       93.184.215.14" in text
    assert re.search(r";; Received \d+ bytes from 192\.5\.6\.30#53\(a\.gtld-servers\.net\) "
                     r"in \d+ ms", text)
    assert "#53(a.iana-servers.net) in" in text
    # After priming, the root list the root server gave is the one used.
    assert {s.name for s in tracer.servers} == {"a.iana-servers.net."}


def test_trace_follows_a_referral_without_glue_through_the_resolver():
    def glueless(packet, tcp=False, edns=True):
        return _answer(packet, authority=[_ns("example.com.", "ns1.example.net.")])

    asked = []

    def resolve(name):
        asked.append(name)
        return [IANA]

    tracer = _tracer(FakeDNS(com=glueless), resolve=resolve).run()
    assert tracer.ok and asked == ["ns1.example.net."]
    assert tracer.steps[-1].server == "ns1.example.net." and tracer.steps[-1].address == IANA


def test_a_truncated_answer_is_asked_again_over_tcp():
    def truncating(packet, tcp=False, edns=True):
        if not tcp:
            return _answer(packet, tc=True)
        return FakeDNS.com_referral(packet)

    dns = FakeDNS(com=truncating)
    tracer = _tracer(dns).run()
    assert tracer.ok
    com_calls = [c for c in dns.calls if c[0] == GTLD]
    assert [c[3] for c in com_calls] == [False, True]
    assert ";; Truncated, retrying in TCP mode." in tracer.text()


def test_a_server_that_rejects_edns_is_asked_without_it():
    def old_server(packet, tcp=False, edns=True):
        if edns:
            return _answer(packet, rcode=1)                  # FORMERR
        return FakeDNS.com_referral(packet)

    dns = FakeDNS(com=old_server)
    assert _tracer(dns).run().ok
    assert [c[4] for c in dns.calls if c[0] == GTLD] == [True, False]


def test_nxdomain_is_an_answer_not_a_failure():
    def nothing(packet):
        return _answer(packet, authority=[_soa("example.com.")], rcode=3, aa=True)

    tracer = _tracer(FakeDNS(final=nothing), name="nope.example.com").run()
    assert tracer.ok and tracer.status == "NXDOMAIN" and not tracer.error
    text = tracer.text()
    assert ";; NXDOMAIN: nope.example.com. does not exist (says a.iana-servers.net)" in text
    assert "SOA" in text


def test_an_alias_and_a_name_without_the_type_say_what_they_are():
    def alias(packet):
        return _answer(packet, answers=[_cname("www.example.com.", "edge.example.net.")],
                       aa=True)

    tracer = _tracer(FakeDNS(final=alias)).run()
    assert tracer.ok and "is an alias for edge.example.net." in tracer.text()

    def nodata(packet):
        return _answer(packet, authority=[_soa("example.com.")], aa=True)

    tracer = _tracer(FakeDNS(final=nodata), qtype="AAAA").run()
    assert tracer.ok and "NODATA: www.example.com. exists but has no AAAA record." in tracer.text()


def test_a_referral_upwards_stops_the_walk_as_a_lame_delegation():
    def upwards(packet, tcp=False, edns=True):
        return _answer(packet, authority=[_ns(".", "a.root-servers.net.")],
                       additional=[_a("a.root-servers.net.", "198.41.0.4")])

    tracer = _tracer(FakeDNS(com=upwards)).run()
    assert not tracer.ok and "lame delegation" in tracer.error
    assert tracer.text().rstrip().endswith(tracer.error)


def test_servers_that_never_answer_are_reported_like_dig_does():
    def silent(packet, tcp=False, edns=True):
        raise socket.timeout("timed out")

    tracer = _tracer(FakeDNS(com=silent)).run()
    assert not tracer.ok and tracer.error == "No server for com. answered."
    assert ";; communications error to 192.5.6.30#53: timed out" in tracer.text()

    def refused(packet, tcp=False, edns=True):
        raise ConnectionRefusedError(111, "Connection refused")

    tracer = _tracer(FakeDNS(com=refused)).run()
    assert ";; communications error to 192.5.6.30#53: Connection refused" in tracer.text()


def test_answers_to_another_question_are_not_believed():
    def spoofed(packet, tcp=False, edns=True):
        return _answer(packet, authority=[_ns("example.com.", "evil.example.")],
                       qid=(struct.unpack("!H", packet[:2])[0] + 1) & 0xFFFF)

    tracer = _tracer(FakeDNS(com=spoofed)).run()
    assert not tracer.ok and "answered a different question" in tracer.text()


def test_a_network_that_answers_port_53_itself_is_named():
    def middlebox(packet):
        return _answer(packet, rcode=3)                       # NXDOMAIN for "."

    tracer = _tracer(FakeDNS(prime=middlebox)).run()
    assert not tracer.ok and len(tracer.steps) == 1
    assert "intercepts DNS on port 53" in tracer.error and "NXDOMAIN" in tracer.error

    def blocked(address, packet, tcp=False):
        raise OSError(101, "Network is unreachable")

    tracer = _tracer(blocked).run()
    assert not tracer.ok and "No root server answered" in tracer.error
    assert "communications error to" in tracer.text()


def test_a_delegation_loop_ends():
    def loop(packet, tcp=False, edns=True):
        name, _t, _e = _question(packet)
        return _answer(packet, authority=[_ns("example.com.", "a.gtld-servers.net.")],
                       additional=[_a("a.gtld-servers.net.", GTLD)])

    def deeper(packet):
        # Each level refers one label deeper, for ever.
        name, _t, _e = _question(packet)
        return _answer(packet, authority=[_ns(name, "a.iana-servers.net.")],
                       additional=[_a("a.iana-servers.net.", IANA)])

    name = ".".join(["x"] * 30) + ".example.com"
    tracer = _tracer(FakeDNS(com=loop, final=deeper), name=name)
    tracer.run()
    assert tracer.done and not tracer.ok and len(tracer.steps) <= dnstrace.MAX_STEPS + 1


def test_dig_trace_falls_back_to_the_built_in_walk(monkeypatch):
    seen = []

    async def fake_direct(domain, progress=None):
        seen.append(domain)
        return dns_whois.CommandResult(True, "trace text", "", "built-in trace (x)")

    monkeypatch.setattr(dns_whois, "have", lambda tool: tool != "dig")
    monkeypatch.setattr(dns_whois, "trace_direct", fake_direct)
    result = asyncio.run(dns_whois.trace("example.com"))
    assert seen == ["example.com"] and result.output == "trace text"


def test_the_built_in_walk_reports_each_level_as_it_goes():
    messages = []
    tracer = _tracer(FakeDNS())
    result = asyncio.run(dns_whois.trace_direct("www.example.com", progress=messages.append,
                                                tracer=tracer))
    assert result.ok and result.output == tracer.text()
    assert result.command.startswith(dns_whois.TRACE_BUILT_IN)
    assert messages == [
        "Asking the root servers about www.example.com…",
        "Asking the root servers about www.example.com…",
        "Asking the com servers about www.example.com…",
        "Asking the example.com servers about www.example.com…",
    ]


def _dns_pane_run(tmp_path, monkeypatch, result):
    from textual.widgets import TabbedContent

    from netzilla.app import NetzillaApp
    from netzilla.clipboard import plain
    from netzilla.screens.dns_whois import DNSWhoisPane

    monkeypatch.setattr(hostos, "NAME", hostos.WINDOWS)

    async def fake_trace(domain, progress=None):
        if progress:
            progress("Asking the root servers about example.com…")
        return result

    monkeypatch.setattr(dns_whois, "trace", fake_trace)

    async def go():
        app = NetzillaApp(config_path=tmp_path / "config.toml", offline=True)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            app.query_one("#tabs", TabbedContent).active = "dns"
            await pilot.pause()
            pane = app.query(DNSWhoisPane).first()
            pane.set_field("target", "example.com")
            await pane.execute("trace")
            await pilot.pause()
            return plain([w.content for w in pane.results.children
                          if getattr(w, "content", None)], 160)

    return asyncio.run(go())


def test_dns_tab_on_windows_shows_the_built_in_trace(tmp_path, monkeypatch):
    tracer = _tracer(FakeDNS(), name="example.com").run()
    good = dns_whois.CommandResult(True, tracer.text(), "",
                                   f"{dns_whois.TRACE_BUILT_IN} (dig is not installed)")
    text = _dns_pane_run(tmp_path, monkeypatch, good)
    assert "DELEGATION PATH" in text.upper() and "built-in trace" in text
    assert "a.gtld-servers.net." in text and "not installed" in text
    assert "THE TRACE STOPPED" not in text.upper()

    bad = dns_whois.CommandResult(False, "; <<>> netzilla trace <<>> example.com A\n",
                                  "A root server's address answered NXDOMAIN without "
                                  "listing the root servers — something on this network "
                                  "intercepts DNS on port 53, so the real delegation can't "
                                  "be walked from here.",
                                  f"{dns_whois.TRACE_BUILT_IN} (dig is not installed)")
    text = _dns_pane_run(tmp_path, monkeypatch, bad)
    assert "THE TRACE STOPPED" in text.upper() and "intercepts DNS" in text


def test_windows_help_and_tool_notes_no_longer_say_trace_is_missing():
    from netzilla import help as cards

    card = cards.get_help("DNSWhoisPane", "trace", hostos.WINDOWS)
    assert "walks the delegation itself" in card.note and "Linux and macOS only" not in card.note
    assert "walks the delegation itself" in cards.get_help("DNSWhoisPane", "trace", "linux").note
    assert "DIG +TRACE" in hostos.UNAVAILABLE["dig"]
    dhcp_card = cards.get_help("LANPane", "dhcp", hostos.WINDOWS)
    assert "Run as administrator" in dhcp_card.note and "can't listen" not in dhcp_card.note


# ====================================================== ROGUE DHCP on Windows
def _offer(xid: int, server: str, offered: str, lease: int = 86400) -> bytes:
    body = bytearray(240)
    body[0] = 2                                             # BOOTREPLY
    body[1], body[2] = 1, 6
    body[4:8] = struct.pack("!I", xid)
    body[16:20] = socket.inet_aton(offered)
    body[236:240] = dhcp.MAGIC_COOKIE
    options = (bytes([53, 1, 2, 54, 4]) + socket.inet_aton(server)
               + bytes([1, 4]) + socket.inet_aton("255.255.255.0")
               + bytes([3, 4]) + socket.inet_aton(server)
               + bytes([51, 4]) + struct.pack("!I", lease) + bytes([255]))
    return bytes(body) + options


def _ip_packet(payload: bytes, source: str, sport=67, dport=68, protocol=17,
               fragment=0) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, fragment, 64,
                         protocol, 0, socket.inet_aton(source),
                         socket.inet_aton("255.255.255.255"))
    return header + udp


class FakeSocket:
    def __init__(self, world, kind):
        self.world, self.kind = world, kind
        self.options, self.bound, self.sent, self.ioctls = [], None, [], []
        self.closed = False
        self.inbox = list(world.inbox.get(kind, []))

    def setsockopt(self, *args):
        self.options.append(args)

    def bind(self, address):
        error = self.world.bind_errors.get((self.kind, address[1]))
        if error is not None:
            raise error
        self.bound = address

    def sendto(self, data, address):
        self.sent.append((data, address))
        self.world.sent.append((self.kind, self.bound, data, address))

    def settimeout(self, value):
        pass

    def ioctl(self, control, mode):
        self.ioctls.append((control, mode))
        if mode in self.world.ioctl_refuses:
            raise OSError(10022, "An invalid argument was supplied")

    def recv(self, size):
        if self.inbox:
            return self.inbox.pop(0)
        raise socket.timeout("timed out")

    def recvfrom(self, size):
        if self.inbox:
            return self.inbox.pop(0)
        raise socket.timeout("timed out")

    def connect(self, address):
        self.peer = address

    def getsockname(self):
        return (self.world.address, 50000)

    def close(self):
        self.closed = True


class FakeSockets:
    """Just enough of the socket module for detect_windows."""

    AF_INET, SOCK_DGRAM, SOCK_RAW, IPPROTO_IP = 2, 2, 3, 0
    SOL_SOCKET, SO_BROADCAST, SO_RCVBUF = 0xFFFF, 0x20, 0x1002
    SIO_RCVALL, RCVALL_ON, RCVALL_OFF, RCVALL_IPLEVEL = 0x98000001, 1, 0, 3

    def __init__(self, address="192.168.1.50"):
        self.address = address
        self.inbox: dict[str, list] = {}
        self.bind_errors: dict = {}
        self.ioctl_refuses: set = set()
        self.raw_error: Exception | None = None
        self.sent: list = []
        self.made: list[FakeSocket] = []

    def socket(self, family, kind, proto=0):
        name = "raw" if kind == self.SOCK_RAW else "udp"
        if name == "raw" and self.raw_error is not None:
            raise self.raw_error
        sock = FakeSocket(self, name)
        self.made.append(sock)
        return sock

    def gethostname(self):
        return "box"

    def gethostbyname(self, name):
        return "127.0.1.1"


def _detect(sockets, **kwargs):
    return dhcp.detect_windows(listen_seconds=1.0, sockets=sockets,
                               clock=Clock(step=0.05), **kwargs)


def test_dhcp_offers_are_read_out_of_raw_ip_packets():
    payload = _offer(0x11223344, "192.168.1.1", "192.168.1.77")
    offer = dhcp.offer_from_ip_packet(_ip_packet(payload, "192.168.1.1"), 0x11223344)
    assert offer["from"] == "192.168.1.1" and offer["offered_ip"] == "192.168.1.77"
    assert offer["server_id"] == "192.168.1.1" and offer["lease_seconds"] == 86400
    assert dhcp.offer_from_ip_packet(_ip_packet(payload, "192.168.1.1"), 0x99) is None
    assert dhcp.offer_from_ip_packet(_ip_packet(payload, "192.168.1.1", sport=53), None) is None
    assert dhcp.offer_from_ip_packet(_ip_packet(payload, "192.168.1.1", protocol=6), None) is None
    assert dhcp.offer_from_ip_packet(_ip_packet(payload, "192.168.1.1", fragment=185),
                                     None) is None
    assert dhcp.offer_from_ip_packet(b"\x60" + bytes(60), None) is None
    assert dhcp.offer_from_ip_packet(b"\x45\x00", None) is None


def test_the_default_route_address_is_found_without_sending_anything():
    world = FakeSockets("10.1.2.3")
    assert dhcp.primary_ipv4(world) == "10.1.2.3"
    assert world.sent == [] and world.made[0].peer == ("192.0.2.1", 9)
    world = FakeSockets("0.0.0.0")
    assert dhcp.primary_ipv4(world) == ""                  # 127.0.1.1 is no use either


def test_windows_hears_offers_on_udp_68_when_the_dhcp_client_is_stopped():
    world = FakeSockets()
    random.seed(4)
    xid = random.Random(4).getrandbits(32)
    world.inbox["udp"] = [(_offer(xid, "192.168.1.1", "192.168.1.70"), ("192.168.1.1", 67))]
    random.seed(4)
    offers = _detect(world, admin=False)
    assert [o["server_id"] for o in offers] == ["192.168.1.1"]
    assert offers[0]["heard"] == "udp/68" and dhcp.LAST_HEARD == "udp/68"
    kind, bound, data, address = world.sent[0]
    assert kind == "udp" and address == ("255.255.255.255", 67) and bound == ("", 68)
    assert all(s.closed for s in world.made)


def test_windows_without_administrator_is_told_how_to_get_it():
    world = FakeSockets()
    world.bind_errors[("udp", 68)] = OSError(10048, "Only one usage of each socket address")
    with pytest.raises(PermissionError) as raised:
        _detect(world, admin=False)
    assert "Run as administrator" in str(raised.value)
    world.raw_error = PermissionError(10013, "An attempt was made to access a socket "
                                             "in a way forbidden by its access permissions")
    with pytest.raises(PermissionError) as raised:
        _detect(world, admin=True)
    assert raised.value.args[0] == dhcp.WINDOWS_ADMIN_HELP


def test_windows_as_administrator_hears_every_server_on_a_raw_socket():
    world = FakeSockets("192.168.1.50")
    world.bind_errors[("udp", 68)] = OSError(10048, "in use")
    random.seed(9)
    xid = random.Random(9).getrandbits(32)
    real = _offer(xid, "192.168.1.1", "192.168.1.80")
    rogue = _offer(xid, "192.168.1.66", "10.10.10.10", lease=600)
    world.inbox["raw"] = [
        _ip_packet(b"not dhcp at all", "192.168.1.9", sport=5353, dport=5353),
        _ip_packet(real, "192.168.1.1"),
        _ip_packet(_offer(xid ^ 1, "192.168.1.2", "192.168.1.81"), "192.168.1.2"),
        _ip_packet(rogue, "192.168.1.66"),
        _ip_packet(real, "192.168.1.1"),                     # heard twice, listed once
    ]
    world.ioctl_refuses = {FakeSockets.RCVALL_ON}            # e.g. Wi-Fi: no promiscuity
    random.seed(9)
    offers = _detect(world, admin=True)
    assert sorted(o["server_id"] for o in offers) == ["192.168.1.1", "192.168.1.66"]
    assert {o["heard"] for o in offers} == {"raw socket on 192.168.1.50"}
    raw = next(s for s in world.made if s.kind == "raw")
    assert raw.bound == ("192.168.1.50", 0)
    assert raw.ioctls[:2] == [(FakeSockets.SIO_RCVALL, FakeSockets.RCVALL_ON),
                              (FakeSockets.SIO_RCVALL, FakeSockets.RCVALL_IPLEVEL)]
    assert raw.ioctls[-1] == (FakeSockets.SIO_RCVALL, FakeSockets.RCVALL_OFF)
    sender = [kind_bound for kind_bound in world.sent if kind_bound[0] == "udp"]
    assert sender[-1][1] == ("192.168.1.50", 0) and sender[-1][3] == ("255.255.255.255", 67)
    assert all(s.closed for s in world.made)
    assert dhcp.verdict(offers)[1] == "bad"


def test_a_raw_socket_windows_refuses_is_explained():
    world = FakeSockets()
    world.bind_errors[("udp", 68)] = OSError(10048, "in use")
    world.bind_errors[("raw", 0)] = OSError(10049, "The requested address is not valid")
    with pytest.raises(OSError) as raised:
        _detect(world, admin=True)
    assert "would not open a raw socket on 192.168.1.50" in str(raised.value)
    world = FakeSockets("0.0.0.0")
    world.bind_errors[("udp", 68)] = OSError(10048, "in use")
    with pytest.raises(OSError) as raised:
        _detect(world, admin=True)
    assert "no IPv4 address" in str(raised.value)


def test_rogue_dhcp_runs_the_windows_way_on_windows(windows, monkeypatch):
    calls = []

    def fake(listen_seconds, mac):
        calls.append((listen_seconds, mac))
        return [{"server_id": "192.168.1.1"}]

    monkeypatch.setattr(dhcp, "detect_windows", fake)
    assert asyncio.run(dhcp.detect(2.5)) == [{"server_id": "192.168.1.1"}]
    assert calls == [(2.5, None)]


def _lan_dhcp(tmp_path, monkeypatch, detect, heard=""):
    from textual.widgets import TabbedContent

    from netzilla.app import NetzillaApp
    from netzilla.clipboard import plain
    from netzilla.screens.lan import LANPane

    monkeypatch.setattr(hostos, "NAME", hostos.WINDOWS)
    monkeypatch.setattr(dhcp, "detect", detect)
    monkeypatch.setattr(dhcp, "LAST_HEARD", heard)

    async def go():
        app = NetzillaApp(config_path=tmp_path / "config.toml", offline=True)
        async with app.run_test(size=(180, 50)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            app.query_one("#tabs", TabbedContent).active = "lan"
            await pilot.pause()
            pane = app.query(LANPane).first()
            await pane.execute("dhcp")
            await pilot.pause()
            return plain([w.content for w in pane.results.children
                          if getattr(w, "content", None)], 180)

    return asyncio.run(go())


def test_lan_tab_on_windows_asks_for_administrator(tmp_path, monkeypatch):
    async def refused(listen_seconds=5.0, mac=None):
        raise PermissionError(dhcp.WINDOWS_ADMIN_HELP)

    text = _lan_dhcp(tmp_path, monkeypatch, refused)
    assert "NEEDS ADMINISTRATOR" in text.upper() and "Run as administrator" in text
    assert "UDP/68 is taken" not in text


def test_lan_tab_on_windows_lists_offers_and_says_how_it_heard_them(tmp_path, monkeypatch):
    heard = "raw socket on 192.168.1.50"

    async def two(listen_seconds=5.0, mac=None):
        return [{"server_id": "192.168.1.1", "offered_ip": "192.168.1.80", "from": "192.168.1.1",
                 "routers": ["192.168.1.1"], "dns": [], "heard": heard},
                {"server_id": "192.168.1.66", "offered_ip": "10.0.0.5", "from": "192.168.1.66",
                 "routers": [], "dns": [], "heard": heard}]

    text = _lan_dhcp(tmp_path, monkeypatch, two, heard)
    assert "192.168.1.66" in text and f"heard on a {heard}" in text
    assert "MORE THAN ONE DHCP SERVER" in text.upper()

    async def none(listen_seconds=5.0, mac=None):
        return []

    text = _lan_dhcp(tmp_path, monkeypatch, none, heard)
    assert "NOTHING HEARD" in text.upper() and "Windows Defender Firewall" in text


# ====================================================== Sixel: the encoder
def _decode(sequence: str):
    """(width, height, {(x, y): (r, g, b)}) of one Sixel image — only the
    pixels it sets."""
    assert sequence.startswith("\x1bP") and sequence.endswith("\x1b\\"), sequence[:20]
    params, body = sequence[2:-2].split("q", 1)
    assert [int(p or 0) for p in params.split(";")][1] == 1      # unset pixels stay as they are
    raster = re.match(r'"1;1;(\d+);(\d+)', body)
    width, height = int(raster.group(1)), int(raster.group(2))
    body = body[raster.end():]
    pixels_set, registers = {}, {}
    x = y = colour = i = 0
    while i < len(body):
        char = body[i]
        if char == "#":
            match = re.match(r"#(\d+)(?:;2;(\d+);(\d+);(\d+))?", body[i:])
            colour = int(match.group(1))
            if match.group(2) is not None:
                registers[colour] = tuple(round(int(match.group(k)) * 255 / 100)
                                          for k in (2, 3, 4))
            i += match.end()
            continue
        if char == "$":
            x, i = 0, i + 1
            continue
        if char == "-":
            x, y, i = 0, y + 6, i + 1
            continue
        count = 1
        if char == "!":
            match = re.match(r"!(\d+)", body[i:])
            count, i = int(match.group(1)), i + match.end()
            char = body[i]
        bits = ord(char) - 63
        assert 0 <= bits < 64
        for _ in range(count):
            for k in range(6):
                if bits >> k & 1:
                    pixels_set[(x, y + k)] = registers[colour]
            x += 1
        i += 1
    return width, height, pixels_set


def _close(a, b, slack=3):
    return a is not None and b is not None and all(abs(p - q) <= slack for p, q in zip(a, b))


@needs_pil
def test_sixel_images_come_back_pixel_for_pixel():
    from PIL import Image, ImageDraw

    rng = random.Random(3)
    image = Image.new("RGB", (37, 23), (10, 20, 30))
    draw = ImageDraw.Draw(image)
    for _ in range(40):
        x0, x1 = sorted(rng.randrange(37) for _ in range(2))
        y0, y1 = sorted(rng.randrange(23) for _ in range(2))
        draw.rectangle((x0, y0, x1, y1), fill=tuple(rng.randrange(256) for _ in range(3)))
    sequence = sixel.encode(image)
    assert sequence.startswith('\x1bP0;1;0q"1;1;37;23')
    width, height, got = _decode(sequence)
    assert (width, height) == (37, 23)
    assert all(_close(got.get((x, y)), image.getpixel((x, y)))
               for y in range(23) for x in range(37))
    assert all(x < 37 and y < 23 for x, y in got)
    # A mask leaves holes; `clear` leaves the background colour unset.
    mask = Image.new("L", image.size, 255)
    mask.paste(0, (5, 5, 15, 12))
    _w, _h, got = _decode(sixel.encode(image, mask))
    assert all((x, y) not in got for y in range(5, 12) for x in range(5, 15))
    assert (0, 0) in got or image.getpixel((0, 0)) != (10, 20, 30)
    flat = Image.new("RGB", (12, 12), (10, 20, 30))
    flat.paste((200, 0, 0), (3, 3, 6, 6))
    _w, _h, got = _decode(sixel.encode(flat, clear=(10, 20, 30)))
    assert set(got) == {(x, y) for x in range(3, 6) for y in range(3, 6)}


@needs_pil
def test_photographs_are_cut_to_255_colours_and_index_255_means_unset():
    from PIL import Image

    image = Image.effect_mandelbrot((300, 60), (-2, -1, 1, 1), 60).convert("RGB")
    image = Image.merge("RGB", (image.getchannel(0), image.getchannel(0).rotate(90),
                                image.getchannel(0).transpose(Image.Transpose.FLIP_LEFT_RIGHT)))
    sequence = sixel.encode(image)
    registers = {int(n) for n in re.findall(r"#(\d+);2;", sequence)}
    assert registers and max(registers) < sixel.SKIP and len(registers) <= sixel.MAX_COLOURS
    width, height, got = _decode(sequence)
    assert (width, height) == (300, 60) and len(got) == 300 * 60


def test_runs_are_compressed_and_blank_lines_cost_nothing():
    assert sixel._compress(b"??????~~~~~~@") == b"!6?!6~@"
    assert sixel._compress(b"~~~@") == b"~~~@"


@needs_pil
def test_marker_cells_carry_the_image_and_look_like_its_background():
    from PIL import Image

    image = Image.new("RGB", (40, 40), (12, 34, 56))
    image_id = sixel.show(image, 4, 2)
    row = sixel.placeholder_span(image_id, 1, 1, 3)
    assert row.plain == sixel.MARKER * 2 and not row.plain.isspace()
    style = row.spans[0].style if row.spans else row.style
    assert style.meta == {sixel.META: image_id, "r": 1, "c": 1}
    assert style.bgcolor.triplet.hex == "#0c2238"
    text = sixel.placeholder_text(image_id, 4, 2)
    assert text.plain == (sixel.MARKER * 4 + "\n") * 1 + sixel.MARKER * 4
    # Centring keeps every marker (spaces would be trimmed from the ends).
    centred = Text.assemble(text, justify="center")
    from rich.console import Console

    console = Console(width=20, color_system=None, file=io.StringIO())
    lines = console.render_lines(centred, console.options.update(width=20), pad=False)
    assert [sum(seg.text.count(sixel.MARKER) for seg in line) for line in lines] == [4, 4]
    sixel.delete(image_id)
    assert sixel.picture(image_id) is None


@needs_pil
def test_a_canvas_keeps_two_pictures_and_lets_older_ones_go():
    from PIL import Image

    canvas = sixel.Canvas()
    ids = [canvas.upload(Image.new("RGB", (10, 20), (i, 0, 0)), 1, 1) for i in range(4)]
    assert [sixel.picture(i) is not None for i in ids] == [False, False, True, True]
    canvas.clear()
    assert all(sixel.picture(i) is None for i in ids)


def test_copied_sixel_graphs_paste_as_shaded_blocks():
    from netzilla.clipboard import plain

    assert plain([Text("x ┤" + sixel.MARKER * 5)], 40).splitlines()[0] == "x ┤░░░░░"


def test_pixels_switches_between_kitty_and_sixel():
    written = []
    pixels.use(pixels.SIXEL)
    assert pixels.protocol() == pixels.SIXEL and pixels.module() is sixel
    pixels.set_writer(written.append)
    assert sixel.active() and not kitty.active()
    pixels.use(pixels.KITTY)
    pixels.set_writer(written.append)
    assert kitty.active() and not sixel.active()
    pixels.use("anything else")
    assert pixels.protocol() == pixels.KITTY
    assert isinstance(pixels.Canvas(), kitty.Canvas)


# ====================================================== Sixel: the overlay
CELL = (10, 20)


def _picture(cols, rows):
    """An image whose every cell has a colour of its own (and a 1-pixel frame
    in the background colour), so a decoded crop says which cells it holds."""
    from PIL import Image

    width, height = CELL
    image = Image.new("RGB", (cols * width, rows * height), (5, 5, 5))
    for row in range(rows):
        for col in range(cols):
            image.paste(_cell_colour(col, row),
                        (col * width + 1, row * height + 1, (col + 1) * width - 1,
                         (row + 1) * height - 1))
    return image


def _cell_colour(col, row):
    return (40 + col * 15, 60 + row * 30, 200)


def _cells_in(sequence, cols, rows):
    """{(col, row): drawn?} of a decoded crop, by the colour at cell centres."""
    width, height, got = _decode(sequence)
    found = {}
    for r in range(height // CELL[1] + 1):
        for c in range(width // CELL[0]):
            x, y = c * CELL[0] + CELL[0] // 2, r * CELL[1] + CELL[1] // 2
            if y < height:
                found[(c, r)] = got.get((x, y))
    return width, height, found


_SEQ = re.compile(r"\x1b7\x1b\[(\d+);(\d+)H(\x1bP.*?\x1b\\)\x1b8", re.S)


def _overlay_app(rows_above=2, cols=12, rows=5, size=(40, 20), cover=False,
                 scroll_height=None, filler=0):
    from textual.app import App
    from textual.containers import VerticalScroll
    from textual.widgets import Static

    image_id = sixel.show(_picture(cols, rows), cols, rows)

    class OverlayApp(App):
        CSS = """
        Screen { layers: base top; }
        #cover { layer: top; offset: 6 4; width: 5; height: 2; background: red; }
        """ + (f"#scroller {{ height: {scroll_height}; }}" if scroll_height else "")

        def __init__(self):
            super().__init__()
            self.image_id = image_id
            self.frames: list[str] = []

        def compose(self):
            with VerticalScroll(id="scroller"):
                yield Static("\n".join(f"line {i}" for i in range(rows_above)) or "",
                             id="above")
                yield Static(sixel.placeholder_text(image_id, cols, rows), id="graph")
                yield Static("\n".join("." for _ in range(filler)), id="filler")
            if cover:
                yield Static("toast", id="cover")

        def _display(self, screen, renderable, *args, **kwargs):
            if renderable is not None:
                self.frames.append(sixel.overlay(screen, renderable))
            return super()._display(screen, renderable, *args, **kwargs)

    return OverlayApp()


def _run_overlay(app, script, size=(40, 20)):
    async def go():
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            return await script(app, pilot)

    return asyncio.run(go())


@needs_pil
def test_an_image_is_drawn_over_its_marker_cells_after_the_frame():
    app = _overlay_app(rows_above=2)

    async def script(app, pilot):
        await pilot.pause()
        screen = app.screen
        full = sixel.overlay(screen, screen._compositor.render_update(full=True))
        return full, list(app.frames)

    full, frames = _run_overlay(app, script)
    drawn = _SEQ.findall(full)
    assert len(drawn) == 1
    row, col, image = drawn[0]
    assert (int(row), int(col)) == (3, 1)                     # below the two lines above
    width, height, cells = _cells_in(image, 12, 5)
    assert (width, height) == (120, 100)
    assert all(_close(cells[(c, r)], _cell_colour(c, r)) for c in range(12) for r in range(5))
    # The frames Textual wrote itself carried the image too.
    assert any(_SEQ.search(frame) for frame in frames)
    placement = sixel.OVERLAY.placements[app.image_id]
    assert (placement.left, placement.top) == (0, 2) and len(placement.cells) == 60


@needs_pil
def test_frames_that_leave_an_image_alone_do_not_redraw_it():
    app = _overlay_app(rows_above=2)

    async def script(app, pilot):
        app.frames.clear()
        app.query_one("#filler").update("changed")
        await pilot.pause()
        untouched = list(app.frames)
        app.frames.clear()
        app.query_one("#graph").update(sixel.placeholder_text(app.image_id, 12, 5))
        await pilot.pause()
        return untouched, list(app.frames)

    untouched, touched = _run_overlay(app, script)
    assert untouched and not any(_SEQ.search(frame) for frame in untouched)
    assert any(_SEQ.search(frame) for frame in touched)


@needs_pil
def test_a_scrolled_image_is_cropped_to_what_is_visible():
    app = _overlay_app(rows_above=2, scroll_height=6, filler=10)

    async def script(app, pilot):
        app.query_one("#scroller").scroll_to(y=4, animate=False)
        await pilot.pause()
        await pilot.pause()
        screen = app.screen
        return sixel.overlay(screen, screen._compositor.render_update(full=True))

    full = _run_overlay(app, script)
    (row, col, image), = _SEQ.findall(full)
    assert (int(row), int(col)) == (1, 1)                     # image row 2 at the top
    width, height, cells = _cells_in(image, 12, 3)
    assert (width, height) == (120, 60)
    assert _close(cells[(0, 0)], _cell_colour(0, 2)) and _close(cells[(5, 2)], _cell_colour(5, 4))


@needs_pil
def test_whatever_sits_on_top_of_an_image_keeps_its_cells():
    app = _overlay_app(rows_above=2, cover=True)

    async def script(app, pilot):
        screen = app.screen
        return sixel.overlay(screen, screen._compositor.render_update(full=True))

    full = _run_overlay(app, script)
    (row, col, image), = _SEQ.findall(full)
    width, height, cells = _cells_in(image, 12, 5)
    # The cover is 5 x 2 cells at screen (6, 4): image cells (6..10, 2..3).
    for c in range(12):
        for r in range(5):
            covered = 6 <= c < 11 and 2 <= r < 4
            assert (cells[(c, r)] is None) == covered, (c, r)


@needs_pil
def test_nothing_is_drawn_on_the_last_row_or_hangs_into_it():
    # 20 rows: the graph's rows land on screen rows 14..18; row 19 is the last.
    app = _overlay_app(rows_above=14, rows=6)

    async def script(app, pilot):
        screen = app.screen
        return sixel.overlay(screen, screen._compositor.render_update(full=True))

    full = _run_overlay(app, script)
    (row, col, image), = _SEQ.findall(full)
    width, height, _cells = _cells_in(image, 12, 5)
    assert int(row) == 15
    # Rows 14..18 are drawn; the sixth image row (on row 19) isn't, and the
    # last band is cut so the image ends on a whole band above row 19.
    assert height == (5 * CELL[1]) // 6 * 6 and height % 6 == 0


@needs_pil
def test_a_layer_follows_its_base_and_stays_off_dialogs():
    from PIL import Image
    from textual.screen import ModalScreen
    from textual.widgets import Static

    app = _overlay_app(rows_above=2)
    layer = sixel.show(Image.new("RGB", (40, 40), (250, 120, 0)), 4, 2)

    class Dialog(ModalScreen):
        def compose(self):
            yield Static("dialog")

    async def script(app, pilot):
        screen = app.screen
        sixel.overlay(screen, screen._compositor.render_update(full=True))
        over = sixel.OVERLAY.draw_over(screen, app.image_id, layer, 2, 1)
        again = sixel.overlay(screen, screen._compositor.render_update(full=True))
        written = []
        sixel.set_writer(written.append)
        sent = sixel.draw_over(screen, app.image_id, layer, 2, 1)
        await app.push_screen(Dialog())
        await pilot.pause()
        blocked = sixel.OVERLAY.draw_over(screen, app.image_id, layer, 2, 1)
        return over, again, sent, written, blocked

    over, again, sent, written, blocked = _run_overlay(app, script)
    (row, col, image), = _SEQ.findall(over)
    assert (int(row), int(col)) == (4, 3)                      # base (0, 2) + (2, 1)
    width, height, got = _decode(image)
    assert (width, height) == (40, 40) and _close(got[(0, 0)], (250, 120, 0))
    assert [m[2] for m in _SEQ.findall(again)][-1] == image   # redrawn after its base
    assert sent and written == [over]
    assert blocked == ""


def test_app_frames_carry_the_overlay_only_for_compositor_updates():
    from netzilla.app import _with_sixels

    plain_text = Text("hello")
    assert _with_sixels(None, plain_text) is plain_text


@needs_pil
def test_netzilla_appends_the_overlay_to_the_frame_it_writes(tmp_path):
    from netzilla.app import NetzillaApp, _with_sixels

    async def go():
        app = NetzillaApp(config_path=tmp_path / "config.toml", offline=True)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            _sixel_mode(app)
            await pilot.pause(0.3)
            update = app.screen._compositor.render_update(full=True)
            wrapped = _with_sixels(app.screen, update)
            return update.render_segments(app.console), wrapped.render_segments(app.console)

    plain_frame, with_images = asyncio.run(go())
    assert with_images.startswith(plain_frame) and len(with_images) > len(plain_frame)
    assert "\x1bP0;1;0q" in with_images[len(plain_frame):]


# ====================================================== Sixel in netzilla
def _sixel_mode(app, written=None):
    """As _start_graphics does in Windows Terminal (headless can't)."""
    pixels.use(pixels.SIXEL)
    sixel.set_writer((written if written is not None else []).append)
    app.terminal = termcaps.detect({"WT_SESSION": "1"}, b"\x1b[?61;4;6;7;14;21;22;23;24;28;32;42c")
    app._pixels_ready = True
    app._cell_px = app._measure_cells()
    app._refresh_static_graphics()


@needs_pil
def test_dash_banner_is_one_sixel_image_and_the_breath_is_laid_over_it(tmp_path):
    from netzilla.app import NetzillaApp
    from netzilla.graphics import banner
    from netzilla.screens.dashboard import DashboardPane

    written = []

    async def go():
        app = NetzillaApp(config_path=tmp_path / "config.toml", offline=True)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            _sixel_mode(app, written)
            await pilot.pause(0.2)
            pane = app.query(DashboardPane).first()
            art = pane.query_one("#banner").content
            # Place the banner as a real frame would.
            sixel.overlay(app.screen, app.screen._compositor.render_update(full=True))
            await pilot.pause(banner.FIRE_EVERY * 8)
            later = pane.query_one("#banner").content
            return dict(pane._logo), art, later, app.cell_px, dict(sixel.OVERLAY.layers)

    logo, art, later, cell, layers = asyncio.run(go())
    assert logo["mode"] == "pixels" and cell == (10, 20)
    ids = {span.style.meta.get(sixel.META) for span in art.spans if span.style
           and getattr(span.style, "meta", None)}
    assert ids == {logo["banner_id"]}                         # no fire cells in the text
    assert sixel.MARKER in art.plain and later is art         # the text never changes
    fires = [w for w in written if "\x1bP" in w]
    assert fires, "the breath was never drawn"
    assert all(len(_SEQ.findall(w)) == 1 for w in fires)
    assert set(logo["fire_ids"]) <= set(range(0, banner.FIRE_FRAMES, 2))
    assert layers[logo["banner_id"]][1:] == logo["window"][:2]


@needs_pil
def test_every_tab_draws_in_sixel_mode(tmp_path):
    from textual.widgets import TabbedContent

    from netzilla.app import TABS, NetzillaApp
    from netzilla.graphics.charts import LineGraph

    async def go():
        app = NetzillaApp(config_path=tmp_path / "config.toml", offline=True)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            _sixel_mode(app)
            tabs = app.query_one("#tabs", TabbedContent)
            for tab_id, _label, pane_class in TABS:
                tabs.active = tab_id
                await pilot.pause()
                assert tabs.active == tab_id
                sixel.overlay(app.screen, app.screen._compositor.render_update(full=True))
            pane = app.query(TABS[0][2]).first()
            graph = pane.graph("v47", LineGraph([1, 5, 3, 8, 2] * 10, 0, 10, width=50))
            return graph, app.graphics_mode

    graph, mode = asyncio.run(go())
    assert mode == "pixel" and sixel.MARKER in graph.plain
    assert "┤" in graph.plain                                  # the axis stays text


def test_graphs_still_use_kitty_where_kitty_works(tmp_path):
    from netzilla.app import NetzillaApp
    from netzilla.graphics.charts import LineGraph

    written = []

    async def go():
        app = NetzillaApp(config_path=tmp_path / "config.toml", offline=True)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            kitty.set_writer(written.append)
            app.terminal = termcaps.detect({"TERM": "xterm-kitty"})
            app._pixels_ready = True
            pane = app.query("DashboardPane").first()
            return pane.graph("v47", LineGraph([1, 5, 3] * 10, 0, 10, width=30))

    graph = asyncio.run(go())
    if plot.HAVE_PIL:
        assert kitty.PLACEHOLDER in graph.plain and sixel.MARKER not in graph.plain
        assert any("a=T" in w for w in written)


# ====================================================== detecting Sixel
WT_DA1 = b"\x1b[?61;4;6;7;14;21;22;23;24;28;32;42c"
OLD_WT_DA1 = b"\x1b[?61;6;7;14;21;22;23;24;28;32;42c"


def test_windows_terminal_with_sixel_gets_pixel_graphs():
    info = termcaps.detect({"WT_SESSION": "abc"}, WT_DA1)
    assert info.name == "windows-terminal" and info.sixel and not info.placeholders
    assert info.pixel_capable() and info.image_protocol() == "sixel"
    assert info.graphics_mode("auto") == "pixel" and info.sixel_cell() == (10, 20)
    assert "Sixel images" in info.graphics_reason()


def test_older_or_silent_windows_terminals_say_what_to_do():
    old = termcaps.detect({"WT_SESSION": "abc"}, OLD_WT_DA1)
    assert not old.sixel and old.graphics_mode("auto") == "text"
    assert "1.22" in old.graphics_reason() and "winget upgrade" in old.graphics_reason()
    silent = termcaps.detect({"WT_SESSION": "abc"}, b"")
    assert silent.graphics_mode("auto") == "text"
    assert "did not answer" in silent.graphics_reason()
    assert silent.image_protocol() == "sixel"                  # what Pixel would use


def test_wezterm_uses_sixel_once_it_knows_the_cell_size():
    env = {"TERM_PROGRAM": "WezTerm", "TERM_PROGRAM_VERSION": "20240203-110809-5046fc22"}
    reply = b"\x1bP>|WezTerm 20240203-110809-5046fc22\x1b\\" + b"\x1b[6;19;9t" + WT_DA1
    info = termcaps.detect(env, reply)
    assert info.name == "wezterm" and info.sixel and info.cell_px == (9, 19)
    assert info.graphics_mode("auto") == "pixel" and info.image_protocol() == "sixel"
    assert info.sixel_cell() is None
    blind = termcaps.detect(env, b"\x1bP>|WezTerm 20240203\x1b\\" + WT_DA1)
    assert blind.graphics_mode("auto") == "text" and "cell size" in blind.graphics_reason()


def test_other_sixel_terminals_get_it_only_when_asked():
    info = termcaps.detect({"TERM": "xterm"}, b"\x1bP>|XTerm(390)\x1b\\" + b"\x1b[?63;1;2;4;6;9c")
    assert info.sixel and not info.pixel_capable() and info.graphics_mode("auto") == "text"
    assert info.graphics_mode("pixel") == "pixel" and info.image_protocol() == "sixel"
    assert "choose Pixel on SETTINGS" in info.graphics_reason()


def test_sixel_is_off_through_tmux_and_under_no_color():
    tmux = termcaps.detect({"WT_SESSION": "abc", "TMUX": "/tmp/tmux-0/default,1,0",
                            "TERM": "tmux-256color"}, WT_DA1)
    assert not tmux.sixel and not tmux.pixel_capable()
    grey = termcaps.detect({"WT_SESSION": "abc", "NO_COLOR": "1"}, WT_DA1)
    assert not grey.sixel and grey.graphics_mode("auto") == "text"
    assert "NO_COLOR" in grey.graphics_reason()


def test_da1_attributes_are_read():
    found = termcaps.parse_replies(b"junk\x1b[?62;4;22c")
    assert found["da1"] and found["da1_params"] == (62, 4, 22)
    assert termcaps.parse_replies(b"")["da1_params"] == ()
    assert termcaps.probe_query(windows=True) == (termcaps.XTVERSION_Q + termcaps.CELL_Q
                                                  + termcaps.DA1_Q)


class FakeConsole:
    def __init__(self, chunks, fail_open=False, fail_read=False):
        self.chunks, self.fail_open, self.fail_read = list(chunks), fail_open, fail_read
        self.written, self.closed, self.opened = [], False, False

    def open(self):
        if self.fail_open:
            raise OSError("not a console")
        self.opened = True

    def write(self, text):
        self.written.append(text)

    def read(self, timeout):
        if self.fail_read:
            raise OSError("gone")
        return self.chunks.pop(0) if self.chunks else ""

    def close(self):
        self.closed = True


def test_windows_consoles_are_asked_through_the_console_api():
    console = FakeConsole(["", "\x1b[?61;4;6", ";7;22c", "late"])
    reply = termcaps.probe_windows(timeout=5, console=console, clock=Clock(0.01))
    assert reply == b"\x1b[?61;4;6;7;22clate" and console.closed
    assert console.written == [termcaps.probe_query(windows=True)]
    assert termcaps.parse_replies(reply)["da1_params"] == (61, 4, 6, 7, 22)
    quiet = FakeConsole([])
    assert termcaps.probe_windows(timeout=0.3, console=quiet, clock=Clock(0.05)) == b""
    assert quiet.closed
    assert termcaps.probe_windows(console=FakeConsole([], fail_open=True)) == b""
    broken = FakeConsole([], fail_read=True)
    assert termcaps.probe_windows(console=broken, clock=Clock()) == b"" and broken.closed
    if hostos.NAME != hostos.WINDOWS:
        assert termcaps.probe_windows(timeout=0.01) == b""        # no console here


def test_terminal_report_names_the_image_protocol(monkeypatch, capsys, tmp_path):
    from netzilla import cli

    info = termcaps.detect({"WT_SESSION": "abc"}, WT_DA1)
    monkeypatch.setattr(termcaps, "startup", lambda allow_probe=True: info)

    class Args:
        no_probe, graphics, config = True, None, str(tmp_path / "config.toml")

    assert cli._terminal_report(Args()) == 0
    out = capsys.readouterr().out
    assert re.search(r"^Sixel\s+yes$", out, re.M)
    assert re.search(r"^Pixel graphs use\s+Sixel$", out, re.M)
    assert re.search(r"^Graphs will be drawn as\s+pixel$", out, re.M)


def test_forced_pixel_on_a_sixel_terminal_is_explained(tmp_path):
    from netzilla.app import NetzillaApp
    from netzilla.clipboard import plain

    async def go():
        app = NetzillaApp(config_path=tmp_path / "config.toml", offline=True,
                          graphics="pixel")
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            await app.workers.wait_for_complete()
            pixels.use(pixels.SIXEL)
            app.terminal = termcaps.detect({"TERM": "xterm"},
                                           b"\x1bP>|XTerm(390)\x1b\\\x1b[?63;1;2;4;6;9c")
            app._pixels_ready = True
            why = app.graphics_why()
            app.query_one("#tabs").active = "settings"
            await pilot.pause()
            settings = app.query("SettingsPane").first()
            settings._graphics_note()
            await pilot.pause()
            return why, plain([settings.query_one("#graphics-note").content], 200)

    why, note = asyncio.run(go())
    assert "Pixel is chosen on SETTINGS" in why and "Sixel" in why
    assert "drawn as Sixel images" in note
