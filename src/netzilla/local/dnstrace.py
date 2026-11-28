"""DIG +TRACE without dig: the delegation walk, done in Python.

dig +trace asks a root server who answers for a name's top-level domain,
asks one of those servers who answers for the next level down, and so on
until a server that holds the name itself answers — printing what each one
handed down. Windows has no dig, so netzilla walks the tree itself: plain DNS
over UDP port 53 (TCP when an answer doesn't fit), no recursion asked of any
server, every server asked only what it knows first-hand. The same walk runs
on any system without dig.

The output reads like dig's: each step's records, then
";; Received N bytes from ADDRESS#53(NAME) in T ms".

Wire format: RFC 1035 (names, compression, the sections); EDNS(0), which
lets a referral with all its glue fit in one UDP answer: RFC 6891. Unknown
record types print in the RFC 3597 form (\\# length hex).
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Callable

PORT = 53
EDNS_SIZE = 1232          # the DNS Flag Day 2020 size: no fragmentation on the way
UDP_TIMEOUT = 2.0         # seconds one server gets before the next is tried
TCP_TIMEOUT = 4.0
TRIES_PER_STEP = 3        # servers tried at one level before giving up
MAX_STEPS = 16            # far deeper than any real delegation

# IANA's root hints (named.root): every resolver starts from these.
ROOT_HINTS: tuple[tuple[str, str, str], ...] = (
    ("a.root-servers.net.", "198.41.0.4", "2001:503:ba3e::2:30"),
    ("b.root-servers.net.", "170.247.170.2", "2801:1b8:10::b"),
    ("c.root-servers.net.", "192.33.4.12", "2001:500:2::c"),
    ("d.root-servers.net.", "199.7.91.13", "2001:500:2d::d"),
    ("e.root-servers.net.", "192.203.230.10", "2001:500:a8::e"),
    ("f.root-servers.net.", "192.5.5.241", "2001:500:2f::f"),
    ("g.root-servers.net.", "192.112.36.4", "2001:500:12::d0d"),
    ("h.root-servers.net.", "198.97.190.53", "2001:500:1::53"),
    ("i.root-servers.net.", "192.36.148.17", "2001:7fe::53"),
    ("j.root-servers.net.", "192.58.128.30", "2001:503:c27::2:30"),
    ("k.root-servers.net.", "193.0.14.129", "2001:7fd::1"),
    ("l.root-servers.net.", "199.7.83.42", "2001:500:9f::42"),
    ("m.root-servers.net.", "202.12.27.33", "2001:dc3::35"),
)

TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 39: "DNAME", 41: "OPT", 43: "DS",
    46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 64: "SVCB", 65: "HTTPS",
    99: "SPF", 257: "CAA",
}
TYPE_CODES = {name: code for code, name in TYPES.items()}
CLASSES = {1: "IN", 3: "CH", 4: "HS"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
          5: "REFUSED", 9: "NOTAUTH"}

A, NS, CNAME, SOA, AAAA, OPT, DNAME = 1, 2, 5, 6, 28, 41, 39


class WireError(ValueError):
    """A DNS message that can't be read (truncated, or pointing nowhere)."""


# ================================================================ names
def encode_name(name: str) -> bytes:
    """'www.example.com' -> b'\\x03www\\x07example\\x03com\\x00'."""
    name = (name or "").strip().rstrip(".")
    if not name:
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        if not label:
            raise WireError(f"empty label in {name!r}")
        try:
            raw = label.encode("ascii")
        except UnicodeEncodeError:
            raw = label.encode("idna")
        if len(raw) > 63:
            raise WireError(f"label longer than 63 bytes in {name!r}")
        out.append(len(raw))
        out += raw
    out.append(0)
    if len(out) > 255:
        raise WireError(f"{name!r} is longer than 255 bytes")
    return bytes(out)


def _label_text(raw: bytes) -> str:
    """One label in presentation form: dots and odd bytes escaped as dig does."""
    out = []
    for byte in raw:
        char = chr(byte)
        if char in '.\\"();@$':
            out.append("\\" + char)
        elif 0x21 <= byte <= 0x7E:
            out.append(char)
        else:
            out.append(f"\\{byte:03d}")
    return "".join(out)


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    """The name at `offset` (following compression pointers) and the offset
    just past it in the original place."""
    labels: list[str] = []
    resume = -1
    jumps = 0
    length_so_far = 0
    while True:
        if offset >= len(data):
            raise WireError("name runs past the end of the message")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise WireError("compression pointer cut short")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if resume < 0:
                resume = offset + 2
            jumps += 1
            if jumps > 64 or pointer >= len(data):
                raise WireError("compression pointer loops or points nowhere")
            offset = pointer
            continue
        if length & 0xC0:
            raise WireError("unsupported label type")
        offset += 1
        if length == 0:
            break
        raw = data[offset:offset + length]
        if len(raw) < length:
            raise WireError("label runs past the end of the message")
        length_so_far += length + 1
        if length_so_far > 255:
            raise WireError("name longer than 255 bytes")
        labels.append(_label_text(raw))
        offset += length
    name = ".".join(labels) + "." if labels else "."
    return name, (resume if resume >= 0 else offset)


def same_name(a: str, b: str) -> bool:
    return a.rstrip(".").lower() == b.rstrip(".").lower()


def is_within(name: str, zone: str) -> bool:
    """True when `name` is `zone` or below it ('www.example.com' within 'com')."""
    name, zone = name.rstrip(".").lower(), zone.rstrip(".").lower()
    if not zone:
        return True
    return name == zone or name.endswith("." + zone)


def depth(name: str) -> int:
    name = name.rstrip(".")
    return len(name.split(".")) if name else 0


# ================================================================ messages
def build_query(name: str, qtype: int = A, qid: int = 0, edns: bool = True,
                recursion: bool = False) -> bytes:
    """A query for one name and type. No recursion is asked for: each server
    answers from what it holds itself, which is what a trace is about."""
    flags = 0x0100 if recursion else 0x0000
    header = struct.pack("!HHHHHH", qid & 0xFFFF, flags, 1, 0, 0, 1 if edns else 0)
    question = encode_name(name) + struct.pack("!HH", qtype, 1)
    if not edns:
        return header + question
    # OPT pseudo-record: root owner, class = our UDP size, no DO bit.
    return header + question + b"\x00" + struct.pack("!HHIH", OPT, EDNS_SIZE, 0, 0)


@dataclass
class Record:
    name: str
    rtype: int
    rclass: int
    ttl: int
    data: str                      # presentation form
    target: str = ""               # NS / CNAME / DNAME: the name it points to
    address: str = ""              # A / AAAA

    @property
    def type_name(self) -> str:
        return TYPES.get(self.rtype, f"TYPE{self.rtype}")


@dataclass
class Message:
    id: int
    flags: int
    question: tuple[str, int] | None
    answers: list[Record]
    authority: list[Record]
    additional: list[Record]
    size: int
    edns: bool = False

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    @property
    def rcode_name(self) -> str:
        return RCODES.get(self.rcode, f"RCODE{self.rcode}")

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def authoritative(self) -> bool:
        return bool(self.flags & 0x0400)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)


def _quote(raw: bytes) -> str:
    out = ['"']
    for byte in raw:
        char = chr(byte)
        if char in '"\\':
            out.append("\\" + char)
        elif 0x20 <= byte <= 0x7E:
            out.append(char)
        else:
            out.append(f"\\{byte:03d}")
    out.append('"')
    return "".join(out)


def _rdata(data: bytes, rtype: int, start: int, end: int) -> tuple[str, str, str]:
    """(presentation, target, address) of one record's data."""
    raw = data[start:end]
    try:
        if rtype == A and len(raw) == 4:
            text = str(ipaddress.IPv4Address(raw))
            return text, "", text
        if rtype == AAAA and len(raw) == 16:
            text = str(ipaddress.IPv6Address(raw))
            return text, "", text
        if rtype in (NS, CNAME, 12, DNAME):
            name, _ = read_name(data, start)
            return name, name, ""
        if rtype == 15 and len(raw) >= 3:                       # MX
            name, _ = read_name(data, start + 2)
            return f"{struct.unpack('!H', raw[:2])[0]} {name}", "", ""
        if rtype == SOA:
            mname, offset = read_name(data, start)
            rname, offset = read_name(data, offset)
            numbers = struct.unpack("!IIIII", data[offset:offset + 20])
            return f"{mname} {rname} " + " ".join(str(n) for n in numbers), "", ""
        if rtype in (16, 99):                                   # TXT, SPF
            parts, offset = [], 0
            while offset < len(raw):
                size = raw[offset]
                parts.append(_quote(raw[offset + 1:offset + 1 + size]))
                offset += 1 + size
            return " ".join(parts), "", ""
        if rtype == 33 and len(raw) >= 7:                       # SRV
            prio, weight, port = struct.unpack("!HHH", raw[:6])
            name, _ = read_name(data, start + 6)
            return f"{prio} {weight} {port} {name}", "", ""
        if rtype == 257 and len(raw) >= 2:                      # CAA
            flags, size = raw[0], raw[1]
            tag = raw[2:2 + size].decode("ascii", "replace")
            return f"{flags} {tag} {_quote(raw[2 + size:])}", "", ""
        if rtype == 43 and len(raw) >= 4:                       # DS
            keytag, alg, digest_type = struct.unpack("!HBB", raw[:4])
            return f"{keytag} {alg} {digest_type} {raw[4:].hex().upper()}", "", ""
    except (WireError, struct.error, ValueError):
        pass
    return f"\\# {len(raw)} {raw.hex().upper()}".rstrip(), "", ""


def _records(data: bytes, offset: int, count: int) -> tuple[list[Record], int, bool]:
    out: list[Record] = []
    edns = False
    for _ in range(count):
        name, offset = read_name(data, offset)
        if offset + 10 > len(data):
            raise WireError("record header cut short")
        rtype, rclass, ttl, size = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if offset + size > len(data):
            raise WireError("record data runs past the end of the message")
        if rtype == OPT:
            edns = True
        else:
            text, target, address = _rdata(data, rtype, offset, offset + size)
            out.append(Record(name, rtype, rclass, ttl, text, target, address))
        offset += size
    return out, offset, edns


def parse(data: bytes) -> Message:
    """A whole DNS message. Raises WireError when it can't be read."""
    if len(data) < 12:
        raise WireError("shorter than a DNS header")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    question = None
    for index in range(qd):
        qname, offset = read_name(data, offset)
        if offset + 4 > len(data):
            raise WireError("question cut short")
        qtype = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 4
        if index == 0:
            question = (qname, qtype)
    answers, offset, _ = _records(data, offset, an)
    authority, offset, _ = _records(data, offset, ns)
    additional, offset, edns = _records(data, offset, ar)
    return Message(qid, flags, question, answers, authority, additional, len(data), edns)


# ================================================================ formatting
def format_record(record: Record) -> str:
    """One record the way dig prints it: tab stops every 8 columns, the name
    column 24 wide (pre-expanded, so it lines up anywhere)."""
    name = record.name
    tabs = 3 - len(name) // 8 if len(name) < 24 else 1
    klass = CLASSES.get(record.rclass, f"CLASS{record.rclass}")
    line = f"{name}{chr(9) * tabs}{record.ttl}\t{klass}\t{record.type_name}\t{record.data}"
    return line.expandtabs(8)


# ================================================================ transport
def ask_udp(address: str, packet: bytes, timeout: float = UDP_TIMEOUT) -> bytes:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((address, PORT))
        sock.send(packet)
        deadline = time.monotonic() + timeout
        while True:
            data = sock.recv(65535)
            if data[:2] == packet[:2]:
                return data
            # Someone else's answer: keep listening until the deadline.
            left = deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout("timed out")
            sock.settimeout(left)


def _recv_exact(sock, size: int) -> bytes:
    chunks, got = [], 0
    while got < size:
        block = sock.recv(size - got)
        if not block:
            raise ConnectionError("connection closed mid-answer")
        chunks.append(block)
        got += len(block)
    return b"".join(chunks)


def ask_tcp(address: str, packet: bytes, timeout: float = TCP_TIMEOUT) -> bytes:
    with socket.create_connection((address, PORT), timeout=timeout) as sock:
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        size = struct.unpack("!H", _recv_exact(sock, 2))[0]
        return _recv_exact(sock, size)


def ask(address: str, packet: bytes, tcp: bool = False) -> bytes:
    """One query to one server: the raw answer, or OSError."""
    return ask_tcp(address, packet) if tcp else ask_udp(address, packet)


_network_ask = ask


def resolve_ipv4(name: str) -> list[str]:
    """Addresses for a nameserver whose referral came without glue, from the
    system's own resolver (dig +trace does the same)."""
    try:
        found = socket.getaddrinfo(name.rstrip("."), PORT, socket.AF_INET, socket.SOCK_DGRAM)
    except (OSError, UnicodeError):
        return []
    out: list[str] = []
    for *_rest, sockaddr in found:
        if sockaddr[0] not in out:
            out.append(sockaddr[0])
    return out


# ================================================================ the walk
@dataclass
class Server:
    name: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)


@dataclass
class Step:
    """One server's answer on the way down."""

    zone: str                       # the level this server was asked about
    server: str = ""
    address: str = ""
    size: int = 0
    ms: float = 0.0
    shown: list[Record] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    message: Message | None = None


def _servers_from(records: list[Record], additional: list[Record],
                  owner: str) -> list[Server]:
    """The NS records for `owner`, each with its glue from `additional`."""
    servers: dict[str, Server] = {}
    for record in records:
        if record.rtype == NS and same_name(record.name, owner) and record.target:
            servers.setdefault(record.target.lower(), Server(record.target))
    for record in additional:
        server = servers.get(record.name.lower())
        if server is None or not record.address:
            continue
        (server.ipv4 if record.rtype == A else server.ipv6).append(record.address)
    return list(servers.values())


def root_servers() -> list[Server]:
    return [Server(name, [v4], [v6]) for name, v4, v6 in ROOT_HINTS]


class Tracer:
    """Walks one name's delegation, one step per call to step().

    `ask(address, packet, tcp)` sends one query and returns the raw answer
    (or raises OSError); `resolve(name)` finds a glueless nameserver's IPv4
    addresses. Both are swappable, so the walk is tested without a network.
    """

    def __init__(self, domain: str, qtype: str | int = "A",
                 ask: Callable[..., bytes] | None = None,
                 resolve: Callable[[str], list[str]] | None = None,
                 rng: random.Random | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.qname = domain.strip().rstrip(".").lower() + "."
        self.qtype = qtype if isinstance(qtype, int) else TYPE_CODES.get(qtype.upper(), A)
        self._ask = ask or _network_ask
        self._resolve = resolve or resolve_ipv4
        self._rng = rng or random.Random()
        self._clock = clock
        self.zone = "."
        self.servers: list[Server] = root_servers()
        self.steps: list[Step] = []
        self.done = False
        self.ok = False
        self.status = ""            # NOERROR / NXDOMAIN / … of the last answer
        self.error = ""
        self.primed = False

    # ----------------------------------------------------------- one query
    def _query(self, server: Server, name: str, qtype: int, step: Step) -> Message | None:
        addresses = list(server.ipv4)
        if not addresses and not server.ipv6:
            addresses = self._resolve(server.name)
            server.ipv4 = list(addresses)
        addresses += server.ipv6                  # IPv6 only when IPv4 fails
        for address in addresses[:2]:
            qid = self._rng.getrandbits(16)
            edns = True
            tcp = False
            for _attempt in range(3):
                packet = build_query(name, qtype, qid, edns=edns)
                started = self._clock()
                try:
                    data = self._ask(address, packet, tcp)
                except (OSError, ValueError) as exc:
                    reason = "timed out" if isinstance(exc, (socket.timeout, TimeoutError)) \
                        else (getattr(exc, "strerror", None) or str(exc) or type(exc).__name__)
                    step.errors.append(f";; communications error to {address}#{PORT}: "
                                       f"{reason}")
                    break
                elapsed = (self._clock() - started) * 1000
                try:
                    message = parse(data)
                except WireError as exc:
                    step.errors.append(f";; unreadable answer from {address}#{PORT}: {exc}")
                    break
                if message.id != qid or not message.is_response or (
                        message.question and not same_name(message.question[0], name)):
                    step.errors.append(f";; {address}#{PORT} answered a different question")
                    break
                if message.truncated and not tcp:
                    tcp = True                    # the answer didn't fit: ask again over TCP
                    step.notes.append(";; Truncated, retrying in TCP mode.")
                    continue
                if message.rcode == 1 and edns:   # FORMERR: an old server without EDNS
                    edns = False
                    continue
                step.server, step.address = server.name, address
                step.size, step.ms = message.size, elapsed
                step.message = message
                return message
        return None

    def _ask_level(self, name: str, qtype: int, step: Step) -> Message | None:
        servers = list(self.servers)
        self._rng.shuffle(servers)
        # Servers that came with glue first: no extra lookup needed.
        servers.sort(key=lambda s: 0 if s.ipv4 else 1 if s.ipv6 else 2)
        for server in servers[:TRIES_PER_STEP]:
            message = self._query(server, name, qtype, step)
            if message is not None:
                return message
        return None

    # ----------------------------------------------------------- the steps
    def prime(self) -> Step:
        """Step 0: a root server's own list of the root servers (dig asks the
        local resolver for this; a root server is asked here, so nothing
        depends on how this machine resolves names)."""
        step = Step(zone=".")
        self.primed = True
        message = self._ask_level(".", NS, step)
        if message is None:
            self.done = True
            self.error = "No root server answered — is outbound UDP/53 blocked?"
            step.notes.append(";; " + self.error)
        else:
            step.shown = [r for r in message.answers if r.rtype == NS]
            fresh = _servers_from(step.shown, message.additional, ".")
            if not step.shown:
                # A real root server always lists the root servers. Anything
                # else is a middlebox answering port 53 in its place.
                self.done = True
                self.error = (f"A root server's address answered {message.rcode_name} "
                              "without listing the root servers — something on this "
                              "network intercepts DNS on port 53, so the real delegation "
                              "can't be walked from here.")
                step.notes.append(";; " + self.error)
            elif any(s.ipv4 for s in fresh):
                self.servers = fresh
        self.steps.append(step)
        return step

    def step(self) -> Step:
        """Ask the current level's servers about the name; follow a referral
        one level down, or stop at an answer."""
        if not self.primed:
            return self.prime()
        step = Step(zone=self.zone)
        self.steps.append(step)
        if self.done:
            return step
        if len(self.steps) > MAX_STEPS:
            return self._stop(step, f"Gave up after {MAX_STEPS} levels — a delegation loop?")
        message = self._ask_level(self.qname, self.qtype, step)
        if message is None:
            return self._stop(step, f"No server for {self.zone} answered.")
        self.status = message.rcode_name
        if message.rcode != 0:
            step.shown = message.answers + [r for r in message.authority if r.rtype == SOA]
            if message.rcode == 3:
                step.notes.append(f";; NXDOMAIN: {self.qname} does not exist "
                                  f"(says {step.server.rstrip('.')})")
                return self._finish(step, ok=True)
            return self._stop(step, f"{step.server.rstrip('.')} answered "
                                    f"{message.rcode_name}.")
        if message.answers:
            step.shown = list(message.answers)
            alias = next((r for r in message.answers if r.rtype in (CNAME, DNAME)
                          and same_name(r.name, self.qname)), None)
            wanted = [r for r in message.answers if r.rtype == self.qtype]
            if alias is not None and not wanted:
                step.notes.append(f";; {self.qname} is an alias for {alias.target} — "
                                  "trace that name to follow it.")
            return self._finish(step, ok=True)
        referral = [r for r in message.authority if r.rtype == NS]
        if not referral or message.authoritative:
            step.shown = [r for r in message.authority if r.rtype == SOA]
            step.notes.append(f";; NODATA: {self.qname} exists but has no "
                              f"{TYPES.get(self.qtype, self.qtype)} record.")
            return self._finish(step, ok=True)
        owner = referral[0].name
        step.shown = [r for r in referral if same_name(r.name, owner)]
        if not is_within(self.qname, owner) or depth(owner) <= depth(self.zone):
            return self._stop(step, f"{step.server.rstrip('.')} referred upwards or "
                                    f"sideways (to {owner}) — a lame delegation.")
        servers = _servers_from(message.authority, message.additional, owner)
        if not servers:
            return self._stop(step, f"The referral to {owner} named no nameservers.")
        self.zone, self.servers = owner, servers
        return step

    def _finish(self, step: Step, ok: bool) -> Step:
        self.done, self.ok = True, ok
        return step

    def _stop(self, step: Step, error: str) -> Step:
        self.done, self.ok = True, False
        self.error = error
        step.notes.append(";; " + error)
        return step

    def run(self) -> "Tracer":
        """The whole walk at once (the pane steps through it instead)."""
        self.prime()
        while not self.done:
            self.step()
        return self

    # ----------------------------------------------------------- output
    def text(self) -> str:
        qtype = TYPES.get(self.qtype, str(self.qtype))
        lines = [f"; <<>> netzilla trace <<>> {self.qname.rstrip('.')} {qtype}",
                 ";; dig is not installed: netzilla walked the delegation itself, "
                 "root servers first.", ""]
        for step in self.steps:
            lines += step.errors
            lines += [format_record(r) for r in step.shown]
            if step.server:
                lines.append(f";; Received {step.size} bytes from {step.address}#{PORT}"
                             f"({step.server.rstrip('.')}) in {step.ms:.0f} ms")
            lines += step.notes
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"


__all__ = ["Tracer", "Step", "Server", "Record", "Message", "WireError", "build_query",
           "parse", "read_name", "encode_name", "format_record", "ask", "ask_udp", "ask_tcp",
           "resolve_ipv4", "root_servers", "is_within", "ROOT_HINTS", "TYPES"]
