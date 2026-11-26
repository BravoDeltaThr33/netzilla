"""Per-tool usage notes shown when an action button is highlighted.

Every button on every tab has an entry here: what to type and where, a few
real-world reasons to reach for it, and public targets that are safe and
useful to try it against. The pane shows the card while a button is hovered or
focused, keeps it up while that tool is running, and hides it the moment the
tool's own output starts to arrive.

Entries are keyed by pane class name, then by action key, so the panes
themselves stay free of long help strings.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.text import Text

from .render import PANEL_BOX
from .themes import Palette


@dataclass(frozen=True)
class ToolHelp:
    usage: str
    uses: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    note: str = ""


H = ToolHelp  # brevity in the table below

HELP: dict[str, dict[str, ToolHelp]] = {
    # ------------------------------------------------------------ DASH
    "DashboardPane": {
        "refresh": H(
            "Re-checks which local tools are installed, looks up your public IP "
            "and shows API quota used. No input needed.",
            uses=(
                "First thing after install: confirm ping/dig/mtr/whois are present.",
                "Confirm which public IP you egress from (VPN on vs off).",
            ),
        ),
        "quota": H(
            "Shows how many calls netzilla has made to each rate-limited API in "
            "its current window. Counted locally, nothing is sent.",
            uses=(
                "Before a batch of lookups, check you won't hit AbuseIPDB or "
                "VirusTotal daily limits halfway through.",
            ),
        ),
    },
    # ------------------------------------------------------------ IP LOOKUP
    "IPLookupPane": {
        "full": H(
            "Type an IPv4/IPv6 address (or leave blank for your own public IP). "
            "Runs geolocation, AbuseIPDB, VirusTotal, GreyNoise and VPN/proxy "
            "detection in parallel.",
            uses=(
                "An unknown IP keeps showing up in firewall denies — who is it?",
                "Triage a source IP from a SIEM alert in one screen.",
            ),
            targets=(
                "8.8.8.8 — Google DNS; GreyNoise tags it a known business service",
                "1.1.1.1 — Cloudflare DNS",
                "45.33.32.156 — scanme.nmap.org, Nmap's public test host",
                "(blank) — your own public IP",
            ),
        ),
        "geo": H(
            "Type an IP (or leave blank). Geolocation, ISP, ASN and hosting/"
            "proxy flags from ip-api.com only. Keyless and fast.",
            uses=(
                "Check which country/ISP a login came from.",
                "Confirm a VPN is actually exiting where you think it is.",
            ),
            targets=("8.8.8.8", "9.9.9.9 — Quad9", "(blank) — your public IP"),
        ),
        "threat": H(
            "Type an IP. Skips geolocation and shows only the reputation "
            "sources: AbuseIPDB, VirusTotal, GreyNoise, VPN/proxy detection.",
            uses=(
                "Decide whether an IP hammering SSH is a known bad actor or "
                "an internet-wide scanner you can ignore.",
            ),
            targets=("8.8.8.8", "45.33.32.156"),
            note="AbuseIPDB, VirusTotal and GreyNoise use keys from SETTINGS.",
        ),
        "block": H(
            "Type an IP or a network up to a /24 (e.g. 203.0.113.0/24). A bare "
            "IP is widened to its /24. AbuseIPDB reports on every reported "
            "address in that block.",
            uses=(
                "One IP in a hosting range is attacking you. Are its neighbours "
                "bad too, so you can block the whole /24?",
            ),
            targets=("8.8.8.0/24", "45.33.32.0/24"),
            note="The free AbuseIPDB plan caps block checks at /24.",
        ),
    },
    # ------------------------------------------------------------ SUBNET
    "SubnetPane": {
        "describe": H(
            "Type a network in CIDR form in the Network field. Shows network "
            "and broadcast addresses, mask, wildcard, usable range and host "
            "count. IPv4 and IPv6. Fully offline.",
            uses=(
                "Get the wildcard mask for an ACL or OSPF network statement.",
                "Check whether an address falls inside a given subnet.",
            ),
            targets=("192.168.10.0/24", "10.20.0.0/22", "172.16.5.77/27", "2001:db8::/48"),
        ),
        "split": H(
            "Network field = the block to carve up. 'Split into /' = the new, "
            "longer prefix. Lists every resulting subnet.",
            uses=(
                "Cut a /24 into /27s for VLANs.",
                "CCNA practice: verify your hand-worked subnetting.",
            ),
            targets=("192.168.10.0/24 split into /27", "10.0.0.0/16 split into /20"),
        ),
        "fit": H(
            "Network field = the parent block. 'Hosts needed' = how many usable "
            "addresses you need. Returns the smallest prefix that fits.",
            uses=(
                "Size a subnet for 50 phones plus growth.",
                "Pick /30 vs /31 for a point-to-point link.",
            ),
            targets=("192.168.10.0/24 with 50 hosts", "10.0.0.0/16 with 500 hosts"),
        ),
        "range": H(
            "Type a range in the Network field as 'start - end'. Returns the "
            "fewest CIDR blocks that exactly cover it.",
            uses=(
                "Turn a DHCP scope or a vendor's 'allow this range' list into "
                "firewall-ready CIDRs.",
            ),
            targets=("10.0.0.5 - 10.0.0.60", "192.168.1.0 - 192.168.3.255"),
        ),
    },
    # ------------------------------------------------------------ DNS/WHOIS
    "DNSWhoisPane": {
        "records": H(
            "Type a domain. Queries A, AAAA, MX, NS, TXT, SOA, CNAME, CAA and SRV "
            "with local dig. Put a resolver in 'DNS server' to ask that server "
            "instead of your system resolver. Internal servers work too.",
            uses=(
                "Check mail routing (MX) and SPF/DMARC (TXT) for a domain.",
                "Compare what your internal DNS answers against 1.1.1.1.",
            ),
            targets=("google.com", "cloudflare.com", "example.com"),
            note="Uses dig (sudo apt install dnsutils). Without it the same types "
                 "are asked of Cloudflare over DNS-over-HTTPS — but then the DNS "
                 "server box can't be honoured and internal zones aren't visible.",
        ),
        "rdap": H(
            "Type a domain or an IP. RDAP is the structured, JSON replacement "
            "for WHOIS: registrar, key dates, nameservers, DNSSEC, and the "
            "abuse contact.",
            uses=(
                "Find where to send an abuse report for an attacking IP.",
                "See when a suspicious domain was registered.",
            ),
            targets=("example.com", "8.8.8.8", "github.com"),
        ),
        "whois": H(
            "Type a domain or an IP. Runs the local whois client and trims the "
            "legal boilerplate.",
            uses=(
                "Registrar and expiry date for a domain you manage.",
                "Owner of an IP block (ARIN/RIPE/APNIC record).",
            ),
            targets=("example.com", "8.8.8.8"),
            note="Needs whois:  sudo apt install whois",
        ),
        "resolver": H(
            "Type a domain. Asks Cloudflare, Google and Quad9 over DNS-over-HTTPS "
            "and compares their answers.",
            uses=(
                "Is a DNS change still propagating, or is one resolver stale?",
                "Is DNSSEC failing? Validating resolvers return SERVFAIL.",
            ),
            targets=(
                "dnssec-failed.org — deliberately broken DNSSEC; expect SERVFAIL",
                "netflix.com — CDN; answers often differ per resolver",
                "example.com — should agree everywhere",
            ),
        ),
        "trace": H(
            "Type a domain. Walks the delegation from the root servers down "
            "(dig +trace) so you can see which nameserver answers at each level.",
            uses=(
                "Diagnose a broken delegation after moving DNS providers.",
                "Find lame delegations or wrong NS records at the registrar.",
            ),
            targets=("example.com", "bbc.co.uk"),
            note="Needs dig. Outbound UDP/53 to the root servers must be allowed.",
        ),
        "reverse": H(
            "Type an IP. Looks up its PTR record, using 'DNS server' if set.",
            uses=(
                "Put a name to an IP in a log.",
                "Check a mail server's PTR matches its HELO name.",
            ),
            targets=("8.8.8.8 → dns.google", "1.1.1.1 → one.one.one.one"),
            note="Uses dig; without it, Cloudflare answers over DNS-over-HTTPS.",
        ),
        "squat": H(
            "Type the domain to protect. Optionally set a different TLD to hunt "
            "in (e.g. 'net'). Generates lookalikes locally (typos, swapped "
            "letters, homoglyphs) and checks which ones resolve.",
            uses=(
                "Find phishing lookalikes of your company's domain.",
                "Build a blocklist of registered lookalikes for your mail filter.",
            ),
            targets=("paypal.com — many registered lookalikes", "your own domain"),
            note="Sends a few hundred DNS queries. Takes a few seconds.",
        ),
        "vt": H(
            "Type a domain. Shows the VirusTotal engine verdicts and categories "
            "for it.",
            uses=("A user clicked a link: is the domain known-malicious?",),
            targets=(
                "testsafebrowsing.appspot.com — Google's Safe Browsing test site",
                "google.com — clean baseline",
            ),
            note="Uses the VirusTotal key from SETTINGS (free tier: 4 lookups/min).",
        ),
    },
    # ------------------------------------------------------------ SSL/TLS
    "SSLTLSPane": {
        "quick": H(
            "Type a hostname (and a port if it's not 443). Connects locally and "
            "reads the certificate: issuer, SANs, expiry, chain trust, hostname "
            "match. Under a second. Works on internal hosts.",
            uses=(
                "How many days until this cert expires?",
                "The browser says 'not secure'. Is it the chain, the name, or "
                "expiry?",
            ),
            targets=(
                "expired.badssl.com — expired certificate",
                "wrong.host.badssl.com — name mismatch",
                "self-signed.badssl.com — self-signed",
                "untrusted-root.badssl.com — unknown CA",
                "badssl.com — a good baseline",
            ),
        ),
        "labs": H(
            "Type a public hostname. Runs Qualys SSL Labs' full graded "
            "assessment (protocols, ciphers, known vulns). Results are cached "
            "24 h.",
            uses=(
                "Prove to an auditor a site scores A or better.",
                "Check a load balancer after a cipher-suite change.",
            ),
            targets=("ssllabs.com", "github.com", "badssl.com"),
            note="First scan of a host takes 1–3 minutes. Public hosts only — "
                 "SSL Labs refuses a few reserved names such as example.com.",
        ),
        "openssl": H(
            "Type a hostname and port. Shows the raw openssl s_client handshake: "
            "negotiated protocol, cipher, and the full chain as served.",
            uses=(
                "The server is missing an intermediate certificate. See exactly "
                "what it sends.",
                "Check TLS on a non-HTTPS port (SMTPS 465, LDAPS 636, 8443).",
            ),
            targets=(
                "incomplete-chain.badssl.com — missing intermediate",
                "tls-v1-2.badssl.com, port 1012 — TLS 1.2 only",
                "smtp.gmail.com, port 465",
            ),
            note="Needs openssl:  sudo apt install openssl",
        ),
        "certs": H(
            "Type a domain. Searches Certificate Transparency logs (crt.sh) for "
            "every certificate ever issued for it and its subdomains.",
            uses=(
                "Find forgotten subdomains and shadow IT.",
                "Spot certificates issued for your domain that you didn't request.",
            ),
            targets=("example.com", "badssl.com — dozens of subdomains"),
            note="crt.sh is slow and sometimes times out. Just retry.",
        ),
    },
    # ------------------------------------------------------------ BGP/ASN
    "BGPPane": {
        "auto": H(
            "Type an IP or an AS number (AS15169 or 15169). For an IP: covering "
            "prefix, origin AS and RPKI validity. For an AS: holder and routing "
            "overview.",
            uses=(
                "Who actually announces this IP on the internet?",
                "Is the route RPKI-valid, or could it be a hijack/leak?",
            ),
            targets=("8.8.8.8", "1.1.1.1", "AS15169 — Google", "AS13335 — Cloudflare"),
        ),
        "prefixes": H(
            "Type an AS number (or an IP; its origin AS is used). Lists every "
            "prefix that AS is announcing right now.",
            uses=(
                "Build an allowlist for a SaaS provider's whole address space.",
                "Check your own AS announces exactly what it should.",
            ),
            targets=("AS13335", "AS15169", "AS2906 — Netflix"),
        ),
        "neighbours": H(
            "Type an AS number or IP. Lists observed BGP neighbours, marked "
            "upstream (left), downstream (right) or unknown.",
            uses=(
                "Who are an ISP's transit providers?",
                "Map a provider's peering before choosing a colo.",
            ),
            targets=("AS13335", "AS7922 — Comcast"),
        ),
        "whois": H(
            "Type an IP, prefix or AS. Fetches the RIPE-database WHOIS objects "
            "(route, aut-num, inetnum) via RIPEstat.",
            uses=("Find the maintainer and route objects behind a prefix.",),
            targets=("193.0.6.139 — ripe.net", "AS3333 — RIPE NCC"),
        ),
        "snapshot": H(
            "Type an IP. Records its current origin AS and prefix locally, and "
            "compares with the last snapshot. Warns if the origin changed.",
            uses=(
                "Snapshot your own public IPs weekly and catch a hijack or "
                "an upstream change.",
            ),
            targets=("your own public IP", "8.8.8.8"),
            note="Take one snapshot now and another later. The second one shows the diff.",
        ),
        "history": H(
            "Type the same IP you snapshotted. Lists every stored origin "
            "snapshot, newest first.",
            uses=("See when an origin change happened.",),
            note="Empty until you've run ORIGIN SNAPSHOT on that IP.",
        ),
    },
    # ------------------------------------------------------------ THREAT
    "ThreatIntelPane": {
        "cve": H(
            "Type a CVE ID or keywords (vendor product). Searches NVD, scores "
            "each result's chance of exploitation in the next 30 days (FIRST "
            "EPSS) and flags any entry on CISA's Known Exploited "
            "Vulnerabilities list — all free.",
            uses=(
                "A vendor advisory dropped. Is it being exploited in the wild?",
                "List recent CVEs for the gear you run.",
            ),
            targets=(
                "CVE-2021-44228 — Log4Shell (in KEV)",
                "CVE-2024-3400 — PAN-OS GlobalProtect (in KEV)",
                "cisco ios xe",
                "fortinet fortios",
            ),
            note="Keyless NVD is rate-limited. Add an NVD key in SETTINGS for faster results.",
        ),
        "ioc": H(
            "Type an IP, domain or file hash. Checks abuse.ch ThreatFox, plus "
            "Feodo Tracker (botnet C2) for IPs and MalwareBazaar for hashes.",
            uses=(
                "An EDR alert gave you a hash or a C2 IP. Is it a known family?",
            ),
            targets=(
                "Pick any fresh IOC from threatfox.abuse.ch/browse",
                "Any C2 IP from feodotracker.abuse.ch",
            ),
            note="Uses the abuse.ch Auth-Key from SETTINGS. IOCs expire, so use current ones.",
        ),
        "urlhaus": H(
            "Type a full URL or a bare host. Checks abuse.ch URLhaus for "
            "malware-distribution listings. Falls back to the offline snapshot "
            "if the API is unreachable.",
            uses=(
                "Is the link in this phishing email serving malware?",
                "Has a compromised site of ours been listed?",
            ),
            targets=(
                "Copy an 'online' URL from urlhaus.abuse.ch/browse",
                "example.com — clean baseline",
            ),
            note="Listed URLs are live malware. Paste them here but never open them in a browser.",
        ),
        "vturl": H(
            "Type a full URL (http:// or https://). Shows VirusTotal's existing "
            "verdicts from ~90 engines. Nothing is submitted.",
            uses=("Second opinion on a link before you click it.",),
            targets=(
                "http://testsafebrowsing.appspot.com/s/malware.html — test page flagged by design",
                "https://www.google.com — clean baseline",
            ),
        ),
        "hash": H(
            "Paste an MD5, SHA-1 or SHA-256 (32/40/64 hex characters). Asks "
            "VirusTotal whether that file is known. The file itself is never "
            "uploaded. To get a hash:  sha256sum <file>",
            uses=(
                "Check a downloaded installer against VirusTotal without uploading it.",
                "Look up a hash from an EDR or email-gateway alert.",
            ),
            targets=(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f "
                "— EICAR test file, SHA-256 (flagged by every engine, harmless)",
                "44d88612fea8a8f36de82e1278abb02f — EICAR, MD5",
            ),
            note="Paste in Tilix with Ctrl+Shift+V, not Ctrl+V.",
        ),
        "timeline": H(
            "Type a domain. Puts the RDAP registration date, the first "
            "certificate seen in CT logs and any threat listings on one timeline.",
            uses=(
                "A domain registered 3 days ago with a brand-new cert is a classic "
                "phishing pattern.",
            ),
            targets=("google.com — decades old", "a lookalike found by TYPOSQUAT SEARCH"),
        ),
        "vtsubmit": H(
            "Type a full URL. Submits it to VirusTotal for a fresh scan and waits "
            "for the result.",
            uses=(
                "A URL VirusTotal has never seen, or last saw months ago.",
            ),
            targets=("https://www.example.com",),
            note="The URL becomes visible to VirusTotal's community. Never submit "
                 "internal URLs or links with tokens in them.",
        ),
        "snapshot": H(
            "No input needed. Shows the age and size of the bundled offline "
            "URLhaus database, and how to refresh it.",
            uses=("Check how stale your offline fallback is before relying on it.",),
        ),
    },
    # ------------------------------------------------------------ DISCOVERY
    "DiscoveryPane": {
        "idb": H(
            "Type an IP in 'IP address'. Shodan InternetDB (keyless) returns the "
            "open ports, hostnames, software (CPE) and likely CVEs Shodan last "
            "saw on it.",
            uses=(
                "What does the internet see on our public IPs?",
                "Quick exposure check on a new vendor's endpoint.",
            ),
            targets=("45.33.32.156 — scanme.nmap.org", "8.8.8.8", "1.1.1.1"),
        ),
        "profile": H(
            "Type an IP in 'IP address'. Asks four free sources at once — "
            "InternetDB, IP-API, RDAP and RIPEstat — and puts together who runs "
            "the address (reverse DNS, organisation, ISP, ASN, announced "
            "prefix, registry network, abuse contact, location, hosting/proxy "
            "flags) and what it exposes. The free equivalent of a paid Shodan "
            "host record.",
            uses=(
                "An address shows up in your logs: whose is it, and who do you "
                "email about it?",
                "Due diligence on a vendor's endpoint before you allow-list it.",
            ),
            targets=("45.33.32.156 — scanme.nmap.org", "8.8.8.8", "1.1.1.1"),
        ),
        "cves": H(
            "Type an IP in 'IP address'. Takes every CVE InternetDB lists for "
            "it and ranks them: known exploited first (CISA KEV), then by the "
            "chance of exploitation in the next 30 days (FIRST EPSS), with "
            "CVSS severity from NVD for the top few. All three are free.",
            uses=(
                "Twenty CVEs on one box — which do you patch tonight?",
                "Explain to a manager why a 'medium' CVE jumps the queue.",
            ),
            targets=("an address of your own that INTERNETDB SCAN shows CVEs for",),
            note="NVD allows 5 lookups per 30 s without a key, so severity is "
                 "fetched for the five most urgent; an NVD key raises that.",
        ),
    },
    # ------------------------------------------------------------ LAN
    "LANPane": {
        "sweep": H(
            "Leave the box blank to sweep this machine's own subnet, or type "
            "one in CIDR form. Pings every host, adds MACs from the ARP cache, "
            "then identifies each device: VENDOR from the offline IEEE "
            "registry, HOSTNAME from reverse DNS (your router knows each DHCP "
            "client's name), mDNS, NetBIOS or UPnP, and DEVICE — netzilla's "
            "best guess at what it is. DETAILS shows the friendly name, model "
            "and services it advertises. Hosts that block ICMP but are in ARP "
            "are listed separately.",
            uses=(
                "What's actually on my Wi-Fi / this VLAN?",
                "Which of these three Amazon MACs is the Fire TV?",
                "Find a free IP before assigning a static.",
            ),
            targets=("blank — this machine's own LAN",
                     "192.168.1.0/24 (or whatever your LAN is)"),
            note="'private MAC' = a randomised Wi-Fi address (phones, tablets, "
                 "laptops), which has no vendor — its hostname usually still "
                 "names it. Only sweep networks you own or are authorised to "
                 "scan. Max /22.",
        ),
        "identify": H(
            "Type ONE IP (from a SWEEP) and press IDENTIFY. netzilla asks the "
            "device every way it knows — reverse DNS, mDNS names, services and "
            "model, NetBIOS, UPnP description, ping TTL — checks "
            "a couple of dozen well-known ports that give devices away "
            "(62078 iPhone, 8009 Chromecast, 8060 Roku, 9100 printer, 3389 "
            "Windows RDP …), reads an SSH banner or web page title if there is "
            "one, and shows its verdict with the evidence behind it.",
            uses=(
                "What is 10.0.0.185, really?",
                "Is that unknown device a phone, a TV or something that "
                "should not be here?",
            ),
            targets=("your router (the gateway, usually .1)",
                     "any address a SWEEP listed"),
            note="The port check is a TCP connect to each port — normal for "
                 "your own devices, but only point it at networks you own or "
                 "manage.",
        ),
        "dhcp": H(
            "No target needed. Broadcasts a DHCPDISCOVER and lists every server "
            "that offers. 'Seconds' = how long to wait for offers.",
            uses=(
                "Clients are getting the wrong gateway. Is there a rogue DHCP "
                "server (a home router someone plugged in)?",
            ),
            targets=("your own LAN — expect exactly one server",),
            note="Needs root:  sudo netzilla",
        ),
        "dupip": H(
            "Type one IP. Watches ARP for that address for 'Seconds' seconds and "
            "flags it if more than one MAC answers.",
            uses=(
                "A user's connection drops every few minutes. Is someone else "
                "using their static IP?",
            ),
            targets=("your default gateway (ip route | grep default)",),
        ),
        "snmp": H(
            "Type a device IP, set the SNMP community, and set the poll interval "
            "in 'Seconds'. Reads sysName/sysDescr/uptime, then samples interface "
            "counters twice for live Mbps and error deltas (SNMP v2c).",
            uses=(
                "Is this uplink saturated right now?",
                "Which port is taking errors? (bad cable, duplex mismatch)",
            ),
            targets=(
                "127.0.0.1 with community 'public' after  sudo apt install snmpd",
                "any switch/router you manage with SNMP enabled",
            ),
            note="Debian/Mint's default snmpd only exposes system info, so "
                 "localhost shows no interface table unless you widen its view. "
                 "Needs:  sudo apt install snmp",
        ),
        "syslog": H(
            "Listens on UDP/514 unless you type a port number (e.g. 1514) in the "
            "target field. 'Seconds' = how long to collect (5–300). Point devices "
            "at this machine's IP and messages appear in a table. Without root, "
            "514 falls back to 1514 automatically.",
            uses=(
                "See what a switch logs while you bounce a port. No syslog "
                "server needed.",
                "Confirm a firewall is really sending its logs.",
            ),
            targets=(
                "Self-test: set Seconds to 30, click SYSLOG CATCH, then in another terminal:\n"
                "      logger -n 127.0.0.1 -P 1514 -d 'hello netzilla'",
                "Cisco IOS:  logging host <this-ip> transport udp port 1514",
            ),
            note="UDP/514 needs root (sudo netzilla). Allow the port in ufw if "
                 "remote devices can't reach you:  sudo ufw allow 1514/udp",
        ),
    },
    # ------------------------------------------------------------ INT
    "InterfacesPane": {
        "rates": H(
            "Pick an interface, set Seconds (2-300), press LIVE RATES. The "
            "panels then refresh every second (or every REFRESH EVERY seconds) "
            "for that long — Mbit/s in and "
            "out, packets/s, errors and drops for every interface, with the "
            "running peak beside the headline. When the window ends you get "
            "the average and peak across the whole run. This is netzilla's "
            "built-in replacement for nload: no install, no root.",
            uses=(
                "Which interface is actually carrying the traffic right now?",
                "Is this link saturated, or is the slowness somewhere else?",
                "Catch errors or drops climbing on a flaky NIC or cable.",
                "Watch a link while you reproduce a problem — set Seconds to "
                "120 and it keeps updating the whole time.",
            ),
            targets=(
                "your default-route interface (marked in REFRESH INTERFACES)",
                "run a speed test or a big download in another window first, "
                "then sample — otherwise an idle link reads 0.00",
                "lo — loopback; try it while copying between local services",
            ),
            note="Press any other button to stop a run early. nload itself is "
                 "a full-screen program and cannot be shown inside netzilla; "
                 "for its scrolling graph run 'nload <iface>' in its own "
                 "terminal.",
        ),
        "iftop": H(
            "Pick an interface, set Seconds, press IFTOP SNAPSHOT. Runs "
            "'iftop -t -s <seconds>' — iftop's own text mode — and shows which "
            "host pairs moved the most traffic in that window, with 2s/10s/40s "
            "averages and totals.",
            uses=(
                "The link is full. Which host or conversation is filling it?",
                "Find the machine running a backup or a torrent in the middle "
                "of the working day.",
                "Prove to a vendor that their appliance is the top talker.",
            ),
            targets=(
                "your default-route interface, while a download runs",
                "a server's uplink during the slow period users complain about",
            ),
            note="Needs permission to open the interface. netzilla checks "
                 "three ways: running as root, iftop carrying cap_net_raw, or "
                 "passwordless sudo — and uses whichever works. The one-time "
                 "fix that makes it work for good, with no sudo:\n"
                 "    sudo setcap cap_net_raw+ep $(which iftop)\n"
                 "Install: sudo apt install -y iftop",
        ),
        "vnstat": H(
            "Pick an interface and a report (summary / daily / monthly / "
            "hourly / top days), then press VNSTAT REPORT. This is history, "
            "not a live view: vnstat's background service logs totals and "
            "netzilla reads its database. No root needed.",
            uses=(
                "How much data did this link move last month?",
                "Is usage trending up toward an ISP data cap?",
                "Which day last month was the heaviest?",
            ),
            targets=(
                "summary — totals and when collection started",
                "daily / monthly — the reports you actually want for a cap",
                "hourly — find the nightly backup window",
            ),
            note="Install and start collecting:  sudo apt install -y vnstat  "
                 "then  sudo systemctl enable --now vnstat. It has no history "
                 "until the service has been running for a while.",
        ),
        "bmon": H(
            "Pick an interface, set Seconds, press BMON SNAPSHOT. Runs bmon in "
            "its scriptable output mode for that window. bmon prints bare "
            "cumulative counters with no header, so netzilla matches them "
            "against the kernel's own /proc/net/dev counters to work out which "
            "column is which, then reports them in real units: totals since "
            "boot, bytes moved during the capture, and the Mbit/s that implies. "
            "No root needed.",
            uses=(
                "A second opinion on per-interface counters alongside LIVE RATES.",
                "Capture a window of interface statistics to paste into a ticket.",
            ),
            targets=("any interface listed in the dropdown",),
            note="When the columns cannot be matched to the kernel counters, "
                 "netzilla says so rather than guessing. bmon's full-screen "
                 "graph mode cannot run inside netzilla — for that run "
                 "'bmon -p <iface>' in its own terminal. "
                 "Install: sudo apt install -y bmon",
        ),
        "refresh": H(
            "No input needed. Re-reads the interface list with 'ip -o link "
            "show' and refills the dropdown, showing each interface's kind, "
            "state, MTU, MAC and addresses, with the default-route one marked.",
            uses=(
                "You just brought up a VPN, bridge or USB adapter.",
                "Work out which interface name is the one you actually use.",
            ),
            note="Uses iproute2, not ifconfig — net-tools is no longer "
                 "installed by default on Ubuntu or Mint.",
        ),
        "tools": H(
            "No input needed. Shows which of iftop, vnstat, bmon and nload are "
            "installed, what each adds, whether this session is running as "
            "root, and the apt command for anything missing.",
            uses=(
                "Run this first on a new machine to see what this tab can do.",
            ),
            note="Only LIVE RATES and REFRESH INTERFACES work with nothing "
                 "installed — and only IFTOP SNAPSHOT needs root.",
        ),
    },
    # ------------------------------------------------------------ CAPTURE
    "CapturePane": {
        "live": H(
            "Pick an interface, optionally add a filter, and press LIVE "
            "CAPTURE. tshark then runs with no packet count and no time limit: "
            "packets appear as they arrive, newest first, with a running "
            "count and rate. Press any other button on this tab to stop it.",
            uses=(
                "Watch traffic while you reproduce a problem, for as long as "
                "it takes.",
                "Sit on a filter like 'dhcp' and wait for the event to happen.",
                "See whether anything at all is reaching this interface.",
            ),
            targets=(
                "no filter — everything on the wire",
                "icmp — then ping from another terminal and watch it appear",
                "dns — then browse, and see each lookup",
                "ip.addr == <the device you are chasing>",
            ),
            note="The PACKETS box is ignored here — that is what CAPTURE is "
                 "for. Packets are shown newest first with the system time "
                 "each one arrived, and netzilla stops the capture by itself "
                 "after 15 minutes so one left running behind another tab "
                 "cannot hold the interface open. Nothing is lost when it "
                 "stops: see STOP LIVE and FILTER HELD.",
        ),
        "stop": H(
            "Ends a running LIVE CAPTURE and keeps every packet it collected "
            "in memory. Nothing is thrown away and nothing is re-captured — "
            "the traffic stays there to be worked through with FILTER HELD "
            "until the next capture replaces it.",
            uses=(
                "You saw the thing you were waiting for go past and want to "
                "stop before it scrolls away.",
                "You have enough traffic and want to start narrowing it down.",
            ),
            targets=(
                "press LIVE CAPTURE, wait for traffic, press STOP LIVE",
            ),
            note="Pressing any other button also stops a live capture, and the "
                 "packets are kept either way — STOP LIVE is simply the one "
                 "that says so and shows you what you have. To keep a capture "
                 "past this netzilla run, use SAVE PCAP instead.",
        ),
        "held": H(
            "Filters the packets a finished capture left in memory. Type a "
            "filter in the FILTER box and press FILTER HELD: netzilla applies "
            "it to what it already has, so it is instant and the traffic does "
            "not have to happen again. Filter as many times as you like.",
            uses=(
                "A live capture caught the problem — now find it in the "
                "thousands of packets around it.",
                "Ask the same capture several different questions without "
                "waiting for the traffic to repeat.",
                "Narrow a capture down before saving or reporting it.",
            ),
            targets=(
                "dns — everything that was a DNS packet",
                "ip.addr == 192.168.1.50 — one machine, both directions",
                "tcp.port == 443 and not ip.addr == 10.0.0.1",
                "frame.len > 1000 — the big ones",
                "(blank) — everything held",
            ),
            note="This filter is applied by netzilla to the columns it parsed, "
                 "not by tshark, so it is a subset of the display-filter "
                 "language: addresses, ports, lengths, protocols, text, and "
                 "and/or/not. Filters that need the decoded packet "
                 "(tcp.analysis.flags) are reported rather than silently "
                 "ignored — put those in the FILTER box and capture again.",
        ),
        "capture": H(
            "Pick an interface, set Packets, optionally type a tshark display "
            "filter, then press CAPTURE. Runs until it has that many packets "
            "or 30 seconds pass, then shows a summary, the protocol mix, "
            "every packet in a table, and the devices on your own LAN that "
            "appear in it — identified by vendor, hostname and type.",
            uses=(
                "See exactly what a device is sending the moment it misbehaves.",
                "Prove whether traffic is arriving at all before blaming the app.",
                "Watch a DHCP or TLS handshake step by step.",
            ),
            targets=(
                "dns — then open any website and watch the lookups",
                "ip.addr == <the machine you are troubleshooting>",
                "icmp — then ping something from another terminal",
                "(blank) — everything on the wire",
            ),
            note="Needs capture permission — press TOOL CHECK once to see "
                 "whether you have it. Press FILTER HELP for filter syntax.",
        ),
        "tcpdump": H(
            "Same idea with tcpdump instead: raw, lightweight output exactly "
            "as tcpdump prints it. The FILTER box here is a BPF capture filter "
            "('port 80'), not a tshark display filter ('tcp.port == 80'). If "
            "the PCAP FILE box holds a real file, it reads that instead.",
            uses=(
                "Paste raw tcpdump output into a ticket or a vendor case.",
                "Work the way you already do on remote boxes with no Wireshark.",
            ),
            targets=(
                "port 80",
                "host 8.8.8.8",
                "icmp",
                "tcp port 443 and host 1.1.1.1",
            ),
            note="BPF syntax only. FILTER HELP shows both languages side by side.",
        ),
        "protocols": H(
            "Captures for up to 30 seconds (or your packet count) and prints "
            "tshark's protocol hierarchy: what share of traffic each protocol "
            "accounted for, nested from Ethernet upwards. Reads the PCAP FILE "
            "instead when one is set.",
            uses=(
                "Work out what is actually on a segment you have never seen.",
                "Spot unexpected protocols — plain HTTP, SMB, mDNS floods.",
            ),
            targets=("a busy interface with no filter", "a saved .pcapng file"),
        ),
        "talkers": H(
            "Runs tshark's IP conversation statistics: which address pairs "
            "exchanged the most, by packets and bytes. Reads the PCAP FILE "
            "instead when one is set.",
            uses=(
                "Find the host saturating a link.",
                "Spot a machine talking to somewhere it should not.",
            ),
            targets=("your uplink interface", "a saved capture from a busy period"),
        ),
        "save": H(
            "Captures to a .pcapng file you can open in the full Wireshark "
            "later. Leave PCAP FILE blank and netzilla names it for you in your "
            "home directory, then fills the box in with the path.",
            uses=(
                "Grab evidence now on a headless box, analyse it properly later.",
                "Attach a capture to a vendor support case.",
            ),
            targets=("~/netzilla-capture.pcapng", "(blank) — auto-named by time"),
            note="Treat capture files as sensitive: they contain whatever was "
                 "on the wire, including cleartext credentials.",
        ),
        "read": H(
            "Put a .pcap or .pcapng path in PCAP FILE and press READ PCAP. "
            "Shows it the same way a live capture is shown, and a display "
            "filter in the FILTER box narrows it down.",
            uses=(
                "Re-examine a capture with a different filter, without "
                "re-capturing.",
                "Read a capture someone else sent you.",
            ),
            targets=(
                "a file you made with SAVE PCAP",
                "anything from tcpdump -w on another machine",
            ),
        ),
        "filters": H(
            "No input needed. Prints the filters worth knowing, with the "
            "tshark display-filter and the tcpdump BPF form of each side by "
            "side, plus ready-made filters you can paste into the FILTER box.",
            uses=(
                "You know what you want to see but not how to say it.",
                "You keep mixing up 'port 80' and 'tcp.port == 80' — they "
                "belong to different tools.",
            ),
            targets=("press it and copy a line into the FILTER box",),
        ),
        "tools": H(
            "No input needed. Shows whether tshark, tcpdump and dumpcap are "
            "installed, and whether this session may actually capture — root, "
            "membership of the wireshark group with cap_net_raw on dumpcap, or "
            "passwordless sudo. Also re-reads the interface list.",
            uses=(
                "Run this first: it tells you whether the rest of the tab will "
                "work and what to do if not.",
            ),
            note="The recommended setup captures with no sudo at all: install "
                 "tshark answering YES to the non-superuser question, then "
                 "'sudo usermod -aG wireshark $USER' and log back in. If it "
                 "says blocked, press FIX PERMISSIONS.",
        ),
        "auth": H(
            "Asks for your sudo password once, in a box inside netzilla, and "
            "every capture for the rest of this run goes through without a "
            "prompt — including after switching tabs. Press it again to lock "
            "the session immediately.\n\n"
            "You do not normally have to press this: when the only way left "
            "to capture is a desktop password dialog on every single capture, "
            "netzilla offers the one-time unlock by itself.",
            uses=(
                "You would rather not click through a pkexec dialog for every "
                "single capture.",
                "You are working over SSH, where a desktop password dialog "
                "cannot appear at all.",
            ),
            note="The password opens a sudo session and is then dropped — "
                 "netzilla does not hold it. It refreshes that session every "
                 "minute so it cannot expire while running, and the session "
                 "ends when netzilla exits (sudo forgets it within 15 minutes, "
                 "or immediately with 'sudo -k'). For a permanent fix that "
                 "needs no password at all, use FIX PERMISSIONS.",
        ),
        "fix": H(
            "No input needed. Runs the one-time capture setup for you: creates "
            "the wireshark group if needed, adds you to it, and gives dumpcap "
            "the cap_net_raw capability. Your desktop asks for your password "
            "(netzilla cannot prompt for one itself — it is drawing on the "
            "terminal), and the exact commands are shown before they run.",
            uses=(
                "TOOL CHECK says capture is blocked and you would rather not "
                "type the commands into a terminal yourself.",
            ),
            note="Capturing works immediately afterwards. The group part only "
                 "takes effect at your next login — after that there is no "
                 "password prompt at all. Needs pkexec and a desktop session; "
                 "without those it prints the commands to run by hand.",
        ),
    },
    # ------------------------------------------------------------ MAC
    "MACPane": {
        "lookup": H(
            "Type a MAC in any format (00:1A:2B:3C:4D:5E, 001a.2b3c.4d5e, "
            "001A2B3C4D5E) or just the first 3 bytes. Checks the offline IEEE "
            "registry first (all three block sizes), then macvendors.com. A "
            "full MAC that is on your LAN right now is also matched to its IP "
            "and identified — hostname and device type.",
            uses=(
                "Identify an unknown device in a switch's MAC table.",
                "Spot VMs and randomised (private) phone MACs.",
            ),
            targets=(
                "00:00:0C:12:34:56 — Cisco",
                "00:50:56:AA:BB:CC — VMware",
                "B8:27:EB:00:00:01 — Raspberry Pi",
                "02:00:00:00:00:01 — locally administered (no vendor)",
            ),
        ),
        "offline": H(
            "Same as LOOK UP, but uses only the bundled IEEE table. Nothing "
            "leaves the machine.",
            uses=("Lookups on an air-gapped or sensitive network.",),
            targets=("0000.0c12.3456 — Cisco-style notation",),
        ),
        "update": H(
            "No input needed. Downloads fresh copies of the IEEE MA-L, MA-M "
            "and MA-S registries (~5 MB). netzilla already ships all three, so "
            "this only matters for prefixes assigned since this release.",
            uses=("Every six months or so, to pick up newly assigned prefixes.",),
        ),
    },
    # ------------------------------------------------------------ LIFECYCLE
    "LifecyclePane": {
        "part": H(
            "Type an exact part number in 'Part number'. Shows end-of-sale and "
            "end-of-support dates, with a link to the vendor bulletin.",
            uses=(
                "Build a refresh plan: which switches go out of support next year?",
                "Justify a hardware budget with vendor EoL dates.",
            ),
            targets=("WS-C3850-24T-L — Catalyst 3850", "any SKU from your own inventory"),
            note="Matching is exact. For fuzzy names use SEARCH FAMILIES.",
        ),
        "search": H(
            "Type a vendor or series in the second field. Lists matching "
            "product families and their slugs.",
            uses=("You know it's 'a Catalyst 3850' but not the exact SKU.",),
            targets=("catalyst 3850", "juniper ex", "fortigate"),
        ),
        "family": H(
            "Put a family slug (copied from SEARCH FAMILIES results) in either "
            "field. Shows every model in that family with its dates.",
            uses=("See the whole product line's EoL timeline at once.",),
            note="Run SEARCH FAMILIES first to get a slug.",
        ),
        "software": H(
            "Type a product in 'Software and version', with the version you run "
            "if you like (Enter in that box runs this). Shows every release "
            "cycle with its end-of-support and end-of-life dates from "
            "endoflife.date, and — given a version — whether yours is still "
            "supported. A vague name lists the matching products to pick from.",
            uses=(
                "Is the IOS XE on this router still getting security fixes?",
                "Audit prep: which firewalls run a PAN-OS or FortiOS past EoL?",
                "Plan upgrades before a release's support ends, not after.",
            ),
            targets=(
                "cisco-ios-xe 17.9.4",
                "panos 10.2",
                "fortios 7.0",
                "routeros 6.49",
                "ubuntu 20.04  ·  windows-server 2016  ·  esxi 7.0",
            ),
            note="Software only — for hardware part numbers use CHECK PART. "
                 "endoflife.date is open data; dates come from each vendor's "
                 "published policy.",
        ),
    },
    # ------------------------------------------------------------ STATUS
    "ServiceStatusPane": {
        "stack": H(
            "Comma-separated provider slugs (up to 12). Reads each vendor's "
            "official status feed.",
            uses=(
                "Users say 'Teams is down'. Is it us or Microsoft?",
                "Morning check of every SaaS your org depends on.",
            ),
            targets=(
                "aws,azure,cloudflare,github,google-cloud",
                "slack,zoom,okta,atlassian",
            ),
            note="Unsure of a slug? Type the name and use FIND PROVIDER.",
        ),
        "incidents": H(
            "No input needed. Lists every active incident across all ~180 "
            "tracked vendors.",
            uses=("Widespread weirdness. Is a big provider having a bad day?",),
        ),
        "find": H(
            "Type a vendor name (first item in the field is used). Returns "
            "matching slugs to use with CHECK STACK.",
            uses=("Find the slug for a provider not in the default list.",),
            targets=("slack", "zoom", "salesforce"),
        ),
    },
    # ------------------------------------------------------------ SPEED
    "SpeedTestPane": {
        "run": H(
            "No input needed. Built in — nothing to install: about 15 s against "
            "Cloudflare's free speed-test servers. Measures latency and jitter, "
            "then download and upload over 4 parallel streams with live graphs, "
            "and latency *while downloading* — the bufferbloat grade.",
            uses=(
                "Is the circuit delivering what the ISP bills for?",
                "Calls stutter when someone downloads: a bufferbloat grade of C "
                "or worse says the router needs SQM (fq_codel/CAKE).",
                "Before/after comparison when troubleshooting a slow site.",
            ),
            note="It saturates the link while running, and is capped at about "
                 "400 MB down and 150 MB up.",
        ),
        "ookla": H(
            "No input needed. Runs a ~30 s download/upload/latency test against "
            "Ookla's servers (the speedtest.net network) from this machine.",
            uses=(
                "Compare with a number your ISP quotes from speedtest.net.",
                "A second opinion when the built-in test looks odd.",
            ),
            note="Needs speedtest-cli (pipx inject netzilla speedtest-cli) or "
                 "Ookla's official 'speedtest' CLI. It saturates the link while "
                 "running.",
        ),
    },
    # ------------------------------------------------------------ DIAG
    "DiagnosticsPane": {
        "ping": H(
            "Type a host or IP and a ping count (1–30). Shows loss and "
            "min/avg/max/jitter plus the raw output.",
            uses=("Is it up? Is there loss or jitter on the path?",),
            targets=("1.1.1.1", "8.8.8.8", "your default gateway"),
        ),
        "trace": H(
            "Type a host or IP. Runs traceroute and labels each hop with its AS. "
            "Stores the path, and the next run flags any reroute.",
            uses=(
                "Where does latency jump: our network, the ISP, or theirs?",
                "Did a routing change send traffic a new way today?",
            ),
            targets=("8.8.8.8", "1.1.1.1", "bbc.co.uk — crosses the Atlantic"),
            note="Takes up to a minute. Needs traceroute.",
        ),
        "mtr": H(
            "Type a host or IP. Runs a 10-cycle mtr report: per-hop loss and "
            "latency.",
            uses=(
                "Evidence for an ISP ticket: loss starting at a specific hop.",
            ),
            targets=("1.1.1.1", "8.8.8.8"),
            note="Loss at a middle hop that doesn't continue to the end is "
                 "usually ICMP rate-limiting, not a real problem. Needs mtr-tiny.",
        ),
        "port": H(
            "Type a host and up to 32 comma-separated TCP ports. A full TCP "
            "connect to each, reported open or closed/filtered.",
            uses=(
                "Is the firewall rule working? Can this box reach the DB on 5432?",
            ),
            targets=(
                "scanme.nmap.org with 22,80,9929,31337 — Nmap's sanctioned test host",
                "portquiz.net with 8080,8443,2222 — answers on every port, "
                "tests your outbound filtering",
            ),
            note="Only probe hosts you own or are allowed to test.",
        ),
        "mtu": H(
            "Type a host or IP. Binary-searches don't-fragment pings to find "
            "the largest packet that gets through.",
            uses=(
                "VPN/GRE tunnel issues: some sites load, others hang.",
                "Check whether PPPoE or a tunnel is clamping to 1492/1400.",
            ),
            targets=("1.1.1.1 — expect 1500 on plain ethernet", "same target with VPN on"),
        ),
        "ntp": H(
            "Type an NTP server in 'Host or IP' (leave 1.1.1.1 or blank for "
            "pool.ntp.org). Measures this machine's clock offset.",
            uses=(
                "Kerberos/AD logins fail, TLS 'not yet valid' errors, logs out of order.",
            ),
            targets=(
                "pool.ntp.org",
                "time.cloudflare.com",
                "time.nist.gov",
                "time.google.com — note: Google smears leap seconds",
            ),
            note="Needs outbound UDP/123.",
        ),
        "tools": H(
            "No input needed. Lists which local tools (ping, traceroute, mtr, "
            "dig, whois, openssl…) are installed and the apt command for any "
            "that are missing.",
            uses=("Run once on a new machine.",),
        ),
    },
    # ------------------------------------------------------------ CONFIG
    "ConfigPane": {
        "analyse": H(
            "Paste 'show interfaces', 'show ip route' or a running-config into "
            "the box, then ANALYSE. Flags error counters, err-disabled and "
            "down/down ports, and counts routes by protocol. Nothing leaves the "
            "machine.",
            uses=(
                "Scan a 48-port 'show interfaces' for CRC errors in one second.",
                "CCNA lab: check your route table has the OSPF routes you expect.",
            ),
            targets=(
                "Output from a Packet Tracer / GNS3 / CML lab device",
                "'show interfaces' from any switch you manage",
            ),
            note="Paste in Tilix with Ctrl+Shift+V.",
        ),
        "clear": H(
            "Empties the paste box and the results.",
        ),
    },
    # ------------------------------------------------------------ CREDS
    "CredsPane": {
        "password": H(
            "Type a password in the first box (it is masked as you type). It is "
            "SHA-1 hashed locally and only the first 5 hex characters are sent "
            "(k-anonymity). The password never leaves the machine and nothing "
            "is cached.",
            uses=(
                "Check whether a service-account or default password is on "
                "attacker wordlists.",
                "Show users why 'Summer2024!' is a bad idea.",
            ),
            targets=(
                "password123 — seen millions of times",
                "a long random passphrase — expect NOT FOUND",
            ),
        ),
        "breach": H(
            "Type a company name or domain in the second box (Enter there runs "
            "this search). Searches HIBP's public directory of "
            "known breaches (~1,000 incidents). This lists breached services, "
            "not individual email addresses.",
            uses=(
                "A vendor we use — have they had a published breach?",
                "Which data types (passwords, phone numbers) leaked in a breach?",
            ),
            targets=("adobe", "linkedin.com", "dropbox", "canva"),
            note="No match only means HIBP hasn't catalogued a breach (e.g. The "
                 "Pirate Bay isn't listed). Per-email search needs a paid HIBP key.",
        ),
    },
    # ------------------------------------------------------------ WIFI
    "WifiPane": {
        "scan": H(
            "Press SCAN to list every access point in range: SSID, BSSID, the "
            "AP's maker, band, channel, signal, encryption and top data rate. "
            "Uses nmcli "
            "when it can (no root, signal shown as approximate dBm from link "
            "quality) and falls back to iw.",
            uses=(
                "Survey what is on the air before choosing a channel or a seat.",
                "Spot an open or WEP network that should not be there.",
                "Find the strongest AP for a device that keeps roaming.",
            ),
            targets=(
                "your own home or office Wi-Fi",
                "a café or hotel network you are allowed to be on",
            ),
            note="This is a passive read of beacons every AP broadcasts — the "
                 "same thing your phone's Wi-Fi list shows. Nothing is "
                 "transmitted, and there is no attack here.",
        ),
        "channels": H(
            "No input beyond a recent SCAN. Shows how busy each 2.4 GHz "
            "channel is — counting overlap, not just APs sitting exactly on it "
            "— and recommends which of 1, 6 or 11 to move to.",
            uses=(
                "Your 2.4 GHz is slow and you want the quietest channel.",
                "Explain to someone why 1/6/11 are the only real choices.",
            ),
            targets=("run SCAN first, then CHANNELS",),
            note="1, 6 and 11 are the only 2.4 GHz channels that do not overlap "
                 "each other. An AP on channel 4 still interferes with 6, which "
                 "is why the second table counts overlap.",
        ),
        "signal": H(
            "Put a network's SSID or BSSID in the GRAPH box — or click it in LIVE "
            "AIR's list — and press SIGNAL. netzilla keeps reading it every couple "
            "of seconds and graphs that one network's dBm live, so you can walk a "
            "site and watch it rise and fall.",
            uses=(
                "Find the dead spot in a house or office by walking with it.",
                "Aim a directional antenna by watching the number climb.",
                "Confirm a repeater actually helps where you stand.",
            ),
            targets=(
                "your own SSID, e.g. HomeNet",
                "a specific radio by BSSID from the SCAN list",
                "blank box: the network picked in LIVE AIR",
            ),
            note="dBm is negative and closer to zero is stronger: -50 is "
                 "excellent, -70 fair, -80 and below is trouble. Runs until you "
                 "press another button, or for STOP AFTER seconds.",
        ),
        "iwscan": H(
            "Forces the iw backend instead of nmcli: exact dBm rather than an "
            "estimate, and precise channel and security detail. Needs an "
            "interface selected and the privilege to scan.",
            uses=(
                "You want real dBm, not the link-quality approximation.",
                "You are documenting a site survey and need accurate numbers.",
            ),
            targets=("pick your wireless interface first, then DEEP SCAN",),
            note="iw scanning needs CAP_NET_ADMIN. TOOL CHECK shows the "
                 "one-time setcap that grants it without full root.",
        ),
        "tools": H(
            "No input. Lists your wireless interfaces, whether nmcli and iw are "
            "installed, and whether the radio is soft-blocked, with the "
            "commands to fix each — and the same for Bluetooth: the bleak "
            "library, the BlueZ service, the adapter and whether it is on.",
            uses=("Run this first if SCAN or BLUETOOTH finds nothing.",),
            note="If SCAN is empty, the radio is often rfkill-blocked: "
                 "'rfkill list' then 'rfkill unblock wifi' (or bluetooth).",
        ),
        "air": H(
            "Press LIVE AIR and leave it running. Every network in range gets a "
            "live signal bar and a scrolling history, your own network (or the "
            "one typed in the GRAPH box) gets a big graph, and the 2.4 GHz "
            "channel load updates as neighbours come and go. Click a network in "
            "the list and the big graph follows it; click it again and the view "
            "shows only that network — its row, its channel and everything seen "
            "of it, with who shares its channel. It keeps going on its own — no "
            "need to press SCAN again — until you press another button, or for "
            "STOP AFTER seconds if you typed one.",
            uses=(
                "Watch the air while you move a router or change its channel.",
                "See a neighbour's network appear, fade or drop off entirely.",
                "Focus on one access point to see what shares or overlaps its channel.",
                "Leave it up on a second screen during a Wi-Fi complaint.",
            ),
            targets=(
                "blank GRAPH box = graph the network you're joined to",
                "click a neighbour's row (or type its SSID) to graph that one instead",
                "keyboard: Tab to the list, ↑ ↓ to pick, Enter for only it, Esc back",
            ),
            note="The table and graph update every REFRESH EVERY seconds. Your "
                 "own network is read from the driver on every update. Every "
                 "other network comes from the radio's latest finished scan, "
                 "and scans keep running in the background — a full scan of "
                 "every channel takes most adapters 2–4 seconds, so those "
                 "readings are only as fresh as that; the headline shows how "
                 "old the newest one is. HISTORY lists each network's last "
                 "readings in dBm, a new one only when the radio has actually "
                 "heard it again.",
        ),
        "link": H(
            "Pick your wireless interface and press LINK HEALTH. It shows the "
            "AP you're joined to, channel, signal, bitrate, retransmissions, "
            "missed beacons, addresses, gateway and DNS — and then keeps "
            "watching, graphing signal and bitrate and counting retries per "
            "second rather than since you joined, so a burst of interference "
            "shows up as it happens.",
            uses=(
                "'The Wi-Fi is slow' — is it signal, interference or the AP?",
                "Catch a laptop that keeps roaming between two access points.",
                "Watch retries climb when the microwave goes on.",
            ),
            targets=("your wireless interface, e.g. wlan0 or wlp3s0",),
            note="Retries above ~10% mean interference or a weak link. Needs "
                 "iw for the radio numbers (no root); nmcli fills in the IP side.",
        ),
        "devices": H(
            "Press DEVICES to see every device on the Wi-Fi you're joined to: "
            "IP, MAC maker, hostname and what it looks like. It is the LAN "
            "tab's SWEEP, aimed automatically at the subnet this wireless "
            "interface is on — even when the machine's default route is a "
            "cable or a VPN.",
            uses=(
                "Who is on my Wi-Fi right now?",
                "Find the IP of a printer, camera or smart plug.",
                "Spot a device you don't recognise.",
            ),
            targets=("your own home or office Wi-Fi",),
            note="Sweeps with ping and reads names from what each device says "
                 "about itself. No root. Use it on networks you run.",
        ),
        "ports": H(
            "Press PORTS after DEVICES (or on its own — it runs DEVICES first). "
            "Every device found is checked for the same small set of "
            "identifying ports the LAN tab's IDENTIFY uses — web admin pages, "
            "printers, file sharing, casting, remote desktop — and anything "
            "worth a second look, like Telnet or unencrypted MQTT, is called out.",
            uses=(
                "Find the smart plug that still has Telnet open.",
                "See which box is actually running the web admin page.",
                "Check nothing on the Wi-Fi exposes Remote Desktop by accident.",
            ),
            targets=("the devices DEVICES found on your own Wi-Fi",),
            note="A plain TCP connect to a couple of dozen ports per device — no "
                 "root, no raw packets. Only for networks you run or may test.",
        ),
        "traffic": H(
            "Pick your wireless interface and press TRAFFIC. Download and upload "
            "are graphed live, second by second, alongside the connections this "
            "machine has open over the Wi-Fi and the services they use. Runs "
            "until you press another button.",
            uses=(
                "Is the Wi-Fi slow, or is something on this machine saturating it?",
                "Watch a download or a video call's bandwidth as it happens.",
                "See which app is talking to which host over the wireless link.",
            ),
            targets=("your wireless interface",),
            note="No root: /proc/net/dev for bytes, ss for connections — the "
                 "same code as the INT and FLOW tabs, limited to the Wi-Fi.",
        ),
        "packets": H(
            "Pick your wireless interface and press PACKETS for a live capture "
            "on it: packets per second graphed, the protocol mix, the busiest "
            "hosts — named by the DNS lookups seen in the same capture — the "
            "lookups themselves, and the newest packets. The PACKETS filter box "
            "takes a tshark display filter, e.g. dns or ip.addr == 192.168.1.20.",
            uses=(
                "What is this machine's Wi-Fi traffic actually made of?",
                "See which names are being looked up, and by what.",
                "Watch a problem device's traffic by filtering to its IP.",
            ),
            targets=("dns", "tcp.port == 443", "ip.addr == 192.168.1.20"),
            note="Uses the CAPTURE tab's tshark and its permission: authenticate "
                 "once and both tabs are unlocked for the session. Packets seen "
                 "are kept for EXPORT CSV; CAPTURE → SAVE PCAP writes a file "
                 "for Wireshark.",
        ),
        "export": H(
            "Press EXPORT CSV to save everything this tab has gathered — "
            "networks and their signal ranges, link samples, throughput, "
            "devices, open ports, DNS lookups and packets — as one CSV file "
            "each, in ~/netzilla-exports/wifi-<date>-<time>/.",
            uses=(
                "Attach a site survey to a ticket.",
                "Graph a long LINK HEALTH run in a spreadsheet.",
            ),
            note="Only views you have run this session have anything to export. "
                 "BLUETOOTH's devices are saved as bluetooth.csv.",
        ),
        "bluetooth": H(
            "Press BLUETOOTH to list every Bluetooth device broadcasting nearby, "
            "live: its name when it sends one, its maker (from the manufacturer "
            "ID in the broadcast), a best guess at what it is — phone, earbuds, "
            "watch, TV, beacon, tracker… — its signal with a history, a rough "
            "distance, and when it was first and last heard. The graph follows "
            "the nearest device heard, the one you click in the list, or the one "
            "named in the GRAPH box (a name, an address or its last four digits, "
            "or a kind such as airtag). Click the picked device again and the view "
            "shows only it: its row, its graph, and everything its broadcasts say.",
            uses=(
                "See what is broadcasting around you — at home, at a desk, on a site.",
                "Find a lost earbud or tracker: pick it, then watch its signal rise as "
                "you walk.",
                "Spot an item tracker that has been near you a long time (flagged).",
            ),
            targets=(
                "click a device's row; click it again to show only it",
                "keyboard: Tab to the list, ↑ ↓ to pick, Enter for only it, Esc back",
                "AirTag, Tile or earbuds typed in the GRAPH box",
            ),
            note="Listening only: netzilla never pairs or connects. On Linux it is an "
                 "active scan — the radio may send a short scan request so a device "
                 "answers with its name. Phones change their Bluetooth address every "
                 "few minutes for privacy, so one phone can appear more than once. "
                 "Distance is a rough estimate from signal strength.",
        ),
        "bttrackers": H(
            "Press BT TRACKERS for the tracker safety check: every AirTag, Find My "
            "accessory, Tile, SmartTag, Chipolo and Google Find Hub tag nearby, "
            "how long each has been near you, and the trackers remembered from "
            "the last seven days with the networks you were on when you heard "
            "them. Click a tracker to graph it; click it again to show only it, "
            "with where it has been heard.",
            uses=(
                "Check a car, bag or coat for a tracker that isn't yours.",
                "Run it at home and again somewhere else — one heard in both is flagged.",
                "Pick one tracker and walk around: its signal rises as you get closer.",
            ),
            targets=("leave it running for ten minutes or more",
                     "a tracker picked in BLUETOOTH stays picked here"),
            note="Flagged: near you for 10+ minutes without a break, or heard on two "
                 "or more networks you were on. An AirTag that says it is with its "
                 "owner is never flagged — Find My only warns about trackers away "
                 "from theirs. Your own tracker will show here too. Trackers are "
                 "remembered in netzilla's local cache for seven days, nothing else.",
        ),
    },
    # ------------------------------------------------------------ FLOW
    "FlowPane": {
        "connections": H(
            "Press CONNECTIONS for every socket this machine has open: "
            "protocol, local and remote address, the service behind it, state "
            "and the owning process. The host filter box narrows it to one IP "
            "or process.",
            uses=(
                "See what a machine is actually talking to right now.",
                "Find which process opened a connection you did not expect.",
                "Check whether a service is really listening and connected.",
            ),
            targets=(
                "(blank) — everything",
                "a process name like firefox or sshd in the filter box",
            ),
            note="Reads your own sockets via ss. Process names for sockets "
                 "owned by other users only show when netzilla runs elevated.",
        ),
        "talkers": H(
            "Ranks remote hosts by how many connections they hold. External "
            "ones get ASN, organisation and rough location via ip-api "
            "(keyless) plus their reverse-DNS name; hosts on your LAN are "
            "identified instead — vendor, hostname and device type, as on "
            "LAN > SWEEP.",
            uses=(
                "Find the host a machine is talking to the most.",
                "Put a name and a network to an unfamiliar remote IP.",
                "Spot a connection to somewhere it has no business being.",
            ),
            targets=("run it while a browser or an app is busy",),
            note="Only public IPs are geolocated. ip-api allows 45 "
                 "lookups/minute on the free tier.",
        ),
        "services": H(
            "Groups active connections by the application service, named from "
            "whichever end is the well-known port — so your browsing shows as "
            "HTTPS and an inbound SSH shows as SSH.",
            uses=(
                "See the shape of what a box is doing at a glance.",
                "Notice plain HTTP, Telnet or SMB where you expected none.",
            ),
            targets=("run it on a busy machine",),
        ),
        "watch": H(
            "A live view: the connection table, its summary and the "
            "established sockets, refreshed about once a second for the "
            "seconds you set. Any other button stops it.",
            uses=(
                "Watch connections appear as you reproduce a problem.",
                "See a scan or a sync open dozens of sockets in real time.",
            ),
            targets=("set WATCH seconds, then WATCH LIVE",),
            note="Stops itself at your seconds (capped at ten minutes) so one "
                 "left running behind another tab cannot poll forever.",
        ),
        "intensity": H(
            "Per-interface throughput right now, from two /proc/net/dev "
            "samples two seconds apart — the same sampler the INT tab uses.",
            uses=(
                "See which interface is carrying the traffic.",
                "Confirm a transfer is actually moving bytes.",
            ),
            targets=("just press it",),
            note="Linux-only, like anything reading /proc/net/dev.",
        ),
        "blacklist": H(
            "Put the path of a file of bad IPs (one IP or CIDR per line, # for "
            "comments) in the BLACKLIST box and press BLACKLIST. Every current "
            "connection to a listed address is flagged.",
            uses=(
                "Check a machine against a threat-intel IP list you trust.",
                "Confirm nothing is talking to a range you are blocking.",
            ),
            targets=(
                "a list you exported from your own SIEM or firewall",
                "a public IP blocklist you have saved locally",
            ),
            note="Matching is local and offline — the list never leaves the "
                 "machine. CIDRs and single IPs both work.",
        ),
        "tools": H(
            "No input. Shows whether ss and netstat are present, how many "
            "sockets are readable right now, and where geo and PCAP come from.",
            uses=("Run this first if the other buttons come up empty.",),
            note="For on-the-wire packet capture and PCAP export, this tab "
                 "points at CAPTURE, which does the actual capture.",
        ),
    },
}


# Every live view reads its refresh interval from the same REFRESH EVERY box;
# say so on each one's card, with that view's own default.
_REFRESH_DEFAULTS = {
    ("WifiPane", "air"): "3 s — scanning faster than every second is refused",
    ("WifiPane", "signal"): "3 s",
    ("WifiPane", "link"): "1 s",
    ("WifiPane", "traffic"): "1 s",
    ("WifiPane", "packets"): "1 s between repaints",
    ("WifiPane", "bluetooth"): "1 s",
    ("WifiPane", "bttrackers"): "1 s",
    ("InterfacesPane", "rates"): "1 s",
    ("FlowPane", "watch"): "1 s",
    ("CapturePane", "live"): "0.6 s between repaints",
    ("LANPane", "dupip"): "1 s between checks",
    ("LANPane", "syslog"): "1 s — the newest messages show live while it listens",
}
for (_pane, _key), _default in _REFRESH_DEFAULTS.items():
    _tool = HELP[_pane][_key]
    HELP[_pane][_key] = replace(
        _tool,
        note=(_tool.note + " " if _tool.note else "")
        + f"REFRESH EVERY sets how often it updates, in seconds (blank = {_default}).",
    )


def get_help(pane: str, action: str) -> ToolHelp | None:
    return HELP.get(pane, {}).get(action)


def help_panel(palette: Palette, label: str, tool: ToolHelp) -> RenderableType:
    """The instruction card rendered above the results area."""
    parts: list[RenderableType] = [Text(tool.usage, style=palette.foreground)]

    def section(title: str, items: tuple[str, ...], bullet: str, style: str) -> None:
        if not items:
            return
        parts.append(Text(""))
        parts.append(Text(title, style=f"bold {palette.secondary}"))
        for item in items:
            line = Text(f" {bullet} ", style=palette.secondary)
            line.append(item, style=style)
            parts.append(line)

    section("USE IT WHEN", tool.uses, "▸", palette.foreground)
    section("TRY IT ON", tool.targets, "›", palette.accent)
    if tool.note:
        parts.append(Text(""))
        parts.append(Text(f"NOTE  {tool.note}", style=palette.warning))

    return Panel(
        Group(*parts),
        title=Text(f" HOW TO USE — {label.upper()} ", style=f"bold {palette.primary}"),
        title_align="left",
        subtitle=Text(" disappears when results arrive ", style=palette.muted),
        subtitle_align="right",
        border_style=palette.accent,
        box=PANEL_BOX,
        padding=(0, 1),
    )


__all__ = ["HELP", "ToolHelp", "get_help", "help_panel"]
