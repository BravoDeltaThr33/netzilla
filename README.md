# netzilla

A single-window, retro-CRT-styled terminal app that pulls together the free
network, DNS, TLS, routing, threat-intel and hardware-lifecycle lookups a
network admin actually reaches for — plus the local tools (`dig`, `whois`,
`openssl`, `ping`, `traceroute`, `mtr`) that no API should be replacing.

Twenty-one tabs, seventeen dark colour themes, **free and open data sources
only**, and zero setup to start using most of it. Runs on Linux and macOS.

- **Pixel graphs in kitty and Ghostty.** Live Wi-Fi signal, a channel
  spectrum, interface rates and the speed test are drawn as real
  anti-aliased images in terminals that can show them, and as text
  everywhere else — netzilla asks the terminal what it is and decides for
  itself.
- **Nothing paid.** Every source is free; most need no key at all, and
  the few that do take a key from a free account — you bring your own.
- **Every control checked.** Every button on every tab and every documented
  key, in both cases, is exercised by the test suite.

![LIVE AIR in kitty — every Wi-Fi network graphed live](docs/showcase/live-air.gif)

## At a glance

DASH puts this machine, your network, the terminal, local tools, key status,
a live network graph and API quota side by side on one screen.

![DASH in kitty](docs/showcase/01-dash-pixel.png)

## What's in it

| Tab | What it does |
|---|---|
| **DASH** | This machine, the network (public IP, DNS, Wi-Fi), the terminal, local tools, key status, a live network graph and API quota — on one screen |
| **IP LOOKUP** | One address, five independent reputation/geo opinions in parallel |
| **SUBNET** | IPv4/IPv6 CIDR maths, splitting, host fitting, range → CIDR |
| **DNS/WHOIS** | `dig`/`whois`, RDAP, DoH resolver-disagreement check, typosquat scan; DNS-over-HTTPS when `dig` is missing |
| **SSL/TLS** | Local cert check, SSL Labs grade, crt.sh Certificate Transparency search |
| **BGP/ASN** | Prefix origin, AS overview, peers, RPKI, origin history (hijack alerts) |
| **THREAT** | CVE with CVSS, EPSS and KEV; URLhaus, ThreatFox/MalwareBazaar/Feodo, first-seen timeline |
| **DISCOVERY** | What the internet sees on an address: InternetDB scan, HOST PROFILE from four free sources, CVE DETAIL ranked by KEV, EPSS and CVSS |
| **LAN** | Sweep that names every device on the network (vendor, hostname, what it is), per-device IDENTIFY, rogue-DHCP detector, duplicate-IP watch, SNMP, syslog catcher |
| **INT** | Per-interface live throughput graphs, iftop/vnstat/bmon reports, NIC maker |
| **WIFI** | A Wi-Fi workbench: live signal graphs for every network, a channel spectrum, live link health, devices on this Wi-Fi and their ports, live traffic and packets on the wireless interface, 1/6/11 channel pick, CSV export |
| **CAPTURE** | Live or bounded tshark/tcpdump capture, protocol stats, pcap save/read |
| **FLOW** | This host's own connections — top talkers with ASN/geo/reverse DNS (LAN peers identified), service breakdown, bandwidth, blacklist flagging |
| **MAC** | Offline IEEE vendor lookup (~54,000 prefixes), private-MAC detection, "is it on my LAN right now?" |
| **LIFECYCLE** | Hardware end-of-sale / end-of-life dates, and software release support (OS, firmware, runtimes) |
| **STATUS** | Live status for 180 cloud/SaaS vendors — "is it us or them" |
| **SPEED** | Built-in speed test: download, upload, latency, jitter, bufferbloat — drawn live |
| **DIAG** | ping, traceroute+ASN, mtr, port list, path MTU, NTP drift |
| **CONFIG** | Paste in a `show interfaces`/running-config and get it summarized, fully local |
| **CREDS** | Pwned-password (k-anonymity) and breach-directory lookup |
| **SETTINGS** | Every API key, theme, graphics mode, notifications, cache controls |

Most of it needs no API key and no root.

## Pixels where the terminal can draw them, text everywhere else

netzilla asks the terminal what it is before the interface starts (about a
third of a second) and draws graphs in whichever form will work:

| kitty / Ghostty | any other terminal |
|---|---|
| ![LIVE AIR, pixel graphs](docs/showcase/02-wifi-live-air-pixel.png) | ![LIVE AIR, text graphs](docs/showcase/03-wifi-live-air-text.png) |
| ![CHANNELS spectrum, pixels](docs/showcase/04-wifi-channels-pixel.png) | ![CHANNELS spectrum, braille](docs/showcase/05-wifi-channels-text.png) |

The image sits exactly where the text graph would: labels, axes and channel
numbers stay as text, so nothing moves when you switch. Pixels are used only
where they are known to work — kitty 0.28+, Ghostty 1.0+, or any terminal
that answers the kitty feature query with Unicode-placeholder support — and
inside tmux when `allow-passthrough` and 24-bit colour are on (netzilla asks
tmux which terminal you're attached from). WezTerm, Konsole, iTerm2, GNOME
Terminal and the rest get text graphs.

```console
$ netzilla --terminal
Terminal                 Ghostty 1.2.3
Identified by            XTVERSION reply (asked the terminal)
Truecolour               yes
kitty graphics           yes
Unicode placeholders     yes
Cell size                10 x 21 px
Hyperlinks               yes
Clipboard (OSC 52)       yes
Notifications            osc777
Graphics setting         auto
Graphs will be drawn as  pixel
Why                      Ghostty 1.2.3 draws kitty-protocol images with Unicode placeholders — graphs are drawn in pixels.
```

Choose **Auto** (default), **Pixel** or **Text** on SETTINGS → DISPLAY, or
for one run with `netzilla --graphics text`.

## The WIFI tab — everything for a Wi-Fi problem, live

Press a button once; the live views keep updating in place until you press
another one (or for as many seconds as **STOP AFTER** says).

| Button | What you get |
|---|---|
| **LIVE AIR** | Updates every 3 seconds (or whatever REFRESH EVERY says — 1 s works): every network with a live signal bar and its last ten readings in dBm, a big graph of your own network, a live spectrum of the channels, networks that disappear marked *gone*, and the 2.4 GHz 1/6/11 load as it changes |
| **SIGNAL** | One network's dBm as a full-height live graph — walk the building and watch it |
| **LINK HEALTH** | Your own connection, live: signal and bitrate graphs, retransmissions *per second*, missed beacons, roaming, addresses/gateway/DNS, and a plain-English verdict |
| **DEVICES** | Who else is on this Wi-Fi — the LAN sweep and device identification, aimed at the Wi-Fi's own subnet |
| **PORTS** | The identifying-port check across every device found, with a "worth a second look" list (Telnet on a smart plug, RDP left on…) |
| **TRAFFIC** | Download/upload of the wireless interface graphed second by second, and which apps are talking to whom over it |
| **PACKETS** | A live capture on the wireless interface: packets/sec, protocols, busiest hosts named by the DNS lookups seen, the lookups themselves |
| **CHANNELS** | Every network as a hump across the channels it really occupies (20/40/80/160 MHz, from the driver), and the channel to pick |
| **EXPORT CSV** | All of the above, saved as CSV |
| **SCAN / DEEP SCAN** | The one-shot survey, and exact dBm via `iw` |

LIVE AIR never waits for the radio: each update reads the latest finished scan
(instant), your own network is read from the driver every update, and new
scans run in the background. A full scan of every channel takes most adapters
2–4 seconds, so other networks' readings are as fresh as that — the headline
says how old the newest one is.

| | |
|---|---|
| ![LINK HEALTH](docs/showcase/06-wifi-link-health-pixel.png) | ![SIGNAL](docs/showcase/07-wifi-signal-pixel.png) |
| ![TRAFFIC](docs/showcase/08-wifi-traffic-pixel.png) | ![INT live rates](docs/showcase/09-int-live-rates-pixel.png) |

## Free lookups

| | |
|---|---|
| ![Built-in speed test](docs/showcase/10-speed-pixel.png) | ![CVE DETAIL with EPSS and KEV](docs/showcase/11-discovery-cve-detail.png) |
| ![HOST PROFILE](docs/showcase/12-discovery-host-profile.png) | ![SOFTWARE EOL](docs/showcase/13-lifecycle-software-eol.png) |

- **HOST PROFILE** — open ports and CVEs (Shodan InternetDB), organisation and
  location (IP-API), origin AS and prefix (RIPEstat), registry and abuse
  contact (RDAP), all at once, all free.
- **CVE DETAIL** — every CVE on an address ranked by what matters first:
  already exploited (CISA KEV), likely to be (FIRST EPSS), then severity
  (NVD CVSS).
- **SOFTWARE EOL** — `ubuntu 20.04`, `panos 10.2`, `ios-xe 17.9`,
  `fortios 7.2`: is that release still supported? Close to 500 products from
  endoflife.date. Also `netzilla software "panos 10.2"`.
- **RUN SPEED TEST** — download and upload over four streams against
  Cloudflare's free endpoints, latency, jitter and bufferbloat graded A+ to F,
  drawn live, with data use capped. Nothing to install.

More in [`docs/showcase/`](docs/showcase/) — CVE lookups with EPSS, DNS
without `dig`, service status and SETTINGS.
The Wi-Fi, LAN and speed-test screenshots use invented sample data; the rest
are live lookups of public hosts (scanme.nmap.org, nmap.org), across a range of
themes.

## Live views: you choose the refresh rate

Every view that streams live data has a **REFRESH EVERY (s)** box on its tab —
WIFI (LIVE AIR, SIGNAL, LINK HEALTH, TRAFFIC, PACKETS), INT (LIVE RATES), FLOW
(WATCH LIVE), CAPTURE (LIVE CAPTURE) and LAN (DUP-IP WATCH, SYSLOG CATCH).
Leave it blank for the view's default (3 s for LIVE AIR and SIGNAL, 1 s for
most others) or type any number of seconds, e.g. `1`, `0.5` or `10`.

## Colours that mean something

Values are coloured by what they are, the same way on every tab and in every
theme — in the pixel graphs too:

| What | Colour |
|---|---|
| Signal and quality (one scale) | excellent **green** · good **blue** · fair **yellow** · weak **orange** · very weak **red** |
| Band | 2.4 GHz **light blue** · 5 GHz **light green** · 6 GHz **lavender** |
| Channel | a colour of its own for every channel number (1, 6 and 11 as far apart as possible) |
| SSID | **pink** — `<hidden>` in **yellow** |
| Security | WPA3 green · WPA2 blue · WPA orange · WEP / Open red |
| Addresses | IPs **teal**, MACs **lilac**, wherever they appear |
| Names | vendors sand · hostnames periwinkle · device types orchid |
| States and verdicts | ESTAB / OK / up green · LISTEN / INFO blue · CHECK yellow · PROBLEM / down red |
| Latency, errors, scores | good-to-bad on the same five-colour scale (CVSS, EPSS, SSL grades, bufferbloat…) |

## Who's on my network?

Leave the box empty on **LAN → SWEEP** (or press **WIFI → DEVICES**) and
netzilla sweeps the subnet you're on and names every device it finds:

```
IP            MAC                VENDOR       HOSTNAME             DEVICE                DETAILS
192.168.1.1   08:9b:f1:00:00:01  eero         —                    Router / gateway      TTL 64 · Unix-like
192.168.1.12  04:0e:3c:00:00:02  HP           HP-OfficeJet-8020    Printer               HP OfficeJet Pro 8020 · IPP print
192.168.1.31  00:12:f0:00:00:03  Intel        DESKTOP-EXAMPLE      Windows PC            NetBIOS WORKGROUP · TTL 128
192.168.1.44  5a:00:00:00:00:04  private MAC  Sams-iPhone          iPhone                iPhone15,2 · Apple Continuity
```

*(illustrative)* The vendor comes from the full IEEE registry, shipped with
netzilla and read offline. The name comes from whatever the device answers: your router's DNS,
mDNS, NetBIOS or UPnP. **DEVICE** is netzilla's best guess from all of it, and
**IDENTIFY** on one IP shows the evidence behind the guess, plus which
tell-tale ports are open. No API, no key.

With a VPN up, the device probes stay on your own LAN. They are never sent
across the tunnel, and home-address lookups never go to the VPN's DNS.

## Keys

| Key | Does |
|---|---|
| <kbd>←</kbd> <kbd>→</kbd> | Switch tabs (with the tab bar focused) |
| <kbd>Tab</kbd> / <kbd>Shift</kbd>+<kbd>Tab</kbd> | Move between fields and buttons |
| <kbd>Enter</kbd> | In a box: run that box's action. On a button: press it |
| <kbd>T</kbd> | Next colour theme (<kbd>Ctrl</kbd>+<kbd>T</kbd> while typing in a box) |
| <kbd>F1</kbd> / <kbd>F2</kbd> | DASH / SETTINGS |
| <kbd>F3</kbd> | Roll this tab's controls up / down (or ▲ ▼) |
| <kbd>F4</kbd> | Copy this tab's results as text (clipboard, OSC 52 over SSH, or a file) |
| <kbd>Ctrl</kbd>+<kbd>P</kbd> | Command palette: any tab, theme, graphics mode, copy, clear cache |
| <kbd>Ctrl</kbd>+<kbd>R</kbd> | Clear the response cache |
| <kbd>Q</kbd> | Quit (<kbd>Ctrl</kbd>+<kbd>Q</kbd> anywhere) |

Letters work in either case. `netzilla --tab wifi` opens on a tab (any case,
or a unique start of its name); `netzilla --help` lists the one-shot commands
(`ip`, `dns`, `asn`, `software`, `sweep`, …) for scripting, with `--json`.

## Themes

Seventeen dark retro palettes — `phosphor-green` (default), `amber-phosphor`,
`ice-cyan`, `vhs-magenta`, `ember-rust`, `sapphire-ice`, `sunset-mesa`,
`desert-sage`, `miami-night`, `arcade-pop`, `neon-mint`, `vapor-pop`,
`crt-neon`, `cyber-coral`, `route-66`, `space-1975`, `disco-70s`. Press
<kbd>T</kbd> to cycle, or pick one on SETTINGS; the pixel graphs follow the
theme. For scanlines, phosphor glow and screen curvature, run it inside
[cool-retro-term](https://github.com/Swordfish90/cool-retro-term) (text
graphs).

## Installing

Needs **Python 3.10+** and [pipx](https://pipx.pypa.io/).

```bash
# 1. Prerequisites — Ubuntu / Linux Mint
sudo apt update
sudo apt install -y python3 python3-venv pipx git dnsutils whois openssl \
    iputils-ping traceroute mtr-tiny iw
pipx ensurepath        # then open a new terminal

# 1. Prerequisites — macOS (Homebrew)
brew install python pipx git mtr net-snmp
pipx ensurepath        # then open a new terminal

# 2. Get netzilla and install it
git clone https://github.com/OWNER/netzilla.git
cd netzilla
pipx install .

# 3. Run it
netzilla --terminal    # optional: what netzilla sees in this terminal
netzilla
```

Prefer a release archive? Download it from the Releases page, then
`tar -xzf netzilla-4.1.0.tar.gz && cd netzilla && pipx install .`

Pillow (for the pixel graphs) is installed with it. The speed test is built
in; `pipx inject netzilla speedtest-cli` adds the optional OOKLA TEST.

Upgrading: `git pull` (or unpack the new archive), then
`pipx install --force .` — your theme and saved keys are kept.

For pixel graphs, run netzilla in [kitty](https://sw.kovidgoyal.net/kitty/)
0.28+ or [Ghostty](https://ghostty.org/) 1.0+ (the kitty packaged for Ubuntu
22.04 / Mint 21 is too old — use kitty's own installer;
[the manual](docs/MANUAL.txt), section 2, has the commands for both). In
tmux, add `set -g allow-passthrough on` to `~/.tmux.conf`.

`netzilla` opens straight to the DASH tab. Every tab tells you exactly which
package to install if a tool it wraps is missing — check `DIAG → TOOL CHECK`
and `WIFI → TOOL CHECK`.

Optional, for packet capture on CAPTURE and WIFI → PACKETS:

```bash
sudo apt install -y tshark tcpdump   # answer YES to "non-superusers capture?"
sudo usermod -aG wireshark $USER     # log out & back in afterwards
```

## API keys — bring your own (all free)

netzilla ships with **no API keys**, and every tab works without one. Four
reputation sources switch on when you add a key from a free account:

| Service | Free tier | Get a key |
|---|---|---|
| AbuseIPDB | 1,000 checks/day | <https://www.abuseipdb.com/account/api> |
| VirusTotal | 4 lookups/min, 500/day (non-commercial) | <https://www.virustotal.com/gui/my-apikey> |
| GreyNoise Community | 50 lookups/week | <https://viz.greynoise.io/signup> |
| abuse.ch (URLhaus, ThreatFox, MalwareBazaar) | free | <https://auth.abuse.ch/> |
| NVD *(optional)* | raises CVE lookups from 5 to 50 per 30 s | <https://nvd.nist.gov/developers/request-an-api-key> |

Press <kbd>F2</kbd> for **SETTINGS**, paste each key into its box, press
**SAVE SETTINGS**, then **TEST KEYS**. Keys are stored only on your machine,
in `~/.config/netzilla/config.toml` (mode 0600), and each is sent only to the
service it belongs to.

Or use environment variables, which win over saved keys:

```bash
export NETZILLA_ABUSEIPDB_API_KEY=...
export NETZILLA_VIRUSTOTAL_API_KEY=...
export NETZILLA_GREYNOISE_API_KEY=...
export NETZILLA_ABUSECH_AUTH_KEY=...
export NETZILLA_NVD_API_KEY=...        # optional
```

![SETTINGS](docs/showcase/17-settings-display.png)

## Data sources

All free: IP-API, AbuseIPDB, VirusTotal (public API), GreyNoise Community,
IPLogs, RDAP, Cloudflare/Google/Quad9 DNS-over-HTTPS, Qualys SSL Labs, crt.sh,
RIPEstat, Team Cymru, NVD, CISA KEV, FIRST EPSS, abuse.ch (URLhaus,
ThreatFox, MalwareBazaar, Feodo Tracker), Shodan InternetDB, macvendors.com,
EOSL.ai, endoflife.date, OutageDeck, Cloudflare's speed-test endpoints and
Have I Been Pwned — plus the local tools. [The manual](docs/MANUAL.txt),
section 5, lists each one's limits. Responses are cached in SQLite so repeat lookups cost no quota.

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```

689 tests. Everything is exercised with recorded or mocked responses and a
fake terminal. No network calls, no root, no packets sent to the devices on
your LAN, and no real key is ever used or printed.

## Scope, on purpose

netzilla diagnoses *networks*, not people. There's no username-enumeration,
email/phone-lookup or credential-harvesting tooling in here — profiling a
person is a different job than diagnosing a network. The one exception is
CREDS, which only checks *your own* password or address against Have I Been
Pwned. Nothing on the WIFI tab associates with, deauthenticates or attacks
anyone's network; DEVICES, PORTS and PACKETS are for networks you run.

## Documentation

[`docs/MANUAL.txt`](docs/MANUAL.txt) covers every tab, step-by-step installs
for Linux and macOS, every command-line option, data sources and their
limits, and troubleshooting. [`CHANGELOG.md`](CHANGELOG.md) lists what
changed.

## License

[MIT](LICENSE). netzilla is an independent project and isn't affiliated with, endorsed
by, or sponsored by any of the data providers it queries. Only scan or
enumerate infrastructure you own or are explicitly authorized to test.
