===============================================================================
 netzilla 4.6.0
 A retro terminal toolkit for network administrators
 Runs on Linux, macOS and Windows
 Free and open data sources only · pixel graphs in kitty and Ghostty
===============================================================================

 ███╗   ██╗███████╗████████╗███████╗██╗██╗     ██╗      █████╗
 ████╗  ██║██╔════╝╚══██╔══╝╚══███╔╝██║██║     ██║     ██╔══██╗
 ██╔██╗ ██║█████╗     ██║     ███╔╝ ██║██║     ██║     ███████║
 ██║╚██╗██║██╔══╝     ██║    ███╔╝  ██║██║     ██║     ██╔══██║
 ██║ ╚████║███████╗   ██║   ███████╗██║███████╗███████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═╝

A single tabbed terminal application that pulls together the free network,
DNS, TLS, routing, threat-intel and hardware-lifecycle data sources a network
administrator actually reaches for — plus the local tools (dig, whois,
openssl, ping, traceroute, mtr) that no API should be replacing.


  NETZILLA SHIPS WITH NO API KEYS
  -------------------------------
  Any copy is safe to keep and to pass along. Every tab works without a key;
  four reputation sources (AbuseIPDB, VirusTotal, GreyNoise, abuse.ch)
  switch on once you add a key from a free account. Section 4 walks
  through getting each one and adding it on the SETTINGS tab (F2).
  INSTALL-FOR-FRIEND.txt has the short version of the install steps.


-------------------------------------------------------------------------------
 1. WHAT'S NEW
-------------------------------------------------------------------------------

 4.6.0 — netzilla runs on Windows and macOS too.

   One netzilla for all three systems: the same tabs, buttons and keys on
   Linux, macOS, and Windows 10 and 11. Where a system does a job its own
   way, netzilla asks it that way, and every tab's TOOL CHECK and the
   instruction cards say what that system needs. Section 3 has the install
   steps for each, and 3d lists what works where.

   Windows
     Interfaces, LIVE RATES and FLOW's connections (with the program behind
     each) come from Windows' own IP Helper API, and the WIFI tab from its
     Native Wi-Fi API: every access point with exact dBm, live signal
     graphs, channels and link health. BLUETOOTH uses Windows' own
     Bluetooth stack. Nothing to install, and no administrator rights.
     tracert and pathping stand in for traceroute and mtr. Windows has no
     dig or whois, so DNS records come over DNS-over-HTTPS and WHOIS from
     netzilla's own client (IANA, then the registry, then the registrar);
     without openssl, the TLS handshake is Python's own. Capture uses
     Wireshark with Npcap. Settings live in %APPDATA%\netzilla
   macOS
     The WIFI tab works on macOS: SCAN, LIVE AIR, SIGNAL, CHANNELS and LINK
     HEALTH read system_profiler, or the airport tool on macOS 14.3 and
     older. So do LIVE RATES, DASH's NETWORK PULSE, WIFI → TRAFFIC and FLOW:
     interface counters from netstat -ib, connections from netstat, and the
     program behind each from lsof. iftop and capture need no sudo once
     Wireshark's ChmodBPF is installed, and mtr runs through the sudo
     session AUTHENTICATE opens. DASH shows the real uptime and memory use,
     and SNMP POLL uses the Net-SNMP tools macOS already has
   Everywhere
     A missing tool names the command that installs it on the system you
     are on (apt, brew or winget), or says what netzilla does instead where
     the tool does not exist. 926 tests (67 new).


 4.5.0 — Tokyo from a picture, and the beast's breath alive.

     right   the drawn Tokyo skyline makes way for a picture of Tokyo at
             night: Tokyo Tower, the Skytree, the towers by the bay and
             the Rainbow Bridge under the stars. Like the beast it ships
             with netzilla as brightness alone and is recoloured from the
             theme, so it changes with T
     left    the beast's breath is alive. It rolls through the theme's own
             bright colours (primary, accent, success, warning and error,
             one of each hue) in waves that leave the jaws and run out to
             the title, its brightness rippling as they go: a 2.4-second
             loop of 24 frames. In kitty and Ghostty the breath's cells are
             a small image of their own for each frame, sent once and then
             only swapped; in Tilix and other terminals its sextants are
             recoloured. It moves only while DASH's banner is on screen —
             another tab, or F3 rolling the controls up, rests it
   859 tests (31 new).


 4.4.0 — pictures either side of DASH's title.

   When the window has room (about 115 columns or more), the NETZILLA title
   on DASH has a picture on each side:
     left    a horned beast — its armoured back lit from within, a spiked
             tail curled over it, claws like scythes — breathing a storm of
             energy into the title. It is a picture that ships with
             netzilla, recoloured from the theme: the body in its main
             colour, the hottest parts (eyes, back, breath) burning towards
             white with a touch of its accent
     right   Tokyo at night: Tokyo Tower in orange-red and white, the
             Skytree, office towers with their windows lit, Mt. Fuji with
             snow on its peak, a crescent moon and stars
   Both are drawn in the active theme's colours, so they change with T like
   everything else. In kitty and Ghostty they are part of the banner image,
   with the same glow and scanlines as the lit letters; in Tilix and other
   terminals they are drawn with sextant characters (each cell split 2 × 3)
   — the same pictures, chunkier, the beast shaded two colours to a cell.
   The pictures grow with the window up to 46 columns each; narrower
   windows get the title alone, as before. DASH still fits a 160 × 50
   screen. 828 tests (31 new).


 4.3.0 — pick one device or network, and show only it.

   Pick one  (WIFI → BLUETOOTH, BT TRACKERS and LIVE AIR)
     Click a device or network in the live list and the big signal graph
     follows it: its row is marked ▶ and highlighted, and a line over the
     list says what is picked. Click it again and the whole view shows
     only it:
       BLUETOOTH    its row, a taller graph, and everything its broadcasts
                    say — name, best guess (and whether it was decoded or
                    guessed), maker, its address and whether that is fixed
                    or changes for privacy, manufacturer data, services,
                    transmit power — and its signal: now, lowest / average /
                    highest, rough distance and what that assumes,
                    broadcasts a second, first and last heard, how long it
                    has been near you, the tracker check and the networks
                    it was heard on
       BT TRACKERS  the same for one tracker, with the networks it has been
                    remembered on
       LIVE AIR     its row, a taller graph, the channel spectrum with just
                    that network, and its vendor, channel, security, lowest
                    / average / highest signal, and which networks share or
                    overlap its channel
     Click the row again (or SHOW ALL) to see everything; LET GO lets go.
     From the keyboard: Tab to the list, ↑ ↓ to pick (while showing only
     one, they step to the next one on its own), Enter shows only it, Esc
     steps back. A device picked in BLUETOOTH stays picked in BT TRACKERS
     (if it is a tracker), and SIGNAL watches the network picked in LIVE
     AIR when the GRAPH box is empty. Typing a name in the GRAPH box drops
     the pick — whichever you did last wins. While the pointer is over the
     list its rows hold still, so a row can't move away as you click;
     newcomers join at the bottom.

   Fixed: the graph's "nearest" device could be one last heard a minute ago
     BLUETOOTH graphed whichever device's last reading was strongest, even
     one that had since gone quiet. It now graphs the nearest device heard
     in the last 15 seconds. A device quiet for longer has its dBm and
     distance greyed — the reading is old — and is listed after the ones
     heard lately.

   Calmer lists
     Rows change places only when a signal has really moved (4 dB for
     Bluetooth, 3 dB for Wi-Fi), not on every flicker of a reading.

   Also
     Better guesses from device names: Cast and Google TV, webOS and Tizen
     sets; LED-strip controllers (ELK-BLEDOM, Triones, LEDBLE); 8BitDo and
     other gamepads. A live view that has stopped still redraws when you
     pick something or change the theme. 797 tests (31 new).


 4.2.0 — Bluetooth on the WIFI tab, and every button lined up.

   BLUETOOTH  (WIFI tab)
     Lists every Bluetooth device broadcasting nearby, live, refreshing
     every second until another button is pressed:
       NAME         the device's own name, when it broadcasts one
       DEVICE       a best guess at what it is — phone, earbuds, headphones,
                    watch, TV, speaker, beacon, keyboard, car, tracker… —
                    decoded from the broadcast where it says (AirPods models,
                    iPhones, AirTags and Find My, Windows PCs, iBeacon and
                    Eddystone beacons, Fast Pair, Tile, SmartTag, Chipolo,
                    Google Find Hub tags), else from its class, appearance,
                    name or maker
       VENDOR       the maker, from the manufacturer ID every broadcast
                    carries (the Bluetooth SIG list ships with netzilla), a
                    member service UUID, or the address's IEEE prefix
       DBM, HISTORY signal now and its last 14 readings as a coloured
                    sparkline; a big graph follows the nearest device, or
                    the one typed in the GRAPH box (name, address, its last
                    four digits, or a kind such as airtag)
       DISTANCE     rough, from signal strength: < 1 m … 20 m +
       FIRST / LAST when it was first and last heard
       FLAG         trackers, and whether one looks like it is following you
     Listening only — netzilla never pairs or connects. Works through
     BlueZ (Linux) or CoreBluetooth (macOS) via the bleak library, which is
     installed with netzilla. No root needed.

   BT TRACKERS  (WIFI tab)
     The tracker safety check: every AirTag, Find My accessory, Tile,
     SmartTag, Chipolo and Find Hub tag nearby, how long each has been near
     you, its signal and distance. A tracker is flagged when it has been
     near you for 10+ minutes without a break, or has been heard on two or
     more networks you were on (trackers are remembered in netzilla's local
     cache for seven days, with the network you were on — nothing else). An
     AirTag that says it is with its owner is never flagged, as with Find
     My itself. TOOL CHECK now checks Bluetooth too, and EXPORT CSV saves
     the devices as bluetooth.csv.

   Every button lined up
     Each tab's buttons sit on equal-width columns shared by all its rows,
     so they line up under each other and a full row runs edge to edge;
     the boxes above end flush with them. Drop-downs no longer carry a
     second border that made them two rows taller than the text boxes next
     to them. On a narrow terminal the columns drop — splitting a row
     evenly, 4 + 4 rather than 7 + 1 — until every label fits. SETTINGS,
     CONFIG and the password box use the same rows.

   Also
     SCAN explains "Network is down": the Wi-Fi interface is off, with the
     command that turns it on. 766 tests (74 new).


 4.1.0 — DASH and SETTINGS use the whole screen.

   DASH
     The NETZILLA logo is centred (text and pixel forms), with a one-line
     summary under it: version, tabs, terminal, graph mode and theme. Below
     the controls, three rows of panels side by side instead of one long
     column:
       THIS MACHINE   host, OS, kernel, uptime, load, memory, Python/Textual
       NETWORK        default interface, IPv4/IPv6, gateway, DNS servers
                      (the real upstream ones behind systemd-resolved),
                      Wi-Fi link, and your public IP / ISP / location
       TERMINAL       what netzilla detected and how graphs are drawn
       LOCAL TOOLING  ping, dig, traceroute, whois... two to a row
       API KEYS       where each key comes from and what it unlocks
       DATA & CACHE   config file, URLhaus snapshot, vendor table, cache
       NETWORK PULSE  live download and upload graphs for the default
                      interface, one sample a second (pixels in kitty and
                      Ghostty), spanning two columns
       API QUOTA      the five busiest counters; QUOTA ONLY lists them all
     Three columns at 140+ columns of terminal, two at ~95, one below that;
     at 160 x 50 the whole overview fits without scrolling. REFRESH re-reads
     everything and adds your public IP (one call to the free ip-api.com).
     The pulse only redraws while DASH is on screen.

   SETTINGS
     The buttons (SAVE, TEST KEYS, SHOW / HIDE, RESET, CLEAR CACHE) now sit
     at the top, so they never scroll away. Below them, two columns: the API
     keys on the left — name and source badge on one line, a one-row box,
     the note and sign-up link under it — and APPEARANCE, DISPLAY and
     BEHAVIOUR on the right, with one-row boxes and switches. A new KEYS AND
     STORAGE panel shows where every key comes from, the config file, the
     cache file and how many answers it holds, the exports folder, and the
     terminal and graph mode. TEST KEYS results appear beside the keys.
     Below ~118 columns the two columns stack.

   Under the hood
     render.PanelGrid lays any set of panels out in columns with equal
     heights; a panel can span two columns. New local/sysinfo.py reads
     memory, uptime, load and resolvers from /proc and /etc (with macOS
     fallbacks). 692 tests (18 new).


 4.0.0 — pixel graphs in kitty and Ghostty, free and open sources only,
         faster start-up, and every control checked.

   Pixel graphs, in the terminals that can draw them
     In kitty (0.28 or newer) and Ghostty (1.0 or newer) every graph is now
     a real image: an anti-aliased line with a soft phosphor glow, the area
     under it shaded, and a dashed grid at the labelled values — each grid
     line exactly the value on its label. Signal graphs are coloured reading
     by reading on the same excellent-green to very-weak-red scale as the
     numbers. Each image sits exactly where the text graph would —
     the dBm labels, the axis line and the channel numbers stay as text
     beside it — so switching modes moves nothing. Graphs live on:

       WIFI      LIVE AIR (signal lines, plus a new spectrum panel), CHANNELS
                 (a spectrum per band), SIGNAL, LINK HEALTH, TRAFFIC
       INT       LIVE RATES        receive and send, per interface
       FLOW      WATCH LIVE        connections over time
       CAPTURE   LIVE CAPTURE      packets per second
       SPEED     the speed test, drawn while it runs
       DASH      the NETZILLA banner, in lit gradient letters

     The spectrum draws each network as a hump across the channels it
     really occupies: 20, 40, 80 or 160 MHz wide, centred where the driver
     says (iw reports both), coloured by channel, with the SSID at its peak
     and a dot beside the network you are joined to.

     Every other terminal keeps text graphs, which got better too: the
     spectrum is drawn in braille dots (2 x 4 per character) with each
     network's name at its peak, and the block graphs are unchanged.

   netzilla knows which terminal it is in
     At start-up it asks the terminal its name and version (XTVERSION),
     whether it can show images, and its cell size in pixels. This takes
     about a third of a second, happens before the screen is taken over,
     and falls back to the environment ($TERM, $TERM_PROGRAM,
     KITTY_WINDOW_ID and friends) for terminals that don't answer. It
     recognises kitty, Ghostty, WezTerm, iTerm2, Konsole, GNOME Terminal and
     other VTE terminals, Windows Terminal, Alacritty, foot, xterm, Rio,
     VS Code, and tmux, Zellij, GNU screen and SSH around any of them.

     Pixels are used only where they are known to work. kitty older than
     0.28 is told to update. WezTerm and Konsole show kitty images, but not
     the Unicode-placeholder kind a full-screen app needs, so they keep text
     graphs. A terminal that answers the kitty feature query decides for
     itself, so future versions that add support get pixels automatically.

       netzilla --terminal        what it found, and why — try it first
       DASH > Terminal panel      the same, inside the app
       SETTINGS > DISPLAY         GRAPHICS: Auto (default), Pixel or Text
       netzilla --graphics text   force a mode for one run, without saving

     Inside tmux, netzilla asks tmux which terminal you are attached from
     (not the environment, which tmux keeps from whichever terminal started
     it), and the images pass through when tmux allows it (set -g
     allow-passthrough on, tmux 3.3+) with 24-bit colour on. If either is
     missing, the reason line says which and you get text graphs, never
     garbage. Over SSH, where $COLORTERM usually doesn't arrive, netzilla
     switches 24-bit colour on itself for a terminal it knows has it.

   Free and open sources only — nothing paid
     Everything that depended on a paid plan is gone:

       * Shodan's main API. Full host records and Shodan Search need a paid
         membership, so the Shodan key, FULL HOST RECORD and SHODAN SEARCH
         are removed. DISCOVERY now runs entirely on the free, keyless
         Shodan InternetDB and gains HOST PROFILE and CVE DETAIL (below).
       * The OutageDeck and EOSL.ai key boxes. Both services answer fully
         without a key; the keys bought nothing netzilla used.

     The keys that remain are free accounts: AbuseIPDB, VirusTotal (public
     API), GreyNoise Community and abuse.ch — plus NVD's, which is optional.
     An old config.toml that still has a Shodan, OutageDeck or EOSL key
     loads without complaint; those lines are ignored and dropped on the
     next save.

   New, from free sources
     DISCOVERY > HOST PROFILE   one address, four free sources at once: open
                                ports, hostnames and CVEs (InternetDB),
                                organisation, ISP and location (IP-API),
                                origin AS and announced prefix (RIPEstat),
                                registry netblock and abuse contact (RDAP)
     DISCOVERY > CVE DETAIL     every CVE InternetDB lists for the address,
                                most urgent first: in CISA KEV (being
                                exploited now), then by FIRST EPSS (the
                                chance of exploitation in the next 30 days),
                                then CVSS from NVD
     THREAT > CVE SEARCH        an EPSS column beside CVSS and KEV
     LIFECYCLE > SOFTWARE EOL   is that software release still supported?
                                "ubuntu 20.04", "panos 10.2", "ios-xe 17.9",
                                "fortios 7.2", "python 3.9" — close to 500
                                products from endoflife.date, with every
                                release's dates. Also as a one-shot:
                                    netzilla software "ubuntu 20.04"
     SPEED > RUN SPEED TEST     built in, nothing to install: download and
                                upload over four streams against Cloudflare's
                                free speed-test endpoints, idle latency,
                                jitter, and bufferbloat — latency while the
                                line is busy, graded A+ to F — all drawn live.
                                Data use is capped. OOKLA TEST still runs
                                speedtest-cli or Ookla's own CLI if present.
     DNS/WHOIS without dig      ALL RECORDS, REVERSE and `netzilla dns` fall
                                back to DNS-over-HTTPS (Cloudflare) when dig
                                isn't installed, and say so

   Faster
     Only the tab you open is built at start-up; every other tab is built
     the first time you visit it. netzilla is on screen in under half the
     time 3.5 took (0.8 s against 1.7 s on the test machine), and DASH's
     slow bookkeeping — the 56,000-URL snapshot, the 54,000-prefix vendor
     table, finding a speed-test backend — runs after the first frame
     instead of before it. A graph image takes 15–20 ms to draw; each frame
     is uploaded once and freed as the next one lands, so a LIVE AIR left
     open all day uses no more memory than one left open for a minute.

   Conveniences
     F4              copy this tab's results as plain text: to the desktop
                     clipboard (wl-copy, xclip, xsel, pbcopy), over SSH
                     through the terminal itself (OSC 52), or failing both
                     to a file in ~/netzilla-exports/ — it says which
     Ctrl+P          command palette: jump to any tab, pick a theme or a
                     graphics mode, copy, clear the cache
     Enter           in a box, runs the action that box is for — on CREDS,
                     Enter in the password box runs PWNED PASSWORD and in
                     the company box runs BREACH SEARCH
     Links           URLs, CVE IDs (to NVD) and AS numbers (to bgp.he.net)
                     are clickable in terminals that support links
     Notifications   a desktop notification when a run of 8 seconds or more
                     finishes while the terminal is in the background
                     (kitty, Ghostty, WezTerm, foot, iTerm2); a switch on
                     SETTINGS > DISPLAY turns it off
     CREDS           the password box hides what you type

   Every control checked
     A test now presses every button on every tab, one after another, and
     every key the app documents is pressed in both upper and lower case.
     Fixed along the way:

       * Q and T are shown in capitals but only worked in lower case. Both
         cases work now, and Ctrl+T changes the theme even while you are
         typing in a box (where a plain T is just a letter).
       * --tab, --theme and one-shot commands match in any case: --tab WIFI,
         --tab dns/whois, --tab life, netzilla IP 8.8.8.8. An unknown --tab
         is now an error that lists the tabs, instead of silently opening
         DASH.
       * A dropdown with nothing chosen was read as the text "Select.NULL".
       * LAN > SNMP POLL left the previous result on screen when net-snmp
         was missing.
       * MAC > UPDATE downloaded the registry even with --offline.
       * A null MX record (RFC 7505, "0 .") was shown as "0".
       * A URL typed with a capital scheme (HTTPS://…) was refused.
       * SUBNET > RANGE took "a - b" and "a to b" but not "a TO b" or an
         en dash.
       * WIFI found a network by BSSID only with colons; dashes, dots or no
         separators at all work now.
       * The AbuseIPDB verdict could say "no abuse reports" above a table of
         them (a 0% score because the address is whitelisted or the reports
         are old). It now says why the score is 0.
       * SSL Labs help suggested example.com, which SSL Labs refuses to
         scan; the examples are now hosts it will grade.
       * The WIFI note said SSIDs are case-sensitive while matching ignored
         case; the note now matches what it does.
       * WIFI > CHANNELS, pressed after a scan or a live view, added its
         panels under what was already on screen, so a second press showed
         everything twice. It now replaces the output like every other
         button — every button was pressed twice in a row to check that no
         other one does this.
       * One-shot output printed "None" for empty fields; it prints "—".
       * Piping one-shot output into head (netzilla dns example.com | head
         -3) could end in a Python traceback; it now just stops.

     674 tests (94 new). Pillow is a new dependency (installed for you);
     without it graphs simply stay text.


 3.5.0 — LIVE AIR keeps the pace you set, and HISTORY shows the readings.

   Fixed: REFRESH EVERY 1 s still updated LIVE AIR only every 3–4 s
     Every tick used to wait for a full radio scan — iw or NetworkManager
     tuning through every channel, which takes most adapters 2–4 seconds —
     so no setting could go faster than the scan. Now each tick reads the
     latest *finished* scan, which is instant (`iw dev <if> scan dump`, no
     root needed, and it sees NetworkManager's scans too), while new scans
     are requested in the background every REFRESH EVERY seconds. Your own
     network is read from the driver on every tick as before. So the table
     and graph update exactly as often as you ask; other networks' numbers
     change as each background scan completes, and the headline shows how
     old the newest scan result is. SIGNAL works the same way.

   HISTORY is the readings themselves
     LIVE AIR's HISTORY column lists each network's last ten readings in
     dBm, oldest to newest — "-26 -25 -26 -27 -25 -26 -28" — each number
     in its signal colour (excellent green · good blue · fair yellow ·
     weak orange · very weak red). A reading is added only when the radio
     has actually heard that network again, never twice for the same scan.
     The LIVE HISTORY GRAPHS setting on SETTINGS is gone with the graph.

   Also: a command that's stopped part-way (by pressing another button)
   is now killed rather than left running. 580 tests.


 3.4.0 — pick your own refresh rate, and colours that mean something.

   REFRESH EVERY (seconds), on every live view
     Each tab with a live view has a REFRESH EVERY box: WIFI (LIVE AIR,
     SIGNAL, LINK HEALTH, TRAFFIC, PACKETS), INT (LIVE RATES), FLOW (WATCH
     LIVE), CAPTURE (LIVE CAPTURE) and LAN (DUP-IP WATCH, and SYSLOG CATCH,
     which now shows messages live as they arrive). Blank keeps the view's
     default — 3 s for LIVE AIR and SIGNAL, 0.6 s for CAPTURE's repaint,
     1 s for the rest — or type any number of seconds, e.g. 1, 0.5 or 10.
     LIVE AIR and SIGNAL won't scan faster than once a second.

   Colours that mean something, on every tab
     Values are now coloured by what they are, the same way everywhere and
     in every theme, so a reading means the same thing wherever it shows up:

       signal & quality   excellent green · good blue · fair yellow ·
                          weak orange · very weak red — the dBm number, the
                          quality word, the SIGNAL bars and the live graphs
                          all use this one scale
       band               2.4 GHz light blue · 5 GHz light green ·
                          6 GHz lavender
       channel            every channel number its own colour; 1, 6 and 11
                          (and the common 5 GHz channels) as far apart as
                          possible
       SSID               pink; <hidden> yellow
       security           WPA3 green · WPA2 blue · WPA orange · WEP/Open red
       addresses          IPs teal and MACs lilac, even inside free text
       names              vendors sand · hostnames periwinkle · devices orchid
       states, verdicts   ESTAB/OK/up green · LISTEN/INFO blue · CHECK yellow ·
                          PROBLEM/down red; latency, error counts, abuse
                          scores, SSL grades and CVSS on the same good-to-bad
                          scale; protocols a colour each

     The theme still colours everything around the data — borders, titles,
     labels, buttons.

   LIVE AIR's HISTORY column
     Drawn in quadrants instead of sextants — two readings per character,
     two rows tall, in the same colour as that network's signal — and
     without block outlines (every other graph and bar keeps them). Each
     network's history is now fitted to its own range, never tighter than
     20 dB, so you see how it moves. Quadrants are ordinary block characters
     every terminal draws. A saved "sextant" setting becomes quadrants.

   RANGE reads "-62 / -48" (weakest / strongest) instead of "-62 … -48".
   585 tests.


 3.3.0 — roll the controls up, LIVE AIR every three seconds, and graphs you
         can read block by block.

   Roll the controls up (every tab)
     Every tab's control box now has a ▲ in its top-right corner. Press it
     — or F3 anywhere — and the description, fields and buttons roll up
     into one line, so the output gets the whole screen. ▼ (or F3 again)
     brings them back. Each tab remembers its own state, so LIVE AIR can
     stay rolled up while LAN keeps its buttons. DASH's banner, CONFIG's
     paste box and the SETTINGS forms roll up the same way.

   LIVE AIR and SIGNAL scan every 3 seconds
     A fresh scan is requested on every tick, and the cadence is measured
     start to start — an iw scan that takes two seconds is followed by a
     one-second wait, not three. NetworkManager still declines some rescans
     when asked often; netzilla then shows its latest list, and your own
     network is always read straight from the driver. With iw's scan
     capability set up (WIFI > TOOL CHECK), every network is fresh every
     three seconds.

   Outlined blocks
     A column of full blocks used to paint as one solid slab. Every full
     block in the graphs (LIVE AIR, SIGNAL, LINK HEALTH, TRAFFIC, PACKETS)
     and in the SIGNAL bars now has a thin outline in the theme's own
     background colour, so you can count the blocks in a bar and see
     exactly where each column steps.

   Sextant HISTORY graphs
     LIVE AIR's HISTORY column is drawn in sextants — Unicode characters
     that split a cell into 2 × 3 — two rows tall: two readings per
     character across, six levels up, so the column now holds three
     minutes of history instead of one and a half. GNOME Terminal, Xfce
     Terminal, Tilix, kitty, Ghostty and WezTerm draw sextants themselves.
     If yours shows boxes or question marks in that column, SETTINGS >
     LIVE HISTORY GRAPHS switches back to one row of block characters,
     which work everywhere.

   Fixed: with iw scanning, a hidden network's name was read from the line
   after its empty SSID, so it showed as "Supported rates: 6.0* 9…".
   Hidden networks now read <hidden>. 577 tests.


 3.2.0 — the WIFI tab becomes a Wi-Fi workbench, netscanner-style, and its
         graphs are live: press a button once and it keeps updating.

   Everything you reach for when "the Wi-Fi is bad" is now on one tab. Some
   of it also lives on LAN, INT, FLOW and CAPTURE; the WIFI tab reuses those
   tabs' own code rather than a second copy, pointed at the wireless
   interface and the subnet it is actually on.

     SCAN          as before: every AP, its maker, band, channel, dBm and
                   security. Now also feeds the live history below.
     LIVE AIR      new. Every network on the air with a live signal bar and a
                   scrolling history; a big graph of your own network (or the
                   one you type in NETWORK); networks that drop off the air
                   marked "gone"; the 2.4 GHz 1/6/11 load updating as it
                   changes. It never needs re-running — it keeps going until
                   you press another button.
     SIGNAL        now live and open-ended: one network's dBm drawn as a
                   full-height graph, newest on the right, for walking a site.
     LINK HEALTH   new, live. The AP you're joined to, channel and width,
                   signal, bitrate, retransmissions PER SECOND (not averaged
                   since you joined, so a burst of interference shows as it
                   happens), missed beacons, roaming between APs, IP, gateway
                   and DNS — with a plain-English "what this means" list.
     DEVICES       new. Who else is on this Wi-Fi: LAN > SWEEP's discovery and
                   identification, aimed at the Wi-Fi interface's own subnet
                   (even when the default route is a cable or a VPN).
     PORTS         new. LAN > IDENTIFY's identifying-port check, across every
                   device DEVICES found, with a "worth a second look" list
                   (Telnet on a smart plug, RDP left on, unencrypted MQTT…).
     TRAFFIC       new, live. Download and upload of the wireless interface
                   graphed second by second, plus this machine's connections
                   over the Wi-Fi — who, which service, which process.
     PACKETS       new, live. A capture on the wireless interface: packets per
                   second, protocol mix, the busiest hosts named by the DNS
                   lookups seen in the same capture, the lookups themselves,
                   and the newest packets. Uses CAPTURE's tshark and its
                   one-password-per-session unlock.
     EXPORT CSV    new. Everything gathered this session — networks, link
                   samples, throughput, devices, ports, DNS, packets — as CSV
                   files in ~/netzilla-exports/wifi-<date>-<time>/.

   The live views share one box: STOP AFTER (seconds). Leave it blank and a
   live view runs until you press another button; type 300 and it stops by
   itself after five minutes.

   Where the live numbers come from, and what needs root:
     * Your own network is read from the driver (iw dev <if> link) on every
       tick — no root. Other networks come from NetworkManager's scan list,
       which it lets netzilla refresh every ten seconds or so; if DEEP SCAN
       works on this machine (iw with CAP_NET_ADMIN), LIVE AIR uses iw for
       every network, fresh each tick.
     * LINK HEALTH, DEVICES, PORTS and TRAFFIC need no root at all.
     * PACKETS needs capture permission, exactly like CAPTURE — authenticate
       once on either tab and both are unlocked until netzilla exits.

   Only point DEVICES, PORTS and PACKETS at networks you run or are allowed
   to test. 496 tests.


 3.1.0 — every device netzilla finds now says what it is.

   Wherever netzilla turns up a client by IP or MAC — a LAN sweep, a
   duplicate-IP watch, a DHCP server, a syslog sender, a FLOW connection, a
   packet capture, a Wi-Fi access point, a MAC you paste in — it now adds
   who made it, what it is called, and what kind of device it looks like.
   All of it comes from the offline IEEE registry and from what the devices
   on your own LAN already say about themselves. No API, no key.

   LAN > SWEEP gains four columns:

     VENDOR     the MAC's maker, from the full IEEE registry, now bundled:
                all three block sizes (MA-L, MA-M, MA-S), ~54,000 entries,
                longest prefix first. The old table had 221 entries and
                missed most home devices. A randomised address reads
                "private MAC", because it has no maker to look up.
     HOSTNAME   reverse DNS, asked of your router first — it handed out the
                DHCP lease and knows the name each device gave
                ("Jordans-iPhone") — then mDNS, NetBIOS, or the UPnP
                friendly name, whichever the device answers
     DEVICE     netzilla's best guess: Router / gateway, iPhone, Windows PC,
                Fire TV, PlayStation, Printer, Roku, Phone / tablet /
                laptop (for a private MAC), Virtual machine, This computer …
     DETAILS    the friendly name, the model ("iPhone15,2", "Roku Ultra",
                "Chromecast HD"), the services it advertises (AirPlay,
                Google Cast, IPP print, HomeKit …), its NetBIOS workgroup,
                and the ping TTL (64 = Linux/Apple/Android, 128 = Windows)

     A summary sits above the table: how many devices, how many were named,
     how many use private MACs, the device mix and the top vendors. Leave the
     box BLANK and SWEEP covers this machine's own subnet — it finds it for
     you, and sees past a full-tunnel VPN to the real LAN.

   LAN > IDENTIFY (new)
     Type one IP. netzilla asks the device every way it knows, checks about
     two dozen well-known ports that give devices away (62078 iPhone, 8009
     Chromecast, 8060 Roku, 9100 printer, 3389 Windows RDP, 8123 Home
     Assistant …), reads an SSH banner or web page title if there is one,
     and shows its verdict WITH THE EVIDENCE — "name 'desktop-k3v9tq1' ·
     tcp/3389 open · MAC vendor Intel" — so it can be checked rather than
     taken on faith.

   And everywhere else a client turns up:
     LAN > DUP-IP WATCH   each MAC claiming the address, with vendor and type
     LAN > ROGUE DHCP     each answering server's MAC, vendor, name and type
     LAN > SYSLOG CATCH   a "devices that logged" table
     FLOW > TOP TALKERS   LAN peers get vendor, hostname and device type;
                          external hosts get their reverse-DNS name beside
                          the ASN and geo
     CAPTURE              "LAN devices in this capture", after CAPTURE and
                          FILTER HELD on a live capture
     WIFI > SCAN          an AP VENDOR column (a router's extra SSIDs show as
                          "virtual BSSID")
     INT                  a NIC VENDOR column
     MAC                  randomised addresses are explained and never sent
                          online; a MAC on your LAN right now is matched to
                          its IP and identified
     one-shot             netzilla sweep [CIDR] and netzilla identify IP,
                          both with --json

   How far the questions go — this matters with a VPN up:
     * The device probes (mDNS, NetBIOS, UPnP) go only to the addresses being
       identified. Addresses found some other way — a FLOW connection, a
       syslog sender — are probed only when they are on one of this
       machine's own LAN segments; VPN tunnels (GlobalProtect's gpd0,
       OpenVPN, WireGuard, Tailscale) and container bridges never count as
       the LAN. Across a VPN they get a reverse-DNS lookup and nothing else.
     * Reverse DNS for a home address is asked of your router, then of a
       resolver on this machine or your LAN — never of a VPN's corporate
       DNS, so your LAN's inventory does not leave it.
     * SWEEP of your own subnet sends one UPnP (SSDP) search to the local
       segment, plus a direct one to each device, which gets through ufw.
     * A sweep of more than 256 devices names the first 256 and says so;
       the rest keep their vendor column.
     * A saved pcap is never matched against today's LAN.
     Only sweep or identify networks you own or manage.

   Also fixed: typing a huge range into SWEEP (an IPv6 /64, an IPv4 /8) is
   refused at once instead of being built in memory first. The test suite
   now passes on current Textual (8.x) — some older test harnesses assigned
   to `self.log`, which newer Textual makes read-only. 445 tests.


 3.0.0 — two new tabs: WIFI (RF analysis) and FLOW (connections & traffic).
         A major version, because the toolkit now covers the airwaves and
         this host's own live traffic, not just what you point it at.

   WIFI — RF analysis, netzilla's take on inSSIDer.
     A passive read of the beacon frames every access point already
     broadcasts: what is nearby, on which channel and band, how it is
     secured, and how strong it is. The same information your phone's Wi-Fi
     list shows, in a form a network engineer can act on. Nothing here
     transmits, associates, deauthenticates or cracks anything — there is no
     attack surface in it, by design.

       SCAN              Every AP on the air, sorted by signal: SSID, BSSID,
                         band (2.4 / 5 / 6 GHz), channel, dBm, quality,
                         encryption and top rate. '*' marks the one you are on.
       CHANNELS          2.4 GHz congestion counting overlap, not just exact
                         channel — an AP on channel 4 still steps on channel 6
                         — and a recommendation of 1, 6 or 11 with the reason.
       SIGNAL OVER TIME  Rescans one network every couple of seconds and
                         graphs its dBm as a sparkline, so you can walk a site
                         and watch the signal rise and fall.
       DEEP SCAN (iw)    The exact-dBm path, using `iw scan` where nmcli only
                         estimates from link quality.
       TOOL CHECK        Which interfaces and scan tools are present, and the
                         one-time setup if iw needs it.

     Needs no API key. nmcli (already on Ubuntu/Mint) scans with no root at
     all; iw gives exact dBm and needs a capability — TOOL CHECK explains the
     one-line fix. Scan only networks you are allowed to; a passive scan is
     legal and unremarkable on your own premises.

   FLOW — connections & traffic, netzilla's take on Sniffnet.
     A monitor of THIS machine's own network activity: which sockets are
     open, who they talk to, on what service, and how hard the interfaces are
     working. It reads what ss and /proc already report — no key, no capture
     privilege — and resolves the external hosts to ASN and geolocation.

       CONNECTIONS   Every socket: protocol, local/remote, named service,
                     state and owning process (your own without root; all of
                     them with a sudo session — the same one CAPTURE uses).
       TOP TALKERS   The busiest remote hosts, with the external ones resolved
                     to ASN, org and city/country (ip-api, keyless).
       SERVICES      Traffic grouped by application service, named from the
                     well-known port on whichever end has one.
       WATCH LIVE    The established-connection table refreshing about once a
                     second, with a running peak, until you stop it.
       BANDWIDTH     Per-interface throughput right now, from two
                     /proc/net/dev samples two seconds apart.
       BLACKLIST     Flags any connection to an IP or CIDR in a file you
                     supply — one per line, # for comments.

     For packets on the wire rather than sockets on this host, that is still
     the CAPTURE tab; FLOW points you there for PCAP export.

   A note on scope: the design this grew from also proposed people-search
   tooling — enumerating a person's accounts across platforms from a
   username, checking an email or phone against sites, and pulling a target's
   breached credentials. That part is deliberately not here: it profiles a
   private individual, which is a different thing from diagnosing a network.
   The defensive equivalent already lives on the CREDS tab — check whether
   YOUR OWN password or address turns up in a breach — and that is unchanged.


 2.6.1 — dumpcap is found when it is there, and everything runs faster.

   "dumpcap is not installed" when dumpcap plainly is installed.
     netzilla looked for it with a PATH search, and a PATH search answers
     "can I run this", not "does this exist". The stock Debian/Ubuntu/Mint
     arrangement is /usr/bin/dumpcap owned root:wireshark mode 0750, so for
     anyone not in the wireshark group it carries no execute bit at all, PATH
     lookup skips straight past it, and netzilla reported it missing — which
     sent you off installing something you already had.

     It is now found by looking for the file, not for permission to run it,
     and TOOL CHECK reports what it actually found:

         DUMPCAP   /usr/bin/dumpcap  (-rwxr-x--- root:wireshark)
                   — you may NOT run it

     with a line underneath saying that is the wireshark-group arrangement
     and FIX PERMISSIONS sorts it out. getcap is found the same way, since it
     lives in /usr/sbin and that is not on every user's PATH either.

   Live capture: about 4.8x faster.
     Measured end to end on 30,000 packets: 39,000 packets/s before, 189,000
     after. Two causes, both in the path every single packet takes.

       * Output was read a line at a time with asyncio.wait_for(), which
         builds a task and schedules a timer on every call — so on a busy
         interface the event loop, not the capture, was the limit. It now
         reads in chunks and splits them locally: about 61,000 lines/s
         before, 1,100,000 after. A quiet link responds just as quickly as it
         did, because a chunked read still returns the moment bytes arrive.

       * The rolling buffer was trimmed to its ceiling on every packet, which
         means shuffling the whole list down by one each time. It now
         overshoots a little and is cut back in one go — same ceiling,
         roughly 17x less work.

   The capture-permission check no longer runs twice for nothing.
     It shells out to getcap and to sudo, and every capture button asked
     first, so pressing two in a row paid for it twice. The answer is now
     remembered for a few seconds. TOOL CHECK always asks afresh — saying
     what is true right now is its whole job — and the cache key carries the
     session and root state, so unlocking or locking can never be served a
     stale answer.

   Start-up is roughly twice as fast.
     httpx is about half of netzilla's import time and a session that only
     uses the local tabs never needs it, so it is now imported when the first
     network call happens instead of at start-up. That is the same pattern
     the OUI and URLhaus modules already used.

   None of this changes what netzilla does — 305 tests cover it, including
   new ones for the dumpcap case, for the chunked reader (every line
   delivered, including a last line with no newline on it), for the buffer
   ceiling, and for the permission cache being invalidated properly.


 2.6.0 — the CAPTURE tab: authenticate once, see the real time each packet
         arrived, stop a live capture without losing it.

   Authenticate once, not once per capture.
     When the only way netzilla could capture was pkexec, your desktop asked
     for the password before every single capture, and again after switching
     tabs. It now asks once, in a box inside netzilla, and opens a sudo
     session with what you type. Everything afterwards — every capture, every
     tab, the INT tab's iftop as well — goes through with no prompt at all,
     for as long as netzilla is running.

     The password is used once to open that session and then dropped: netzilla
     does not hold it, and it never appears on a command line. AUTHENTICATE
     still does this by hand, and pressing it again locks the session
     immediately. FIX PERMISSIONS remains the permanent answer that needs no
     password at all after your next login.

   A SYSTIME column.
     Every packet table now shows the wall-clock time the packet arrived, to
     the millisecond (14:03:22.918), so a capture can be lined up against a
     log entry or a ticket. tshark is run with `-t a` to get it. The old
     relative time is still there as the Δt column, measured from the first
     packet shown — which keeps it meaningful in the live view, where packets
     are listed newest first. The capture summary reports the first and last
     packet times as well.

   LIVE CAPTURE happens in the live view, and says so.
     The live capture now takes over the results area for as long as it runs,
     under a banner that says it is live, on what interface, with what filter,
     and how to stop it. Nothing else is drawn underneath it, so there is no
     second view to end up in.

   STOP LIVE — stop the capture, keep the packets.
     New button. It ends a running live capture and keeps every packet it
     collected in memory. Pressing any other button also stops the capture,
     and the packets are kept either way; STOP LIVE is the one that says so
     and shows you what you have.

   FILTER HELD — re-filter what you already captured.
     New button. Type a filter in the FILTER box and press FILTER HELD: it is
     applied to the packets already in memory, so it is instant and the
     traffic does not have to happen again. Filter as many times as you like,
     with a different filter each time. CAPTURE and READ PCAP leave their
     packets there too. They stay until the next capture replaces them — to
     keep a capture beyond this netzilla run, use SAVE PCAP.

     This filter is applied by netzilla rather than by tshark, so it covers
     what netzilla parsed: a bare word (protocol, address or any text in the
     line), ip.addr / ip.src / ip.dst, tcp.port / udp.port / srcport /
     dstport, frame.len, protocol, frame contains "text", the operators
     == != > < >= <=, CIDR networks such as 10.0.0.0/8, and terms joined with
     and / or / not, read left to right. Filters that need the decoded packet
     (tcp.analysis.flags, tls.handshake.type) cannot be applied after the
     fact — netzilla says so rather than quietly matching nothing, and you can
     put those in the FILTER box and capture again.

     One more thing it is stricter about: 'ip.addr != 10.0.0.1' here means
     neither end was that address, which is what people mean by it and
     famously not what Wireshark does with it.

   A pasted FILTER HELP line is explained rather than handed to tshark.
     Copying a whole row out of FILTER HELP — "PROTOCOL: UDP", "TCPDUMP: PORT
     80" — used to reach tshark as a filter and come back as
     '"UDP" was unexpected in this context'. netzilla now recognises the
     heading, says so, and shows you the part to use.

   Housekeeping: each release's test suite now checks that the version is at
   least that release rather than exactly it, so running pytest on 2.6 no
   longer reports failures from the 2.1-2.5 suites.


 2.5.1 — fixes a stylesheet error that stopped 2.5.0 starting at all.

   2.5.0 shipped with one invalid CSS value on the new password dialog
   (`align: horizontal center` — that property needs a horizontal AND a
   vertical keyword). Textual abandons the entire stylesheet at the first bad
   value, so netzilla exited with "CSS parsing failed" before drawing
   anything. Every other test passed, because none of them started the app.

   Two layers of checking now cover that:
     * tests/test_smoke.py starts the real application, opens all nineteen
       tabs, applies all seventeen themes, pushes the password dialog and
       checks the CAPTURE tab's buttons are laid out. It needs Textual
       installed, which is the situation that matters.
     * tests/test_css.py parses netzilla.tcss without Textual and checks
       every declaration for the wrong number of values or an unknown
       keyword, including a test that it does catch the 2.5.0 mistake.

 2.5.0 — unlock once, and a live capture that never stops on its own.

   CAPTURE > AUTHENTICATE
     Asks for your sudo password once, in a box inside netzilla, and every
     capture for the rest of that run goes through with no prompt at all.
     Press it again to lock the session immediately.

     What it does with the password matters: it opens a sudo session with it
     and then drops it. netzilla does not hold your password in memory —
     sudo's own timestamp does the remembering, and netzilla refreshes that
     timestamp every minute so it cannot expire while the app is running. The
     password goes to sudo on stdin, so it never appears in a command line
     where other users could read it out of the process table. If sudo on
     this machine is configured not to cache (timestamp_timeout=0), netzilla
     says so rather than pretending it worked.

     The session ends when netzilla exits. sudo forgets it on its own within
     15 minutes, or immediately with 'sudo -k'.

   CAPTURE > LIVE CAPTURE
     tshark with no packet count and no time limit: packets appear as they
     arrive, newest first, with a running total and rate. Press any other
     button on the tab to stop it. The PACKETS box is ignored here — that is
     what CAPTURE is for.

     The last 300 packets are kept for display so a long run cannot grow
     without bound, a quiet link still ticks over rather than looking frozen,
     and netzilla stops a live capture by itself after 15 minutes so one left
     running behind another tab cannot hold an interface open all afternoon.
     Stopping always kills tshark, including when the stop comes from
     pressing another button mid-capture.

   Also: panes with more than eight buttons now deal them across two rows
   rather than running off the right-hand edge — CAPTURE has eleven.

 2.4.0 — eleven more themes, and CAPTURE that can unblock itself.

   Eleven colour palettes added, from supplied colour strips and retro
   posters. In each one the darkest colour of the palette is the background,
   as asked; the most saturated becomes the dominant colour, and the lightest
   becomes body text — washed toward white first when it was a saturated
   yellow or cyan, so paragraphs do not glow. Every role was contrast-checked
   against both the background and the panel colour:

     sunset-mesa    orange, gold and teal        arcade-pop    red, blue, gold
     desert-sage    coral, cream and sage        neon-mint     pink and mint
     miami-night    hot pink on deep navy        vapor-pop     pink/cyan/violet
     crt-neon       pink, mint and yellow        cyber-coral   coral and teal
     route-66       brick red and roadside tan   space-1975    rocket orange
     disco-70s      mint, cream and burnt orange

   That makes seventeen themes. The six that were already there are
   untouched, including their exact colour values.

   CAPTURE permission is no longer a dead end:
     * New FIX PERMISSIONS button. It runs the one-time setup for you —
       creating the wireshark group, adding you to it, and giving dumpcap the
       cap_net_raw capability — with your desktop asking for the password,
       since netzilla cannot prompt for one on a terminal it is drawing on.
       The exact commands are shown before they run.
     * pkexec is now one of the routes netzilla will capture through, so on a
       desktop session capturing works immediately via a password dialog,
       before any setup at all.
     * "dumpcap capabilities: none" used to be printed even when getcap was
       simply not installed. Unknown and none are now told apart.
     * TOOL CHECK also reports whether you can actually execute dumpcap,
       which is the real symptom of having answered "no" during the tshark
       install, and whether pkexec is available.
     * A capture saved while elevated is handed back to you rather than being
       left owned by root.

 2.3.0 — the CAPTURE tab, and a sixth theme.

   New CAPTURE tab (tshark and tcpdump, both local, no key):
     * CAPTURE         tshark bounded by a packet count and a 30s window, so
                       it always stops. Its packets are parsed into a real
                       table with a capture summary, a protocol mix and the
                       packet list — not a wall of text.
     * TCPDUMP CAPTURE the same idea with tcpdump, shown raw, because raw
                       tcpdump output is what goes into a ticket.
     * PROTOCOL STATS  tshark -z io,phs — what share each protocol had.
     * TOP TALKERS     tshark -z conv,ip — which address pairs moved the most.
     * SAVE PCAP       writes a .pcapng the full Wireshark can open later, and
                       fills the path back into the PCAP FILE box.
     * READ PCAP       reads any .pcap/.pcapng back, filter and all.
     * FILTER HELP     the filters worth knowing, with the tshark display
                       filter and the tcpdump BPF form of each side by side —
                       by protocol, by IP, by port, by content, and combining
                       rules with and/or/not — plus ready-made examples.
     * TOOL CHECK      whether tshark/tcpdump/dumpcap are installed and
                       whether this session may capture at all: root, the
                       wireshark group with cap_net_raw on dumpcap, or
                       passwordless sudo. It names which one it is using.

   Capture permission is worked out rather than assumed. The recommended
   setup needs no sudo at any point:

       sudo apt install -y tshark tcpdump     (answer YES to the
                                               "non-superusers" question)
       sudo usermod -aG wireshark $USER
       then log out and back in

   New theme:
     * sapphire-ice — the kwkpass colour scheme carried over so the two tools
       match: Sapphire Blue #0F52BA for titles, Blue #0000FF for labels and
       borders, Ice Blue #D8EBF2 for values, on solid black. All five original
       themes are untouched; press T to cycle through all six.

 2.2.1 — INT tab fixes from first real use.

   * The interface dropdown showed nothing after you picked something. The
     widget had a fixed height and its own border, which left the inner part
     that draws the selected value exactly one row too few to draw in. Both
     dropdowns now size themselves and are styled on the inside.
   * Seconds and the vnstat report box held placeholders, not values, so they
     looked set but were empty and every action fell back to its own default
     (LIVE RATES sampled 5s while the box showed 10). They now hold real
     values of 10 and "summary".
   * LIVE RATES is genuinely live. It rewrites its panels every second for as
     long as you ask (2-300s) instead of taking one sample and stopping, keeps
     a running peak beside the headline, and ends with the average and peak
     across the whole window. Press any other button to stop it early.
   * IFTOP SNAPSHOT no longer just says "needs root". netzilla checks whether
     it is running as root, whether iftop carries cap_net_raw, and whether
     sudo will run without a password — then uses whichever works. If none do,
     it says exactly what it checked and leads with the one-time setcap fix.
   * BMON SNAPSHOT now means something. bmon prints bare cumulative counters
     with no header, so netzilla matches those numbers against the kernel's
     own /proc/net/dev counters to identify each column, then reports totals
     since boot, bytes moved during the capture, and the Mbit/s that implies.
     If the columns cannot be matched it says so instead of guessing.

 2.2.0 — the INT tab: pick an interface, watch what is moving across it.

   * New INT tab, sitting next to LAN. The interface picker is a dropdown
     filled from 'ip -o link show' (not ifconfig — net-tools is no longer
     installed by default on Ubuntu or Mint), showing each interface's kind,
     state, MTU, MAC, addresses, and which one carries the default route.
   * LIVE RATES — netzilla's own live throughput view: /proc/net/dev sampled
     twice, giving Mbit/s in and out, packets/s, errors and drops for every
     interface at once, with a bar so the busy one is obvious. Needs nothing
     installed and no root. This is the stand-in for nload, which is a
     full-screen program and cannot be drawn inside netzilla's own interface.
   * IFTOP SNAPSHOT — runs 'iftop -t -s <seconds>', iftop's own text mode, to
     get the per-connection breakdown of who filled the link. Needs root, and
     says exactly how to arrange that if it does not have it.
   * VNSTAT REPORT — summary, daily, monthly, hourly or top-days history from
     vnstat's database, read through its JSON output and rendered as netzilla
     tables. Understands both the vnstat 2.x and 1.x JSON dialects (1.x
     reports KiB where 2.x reports bytes). Explains how to start the service
     when there is no history yet.
   * BMON SNAPSHOT — captures a window of bmon's scriptable output module and
     shows the counters plus the raw capture.
   * TOOL CHECK — which of iftop/vnstat/bmon/nload are present, what each one
     adds, whether this session is root, and the apt line for anything absent.
   * Shared: panes can now have dropdown fields, not just text boxes.

 2.1.0 — built-in instructions, and fixes from real use.

   * Every tool now explains itself. Hover over any button (or Tab to it) and
     a HOW TO USE card appears: what to type and where, when you'd reach for
     the tool, and public targets that are safe to try it on (badssl.com
     hosts for SSL/TLS, scanme.nmap.org for port checks, the EICAR test hash
     for FILE HASH, dnssec-failed.org for RESOLVER CHECK, and so on). Click
     the button and the card stays up while the tool runs, then gives way to
     the results. If your input is rejected, the card stays so you can see
     what the input should look like.
   * LAN > SYSLOG CATCH works without sudo. The port used to be hard-wired
     to 514, so the "use a high port" advice could not be followed. Now:
     without root it falls back to udp/1514 by itself; type any port in the
     target field to choose one; the status line counts messages live and
     shows a ready-to-paste 'logger' self-test command; listen time can be
     up to 300 s.
   * LAN: the third field is now labelled "Seconds" (the old label was cut
     off).
   * CREDS > BREACH SEARCH matches more forgivingly: URLs, www./mail.
     subdomains and email addresses are reduced to the domain, so
     'https://www.linkedin.com/login', 'mail.adobe.com' and 'you@yahoo.com'
     all find their breach. A "no match" result explains that HIBP lists
     about 1,000 verified incidents, not every site ever hacked (The Pirate
     Bay, for example, is not in it).
   * SPEED: the saturation warning now lives in the instruction card, so the
     card stays up for the whole test.

 2.0.0 — a major release. The title bar now reads "netzilla" with the version
 number, and three new tabs plus a wave of new tools turn netzilla from an
 API-aggregator into a full LAN-side toolkit. Nothing existing was removed.

 New LAN tab (all local, no API, no key):
   * SWEEP        ping every host in a CIDR, enriched with MACs from the ARP
                  cache — the internal-network view DISCOVERY never had.
   * ROGUE DHCP   broadcast a DISCOVER and flag if more than one server answers
                  (needs root: sudo netzilla).
   * DUP-IP WATCH watch who claims an IP and flag two MACs answering for one
                  address — the cause of intermittent, hard-to-pin outages.
   * SNMP POLL    two counter samples a few seconds apart give live per-interface
                  Mbps and a rising-error count (needs: sudo apt install snmp).
   * SYSLOG CATCH stand up a syslog listener and collect device logs
                  (udp/514 as root; udp/1514 automatically otherwise).

 New CONFIG tab:
   * Paste a 'show interfaces', 'show ip route' or running-config and netzilla
     flags interfaces with error counters, err-disabled/protocol-down ports,
     and route counts by protocol. Pure local text parsing — nothing is sent.

 New CREDS tab (Have I Been Pwned, keyless):
   * PWNED PASSWORD  k-anonymity breach check — only the first 5 characters of
     the password's SHA-1 hash ever leave the machine.
   * BREACH SEARCH   look up known breaches by company or domain.

 DIAG gained:
   * TRACEROUTE +ASN — each hop now shows its origin AS and registry/country
     (via Team Cymru over DNS), and the path is remembered so reruns flag
     reroutes.
   * PATH MTU — binary-searches the largest DF packet that survives the path;
     finds tunnel/VPN MTU clamping.
   * NTP DRIFT — checks this machine's clock against an NTP server (clock skew
     silently breaks TLS, Kerberos and TOTP).
   * PORT CHECK now takes a comma-separated list, e.g. 443,80,22.

 DNS/WHOIS gained:
   * RDAP — structured, modern WHOIS via rdap.org (auto-routes to the right
     registry), including the abuse contact.
   * RESOLVER CHECK — queries Cloudflare, Google and Quad9 over DoH at once and
     flags disagreement (hijack / split-horizon / filtering).

 SSL/TLS gained:
   * CERT SEARCH (CT) — Certificate Transparency search via crt.sh: subdomain
     discovery and spotting certificates you did not order.

 BGP/ASN gained:
   * ORIGIN SNAPSHOT / HISTORY — record a prefix's origin AS and diff it over
     time; a complete origin-AS change is flagged as a possible hijack.

 THREAT gained:
   * CVE search now cross-references CISA's Known Exploited Vulnerabilities
     catalog — a "● EXPLOITED" marker means patch it first, whatever the CVSS.
   * IOC LOOKUP — one button checks abuse.ch ThreatFox (all IOCs), Feodo
     Tracker (IPs) and MalwareBazaar (hashes), using your existing Auth-Key.
   * FIRST-SEEN TIMELINE — combines RDAP registration, earliest certificate
     (crt.sh) and first threat-feed sighting; fresh + fresh + flagged is a fast
     phishing tell.


 1.1.2 — STATUS, BGP/ASN and typosquat fixes
   * STATUS: every provider showed UNKNOWN or "Not found", and ACTIVE
     INCIDENTS crashed with "TypeError: unhashable type: 'slice'". netzilla
     now reads OutageDeck's real response format (checked against its
     published API documentation), so statuses, headlines and incidents
     display correctly.
   * STATUS: failed lookups no longer count as "operational" in the verdict.
     A degraded provider now lists what it is reporting (incident titles or
     affected services).
   * STATUS: an unknown slug now suggests real ones ("did you mean
     google-cloud, google-workspace?"). Common names work too: google or gcp
     means google-cloud. New FIND PROVIDER button: type part of a vendor
     name and it lists the exact slugs to use.
   * STATUS: default stack is now aws, azure, cloudflare, github,
     google-cloud. OutageDeck does not track Microsoft 365 as a provider;
     use 'azure'.
   * BGP/ASN: RIPEstat is often slow under load. netzilla now waits up to
     20s and retries once. If RIPEstat still doesn't answer, it falls back
     to Team Cymru's IP-to-ASN service over plain DNS (prefix, origin AS,
     holder, country, registry) and says so on screen.
   * DNS/WHOIS: DomainsDB started requiring an API key ("API key
     required") and offers no public way to get one, so TYPOSQUAT SEARCH no
     longer uses it. netzilla now generates ~200 realistic lookalikes of the
     domain itself (dropped/doubled/swapped letters, neighbouring keys,
     look-alike characters such as 1 for l, hyphens, bit flips, other TLDs,
     add-ons like -login) and checks which ones actually exist in DNS.
     No key, no rate limit. It also works with 'www.' and full URLs, and
     it warns you if your ISP's DNS answers for names that don't exist.

 1.1.1 — SPEED tab fix
   * The SPEED tab used to say "speedtest-cli is not installed" for ANY
     problem loading it. It now shows the real error, the Python interpreter
     netzilla is running under, and the exact commands to check the install.
   * Picks up a package injected while netzilla is already running.
   * Three ways to measure, tried in order: the speedtest-cli Python module,
     the speedtest-cli command, then Ookla's official 'speedtest' CLI.
     If Ookla blocks speedtest-cli (HTTP Error 403), it falls through to the
     official CLI automatically when that is installed.
   * DASH shows which speed-test method is active.

 1.1.0

 Default API keys, still fully editable
   * The four required keys come pre-filled, so every tab works on first
     launch with nothing to configure.
   * SETTINGS shows where each key comes from: BUNDLED DEFAULT, CUSTOM KEY
     (yours) or ENVIRONMENT VARIABLE.
   * Type a new key and SAVE to override one. Clear a field and SAVE to go back
     to its default. RESET TO DEFAULTS clears every override at once.
   * TEST KEYS makes one live call per service using what is typed in the
     boxes right now, so you can check a new key before saving it. Cached
     answers are skipped, so an old success can't hide a bad new key.

 Changes based on each vendor's API documentation
   * GreyNoise — rebuilt around the fields the API actually returns (noise,
     riot, classification, name, last_seen). 1.0 misread them. New verdicts:
     MALICIOUS / BENIGN / UNCLASSIFIED SCANNER, KNOWN BUSINESS SERVICE (RIOT),
     NOT OBSERVED. Quota tracking now uses the real limit of 50 lookups per
     week (shared with the GreyNoise website). IPv6 and private addresses are
     answered locally instead of spending a lookup on a guaranteed error. If
     the key is rejected, netzilla retries anonymously (10/day) and says so.
   * AbuseIPDB — the IP report now names the abuse categories (Brute-Force,
     SSH, Port Scan…) and shows the most recent reporter comments. New BLOCK
     CHECK /24 action lists every reported address in the surrounding /24.
     The dashboard shows AbuseIPDB's own count of calls left today.
   * VirusTotal — new FILE HASH lookup (MD5 / SHA-1 / SHA-256; nothing is ever
     uploaded), new SUBMIT URL TO VT for URLs it has never seen, new VT
     REPUTATION on the DNS/WHOIS tab, and every VT panel lists which engines
     flagged the target and what they called it.
   * URLhaus — an offline snapshot of the URLhaus database (56,193 malware
     URLs, captured 2026-09-19) now ships with netzilla. If the live API is
     unreachable, or you run with --offline, lookups answer from the snapshot
     and say how old it is. Popular shared sites (GitHub, Google Drive,
     Discord's file CDN…) get a warning instead of a false "bad host" verdict.
   * Error messages now include the vendor's own explanation
     ("Daily rate limit of 1000 requests exceeded…") and, for rate limits,
     how long to wait.

 Also
   * New one-shot commands: netzilla urlhaus, netzilla hash, netzilla block.
   * New flags: --import-urlhaus, --update-urlhaus, --no-default-keys.
   * Fixed: quota history was trimmed after 48 hours, which broke any weekly
     limit.
   * Tests: 92 checks. Client tests replay the exact responses shown in each
     vendor's documentation.


-------------------------------------------------------------------------------
 2. WHAT YOU GET
-------------------------------------------------------------------------------

Twenty-one tabs, switched with the mouse or the left/right arrow keys:

  DASH         This machine, the network (public IP, DNS, Wi-Fi), the
               terminal, local tools, key sources, a live network pulse
               graph and API quota — side by side, on one screen, under the
               NETZILLA title with a picture either side
  IP LOOKUP    One address, five independent opinions in parallel; /24 check
  SUBNET       IPv4/IPv6 CIDR maths, splitting, host fitting, range -> CIDR
  DNS/WHOIS    dig/whois, RDAP, DoH resolver check, typosquat, VT reputation;
               falls back to DNS-over-HTTPS when dig is missing
  SSL/TLS      Local cert check, SSL Labs grade, crt.sh Certificate Transparency
  BGP/ASN      Prefix origin, AS overview, peers, RPKI, origin snapshot/history
  THREAT       CVE with CVSS, EPSS and KEV; URLhaus, ThreatFox/MalwareBazaar/
               Feodo, first-seen timeline
  DISCOVERY    What the internet sees on an address: InternetDB exposure scan,
               HOST PROFILE (four free sources), CVE DETAIL ranked by KEV,
               EPSS and CVSS
  LAN          Sweep that names every device (vendor, hostname, type), per-
               device IDENTIFY with evidence, rogue DHCP, dup-IP, SNMP, syslog
  INT          Per-interface live rates, iftop/vnstat/bmon reports, NIC vendor
  WIFI         Wi-Fi workbench: live signal graphs for every network (a scan
               every 3 s or as set, dBm history), link
               health (signal, bitrate, retries/sec, roaming), devices on
               this Wi-Fi and their ports, live traffic and packets on the
               wireless interface, 1/6/11 channel pick, CSV export — and
               BLUETOOTH (every device broadcasting nearby: name, maker,
               best guess, signal history, rough distance) and BT TRACKERS
               (a tracker that keeps showing up near you); click a network
               or device in a live list to graph it, again to show only it
  CAPTURE      Live + bounded tshark/tcpdump capture with systime, stop-and-
               keep, re-filtering held packets, pcap save/read, filter help
  FLOW         This host's live connections: talkers with ASN/geo/rDNS (LAN
               peers identified), services,
               bandwidth, blacklist flagging (Sniffnet-style); no key needed
  MAC          Offline IEEE registry (~54,000 prefixes), private-MAC check,
               "on your LAN now", keyless online fallback
  LIFECYCLE    Hardware end-of-sale / end-of-service-life dates, source-linked;
               software release support (OS, firmware, runtimes) from
               endoflife.date
  STATUS       Live status for 180 cloud and SaaS vendors ("is it us or them")
  SPEED        Built-in speed test: download, upload, latency, jitter and
               bufferbloat, drawn live; optional Ookla test
  DIAG         ping, traceroute+ASN, mtr, TCP port list, path MTU, NTP drift
  CONFIG       Paste-in show-output / running-config summarizer (local)
  CREDS        Pwned-password (k-anonymity) and breach-directory lookup
  SETTINGS     Every API key and shared secret, theme, graphics mode,
               notifications, cache controls

Every data source is free or open: no tab needs a paid plan, and most need
no key at all (section 6 lists them).

Graphs are drawn in pixels in kitty and Ghostty, and with text everywhere
else — netzilla works out which terminal it is in by itself. Run
`netzilla --terminal` to see what it decided.

Screenshots of most of these, in pixel and text form, are in docs/showcase/
inside this folder (open live-air.gif to see LIVE AIR moving).

Some LAN actions send raw/broadcast packets or bind privileged ports, so on
Linux they need root — run them with `sudo netzilla`. Each says so plainly if
you don't. On INT, only IFTOP SNAPSHOT needs root; LIVE RATES works as any
user with nothing installed. netzilla runs on Linux, macOS and Windows;
section 3d says what differs on each.

Seventeen retro colour themes, all dark, each with a different dominant colour:

  phosphor-green    classic green CRT            (default)
  amber-phosphor    vintage amber monitor
  ice-cyan          cold blue terminal
  vhs-magenta       synthwave tape deck
  ember-rust        burnt orange dashboard
  sapphire-ice      kwkpass sapphire/ice blue on black
  sunset-mesa       orange, gold and teal on deep plum
  desert-sage       coral, cream and sage on near-black
  miami-night       hot pink and cyan on deep navy
  arcade-pop        primary red, blue and gold on black
  neon-mint         pink and mint on black
  vapor-pop         pink, cyan and violet on black
  crt-neon          pink, mint and yellow on charcoal
  cyber-coral       coral and teal on slate
  route-66          brick red and roadside tan
  space-1975        rocket orange on deep teal
  disco-70s         mint, cream and burnt orange

In every theme the darkest colour of its palette is the background, and the
pixel graphs take their colours from the theme too. Press T to cycle through
them (Ctrl+T while typing in a box), pick one on SETTINGS, or press Ctrl+P
and type "theme".


-------------------------------------------------------------------------------
 3. INSTALLING  (step by step)
-------------------------------------------------------------------------------

Three tracks below: Linux (Ubuntu / Linux Mint), macOS and Windows. All end
up running the same `netzilla` command; only how you get Python, pipx and the
local tools installed differs. 3d lists what works differently on each, and
3e (upgrading, removing, a terminal for the pixel graphs) is for all three.


-------------------------------- 3a. LINUX (Ubuntu / Linux Mint) --------------------------------

These steps work on Ubuntu 22.04/24.04 and Mint 21.x/22.x (Mint tracks
Ubuntu's packages, so the same apt commands apply). Commands are typed into
a terminal (Ctrl+Alt+T opens one on both).


 STEP 1 — Check your Python version
 ----------------------------------
     python3 --version

 You need 3.10 or newer. Mint 21.x ships 3.10, Mint 22.x ships 3.12. Both are
 fine. If it prints something older:

     sudo apt update
     sudo apt install python3 python3-venv python3-pip


 STEP 2 — Install the local command-line tools netzilla wraps
 ------------------------------------------------------------
     sudo apt update
     sudo apt install dnsutils whois openssl iputils-ping traceroute mtr-tiny

 For WIFI → BLUETOOTH and BT TRACKERS (Mint and Ubuntu desktops already
 have these; netzilla installs the bleak library itself):

     sudo apt install bluez rfkill
     sudo systemctl enable --now bluetooth

 Optional, for the INT tab's iftop/vnstat/bmon actions (LIVE RATES and the
 interface list work without them):

     sudo apt install -y iftop vnstat bmon
     sudo systemctl enable --now vnstat        # vnstat needs its collector

 Optional, for the CAPTURE tab:

     sudo apt install -y tshark tcpdump

 The tshark installer asks "Should non-superusers be able to capture
 packets?" — answer YES, then add yourself to the group it creates and log
 out and back in, and capturing never needs sudo:

     sudo usermod -aG wireshark $USER

 Already said no? Undo it with:  sudo dpkg-reconfigure wireshark-common

 netzilla degrades gracefully if any are missing — the tab tells you exactly
 which apt package to install. DIAG -> TOOL CHECK shows what is present.


 STEP 3 — Install pipx
 ---------------------
     sudo apt install pipx
     pipx ensurepath

 Close and reopen your terminal so the PATH change takes effect.

 If apt cannot find pipx (older Mint releases):

     python3 -m pip install --user pipx
     python3 -m pipx ensurepath


 STEP 4 — Unpack and install netzilla
 ------------------------------------
     cd ~/Downloads
     tar -xzf netzilla-4.6.0.tar.gz
     cd netzilla
     pipx install .

 The archive contains a netzilla/ directory, so always `cd` into the folder
 the tar created before installing. Extracting with `-C somewhere` and then
 running `pipx install .` in `somewhere` fails with "Directory is not
 installable" — pyproject.toml is one level further down.

 pipx fetches everything netzilla needs, Pillow (for the pixel graphs)
 included. The speed test is built in; only SPEED's optional OOKLA TEST
 needs an extra package:

     pipx inject netzilla speedtest-cli         # optional


 STEP 5 — Run it
 ---------------
     netzilla --terminal        # optional: what netzilla sees in this terminal
     netzilla

 The app opens on DASH. The API KEYS panel shows every key as "not set" —
 expected, since netzilla ships with no keys; see section 4 — and DATA &
 CACHE should show "URLhaus snapshot 56,193 URLs".
 The TERMINAL panel names your terminal and says whether graphs will be
 pixels or text. If the command is not found, open a new terminal or run
 ~/.local/bin/netzilla.


 STEP 6 — Confirm the keys work
 ------------------------------
 Press F2 (SETTINGS) and press TEST KEYS. Each service should report WORKING.
 This makes one real call per service; the GreyNoise one counts as 1 of its
 50 weekly lookups. (netzilla ships with no keys, so TEST KEYS has nothing
 to check until you add your own on SETTINGS; see section 4.)


-------------------------------- 3b. macOS --------------------------------

These steps work on macOS 13 (Ventura) through the current release, on both
Apple Silicon and Intel Macs. Commands go in Terminal.app or iTerm2.


 STEP 1 — Install Homebrew (if you do not already have it)
 -----------------------------------------------------------
     /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

 Follow the "Next steps" it prints at the end (it usually asks you to add
 Homebrew to your PATH with a couple of `echo` lines into your shell profile).
 If Homebrew is already installed, skip to Step 2.


 STEP 2 — Install Python, pipx, and the one extra tool netzilla wraps
 --------------------------------------------------------------------
     brew install python pipx mtr
     pipx ensurepath

 Close and reopen your terminal so the PATH change takes effect.

 macOS already ships dig, whois, traceroute, ping, openssl, tcpdump and the
 Net-SNMP tools (for SNMP POLL), so only mtr (for MTR REPORT) needs
 installing. DIAG -> TOOL CHECK confirms what is present after install.

 Optional, for the INT tab's iftop/vnstat/bmon actions (LIVE RATES and the
 interface list work without them):

     brew install iftop vnstat bmon
     sudo brew services start vnstat         # vnstat needs its collector

 Optional, for the CAPTURE tab and WIFI -> PACKETS: Wireshark. It brings
 ChmodBPF, which lets your account capture packets (and run iftop) with no
 sudo; log out and back in after installing it:

     brew install --cask wireshark-app

 Until then, CAPTURE -> AUTHENTICATE opens a sudo session for the run.


 STEP 3 — Unpack and install netzilla
 -------------------------------------
     cd ~/Downloads
     tar -xzf netzilla-4.6.0.tar.gz
     cd netzilla
     pipx install .

 Optional, for SPEED's OOKLA TEST only (RUN SPEED TEST is built in):

     pipx inject netzilla speedtest-cli


 STEP 4 — Run it
 -----------------
     netzilla

 If Terminal.app is narrower than 100 columns the layout looks cramped —
 widen the window or switch to a smaller font size. Terminal.app and iTerm2
 draw the graphs with text; for the pixel graphs run netzilla in kitty or
 Ghostty (both free):

     brew install --cask kitty        # or:  brew install --cask ghostty


 STEP 5 — Add your own API keys
 ---------------------------------
 netzilla ships with no API keys (see section 4). Press F2 (SETTINGS), type
 each key into its box, SAVE SETTINGS, then TEST KEYS.
 Every tab works keyless except the reputation panels on IP LOOKUP, THREAT
 and IOC LOOKUP, which read "not configured" until you add a key.

 macOS-specific notes:
   * The first time WIFI -> BLUETOOTH scans, macOS asks whether your
     terminal app may use Bluetooth: allow it. Refused by mistake? System
     Settings -> Privacy & Security -> Bluetooth, then quit and reopen the
     terminal.
   * If WIFI -> SCAN shows network names as <redacted>, allow your terminal
     app under System Settings -> Privacy & Security -> Location Services.
   * MTR REPORT needs root on macOS: it runs through the sudo session
     CAPTURE -> AUTHENTICATE opens, or start netzilla with  sudo netzilla
   * LAN -> ROGUE DHCP binds a privileged port, so it needs  sudo netzilla
     too. SYSLOG CATCH does not: macOS lets any user listen on port 514.
   * If macOS's firewall asks whether Python may accept incoming
     connections when you run SYSLOG CATCH or LAN -> SWEEP, click Allow —
     that is the macOS Application Firewall asking on behalf of the Python
     interpreter netzilla runs in, not a sign that anything is wrong.


-------------------------------- 3c. WINDOWS --------------------------------

These steps work on Windows 10 (version 1809 or newer) and Windows 11.
Commands go in Windows Terminal, which opens PowerShell: on Windows 11,
right-click Start and choose Terminal.


 STEP 1 — Install Python
 -----------------------
     winget install Python.Python.3.13

 Any Python from 3.10 on works; if `py --version` already prints one, skip
 this step. Without winget, the installer from python.org does the same.
 Close and reopen Windows Terminal afterwards.


 STEP 2 — Install pipx
 ---------------------
     py -m pip install --user pipx
     py -m pipx ensurepath

 Close and reopen Windows Terminal so the PATH change takes effect. If
 `pipx` is still not found, type `py -m pipx` wherever these steps say
 `pipx`.


 STEP 3 — Unpack and install netzilla
 ------------------------------------
     cd ~/Downloads
     tar -xzf netzilla-4.6.0.tar.gz
     cd netzilla
     pipx install .

 tar comes with Windows 10 and 11. pipx fetches everything netzilla needs,
 the Bluetooth library for Windows included.


 STEP 4 — Run it
 ---------------
     netzilla

 Run it in Windows Terminal: the old console window draws netzilla's
 borders and colours badly. Windows 11 has Windows Terminal already; on
 Windows 10:

     winget install Microsoft.WindowsTerminal

 Graphs are drawn with text in Windows Terminal.

 Nothing else is needed: netzilla uses Windows' own ping, tracert,
 pathping, arp and netsh, reads the network straight from Windows, and
 brings its own WHOIS client and DNS-over-HTTPS. Two optional extras:

   openssl, for SSL/TLS -> OPENSSL HANDSHAKE's full report (without it
   the handshake is done by Python's own TLS):

     winget install ShiningLight.OpenSSL.Light

   Wireshark, for the CAPTURE tab and WIFI -> PACKETS. It needs Npcap, the
   capture driver, which winget's install leaves out: get it from
   https://npcap.com (or run Wireshark's own installer and tick Npcap).

     winget install WiresharkFoundation.Wireshark

 Under WSL, netzilla is the Linux version and sees WSL's own virtual
 network, not Windows' Wi-Fi and adapters: install it on Windows itself,
 as above, for those.


 STEP 5 — Add your own API keys
 ------------------------------
 As on Linux and macOS: F2 (SETTINGS), type each key, SAVE SETTINGS, then
 TEST KEYS. Keys are kept in %APPDATA%\netzilla\config.toml.

 Windows-specific notes:
   * Windows 11 24H2 and later show Wi-Fi networks only to apps allowed
     your location. If WIFI -> SCAN is empty, turn on Settings -> Privacy
     & security -> Location -> "Let desktop apps access your location".
     WIFI -> TOOL CHECK says when this is the reason.
   * The first time SYSLOG CATCH listens, Windows Defender Firewall asks
     whether Python may communicate on networks: allow it on private
     networks, or other devices' messages never arrive.
   * Windows has no sudo, and nothing in netzilla needs Administrator
     there — unless Npcap was installed for Administrators only; then
     start Windows Terminal with "Run as administrator" to capture.


-------------------------------- 3d. WHAT WORKS WHERE --------------------------------

 Every tab is there on all three systems, and everything looked up over the
 internet (IP LOOKUP, SUBNET, BGP/ASN, THREAT, DISCOVERY, MAC, LIFECYCLE,
 STATUS, SPEED, CONFIG, CREDS, SSL Labs and crt.sh, RDAP, RESOLVER CHECK)
 works the same everywhere. The local tools are where systems differ:

 DNS/WHOIS
   macOS     everything, with the dig and whois macOS ships.
   Windows   ALL RECORDS and REVERSE ask Cloudflare over DNS-over-HTTPS
             (Windows has no dig), so the DNS server box is ignored and
             internal zones aren't visible. DIG +TRACE is Linux and macOS
             only. WHOIS uses netzilla's own client and needs outbound TCP
             port 43.

 SSL/TLS
   macOS     OPENSSL HANDSHAKE shows LibreSSL's full report.
   Windows   without openssl installed, OPENSSL HANDSHAKE uses Python's
             own TLS: protocol, cipher and certificate, not the chain as
             served.

 LAN
   macOS     ROGUE DHCP needs sudo. SNMP POLL uses the tools macOS ships.
             SYSLOG CATCH listens on 514 without sudo.
   Windows   no ROGUE DHCP: Windows' DHCP Client service holds UDP/68. No
             SNMP POLL: Net-SNMP has no current Windows release. SWEEP,
             IDENTIFY, DUP-IP WATCH and SYSLOG CATCH work, with no
             administrator rights.

 INT
   macOS     LIVE RATES works with nothing installed; iftop, vnstat and
             bmon come from Homebrew, and iftop needs ChmodBPF or sudo.
   Windows   LIVE RATES and the interface list work; iftop, vnstat and bmon
             have no Windows versions.

 WIFI
   macOS     SCAN and LIVE AIR take a few seconds a scan, and macOS 14.4
             and later hide access points' MAC addresses (BSSIDs), so the
             AP maker column stays blank there. LINK HEALTH shows no
             retries or missed beacons. DEEP SCAN is the same as SCAN.
             BLUETOOTH needs your terminal app allowed to use Bluetooth,
             and shows identifiers macOS makes up instead of real
             addresses.
   Windows   everything except LINK HEALTH's retries and missed beacons,
             which Windows doesn't report. DEEP SCAN is the same as SCAN.
             Windows 11 24H2+ needs location access allowed (3c above).
   Both      PACKETS needs the capture setup below.

 CAPTURE
   macOS     tshark and dumpcap from Wireshark; ChmodBPF (installed with
             it) replaces FIX PERMISSIONS, and AUTHENTICATE covers a run
             until then.
   Windows   tshark with Npcap; there is no TCPDUMP CAPTURE (no tcpdump),
             and AUTHENTICATE and FIX PERMISSIONS have nothing to do.

 FLOW
   macOS     without sudo, process names are shown only for your own
             programs.
   Windows   everything, with no administrator rights.

 DIAG
   macOS     MTR REPORT needs root (AUTHENTICATE's sudo session, or sudo
             netzilla).
   Windows   TRACEROUTE +ASN runs tracert and MTR REPORT runs pathping,
             both slower than their Linux cousins (a minute or two).

 Pixel graphs need kitty or Ghostty, which run on Linux and macOS. On
 Windows the graphs are drawn with text.


-------------------------------- 3e. ALL SYSTEMS --------------------------------

 UPGRADING FROM AN EARLIER VERSION (any 1.x, 2.x, 3.x or 4.x -> 4.6.0)
 ----------------------------------------------------------------------
     cd ~/Downloads
     tar -xzf netzilla-4.6.0.tar.gz
     cd netzilla
     pipx install --force .
     pipx inject netzilla speedtest-cli      # optional; --force wipes it

 Your existing config.toml (theme, any keys you typed) is kept: it lives in
 ~/.config/netzilla on Linux and macOS, and %APPDATA%\netzilla on Windows.
 Blank key lines left over from 1.0 do not hide the new defaults. Keys you
 entered yourself still take priority over the defaults. A Shodan,
 OutageDeck or EOSL.ai key saved by an older version is ignored — those
 services are used without one now.


 REMOVING AN OLD VERSION / CLEAN REINSTALL
 ------------------------------------------
 Upgrading in place with `pipx install --force .` is enough for almost
 everything, and it keeps your config. To remove netzilla completely first:

     pipx uninstall netzilla

 That deletes the app and its private virtualenv. It leaves your own data
 behind on purpose — all of it lives in one directory, ~/.config/netzilla
 on Linux and macOS and %APPDATA%\netzilla on Windows:

     config.toml       theme, any keys you typed (0600)
     cache.sqlite3     cached responses, quota counters, route/origin
                       snapshot history
     oui.csv           a newer IEEE registry, if you ran --update-oui

 Delete that too only if you want a factory-fresh start:

     rm -rf ~/.config/netzilla                        # Linux, macOS
     Remove-Item -Recurse $env:APPDATA\netzilla       # Windows (PowerShell)

 Then install the new version as in 3a, 3b or 3c above. If `netzilla` still
 runs an old build afterwards, an older copy is ahead of it on your PATH:

     which -a netzilla                                # Linux, macOS
     where.exe netzilla                               # Windows

 (A copy installed with plain `pip install --user` in the past lives at
 ~/.local/bin/netzilla and is removed with `pip uninstall netzilla`.)


 ALTERNATIVE — virtualenv instead of pipx
 ----------------------------------------
     cd ~/Downloads/netzilla
     python3 -m venv .venv
     source .venv/bin/activate
     pip install --upgrade pip
     pip install -e .
     pip install speedtest-cli        # optional, for OOKLA TEST
     netzilla

 With this route, run `source .venv/bin/activate` before each use. On
 Windows (PowerShell) there is nothing to activate:

     cd ~/Downloads/netzilla
     py -m venv .venv
     .venv\Scripts\python -m pip install -e .
     .venv\Scripts\netzilla


 OPTIONAL — a terminal that draws the pixel graphs
 -------------------------------------------------
 netzilla runs in any terminal. In kitty 0.28+ or Ghostty 1.0+ its graphs
 are drawn as images; everywhere else they are drawn with text. Nothing to
 configure either way — netzilla asks the terminal at start-up.

   kitty, newest release (any Linux, installs into your home folder; these
   are the commands from kitty's own install page):

     curl -L https://sw.kovidgoyal.net/kitty/installer.sh | sh /dev/stdin
     mkdir -p ~/.local/bin ~/.local/share/applications
     ln -sf ~/.local/kitty.app/bin/kitty ~/.local/kitty.app/bin/kitten ~/.local/bin/
     cp ~/.local/kitty.app/share/applications/kitty.desktop ~/.local/share/applications/
     sed -i "s|Icon=kitty|Icon=$(readlink -f ~)/.local/kitty.app/share/icons/hicolor/256x256/apps/kitty.png|g" ~/.local/share/applications/kitty.desktop
     sed -i "s|Exec=kitty|Exec=$(readlink -f ~)/.local/kitty.app/bin/kitty|g" ~/.local/share/applications/kitty.desktop

     kitty is then in your applications menu. `sudo apt install kitty`
     also works on Ubuntu 24.04 / Mint 22, whose kitty is new enough;
     Ubuntu 22.04 / Mint 21 ship kitty 0.21, which is too old — netzilla
     says so and keeps text graphs.

   Ghostty:
     Ubuntu 26.04 and newer:
       sudo apt install ghostty
     Ubuntu 24.04 / Mint 22, from the community PPA
     (github.com/mkasberg/ghostty-ubuntu):
       sudo add-apt-repository ppa:mkasberg/ghostty-ubuntu
       sudo apt update && sudo apt install ghostty
     Any Linux with snap:
       sudo snap install ghostty --classic
     macOS:
       brew install --cask ghostty

 Then start netzilla from inside it. `netzilla --terminal` should say
 "Graphs will be drawn as  pixel". To use it inside tmux, add this line to
 ~/.tmux.conf and restart tmux (tmux 3.3 or newer):

     set -g allow-passthrough on


 OPTIONAL — the full CRT look
 ----------------------------
 netzilla controls its own colours, borders and layout, but phosphor glow,
 scanlines and screen curvature come from the terminal emulator:

     sudo apt install cool-retro-term

 (macOS: cool-retro-term is not on Homebrew. iTerm2's Preferences -> Profiles
 -> Colors has a "Retro Terminal" scheme that gets partway there; it will not
 add scanlines or screen curvature.)

 Launch netzilla inside it. Profile pairings (right-click -> Settings):

     cool-retro-term profile     netzilla theme
     ------------------------    ----------------
     Default Green / Vintage     phosphor-green
     Default Amber               amber-phosphor
     IBM DOS                     ice-cyan
     Futuristic                  vhs-magenta
     Apple ][                    ember-rust

 cool-retro-term draws netzilla's graphs with text (it has no image
 support), which suits it. Any terminal works; use a monospace font with
 box-drawing and braille glyphs (JetBrains Mono, Fira Code, DejaVu Sans
 Mono) and a window at least 100 columns wide.


-------------------------------------------------------------------------------
 4. API KEYS
-------------------------------------------------------------------------------

 netzilla ships with no API keys. Every key it uses is one you add yourself,
 and it stays on your machine.

 How netzilla picks which key to use (first match wins)
 ------------------------------------------------------
   1. Environment variable      NETZILLA_ABUSEIPDB_API_KEY=...
   2. Your own saved key        ~/.config/netzilla/config.toml
                                (%APPDATA%\netzilla\config.toml on Windows)


 Adding or changing a key
 ------------------------
   F2 -> type the key into its box -> SAVE SETTINGS
   The tag under the box changes to "CUSTOM KEY".
   Press TEST KEYS to confirm it works.

 Removing a key
 --------------
   Clear its box -> SAVE SETTINGS


 The four free-account keys
 --------------------------
   AbuseIPDB API Key            free: 1,000 checks/day, 100 /24 block
                                checks/day. Sent as the "Key" header.
   VirusTotal API Key           free: 4 requests/min, 500/day. Sent as
                                "x-apikey". Public-API data is for
                                non-commercial use.
   GreyNoise Community API Key  free: 50 lookups per WEEK, shared with the
                                GreyNoise website. Sent as "key".
   abuse.ch Auth-Key (URLhaus)  free. Sent as "Auth-Key". The same key works
                                for MalwareBazaar and ThreatFox.

 Optional key (its tab already works without one)
 ------------------------------------------------
   NVD           https://nvd.nist.gov/developers/request-an-api-key
                 free. Raises CVE lookups from 5 to 50 per 30 seconds, and
                 lets DISCOVERY > CVE DETAIL fetch CVSS for 50 CVEs at a
                 time instead of 5.

 Every key netzilla uses comes from a free account. Nothing in it needs a
 paid plan: 4.0 removed the Shodan key (its host records and Search are
 paid-only; DISCOVERY uses the free InternetDB instead) and the OutageDeck
 and EOSL.ai key boxes (both work fully without one).

 A note on GreyNoise
 -------------------
 GreyNoise does not grant API-key access to accounts registered with free
 webmail addresses. If TEST KEYS reports "KEY REJECTED (401)", that is the
 usual cause. netzilla keeps working in that case: it falls back to anonymous
 lookups (10 per day) and says so on every GreyNoise panel.

 A note on shared secrets
 ------------------------
 None of these services use an HMAC-style secret-key pair; they are all
 single-token schemes. abuse.ch calls its token an "Auth-Key", so SETTINGS
 labels it [SHARED SECRET] to keep the distinction visible.


 SHARING NETZILLA
 ----------------
 There are no keys to strip first. Your own keys typed on SETTINGS live only
 in ~/.config/netzilla/config.toml (mode 0600; on Windows in
 %APPDATA%\netzilla\config.toml, inside your own profile), never in the
 netzilla folder, so a copy of the folder is safe to pass along as it is.

 Older copies of netzilla could carry keys in a bundled file,
 src/netzilla/data/default_credentials.toml. netzilla no longer reads or
 installs that file, and .gitignore keeps it out of git. Delete it from any
 old folder or install you still have, for example:

     rm -f ~/Downloads/netzilla/src/netzilla/data/default_credentials.toml
     find ~/.local -path '*netzilla/data/default_credentials.toml' -delete

 Keys that came from that file show as "not set" after upgrading. Type them
 into SETTINGS and SAVE once; from then on they are kept in your
 config.toml.


-------------------------------------------------------------------------------
 5. KEYS AND COMMANDS
-------------------------------------------------------------------------------

 Inside the app (letters work in either case — q or Q, t or T):

   Left / Right arrows   move between tabs (with the tab bar focused)
   Tab / Shift+Tab       move between fields and buttons within a tab
   Enter                 in a box: run the action that box is for (usually
                         the tab's first button); on a button: press it
   T                     cycle the colour theme (Ctrl+T while typing in a
                         box, where T is just a letter)
   F1 / F2               jump to DASH / SETTINGS
   F3                    roll this tab's controls up / back down (or ▲ ▼)
   F4                    copy this tab's results as plain text
   Ctrl+P                command palette: any tab, any theme, graphics
                         mode, copy, clear cache, quit — type to filter
   Ctrl+R                clear the response cache
   In a live list        (WIFI: LIVE AIR, BLUETOOTH, BT TRACKERS) click a
                         row to graph it, click it again to show only it;
                         or Tab to the list: ↑ ↓ pick, Enter shows only it,
                         Esc steps back
   Q                     quit (Ctrl+Q anywhere, even while typing; Ctrl+C
                         too, except in a text box, where it copies)

 The footer shows the keys that work where you are: T and Q drop out of it
 while a text box has the cursor, because there they type a letter.

 From the shell:

   netzilla                          launch the TUI
   netzilla --theme amber-phosphor   launch with a specific theme
   netzilla --tab wifi               open straight to a tab — its name in
                                     any case, or the start of it (dns,
                                     DNS/WHOIS, life, ip lookup)
   netzilla --graphics text          draw graphs as text (or pixel, or
                                     auto) for this run, without saving
   netzilla --terminal               what netzilla detects about this
                                     terminal, and why graphs will be pixels
                                     or text
   netzilla --no-probe               don't ask the terminal at start-up;
                                     detect from the environment only
   netzilla --offline                no network calls; local tools and the
                                     URLhaus snapshot keep working
   netzilla --update-oui             download the full IEEE OUI registry
   netzilla --update-urlhaus         refresh the URLhaus snapshot from abuse.ch
   netzilla --import-urlhaus FILE    load a URLhaus dump you downloaded
                                     (.json, .zip, or the plain-text URL list)
   netzilla --help                   full option list

 One-shot mode for scripting (no TUI; add --json to pipe into jq):

   netzilla ip 8.8.8.8 --json
   netzilla subnet 10.0.0.0/22
   netzilla mac 00:1A:2B:3C:4D:5E
   netzilla dns example.com --json
   netzilla asn AS15169 --json
   netzilla status aws,cloudflare,github --json
   netzilla eol WS-C3850-24T-L
   netzilla software "ubuntu 20.04"           software release support
   netzilla software "panos 10.2" --json
   netzilla urlhaus 5.175.222.237             host check
   netzilla urlhaus "http://bad.example/x"     exact URL check
   netzilla hash <md5|sha1|sha256>            VirusTotal file verdict
   netzilla block 203.0.113.0/24              AbuseIPDB /24 reputation
   netzilla sweep                             every device on this LAN, named
   netzilla sweep 10.0.0.0/24 --json          … a subnet you choose, as JSON
   netzilla identify 10.0.0.185               one device, with its evidence


-------------------------------------------------------------------------------
 6. DATA SOURCES
-------------------------------------------------------------------------------

 Tab          Source                    Auth         Free-tier limit
 -----------  ------------------------  -----------  -----------------------
 IP LOOKUP    IP-API                    none         45 req/min
              AbuseIPDB check           API key      1,000/day
              AbuseIPDB check-block     API key      100/day, up to /24
              VirusTotal                API key      4/min, 500/day
              GreyNoise Community       API key      50/week (anon: 10/day)
              IPLogs                    none         fair use, no signup
 SUBNET       Python ipaddress          local        none
 DNS/WHOIS    dig / whois               local        none
              RDAP (rdap.org)           none         fair use
              DoH: Cloudflare/Google/   none         fair use (also the
                Quad9                                fallback without dig)
              Typosquat generator       local DNS    none
              VirusTotal domains        API key      4/min, 500/day
 SSL/TLS      openssl + Python ssl      local        none
              Qualys SSL Labs           none         scan-rate limited
              crt.sh (CT logs)          none         fair use (unofficial)
 BGP/ASN      RIPE NCC RIPEstat         none         fair use
              Team Cymru (fallback)     DNS (dig)    none
 THREAT       NVD                       optional     5/30s, 50/30s with key
              CISA KEV catalog          none         fair use
              FIRST EPSS                none         fair use (100 CVEs/call)
              URLhaus (abuse.ch)        Auth-Key     fair use
              URLhaus snapshot          local        none (dated 2026-09-19)
              ThreatFox (abuse.ch)      Auth-Key     fair use
              MalwareBazaar (abuse.ch)  Auth-Key     fair use
              Feodo Tracker (abuse.ch)  none         fair use
              VirusTotal URLs / files   API key      4/min, 500/day
 DISCOVERY    Shodan InternetDB         none         fair use
              IP-API, RDAP, RIPEstat    none         as above (HOST PROFILE)
              NVD, FIRST EPSS, KEV      none         as above (CVE DETAIL)
 LAN          ping / ARP / DHCP / SNMP  local        none (SNMP: net-snmp)
              device identification:    local        none — asks the devices:
                reverse DNS, mDNS,                     router DNS, udp/5353,
                NetBIOS, SSDP/UPnP                     udp/137, udp+tcp UPnP
 INT          /proc/net/dev             local        none (LIVE RATES)
              iftop / vnstat / bmon     local        none (root for iftop)
 CAPTURE      tshark / tcpdump          local        none (capture privilege)
              syslog listener           local        none (root only for :514)
 MAC          Bundled IEEE registry     local        none (MA-L/MA-M/MA-S)
              macvendors.com            none         ~1 req/sec
 WIFI         nmcli / iw                local        none (iw scan: root)
              Bluetooth broadcasts      local radio  none — listening only,
                (BlueZ via bleak)                    no pairing, no root
              Bluetooth SIG company     bundled      none (via the MIT-
                identifiers and UUIDs                licensed bluetooth-
                                                     numbers project)
 LIFECYCLE    EOSL.ai (hardware)        none         unmetered, CC BY 4.0
              endoflife.date (software) none         fair use, MIT licensed
 STATUS       OutageDeck                none         120 req/hour
 SPEED        Cloudflare speed test     none         fair use; netzilla caps
                (speed.cloudflare.com)               a run at 400 MB down,
                                                     150 MB up
              speedtest-cli / Ookla CLI local        optional (OOKLA TEST)
 DIAG         ping/traceroute/mtr       local        none
              path MTU / NTP drift      local        none
 CONFIG       local text parser         local        none
 CREDS        Have I Been Pwned         none         k-anonymity, keyless

 Responses are cached in SQLite by how fast the data changes — 24h for
 geolocation, 1h for reputation (6h for GreyNoise, whose lookups are
 scarce), 5 min for DNS, 30s for service status — so repeat lookups cost no
 quota. The DASH quota panel counts calls from this machine; for AbuseIPDB it
 also shows the vendor's own "calls left today", which includes calls made
 elsewhere.

 Every source above is free to use. None needs a paid plan, and the keyed
 ones (AbuseIPDB, VirusTotal, GreyNoise, abuse.ch, and optionally NVD) need
 only a free account.

 Caveats:
   * IP-API's free tier is HTTP-only (HTTPS is paid). The data is public
     geolocation, but it is a deliberate exception to HTTPS-everywhere.
   * InternetDB is Shodan's free summary of its last scan of an address —
     ports, hostnames, CPEs, tags and CVEs, updated weekly — not a live
     scan. Shodan's full host records and Search are paid and not used.
     Like VirusTotal's public API, InternetDB is free for non-commercial
     use; Shodan asks for a licence if you use it to make money.
   * EPSS is a probability, not a verdict: 0.40 means a 40% chance of
     exploitation activity being seen in the next 30 days.
   * The URLhaus snapshot is a point-in-time copy. It is labelled with its
     date wherever it is used; refresh it with --update-urlhaus.


-------------------------------------------------------------------------------
 7. PROJECT LAYOUT
-------------------------------------------------------------------------------

   src/netzilla/
     app.py            Textual app shell: tabs (each built on first visit),
                       themes, key bindings, command palette, graphics mode
     cli.py            argparse entry point, one-shot mode, update/import flags
     config.py         config.toml, credential schema, env > custom > default
     cache.py          SQLite TTL cache and quota counters
     services.py       async HTTP layer, vendor error parsing, rate headers
     render.py         Rich renderable helpers (themed panels and tables)
     themes.py         the seventeen palettes
     validators.py     local input validation (runs before any network call)
     termcaps.py       which terminal is this? XTVERSION, kitty graphics and
                       feature queries, cell size, tmux/SSH, environment
                       fallbacks; decides pixel or text graphs
     hostos.py         which system this is (Linux, macOS, Windows) and all
                       that differs by it: where settings live, where a tool
                       is installed off PATH, the apt/brew/winget command
                       for a missing one, admin rights, tools' code pages
     graphics/         kitty.py (the kitty graphics protocol with Unicode
                       placeholders, image upload and freeing), plot.py
                       (the pixel drawings, with Pillow), charts.py (each
                       graph once, rendered as pixels or text)
     clipboard.py      F4: desktop clipboard tool, OSC 52, or a file
     notify.py         desktop notifications through the terminal
     netzilla.tcss     Textual CSS
     clients/          one module per external API; each documents its
                       endpoints, auth and limits at the top. 2.0 adds rdap,
                       doh, crtsh, abusech (ThreatFox/MalwareBazaar/Feodo/SSLBL),
                       kev and hibp; 4.0 adds epss and endoflife, and
                       shodan is InternetDB only
     local/            subnet maths, dig/whois, openssl, ping/traceroute,
                       OUI table, speedtest, offline URLhaus snapshot. 2.0 adds
                       lan, dhcp, arpwatch, snmp, mtu, ntp, syslog, confparse,
                       elevation (one sudo unlock per session), netif
                       (interfaces + /proc/net/dev rates), bwtools
                       (iftop/vnstat/bmon wrappers), capture (tshark/
                       tcpdump + filter reference),
                       cymru and history. 3.0 adds wifi and flows; 3.1 adds
                       devices (who is that IP/MAC: vendor, reverse DNS,
                       mDNS, NetBIOS, UPnP, TTL, classification); 3.2 adds
                       wifitools (link parsing, live signal/link/throughput
                       history, block charts, DNS-named traffic, CSV export);
                       4.0 adds cfspeed (the built-in Cloudflare speed test);
                       4.1 adds sysinfo; 4.2 adds bluetooth (scanning via
                       bleak, decoding broadcasts, device guesses, distance,
                       tracker checks); 4.6 adds winapi (Windows' IP Helper
                       API: adapters, counters, connections and their
                       programs) and wlanapi (Windows' Native Wi-Fi API:
                       scans, signal and the joined network), both through
                       ctypes
     screens/          one module per tab; all inherit screens/base.py. 2.0 adds
                       lan, config_review and creds; 4.3 adds picking (pick
                       a row of a live list, and show only it)
     data/
       urlhaus_snapshot.csv.gz    offline URLhaus database, 1.4 MB
       bt_numbers.csv.gz          Bluetooth company IDs and service UUIDs
       oui.csv.gz                 the full IEEE registry, all three block
                                  sizes (~54,000 prefixes, 570 KB)
   docs/showcase/      screenshots — pixel graphs as kitty/Ghostty show them,
                       text graphs as any other terminal does — and
                       live-air.gif (Wi-Fi data invented; lookups of public
                       test hosts)
   tests/
     test_netzilla.py  subnet maths, validators, config, verdicts, themes
     test_v11.py       default keys, snapshot, and client behaviour against
                       each vendor's documented responses (mocked HTTP)
     test_v112.py      STATUS/OutageDeck, RIPEstat fallback, typosquat
     test_v20.py       the 2.0 clients and local diagnostic modules
     test_v31.py       device identification: DNS/mDNS/NetBIOS/SSDP parsers
                       against wire-format replies, classification, the
                       pipeline and every screen that uses it
     test_v32.py       the WIFI workbench: iw/nmcli parsing, charts, the live
                       views driven tick by tick against fake tools
     test_v33.py       roll-up controls on every tab (real app), the 3-second
                       cadence, outlined blocks, iw hidden SSIDs
     test_v34.py       REFRESH EVERY on every live view, the colour rules,
                       RANGE format, fields fit (real app)
     test_v35.py       LIVE AIR keeps its pace while a scan takes 3 s, one
                       reading per scan, HISTORY as coloured dBm readings
     test_v40.py       no paid API anywhere, HOST PROFILE / CVE DETAIL /
                       SOFTWARE EOL, terminal detection (kitty, Ghostty,
                       tmux, SSH, old versions), the kitty protocol bytes,
                       pixel and text graphs, every key in both cases,
                       every button on every tab, copy, notifications,
                       links, the speed test, DNS without dig
     test_v41.py       DASH and SETTINGS filling the screen: panel grids,
                       the centred logo, everything on a 160 x 50 screen
     test_v42.py       buttons on shared columns on every tab, Bluetooth
                       decoding and best guesses, the tracker check, and
                       BLUETOOTH / BT TRACKERS against a fake radio
     test_v43.py       picking a device or network (real clicks and keys)
                       and showing only it, the nearest device heard
                       lately, steady row order, the detail panels
     test_v44.py       the pictures beside DASH's title: every sextant,
                       every theme in pixels and characters, room and
                       resizing, the image kitty is sent
     test_v45.py       the city picture; the breath's colours (the theme's
                       own, rolling out and looping), its frames in pixels
                       and characters, and DASH keeping it moving only
                       while it is on screen
     test_v46.py       Windows and macOS: the Windows API structures built
                       byte by byte, netsh/netstat/tracert/pathping output
                       in other languages, macOS's ifconfig, netstat,
                       system_profiler and airport output, WHOIS and TLS
                       without the programs, and every tab's TOOL CHECK
                       and help cards run as each system
     conftest.py       stubs out every real LAN probe, so running the tests
                       never sends a packet to the devices on your network


-------------------------------------------------------------------------------
 8. RUNNING THE TESTS
-------------------------------------------------------------------------------

     cd ~/Downloads/netzilla
     python3 -m venv .venv
     source .venv/bin/activate
     pip install -e ".[dev]"
     pytest -q

 927 checks, about five minutes, run on Linux: macOS and Windows are tested
 by faking them, with their tools' recorded output. No network calls, no
 root, and no real API key is used or printed — HTTP is served by httpx's
 MockTransport using the example responses from each vendor's
 documentation, the LAN/DHCP/SNMP/NTP protocol logic is exercised as pure
 functions, and the terminal is a fake that answers netzilla's start-up
 questions the way kitty, Ghostty, tmux and others do.


-------------------------------------------------------------------------------
 9. TROUBLESHOOTING
-------------------------------------------------------------------------------

 "netzilla: command not found"
     Open a new terminal, or run ~/.local/bin/netzilla. `pipx ensurepath`
     fixes it permanently. On Windows the message reads "netzilla is not
     recognized…": open a new Windows Terminal, or run `py -m pipx
     ensurepath` again; netzilla.exe is in %USERPROFILE%\.local\bin.

 Windows: borders look broken or the colours are missing
     The old console window can't draw netzilla properly. Run it in Windows
     Terminal (Windows 11 has it; on Windows 10:
     winget install Microsoft.WindowsTerminal).

 Windows: WIFI > SCAN is empty
     Windows 11 24H2 and later hide Wi-Fi networks from apps that may not
     use your location. Turn on Settings > Privacy & security > Location,
     and "Let desktop apps access your location" on the same page. WIFI >
     TOOL CHECK says when this is the reason. Otherwise: Wi-Fi on, Airplane
     mode off.

 Windows: CAPTURE says Npcap is not installed
     Wireshark captures through Npcap, and winget's Wireshark install
     leaves it out. Get it from https://npcap.com (or run Wireshark's own
     installer and tick Npcap), then press TOOL CHECK again. If Npcap was
     installed for Administrators only, start Windows Terminal with "Run as
     administrator".

 macOS: WIFI > SCAN shows no BSSIDs, or names as <redacted>
     macOS 14.4 and later keep access points' MAC addresses from
     command-line tools, so BSSID and the AP maker stay blank there. Names
     shown as <redacted> need Location Services for your terminal app:
     System Settings > Privacy & Security > Location Services.

 macOS: "mtr needs root on macOS"
     Homebrew's mtr can't send its probes as an ordinary user. Press
     AUTHENTICATE on the CAPTURE tab once and netzilla runs mtr through
     that sudo session, or start netzilla with  sudo netzilla

 Graphs are drawn with text in kitty or Ghostty
     Run `netzilla --terminal` in that window: the last line, "Why", names
     the reason. The usual ones:
       * kitty older than 0.28 (Ubuntu 22.04 / Mint 21 ship 0.21) — install
         the current kitty, section 3 "a terminal that draws the pixel
         graphs".
       * inside tmux without passthrough — add `set -g allow-passthrough on`
         to ~/.tmux.conf and restart tmux (3.3 or newer).
       * inside tmux without 24-bit colour — the reason line says "tmux is
         not passing 24-bit colour"; add this to ~/.tmux.conf as well:
             set -as terminal-features ',*:RGB'
       * NO_COLOR is set in your environment — pixel graphs need colour.
       * inside GNU screen or Zellij — neither passes images through; run
         netzilla outside it.
       * SETTINGS > DISPLAY > GRAPHICS is set to Text, or you started it
         with --graphics text.
       * "Pixel needs a real terminal and Pillow" — Pillow is missing from
         netzilla's environment: pipx runpip netzilla install pillow

 Graphs show as empty boxes or stray characters
     The terminal can't draw kitty images but GRAPHICS was set to Pixel.
     Set it back to Auto on SETTINGS > DISPLAY (or Ctrl+P, "Graphics:
     auto") and netzilla only uses pixels where they work.

 Ghostty or kitty over SSH
     Works: netzilla asks the terminal at the far end, waiting a little
     longer for the answer over SSH. If the terminal doesn't answer in
     time, run `netzilla --terminal` — and if it says "environment" only,
     add `--graphics pixel` for that session.

 Graphs look slightly soft right after changing the font size
     The terminal scales the old image to the new cells until it is
     redrawn: each live graph on its next update, the DASH banner as soon
     as the window stops changing size.

 DASH's API KEYS panel says "not set" for every key after installing
     Expected: netzilla ships with no keys. Add your own on SETTINGS (F2)
     and SAVE; see section 4.

 TEST KEYS shows an error for one service
     The message includes the service's own explanation. "Unauthorized" means
     the key was rejected — paste a fresh one from the vendor's site. For
     GreyNoise, see the note in section 4.

 "Rate limited" on IP LOOKUP
     A free-tier ceiling was hit; the message says how long to wait. DASH
     shows which service. GreyNoise resets weekly, the others daily.

 URLhaus answers say "offline snapshot" while you are online
     The live API was unreachable or rejected the Auth-Key; the reason is in
     the note on the panel. TEST KEYS will confirm whether the key works.

 BLOCK CHECK refuses a network
     The free AbuseIPDB plan checks up to a /24. Split larger networks on the
     SUBNET tab (SPLIT into /24) and check each one.

 WIFI > LIVE AIR: my own network moves every tick, the others less often
     Expected. Your own network is read from the driver on every tick.
     Everything else changes when a background scan finishes, and a full
     scan of every channel takes most adapters 2–4 seconds whatever REFRESH
     EVERY says — the headline shows how old the newest scan result is.
     Scans are started with iw when it has the scan capability (WIFI > TOOL
     CHECK shows the one-time command), otherwise by NetworkManager, which
     sometimes declines a request made very soon after the last.

 I want LIVE AIR (or any live view) faster or slower
     Type the seconds into REFRESH EVERY on that tab — e.g. 1 for LIVE AIR
     every second, 10 for a gentle background watch. Blank = the default.

 Colours look wrong or hard to read in my terminal
     netzilla sends exact colours (truecolor). If everything looks washed
     out, the terminal may be limited to 256 colours, or not saying that it
     isn't: netzilla turns 24-bit colour on by itself for terminals it
     recognises (kitty, Ghostty, WezTerm, iTerm2, Konsole, GNOME Terminal
     and other VTE terminals, foot, Alacritty, Windows Terminal), which also
     covers SSH sessions. For anything else, set COLORTERM=truecolor.

 I rolled the controls up and can't find the buttons
     Press F3, or the ▼ at the right-hand end of the one-line control box.

 WIFI > LINK HEALTH shows no graph, only addresses
     iw is missing. `sudo apt install iw` — reading the link needs no root.

 WIFI > DEVICES says the interface has no IPv4 address
     The Wi-Fi isn't associated, or got no DHCP lease. LINK HEALTH shows
     which; LAN > SWEEP with a CIDR typed in still works in the meantime.

 WIFI > PACKETS asks for a password
     It is the same one-time unlock as the CAPTURE tab. Enter your sudo
     password once and neither tab asks again until netzilla exits.

 WIFI > BLUETOOTH says Bluetooth is off, unavailable or not running
     The card says which, and the fix. In short, on Linux:
         rfkill unblock bluetooth             # if it is blocked
         bluetoothctl power on                # if it is off
         sudo systemctl enable --now bluetooth   # if bluetoothd is not running
     On macOS and Windows, turn Bluetooth on in Control Center or quick
     settings; on macOS, also allow your terminal app under System Settings
     > Privacy & Security > Bluetooth. TOOL CHECK shows each of these. A
     virtual machine (Hyper-V, VirtualBox, WSL) normally cannot see the
     host's Bluetooth radio, so run netzilla on the machine itself.

 WIFI > BLUETOOTH lists the same phone more than once
     Phones, watches and many earbuds change their Bluetooth address every
     few minutes for privacy, so one device can show as several; the old
     ones go quiet and drop off after 15 minutes. Distance is a rough
     estimate from signal strength — walls, pockets and bodies move it by
     a factor of two either way.

 WIFI > BLUETOOTH or LIVE AIR: the list stops re-sorting
     It holds still while the mouse pointer is over it, so the row you are
     about to click can't move (the subtitle says so). Move the pointer off
     the list and it sorts again.

 WIFI > BLUETOOTH: a device's dBm and distance are grey
     It hasn't been heard for 15 seconds or more, so its last reading is
     old. LAST SEEN says how long ago; after a minute it reads "gone".

 WIFI > BT TRACKERS flags my own tracker
     A Tile or SmartTag on your own keys stays near you, so after ten
     minutes it is flagged like any other — it has no way to say it is
     yours. An AirTag near its owner's iPhone says so and is not flagged.

 The layout looks cramped or borders render as question marks
     Widen the window to 100+ columns and use a font with box-drawing and
     braille glyphs (the text spectrum on WIFI is drawn in braille dots).

 A tab says a tool is not installed
     DIAG -> TOOL CHECK prints the exact command for your system (apt, brew
     or winget), or what netzilla uses instead where the tool doesn't exist.

 CAPTURE: TOOL CHECK says you may NOT run dumpcap
     dumpcap is installed but is root:wireshark 0750, and you are not in that
     group — the standard arrangement when tshark was installed answering NO
     to "should non-superusers be able to capture packets?". Press FIX
     PERMISSIONS, or run 'sudo dpkg-reconfigure wireshark-common' and answer
     yes. Either way the group part only takes effect at your next login.
     Capturing still works in the meantime through the sudo session netzilla
     opens for you.

 CAPTURE: "netzilla cannot capture packets yet"
     Press FIX PERMISSIONS. It runs the one-time setup for you and your
     desktop asks for the password. Capturing works straight afterwards.
     On a desktop session netzilla can also capture through pkexec without
     any setup — you get a password dialog per capture instead.

     By hand, if you prefer:
         sudo apt install -y tshark          (answer YES to the
                                              "non-superusers" question)
         sudo usermod -aG wireshark $USER
         sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)
         log out and back in, then check:  id -nG | grep wireshark
     If you answered no during install:  sudo dpkg-reconfigure wireshark-common
     `sudo netzilla` also works. TOOL CHECK shows exactly what is in place.

 CAPTURE: tired of the password dialog on every capture
     From 2.6 netzilla asks once, in its own box, and opens a sudo session —
     no dialog per capture and none after switching tabs. AUTHENTICATE does
     the same by hand, and pressing it again locks the session. FIX
     PERMISSIONS is the permanent version and needs no password at all after
     your next login.

     If it still asks every time, the message says why. The usual cause is
     'timestamp_timeout=0' in sudoers, which tells sudo not to remember a
     session at all; FIX PERMISSIONS is the way round that.

 CAPTURE: stopping a live capture without losing it
     Press STOP LIVE. The capture ends and every packet it collected stays in
     memory — press FILTER HELD to work through them. Any other button also
     stops it and the packets are kept just the same. It stops by itself
     after 15 minutes. If you switch tabs while it runs it keeps capturing
     until one of those happens — that is deliberate, so a capture you are
     watching is not thrown away because you looked something up elsewhere.

 CAPTURE: '"..." was unexpected in this context' from tshark
     Usually a whole line copied out of FILTER HELP, heading and all. Use
     only the filter itself — 'udp' rather than 'PROTOCOL: UDP'. netzilla
     catches the common shapes and tells you which part to keep.

 CAPTURE: FILTER HELD says a filter could not be applied
     It only has the columns netzilla parsed — systime, addresses, ports,
     lengths, protocol and the info text. Filters that need the decoded
     packet (tcp.analysis.flags, tls.handshake.type, http.host) have to be
     given to tshark itself: put them in the FILTER box and press CAPTURE or
     LIVE CAPTURE.

 CAPTURE: still asks for a password after FIX PERMISSIONS
     Expected until your next login. The capability on dumpcap applies
     immediately, but being a member of the wireshark group does not — group
     membership is only read when a session starts. Log out and back in and
     the password prompts stop.

 CAPTURE: a capture returns nothing
     Either the link was quiet or the filter excluded everything. The FILTER
     box is tshark display-filter syntax for CAPTURE ("tcp.port == 80") and
     tcpdump BPF syntax for TCPDUMP CAPTURE ("tcp port 80") — they are
     different languages. Press FILTER HELP for both, side by side. Clear the
     box entirely to see all traffic.

 CAPTURE: the packet table is missing but raw text appeared
     tshark printed something netzilla's parser did not recognise, so the raw
     output is shown instead of being silently dropped. The capture itself is
     fine, and SAVE PCAP plus Wireshark will always work.

 LAN: ROGUE DHCP says "Needs root"
     DHCP uses privileged/raw ports (UDP 67/68). Run netzilla with sudo:
         sudo netzilla
     Your config and keys are read from your own ~/.config/netzilla either way.
     On Windows it can't run at all: Windows' DHCP Client service keeps
     UDP/68 for itself. Run it from Linux or macOS on the same network.

 LAN: SYSLOG CATCH receives nothing
     On Linux without root it listens on udp/1514, not 514; the result says
     which. (macOS and Windows let it listen on 514 as any user; there,
     allow Python through the firewall when asked.)
     Point the device at that port (Cisco: logging host <ip> transport udp
     port 1514), allow it through the firewall (sudo ufw allow 1514/udp),
     and self-test from this machine while it listens:
         logger -n 127.0.0.1 -P 1514 -d 'hello netzilla'
     "Needs root" appears only if you typed a port below 1024 yourself.

 CREDS: BREACH SEARCH finds nothing for a site you know was hacked
     HIBP only lists breaches it has verified and published (about 1,000).
     Many hacked sites are not in it. Try the bare company name as well.

 INT: the interface dropdown is empty
     Press REFRESH INTERFACES. If it stays empty, iproute2 is missing —
     install it with `sudo apt install iproute2`. netzilla falls back to
     ifconfig and then to /proc/net/dev, so this is rare.

 INT: LIVE RATES shows 0.00 Mbit/s everywhere
     Nothing was moving while it watched. It updates every second for the
     whole window, so start a download or a speed test and watch the numbers
     climb. An idle link really is 0.00.

 INT: the interface dropdown looks empty
     On 2.2.0 the selected value was invisible — fixed in 2.2.1. If it is
     genuinely empty, press REFRESH INTERFACES.

 INT: IFTOP SNAPSHOT cannot open the interface
     iftop puts the interface in promiscuous mode, which a normal user may
     not do. netzilla will use root, a cap_net_raw capability on the binary,
     or passwordless sudo — whichever it finds. The cleanest fix is the
     capability, granted once, after which no sudo is involved at all:
         sudo setcap cap_net_raw+ep $(which iftop)
     `sudo netzilla` also works. LIVE RATES needs none of this. On macOS
     the lasting fix is Wireshark's ChmodBPF (brew install --cask
     wireshark-app, then log out and back in); iftop then needs no sudo.

 INT: VNSTAT REPORT says there is no data yet
     vnstat only knows what its collector has recorded since it started:
         sudo apt install -y vnstat
         sudo systemctl enable --now vnstat
     (macOS: brew install vnstat, then sudo brew services start vnstat.)
     Daily totals appear the same day; monthly totals fill in over the month.

 INT: BMON SNAPSHOT says the columns could not be identified
     bmon prints unlabelled numbers and its output differs between builds.
     netzilla names the columns by matching them against /proc/net/dev
     (netstat -ib on macOS); when nothing matches it refuses to guess and
     shows the raw capture instead.
     LIVE RATES gives the same figures with units attached.

 LAN: SNMP POLL says "net-snmp not installed"
     netzilla uses the system SNMP tools. Install them:
         sudo apt install snmp
     Then check the device's community string and that UDP/161 is reachable.
     macOS ships them already. Windows has no current Net-SNMP release, so
     poll from Linux or macOS.

 LAN: SWEEP finds nothing
     Hosts may block ICMP, or you may be off-segment. Hosts already in the ARP
     cache are listed separately even if they don't answer ping. A ping sweep
     needs no root; a full raw-ARP sweep would — netzilla uses the unprivileged
     ping+neighbour approach.

 DIAG: PATH MTU shows a value below 1500
     A tunnel or VPN on the path is clamping the MTU (1492 = PPPoE/DSL is
     normal). That is the usual cause of "only large transfers stall".

 DNS/WHOIS: RESOLVER CHECK says resolvers disagree
     Often benign (DNS-based CDN steering). Investigate if you did not expect
     it — it can also mean split-horizon DNS, ISP NXDOMAIN redirection, or
     DNS hijacking.

 CREDS: is my password sent anywhere?
     No. Only the first five characters of its SHA-1 hash are sent (HIBP's
     k-anonymity range API), and nothing about it is cached.

 STATUS says a provider is "not an OutageDeck provider slug"
     Use the slugs it suggests, or type part of the name (e.g. micro,
     google, cisco) in the field and press FIND PROVIDER. The full list is at
     https://outagedeck.com/providers

 BGP/ASN says "RIPEstat unavailable — using fallback"
     RIPEstat was slow or down. The prefix and origin AS came from Team
     Cymru over DNS instead, which is accurate but has no RPKI, neighbour or
     prefix-list data. Try again in a few minutes for the full RIPE view.
     The fallback needs 'dig' (sudo apt install dnsutils).

 TYPOSQUAT SEARCH finds nothing or everything
     Nothing: good news, or outbound DNS is blocked on this network.
     Everything: your ISP's DNS answers for names that don't exist. netzilla
     filters those answers and warns you; set this machine's DNS to 1.1.1.1
     or 9.9.9.9 for a clean scan.

 SPEED: RUN SPEED TEST fails
     RUN SPEED TEST needs nothing installed; it talks to
     speed.cloudflare.com over HTTPS. If it fails, the panel names the
     error — usually a firewall or proxy that blocks speed.cloudflare.com,
     or --offline. OOKLA TEST is a separate, optional route (below).

 SPEED: my result is lower than another speed test's
     Every test measures to a different server. RUN SPEED TEST uses four
     parallel streams to the nearest Cloudflare data centre (named in the
     result) and caps a run at 400 MB down / 150 MB up, so on links much
     faster than ~1 Gbit/s it can finish before reaching full speed. The
     bufferbloat grade is the most useful number on any line: it is how
     much latency rises while the line is busy.

 SPEED: OOKLA TEST is unavailable or fails
     1. Read the red panel: it names the real error and the Python that
        netzilla runs under.
     2. Re-inject into netzilla's own environment, then restart netzilla:
            pipx inject netzilla speedtest-cli
        (Upgrading with 'pipx install --force .' removes injected packages,
        so run this again after every upgrade.)
     3. Confirm it is there:
            pipx runpip netzilla list | grep -i speedtest
            which -a netzilla        # two lines = two installs; remove one
     4. "HTTP Error 403: Forbidden" means Ookla refused the unofficial
        speedtest-cli client. Install Ookla's official CLI and netzilla
        switches to it on its own:
            https://www.speedtest.net/apps/cli   (Ubuntu/Debian instructions
            work on Linux Mint)
     RUN SPEED TEST keeps working whatever happens to OOKLA TEST.

 MAC lookups miss vendors
     The full IEEE registry ships with netzilla (MA-L, MA-M and MA-S). A
     vendor that is still missing registered its prefix after this release:
         netzilla --update-oui   (downloads a fresh copy of all three)
     A MAC shown as "private MAC" is randomised and has no vendor at all —
     see below.

 SWEEP: a device shows "private MAC" and no vendor
     Phones, tablets and laptops use a made-up ("randomised" or "private")
     Wi-Fi address by default — iOS, Android, Windows and macOS all do. Its
     HOSTNAME column usually still names it; if not, press IDENTIFY with its
     IP. To see the real MAC, turn private addressing off for your home
     network on that device (iPhone: Settings > Wi-Fi > (i) > Private Wi-Fi
     Address).

 SWEEP: the HOSTNAME column is mostly empty
     Most names come from your router's DNS. Some routers do not answer
     reverse lookups for DHCP clients; netzilla then relies on mDNS (Apple
     and Google gear, printers, Linux with avahi), NetBIOS (Windows, Samba)
     and UPnP (TVs, streamers, routers). Devices that are asleep — phones
     doze their Wi-Fi — answer nothing; sweep again, or IDENTIFY one.

 SWEEP: the DEVICE column is wrong
     It is a best guess, weighed from everything the device said. IDENTIFY
     shows the evidence behind it, which usually makes the mistake obvious.


-------------------------------------------------------------------------------
 10. UNINSTALLING
-------------------------------------------------------------------------------

     pipx uninstall netzilla
     rm -rf ~/.config/netzilla          # your overrides, cache, snapshots

 On Windows (PowerShell):

     pipx uninstall netzilla
     Remove-Item -Recurse $env:APPDATA\netzilla


===============================================================================
 netzilla is an independent tool and is not affiliated with, endorsed by, or
 sponsored by any of the data providers it queries. Respect each provider's
 terms of service and rate limits. Only scan and enumerate infrastructure you
 own or are explicitly authorised to test.
===============================================================================
