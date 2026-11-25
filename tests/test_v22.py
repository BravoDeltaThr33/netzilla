"""Tests for netzilla 2.2: the INT tab — interface discovery, live rates from
/proc/net/dev, and the iftop/vnstat/bmon wrappers.

Every parser is exercised as a pure function over captured command output, so
none of iftop, vnstat or bmon needs to be installed and nothing needs root.
"""

from __future__ import annotations

import asyncio

from netzilla import __version__
from netzilla.app import TABS
from netzilla.help import get_help
from netzilla.local import bwtools, netif
from netzilla.local.runner import run_for
from netzilla.screens.interfaces import InterfacesPane
from netzilla.validators import ValidationError

IP_LINK = (
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode "
    "DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd "
    "00:00:00:00:00:00\n"
    "2: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state "
    "UP mode DEFAULT group default qlen 1000\\    link/ether 3c:7c:3f:11:22:33 "
    "brd ff:ff:ff:ff:ff:ff\n"
    "3: wlp2s0: <BROADCAST,MULTICAST> mtu 1500 qdisc noqueue state DOWN mode "
    "DORMANT group default qlen 1000\\    link/ether a4:c3:f0:aa:bb:cc brd "
    "ff:ff:ff:ff:ff:ff\n"
    "5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc "
    "pfifo_fast state UNKNOWN mode DEFAULT group default qlen 500\\    link/none"
)

IP_ADDR = (
    "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
    "2: enp3s0    inet 192.168.1.42/24 brd 192.168.1.255 scope global dynamic "
    "enp3s0\\       valid_lft 84000sec\n"
    "2: enp3s0    inet6 fe80::3e7c:3fff:fe11:2233/64 scope link \\       "
    "valid_lft forever"
)

IFCONFIG = (
    "enp3s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
    "        inet 192.168.1.42  netmask 255.255.255.0  broadcast 192.168.1.255\n"
    "        ether 3c:7c:3f:11:22:33  txqueuelen 1000  (Ethernet)\n"
    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
    "        inet 127.0.0.1  netmask 255.0.0.0"
)

PROC = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    "
    "packets errs drop fifo colls carrier compressed\n"
    "    lo:   66425      10    0    0    0     0          0         0    66425"
    "      10    0    0    0     0       0          0\n"
    "  eth0: 1000000    1000    1    2    0     0          0         0   500000"
    "     500    0    1    0     0       0          0"
)


def test_version_is_2_2():
    """The features below arrived in 2.2; later releases keep them."""
    assert tuple(int(part) for part in __version__.split(".")[:2]) >= (2, 2), (
        __version__
    )


def test_int_tab_is_registered():
    ids = [t[0] for t in TABS]
    assert "int" in ids
    assert ("int", "INT", InterfacesPane) in TABS
    # Sits next to the other local-network tab.
    assert ids.index("int") == ids.index("lan") + 1


def test_every_int_button_has_help():
    for action in InterfacesPane.ACTIONS:
        assert get_help("InterfacesPane", action.key) is not None, action.key


# ------------------------------------------------------- interface discovery
def test_parse_ip_link():
    found = netif.parse_ip_link(IP_LINK)
    names = [i["name"] for i in found]
    assert names == ["lo", "enp3s0", "wlp2s0", "tun0"]
    eth = found[1]
    assert eth["state"] == "UP"
    assert eth["mtu"] == "1500"
    assert eth["mac"] == "3c:7c:3f:11:22:33"
    assert eth["kind"] == "ethernet"
    assert found[0]["kind"] == "loopback"
    assert found[2]["kind"] == "wireless"
    assert found[3]["kind"] == "tunnel/VPN"


def test_parse_ip_addr_and_default_route():
    addresses = netif.parse_ip_addr(IP_ADDR)
    assert addresses["enp3s0"] == [
        "192.168.1.42/24", "fe80::3e7c:3fff:fe11:2233/64"
    ]
    assert addresses["lo"] == ["127.0.0.1/8"]
    assert netif.parse_default_routes(
        "default via 192.168.1.1 dev enp3s0 proto dhcp metric 100"
    ) == ["enp3s0"]


def test_parse_ifconfig_fallback():
    found = netif.parse_ifconfig(IFCONFIG)
    assert [i["name"] for i in found] == ["enp3s0", "lo"]
    assert found[0]["mac"] == "3c:7c:3f:11:22:33"
    assert "192.168.1.42" in found[0]["addresses"]
    assert found[0]["mtu"] == "1500"


def test_pick_default_prefers_the_default_route():
    found = netif.parse_ip_link(IP_LINK)
    for iface in found:
        iface["addresses"] = netif.parse_ip_addr(IP_ADDR).get(iface["name"], [])
    assert netif.pick_default(found) == "enp3s0"          # by addresses
    found[1]["default_route"] = True
    assert netif.pick_default(found) == "enp3s0"          # by route
    assert netif.pick_default([]) == ""


def test_interface_rows_mark_the_default_route():
    found = netif.parse_ip_link(IP_LINK)
    found[1]["default_route"] = True
    rows = netif.interface_rows(found)
    assert "default route" in rows[1][0]
    assert rows[0][4] == "00:00:00:00:00:00"
    assert rows[3][4] == "—"                              # tun0 has no MAC


# -------------------------------------------------------------- live rates
def test_parse_proc_net_dev():
    counters = netif.parse_proc_net_dev(PROC)
    assert set(counters) == {"lo", "eth0"}
    assert counters["eth0"]["rx_bytes"] == 1_000_000
    assert counters["eth0"]["tx_packets"] == 500
    assert counters["eth0"]["rx_errs"] == 1
    assert counters["eth0"]["rx_drop"] == 2


def test_rates_between_converts_to_mbps():
    first = netif.parse_proc_net_dev(PROC)
    second = {
        "eth0": dict(first["eth0"]),
        "lo": dict(first["lo"]),
    }
    # 1,250,000 bytes in 10s = 1 Mbit/s
    second["eth0"]["rx_bytes"] += 1_250_000
    second["eth0"]["tx_bytes"] += 2_500_000
    second["eth0"]["rx_packets"] += 100
    second["eth0"]["rx_errs"] += 3
    second["eth0"]["tx_drop"] += 4
    rates = netif.rates_between(first, second, 10.0)
    eth = next(r for r in rates if r["name"] == "eth0")
    assert round(eth["rx_mbps"], 3) == 1.0
    assert round(eth["tx_mbps"], 3) == 2.0
    assert eth["rx_pps"] == 10.0
    assert eth["errors"] == 3
    assert eth["drops"] == 4
    assert rates[0]["name"] == "eth0"          # busiest first


def test_rates_ignore_counter_resets_and_new_interfaces():
    first = netif.parse_proc_net_dev(PROC)
    second = {"eth0": dict(first["eth0"]), "wg0": dict(first["lo"])}
    second["eth0"]["rx_bytes"] = 0             # interface reset
    rates = netif.rates_between(first, second, 5.0)
    assert [r["name"] for r in rates] == ["eth0"]   # wg0 had no first sample
    assert rates[0]["rx_mbps"] == 0.0               # never negative


def test_live_sampling_against_the_real_proc_file():
    rates = asyncio.run(netif.sample_rates(2.0))
    assert rates, "/proc/net/dev should be readable on Linux"
    assert all(r["rx_mbps"] >= 0 and r["seconds"] > 0 for r in rates)
    rows = netif.rate_rows(rates, highlight=rates[0]["name"])
    assert rows[0][0].startswith("▸ ")
    assert len(rows[0]) == 7
    assert dict(netif.rate_summary(rates[0]))["Interface"] == rates[0]["name"]


def test_bar_and_human_bytes():
    assert netif.bar(5, 10, width=10) == "█████·····"
    assert netif.bar(0, 0, width=4) == "····"
    assert netif.bar(99, 10, width=4) == "████"       # clamped
    assert netif.human_bytes(512) == "512 B"
    assert netif.human_bytes(5 * 1024 ** 3) == "5.0 GiB"


# ------------------------------------------------------------------ vnstat
V2 = {
    "vnstatversion": "2.10", "jsonversion": "2",
    "interfaces": [{
        "name": "enp3s0",
        "created": {"date": {"year": 2026, "month": 8, "day": 1}},
        "updated": {"date": {"year": 2026, "month": 9, "day": 20},
                    "time": {"hour": 12, "minute": 30}},
        "traffic": {
            "total": {"rx": 98765432109, "tx": 12345678901},
            "day": [
                {"id": 1, "date": {"year": 2026, "month": 9, "day": 19},
                 "rx": 5368709120, "tx": 1073741824},
                {"id": 2, "date": {"year": 2026, "month": 9, "day": 20},
                 "rx": 2147483648, "tx": 536870912},
            ],
            "month": [{"id": 1, "date": {"year": 2026, "month": 9},
                       "rx": 53687091200, "tx": 10737418240}],
            "hour": [{"id": 1, "date": {"year": 2026, "month": 9, "day": 20},
                      "time": {"hour": 11}, "rx": 104857600, "tx": 20971520}],
        },
    }],
}

# vnstat 1.x: different key names, and rx/tx are KiB rather than bytes.
V1 = {
    "vnstatversion": "1.18", "jsonversion": "1",
    "interfaces": [{
        "id": "eth0",
        "created": {"date": {"year": 2026, "month": 8, "day": 1}},
        "updated": {"date": {"year": 2026, "month": 9, "day": 20}},
        "traffic": {
            "total": {"rx": 96450617, "tx": 12056327},
            "days": [{"id": 0, "date": {"year": 2026, "month": 9, "day": 19},
                      "rx": 5242880, "tx": 1048576}],
        },
    }],
}


def test_vnstat_v2_summary_and_periods():
    summary = dict(bwtools.vnstat_summary(V2, "enp3s0"))
    assert summary["Interface"] == "enp3s0"
    assert summary["Total received"] == "92.0 GiB"
    assert summary["Last update"] == "2026-09-20 12:30"
    daily = bwtools.vnstat_rows(V2, "enp3s0", "daily")
    assert daily[0][0] == "2026-09-20"        # newest first
    assert daily[1] == ["2026-09-19", "5.0 GiB", "1.0 GiB", "6.0 GiB"]
    assert bwtools.vnstat_rows(V2, "enp3s0", "monthly")[0][0] == "2026-09"
    assert bwtools.vnstat_rows(V2, "enp3s0", "hourly")[0][0] == "2026-09-20 11:00"


def test_vnstat_v1_dialect_is_scaled_from_kib():
    summary = dict(bwtools.vnstat_summary(V1, "eth0"))
    assert summary["Interface"] == "eth0"
    assert summary["Total received"] == "92.0 GiB"      # same as v2 in bytes
    assert bwtools.vnstat_rows(V1, "eth0", "daily") == [
        ["2026-09-19", "5.0 GiB", "1.0 GiB", "6.0 GiB"]
    ]


def test_vnstat_handles_unknown_interface_and_empty_payload():
    assert bwtools.vnstat_summary({}, "eth0") == []
    assert bwtools.vnstat_rows({"interfaces": []}, "eth0", "daily") == []
    # An interface that is not in the database falls back to the first block.
    assert dict(bwtools.vnstat_summary(V2, "nope"))["Interface"] == "enp3s0"


def test_vnstat_service_hint_only_fires_when_there_is_no_data():
    assert "systemctl enable --now vnstat" in bwtools.vnstat_service_hint(
        "Error: No data available yet."
    )
    assert bwtools.vnstat_service_hint("enp3s0  /  daily\n  today  1.2 GiB") == ""


# -------------------------------------------------------------- iftop / bmon
def test_needs_root_detection():
    from netzilla.local.runner import CommandResult

    assert bwtools.needs_root_error(
        CommandResult(False, "", "pcap_open_live(eth0): Operation not permitted")
    )
    assert bwtools.needs_root_error(CommandResult(False, "", "You must be root"))
    assert not bwtools.needs_root_error(
        CommandResult(False, "", "interface eth9 does not exist")
    )


def test_bmon_rows_parse_and_degrade():
    output = (
        "name=enp3s0 rxrate.bytes=125000 txrate.bytes=64000 rxrate.packets=110 "
        "txrate.packets=90\n"
        "name=enp3s0 rxrate.bytes=250000 txrate.bytes=128000 rxrate.packets=220 "
        "txrate.packets=180\n"
        "name=lo rxrate.bytes=10 txrate.bytes=10 rxrate.packets=1 txrate.packets=1"
    )
    rows = bwtools.bmon_rows(output)
    assert rows[0] == ["enp3s0", "250,000", "128,000", "220", "180"]  # newest wins
    assert bwtools.bmon_rows(output, "enp3s0") == [rows[0]]
    # Output from a build whose format module differs is simply not parsed;
    # the pane still shows the raw capture.
    assert bwtools.bmon_rows("#### ascii art ####") == []
    assert bwtools.bmon_rows("") == []


def test_tools_status_lists_all_four_with_hints():
    status = bwtools.tools_status()
    assert [t[0] for t in status] == ["iftop", "vnstat", "bmon", "nload"]
    for _tool, installed, purpose, hint in status:
        assert isinstance(installed, bool)
        assert purpose and hint.startswith("sudo apt install")


def test_missing_tool_is_reported_not_raised():
    result = asyncio.run(bwtools.iftop_snapshot("eth0", 2))
    if result.missing_tool:                  # the usual case in CI
        assert result.missing_tool == "iftop"
        assert not result.ok


def test_run_for_keeps_output_from_a_tool_that_never_exits():
    """bmon streams forever; netzilla stops it and keeps what it printed."""
    script = (
        "import time\n"
        "while True:\n"
        "    print('name=eth0 rxrate.bytes=1000', flush=True)\n"
        "    time.sleep(0.2)\n"
    )
    result = asyncio.run(run_for(["python3", "-u", "-c", script], seconds=2))
    assert result.ok
    assert len(result.output.splitlines()) >= 3
    assert bwtools.bmon_rows(result.output) == [["eth0", "1,000", "—", "—", "—"]]


def test_run_for_reports_a_missing_binary():
    result = asyncio.run(run_for(["definitely-not-a-real-tool"], seconds=1))
    assert not result.ok and result.missing_tool == "definitely-not-a-real-tool"


# ---------------------------------------------------------- pane validation
class _FakePane:
    """Exercise the pane's validators without standing up the whole app."""

    def __init__(self, **values: str) -> None:
        self._values = values

    def field(self, key: str) -> str:
        return self._values.get(key, "")


def test_pane_requires_an_interface():
    try:
        InterfacesPane._iface(_FakePane(iface=""))
    except ValidationError as exc:
        assert "REFRESH INTERFACES" in str(exc)
    else:
        raise AssertionError("expected ValidationError")
    assert InterfacesPane._iface(_FakePane(iface="enp3s0")) == "enp3s0"


def test_pane_seconds_validation():
    assert InterfacesPane._seconds(_FakePane(secs="15")) == 15
    assert InterfacesPane._seconds(_FakePane(secs="")) == 10          # default
    for bad in ("abc", "0", "999"):
        try:
            InterfacesPane._seconds(_FakePane(secs=bad))
        except ValidationError:
            continue
        raise AssertionError(f"{bad} should have been rejected")


# ================================================= 2.2.1 fixes
def test_seconds_and_mode_fields_hold_real_values_not_placeholders():
    """A placeholder looked like a default but left the field empty, so every
    action silently fell back to its own number."""
    fields = {f.key: f for f in InterfacesPane.FIELDS}
    assert fields["secs"].value == "10"
    assert fields["mode"].value == "summary"
    assert fields["mode"].choices and "summary" in fields["mode"].choices
    assert fields["iface"].choices == ()          # filled in at mount


def test_live_rates_window_summary_averages_the_whole_run():
    first = netif.parse_proc_net_dev(PROC)
    last = {"eth0": dict(first["eth0"]), "lo": dict(first["lo"])}
    last["eth0"]["rx_bytes"] += 12_500_000        # 100 Mbit over 10s = 10 Mbit/s
    last["eth0"]["tx_bytes"] += 1_250_000
    rows = dict(netif.window_summary(first, last, 10.0, "eth0",
                                     peak_rx=25.0, peak_tx=3.0))
    assert rows["Average down"] == "10.00 Mbit/s"
    assert rows["Average up"] == "1.00 Mbit/s"
    assert rows["Peak down"] == "25.00 Mbit/s"
    assert rows["Watched for"] == "10s"
    assert "11.9 MiB in" in rows["Moved in total"]
    assert netif.window_summary(first, last, 10.0, "nope") == []


# -------------------------------------------------- bmon, in real units
# Exactly what bmon printed on a real machine: a name and bare counters.
BMON = "\n".join(
    f"enx0 {2014694820 + i * 600} {75902905 + i * 250} 0 {289016 + i * 3}"
    for i in range(10)
)


def test_counter_labels_name_bmon_columns_from_the_kernel():
    counters = {"enx0": {"rx_bytes": 2014700220, "tx_bytes": 75905155,
                         "rx_packets": 1_500_000, "tx_packets": 289043,
                         "rx_errs": 0, "tx_errs": 0, "rx_drop": 0, "tx_drop": 0}}
    known = netif.counter_labels(counters, "enx0")
    assert known[2014700220] == "rx_bytes"
    assert known[75905155] == "tx_bytes"
    assert netif.counter_labels(counters, "missing") == {}

    rows, how = bwtools.bmon_report(BMON, "enx0", 10.0, known)
    values = dict(rows)
    assert "matching /proc/net/dev" in how
    assert values["Received — total since boot"].startswith("1.9 GiB")
    # 5,400 bytes over 10s = 0.00 Mbit/s, but the byte figure must be right.
    assert "5.3 KiB" in values["Received — during this capture"]
    assert values["Sent — total since boot"].startswith("72.4 MiB")


def test_bmon_report_falls_back_positionally_and_says_so():
    rows, how = bwtools.bmon_report(BMON, "enx0", 10.0, {})
    values = dict(rows)
    assert "assumed" in how                       # honest about guessing
    assert values["Interface"] == "enx0"
    assert values["Received — total since boot"].startswith("1.9 GiB")
    assert values["Samples"].startswith("10 lines")


def test_bmon_report_is_empty_when_there_is_nothing_to_read():
    assert bwtools.bmon_report("", "enx0", 10.0, {}) == ([], "")
    assert bwtools.bmon_report("no numbers here", "enx0", 10.0, {}) == ([], "")


def test_bmon_samples_ignores_headers_and_junk():
    samples = bwtools.bmon_samples(
        "# comment\n1234 5678\nenx0 10 20\nenx0 30 40\nlo 1 2"
    )
    assert samples == {"enx0": [[10, 20], [30, 40]], "lo": [[1, 2]]}


# ------------------------------------------------------ iftop elevation
def test_elevation_reports_root_without_running_anything():
    import netzilla.local.bwtools as bw

    original = bw.is_root
    bw.is_root = lambda: True
    try:
        prefix, why = asyncio.run(bwtools.elevation("iftop"))
        assert prefix == [] and "root" in why
    finally:
        bw.is_root = original


def test_elevation_returns_a_reason_when_it_cannot_elevate():
    prefix, why = asyncio.run(bwtools.elevation("iftop"))
    # In a normal unprivileged test environment this is None; either way the
    # explanation must name what was checked rather than just "needs root".
    assert prefix is not None or all(
        word in why for word in ("root", "cap_net_raw", "sudo")
    )


def test_iftop_snapshot_accepts_an_elevation_prefix():
    result = asyncio.run(bwtools.iftop_snapshot("eth0", 2, prefix=["sudo", "-n"]))
    assert "iftop" in result.command
    if result.missing_tool:
        assert result.missing_tool != "sudo"      # never blame the wrong binary
