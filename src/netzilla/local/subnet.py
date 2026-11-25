"""Subnet calculator — pure stdlib ipaddress, no API, no rate limit.

Calling a web API to do CIDR arithmetic would be slower, rate limited and
offline-fragile for maths Python already does perfectly.
"""

from __future__ import annotations

import ipaddress
from typing import Union

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def describe(network: Network) -> list[tuple[str, object]]:
    """Full breakdown of a network."""
    version = network.version
    rows: list[tuple[str, object]] = [
        ("Network", str(network)),
        ("IP version", f"IPv{version}"),
        ("Network address", str(network.network_address)),
        ("Prefix length", f"/{network.prefixlen}"),
        ("Netmask", str(network.netmask)),
    ]
    if version == 4:
        rows.append(("Wildcard mask", str(network.hostmask)))
        rows.append(("Broadcast address", str(network.broadcast_address)))

    total = network.num_addresses
    rows.append(("Total addresses", f"{total:,}"))

    if version == 4:
        if network.prefixlen <= 30:
            usable = max(total - 2, 0)
            hosts = list(network.hosts())
            first = str(hosts[0]) if hosts else "—"
            last = str(hosts[-1]) if hosts else "—"
        elif network.prefixlen == 31:
            # RFC 3021 point-to-point link: both addresses are usable.
            usable = 2
            first = str(network.network_address)
            last = str(network.broadcast_address)
        else:
            usable = 1
            first = last = str(network.network_address)
        rows.append(("Usable hosts", f"{usable:,}"))
        rows.append(("First usable", first))
        rows.append(("Last usable", last))
    else:
        rows.append(("First address", str(network.network_address)))
        rows.append(("Last address", str(network[-1])))

    rows.append(("Private (RFC1918/ULA)", network.is_private))
    rows.append(("Globally routable", network.is_global))
    rows.append(("Multicast", network.is_multicast))
    rows.append(("Loopback", network.is_loopback))
    rows.append(("Link-local", network.is_link_local))
    if version == 4:
        rows.append(("Binary netmask", _binary_v4(network.netmask)))
        rows.append(("Binary network", _binary_v4(network.network_address)))
    rows.append(("Reverse DNS zone", network.network_address.reverse_pointer))
    return rows


def split_into(network: Network, new_prefix: int, limit: int = 64) -> list[list[object]]:
    """Divide a network into equal subnets of `new_prefix` length."""
    if new_prefix <= network.prefixlen:
        raise ValueError(
            f"New prefix /{new_prefix} must be longer than /{network.prefixlen}."
        )
    max_prefix = 32 if network.version == 4 else 128
    if new_prefix > max_prefix:
        raise ValueError(f"/{new_prefix} is not valid for IPv{network.version}.")

    rows: list[list[object]] = []
    for index, subnet in enumerate(network.subnets(new_prefix=new_prefix)):
        if index >= limit:
            rows.append(["…", "…", "…", "…", "truncated"])
            break
        if subnet.version == 4 and subnet.prefixlen <= 30:
            hosts = list(subnet.hosts())
            first, last = str(hosts[0]), str(hosts[-1])
            usable = f"{len(hosts):,}"
        else:
            first = str(subnet.network_address)
            last = str(subnet[-1])
            usable = f"{subnet.num_addresses:,}"
        rows.append([
            index + 1,
            str(subnet),
            first,
            last,
            usable,
        ])
    return rows


def hosts_needed(network: Network, hosts: int) -> tuple[int, str]:
    """Smallest prefix inside `network` that fits `hosts` usable addresses."""
    if hosts < 1:
        raise ValueError("Host count must be at least 1.")
    max_prefix = 32 if network.version == 4 else 128
    needed = hosts + 2 if network.version == 4 and hosts > 1 else hosts
    for prefix in range(max_prefix, network.prefixlen - 1, -1):
        size = 2 ** (max_prefix - prefix)
        if size >= needed:
            return prefix, f"/{prefix} holds {size:,} addresses"
    raise ValueError(f"{hosts:,} hosts will not fit inside {network}.")


def contains(network: Network, address: str) -> bool:
    return ipaddress.ip_address(address) in network


def summarise_range(start: str, end: str) -> list[str]:
    """Smallest set of CIDR blocks covering an inclusive address range."""
    first = ipaddress.ip_address(start)
    last = ipaddress.ip_address(end)
    if first.version != last.version:
        raise ValueError("Start and end must be the same IP version.")
    if int(first) > int(last):
        first, last = last, first
    return [str(net) for net in ipaddress.summarize_address_range(first, last)]


def _binary_v4(address) -> str:
    octets = str(address).split(".")
    return ".".join(format(int(octet), "08b") for octet in octets)
