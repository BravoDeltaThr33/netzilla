"""Shared test setup.

Device identification (netzilla.local.devices) sends real packets — DNS,
mDNS, NetBIOS, SSDP, TCP connects — to real LAN addresses. The sample
addresses in these tests (192.168.1.x, 10.0.0.x) may well be real devices on
the network of whoever runs the suite, so by default every probe is stubbed
out here: nothing leaves the machine, and tests stay fast. Tests that
exercise the identification logic feed it recorded replies explicitly.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_lan_probes(monkeypatch):
    from netzilla.local import devices

    async def no_exchange(*_args, **_kwargs):
        return []

    async def no_http(*_args, **_kwargs):
        return None

    async def no_ports(*_args, **_kwargs):
        return []

    async def empty_context():
        return {"self": {}, "networks": [], "gateways": set(),
                "default_interface": None}

    monkeypatch.setattr(devices, "udp_exchange", no_exchange)
    monkeypatch.setattr(devices, "http_get", no_http)
    monkeypatch.setattr(devices, "port_scan", no_ports)
    monkeypatch.setattr(devices, "local_context", empty_context)
