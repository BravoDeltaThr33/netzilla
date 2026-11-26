"""Built-in speed test against Cloudflare's free speed-test endpoints.

The same endpoints speed.cloudflare.com itself uses — free, no key, no
account, nothing to install:

    GET  https://speed.cloudflare.com/__down?bytes=N   N bytes of zeros
    POST https://speed.cloudflare.com/__up             discards the body

Each response carries `cf-meta-*` headers (your IP, ASN, country, city and
the Cloudflare data centre that answered) and a Server-Timing header saying
how long the server itself spent, which is taken off each latency sample.

What it measures, in order:

  latency      20 empty requests, one at a time: median and jitter (the
               mean change from one sample to the next)
  download     4 parallel streams for DOWN_SECONDS, sampled every quarter
               second, so the graph moves while it runs
  upload       the same, the other way, for UP_SECONDS
  bufferbloat  latency measured *while the download runs*; the rise over
               idle latency is what makes calls stutter when someone else is
               downloading. Graded like the well-known bufferbloat tests.

Data use is capped (DOWN_CAP / UP_CAP), so a fast link finishes early rather
than pulling gigabytes.
"""

from __future__ import annotations

import asyncio
import os
import re
import statistics
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

BASE = "https://speed.cloudflare.com"
STREAMS = 4
DOWN_SECONDS = 8.0
UP_SECONDS = 6.0
DOWN_CAP = 400_000_000          # bytes
UP_CAP = 150_000_000
SAMPLE_EVERY = 0.25
LATENCY_SAMPLES = 20
RAMP_SECONDS = 1.0              # ignored at the start of each phase (TCP ramp-up)

_SERVER_DUR = re.compile(r"cfSpeedWorker;dur=([\d.]+)")
_REQUEST_DUR = re.compile(r"cfRequestDuration;dur=([\d.]+)")


@dataclass
class Progress:
    """What the live view draws: the phase and every sample so far."""

    phase: str = "latency"                       # latency | download | upload | done
    down: list[float] = field(default_factory=list)      # Mbit/s per sample
    up: list[float] = field(default_factory=list)
    latency: list[float] = field(default_factory=list)   # ms, idle
    loaded: list[float] = field(default_factory=list)    # ms, during download
    meta: dict = field(default_factory=dict)
    now_mbps: float = 0.0


Callback = Callable[[Progress], None | Awaitable[None]]


def _server_ms(headers) -> float:
    value = headers.get("server-timing", "") or ""
    match = _SERVER_DUR.search(value) or _REQUEST_DUR.search(value)
    try:
        return float(match.group(1)) if match else 0.0
    except ValueError:
        return 0.0


def _meta(headers) -> dict:
    out = {}
    for key in ("ip", "asn", "country", "city", "colo", "timezone"):
        value = headers.get(f"cf-meta-{key}")
        if value:
            out[key] = value
    if "colo" not in out:
        # CF-RAY ends in the answering data centre: "a525995a19ec7dae-IAD".
        ray = headers.get("cf-ray") or ""
        if "-" in ray:
            out["colo"] = ray.rsplit("-", 1)[1][:4].upper()
    return out


async def _emit(callback: Callback | None, progress: Progress) -> None:
    if callback is None:
        return
    result = callback(progress)
    if asyncio.iscoroutine(result):
        await result


async def _ping(client, progress: Progress | None = None) -> float | None:
    started = time.perf_counter()
    try:
        response = await client.get(f"{BASE}/__down", params={"bytes": "0"})
    except Exception:
        return None
    elapsed = (time.perf_counter() - started) * 1000.0
    if progress is not None and not progress.meta:
        progress.meta = _meta(response.headers)
    return max(0.1, elapsed - _server_ms(response.headers))


def jitter(samples: list[float]) -> float:
    if len(samples) < 2:
        return 0.0
    return statistics.fmean(abs(b - a) for a, b in zip(samples, samples[1:]))


def bufferbloat_grade(idle_ms: float, loaded_ms: float) -> tuple[str, float]:
    """(grade, added milliseconds) — A+ under 5 ms of added latency, F over 400."""
    added = max(0.0, loaded_ms - idle_ms)
    for limit, grade in ((5, "A+"), (30, "A"), (60, "B"), (200, "C"), (400, "D")):
        if added < limit:
            return grade, added
    return "F", added


async def _phase(sampler_list: list[float], progress: Progress, callback: Callback | None,
                 workers: list[Callable[[], Awaitable[None]]], counter: dict,
                 seconds: float, cap: int) -> float:
    """Run the workers, sampling the shared byte counter; returns Mbit/s."""
    tasks = [asyncio.create_task(work()) for work in workers]
    started = time.perf_counter()
    last_at, last_bytes = started, 0
    steady_from, steady_bytes = None, 0
    try:
        while True:
            await asyncio.sleep(SAMPLE_EVERY)
            now = time.perf_counter()
            done_bytes = counter["bytes"]
            mbps = (done_bytes - last_bytes) * 8 / max(1e-6, now - last_at) / 1e6
            last_at, last_bytes = now, done_bytes
            sampler_list.append(round(mbps, 2))
            progress.now_mbps = mbps
            if steady_from is None and now - started >= RAMP_SECONDS:
                steady_from, steady_bytes = now, done_bytes
            await _emit(callback, progress)
            if now - started >= seconds or done_bytes >= cap or \
                    all(task.done() for task in tasks):
                break
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    end = time.perf_counter()
    if steady_from is not None and end - steady_from > 0.2:
        return (counter["bytes"] - steady_bytes) * 8 / (end - steady_from) / 1e6
    return counter["bytes"] * 8 / max(1e-6, end - started) / 1e6


async def run(callback: Callback | None = None, user_agent: str = "netzilla") -> dict:
    """Run the whole test; returns the results dict SPEED shows."""
    import httpx

    progress = Progress()
    timeout = httpx.Timeout(30.0, connect=10.0)
    limits = httpx.Limits(max_connections=STREAMS + 2, max_keepalive_connections=STREAMS + 2)
    headers = {"User-Agent": user_agent, "Referer": "https://speed.cloudflare.com/"}
    async with httpx.AsyncClient(timeout=timeout, limits=limits, headers=headers,
                                 follow_redirects=True) as client:
        # ---------------------------------------------------------- latency
        progress.phase = "latency"
        await _emit(callback, progress)
        for _ in range(LATENCY_SAMPLES):
            sample = await _ping(client, progress)
            if sample is not None:
                progress.latency.append(round(sample, 2))
                await _emit(callback, progress)
        if not progress.latency:
            raise RuntimeError(
                "speed.cloudflare.com did not answer — no internet connection, or "
                "a proxy or firewall is blocking it."
            )

        # --------------------------------------------------------- download
        progress.phase = "download"
        down_counter = {"bytes": 0}
        stop = {"flag": False}

        async def downloader() -> None:
            size = 25_000_000
            while not stop["flag"]:
                async with client.stream("GET", f"{BASE}/__down",
                                         params={"bytes": str(size)}) as response:
                    async for chunk in response.aiter_raw(65536):
                        down_counter["bytes"] += len(chunk)
                        if stop["flag"]:
                            return

        async def loaded_pinger() -> None:
            # Latency under load, on its own connection pool.
            async with httpx.AsyncClient(timeout=timeout, headers=headers) as pinger:
                while not stop["flag"]:
                    sample = await _ping(pinger)
                    if sample is not None:
                        progress.loaded.append(round(sample, 2))
                    await asyncio.sleep(0.35)

        pinger = asyncio.create_task(loaded_pinger())
        try:
            down = await _phase(progress.down, progress, callback,
                                [downloader] * STREAMS, down_counter,
                                DOWN_SECONDS, DOWN_CAP)
        finally:
            stop["flag"] = True
            pinger.cancel()
            await asyncio.gather(pinger, return_exceptions=True)

        # ----------------------------------------------------------- upload
        progress.phase = "upload"
        up_counter = {"bytes": 0}
        stop["flag"] = False
        block = os.urandom(1 << 20)

        async def body():
            sent = 0
            while sent < 8_000_000 and not stop["flag"]:
                for offset in range(0, len(block), 65536):
                    chunk = block[offset:offset + 65536]
                    up_counter["bytes"] += len(chunk)
                    sent += len(chunk)
                    yield chunk

        async def uploader() -> None:
            while not stop["flag"]:
                await client.post(f"{BASE}/__up", content=body(),
                                  headers={"Content-Type": "application/octet-stream"})

        try:
            up = await _phase(progress.up, progress, callback,
                              [uploader] * STREAMS, up_counter, UP_SECONDS, UP_CAP)
        finally:
            stop["flag"] = True

    progress.phase = "done"
    await _emit(callback, progress)
    idle = statistics.median(progress.latency)
    loaded = statistics.median(progress.loaded) if progress.loaded else idle
    grade, added = bufferbloat_grade(idle, loaded)
    meta = progress.meta
    return {
        "download_mbps": down,
        "upload_mbps": up,
        "ping_ms": idle,
        "jitter_ms": jitter(progress.latency),
        "loaded_ms": loaded,
        "bufferbloat": grade,
        "bufferbloat_added_ms": added,
        "server_name": "Cloudflare" + (f" {meta['colo']}" if meta.get("colo") else ""),
        "server_location": meta.get("colo"),
        "server_host": "speed.cloudflare.com",
        "distance_km": None,
        "client_isp": f"AS{meta['asn']}" if meta.get("asn") else None,
        "client_ip": meta.get("ip"),
        "client_place": ", ".join(p for p in (meta.get("city"), meta.get("country")) if p),
        "share_url": None,
        "backend": "Cloudflare (built in)",
        "down_samples": list(progress.down),
        "up_samples": list(progress.up),
        "downloaded_bytes": down_counter["bytes"],
        "uploaded_bytes": up_counter["bytes"],
    }


__all__ = ["run", "Progress", "bufferbloat_grade", "jitter", "BASE"]
