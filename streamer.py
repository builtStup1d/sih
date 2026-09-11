"""
Continuous real-time traffic generator for the FlowGuard AI API server.

Runs on a background thread: emits FlowRecord objects at a configurable
rate, runs each one through the trained pipeline (feature extraction ->
hybrid model inference -> alert engine), persists every flow to SQLite,
and broadcasts live events (flow / alert / stats) to connected WebSocket
clients.

The simulated mix interleaves benign background traffic with randomly
scheduled attack episodes (scan, beaconing, DGA, exfiltration, malware,
DDoS burst) so the dashboard always has something live to show.
"""

from __future__ import annotations

import random
import string
import threading
import time
from typing import Callable, List, Optional, Tuple

from flowguard.features import FlowRecord

random.seed(int(time.time() * 1000) % 2**32)

PRIVATE_SUBNET = "10.0.{}.{}"

FlowEvent = Callable[[FlowRecord], None]


def _rand_ip(octet3_range=(0, 20)) -> str:
    return PRIVATE_SUBNET.format(random.randint(*octet3_range), random.randint(2, 254))


def _rand_ja3() -> str:
    return "".join(random.choices(string.hexdigits.lower(), k=32))


def _dga_domain() -> str:
    length = random.randint(16, 28)
    body = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{body}.{random.choice(['com', 'net', 'info', 'biz'])}"


def _normal_domain() -> str:
    return random.choice(
        ["mail.company.com", "api.vendor.io", "cdn.assets.net", "erp.internal.local"]
    )


def _gen_benign(ts: float) -> FlowRecord:
    return FlowRecord(
        flow_id=f"flow-{ts:.3f}",
        timestamp=ts,
        src_ip=_rand_ip((1, 10)),
        dst_ip=_rand_ip((30, 60)),
        src_port=random.randint(1024, 65535),
        dst_port=random.choice([443, 443, 443, 80, 22, 3389]),
        protocol="TCP",
        packet_count=random.randint(5, 120),
        byte_count=random.randint(1000, 50000),
        duration=random.uniform(0.2, 4.0),
        tls_ja3=_rand_ja3() if random.random() < 0.7 else None,
        dns_query=_normal_domain() if random.random() < 0.15 else None,
        ttl=64,
    )


def _gen_ddos(ts: float) -> FlowRecord:
    return FlowRecord(
        flow_id=f"ddos-{ts:.3f}",
        timestamp=ts,
        src_ip=_rand_ip((70, 90)),
        dst_ip="10.0.100.10",
        src_port=random.randint(1024, 65535),
        dst_port=80,
        protocol="UDP",
        packet_count=random.randint(3000, 9000),
        byte_count=random.randint(300000, 900000),
        duration=random.uniform(0.5, 1.5),
        ttl=random.randint(40, 60),
    )


def _gen_port_scan(ts: float) -> FlowRecord:
    return FlowRecord(
        flow_id=f"scan-{ts:.3f}",
        timestamp=ts,
        src_ip=_rand_ip((91, 91)),
        dst_ip="10.0.100.20",
        src_port=random.randint(1024, 65535),
        dst_port=random.randint(1, 1024),
        protocol="TCP",
        packet_count=random.randint(1, 3),
        byte_count=random.randint(40, 120),
        duration=random.uniform(0.01, 0.1),
        ttl=64,
    )


def _gen_beaconing(ts: float) -> FlowRecord:
    return FlowRecord(
        flow_id=f"beacon-{ts:.3f}",
        timestamp=ts,
        src_ip=_rand_ip((92, 92)),
        dst_ip=_rand_ip((200, 210)),
        src_port=random.randint(1024, 65535),
        dst_port=443,
        protocol="TCP",
        packet_count=random.randint(4, 8),
        byte_count=random.randint(300, 600),
        duration=random.uniform(0.1, 0.3),
        tls_ja3="e7d705a3286e19ea42f587b344ee6865",
        ttl=64,
    )


def _gen_dga(ts: float) -> FlowRecord:
    return FlowRecord(
        flow_id=f"dga-{ts:.3f}",
        timestamp=ts,
        src_ip=_rand_ip((93, 93)),
        dst_ip="10.0.53.1",
        src_port=random.randint(1024, 65535),
        dst_port=53,
        protocol="UDP",
        packet_count=2,
        byte_count=random.randint(80, 200),
        duration=0.05,
        dns_query=_dga_domain(),
        ttl=64,
    )


def _gen_exfiltration(ts: float) -> FlowRecord:
    return FlowRecord(
        flow_id=f"exfil-{ts:.3f}",
        timestamp=ts,
        src_ip=_rand_ip((94, 94)),
        dst_ip=_rand_ip((220, 230)),
        src_port=random.randint(1024, 65535),
        dst_port=443,
        protocol="TCP",
        packet_count=random.randint(2000, 5000),
        byte_count=random.randint(2400000, 7500000),
        duration=random.uniform(2.0, 5.0),
        tls_ja3=_rand_ja3(),
        ttl=64,
    )


def _gen_encrypted_malware(ts: float) -> FlowRecord:
    return FlowRecord(
        flow_id=f"malware-{ts:.3f}",
        timestamp=ts,
        src_ip=_rand_ip((95, 95)),
        dst_ip=_rand_ip((240, 250)),
        src_port=random.randint(1024, 65535),
        dst_port=443,
        protocol="TCP",
        packet_count=random.randint(10, 40),
        byte_count=random.randint(2000, 8000),
        duration=random.uniform(0.5, 2.0),
        tls_ja3="771,4865-4866-4867,0-23-65281,29-23-24,0",
        ttl=random.randint(50, 55),
    )


EPISODE_GENERATORS: List[Tuple[str, Callable[[float], FlowRecord]]] = [
    ("port_scan", _gen_port_scan),
    ("botnet_beaconing", _gen_beaconing),
    ("dga_dns_tunneling", _gen_dga),
    ("exfiltration", _gen_exfiltration),
    ("encrypted_malware", _gen_encrypted_malware),
    ("ddos", _gen_ddos),
]


class TrafficStreamer:
    """Continuous real-time traffic generator.

    Emits a realistic traffic mix on a background thread. Unlike a raw
    ``threading.Thread`` (which can only be started once and is permanent
    once it exits), this class spawns a *fresh* worker thread on every
    ``start()`` so the stream can be stopped and restarted repeatedly
    (e.g. via the API ``/api/stream/stop`` + ``/api/stream/start`` or
    ``/api/reset``).

    Parameters
    ----------
    on_event : callable
        Invoked with each generated FlowRecord (analysis, persistence,
        broadcast all happen here).
    rate_hz : float
        Baseline benign-flow cadence (flows per second).
    episode_every : float
        Average seconds between attack-episode starts.
    episode_span : float
        How long one attack episode lasts (seconds).
    live_pace : bool
        When True, wall-clock sleep tracks the synthetic timestamps so the
        stream behaves like a real live feed. When False, sleeps are capped
        to make the dashboard livelier (timestamps still advance normally).
    """

    def __init__(
        self,
        on_event: FlowEvent,
        rate_hz: float = 3.0,
        episode_every: float = 20.0,
        episode_span: float = 8.0,
        live_pace: bool = True,
    ):
        self.on_event = on_event
        self._rate = rate_hz
        self._episode_every = episode_every
        self._episode_span = episode_span
        self._live_pace = live_pace
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._count = 0
        self._t0 = time.time()
        self._thread: Optional[threading.Thread] = None

        self._episode: Optional[Tuple[str, Callable[[float], FlowRecord]]] = None
        self._episode_deadline = 0.0
        self._next_episode = 0.0
        self._ts = time.time()

    # -- introspection ----------------------------------------------------

    @property
    def running(self) -> bool:
        thread = self._thread
        return bool(thread and thread.is_alive())

    @property
    def processed(self) -> int:
        with self._lock:
            return self._count

    @property
    def throughput_fps(self) -> float:
        with self._lock:
            return self._count / max(time.time() - self._t0, 1e-9)

    # -- controls ---------------------------------------------------------

    def start(self) -> None:
        """Begin (or resume) streaming on a fresh background thread."""
        if self.running:
            return
        self._stop.clear()
        thread = threading.Thread(
            target=self._loop, daemon=True, name="flowguard-streamer"
        )
        self._thread = thread
        thread.start()

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float | None = None) -> None:
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)

    def set_rate(self, rate_hz: float) -> None:
        with self._lock:
            self._rate = max(0.5, float(rate_hz))

    @property
    def rate_hz(self) -> float:
        with self._lock:
            return self._rate

    def _bump_count(self) -> None:
        with self._lock:
            self._count += 1

    # -- generation -------------------------------------------------------

    def _episode_step(self, episode_name: Optional[str]) -> float:
        """Wall-clock sleep between consecutive flows for the current mix."""
        if episode_name is None:
            step = random.uniform(0.4, 2.5) / max(self.rate_hz, 0.5)
        else:
            step = {
                "port_scan": 0.03,
                "botnet_beaconing": 1.0,
                "dga_dns_tunneling": 0.4,
                "exfiltration": 0.5,
                "encrypted_malware": 0.6,
                "ddos": 0.03,
            }.get(episode_name, 0.5)
        # The synthetic timestamp advances with the same cadence so the
        # time-series data stays self-consistent.
        self._ts += step
        if not self._live_pace:
            step = min(step, 0.35)
        return step

    def _schedule(self, now: float) -> Optional[str]:
        """Return the active generator name for time *now*."""
        if self._episode is None:
            if now >= self._next_episode:
                pick = random.choice(EPISODE_GENERATORS)
                self._episode = pick
                self._episode_deadline = now + self._episode_span
            return None

        name = self._episode[0]
        if now >= self._episode_deadline:
            self._episode = None
            self._next_episode = now + random.uniform(
                self._episode_every, self._episode_every * 1.8
            )
            return None
        return name

    def _loop(self) -> None:
        now = time.time()
        self._next_episode = now + random.uniform(self._episode_every, self._episode_every * 1.6)

        while not self._stop.wait(0):
            now = time.time()
            episode_name = self._schedule(now)
            step = self._episode_step(episode_name)

            if episode_name is not None:
                flow = self._episode[1](self._ts)
            else:
                flow = _gen_benign(self._ts)

            try:
                self.on_event(flow)
                self._bump_count()
            except Exception as exc:  # never kill the stream thread
                print(f"[streamer] on_event failed: {exc}")
                time.sleep(0.5)
                continue

            if self._stop.wait(step):
                break