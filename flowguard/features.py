"""
Feature extraction layer.

Takes raw flow records (the kind you'd get from NetFlow/IPFIX/sFlow, or
summarized packet captures) and turns them into the numeric feature
vectors the detection models consume. Nothing here touches payload
bytes -- only metadata: timing, size, counts, and header-level fields
(ports, TTL, TLS/QUIC handshake fingerprints, DNS query strings).
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import Deque, Dict, List, Optional


@dataclass
class FlowRecord:
    """A single one-way flow observation (mirrored / diode traffic)."""

    flow_id: str
    timestamp: float          # epoch seconds
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str             # "TCP", "UDP", "ICMP"
    packet_count: int
    byte_count: int
    duration: float           # seconds
    tls_ja3: Optional[str] = None       # TLS/QUIC client fingerprint, if present
    dns_query: Optional[str] = None     # DNS question name, if this is a DNS flow
    ttl: Optional[int] = None


@dataclass
class FlowFeatures:
    """Numeric feature vector derived from a FlowRecord + rolling context."""

    flow_id: str
    pps: float                      # packets per second
    bps: float                      # bytes per second
    avg_pkt_size: float
    byte_ratio: float               # asymmetry proxy (byte_count vs rolling avg)
    inter_arrival_mean: float       # mean seconds between flows from this src
    inter_arrival_stdev: float      # low stdev + tight mean => beaconing
    dst_fanout: int                 # distinct destination IPs from this src recently
    port_fanout: int                # distinct destination ports from this src recently
    dns_entropy: float              # Shannon entropy of DNS query name (DGA signal)
    dns_query_len: int
    is_encrypted: bool
    ttl_delta: float                # deviation from this src's rolling modal TTL

    def as_vector(self) -> List[float]:
        """Fixed-order numeric vector for ML models."""
        return [
            self.pps,
            self.bps,
            self.avg_pkt_size,
            self.byte_ratio,
            self.inter_arrival_mean,
            self.inter_arrival_stdev,
            float(self.dst_fanout),
            float(self.port_fanout),
            self.dns_entropy,
            float(self.dns_query_len),
            1.0 if self.is_encrypted else 0.0,
            self.ttl_delta,
        ]

    @staticmethod
    def feature_names() -> List[str]:
        return [
            "pps", "bps", "avg_pkt_size", "byte_ratio",
            "inter_arrival_mean", "inter_arrival_stdev",
            "dst_fanout", "port_fanout", "dns_entropy",
            "dns_query_len", "is_encrypted", "ttl_delta",
        ]


def shannon_entropy(s: str) -> float:
    """Character-level Shannon entropy, used to flag DGA-style DNS names."""
    if not s:
        return 0.0
    freq: Dict[str, int] = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class RollingContext:
    """
    Maintains a small sliding window of recent history per source IP so
    features like fan-out, beaconing regularity, and TTL drift can be
    computed online, without needing to store full traffic history.
    """

    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        self._last_seen: Dict[str, float] = {}
        self._inter_arrivals: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self._dst_ips: Dict[str, Deque[str]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self._dst_ports: Dict[str, Deque[int]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self._byte_counts: Dict[str, Deque[int]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self._ttls: Dict[str, Deque[int]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )

    def update_and_get(self, flow: FlowRecord) -> Dict[str, float]:
        src = flow.src_ip

        # inter-arrival time for this source
        last_ts = self._last_seen.get(src)
        if last_ts is not None:
            self._inter_arrivals[src].append(max(flow.timestamp - last_ts, 0.0))
        self._last_seen[src] = flow.timestamp

        self._dst_ips[src].append(flow.dst_ip)
        self._dst_ports[src].append(flow.dst_port)
        self._byte_counts[src].append(flow.byte_count)
        if flow.ttl is not None:
            self._ttls[src].append(flow.ttl)

        ia = list(self._inter_arrivals[src])
        ia_mean = mean(ia) if ia else 0.0
        ia_std = pstdev(ia) if len(ia) > 1 else 0.0

        byte_hist = list(self._byte_counts[src])
        avg_bytes = mean(byte_hist) if byte_hist else flow.byte_count
        byte_ratio = (flow.byte_count / avg_bytes) if avg_bytes > 0 else 1.0

        ttl_hist = list(self._ttls[src])
        if ttl_hist and flow.ttl is not None:
            modal_ttl = max(set(ttl_hist), key=ttl_hist.count)
            ttl_delta = abs(flow.ttl - modal_ttl)
        else:
            ttl_delta = 0.0

        return {
            "inter_arrival_mean": ia_mean,
            "inter_arrival_stdev": ia_std,
            "dst_fanout": len(set(self._dst_ips[src])),
            "port_fanout": len(set(self._dst_ports[src])),
            "byte_ratio": byte_ratio,
            "ttl_delta": ttl_delta,
        }


class FeatureExtractor:
    """Stateful extractor: wraps a RollingContext and converts flows -> FlowFeatures."""

    def __init__(self, window_size: int = 50):
        self.ctx = RollingContext(window_size=window_size)

    def extract(self, flow: FlowRecord) -> FlowFeatures:
        ctx_feats = self.ctx.update_and_get(flow)

        pps = flow.packet_count / flow.duration if flow.duration > 0 else float(flow.packet_count)
        bps = flow.byte_count / flow.duration if flow.duration > 0 else float(flow.byte_count)
        avg_pkt_size = flow.byte_count / flow.packet_count if flow.packet_count > 0 else 0.0

        dns_entropy = shannon_entropy(flow.dns_query) if flow.dns_query else 0.0
        dns_len = len(flow.dns_query) if flow.dns_query else 0

        is_encrypted = flow.tls_ja3 is not None

        return FlowFeatures(
            flow_id=flow.flow_id,
            pps=pps,
            bps=bps,
            avg_pkt_size=avg_pkt_size,
            byte_ratio=ctx_feats["byte_ratio"],
            inter_arrival_mean=ctx_feats["inter_arrival_mean"],
            inter_arrival_stdev=ctx_feats["inter_arrival_stdev"],
            dst_fanout=int(ctx_feats["dst_fanout"]),
            port_fanout=int(ctx_feats["port_fanout"]),
            dns_entropy=dns_entropy,
            dns_query_len=dns_len,
            is_encrypted=is_encrypted,
            ttl_delta=ctx_feats["ttl_delta"],
        )
