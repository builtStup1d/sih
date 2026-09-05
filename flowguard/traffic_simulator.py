"""
Synthetic traffic generator. Stands in for the real ingest source
(packet capture replay or a NetFlow/IPFIX/sFlow feed) so the pipeline
can be trained and demoed without a live network tap. Produces
FlowRecord objects labeled with their ground-truth class, which is
used only for training/evaluation -- never fed to the model at
inference time.
"""

from __future__ import annotations

import random
import string
import time
from typing import Iterator, List, Tuple

from .features import FlowRecord

random.seed(7)

PRIVATE_SUBNET = "10.0.{}.{}"


def _rand_ip(octet3_range=(0, 20)) -> str:
    return PRIVATE_SUBNET.format(random.randint(*octet3_range), random.randint(2, 254))


def _rand_ja3() -> str:
    return "".join(random.choices(string.hexdigits.lower(), k=32))


def _dga_domain() -> str:
    length = random.randint(16, 28)
    body = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    tld = random.choice(["com", "net", "info", "biz"])
    return f"{body}.{tld}"


def _normal_domain() -> str:
    return random.choice(
        ["mail.company.com", "api.vendor.io", "cdn.assets.net", "erp.internal.local"]
    )


def gen_benign(n: int, start_ts: float, src_pool: List[str]) -> List[Tuple[FlowRecord, str]]:
    out = []
    ts = start_ts
    for i in range(n):
        ts += random.uniform(0.5, 6.0)
        src = random.choice(src_pool)
        pkt = random.randint(5, 120)
        dur = random.uniform(0.2, 4.0)
        flow = FlowRecord(
            flow_id=f"benign-{i}",
            timestamp=ts,
            src_ip=src,
            dst_ip=_rand_ip((30, 60)),
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([443, 443, 443, 80, 22, 3389]),
            protocol="TCP",
            packet_count=pkt,
            byte_count=pkt * random.randint(300, 900),
            duration=dur,
            tls_ja3=_rand_ja3() if random.random() < 0.7 else None,
            dns_query=_normal_domain() if random.random() < 0.15 else None,
            ttl=64,
        )
        out.append((flow, "benign"))
    return out


def gen_ddos(n: int, start_ts: float) -> List[Tuple[FlowRecord, str]]:
    out = []
    ts = start_ts
    attacker_ips = [_rand_ip((70, 90)) for _ in range(5)]
    for i in range(n):
        ts += random.uniform(0.01, 0.05)
        pkt = random.randint(3000, 9000)
        dur = random.uniform(0.5, 1.5)
        flow = FlowRecord(
            flow_id=f"ddos-{i}",
            timestamp=ts,
            src_ip=random.choice(attacker_ips),
            dst_ip="10.0.100.10",
            src_port=random.randint(1024, 65535),
            dst_port=80,
            protocol="UDP",
            packet_count=pkt,
            byte_count=pkt * random.randint(60, 100),
            duration=dur,
            ttl=random.randint(40, 60),
        )
        out.append((flow, "ddos"))
    return out


def gen_port_scan(n: int, start_ts: float) -> List[Tuple[FlowRecord, str]]:
    out = []
    ts = start_ts
    scanner_ip = _rand_ip((91, 91))
    target_ip = "10.0.100.20"
    for i in range(n):
        ts += random.uniform(0.02, 0.2)
        flow = FlowRecord(
            flow_id=f"scan-{i}",
            timestamp=ts,
            src_ip=scanner_ip,
            dst_ip=target_ip,
            src_port=random.randint(1024, 65535),
            dst_port=random.randint(1, 1024),
            protocol="TCP",
            packet_count=random.randint(1, 3),
            byte_count=random.randint(40, 120),
            duration=random.uniform(0.01, 0.1),
            ttl=64,
        )
        out.append((flow, "port_scan"))
    return out


def gen_beaconing(n: int, start_ts: float) -> List[Tuple[FlowRecord, str]]:
    out = []
    ts = start_ts
    bot_ip = _rand_ip((92, 92))
    c2_ip = _rand_ip((200, 210))
    interval = 5.0  # very regular
    for i in range(n):
        ts += interval + random.uniform(-0.05, 0.05)  # tight jitter
        flow = FlowRecord(
            flow_id=f"beacon-{i}",
            timestamp=ts,
            src_ip=bot_ip,
            dst_ip=c2_ip,
            src_port=random.randint(1024, 65535),
            dst_port=443,
            protocol="TCP",
            packet_count=random.randint(4, 8),
            byte_count=random.randint(300, 600),
            duration=random.uniform(0.1, 0.3),
            tls_ja3="e7d705a3286e19ea42f587b344ee6865",  # fixed fingerprint -> known-bad
            ttl=64,
        )
        out.append((flow, "botnet_beaconing"))
    return out


def gen_dga(n: int, start_ts: float) -> List[Tuple[FlowRecord, str]]:
    out = []
    ts = start_ts
    infected_ip = _rand_ip((93, 93))
    for i in range(n):
        ts += random.uniform(1.0, 3.0)
        flow = FlowRecord(
            flow_id=f"dga-{i}",
            timestamp=ts,
            src_ip=infected_ip,
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
        out.append((flow, "dga_dns_tunneling"))
    return out


def gen_exfiltration(n: int, start_ts: float) -> List[Tuple[FlowRecord, str]]:
    out = []
    ts = start_ts
    insider_ip = _rand_ip((94, 94))
    ext_ip = _rand_ip((220, 230))
    for i in range(n):
        ts += random.uniform(0.5, 1.5)
        pkt = random.randint(2000, 5000)
        flow = FlowRecord(
            flow_id=f"exfil-{i}",
            timestamp=ts,
            src_ip=insider_ip,
            dst_ip=ext_ip,
            src_port=random.randint(1024, 65535),
            dst_port=443,
            protocol="TCP",
            packet_count=pkt,
            byte_count=pkt * random.randint(1200, 1500),
            duration=random.uniform(2.0, 5.0),
            tls_ja3=_rand_ja3(),
            ttl=64,
        )
        out.append((flow, "exfiltration"))
    return out


def gen_encrypted_malware(n: int, start_ts: float) -> List[Tuple[FlowRecord, str]]:
    out = []
    ts = start_ts
    infected_ip = _rand_ip((95, 95))
    for i in range(n):
        ts += random.uniform(0.3, 1.2)
        flow = FlowRecord(
            flow_id=f"malware-{i}",
            timestamp=ts,
            src_ip=infected_ip,
            dst_ip=_rand_ip((240, 250)),
            src_port=random.randint(1024, 65535),
            dst_port=443,
            protocol="TCP",
            packet_count=random.randint(10, 40),
            byte_count=random.randint(2000, 8000),
            duration=random.uniform(0.5, 2.0),
            tls_ja3="771,4865-4866-4867,0-23-65281,29-23-24,0",  # known-bad JA3
            ttl=random.randint(50, 55),
        )
        out.append((flow, "encrypted_malware"))
    return out


def build_training_set(base_ts: float = 1_700_000_000.0):
    """Balanced-ish labeled dataset used to fit the anomaly + supervised models."""
    src_pool = [_rand_ip((1, 10)) for _ in range(8)]
    data: List[Tuple[FlowRecord, str]] = []
    data += gen_benign(400, base_ts, src_pool)
    data += gen_ddos(60, base_ts)
    data += gen_port_scan(60, base_ts)
    data += gen_beaconing(40, base_ts)
    data += gen_dga(40, base_ts)
    data += gen_exfiltration(40, base_ts)
    data += gen_encrypted_malware(40, base_ts)
    data.sort(key=lambda t: t[0].timestamp)
    return data


def build_demo_stream(base_ts: float | None = None):
    """
    A shorter, interleaved stream used for the live 2-3 minute demo:
    normal background traffic with a scan, a beaconing burst, and an
    exfiltration episode mixed in, in chronological order.
    """
    base_ts = base_ts or time.time()
    src_pool = [_rand_ip((1, 10)) for _ in range(5)]
    data: List[Tuple[FlowRecord, str]] = []
    data += gen_benign(60, base_ts, src_pool)
    data += gen_port_scan(25, base_ts + 5)
    data += gen_beaconing(8, base_ts + 15)
    data += gen_exfiltration(10, base_ts + 40)
    data += gen_dga(10, base_ts + 55)
    data.sort(key=lambda t: t[0].timestamp)
    return data
