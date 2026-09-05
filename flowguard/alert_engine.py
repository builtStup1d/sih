"""
Alert layer. Converts a (FlowRecord, FlowFeatures, ModelVerdict) triple
into a standardized Alert object: timestamp, flow ID, threat class,
confidence, evidence, and severity — matching the alert format on the
"Alert Format" slide.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from .features import FlowFeatures
from .features import FlowRecord
from .models import ModelVerdict

SEVERITY_MAP = {
    "benign": "info",
    "anomalous_unclassified": "medium",
    "port_scan": "medium",
    "botnet_beaconing": "high",
    "dga_dns_tunneling": "high",
    "encrypted_malware": "high",
    "ddos": "critical",
    "exfiltration": "critical",
}


@dataclass
class Alert:
    timestamp: str
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    threat_class: str
    confidence: float
    severity: str
    evidence: List[str]
    model_source: str

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class AlertEngine:
    def __init__(self, benign_class: str = "benign"):
        self.benign_class = benign_class
        self.alerts: List[Alert] = []

    def process(
        self, flow: FlowRecord, features: FlowFeatures, verdict: ModelVerdict
    ) -> Optional[Alert]:
        if verdict.threat_class == self.benign_class:
            return None

        alert = Alert(
            timestamp=datetime.fromtimestamp(flow.timestamp, tz=timezone.utc).isoformat(),
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            threat_class=verdict.threat_class,
            confidence=round(verdict.confidence, 3),
            severity=SEVERITY_MAP.get(verdict.threat_class, "medium"),
            evidence=verdict.evidence,
            model_source=verdict.source,
        )
        self.alerts.append(alert)
        return alert

    def by_class(self, threat_class: str) -> List[Alert]:
        return [a for a in self.alerts if a.threat_class == threat_class]

    def export_json(self, path: str) -> None:
        with open(path, "w") as fh:
            json.dump([a.to_dict() for a in self.alerts], fh, indent=2)

    def export_csv(self, path: str) -> None:
        import csv
        if not self.alerts:
            return
        fieldnames = list(self.alerts[0].to_dict().keys())
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for a in self.alerts:
                row = a.to_dict()
                row["evidence"] = "; ".join(row["evidence"])
                writer.writerow(row)
