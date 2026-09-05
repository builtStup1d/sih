"""
Model layer: rules + anomaly detection + supervised classifier, combined
into one hybrid model. This mirrors the "explainability + flexibility"
design from the presentation: rules catch obvious/known patterns,
anomaly detection catches unknowns, and the supervised classifier
recognizes previously-labeled attack families.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from .features import FlowFeatures

THREAT_CLASSES = [
    "benign",
    "ddos",
    "botnet_beaconing",
    "dga_dns_tunneling",
    "encrypted_malware",
    "port_scan",
    "exfiltration",
]


@dataclass
class ModelVerdict:
    threat_class: str
    confidence: float
    source: str                 # "rule", "anomaly", "classifier", "hybrid"
    evidence: List[str]


# ---------------------------------------------------------------------------
# 1. Rule-based detector — cheap, explainable, catches obvious patterns
# ---------------------------------------------------------------------------
class RuleBasedDetector:
    def __init__(
        self,
        ddos_pps_threshold: float = 2000.0,
        scan_port_fanout_threshold: int = 15,
        scan_dst_fanout_threshold: int = 10,
        beacon_stdev_threshold: float = 0.5,
        beacon_min_mean: float = 1.0,
        dga_entropy_threshold: float = 3.8,
        exfil_bps_threshold: float = 5_000_000.0,
        exfil_byte_ratio_threshold: float = 4.0,
    ):
        self.ddos_pps_threshold = ddos_pps_threshold
        self.scan_port_fanout_threshold = scan_port_fanout_threshold
        self.scan_dst_fanout_threshold = scan_dst_fanout_threshold
        self.beacon_stdev_threshold = beacon_stdev_threshold
        self.beacon_min_mean = beacon_min_mean
        self.dga_entropy_threshold = dga_entropy_threshold
        self.exfil_bps_threshold = exfil_bps_threshold
        self.exfil_byte_ratio_threshold = exfil_byte_ratio_threshold

    def evaluate(self, f: FlowFeatures) -> Optional[ModelVerdict]:
        # DDoS: very high packet rate
        if f.pps >= self.ddos_pps_threshold:
            return ModelVerdict(
                "ddos", 0.9, "rule",
                [f"pps={f.pps:.0f} >= {self.ddos_pps_threshold:.0f}"],
            )

        # Port scanning / reconnaissance: fan-out across many ports/dsts, low volume
        if (f.port_fanout >= self.scan_port_fanout_threshold
                or f.dst_fanout >= self.scan_dst_fanout_threshold):
            return ModelVerdict(
                "port_scan", 0.85, "rule",
                [f"port_fanout={f.port_fanout}", f"dst_fanout={f.dst_fanout}"],
            )

        # DGA / DNS tunneling: high-entropy, long DNS query names
        if f.dns_query_len > 0 and f.dns_entropy >= self.dga_entropy_threshold:
            return ModelVerdict(
                "dga_dns_tunneling", 0.8, "rule",
                [f"dns_entropy={f.dns_entropy:.2f}", f"dns_len={f.dns_query_len}"],
            )

        # Botnet beaconing: tight, regular inter-arrival timing (low jitter)
        if (f.inter_arrival_mean >= self.beacon_min_mean
                and 0 < f.inter_arrival_stdev <= self.beacon_stdev_threshold):
            return ModelVerdict(
                "botnet_beaconing", 0.75, "rule",
                [f"ia_mean={f.inter_arrival_mean:.2f}s",
                 f"ia_stdev={f.inter_arrival_stdev:.2f}s (low jitter)"],
            )

        # Exfiltration: sustained high outbound rate with abnormal byte volume
        if f.bps >= self.exfil_bps_threshold and f.byte_ratio >= self.exfil_byte_ratio_threshold:
            return ModelVerdict(
                "exfiltration", 0.8, "rule",
                [f"bps={f.bps:.0f}", f"byte_ratio={f.byte_ratio:.2f}"],
            )

        return None


# ---------------------------------------------------------------------------
# 2. Anomaly detector — catches unknowns / novel behavior
# ---------------------------------------------------------------------------
class AnomalyDetector:
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.model = IsolationForest(
            contamination=contamination, random_state=random_state, n_estimators=150
        )
        self._fitted = False

    def fit(self, feature_vectors: List[List[float]]) -> None:
        X = np.array(feature_vectors)
        self.model.fit(X)
        self._fitted = True

    def evaluate(self, f: FlowFeatures) -> ModelVerdict:
        if not self._fitted:
            return ModelVerdict("benign", 0.0, "anomaly", ["anomaly model not trained"])
        x = np.array([f.as_vector()])
        score = self.model.decision_function(x)[0]     # higher = more normal
        is_anomaly = self.model.predict(x)[0] == -1
        # map decision_function score (~[-0.5, 0.5]) to a 0-1 anomaly confidence
        confidence = float(np.clip(0.5 - score, 0.0, 1.0))
        if is_anomaly:
            return ModelVerdict(
                "anomalous_unclassified", confidence, "anomaly",
                [f"isolation_forest_score={score:.3f}"],
            )
        return ModelVerdict("benign", 1.0 - confidence, "anomaly", [])


# ---------------------------------------------------------------------------
# 3. Supervised classifier — recognizes known, previously-labeled attacks
# ---------------------------------------------------------------------------
class SupervisedClassifier:
    def __init__(self, random_state: int = 42):
        self.model = RandomForestClassifier(
            n_estimators=200, max_depth=10, random_state=random_state
        )
        self._fitted = False

    def fit(self, feature_vectors: List[List[float]], labels: List[str]) -> None:
        X = np.array(feature_vectors)
        self.model.fit(X, labels)
        self._fitted = True

    def evaluate(self, f: FlowFeatures) -> ModelVerdict:
        if not self._fitted:
            return ModelVerdict("benign", 0.0, "classifier", ["classifier not trained"])
        x = np.array([f.as_vector()])
        probs = self.model.predict_proba(x)[0]
        classes = self.model.classes_
        top_idx = int(np.argmax(probs))
        return ModelVerdict(
            str(classes[top_idx]), float(probs[top_idx]), "classifier",
            [f"p({classes[top_idx]})={probs[top_idx]:.2f}"],
        )


# ---------------------------------------------------------------------------
# Hybrid combiner
# ---------------------------------------------------------------------------
class HybridModel:
    """
    Combines rule, anomaly, and classifier verdicts:
      1. A confident rule match wins immediately (explainable, cheap).
      2. Otherwise, take the higher-confidence of classifier vs anomaly.
      3. If nothing crosses the confidence floor, call it benign.
    """

    def __init__(
        self,
        rules: RuleBasedDetector,
        anomaly: AnomalyDetector,
        classifier: SupervisedClassifier,
        min_confidence: float = 0.55,
    ):
        self.rules = rules
        self.anomaly = anomaly
        self.classifier = classifier
        self.min_confidence = min_confidence

    def predict(self, f: FlowFeatures) -> ModelVerdict:
        rule_hit = self.rules.evaluate(f)
        if rule_hit is not None:
            return rule_hit

        clf_verdict = self.classifier.evaluate(f)
        anomaly_verdict = self.anomaly.evaluate(f)

        candidates = [clf_verdict, anomaly_verdict]
        candidates.sort(key=lambda v: v.confidence, reverse=True)
        best = candidates[0]

        if best.threat_class == "benign" or best.confidence < self.min_confidence:
            return ModelVerdict("benign", best.confidence, "hybrid", [])

        return ModelVerdict(
            best.threat_class, best.confidence, "hybrid",
            best.evidence + [f"combined_from={best.source}"],
        )
