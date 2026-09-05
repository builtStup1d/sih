"""
Ties the layers together end to end:

    Stream ingest -> Feature extraction -> ML inference -> Alert engine

Matches the architecture slide. `FlowGuardPipeline.train()` fits the
anomaly + supervised models on labeled synthetic data; `run_stream()`
replays/consumes flows one at a time (as a true streaming system would)
and yields an Alert for each flow that crosses a threat threshold.
"""

from __future__ import annotations

import time
from typing import Callable, Iterable, Iterator, List, Optional, Tuple

from .alert_engine import Alert, AlertEngine
from .features import FeatureExtractor, FlowRecord
from .models import AnomalyDetector, HybridModel, RuleBasedDetector, SupervisedClassifier


class FlowGuardPipeline:
    def __init__(self, window_size: int = 50, min_confidence: float = 0.55):
        self.extractor = FeatureExtractor(window_size=window_size)
        self.rules = RuleBasedDetector()
        self.anomaly = AnomalyDetector()
        self.classifier = SupervisedClassifier()
        self.hybrid = HybridModel(self.rules, self.anomaly, self.classifier, min_confidence)
        self.alert_engine = AlertEngine()
        self._trained = False
        self.flows_processed = 0

    def train(self, labeled_flows: List[Tuple[FlowRecord, str]]) -> None:
        """Fit anomaly detector (unsupervised) and classifier (supervised)."""
        fe = FeatureExtractor(window_size=self.extractor.ctx.window_size)
        vectors, labels = [], []
        for flow, label in labeled_flows:
            feats = fe.extract(flow)
            vectors.append(feats.as_vector())
            labels.append(label)

        # Anomaly detector trains only on benign traffic, as intended.
        benign_vectors = [v for v, l in zip(vectors, labels) if l == "benign"]
        self.anomaly.fit(benign_vectors)

        self.classifier.fit(vectors, labels)
        self._trained = True

    def process_flow(self, flow: FlowRecord) -> Optional[Alert]:
        features = self.extractor.extract(flow)
        verdict = self.hybrid.predict(features)
        self.flows_processed += 1
        return self.alert_engine.process(flow, features, verdict)

    def run_stream(
        self,
        flows: Iterable[FlowRecord],
        on_alert: Optional[Callable[[Alert], None]] = None,
        realtime_replay: bool = False,
    ) -> List[Alert]:
        """
        Consume a stream of FlowRecords. If realtime_replay is True,
        sleeps between flows to mimic real inter-arrival timing (useful
        for the live demo); otherwise processes as fast as possible
        (useful for throughput testing).
        """
        produced: List[Alert] = []
        last_ts = None
        t0 = time.perf_counter()

        for flow in flows:
            if realtime_replay and last_ts is not None:
                gap = min(max(flow.timestamp - last_ts, 0.0), 2.0)  # cap for demo pacing
                time.sleep(gap)
            last_ts = flow.timestamp

            alert = self.process_flow(flow)
            if alert:
                produced.append(alert)
                if on_alert:
                    on_alert(alert)

        elapsed = max(time.perf_counter() - t0, 1e-9)
        self.last_run_throughput_fps = self.flows_processed / elapsed
        return produced
