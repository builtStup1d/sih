# FlowGuard AI — Reference Implementation

Passive, AI-based detection of cyber threats in unidirectional (one-way)
IP traffic. Matches the architecture in the presentation:

```
Stream ingest -> Feature extraction -> ML inference -> Alert engine -> Dashboard
```

Everything operates on metadata only — no payload decryption, no probes
sent back toward the source, no mitigation actions.

## Project layout

```
flowguard/
  flowguard/
    features.py           # FlowRecord model + rolling feature extraction
    models.py              # RuleBasedDetector, AnomalyDetector (IsolationForest),
                            # SupervisedClassifier (RandomForest), HybridModel
    alert_engine.py         # Alert model + AlertEngine (JSON/CSV export)
    traffic_simulator.py    # Synthetic benign + attack traffic generator
    pipeline.py              # FlowGuardPipeline: ties ingest->features->model->alerts
    dashboard.py             # Console alert renderer + summary table
  demo.py                    # End-to-end runnable demo (matches the demo script slide)
  requirements.txt
```

## Threats covered

DDoS, botnet beaconing, DGA/DNS tunneling, encrypted malware traffic,
reconnaissance/port scanning, and data exfiltration — each detected
through a distinct behavioral signal (rate, entropy, timing regularity,
fan-out, byte asymmetry, TLS/QUIC fingerprints).

## Quickstart

```bash
pip install -r requirements.txt
python demo.py                                  # fast replay + summary
python demo.py --filter botnet_beaconing         # filter the alert view
python demo.py --realtime                        # paced, for a live demo
python demo.py --export-json alerts.json --export-csv alerts.csv
```

Sample output includes color-coded alerts (`timestamp`, `flow_id`,
`src/dst`, `threat_class`, `confidence`, `evidence`), a summary table
by threat class, and the measured flows/sec throughput.

## Using it as a library

```python
from flowguard.pipeline import FlowGuardPipeline
from flowguard.traffic_simulator import build_training_set, build_demo_stream

pipeline = FlowGuardPipeline()
pipeline.train(build_training_set())

for flow, _label in build_demo_stream():
    alert = pipeline.process_flow(flow)
    if alert:
        print(alert.to_json())
```

To plug in real traffic, replace `traffic_simulator` with a reader that
yields `FlowRecord` objects from your NetFlow/IPFIX/sFlow collector or
summarized packet captures (`flowguard/features.py` defines the schema).

## Tuning notes

- `RuleBasedDetector` thresholds (pps, fan-out, entropy, jitter) are
  starting points — tune against your own traffic baseline to control
  false positives, especially `scan_dst_fanout_threshold` for busy
  benign hosts that legitimately talk to many destinations.
- `HybridModel.min_confidence` controls how aggressively the anomaly/
  classifier path escalates to an alert versus staying silent.
- `AnomalyDetector` is trained only on benign traffic (unsupervised),
  so it can flag novel attack types the classifier has never seen.
