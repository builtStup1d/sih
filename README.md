# FlowGuard AI — Reference Implementation

Passive, AI-based detection of cyber threats in unidirectional (one-way)
IP traffic. Matches the architecture in the presentation:

```
Stream ingest -> Feature extraction -> ML inference -> Alert engine -> Dashboard
```

Everything operates on metadata only — no payload decryption, no probes
sent back toward the source, no mitigation actions.

The current version ships as a **FastAPI server** (REST + WebSocket +
SQLite persistence) with a **React dashboard** (Vite + Recharts) that
updates in real time. A background `TrafficStreamer` plays a continuous
synthetic traffic mix so the dashboard always has live data.

## Project layout

```
flowguard/
  flowguard/
    features.py           # FlowRecord model + rolling feature extraction
    models.py              # RuleBasedDetector, AnomalyDetector (IsolationForest),
                            # SupervisedClassifier (RandomForest), HybridModel
    alert_engine.py         # Alert model + AlertEngine (SQLite persistence)
    storage.py              # AlertStore + FlowStore (SQLite persistence layer)
    traffic_simulator.py    # Synthetic benign + attack traffic generator
    pipeline.py             # FlowGuardPipeline: ties ingest->features->model->alerts
  streamer.py                # Continuous real-time traffic streamer (background thread)
  server.py                  # FastAPI app: REST API + WebSocket + static hosting
  dashboard/                 # React (Vite) frontend
    package.json
    vite.config.js           # dev proxy /api & /ws -> :8000
    src/
      App.jsx
      main.jsx
      index.css
      hooks/useRealtime.js       # REST bootstrap + WebSocket live stream
      lib/api.js                 # API client for all REST endpoints
      lib/format.js
      components/                # Header, StatCards, TimeSeriesChart,
                                 # AlertTimeline, ThreatDonut, TopIPs,
                                 # LiveFeed, TrafficStream
    dist/                    # production build (served by FastAPI at :8000)
  requirements.txt
  flowguard_alerts.db        # SQLite alert persistence (generated)
  flowguard_flows.db         # SQLite flow persistence (generated)
```

The legacy console demo (`demo.py`) and console alert renderer
(`flowguard/dashboard.py`) were removed — the React dashboard replaces them.

## Threats covered

DDoS, botnet beaconing, DGA/DNS tunneling, encrypted malware traffic,
reconnaissance/port scanning, and data exfiltration — each detected
through a distinct behavioral signal (rate, entropy, timing regularity,
fan-out, byte asymmetry, TLS/QUIC fingerprints).

## Quickstart

### 1. Backend (FastAPI)

```bash
pip install -r requirements.txt
python server.py                  # uvicorn on http://0.0.0.0:8000
# or, with hot reload:
uvicorn server:app --reload --port 8000
```

On startup the server:
1. Trains the hybrid model on labeled synthetic traffic.
2. Points the alert engine at a SQLite-backed `AlertStore`
   (`flowguard_alerts.db`) and starts a `FlowStore` (`flowguard_flows.db`)
   that persists every raw flow.
3. Seeds dashboard history from labeled traffic if the flow DB is empty.
4. Starts the `TrafficStreamer` background thread (default 3 flows/s) that
   interleaves benign traffic with randomly scheduled attack episodes and
   pushes every flow through `features -> hybrid model -> alert engine`.
5. Broadcasts live `flow`, `alert`, and `stats` events over WebSocket ` /ws`.

### 2. Frontend (React + Vite, dev mode)

```bash
cd dashboard
npm install
npm run dev                       # Vite dev server on http://localhost:5173
```

The Vite dev server proxies `/api` and `/ws` to `http://127.0.0.1:8000`, so
open http://localhost:5173 while the backend is running.

### 3. Production build (served by FastAPI)

```bash
cd dashboard && npm run build     # writes dashboard/dist
python server.py                  # app mounts dashboard/dist at "/" (http://localhost:8000)
```

## REST API

Base URL: `http://localhost:8000` (dev proxy: `http://localhost:5173`)

| Method | Endpoint                    | Description |
| ------ | --------------------------- | ----------- |
| GET    | `/api/health`               | Health: flows/alerts counts, stream state, model trained flag |
| GET    | `/api/stats`                | Totals, per-threat-class alert counts, severity map, stream state |
| GET    | `/api/alerts`               | Alerts with filters: `limit`, `threat_class`, `severity`, `q` |
| GET    | `/api/flows`                | Recent raw flows: `limit`, `paired_alert` (threat class filter) |
| GET    | `/api/top`                  | Top source/destination IPs by alert count: `n` |
| GET    | `/api/timeline`             | Alert counts bucketed over time: `bucket_seconds` |
| GET    | `/api/series`               | Time-bucketed traffic + alert series for charts: `bucket_seconds`, `points`, `threat_class` |
| GET    | `/api/stream`               | Current stream state (running, rate, processed, fps, clients) |
| POST   | `/api/stream/start`         | Resume the live traffic stream |
| POST   | `/api/stream/stop`          | Pause the live traffic stream |
| POST   | `/api/stream/rate`          | Change stream cadence: `rate_hz` (0.5–50.0) |
| POST   | `/api/reset`                | Stop stream, wipe local history, optionally re-seed: `reseed` |

### WebSocket (`/ws`)

Connects to the live event feed. Messages are JSON:

- `{"type": "hello", "message": "connected"}` on connect.
- `{"type": "flow", "data": {...}, "stats": {...}}` for every observed flow
  (includes `paired_alert` — the threat class attached to that flow, or null).
- `{"type": "alert", "data": {...}}` whenever a flow crosses a threat threshold.

## React dashboard

Single-page dashboard (`dashboard/src/App.jsx`) rendered from the REST
snapshot and the WebSocket stream:

- **Header** — connection state, live stream controls (start/stop/rate/reset).
- **StatCards** — total flows, alerts, bytes, per-threat-class counts.
- **TimeSeriesChart** — realtime traffic/throughput/alert rate (5s buckets).
- **ThreatDonut** — share of alerts by threat class.
- **AlertTimeline** — alert activity stacked by class.
- **TopIPs** — most active source/destination hosts by alert count.
- **LiveFeed** — live alert feed, color-coded by severity.
- **TrafficStream** — every flow observed on the wire.

Alerts carry `timestamp`, `flow_id`, `src/dst`, `threat_class`,
`confidence`, `severity`, `evidence`, and `model_source`.

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

To plug in real traffic, replace the simulator with a reader that yields
`FlowRecord` objects from your NetFlow/IPFIX/sFlow collector or summarized
packet captures (`flowguard/features.py` defines the schema). In the server
deployment, `streamer.py` fills this ingest role.

## Tuning notes

- `RuleBasedDetector` thresholds (pps, fan-out, entropy, jitter) are
  starting points — tune against your own traffic baseline to control
  false positives, especially `scan_dst_fanout_threshold` for busy
  benign hosts that legitimately talk to many destinations.
- `HybridModel.min_confidence` controls how aggressively the anomaly/
  classifier path escalates to an alert versus staying silent.
- `AnomalyDetector` is trained only on benign traffic (unsupervised),
  so it can flag novel attack types the classifier has never seen.
- Stream cadence is 3 flows/s by default; override with
  `python server.py --rate 10` or `FLOWGUARD_RATE_HZ`, or live via the
  dashboard header / `/api/stream/rate`.