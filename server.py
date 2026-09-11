"""
FlowGuard AI — real-time API server (FastAPI + WebSocket).

Responsibilities:
  * Train the hybrid detection model on labeled synthetic traffic.
  * Run a continuous traffic streamer (see ``streamer.py``) on a background
    thread, feeding every flow through the pipeline.
  * Persist every raw flow AND every raised alert to SQLite
    (``flowguard_alerts.db`` for alerts, ``flowguard_flows.db`` for flows).
  * Serve REST endpoints for historical data + a WebSocket for live events
    (flows, alerts, stats).

Run:
    uvicorn server:app --reload --port 8000
or simply:
    python server.py

Front-end:
    cd dashboard && npm install && npm run dev   (Vite dev server on :5173)
    npm run build                                 (production build -> dashboard/dist)
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import time
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from flowguard.alert_engine import AlertEngine, SEVERITY_MAP
from flowguard.pipeline import FlowGuardPipeline
from flowguard.storage import AlertStore, FlowStore
from flowguard.traffic_simulator import build_demo_stream, build_training_set

from streamer import TrafficStreamer

ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(ROOT, "dashboard", "dist")

DEFAULT_ALERTS_DB = os.path.join(ROOT, "flowguard_alerts.db")
DEFAULT_FLOWS_DB = os.path.join(ROOT, "flowguard_flows.db")

# ---------------------------------------------------------------------------
# Thread-safe WebSocket fan-out
# ---------------------------------------------------------------------------


class Broadcaster:
    """Broadcasts JSON payloads to all connected WebSocket clients.

    Callable from any thread: ``broadcast`` schedules the send on the
    event-loop thread via ``call_soon_threadsafe``.
    """

    def __init__(self) -> None:
        self._conns: set = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def add(self, ws: WebSocket) -> None:
        self._conns.add(ws)

    def remove(self, ws: WebSocket) -> None:
        self._conns.discard(ws)

    def __len__(self) -> int:
        return len(self._conns)

    def broadcast(self, payload: dict) -> None:
        loop = self._loop
        if loop is None or not self._conns:
            return
        try:
            loop.call_soon_threadsafe(self._schedule_send, dict(payload))
        except RuntimeError:
            pass  # loop is shutting down

    def _schedule_send(self, payload: dict) -> None:
        for ws in list(self._conns):
            asyncio.ensure_future(self._safe_send(ws, payload))

    async def _safe_send(self, ws: WebSocket, payload: dict) -> None:
        try:
            await ws.send_json(payload)
        except Exception:
            self.remove(ws)


broadcaster = Broadcaster()

pipeline: Optional[FlowGuardPipeline] = None
alert_store: Optional[AlertStore] = None
flow_store: Optional[FlowStore] = None
streamer: Optional[TrafficStreamer] = None

# ---------------------------------------------------------------------------
# App + lifespan
# ---------------------------------------------------------------------------


def _analyze_flow(flow, broadcast: bool) -> None:
    """Run one flow through the pipeline; persist + optionally broadcast."""
    features = pipeline.extractor.extract(flow)
    verdict = pipeline.hybrid.predict(features)
    alert = pipeline.alert_engine.process(flow, features, verdict)
    paired = alert.threat_class if alert is not None else None

    flow_store.insert_flow(flow, paired_alert=paired)

    if broadcast:
        stats = {
            "processed": streamer.processed,
            "throughput_fps": round(streamer.throughput_fps, 1),
            "running": streamer.running,
            "rate_hz": round(streamer.rate_hz, 2),
        }
        broadcaster.broadcast(
            {
                "type": "flow",
                "data": {
                    "flow_id": flow.flow_id,
                    "timestamp": flow.timestamp,
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "src_port": flow.src_port,
                    "dst_port": flow.dst_port,
                    "protocol": flow.protocol,
                    "packet_count": flow.packet_count,
                    "byte_count": flow.byte_count,
                    "duration": flow.duration,
                    "tls_ja3": flow.tls_ja3,
                    "dns_query": flow.dns_query,
                    "paired_alert": paired,
                },
                "stats": stats,
            }
        )
        if alert is not None:
            broadcaster.broadcast({"type": "alert", "data": alert.to_dict()})


def _seed_from_history() -> None:
    """If the flow DB is empty, replay labeled traffic to give the dashboard
    instant history. No broadcasting during the replay (avoids flooding)."""
    if flow_store.count() > 0:
        return
    print("[server] seeding dashboard history from labeled traffic...")
    t0 = time.perf_counter()
    for flow, _label in build_training_set():
        _analyze_flow(flow, broadcast=False)
    print(f"[server] seeded {flow_store.count()} flows in "
          f"{time.perf_counter() - t0:.2f}s")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    global pipeline, alert_store, flow_store, streamer

    alerts_db = os.environ.get("FLOWGUARD_ALERTS_DB", DEFAULT_ALERTS_DB)
    flows_db = os.environ.get("FLOWGUARD_FLOWS_DB", DEFAULT_FLOWS_DB)

    print("[server] training hybrid model on labeled synthetic traffic...")
    pipeline = FlowGuardPipeline()
    t0 = time.perf_counter()
    pipeline.train(build_training_set())
    print(f"[server] trained in {time.perf_counter() - t0:.2f}s")

    # Point the pipeline's alert engine at our SQLite-backed store.
    pipeline.alert_engine = AlertEngine(db_path=alerts_db)
    alert_store = pipeline.alert_engine.store
    flow_store = FlowStore(flows_db)

    _seed_from_history()

    streamer = TrafficStreamer(
        on_event=lambda flow: _analyze_flow(flow, broadcast=True),
        rate_hz=float(os.environ.get("FLOWGUARD_RATE_HZ", "3.0")),
    )
    streamer.start()
    print(f"[server] streamer started @ {streamer.rate_hz} flows/s "
          f"(press CTRL+C to stop)")

    try:
        yield
    finally:
        streamer.stop()
        streamer.join(timeout=2)
        flow_store.close()
        alert_store.close()


app = FastAPI(
    title="FlowGuard AI API",
    description="Passive AI-based threat detection for unidirectional IP traffic.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------


def _stream_state() -> dict:
    return {
        "running": bool(streamer and streamer.running),
        "paused": False,
        "rate_hz": round(streamer.rate_hz, 2) if streamer else 0.0,
        "processed": streamer.processed if streamer else 0,
        "throughput_fps": round(streamer.throughput_fps, 1) if streamer else 0.0,
        "clients": len(broadcaster),
    }


@app.get("/api/health")
def api_health() -> dict:
    return {
        "status": "ok",
        "flows": flow_store.count(),
        "alerts": sum(alert_store.get_summary().values()),
        "stream": _stream_state(),
        "trained": bool(pipeline and pipeline._trained),
    }


@app.get("/api/stats")
def api_stats() -> dict:
    summary = alert_store.get_summary()
    severity = {cls: SEVERITY_MAP.get(cls, "medium") for cls in summary}
    return {
        "total_alerts": sum(summary.values()),
        "total_flows": flow_store.count(),
        "total_bytes": flow_store.total_bytes(),
        "per_threat_class": dict(
            sorted(summary.items(), key=lambda kv: kv[1], reverse=True)
        ),
        "severity": severity,
        "stream": _stream_state(),
    }


@app.get("/api/alerts")
def api_alerts(
    limit: int = Query(200, ge=1, le=1000),
    threat_class: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
) -> dict:
    alerts = alert_store.get_alerts(threat_class=threat_class, limit=limit)
    q_low = q.lower() if q else None
    out = []
    for a in alerts:
        if severity and SEVERITY_MAP.get(a.threat_class, "medium") != severity:
            continue
        if q_low:
            haystack = {
                a.flow_id, a.src_ip, a.dst_ip, a.threat_class,
                a.model_source,
            } | set(a.evidence or [])
            if not any(q_low in h.lower() for h in haystack):
                continue
        out.append(a.to_dict())
    return {"alerts": out, "total": len(out)}


@app.get("/api/flows")
def api_flows(
    limit: int = Query(50, ge=1, le=500),
    paired_alert: Optional[str] = None,
) -> dict:
    return {"flows": flow_store.get_flows(limit=limit, paired_alert=paired_alert)}


@app.get("/api/top")
def api_top(n: int = Query(5, ge=1, le=50)) -> dict:
    return {
        "sources": [[ip, c] for ip, c in alert_store.get_top_sources(n)],
        "destinations": [[ip, c] for ip, c in alert_store.get_top_destinations(n)],
    }


@app.get("/api/timeline")
def api_timeline(bucket_seconds: int = Query(60, ge=1, le=86400)) -> dict:
    timeline = alert_store.get_alert_timeline(bucket_seconds=bucket_seconds)
    return {
        "timeline": [{"start": s, "count": c} for s, c in timeline],
    }


@app.get("/api/series")
def api_series(
    bucket_seconds: int = Query(5, ge=1, le=3600),
    points: int = Query(60, ge=2, le=500),
    threat_class: Optional[str] = None,
) -> dict:
    """Time-bucketed traffic + alert series for the dashboard charts."""
    series = flow_store.get_series(bucket_seconds=bucket_seconds, points=points)
    if threat_class:
        for b in series:
            b["alerts"] = b["classes"].get(threat_class, 0)
    return {"buckets": series, "classes": list(dict.fromkeys(
        cls for b in series for cls in b["classes"])
    )}


@app.get("/api/stream")
def api_stream_state() -> dict:
    return _stream_state()


@app.post("/api/stream/start")
def api_stream_start() -> dict:
    if streamer and not streamer.running:
        streamer.start()
    return _stream_state()


@app.post("/api/stream/stop")
def api_stream_stop() -> dict:
    if streamer:
        streamer.stop()
    return _stream_state()


@app.post("/api/stream/rate")
def api_stream_rate(rate_hz: float = Query(3.0, ge=0.5, le=50.0)) -> dict:
    if streamer:
        streamer.set_rate(rate_hz)
    return _stream_state()


@app.post("/api/reset")
def api_reset(reseed: bool = Query(True)) -> dict:
    """Stop the stream, wipe local history, optionally re-seed."""
    if streamer:
        streamer.stop()
        streamer.join(timeout=2)
    alert_store.clear()
    flow_store.clear()
    if reseed:
        _seed_from_history()
    streamer.start()
    return {"reset": True, "seeded": reseed, **{"stream": _stream_state()}}


# ---------------------------------------------------------------------------
# WebSocket — live events
# ---------------------------------------------------------------------------


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    broadcaster.set_loop(asyncio.get_running_loop())
    broadcaster.add(ws)
    await ws.send_json({"type": "hello", "message": "connected"})
    try:
        while True:
            await ws.receive_text()  # keep the socket alive
    except WebSocketDisconnect:
        broadcaster.remove(ws)
    except Exception:
        broadcaster.remove(ws)


# ---------------------------------------------------------------------------
# Optional static file hosting (production build of the React dashboard)
# ---------------------------------------------------------------------------

if os.path.isdir(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="dashboard")


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="Run the FlowGuard AI API server.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--rate", type=float, default=3.0,
                        help="Live stream flows per second.")
    args = parser.parse_args()
    os.environ.setdefault("FLOWGUARD_RATE_HZ", str(args.rate))
    uvicorn.run("server:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()