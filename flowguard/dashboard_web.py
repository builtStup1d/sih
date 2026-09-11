"""
Read-only web dashboard for FlowGuard AI alerts.

Zero-dependency: serves a single embedded HTML page (vanilla JS + CSS,
CSS-based bar chart) over Python's stdlib ``http.server``, reading alert
history directly from the ``AlertStore`` SQLite database.  No Flask, no
front-end build step, no external assets.

Run:
    python -m flowguard.dashboard_web                 # http://localhost:8000
    python -m flowguard.dashboard_web --port 8080 --db my_alerts.db

Endpoints (all read-only):
    /                              HTML dashboard
    /api/summary                   total + counts per threat_class
    /api/alerts?threat_class=&limit=   recent alerts (newest first)
    /api/top?n=                    top source and destination IPs
    /api/timeline?bucket_seconds=  time-bucketed alert counts
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sqlite3
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List
from urllib.parse import parse_qs, urlparse

from .alert_engine import SEVERITY_MAP
from .storage import AlertStore

DEFAULT_DB = "flowguard_alerts.db"

SEVERITY_COLOR = {
    "critical": "#ff4d4f",  # red
    "high": "#e6b450",      # amber
    "medium": "#4fc1ff",    # blue
    "info": "#8b949e",      # grey
}


def _open_store(db_path: str) -> AlertStore:
    """Open a fresh read handle to the alert DB (thread-safe, read-only use)."""
    store = AlertStore(db_path)
    return store


def _json(obj) -> bytes:
    return json.dumps(obj).encode("utf-8")


PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FlowGuard AI &mdash; Alert Dashboard</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #4fc1ff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 24px; border-bottom: 1px solid var(--border);
    background: var(--panel);
  }
  header h1 { font-size: 18px; margin: 0; }
  header .sub { color: var(--muted); font-size: 12px; margin-top: 2px; }
  header .actions { display: flex; gap: 8px; align-items: center; }
  button, select {
    background: #21262d; color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 6px 12px; font-size: 13px; cursor: pointer;
  }
  button:hover { border-color: var(--accent); }
  main { padding: 24px; max-width: 1200px; margin: 0 auto; }
  .grid { display: grid; grid-template-columns: 1fr; gap: 16px; }
  @media (min-width: 900px) {
    .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .span2 { grid-column: 1 / -1; }
  }
  .panel {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px;
  }
  .panel h2 { font-size: 14px; margin: 0 0 12px; color: var(--muted); font-weight: 600;
              text-transform: uppercase; letter-spacing: .05em; }
  .summary { display: flex; flex-wrap: wrap; gap: 10px; }
  .card {
    border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px;
    min-width: 110px; background: #0d1117;
  }
  .card .num { font-size: 26px; font-weight: 700; }
  .card .lbl { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .chart { display: flex; align-items: flex-end; gap: 4px; height: 180px;
           padding-top: 8px; border-bottom: 1px solid var(--border); }
  .bar-wrap { flex: 1; min-width: 0; display: flex; flex-direction: column;
              align-items: center; height: 100%; }
  .bar-stack { display: flex; flex-direction: column; justify-content: flex-end;
               width: 100%; max-width: 42px; height: 100%; min-height: 2px;
               border-radius: 4px 4px 0 0; overflow: hidden; }
  .bar-seg { width: 100%; min-height: 2px; }
  .bar-label { font-size: 10px; color: var(--muted); margin-top: 6px;
               white-space: nowrap; transform: rotate(-40deg); transform-origin: left bottom; }
  .donut-flex { display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }
  .legend { display: flex; flex-direction: column; gap: 6px; font-size: 13px;
            flex: 1; min-width: 160px; margin-top: 12px; }
  .legend-item { display: flex; align-items: center; gap: 8px; }
  .legend-val { color: var(--muted); margin-left: auto; padding-right: 4px; }
  .swatch { display: inline-block; width: 10px; height: 10px; border-radius: 2px; flex: none; }
  .hbar-row { display: flex; align-items: center; gap: 10px; margin: 6px 0; }
  .hbar-lbl { font-size: 12px; color: var(--muted); width: 120px; flex: none;
              overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .hbar-track { flex: 1; background: #21262d; border-radius: 4px; height: 18px;
                overflow: hidden; display: flex; align-items: center; }
  .hbar-fill { background: var(--accent); border-radius: 4px; height: 100%;
               font-size: 11px; color: #0d1117; font-weight: 700; text-align: right;
               padding-right: 6px; line-height: 18px; min-width: 18px; }
  .hl { font-size: 13px; color: var(--muted); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border);
           white-space: nowrap; }
  th { color: var(--muted); font-weight: 600; font-size: 12px; }
  .scroll { overflow-x: auto; }
  .pill { display: inline-block; padding: 1px 8px; border-radius: 10px;
          font-size: 11px; font-weight: 600; color: #0d1117; }
  .empty { color: var(--muted); font-size: 13px; padding: 12px 0; }
  .severity-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
                  margin-right: 6px; }
  .footer { color: var(--muted); font-size: 12px; padding: 24px; text-align: center; }
</style>
</head>
<body>
<header>
  <div>
    <h1>&#x1F6E1;&#xFE0F; FlowGuard AI &mdash; Alert Dashboard</h1>
    <div class="sub">Passive, AI-based threat detection &middot; read-only view of alert history</div>
  </div>
  <div class="actions">
    <span class="hl" id="total-label"></span>
    <button id="refresh">Refresh</button>
  </div>
</header>
<main class="grid">
  <section class="panel span2">
    <h2>Summary</h2>
    <div class="summary" id="summary"></div>
  </section>

  <section class="panel">
    <h2>Alerts by Threat Class</h2>
    <div id="donut-class"></div>
  </section>

  <section class="panel">
    <h2>Alerts by Severity</h2>
    <div id="donut-severity"></div>
  </section>

  <section class="panel span2">
    <h2>Alert Timeline</h2>
    <div class="chart" id="timeline"></div>
    <div class="legend" id="timeline-legend"></div>
  </section>

  <section class="panel">
    <h2>Top Sources</h2>
    <div id="sources"></div>
  </section>

  <section class="panel">
    <h2>Top Destinations</h2>
    <div id="destinations"></div>
  </section>

  <section class="panel span2">
    <h2>Recent Alerts</h2>
    <div class="actions" style="margin-bottom:12px;">
      <label class="hl" for="threat-filter">Filter:</label>
      <select id="threat-filter"><option value="">all classes</option></select>
    </div>
    <div class="scroll">
      <table>
        <thead>
          <tr>
            <th>Severity</th><th>Timestamp</th><th>Flow ID</th>
            <th>Source</th><th>Destination</th><th>Protocol</th>
            <th>Class</th><th>Confidence</th><th>Model</th><th>Evidence</th>
          </tr>
        </thead>
        <tbody id="alerts-body"></tbody>
      </table>
    </div>
    <div class="actions" id="load-more" style="margin-top:12px;"></div>
  </section>
</main>
<div class="footer">FlowGuard AI &middot; alerts are stored locally in the
  <code>flowguard_alerts.db</code> SQLite file.<br>
  Copyright &copy; VAPTS</div>

<script>
"use strict";
const SEVERITY_COLOR = {
  "critical": "#ff4d4f", "high": "#e6b450",
  "medium": "#4fc1ff", "info": "#8b949e"
};
let THREAT_COLORS = {};
let CURRENT_ALERTS = [];
let visibleCount = 10;

function el(tag, attrs, text) {
  const node = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
}

async function getJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(url + " -> " + res.status);
  return res.json();
}

function renderSummary(summary) {
  const box = document.getElementById("summary");
  box.replaceChildren();
  const total = { total: 0 };
  box.appendChild(makeCard("total", summary.total, "#4fc1ff"));
  for (const [cls, n] of Object.entries(summary.per_threat_class)) {
    box.appendChild(makeCard(cls, n, SEVERITY_COLOR[summary.severity[cls] || "info"]));
  }
  document.getElementById("total-label").textContent =
    summary.total + " alert" + (summary.total === 1 ? "" : "s");
}

function makeCard(lbl, num, color) {
  const card = el("div", { "class": "card" });
  const n = el("div", { "class": "num" }, String(num));
  n.style.color = color;
  card.appendChild(n);
  card.appendChild(el("div", { "class": "lbl" }, lbl));
  return card;
}

function renderTimeline(tl) {
  const chart = document.getElementById("timeline");
  chart.replaceChildren();
  if (!tl.timeline.length) {
    chart.appendChild(el("div", { "class": "empty" }, "No alerts yet."));
    renderLegend([]);
    return;
  }
  const max = Math.max(...tl.timeline.map(
    b => Object.values(b.counts).reduce((a, c) => a + c, 0)), 1);
  for (const b of tl.timeline) {
    const wrap = el("div", { "class": "bar-wrap" });
    const stack = el("div", { "class": "bar-stack" });
    const entries = Object.entries(b.counts).sort((x, y) => y[1] - x[1]);
    for (const [cls, n] of entries) {
      const seg = el("div", { "class": "bar-seg" });
      seg.style.height = Math.max((n / max) * 100, 2) + "%";
      seg.style.background = THREAT_COLORS[cls] || "#8b949e";
      seg.title = cls + ": " + n;
      stack.appendChild(seg);
    }
    wrap.appendChild(stack);
    const t = new Date(b.start);
    wrap.appendChild(el("div", { "class": "bar-label" }, t.toTimeString().slice(0, 8)));
    chart.appendChild(wrap);
  }
  renderLegend(tl.classes);
}

function renderLegend(classes) {
  const box = document.getElementById("timeline-legend");
  box.replaceChildren();
  if (!classes.length) return;
  box.style.flexDirection = "row";
  box.style.flexWrap = "wrap";
  for (const cls of classes) {
    const item = el("div", { "class": "legend-item" });
    const sw = el("span", { "class": "swatch" });
    sw.style.background = THREAT_COLORS[cls] || "#8b949e";
    item.appendChild(sw);
    item.appendChild(el("span", {}, cls));
    box.appendChild(item);
  }
}

function renderBars(id, rows) {
  const box = document.getElementById(id);
  box.replaceChildren();
  if (!rows.length) {
    box.appendChild(el("div", { "class": "empty" }, "No data."));
    return;
  }
  const max = Math.max(...rows.map(([, n]) => n), 1);
  for (const [ip, n] of rows) {
    const row = el("div", { "class": "hbar-row" });
    row.appendChild(el("span", { "class": "hbar-lbl" }, ip));
    const track = el("div", { "class": "hbar-track" });
    const fill = el("div", { "class": "hbar-fill" });
    fill.style.width = Math.max((n / max) * 100, 6) + "%";
    fill.textContent = n;
    track.appendChild(fill);
    row.appendChild(track);
    box.appendChild(row);
  }
}

function renderDonut(id, data) {
  const box = document.getElementById(id);
  box.replaceChildren();
  const total = data.reduce((s, d) => s + d.value, 0);
  if (!total) {
    box.appendChild(el("div", { "class": "empty" }, "No data."));
    return;
  }
  const NS = "http://www.w3.org/2000/svg";
  const R = 54, C = 2 * Math.PI * R;
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 140 140");
  svg.setAttribute("width", "150");
  svg.setAttribute("height", "150");
  const track = document.createElementNS(NS, "circle");
  track.setAttribute("cx", "70"); track.setAttribute("cy", "70"); track.setAttribute("r", String(R));
  track.setAttribute("fill", "none"); track.setAttribute("stroke", "#21262d");
  track.setAttribute("stroke-width", "16");
  svg.appendChild(track);
  let offset = 0;
  for (const d of data) {
    if (!d.value) continue;
    const frac = d.value / total;
    const seg = document.createElementNS(NS, "circle");
    seg.setAttribute("cx", "70"); seg.setAttribute("cy", "70"); seg.setAttribute("r", String(R));
    seg.setAttribute("fill", "none"); seg.setAttribute("stroke", d.color);
    seg.setAttribute("stroke-width", "16");
    seg.setAttribute("stroke-dasharray", (frac * C) + " " + C);
    seg.setAttribute("stroke-dashoffset", String(-offset * C));
    seg.setAttribute("transform", "rotate(-90 70 70)");
    seg.title = d.label + ": " + d.value;
    svg.appendChild(seg);
    offset += frac;
  }
  const center = document.createElementNS(NS, "text");
  center.setAttribute("x", "70"); center.setAttribute("y", "76");
  center.setAttribute("text-anchor", "middle"); center.setAttribute("fill", "#e6edf3");
  center.setAttribute("font-size", "24"); center.setAttribute("font-weight", "700");
  center.textContent = String(total);
  svg.appendChild(center);

  const flex = el("div", { "class": "donut-flex" });
  flex.appendChild(svg);
  const legend = el("div", { "class": "legend" });
  for (const d of data) {
    if (!d.value) continue;
    const item = el("div", { "class": "legend-item" });
    const sw = el("span", { "class": "swatch" });
    sw.style.background = d.color;
    item.appendChild(sw);
    item.appendChild(el("span", {}, d.label));
    item.appendChild(el("span", { "class": "legend-val" }, String(d.value)));
    legend.appendChild(item);
  }
  flex.appendChild(legend);
  box.appendChild(flex);
}

function populateFilter(classes) {
  const sel = document.getElementById("threat-filter");
  const prev = sel.value;
  sel.replaceChildren();
  sel.appendChild(el("option", { "value": "" }, "all classes"));
  for (const cls of classes) sel.appendChild(el("option", { "value": cls }, cls));
  if (prev && classes.includes(prev)) sel.value = prev;
}

function renderAlerts(alerts) {
  const body = document.getElementById("alerts-body");
  body.replaceChildren();
  CURRENT_ALERTS = alerts;
  for (const a of alerts.slice(0, visibleCount)) {
    const tr = el("tr");
    const dot = el("span", { "class": "severity-dot" });
    dot.style.background = SEVERITY_COLOR[a.severity] || "#8b949e";
    const sev = el("td", {});
    sev.appendChild(dot);
    tr.appendChild(sev);
    tr.appendChild(el("td", {}, a.timestamp));
    tr.appendChild(el("td", {}, a.flow_id));
    tr.appendChild(el("td", {}, a.src_ip + ":" + a.src_port));
    tr.appendChild(el("td", {}, a.dst_ip + ":" + a.dst_port));
    tr.appendChild(el("td", {}, a.protocol));
    const cls = el("td", {}, " ");
    const pill = el("span", { "class": "pill" });
    pill.textContent = a.threat_class;
    pill.style.background = SEVERITY_COLOR[a.severity] || "#8b949e";
    cls.textContent = "";
    cls.appendChild(pill);
    tr.appendChild(cls);
    tr.appendChild(el("td", {}, String(a.confidence)));
    tr.appendChild(el("td", {}, a.model_source));
    tr.appendChild(el("td", {}, (a.evidence || []).join("; ")));
    body.appendChild(tr);
  }
  if (!alerts.length) {
    const tr = el("tr");
    const td = el("td", { "colspan": "10" }, "No alerts match the current filter.");
    tr.appendChild(td);
    body.appendChild(tr);
  }
  updateLoadMore(alerts.length);
}

function updateLoadMore(total) {
  const wrap = document.getElementById("load-more");
  wrap.replaceChildren();
  if (!total) return;
  const shown = Math.min(visibleCount, total);
  wrap.appendChild(el("span", { "class": "hl" }, "Showing " + shown + " of " + total));
  if (shown < total) {
    const b = el("button", {}, "Show " + Math.min(10, total - shown) + " more");
    b.addEventListener("click", () => {
      visibleCount += 10;
      renderAlerts(CURRENT_ALERTS);
    });
    wrap.appendChild(b);
  }
}

async function loadAlerts() {
  const filter = document.getElementById("threat-filter").value;
  const qs = filter ? "?threat_class=" + encodeURIComponent(filter) : "?";
  const data = await getJSON("/api/alerts" + qs + "&limit=200");
  visibleCount = 10;
  renderAlerts(data.alerts);
}

async function loadAll() {
  try {
    const [summary, top, timeline] = await Promise.all([
      getJSON("/api/summary"),
      getJSON("/api/top?n=5"),
      getJSON("/api/timeline?bucket_seconds=60"),
    ]);
    THREAT_COLORS = {};
    for (const [cls, sev] of Object.entries(summary.severity)) {
      THREAT_COLORS[cls] = SEVERITY_COLOR[sev] || "#8b949e";
    }
    const severityCounts = {};
    for (const [cls, n] of Object.entries(summary.per_threat_class)) {
      const sev = summary.severity[cls] || "info";
      severityCounts[sev] = (severityCounts[sev] || 0) + n;
    }
    const classes = Object.keys(summary.per_threat_class).sort();
    renderSummary(summary);
    populateFilter(classes);
    renderDonut("donut-class", Object.entries(summary.per_threat_class).map(([cls, n]) =>
      ({ label: cls, value: n, color: THREAT_COLORS[cls] })));
    renderDonut("donut-severity", Object.entries(severityCounts).map(([sev, n]) =>
      ({ label: sev, value: n, color: SEVERITY_COLOR[sev] })));
    renderBars("sources", top.sources);
    renderBars("destinations", top.destinations);
    renderTimeline(timeline);
    await loadAlerts();
  } catch (err) {
    document.body.insertAdjacentHTML("beforeend",
      "<pre style='padding:16px;color:#ff9b9b'>Failed to load: " +
      err.message.replace(/</g, "&lt;") + "</pre>");
  }
}

document.getElementById("refresh").addEventListener("click", loadAll);
document.getElementById("threat-filter").addEventListener("change", loadAlerts);
loadAll();
</script>
</body>
</html>
"""


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Serves the dashboard page and its read-only JSON API."""

    DB_PATH: str = DEFAULT_DB

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        route = parsed.path
        query = parse_qs(parsed.query)

        if route == "/":
            return self._send_html()
        if route == "/api/summary":
            return self._send_json(self._api_summary())
        if route == "/api/alerts":
            return self._send_json(self._api_alerts(query))
        if route == "/api/top":
            return self._send_json(self._api_top(query))
        if route == "/api/timeline":
            return self._send_json(self._api_timeline(query))
        return self._send_json({"error": "not found"}, status=404)

    # ---- API handlers -------------------------------------------------

    def _query_int(self, query: Dict[str, List[str]], key: str, default, lo=None, hi=None):
        vals = query.get(key)
        if not vals:
            return default
        try:
            value = int(vals[0])
        except (TypeError, ValueError):
            return default
        if lo is not None:
            value = max(value, lo)
        if hi is not None:
            value = min(value, hi)
        return value

    def _api_summary(self) -> dict:
        store = _open_store(self.DB_PATH)
        try:
            summary = store.get_summary()
            severity = {cls: SEVERITY_MAP.get(cls, "medium") for cls in summary}
            return {
                "total": sum(summary.values()),
                "per_threat_class": dict(sorted(summary.items(), key=lambda kv: kv[1], reverse=True)),
                "severity": severity,
            }
        finally:
            store.close()

    def _api_alerts(self, query: Dict[str, List[str]]) -> dict:
        threat_class = (query.get("threat_class") or [None])[0]
        limit = self._query_int(query, "limit", 200, lo=1, hi=1000)
        since = (query.get("since") or [None])[0]
        store = _open_store(self.DB_PATH)
        try:
            alerts = store.get_alerts(threat_class=threat_class, since=since, limit=limit)
            return {"alerts": [a.to_dict() for a in alerts]}
        finally:
            store.close()

    def _api_top(self, query: Dict[str, List[str]]) -> dict:
        n = self._query_int(query, "n", 5, lo=1, hi=50)
        store = _open_store(self.DB_PATH)
        try:
            return {
                "sources": [[ip, cnt] for ip, cnt in store.get_top_sources(n)],
                "destinations": [[ip, cnt] for ip, cnt in store.get_top_destinations(n)],
            }
        finally:
            store.close()

    def _api_timeline(self, query: Dict[str, List[str]]) -> dict:
        bucket = self._query_int(query, "bucket_seconds", 60, lo=1, hi=86400)
        store = _open_store(self.DB_PATH)
        try:
            from datetime import datetime, timezone
            buckets: Dict[int, Dict[str, int]] = {}
            for alert in store.get_alerts():
                try:
                    dt = datetime.fromisoformat(alert.timestamp)
                except ValueError:
                    continue
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                epoch = int(dt.timestamp())
                key = epoch - (epoch % bucket)
                counts = buckets.setdefault(key, {})
                counts[alert.threat_class] = counts.get(alert.threat_class, 0) + 1
            classes = sorted({cls for counts in buckets.values() for cls in counts})
            timeline = []
            for key in sorted(buckets):
                start = datetime.fromtimestamp(key, tz=timezone.utc).isoformat()
                timeline.append({"start": start, "counts": buckets[key]})
            return {"timeline": timeline, "classes": classes}
        finally:
            store.close()

    # ---- HTTP plumbing -------------------------------------------------

    def _send_html(self) -> None:
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(PAGE_HTML.encode("utf-8"))
        except ConnectionError:
            pass  # client aborted the request; nothing more to send

    def _send_json(self, payload, status: int = 200) -> None:
        body = _json(payload)
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except ConnectionError:
            pass  # client aborted the request; nothing more to send

    def log_message(self, fmt: str, *args) -> None:
        pass


def make_handler(db_path: str) -> type:
    """Build a request handler class bound to *db_path*.

    Called once at startup and again after each auto-reload, so the class
    always reflects the latest module source.
    """
    return type(
        "ConfiguredDashboardHandler",
        (DashboardRequestHandler,),
        {"DB_PATH": db_path},
    )


def _reload_watcher(module_name: str, file_path: str, server, db_path: str) -> None:
    """Background thread: when the source file changes, reload the module
    and hot-swap the handler class so edits show up without a restart."""
    module = sys.modules[module_name]
    mtime = os.stat(file_path).st_mtime if os.path.exists(file_path) else 0
    stop = threading.Event()
    while not stop.wait(0.8):
        try:
            new_mtime = os.stat(file_path).st_mtime
        except OSError:
            continue
        if new_mtime == mtime:
            continue
        try:
            importlib.reload(module)
        except Exception as exc:  # source may be mid-edit; keep old handler
            print(f"[dashboard] reload skipped ({exc})")
            continue
        mtime = new_mtime
        server.RequestHandlerClass = make_handler(db_path)
        print("[dashboard] source changed - handler reloaded (auto)")


def serve(
    db_path: str = DEFAULT_DB,
    host: str = "127.0.0.1",
    port: int = 8000,
    auto_reload: bool = True,
) -> None:
    """Start the dashboard HTTP server (blocks until interrupted).

    With *auto_reload* (default), the module source is watched and any
    edit is applied on the next request without restarting the server.
    """
    server = ThreadingHTTPServer((host, port), make_handler(db_path))
    print(f"FlowGuard AI dashboard: http://{host}:{port}/  (db: {db_path})")
    if auto_reload:
        watcher = threading.Thread(
            target=_reload_watcher,
            args=(__name__, __file__, server, db_path),
            daemon=True,
        )
        watcher.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the FlowGuard AI web dashboard (read-only).")
    parser.add_argument("--db", default=DEFAULT_DB, help="Path to the alerts SQLite DB.")
    parser.add_argument("--host", default="127.0.0.1", help="Interface to bind.")
    parser.add_argument("--port", type=int, default=8000, help="TCP port to bind.")
    parser.add_argument(
        "--no-reload", action="store_true",
        help="Disable auto-reload on source changes (production mode).",
    )
    args = parser.parse_args()
    serve(db_path=args.db, host=args.host, port=args.port, auto_reload=not args.no_reload)


if __name__ == "__main__":
    main()