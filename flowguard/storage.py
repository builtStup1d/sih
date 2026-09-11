"""
SQLite persistence layer for FlowGuard AI alerts.

Uses a single ``alerts`` table whose columns mirror the Alert dataclass
fields 1:1, plus an ``id`` auto-increment primary key and an
``inserted_at`` column (DEFAULT CURRENT_TIMESTAMP) that records when the
row was persisted — distinct from the flow-level ``timestamp`` field.

Schema choice rationale:
  - SQLite ships with Python's stdlib (no extra dependencies), matching
    the project's minimal-requirements constraint.
  - A flat table with TEXT/INTEGER/REAL columns keeps the mapping to the
    Alert dataclass trivial — no ORM or migration tooling needed.
  - ``evidence`` (a List[str]) is stored as a JSON-encoded TEXT column
    for portability; callers never need to know the encoding.
"""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from .alert_engine import Alert
    from .features import FlowRecord

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    flow_id       TEXT    NOT NULL,
    src_ip        TEXT    NOT NULL,
    dst_ip        TEXT    NOT NULL,
    src_port      INTEGER NOT NULL,
    dst_port      INTEGER NOT NULL,
    protocol      TEXT    NOT NULL,
    threat_class  TEXT    NOT NULL,
    confidence    REAL    NOT NULL,
    severity      TEXT    NOT NULL,
    evidence      TEXT    NOT NULL,
    model_source  TEXT    NOT NULL,
    inserted_at   TEXT    DEFAULT CURRENT_TIMESTAMP
)
"""

_ALERT_COLS = (
    "timestamp", "flow_id", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "threat_class", "confidence", "severity", "evidence",
    "model_source",
)


def _row_to_alert(row: sqlite3.Row) -> Alert:
    """Convert a SQLite row back into an Alert dataclass instance."""
    from .alert_engine import Alert
    return Alert(
        timestamp=row["timestamp"],
        flow_id=row["flow_id"],
        src_ip=row["src_ip"],
        dst_ip=row["dst_ip"],
        src_port=row["src_port"],
        dst_port=row["dst_port"],
        protocol=row["protocol"],
        threat_class=row["threat_class"],
        confidence=row["confidence"],
        severity=row["severity"],
        evidence=json.loads(row["evidence"]),
        model_source=row["model_source"],
    )


class AlertStore:
    """Lightweight SQLite-backed store for FlowGuard alerts."""

    def __init__(self, db_path: str = "flowguard_alerts.db") -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(
            db_path, check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self.init_db()

    def init_db(self) -> None:
        """Create the alerts table if it does not exist (idempotent)."""
        self._conn.execute(_CREATE_TABLE)
        self._conn.commit()

    def insert_alert(self, alert: Alert) -> None:
        """Persist a single Alert to the database."""
        self._conn.execute(
            f"INSERT INTO alerts ({', '.join(_ALERT_COLS)}) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert.timestamp,
                alert.flow_id,
                alert.src_ip,
                alert.dst_ip,
                alert.src_port,
                alert.dst_port,
                alert.protocol,
                alert.threat_class,
                alert.confidence,
                alert.severity,
                json.dumps(alert.evidence),
                alert.model_source,
            ),
        )
        self._conn.commit()

    def get_alerts(
        self,
        threat_class: Optional[str] = None,
        since: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Alert]:
        """Retrieve alerts with optional filtering."""
        clauses: List[str] = []
        params: List = []
        if threat_class is not None:
            clauses.append("threat_class = ?")
            params.append(threat_class)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)

        sql = "SELECT * FROM alerts"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"

        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_alert(r) for r in rows]

    def get_summary(self) -> Dict[str, int]:
        """Alert counts grouped by threat_class."""
        rows = self._conn.execute(
            "SELECT threat_class, COUNT(*) AS cnt FROM alerts GROUP BY threat_class"
        ).fetchall()
        return {row["threat_class"]: row["cnt"] for row in rows}

    def get_top_sources(self, n: int = 5) -> List[Tuple[str, int]]:
        """Top *n* source IPs by alert count."""
        rows = self._conn.execute(
            "SELECT src_ip, COUNT(*) AS cnt FROM alerts "
            "GROUP BY src_ip ORDER BY cnt DESC LIMIT ?",
            (n,),
        ).fetchall()
        return [(row["src_ip"], row["cnt"]) for row in rows]

    def get_top_destinations(self, n: int = 5) -> List[Tuple[str, int]]:
        """Top *n* destination IPs by alert count."""
        rows = self._conn.execute(
            "SELECT dst_ip, COUNT(*) AS cnt FROM alerts "
            "GROUP BY dst_ip ORDER BY cnt DESC LIMIT ?",
            (n,),
        ).fetchall()
        return [(row["dst_ip"], row["cnt"]) for row in rows]

    def get_alert_timeline(
        self, bucket_seconds: int = 60,
    ) -> List[Tuple[str, int]]:
        """Alert counts bucketed by *bucket_seconds* intervals.

        Each bucket is labelled with the ISO-formatted start time of the
        window (UTC).  Useful for rendering a timeline chart on a dashboard.
        """
        rows = self._conn.execute(
            "SELECT timestamp FROM alerts ORDER BY id ASC"
        ).fetchall()
        if not rows:
            return []

        from datetime import datetime, timezone

        buckets: Dict[int, int] = {}
        for row in rows:
            ts_str = row["timestamp"]
            # Handle both timezone-aware and naive ISO strings
            try:
                dt = datetime.fromisoformat(ts_str)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            epoch = int(dt.timestamp())
            bucket_key = epoch - (epoch % bucket_seconds)
            buckets[bucket_key] = buckets.get(bucket_key, 0) + 1

        timeline: List[Tuple[str, int]] = []
        for key in sorted(buckets):
            bucket_start = datetime.fromtimestamp(key, tz=timezone.utc).isoformat()
            timeline.append((bucket_start, buckets[key]))
        return timeline

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()

    def __enter__(self) -> AlertStore:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def clear(self) -> None:
        """Delete all rows (used by the demo API reset endpoint)."""
        self._conn.execute("DELETE FROM alerts")
        self._conn.commit()


# ---------------------------------------------------------------------------
# FlowStore — persists every raw traffic flow (real-time stream history).
# ---------------------------------------------------------------------------

_CREATE_FLOWS_TABLE = """
CREATE TABLE IF NOT EXISTS flows (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id       TEXT    NOT NULL,
    timestamp     REAL    NOT NULL,
    src_ip        TEXT    NOT NULL,
    dst_ip        TEXT    NOT NULL,
    src_port      INTEGER NOT NULL,
    dst_port      INTEGER NOT NULL,
    protocol      TEXT    NOT NULL,
    packet_count  INTEGER NOT NULL,
    byte_count    INTEGER NOT NULL,
    duration      REAL    NOT NULL,
    tls_ja3       TEXT,
    dns_query     TEXT,
    ttl           INTEGER,
    paired_alert  TEXT,
    inserted_at   TEXT    DEFAULT CURRENT_TIMESTAMP
)
"""


def _flow_row_to_dict(row: sqlite3.Row) -> Dict[str, object]:
    return {
        "id": row["id"],
        "flow_id": row["flow_id"],
        "timestamp": row["timestamp"],
        "src_ip": row["src_ip"],
        "dst_ip": row["dst_ip"],
        "src_port": row["src_port"],
        "dst_port": row["dst_port"],
        "protocol": row["protocol"],
        "packet_count": row["packet_count"],
        "byte_count": row["byte_count"],
        "duration": row["duration"],
        "tls_ja3": row["tls_ja3"],
        "dns_query": row["dns_query"],
        "ttl": row["ttl"],
        "paired_alert": row["paired_alert"],
    }


class FlowStore:
    """SQLite-backed persistence for the raw (real-time) traffic stream."""

    def __init__(self, db_path: str = "flowguard_flows.db") -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.init_db()

    def init_db(self) -> None:
        self._conn.execute(_CREATE_FLOWS_TABLE)
        self._conn.commit()

    def insert_flow(
        self, flow: FlowRecord, paired_alert: Optional[str] = None
    ) -> None:
        """Persist one flow. *paired_alert* holds the threat class name that the
        analysis attached to this flow (None for benign traffic)."""
        self._conn.execute(
            "INSERT INTO flows (flow_id, timestamp, src_ip, dst_ip, src_port, "
            "dst_port, protocol, packet_count, byte_count, duration, tls_ja3, "
            "dns_query, ttl, paired_alert) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                flow.flow_id,
                flow.timestamp,
                flow.src_ip,
                flow.dst_ip,
                flow.src_port,
                flow.dst_port,
                flow.protocol,
                flow.packet_count,
                flow.byte_count,
                flow.duration,
                flow.tls_ja3,
                flow.dns_query,
                flow.ttl,
                paired_alert,
            ),
        )
        self._conn.commit()

    def get_flows(
        self,
        limit: int = 100,
        paired_alert: Optional[str] = None,
    ) -> List[Dict[str, object]]:
        """Most recent flows (newest first), optional threat-class filter."""
        sql = "SELECT * FROM flows"
        params: List = []
        if paired_alert is not None:
            sql += " WHERE paired_alert = ?"
            params.append(paired_alert)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, params).fetchall()
        return [_flow_row_to_dict(r) for r in rows]

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS c FROM flows").fetchone()
        return int(row["c"])

    def total_bytes(self) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(byte_count), 0) AS b FROM flows"
        ).fetchone()
        return int(row["b"])

    def get_series(
        self, bucket_seconds: int = 5, points: int = 60
    ) -> List[Dict[str, object]]:
        """Time-bucketed flow/byte/alert counts for time-series charts.

        Only the last ``points`` buckets are returned (newest first).
        """
        rows = self._conn.execute(
            "SELECT timestamp, byte_count, paired_alert FROM flows "
            "ORDER BY timestamp ASC"
        ).fetchall()
        if not rows:
            return []

        buckets: Dict[int, Dict[str, object]] = {}
        for r in rows:
            key = int(r["timestamp"]) - (int(r["timestamp"]) % bucket_seconds)
            b = buckets.setdefault(
                key,
                {"start": key, "flows": 0, "bytes": 0, "alerts": 0,
                 "classes": {}},
            )
            b["flows"] = int(b["flows"]) + 1
            b["bytes"] = int(b["bytes"]) + int(r["byte_count"])
            cls = r["paired_alert"]
            if cls:
                b["alerts"] = int(b["alerts"]) + 1
                classes = b["classes"]
                classes[cls] = classes.get(cls, 0) + 1

        from datetime import datetime, timezone

        # Keep only the last `points` buckets; format start as ISO-8601.
        keys = sorted(buckets)[-points:]
        out: List[Dict[str, object]] = []
        for k in keys:
            b = buckets[k]
            start = datetime.fromtimestamp(k, tz=timezone.utc).isoformat()
            out.append(
                {
                    "start": start,
                    "flows": b["flows"],
                    "bytes": b["bytes"],
                    "alerts": b["alerts"],
                    "classes": b["classes"],
                }
            )
        return out

    def clear(self) -> None:
        """Delete all rows (used by the demo API reset endpoint)."""
        self._conn.execute("DELETE FROM flows")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "FlowStore":
        return self

    def __exit__(self, *args) -> None:
        self.close()
