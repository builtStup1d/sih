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
