"""SQLite persistence layer (stdlib only, no external DB required).

The store keeps three tables: ``events`` (raw normalized activity), ``alerts``
(scored findings, with explanations serialized as JSON) and ``responses``
(the audit trail of simulated/real response actions). SQLite keeps the tool
zero-dependency for storage and trivially portable across the three OSes.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from dateutil import parser as dtparser

from aegis_uba.models import Alert, Event, Explanation, RiskLevel

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    user        TEXT NOT NULL,
    action      TEXT NOT NULL,
    host        TEXT,
    source_ip   TEXT,
    resource    TEXT,
    bytes       INTEGER DEFAULT 0,
    success     INTEGER DEFAULT 1,
    department  TEXT,
    role        TEXT,
    country     TEXT,
    extra       TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user           TEXT NOT NULL,
    window_start   TEXT NOT NULL,
    window_end     TEXT NOT NULL,
    risk_score     REAL NOT NULL,
    risk_level     TEXT NOT NULL,
    ml_score       REAL,
    department     TEXT,
    role           TEXT,
    event_count    INTEGER,
    explanations   TEXT,
    recommended    TEXT,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(user);

CREATE TABLE IF NOT EXISTS responses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user        TEXT NOT NULL,
    action      TEXT NOT NULL,
    mode        TEXT NOT NULL,
    detail      TEXT,
    created_at  TEXT NOT NULL
);
"""


class Store:
    """Thin, well-typed wrapper around a SQLite database file."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    # --- events --------------------------------------------------------
    def add_events(self, events: Iterable[Event]) -> int:
        rows = [
            (
                e.timestamp.isoformat(),
                e.user,
                e.action.value,
                e.host,
                e.source_ip,
                e.resource,
                e.bytes,
                1 if e.success else 0,
                e.department,
                e.role,
                e.country,
                json.dumps(e.extra),
            )
            for e in events
        ]
        if not rows:
            return 0
        with self._conn() as conn:
            conn.executemany(
                """INSERT INTO events
                   (timestamp,user,action,host,source_ip,resource,bytes,success,
                    department,role,country,extra)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )
        return len(rows)

    def iter_events(self) -> list[Event]:
        with self._conn() as conn:
            cur = conn.execute("SELECT * FROM events ORDER BY timestamp ASC")
            return [self._row_to_event(r) for r in cur.fetchall()]

    def events_for_user(self, user: str) -> list[Event]:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT * FROM events WHERE user=? ORDER BY timestamp ASC", (user,)
            )
            return [self._row_to_event(r) for r in cur.fetchall()]

    def event_count(self) -> int:
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def distinct_users(self) -> list[str]:
        with self._conn() as conn:
            cur = conn.execute("SELECT DISTINCT user FROM events ORDER BY user")
            return [r[0] for r in cur.fetchall()]

    @staticmethod
    def _row_to_event(r: sqlite3.Row) -> Event:
        return Event(
            timestamp=dtparser.isoparse(r["timestamp"]),
            user=r["user"],
            action=r["action"],
            host=r["host"] or "unknown",
            source_ip=r["source_ip"] or "0.0.0.0",
            resource=r["resource"] or "",
            bytes=r["bytes"] or 0,
            success=bool(r["success"]),
            department=r["department"] or "unknown",
            role=r["role"] or "unknown",
            country=r["country"] or "US",
            extra=json.loads(r["extra"]) if r["extra"] else {},
        )

    # --- alerts --------------------------------------------------------
    def replace_alerts(self, alerts: Iterable[Alert]) -> int:
        alerts = list(alerts)
        with self._conn() as conn:
            conn.execute("DELETE FROM alerts")
            conn.executemany(
                """INSERT INTO alerts
                   (user,window_start,window_end,risk_score,risk_level,ml_score,
                    department,role,event_count,explanations,recommended,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        a.user,
                        a.window_start.isoformat(),
                        a.window_end.isoformat(),
                        a.risk_score,
                        a.risk_level.value,
                        a.ml_score,
                        a.department,
                        a.role,
                        a.event_count,
                        json.dumps([e.model_dump() for e in a.explanations]),
                        json.dumps(a.recommended_actions),
                        a.created_at.isoformat(),
                    )
                    for a in alerts
                ],
            )
        return len(alerts)

    def get_alerts(self, min_level: RiskLevel | None = None) -> list[Alert]:
        with self._conn() as conn:
            cur = conn.execute("SELECT * FROM alerts ORDER BY risk_score DESC")
            alerts = [self._row_to_alert(r) for r in cur.fetchall()]
        if min_level is not None:
            alerts = [a for a in alerts if a.risk_level.rank >= min_level.rank]
        return alerts

    @staticmethod
    def _row_to_alert(r: sqlite3.Row) -> Alert:
        return Alert(
            user=r["user"],
            window_start=dtparser.isoparse(r["window_start"]),
            window_end=dtparser.isoparse(r["window_end"]),
            risk_score=r["risk_score"],
            risk_level=RiskLevel(r["risk_level"]),
            ml_score=r["ml_score"] or 0.0,
            department=r["department"] or "unknown",
            role=r["role"] or "unknown",
            event_count=r["event_count"] or 0,
            explanations=[Explanation(**e) for e in json.loads(r["explanations"] or "[]")],
            recommended_actions=json.loads(r["recommended"] or "[]"),
        )

    # --- responses -----------------------------------------------------
    def log_response(self, user: str, action: str, mode: str, detail: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO responses (user,action,mode,detail,created_at) VALUES (?,?,?,?,?)",
                (user, action, mode, detail, datetime.now(timezone.utc).isoformat()),
            )

    def get_responses(self) -> list[dict]:
        with self._conn() as conn:
            cur = conn.execute("SELECT * FROM responses ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]

    def reset(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                "DELETE FROM events; DELETE FROM alerts; DELETE FROM responses;"
            )
