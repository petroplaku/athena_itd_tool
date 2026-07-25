"""SQLite persistence layer (stdlib only, no external DB required).

Tables: ``events`` (raw normalized activity, de-duplicated by fingerprint),
``alerts`` (scored findings with triage state that survives re-analysis),
``responses`` (audit trail of response actions), ``cases`` (investigations),
``notes`` (analyst annotations), ``watchlist`` (heightened-scrutiny users),
``feedback`` (analyst verdicts that tune the detectors) and ``audit``
(operator actions against the platform itself). SQLite keeps the tool
zero-dependency for storage and trivially portable across the three OSes.
"""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dateutil import parser as dtparser

from athena_itd.models import (
    Alert,
    AlertStatus,
    Case,
    CaseStatus,
    Event,
    Explanation,
    FeatureContribution,
    Feedback,
    Note,
    RiskLevel,
    Verdict,
    WatchlistEntry,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT UNIQUE,
    timestamp   TEXT NOT NULL,
    user        TEXT NOT NULL,
    action      TEXT NOT NULL,
    host        TEXT,
    source_ip   TEXT,
    dest_ip     TEXT,
    resource    TEXT,
    bytes       INTEGER DEFAULT 0,
    success     INTEGER DEFAULT 1,
    department  TEXT,
    role        TEXT,
    country     TEXT,
    source      TEXT,
    extra       TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key      TEXT UNIQUE,
    user           TEXT NOT NULL,
    window_start   TEXT NOT NULL,
    window_end     TEXT NOT NULL,
    risk_score     REAL NOT NULL,
    risk_level     TEXT NOT NULL,
    ml_score       REAL,
    rule_score     REAL,
    peer_score     REAL,
    sequence_score REAL,
    confidence     REAL,
    department     TEXT,
    role           TEXT,
    event_count    INTEGER,
    explanations   TEXT,
    contributions  TEXT,
    recommended    TEXT,
    mitre          TEXT,
    detectors      TEXT,
    status         TEXT DEFAULT 'new',
    assignee       TEXT DEFAULT '',
    case_id        INTEGER,
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

CREATE TABLE IF NOT EXISTS cases (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT NOT NULL,
    subject_user TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open',
    severity     TEXT NOT NULL DEFAULT 'MEDIUM',
    owner        TEXT DEFAULT '',
    summary      TEXT DEFAULT '',
    alert_keys   TEXT DEFAULT '[]',
    tags         TEXT DEFAULT '[]',
    verdict      TEXT DEFAULT 'unknown',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    closed_at    TEXT
);

CREATE TABLE IF NOT EXISTS notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    author      TEXT DEFAULT '',
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_target ON notes(target_type, target_id);

CREATE TABLE IF NOT EXISTS watchlist (
    user        TEXT PRIMARY KEY,
    reason      TEXT NOT NULL,
    multiplier  REAL NOT NULL DEFAULT 1.35,
    added_by    TEXT DEFAULT 'system',
    expires_at  TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_key   TEXT NOT NULL,
    user        TEXT NOT NULL,
    detector    TEXT DEFAULT '',
    verdict     TEXT NOT NULL,
    analyst     TEXT DEFAULT '',
    note        TEXT DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT DEFAULT '',
    detail      TEXT DEFAULT '',
    source_ip   TEXT DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    role        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    source_ip   TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
"""

# Columns added over the life of the schema; applied idempotently so a v1
# database opens cleanly under a v3 build.
_MIGRATIONS: list[tuple[str, str, str]] = [
    ("events", "fingerprint", "TEXT"),
    ("events", "dest_ip", "TEXT"),
    ("events", "source", "TEXT"),
    ("alerts", "dedup_key", "TEXT"),
    ("alerts", "rule_score", "REAL"),
    ("alerts", "peer_score", "REAL"),
    ("alerts", "sequence_score", "REAL"),
    ("alerts", "confidence", "REAL"),
    ("alerts", "contributions", "TEXT"),
    ("alerts", "mitre", "TEXT"),
    ("alerts", "detectors", "TEXT"),
    ("alerts", "status", "TEXT DEFAULT 'new'"),
    ("alerts", "assignee", "TEXT DEFAULT ''"),
    ("alerts", "case_id", "INTEGER"),
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    """Thin, well-typed wrapper around a SQLite database file."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        # timeout lets concurrent writers wait for the lock instead of erroring;
        # WAL + NORMAL sync give much better read/write concurrency than the
        # rollback-journal default while staying crash-safe.
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            existing: dict[str, set[str]] = {}
            for table, column, decl in _MIGRATIONS:
                if table not in existing:
                    cur = conn.execute(f"PRAGMA table_info({table})")
                    existing[table] = {r[1] for r in cur.fetchall()}
                if column not in existing[table]:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
            # Indexes on migrated columns must come after the ALTERs so a v1
            # database opens cleanly. Multiple NULL fingerprints (v1 rows) are
            # permitted by SQLite unique indexes, so legacy data is untouched.
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_fp ON events(fingerprint)")

    # --- events --------------------------------------------------------
    def add_events(self, events: Iterable[Event]) -> int:
        """Insert events, silently skipping fingerprint duplicates (replays).

        Identical events *within* one batch are genuine repeats (several failed
        logins in the same second is exactly what a brute force looks like), so
        each in-batch occurrence gets an ordinal suffix. A replayed export
        produces the same ordinals and therefore still de-duplicates fully.
        """
        seen: dict[str, int] = {}

        def fp(e: Event) -> str:
            base = e.fingerprint
            n = seen.get(base, 0)
            seen[base] = n + 1
            return base if n == 0 else f"{base}#{n}"

        rows = [
            (
                fp(e),
                e.timestamp.isoformat(),
                e.user,
                e.action.value,
                e.host,
                e.source_ip,
                e.dest_ip,
                e.resource,
                e.bytes,
                1 if e.success else 0,
                e.department,
                e.role,
                e.country,
                e.source,
                json.dumps(e.extra),
            )
            for e in events
        ]
        if not rows:
            return 0
        with self._conn() as conn:
            before = conn.total_changes
            conn.executemany(
                """INSERT OR IGNORE INTO events
                   (fingerprint,timestamp,user,action,host,source_ip,dest_ip,resource,
                    bytes,success,department,role,country,source,extra)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )
            return conn.total_changes - before

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

    def events_since(self, since: datetime) -> list[Event]:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp ASC",
                (since.isoformat(),),
            )
            return [self._row_to_event(r) for r in cur.fetchall()]

    def country_counts(self) -> dict[str, int]:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT country, COUNT(*) AS n FROM events GROUP BY country")
            return {r["country"] or "??": r["n"] for r in cur.fetchall()}

    def action_counts(self) -> dict[str, int]:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT action, COUNT(*) AS n FROM events GROUP BY action ORDER BY n DESC")
            return {r["action"]: r["n"] for r in cur.fetchall()}

    def user_directory(self) -> list[dict]:
        """One representative profile row per user (latest dept/role/host/ip)."""
        with self._conn() as conn:
            cur = conn.execute(
                """SELECT user, department, role, host, source_ip, country,
                          MIN(timestamp) AS first_seen,
                          MAX(timestamp) AS last_seen,
                          COUNT(*) AS event_count
                   FROM events GROUP BY user ORDER BY user"""
            )
            return [dict(r) for r in cur.fetchall()]

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
            dest_ip=r["dest_ip"] or "",
            resource=r["resource"] or "",
            bytes=r["bytes"] or 0,
            success=bool(r["success"]),
            department=r["department"] or "unknown",
            role=r["role"] or "unknown",
            country=r["country"] or "US",
            source=r["source"] or "generic",
            extra=json.loads(r["extra"]) if r["extra"] else {},
        )

    # --- alerts --------------------------------------------------------
    def replace_alerts(self, alerts: Iterable[Alert]) -> int:
        """Store a fresh analysis run, carrying triage state across by dedup key.

        A re-analysis must never silently reset an analyst's work: status,
        assignee and case linkage survive as long as the (user, window) identity
        matches.
        """
        alerts = list(alerts)
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT dedup_key, status, assignee, case_id FROM alerts "
                "WHERE dedup_key IS NOT NULL")
            carry = {r["dedup_key"]: (r["status"], r["assignee"], r["case_id"])
                     for r in cur.fetchall()}
            conn.execute("DELETE FROM alerts")
            rows = []
            for a in alerts:
                status, assignee, case_id = carry.get(
                    a.dedup_key, (a.status.value, a.assignee, a.case_id))
                rows.append((
                    a.dedup_key,
                    a.user,
                    a.window_start.isoformat(),
                    a.window_end.isoformat(),
                    a.risk_score,
                    a.risk_level.value,
                    a.ml_score,
                    a.rule_score,
                    a.peer_score,
                    a.sequence_score,
                    a.confidence,
                    a.department,
                    a.role,
                    a.event_count,
                    json.dumps([e.model_dump() for e in a.explanations]),
                    json.dumps([c.model_dump() for c in a.contributions]),
                    json.dumps(a.recommended_actions),
                    json.dumps(a.mitre_techniques),
                    json.dumps(a.detectors),
                    status,
                    assignee,
                    case_id,
                    a.created_at.isoformat(),
                ))
            conn.executemany(
                """INSERT OR REPLACE INTO alerts
                   (dedup_key,user,window_start,window_end,risk_score,risk_level,
                    ml_score,rule_score,peer_score,sequence_score,confidence,
                    department,role,event_count,explanations,contributions,
                    recommended,mitre,detectors,status,assignee,case_id,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )
        return len(alerts)

    def get_alerts(self, min_level: RiskLevel | None = None,
                   status: str | None = None) -> list[Alert]:
        with self._conn() as conn:
            cur = conn.execute("SELECT * FROM alerts ORDER BY risk_score DESC")
            alerts = [self._row_to_alert(r) for r in cur.fetchall()]
        if min_level is not None:
            alerts = [a for a in alerts if a.risk_level.rank >= min_level.rank]
        if status is not None:
            if status == "open":
                alerts = [a for a in alerts if a.status.is_open]
            else:
                alerts = [a for a in alerts if a.status.value == status]
        return alerts

    def get_alert(self, dedup_key: str) -> Alert | None:
        with self._conn() as conn:
            r = conn.execute(
                "SELECT * FROM alerts WHERE dedup_key=?", (dedup_key,)).fetchone()
        return self._row_to_alert(r) if r else None

    def set_alert_status(self, dedup_key: str, status: AlertStatus,
                         assignee: str | None = None) -> bool:
        with self._conn() as conn:
            if assignee is None:
                cur = conn.execute(
                    "UPDATE alerts SET status=? WHERE dedup_key=?",
                    (status.value, dedup_key))
            else:
                cur = conn.execute(
                    "UPDATE alerts SET status=?, assignee=? WHERE dedup_key=?",
                    (status.value, assignee, dedup_key))
            return cur.rowcount > 0

    def link_alert_case(self, dedup_key: str, case_id: int | None) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE alerts SET case_id=? WHERE dedup_key=?", (case_id, dedup_key))
            return cur.rowcount > 0

    @staticmethod
    def _row_to_alert(r: sqlite3.Row) -> Alert:
        return Alert(
            user=r["user"],
            window_start=dtparser.isoparse(r["window_start"]),
            window_end=dtparser.isoparse(r["window_end"]),
            risk_score=r["risk_score"],
            risk_level=RiskLevel(r["risk_level"]),
            ml_score=r["ml_score"] or 0.0,
            rule_score=r["rule_score"] or 0.0,
            peer_score=r["peer_score"] or 0.0,
            sequence_score=r["sequence_score"] or 0.0,
            confidence=r["confidence"] if r["confidence"] is not None else 1.0,
            department=r["department"] or "unknown",
            role=r["role"] or "unknown",
            event_count=r["event_count"] or 0,
            explanations=[Explanation(**e) for e in json.loads(r["explanations"] or "[]")],
            contributions=[FeatureContribution(**c)
                           for c in json.loads(r["contributions"] or "[]")],
            recommended_actions=json.loads(r["recommended"] or "[]"),
            mitre_techniques=json.loads(r["mitre"] or "[]"),
            detectors=json.loads(r["detectors"] or "[]"),
            status=AlertStatus(r["status"] or "new"),
            assignee=r["assignee"] or "",
            case_id=r["case_id"],
            created_at=dtparser.isoparse(r["created_at"]),
        )

    # --- responses -----------------------------------------------------
    def log_response(self, user: str, action: str, mode: str, detail: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO responses (user,action,mode,detail,created_at) VALUES (?,?,?,?,?)",
                (user, action, mode, detail, _now()),
            )

    def get_responses(self) -> list[dict]:
        with self._conn() as conn:
            cur = conn.execute("SELECT * FROM responses ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]

    # --- cases ---------------------------------------------------------
    def create_case(self, case: Case) -> Case:
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO cases (title,subject_user,status,severity,owner,summary,
                                      alert_keys,tags,verdict,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (case.title, case.subject_user, case.status.value, case.severity.value,
                 case.owner, case.summary, json.dumps(case.alert_keys),
                 json.dumps(case.tags), case.verdict.value,
                 case.created_at.isoformat(), case.updated_at.isoformat()))
            case.id = cur.lastrowid
        return case

    def update_case(self, case_id: int, **fields) -> bool:
        allowed = {"title", "status", "severity", "owner", "summary",
                   "alert_keys", "tags", "verdict", "closed_at"}
        sets, vals = ["updated_at=?"], [_now()]
        for key, value in fields.items():
            if key not in allowed or value is None:
                continue
            if key in ("alert_keys", "tags"):
                value = json.dumps(value)
            sets.append(f"{key}=?")
            vals.append(value)
        vals.append(case_id)
        with self._conn() as conn:
            cur = conn.execute(
                f"UPDATE cases SET {', '.join(sets)} WHERE id=?", vals)
            return cur.rowcount > 0

    def get_case(self, case_id: int) -> Case | None:
        with self._conn() as conn:
            r = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        return self._row_to_case(r) if r else None

    def get_cases(self, open_only: bool = False) -> list[Case]:
        with self._conn() as conn:
            cur = conn.execute("SELECT * FROM cases ORDER BY updated_at DESC")
            cases = [self._row_to_case(r) for r in cur.fetchall()]
        if open_only:
            cases = [c for c in cases if c.status.is_open]
        return cases

    @staticmethod
    def _row_to_case(r: sqlite3.Row) -> Case:
        return Case(
            id=r["id"],
            title=r["title"],
            subject_user=r["subject_user"],
            status=CaseStatus(r["status"]),
            severity=RiskLevel(r["severity"]),
            owner=r["owner"] or "",
            summary=r["summary"] or "",
            alert_keys=json.loads(r["alert_keys"] or "[]"),
            tags=json.loads(r["tags"] or "[]"),
            verdict=Verdict(r["verdict"] or "unknown"),
            created_at=dtparser.isoparse(r["created_at"]),
            updated_at=dtparser.isoparse(r["updated_at"]),
            closed_at=dtparser.isoparse(r["closed_at"]) if r["closed_at"] else None,
        )

    # --- notes ---------------------------------------------------------
    def add_note(self, note: Note) -> Note:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO notes (target_type,target_id,author,body,created_at) "
                "VALUES (?,?,?,?,?)",
                (note.target_type, note.target_id, note.author, note.body,
                 note.created_at.isoformat()))
            note.id = cur.lastrowid
        return note

    def get_notes(self, target_type: str, target_id: str) -> list[Note]:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT * FROM notes WHERE target_type=? AND target_id=? "
                "ORDER BY created_at ASC", (target_type, target_id))
            return [
                Note(id=r["id"], target_type=r["target_type"], target_id=r["target_id"],
                     author=r["author"] or "", body=r["body"],
                     created_at=dtparser.isoparse(r["created_at"]))
                for r in cur.fetchall()
            ]

    # --- watchlist -----------------------------------------------------
    def watchlist_add(self, entry: WatchlistEntry) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO watchlist (user,reason,multiplier,added_by,expires_at,created_at)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(user) DO UPDATE SET
                     reason=excluded.reason, multiplier=excluded.multiplier,
                     added_by=excluded.added_by, expires_at=excluded.expires_at""",
                (entry.user, entry.reason, entry.multiplier, entry.added_by,
                 entry.expires_at.isoformat() if entry.expires_at else None,
                 entry.created_at.isoformat()))

    def watchlist_remove(self, user: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM watchlist WHERE user=?", (user,))
            return cur.rowcount > 0

    def watchlist(self, active_only: bool = True) -> list[WatchlistEntry]:
        with self._conn() as conn:
            cur = conn.execute("SELECT * FROM watchlist ORDER BY created_at DESC")
            entries = [
                WatchlistEntry(
                    user=r["user"], reason=r["reason"], multiplier=r["multiplier"],
                    added_by=r["added_by"] or "system",
                    expires_at=dtparser.isoparse(r["expires_at"]) if r["expires_at"] else None,
                    created_at=dtparser.isoparse(r["created_at"]))
                for r in cur.fetchall()
            ]
        if active_only:
            now = datetime.now(timezone.utc)
            entries = [e for e in entries
                       if e.expires_at is None
                       or e.expires_at.replace(tzinfo=e.expires_at.tzinfo or timezone.utc) > now]
        return entries

    def watchlist_multipliers(self) -> dict[str, float]:
        return {e.user: e.multiplier for e in self.watchlist(active_only=True)}

    # --- feedback ------------------------------------------------------
    def add_feedback(self, fb: Feedback) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO feedback (alert_key,user,detector,verdict,analyst,note,created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (fb.alert_key, fb.user, fb.detector, fb.verdict.value, fb.analyst,
                 fb.note, fb.created_at.isoformat()))

    def get_feedback(self) -> list[dict]:
        with self._conn() as conn:
            cur = conn.execute("SELECT * FROM feedback ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]

    def detector_precision(self) -> dict[str, dict]:
        """Per-detector TP/FP tallies from analyst feedback (weight-tuning input)."""
        stats: dict[str, dict] = {}
        for row in self.get_feedback():
            det = row["detector"] or "overall"
            s = stats.setdefault(det, {"true_positive": 0, "false_positive": 0,
                                       "benign_true_positive": 0, "unknown": 0})
            s[row["verdict"]] = s.get(row["verdict"], 0) + 1
        for det, s in stats.items():
            judged = s["true_positive"] + s["false_positive"]
            s["precision"] = round(s["true_positive"] / judged, 3) if judged else None
        return stats

    # --- audit ---------------------------------------------------------
    def log_audit(self, actor: str, action: str, target: str = "",
                  detail: str = "", source_ip: str = "") -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO audit (actor,action,target,detail,source_ip,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (actor, action, target, detail, source_ip, _now()))

    def get_audit(self, limit: int = 200) -> list[dict]:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT * FROM audit ORDER BY created_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]

    # --- sessions (persistent, cross-worker) ---------------------------
    def create_session(self, token_hash: str, username: str, role: str,
                       ttl_minutes: int, source_ip: str = "") -> str:
        expires = (datetime.now(timezone.utc) +
                   timedelta(minutes=ttl_minutes)).isoformat()
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sessions "
                "(token_hash,username,role,created_at,expires_at,source_ip) "
                "VALUES (?,?,?,?,?,?)",
                (token_hash, username, role, _now(), expires, source_ip))
        return expires

    def get_session(self, token_hash: str) -> dict | None:
        """Return the live session for a token hash, or None if absent/expired."""
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE token_hash=?",
                               (token_hash,)).fetchone()
            if not row:
                return None
            if row["expires_at"] < _now():
                conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
                return None
            return dict(row)

    def delete_session(self, token_hash: str) -> bool:
        with self._conn() as conn:
            return conn.execute("DELETE FROM sessions WHERE token_hash=?",
                                (token_hash,)).rowcount > 0

    def delete_user_sessions(self, username: str) -> int:
        with self._conn() as conn:
            return conn.execute("DELETE FROM sessions WHERE username=?",
                                (username,)).rowcount

    def purge_expired_sessions(self) -> int:
        with self._conn() as conn:
            return conn.execute("DELETE FROM sessions WHERE expires_at < ?",
                                (_now(),)).rowcount

    def list_sessions(self) -> list[dict]:
        """All live (non-expired) sessions, newest first. The token hash is the
        opaque id — it can't be used to authenticate (auth needs the raw token)."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT token_hash,username,role,created_at,expires_at,source_ip "
                "FROM sessions WHERE expires_at >= ? ORDER BY created_at DESC",
                (_now(),)).fetchall()
        return [dict(r) for r in rows]

    # --- lifecycle -----------------------------------------------------
    def purge(self, event_days: int, alert_days: int, audit_days: int) -> dict[str, int]:
        """Apply the retention policy; returns rows removed per table."""
        now = datetime.now(timezone.utc)
        cutoffs = {
            "events": (now - timedelta(days=event_days)).isoformat(),
            "alerts": (now - timedelta(days=alert_days)).isoformat(),
            "audit": (now - timedelta(days=audit_days)).isoformat(),
            "responses": (now - timedelta(days=audit_days)).isoformat(),
        }
        removed: dict[str, int] = {}
        with self._conn() as conn:
            removed["events"] = conn.execute(
                "DELETE FROM events WHERE timestamp < ?", (cutoffs["events"],)).rowcount
            removed["alerts"] = conn.execute(
                "DELETE FROM alerts WHERE created_at < ?", (cutoffs["alerts"],)).rowcount
            removed["audit"] = conn.execute(
                "DELETE FROM audit WHERE created_at < ?", (cutoffs["audit"],)).rowcount
            removed["responses"] = conn.execute(
                "DELETE FROM responses WHERE created_at < ?",
                (cutoffs["responses"],)).rowcount
        return removed

    # tables safe to wipe on a corpus reset, in FK-safe order
    _RESET_TABLES = ("feedback", "notes", "responses", "alerts", "events")
    _RESET_TABLES_ALL = _RESET_TABLES + ("cases", "watchlist")

    def reset(self, *, full: bool = False) -> dict[str, int]:
        """Clear the corpus. ``full`` also drops cases and the watchlist.

        The audit trail is always preserved so the reset itself remains
        accountable. Returns per-table deleted-row counts.
        """
        tables = self._RESET_TABLES_ALL if full else self._RESET_TABLES
        removed: dict[str, int] = {}
        with self._conn() as conn:
            for tbl in tables:
                removed[tbl] = conn.execute(f"DELETE FROM {tbl}").rowcount
        return removed
