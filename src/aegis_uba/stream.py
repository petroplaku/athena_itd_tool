"""Real-time monitoring engine.

``LiveEngine`` runs a background worker that simulates a continuous stream of
enterprise user-activity telemetry (the kind a SIEM/EDR would forward), persists
it, and periodically re-scores the recent window against the trained anomaly
model — the same loop a production SOC deployment uses. Detected HIGH/CRITICAL
findings and every raw event are published to subscribers so the web dashboard
can render a live feed and pop threat notifications.

In a real deployment the ``_produce`` step is replaced by a collector tailing
logs or consuming a message bus; everything downstream (scoring, alerting,
response) is identical.
"""
from __future__ import annotations

import json
import queue
import random
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from typing import Any

from aegis_uba.config import Config, get_config
from aegis_uba.detect import Analyzer
from aegis_uba.ingest.synthetic import generate_synthetic
from aegis_uba.models import Action, Alert, Event, RiskLevel
from aegis_uba.storage import Store

_SCENARIOS = ["data_exfiltration", "off_hours_access", "failed_login_burst",
              "privilege_escalation", "impossible_travel"]


class LiveEngine:
    """Thread-safe singleton driving live ingestion, scoring and notifications."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._subscribers: list[queue.Queue] = []
        self._feed: deque[dict] = deque(maxlen=200)
        self._roster: list[dict] = []
        self._analyzer: Analyzer | None = None
        self.running = False
        self.started_at: datetime | None = None
        self.events_emitted = 0
        self.anomalies_injected = 0
        self.eps = 5.0
        self.inject_prob = 0.06
        self.score_interval = 4.0
        self.last_score_at: datetime | None = None
        self._last_alert_count = 0

    # --- lifecycle -----------------------------------------------------
    def start(self, eps: float = 5.0, inject_prob: float = 0.06,
              warmup_users: int = 25, warmup_days: int = 21) -> dict:
        with self._lock:
            if self.running:
                return self.status()
            cfg = get_config()
            store = Store(cfg.db_path)
            self._ensure_warmup(cfg, store, warmup_users, warmup_days)
            self._load_roster(store)
            self.eps = max(0.2, eps)
            self.inject_prob = min(0.5, max(0.0, inject_prob))
            self._stop.clear()
            self.running = True
            self.started_at = datetime.now()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            self._publish({"type": "status", "state": "started",
                           "at": self.started_at.isoformat()})
            return self.status()

    def stop(self) -> dict:
        with self._lock:
            if not self.running:
                return self.status()
            self._stop.set()
            self.running = False
        if self._thread:
            self._thread.join(timeout=3)
        self._publish({"type": "status", "state": "stopped",
                       "at": datetime.now().isoformat()})
        return self.status()

    def status(self) -> dict:
        uptime = (datetime.now() - self.started_at).total_seconds() if self.started_at else 0
        return {
            "running": self.running,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "uptime_seconds": round(uptime, 1),
            "events_emitted": self.events_emitted,
            "anomalies_injected": self.anomalies_injected,
            "eps": self.eps,
            "inject_prob": self.inject_prob,
            "roster_size": len(self._roster),
            "last_score_at": self.last_score_at.isoformat() if self.last_score_at else None,
        }

    # --- subscriptions (SSE) ------------------------------------------
    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=500)
        with self._lock:
            self._subscribers.append(q)
        # Prime with recent feed so a new client isn't blank.
        for item in list(self._feed)[-30:]:
            try:
                q.put_nowait(item)
            except queue.Full:
                break
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def recent_feed(self, limit: int = 50) -> list[dict]:
        return list(self._feed)[-limit:]

    def _publish(self, item: dict) -> None:
        self._feed.append(item)
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(item)
            except queue.Full:
                pass

    # --- worker --------------------------------------------------------
    def _run(self) -> None:
        cfg = get_config()
        store = Store(cfg.db_path)
        self._load_model(cfg, store)
        last_score = time.monotonic()
        while not self._stop.is_set():
            batch = self._produce(store)
            for ev in batch:
                self._publish(self._event_payload(ev))
            now = time.monotonic()
            if now - last_score >= self.score_interval:
                self._rescore(cfg, store)
                last_score = now
            time.sleep(1.0 / self.eps if self.eps else 0.5)

    def _produce(self, store: Store) -> list[Event]:
        """Emit one tick of live telemetry (normal, with occasional injected threat)."""
        if not self._roster:
            return []
        events: list[Event] = []
        if random.random() < self.inject_prob:
            events = self._inject_anomaly()
            self.anomalies_injected += 1
        else:
            u = random.choice(self._roster)
            events = self._normal_burst(u)
        store.add_events(events)
        self.events_emitted += len(events)
        return events

    def _normal_burst(self, u: dict) -> list[Event]:
        now = datetime.now()
        ip = u["source_ip"]
        evs = [Event(timestamp=now, user=u["user"], action=Action.LOGIN,
                     host=u["host"], source_ip=ip, department=u["department"],
                     role=u["role"], country=u.get("country", "US"))]
        for _ in range(random.randint(1, 4)):
            evs.append(Event(
                timestamp=now + timedelta(seconds=random.randint(1, 50)),
                user=u["user"],
                action=random.choice([Action.FILE_ACCESS, Action.EMAIL_SEND,
                                      Action.FILE_DOWNLOAD]),
                host=u["host"], source_ip=ip, department=u["department"], role=u["role"],
                resource=f"/shared/reports/f{random.randint(1, 500)}.dat",
                bytes=int(abs(random.gauss(2_000_000, 1_200_000))),
                country=u.get("country", "US")))
        return evs

    def _inject_anomaly(self) -> list[Event]:
        u = random.choice(self._roster)
        scenario = random.choice(_SCENARIOS)
        now = datetime.now()
        ip = u["source_ip"]
        d, r = u["department"], u["role"]
        evs: list[Event] = []

        def E(**kw):
            base = dict(user=u["user"], host=u["host"], source_ip=ip,
                        department=d, role=r, country="US")
            base.update(kw)
            return Event(**base)

        if scenario == "data_exfiltration":
            for k in range(35):
                evs.append(E(timestamp=now + timedelta(seconds=k), action=Action.FILE_DOWNLOAD,
                             resource=f"/finance/payroll/dump_{k}.zip",
                             bytes=int(abs(random.gauss(80_000_000, 20_000_000)))))
            evs.append(E(timestamp=now + timedelta(seconds=40), action=Action.DATA_TRANSFER,
                         resource="usb://external", bytes=2_400_000_000))
        elif scenario == "off_hours_access":
            night = now.replace(hour=2, minute=random.randint(0, 59))
            for k in range(12):
                evs.append(E(timestamp=night + timedelta(minutes=k * 3), action=Action.LOGIN))
                evs.append(E(timestamp=night + timedelta(minutes=k * 3 + 1),
                             action=Action.FILE_ACCESS, resource="/hr/records/all.csv",
                             bytes=5_000_000))
        elif scenario == "failed_login_burst":
            for k in range(30):
                evs.append(E(timestamp=now + timedelta(seconds=k * 2), action=Action.FAILED_LOGIN,
                             source_ip="203.0.113.66", success=False))
        elif scenario == "privilege_escalation":
            for k in range(7):
                evs.append(E(timestamp=now + timedelta(seconds=k * 5),
                             action=Action.PRIVILEGE_ESCALATION, resource="sudo:root"))
                evs.append(E(timestamp=now + timedelta(seconds=k * 5 + 1),
                             action=Action.CONFIG_CHANGE, resource="/etc/shadow"))
        else:  # impossible_travel
            evs.append(E(timestamp=now, action=Action.LOGIN, country="US"))
            evs.append(E(timestamp=now + timedelta(seconds=30), action=Action.LOGIN,
                         source_ip="185.220.101.5", country="RU"))
            evs.append(E(timestamp=now + timedelta(seconds=45), action=Action.FILE_DOWNLOAD,
                         source_ip="185.220.101.5", country="RU",
                         resource="/legal/contracts/merger.pdf", bytes=40_000_000))
        self._publish({"type": "inject", "user": u["user"], "scenario": scenario,
                       "ts": now.isoformat()})
        return evs

    # --- scoring -------------------------------------------------------
    def _rescore(self, cfg: Config, store: Store) -> None:
        if self._analyzer is None or not self._analyzer.is_fitted:
            return
        recent = store.events_since(datetime.now() - timedelta(days=7))
        if not recent:
            return
        try:
            alerts = self._analyzer.score(recent)
        except Exception:  # scoring must never kill the stream
            return
        store.replace_alerts(alerts)
        self.last_score_at = datetime.now()
        high = [a for a in alerts if a.risk_level.rank >= RiskLevel.HIGH.rank]
        self._publish({"type": "scored", "total": len(alerts), "high": len(high),
                       "ts": self.last_score_at.isoformat()})
        for a in high[:5]:
            self._publish(self._alert_payload(a))

    def _load_model(self, cfg: Config, store: Store) -> None:
        if cfg.model_path.exists():
            try:
                self._analyzer = Analyzer.load(cfg.model_path)
                return
            except Exception:
                pass
        events = store.iter_events()
        if events:
            self._analyzer = Analyzer(cfg.thresholds).fit(events)
            try:
                self._analyzer.save(cfg.model_path)
            except Exception:
                pass

    # --- helpers -------------------------------------------------------
    def _ensure_warmup(self, cfg: Config, store: Store, users: int, days: int) -> None:
        if store.event_count() > 0:
            return
        events, _ = generate_synthetic(users=users, days=days, seed=2024, anomaly_users=0)
        store.add_events(events)

    def _load_roster(self, store: Store) -> None:
        self._roster = store.user_directory()

    @staticmethod
    def _event_payload(e: Event) -> dict:
        return {
            "type": "event",
            "ts": e.timestamp.isoformat(),
            "user": e.user,
            "action": e.action.value,
            "host": e.host,
            "source_ip": e.source_ip,
            "country": e.country,
            "bytes": e.bytes,
            "resource": e.resource,
            "success": e.success,
        }

    @staticmethod
    def _alert_payload(a: Alert) -> dict:
        return {
            "type": "alert",
            "user": a.user,
            "risk_score": a.risk_score,
            "risk_level": a.risk_level.value,
            "top_factor": a.explanations[0].factor if a.explanations else "anomaly",
            "department": a.department,
            "ts": datetime.now().isoformat(),
        }


# Module-level singleton used by the web API and CLI.
ENGINE = LiveEngine()


def sse_format(item: dict) -> str:
    return f"data: {json.dumps(item)}\n\n"
