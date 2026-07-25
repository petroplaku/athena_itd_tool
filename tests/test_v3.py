"""Tests for the v3 platform: detectors, triage, cases, watchlist, governance."""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from athena_itd.config import Config
from athena_itd.detect import (
    DETECTORS,
    Analyzer,
    detector_compliance_map,
    detector_mitre_map,
)
from athena_itd.ingest import generate_synthetic
from athena_itd.models import (
    Action,
    AlertStatus,
    Case,
    Event,
    Feedback,
    Note,
    RiskLevel,
    Verdict,
    WatchlistEntry,
)
from athena_itd.storage import Store


@pytest.fixture()
def corpus():
    return generate_synthetic(users=25, days=21, seed=7)


@pytest.fixture()
def store(tmp_path):
    return Store(tmp_path / "t.sqlite3")


def _mk(user, ts, action, **kw):
    base = {"user": user, "timestamp": ts, "action": action, "host": "WS1",
            "source_ip": "10.0.0.5", "department": "eng", "role": "dev", "country": "US"}
    base.update(kw)
    return Event(**base)


def _normal_days(user, days=14, per_day=6, start=None):
    start = start or datetime(2026, 6, 1, 9, 0)
    evs = []
    for d in range(days):
        day = start + timedelta(days=d)
        evs.append(_mk(user, day, Action.LOGIN))
        for k in range(per_day):
            evs.append(_mk(user, day + timedelta(minutes=10 + k * 30),
                           Action.FILE_ACCESS, resource=f"/shared/reports/f{k}.dat",
                           bytes=1_000_000))
    return evs


def _population(n=8, days=14):
    evs = []
    for i in range(n):
        evs += _normal_days(f"user{i}", days=days)
    return evs


def test_ensemble_members_active(corpus):
    events, _ = corpus
    an = Analyzer(config=Config()).fit(events)
    assert set(an.info()["ensemble"]) >= {"iforest", "lof", "pca", "mahalanobis"}


def test_planted_scenarios_rank_top(corpus):
    events, planted = corpus
    alerts = Analyzer(config=Config()).analyze(events)
    planted_users = {p["user"] for p in planted}
    top = {a.user for a in alerts[:len(planted_users) + 2]}
    assert planted_users <= top, "planted insiders must dominate the ranking"


def test_usb_detector_fires_on_first_time_usb():
    evs = _population()
    day = datetime(2026, 6, 14, 14, 0)
    evs += _normal_days("insider", days=13)
    for k in range(6):
        evs.append(_mk("insider", day + timedelta(minutes=k), Action.USB_WRITE,
                       resource="usb://kingston", bytes=300_000_000))
    alerts = Analyzer(config=Config()).analyze(evs)
    a = next(x for x in alerts if x.user == "insider")
    assert "usb" in a.detectors
    assert any("T1052" in t for t in a.mitre_techniques)


def test_evasion_detector_fires():
    evs = _population()
    day = datetime(2026, 6, 14, 15, 0)
    evs += _normal_days("wiper", days=13)
    evs.append(_mk("wiper", day, Action.LOG_CLEAR, resource="wevtutil cl Security"))
    evs.append(_mk("wiper", day + timedelta(minutes=2), Action.SECURITY_TOOL_DISABLE,
                   resource="defender"))
    alerts = Analyzer(config=Config()).analyze(evs)
    a = next(x for x in alerts if x.user == "wiper")
    assert "evasion" in a.detectors
    assert a.risk_level.rank >= RiskLevel.MEDIUM.rank


def test_disabled_detector_stays_silent():
    evs = _population()
    day = datetime(2026, 6, 14, 15, 0)
    evs += _normal_days("wiper", days=13)
    evs.append(_mk("wiper", day, Action.LOG_CLEAR))
    evs.append(_mk("wiper", day + timedelta(minutes=1), Action.SECURITY_TOOL_DISABLE))
    cfg = Config()
    cfg.disabled_detectors = ["evasion"]
    alerts = Analyzer(config=cfg).analyze(evs)
    a = next(x for x in alerts if x.user == "wiper")
    assert "evasion" not in a.detectors


def test_watchlist_multiplier_boosts_score(corpus):
    events, _ = corpus
    an = Analyzer(config=Config())
    base = {a.user: a.risk_score for a in an.analyze(events)}
    victim = min(base, key=base.get)
    boosted = {a.user: a.risk_score
               for a in an.score(events, watchlist={victim: 2.5})}
    assert boosted[victim] >= base[victim]


def test_alert_carries_v3_fields(corpus):
    events, _ = corpus
    alerts = Analyzer(config=Config()).analyze(events)
    hot = alerts[0]
    assert hot.detectors and hot.mitre_techniques
    assert hot.contributions, "top alert must include feature contributions"
    assert 0 <= hot.confidence <= 1


def test_catalog_maps_are_consistent():
    assert set(detector_mitre_map()) == set(DETECTORS)
    for det, mapping in detector_compliance_map().items():
        assert det in DETECTORS
        for fw, controls in mapping.items():
            assert controls, f"{det}:{fw} maps to no controls"


def test_triage_survives_reanalysis(store, corpus):
    events, _ = corpus
    store.add_events(events)
    alerts = Analyzer(config=Config()).analyze(store.iter_events())
    store.replace_alerts(alerts)
    key = alerts[0].dedup_key
    assert store.set_alert_status(key, AlertStatus.ESCALATED, "analyst1")
    store.replace_alerts(alerts)          # simulated nightly re-run
    kept = store.get_alert(key)
    assert kept.status == AlertStatus.ESCALATED
    assert kept.assignee == "analyst1"


def test_case_lifecycle(store):
    case = store.create_case(Case(title="Exfil probe", subject_user="mallory",
                                  severity=RiskLevel.HIGH))
    assert case.id is not None
    assert store.update_case(case.id, status="in_progress", verdict="true_positive")
    got = store.get_case(case.id)
    assert got.status.value == "in_progress"
    assert got.verdict == Verdict.TRUE_POSITIVE
    store.add_note(Note(target_type="case", target_id=str(case.id),
                        author="a1", body="scoped the host"))
    assert len(store.get_notes("case", str(case.id))) == 1


def test_watchlist_storage_roundtrip(store):
    store.watchlist_add(WatchlistEntry(user="eve", reason="notice period",
                                       multiplier=1.5))
    assert store.watchlist_multipliers() == {"eve": 1.5}
    assert store.watchlist_remove("eve")
    assert store.watchlist_multipliers() == {}


def test_feedback_precision(store):
    store.add_feedback(Feedback(alert_key="k1", user="u", detector="exfil",
                                verdict=Verdict.TRUE_POSITIVE))
    store.add_feedback(Feedback(alert_key="k2", user="u", detector="exfil",
                                verdict=Verdict.FALSE_POSITIVE))
    stats = store.detector_precision()
    assert stats["exfil"]["precision"] == 0.5


def test_event_replay_dedup_preserves_in_batch_repeats(store):
    ts = datetime(2026, 6, 10, 3, 0)
    burst = [_mk("bob", ts, Action.FAILED_LOGIN, success=False) for _ in range(10)]
    assert store.add_events(burst) == 10          # same-second repeats kept
    assert store.add_events(burst) == 0           # replayed export dropped
    assert store.event_count() == 10


def test_persisted_model_scores_new_data(tmp_path, corpus):
    events, _ = corpus
    an = Analyzer(config=Config()).fit(events)
    path = an.save(tmp_path / "m.joblib")
    loaded = Analyzer.load(path, config=Config())
    fresh = _normal_days("newcomer", days=3,
                         start=datetime(2026, 7, 1, 9, 0))
    alerts = loaded.score(fresh)
    assert any(a.user == "newcomer" for a in alerts)


def test_dashboard_template_compiles_and_renders():
    """The console template is plain HTML+CSS+JS outside a small {% raw %} block.

    A bare brace-hash sequence in CSS (e.g. a media query wrapping an id
    selector) silently opens a Jinja comment and takes the whole console down
    with a 500. Compile and render it here so that never ships again.
    """
    from fastapi.templating import Jinja2Templates

    from athena_itd.web import server as web_server

    tpl_dir = Path(web_server.__file__).parent / "templates"
    env = Jinja2Templates(directory=str(tpl_dir)).env
    template = env.get_template("dashboard.html")          # raises on syntax error
    html = template.render(organization="Acme Corp", version="9.9.9")

    assert "ATHENA" in html and "Acme Corp" in html and "9.9.9" in html
    # the {% raw %} block must survive intact — braces in JS are not Jinja
    assert "connectSSE();" in html and "{% raw %}" not in html
    # no unrendered Jinja delimiters may remain
    assert "{{" not in html and "{%" not in html


def test_dashboard_static_assets_exist():
    from athena_itd.web import server as web_server

    static = Path(web_server.__file__).parent / "static"
    assert (static / "athena.jpeg").is_file(), "brand logo missing"
    assert (static / "chart.umd.min.js").is_file(), "chart library missing"


def test_reset_scopes(store):
    from athena_itd.models import Case, RiskLevel, WatchlistEntry
    ts = datetime(2026, 6, 10, 9, 0)
    store.add_events([_mk("carol", ts, Action.LOGIN)])
    store.create_case(Case(title="probe", subject_user="carol",
                           severity=RiskLevel.HIGH))
    store.watchlist_add(WatchlistEntry(user="carol", reason="test"))

    removed = store.reset()                       # corpus only
    assert removed["events"] == 1
    assert store.event_count() == 0
    assert len(store.get_cases()) == 1            # cases survive a plain reset
    assert store.watchlist_multipliers()          # watchlist survives too

    store.reset(full=True)                        # full wipe
    assert not store.get_cases()
    assert not store.watchlist_multipliers()
