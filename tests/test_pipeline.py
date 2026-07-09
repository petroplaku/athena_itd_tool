"""End-to-end and unit tests for the Aegis UBA pipeline."""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from aegis_uba.config import Config, Thresholds
from aegis_uba.detect import Analyzer
from aegis_uba.ingest import generate_synthetic, load_events_from_file
from aegis_uba.models import Action, Event, RiskLevel
from aegis_uba.report import render_html_report, write_reports
from aegis_uba.response import ResponseAction, auto_respond, dispatch
from aegis_uba.storage import Store


@pytest.fixture()
def events_and_truth():
    return generate_synthetic(users=25, days=25, seed=1337)


def test_synthetic_is_deterministic():
    a, pa = generate_synthetic(users=10, days=10, seed=5)
    b, pb = generate_synthetic(users=10, days=10, seed=5)
    assert len(a) == len(b)
    assert [e.user for e in a[:50]] == [e.user for e in b[:50]]
    assert pa == pb


def test_detection_flags_all_planted_scenarios(events_and_truth):
    events, planted = events_and_truth
    alerts = Analyzer(Thresholds()).analyze(events)
    by_user = {a.user: a for a in alerts}
    for p in planted:
        alert = by_user[p["user"]]
        assert alert.risk_level.rank >= RiskLevel.MEDIUM.rank, (
            f"{p['scenario']} for {p['user']} scored only {alert.risk_score}"
        )
        assert alert.explanations, "flagged users must have explanations"


def test_low_false_positive_rate(events_and_truth):
    events, planted = events_and_truth
    planted_users = {p["user"] for p in planted}
    alerts = Analyzer(Thresholds()).analyze(events)
    fps = [a for a in alerts if a.user not in planted_users
           and a.risk_level.rank >= RiskLevel.HIGH.rank]
    assert len(fps) == 0, f"unexpected HIGH+ false positives: {[a.user for a in fps]}"


def test_storage_roundtrip(tmp_path, events_and_truth):
    events, _ = events_and_truth
    store = Store(tmp_path / "t.sqlite3")
    n = store.add_events(events)
    assert n == len(events)
    assert store.event_count() == len(events)
    assert set(store.distinct_users()) == {e.user for e in events}
    reloaded = store.iter_events()
    assert reloaded[0].user == sorted(events, key=lambda e: e.timestamp)[0].user

    alerts = Analyzer(Thresholds()).analyze(events)
    assert store.replace_alerts(alerts) == len(alerts)
    got = store.get_alerts(min_level=RiskLevel.LOW)
    assert len(got) == len(alerts)
    assert got[0].explanations  # explanations survive serialization


def test_csv_loader_roundtrip(tmp_path):
    csv_path = tmp_path / "events.csv"
    csv_path.write_text(
        "timestamp,user,action,source_ip,bytes,success\n"
        "2026-01-01T09:00:00,alice,login,10.0.0.1,0,true\n"
        "2026-01-01T09:05:00,alice,file_download,10.0.0.1,1048576,true\n"
        "2026-01-01T09:06:00,bob,failed_login,203.0.113.5,0,false\n",
        encoding="utf-8",
    )
    events = load_events_from_file(csv_path)
    assert len(events) == 3
    assert events[0].action == Action.LOGIN
    assert events[1].bytes == 1048576
    assert events[2].success is False


def test_authlog_loader(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Jan 10 03:11:01 srv sshd[123]: Failed password for invalid user root from 203.0.113.9 port 2222 ssh2\n"
        "Jan 10 03:11:20 srv sshd[124]: Accepted password for deploy from 10.0.0.5 port 4020 ssh2\n"
        "Jan 10 03:12:00 srv sudo:   deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/cat /etc/shadow\n",
        encoding="utf-8",
    )
    events = load_events_from_file(log, "authlog")
    actions = {e.action for e in events}
    assert Action.FAILED_LOGIN in actions
    assert Action.LOGIN in actions
    assert Action.PRIVILEGE_ESCALATION in actions


def test_report_html_and_json(tmp_path, events_and_truth):
    events, _ = events_and_truth
    alerts = Analyzer(Thresholds()).analyze(events)
    cfg = Config(home=tmp_path)
    cfg.ensure_dirs()
    html = render_html_report(alerts, cfg)
    assert "Aegis UBA" in html and "Insider Threat" in html
    paths = write_reports(alerts, cfg, tmp_path)
    assert paths["html"].exists() and paths["json"].exists()
    data = json.loads(paths["json"].read_text())
    assert data["summary"]["total_users"] == len(alerts)


def test_response_is_simulated_by_default(tmp_path):
    store = Store(tmp_path / "t.sqlite3")
    cfg = Config(home=tmp_path)
    res = dispatch(store, cfg, "alice", ResponseAction.LOCK_ACCOUNT)
    assert res["mode"] == "SIMULATED"
    assert res["webhook"] == "no-webhook-configured"
    trail = store.get_responses()
    assert trail and trail[0]["user"] == "alice"


def test_auto_respond_maps_actions(tmp_path):
    events, _ = generate_synthetic(users=20, days=20, seed=1337)
    store = Store(tmp_path / "t.sqlite3")
    cfg = Config(home=tmp_path)
    alerts = Analyzer(Thresholds()).analyze(events)
    high = next(a for a in alerts if a.risk_level.rank >= RiskLevel.HIGH.rank)
    results = auto_respond(store, cfg, high)
    assert results and all(r["mode"] == "SIMULATED" for r in results)


def test_empty_input_is_safe():
    assert Analyzer(Thresholds()).analyze([]) == []


def test_event_action_coercion():
    e = Event(timestamp=datetime.now(), user="x", action="NOT_A_REAL_ACTION")
    assert e.action == Action.OTHER


# --- upgraded platform: train / persistence / datasets / stream -----------
def test_model_train_save_load_score(tmp_path, events_and_truth):
    events, planted = events_and_truth
    analyzer = Analyzer(Thresholds()).fit(events)
    assert analyzer.is_fitted
    path = tmp_path / "model.joblib"
    analyzer.save(path)
    assert path.exists()

    loaded = Analyzer.load(path)
    assert loaded.info()["fitted"] is True
    alerts = loaded.score(events)
    by_user = {a.user: a for a in alerts}
    # planted scenarios still detected when scoring against the persisted model
    caught = sum(by_user[p["user"]].risk_level.rank >= RiskLevel.MEDIUM.rank for p in planted)
    assert caught == len(planted)


def test_cert_loader(tmp_path):
    from aegis_uba.datasets import detect_cert_release, load_cert
    # minimal CERT-format release
    (tmp_path / "logon.csv").write_text(
        "id,date,user,pc,activity\n"
        "{1},01/04/2010 09:00:00,AAA0001,PC-1,Logon\n"
        "{2},01/04/2010 17:00:00,AAA0001,PC-1,Logoff\n", encoding="utf-8")
    (tmp_path / "device.csv").write_text(
        "id,date,user,pc,activity\n{3},01/04/2010 09:30:00,AAA0001,PC-1,Connect\n",
        encoding="utf-8")
    ldap = tmp_path / "LDAP"; ldap.mkdir()
    (ldap / "2010-01.csv").write_text(
        "employee_name,user_id,email,role,business_unit,functional_unit,department,team,supervisor\n"
        "Aaa,AAA0001,aaa@dtaa.com,Engineer,Eng,Eng,Engineering,E1,BOSS\n", encoding="utf-8")

    rel = detect_cert_release(tmp_path)
    assert "logon" in rel["present"] and "device" in rel["present"]
    events = load_cert(tmp_path)
    assert any(e.action == Action.LOGIN for e in events)
    assert any(e.action == Action.DATA_TRANSFER for e in events)
    assert all(e.department == "Engineering" for e in events)  # LDAP enrichment


def test_dataset_registry():
    from aegis_uba.datasets import REGISTRY, load_dataset
    assert "cert" in REGISTRY and "synthetic" in REGISTRY
    events = load_dataset("synthetic", users=8, days=8)
    assert len(events) > 0


def test_live_engine_start_stop():
    import time
    from aegis_uba.stream import LiveEngine
    eng = LiveEngine()
    q = eng.subscribe()
    eng.start(eps=30, inject_prob=0.4, warmup_users=12, warmup_days=10)
    time.sleep(2.5)
    st = eng.stop()
    assert st["events_emitted"] > 0
    assert not eng.status()["running"]
    types = {i.get("type") for i in eng.recent_feed(200)}
    assert "event" in types
