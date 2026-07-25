"""API-level tests for the hardened web layer (health/ready/metrics/headers/auth)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # get_config() reads ATHENA_HOME fresh per call, so pointing the env at an
    # isolated home is enough — no module reload (which would break other tests).
    monkeypatch.setenv("ATHENA_HOME", str(tmp_path))
    import athena_itd.web.server as server
    return TestClient(server.app), server


def test_health_is_db_free_and_ok(client):
    c, _ = client
    r = c.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_ready_reports_datastore(client):
    c, _ = client
    r = c.get("/api/ready")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"


def test_metrics_prometheus_format(client):
    c, _ = client
    c.get("/api/health")                       # generate at least one request
    r = c.get("/api/metrics")
    assert r.status_code == 200
    body = r.text
    assert "athena_http_requests_total" in body
    assert "# TYPE athena_http_requests_total counter" in body
    assert "athena_events" in body


def test_security_headers_present(client):
    c, _ = client
    r = c.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    # HSTS must NOT be sent over plain HTTP
    assert "Strict-Transport-Security" not in r.headers


def test_hsts_emitted_behind_tls_proxy(client):
    c, _ = client
    r = c.get("/api/health", headers={"X-Forwarded-Proto": "https"})
    assert "Strict-Transport-Security" in r.headers


def test_version_endpoint_is_public(client):
    c, _ = client
    r = c.get("/api/version")
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "ATHENA ITD"
    assert "version" in body and "python" in body


def test_rate_limit_returns_429(client):
    from athena_itd import auth
    c, server = client
    cfg = server.get_config()
    cfg.security.auth_enabled = True
    cfg.security.rate_limit_per_minute = 3
    cfg.security.users = {
        "admin1": {"password_hash": auth.hash_password("adminpass1"),
                   "role": "admin", "active": True},
    }
    cfg.save()
    # reset the shared limiter so other tests don't bleed into this window
    auth.RATE_LIMITER._buckets.clear()
    try:
        c.post("/api/login", json={"username": "admin1", "password": "adminpass1"})
        codes = [c.get("/api/summary").status_code for _ in range(6)]
        assert codes.count(200) == 3            # exactly the budget
        assert 429 in codes                     # then throttled
        # public probes are never rate limited
        assert c.get("/api/health").status_code == 200
    finally:
        cfg.security.auth_enabled = False
        cfg.security.rate_limit_per_minute = 600
        cfg.save()
        auth.RATE_LIMITER._buckets.clear()


def test_api_key_gate_blocks_and_admits(client):
    c, server = client
    cfg = server.get_config()
    cfg.security.auth_enabled = True
    cfg.security.api_key = "s3cr3t-key"
    cfg.save()
    try:
        assert c.get("/api/summary").status_code == 401          # missing key
        assert c.get("/api/summary",
                     headers={"X-API-Key": "wrong"}).status_code == 401
        ok = c.get("/api/summary", headers={"X-API-Key": "s3cr3t-key"})
        assert ok.status_code == 200
        # health/metrics stay open even with auth on
        assert c.get("/api/health").status_code == 200
        assert c.get("/api/metrics").status_code == 200
    finally:
        cfg.security.auth_enabled = False
        cfg.save()
