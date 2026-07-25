"""Authentication, RBAC, sessions and login-throttle tests."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from athena_itd import auth


# ── unit: password hashing ─────────────────────────────────────────────────
def test_password_hash_roundtrip():
    h = auth.hash_password("correct horse battery")
    assert h.startswith("scrypt$")
    assert auth.verify_password("correct horse battery", h)
    assert not auth.verify_password("wrong", h)


def test_password_min_length_enforced():
    with pytest.raises(ValueError):
        auth.hash_password("short")


def test_verify_rejects_garbage():
    assert not auth.verify_password("x", "not-a-valid-hash")


# ── unit: RBAC classifier ──────────────────────────────────────────────────
def test_role_ordering():
    assert auth.role_at_least("admin", "viewer")
    assert auth.role_at_least("analyst", "analyst")
    assert not auth.role_at_least("viewer", "analyst")
    assert not auth.role_at_least("analyst", "admin")


def test_required_role_classification():
    assert auth.required_role("GET", "/api/summary") == "viewer"
    assert auth.required_role("POST", "/api/alert/x/status") == "analyst"
    assert auth.required_role("POST", "/api/config") == "admin"
    assert auth.required_role("POST", "/api/reset") == "admin"
    assert auth.required_role("DELETE", "/api/accounts/bob") == "admin"


# ── unit: login throttle ───────────────────────────────────────────────────
def test_login_throttle_locks_after_max_fails():
    t = auth.LoginThrottle(max_fails=3, base_lock_seconds=10, window_seconds=100)
    assert t.check("bob", "1.2.3.4") == 0
    for _ in range(3):
        t.record_failure("bob", "1.2.3.4")
    assert t.check("bob", "1.2.3.4") > 0            # now locked
    t.record_success("bob", "1.2.3.4")
    assert t.check("bob", "1.2.3.4") == 0            # cleared on success


# ── unit: rate limiter ─────────────────────────────────────────────────────
def test_rate_limiter_fixed_window():
    rl = auth.RateLimiter()
    now = 1000.0                                     # mid-window
    for _ in range(5):
        assert rl.hit("k", 5, now=now) == 0          # first 5 allowed
    assert rl.hit("k", 5, now=now) > 0               # 6th blocked, wait > 0
    assert rl.hit("k", 5, now=now + 60) == 0         # next window resets


def test_rate_limiter_disabled_when_zero():
    rl = auth.RateLimiter()
    for _ in range(1000):
        assert rl.hit("k", 0) == 0                   # per_minute<=0 disables


# ── integration: full auth flow ────────────────────────────────────────────
@pytest.fixture()
def secured(tmp_path, monkeypatch):
    # get_config() reads ATHENA_HOME fresh on every call, so no module reload
    # is needed — reloading would corrupt pickled-model tests elsewhere.
    monkeypatch.setenv("ATHENA_HOME", str(tmp_path))
    import athena_itd.web.server as server
    cfg = server.get_config()
    cfg.security.auth_enabled = True
    cfg.security.users = {
        "admin1": {"password_hash": auth.hash_password("adminpass1"),
                   "role": "admin", "active": True},
        "viewer1": {"password_hash": auth.hash_password("viewerpass1"),
                    "role": "viewer", "active": True},
    }
    cfg.save()
    return TestClient(server.app), server


def test_unauthenticated_is_blocked(secured):
    c, _ = secured
    assert c.get("/api/summary").status_code == 401
    # console shell redirects to login
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/login"


def test_login_sets_session_and_grants_access(secured):
    c, _ = secured
    bad = c.post("/api/login", json={"username": "admin1", "password": "nope"})
    assert bad.status_code == 401
    ok = c.post("/api/login", json={"username": "admin1", "password": "adminpass1"})
    assert ok.status_code == 200 and ok.json()["role"] == "admin"
    assert auth.SESSION_COOKIE in c.cookies
    # now authorized
    assert c.get("/api/summary").status_code == 200
    me = c.get("/api/me").json()
    assert me["user"] == "admin1" and me["role"] == "admin"


def test_rbac_viewer_cannot_mutate_or_admin(secured):
    c, _ = secured
    c.post("/api/login", json={"username": "viewer1", "password": "viewerpass1"})
    csrf = c.cookies.get(auth.CSRF_COOKIE)
    # viewer may read
    assert c.get("/api/summary").status_code == 200
    # viewer may NOT hit an admin surface (403, not 401)
    r = c.post("/api/reset", json={"full": False},
               headers={auth.CSRF_HEADER: csrf})
    assert r.status_code == 403


def test_csrf_required_for_cookie_mutations(secured):
    c, _ = secured
    c.post("/api/login", json={"username": "admin1", "password": "adminpass1"})
    # missing CSRF header → 403 even though authenticated as admin
    r = c.post("/api/analyze")
    assert r.status_code == 403
    # with the token it passes the CSRF gate (400 = no data yet, but past auth)
    csrf = c.cookies.get(auth.CSRF_COOKIE)
    r2 = c.post("/api/analyze", headers={auth.CSRF_HEADER: csrf})
    assert r2.status_code in (200, 400)


def test_api_key_bypasses_csrf_for_automation(secured):
    c, server = secured
    cfg = server.get_config()
    cfg.security.api_key = "svc-key-123"
    cfg.save()
    # machine principal via header — no cookie, no CSRF needed
    r = c.post("/api/analyze", headers={"X-API-Key": "svc-key-123"})
    assert r.status_code in (200, 400)          # authorized (not 401/403)


def test_logout_revokes_session(secured):
    c, _ = secured
    c.post("/api/login", json={"username": "admin1", "password": "adminpass1"})
    csrf = c.cookies.get(auth.CSRF_COOKIE)
    assert c.get("/api/summary").status_code == 200
    c.post("/api/logout", headers={auth.CSRF_HEADER: csrf})
    assert c.get("/api/summary").status_code == 401


def test_disabled_user_cannot_login(secured):
    c, server = secured
    cfg = server.get_config()
    cfg.security.users["viewer1"]["active"] = False
    cfg.save()
    r = c.post("/api/login", json={"username": "viewer1", "password": "viewerpass1"})
    assert r.status_code == 401


# ── integration: self-service sign-up ──────────────────────────────────────
def test_signup_creates_non_admin_and_auto_logs_in(secured):
    c, server = secured
    cfg = server.get_config()
    cfg.security.allow_signup = True
    cfg.security.signup_role = "viewer"
    cfg.save()
    r = c.post("/api/signup", json={"username": "newbie", "password": "s3cretpass"})
    assert r.status_code == 200
    assert r.json()["role"] == "viewer"          # never admin
    assert auth.SESSION_COOKIE in c.cookies       # signed straight in
    # the new session can read but not reach an admin surface
    assert c.get("/api/summary").status_code == 200
    csrf = c.cookies.get(auth.CSRF_COOKIE)
    assert c.post("/api/reset", json={"full": False},
                  headers={auth.CSRF_HEADER: csrf}).status_code == 403


def test_signup_enforces_password_policy(secured):
    c, _ = secured
    r = c.post("/api/signup", json={"username": "shortpw", "password": "abc"})
    assert r.status_code == 400


def test_signup_rejects_duplicate_username(secured):
    c, _ = secured
    r = c.post("/api/signup", json={"username": "admin1", "password": "whatever8"})
    assert r.status_code == 409


def test_signup_can_be_disabled(secured):
    c, server = secured
    cfg = server.get_config()
    cfg.security.allow_signup = False
    cfg.save()
    r = c.post("/api/signup", json={"username": "nope", "password": "s3cretpass"})
    assert r.status_code == 403


def test_session_list_and_revoke(secured):
    c, _ = secured
    c.post("/api/login", json={"username": "admin1", "password": "adminpass1"})
    csrf = c.cookies.get(auth.CSRF_COOKIE)
    sessions = c.get("/api/sessions").json()
    assert len(sessions) >= 1
    mine = next(s for s in sessions if s["current"])
    assert mine["username"] == "admin1" and "id" in mine
    # revoking my own session signs me out
    r = c.delete(f"/api/sessions/{mine['id']}", headers={auth.CSRF_HEADER: csrf})
    assert r.status_code == 200
    assert c.get("/api/summary").status_code == 401


def test_session_list_requires_admin(secured):
    c, _ = secured
    c.post("/api/login", json={"username": "viewer1", "password": "viewerpass1"})
    assert c.get("/api/sessions").status_code == 403


def test_signup_never_grants_admin_even_if_misconfigured(secured):
    c, server = secured
    cfg = server.get_config()
    cfg.security.allow_signup = True
    cfg.security.signup_role = "admin"           # misconfiguration
    cfg.save()
    r = c.post("/api/signup", json={"username": "sneaky", "password": "s3cretpass"})
    assert r.status_code == 200
    assert r.json()["role"] == "viewer"           # downgraded, not admin


# ── integration: bootstrap & hardening guards ──────────────────────────────
def test_bootstrap_generates_unique_admin_password(tmp_path, monkeypatch):
    """Without ATHENA_ADMIN_PASSWORD the seeded admin gets a random one-time
    password — never the old shared default."""
    monkeypatch.setenv("ATHENA_HOME", str(tmp_path))
    monkeypatch.delenv("ATHENA_ADMIN_USER", raising=False)
    monkeypatch.delenv("ATHENA_ADMIN_PASSWORD", raising=False)
    import athena_itd.web.server as server
    server._bootstrap()
    admin = server.get_config().security.users.get("admin")
    assert admin and admin["role"] == "admin" and admin["active"]
    assert not auth.verify_password("a6m1n!!", admin["password_hash"])


def test_bootstrap_uses_env_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("ATHENA_HOME", str(tmp_path))
    monkeypatch.setenv("ATHENA_ADMIN_USER", "root1")
    monkeypatch.setenv("ATHENA_ADMIN_PASSWORD", "sup3rsecret!")
    import athena_itd.web.server as server
    server._bootstrap()
    users = server.get_config().security.users
    assert auth.verify_password("sup3rsecret!", users["root1"]["password_hash"])


def test_last_admin_cannot_be_demoted_or_deactivated(secured):
    c, _ = secured
    c.post("/api/login", json={"username": "admin1", "password": "adminpass1"})
    h = {auth.CSRF_HEADER: c.cookies.get(auth.CSRF_COOKIE)}
    assert c.patch("/api/accounts/admin1", json={"role": "analyst"},
                   headers=h).status_code == 400
    assert c.patch("/api/accounts/admin1", json={"active": False},
                   headers=h).status_code == 400
    # a second active admin lifts the guard
    assert c.patch("/api/accounts/viewer1", json={"role": "admin"},
                   headers=h).status_code == 200
    assert c.patch("/api/accounts/admin1", json={"role": "analyst"},
                   headers=h).status_code == 200


def test_signup_rate_limited_per_ip(secured, monkeypatch):
    c, _ = secured
    monkeypatch.setattr(auth.time, "time", lambda: 1_000_000.0)  # freeze window
    monkeypatch.setattr(auth.RATE_LIMITER, "_buckets", {})       # isolated state
    for i in range(10):
        r = c.post("/api/signup",
                   json={"username": f"bulk{i:02d}", "password": "s3cretpass"})
        assert r.status_code == 200
    r = c.post("/api/signup", json={"username": "bulk99", "password": "s3cretpass"})
    assert r.status_code == 429 and "Retry-After" in r.headers
