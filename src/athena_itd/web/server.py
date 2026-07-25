"""FastAPI application powering the ATHENA ITD enterprise SOC console.

Exposes the complete JSON API — summary, users, alerts + triage, cases, notes,
watchlist, analyst feedback, MITRE ATT&CK coverage, compliance coverage, geo
intelligence, detection config, model training, dataset loading, file ingest,
response actions, audit trail and a Server-Sent-Events live feed — behind a
single-page dashboard. Every capability in the GUI maps to an endpoint here, so
the same backend can drive a SIEM integration or an automation script.

When ``security.auth_enabled`` is set, every ``/api/*`` route (except health)
requires the ``X-API-Key`` header.
"""
from __future__ import annotations

import asyncio
import csv
import io
import logging
import secrets
import tempfile
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

from athena_itd import __version__
from athena_itd import auth as auth_mod
from athena_itd import compliance as compliance_mod
from athena_itd import mitre as mitre_mod
from athena_itd.config import Thresholds, get_config
from athena_itd.datasets import list_datasets, load_dataset
from athena_itd.detect import (
    DETECTORS,
    Analyzer,
    detector_compliance_map,
    detector_mitre_map,
)
from athena_itd.geo import classify_ip, geo_points
from athena_itd.ingest import generate_synthetic, load_events_from_file
from athena_itd.models import (
    AlertStatus,
    Case,
    CaseStatus,
    Feedback,
    Note,
    RiskLevel,
    Verdict,
    WatchlistEntry,
)
from athena_itd.response import (
    ACTION_CATALOG,
    ResponseAction,
    auto_respond,
    dispatch,
    forward_alert,
)
from athena_itd.storage import Store
from athena_itd.stream import ENGINE, sse_format

_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

def _bootstrap() -> None:
    """First-run admin provisioning + housekeeping.

    If auth is enabled but no accounts exist, create an admin from
    ATHENA_ADMIN_USER / ATHENA_ADMIN_PASSWORD (so a container can come up secured
    without an interactive step). Also clears expired sessions on boot.
    """
    import os
    cfg = get_config()
    try:
        _store().purge_expired_sessions()
    except Exception:  # noqa: BLE001
        pass
    if cfg.security.auth_enabled and not cfg.security.users:
        # First admin. Prefer ATHENA_ADMIN_USER / ATHENA_ADMIN_PASSWORD; without
        # them a random one-time password is generated and shown ONCE in the log
        # — there is deliberately no shared built-in default credential.
        user = os.environ.get("ATHENA_ADMIN_USER", "admin")
        pw = os.environ.get("ATHENA_ADMIN_PASSWORD", "")
        generated = not pw
        if generated:
            pw = secrets.token_urlsafe(12)
        try:
            cfg.security.users[user] = {
                "password_hash": auth_mod.hash_password(pw),
                "role": "admin", "active": True}
            cfg.save()
            if generated:
                _log.warning(
                    "bootstrapped admin '%s' with a generated one-time password: %s"
                    "  — sign in and change it (athena users passwd %s), or set "
                    "ATHENA_ADMIN_PASSWORD before first start.", user, pw, user)
            else:
                _log.warning("bootstrapped admin account '%s' from environment", user)
        except ValueError as exc:
            _log.error("admin bootstrap failed: %s", exc)


@asynccontextmanager
async def _lifespan(_app):
    _bootstrap()
    yield


app = FastAPI(title="ATHENA ITD", version=__version__, lifespan=_lifespan)

from fastapi.staticfiles import StaticFiles  # noqa: E402

# Cross-origin access is off unless explicitly allow-listed in config
# (security.cors_origins). Credentials are allowed so cookie sessions work
# from a first-party SPA on a different host.
_cors_origins = get_config().security.cors_origins
if _cors_origins:
    from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")),
          name="static")


def _store() -> Store:
    return Store(get_config().db_path)


def _actor(request: Request) -> str:
    """The authenticated principal for attribution — a real username when the
    caller logged in, 'api' for key-authenticated automation, else 'console'."""
    p = getattr(request.state, "principal", None)
    return p["user"] if p else "console"


def _audit(request: Request, action: str, target: str = "", detail: str = "") -> None:
    """Record an operator action, attributed to the authenticated principal."""
    try:
        ip = request.client.host if request.client else ""
        _store().log_audit(_actor(request), action, target, detail, ip)
    except Exception:   # auditing must never break the operation itself
        pass


_log = logging.getLogger("athena_itd.web")

# --- lightweight in-process metrics (Prometheus text exposition) -----------
_METRICS: dict[str, float] = defaultdict(float)
_LATENCY_SUM: dict[str, float] = defaultdict(float)
_LATENCY_CNT: dict[str, float] = defaultdict(float)


def _bucket(path: str) -> str:
    """Collapse high-cardinality ids so metrics don't explode per-user/-alert."""
    parts = path.split("/")
    out = []
    for p in parts:
        if p.isdigit() or (len(p) >= 12 and any(c.isdigit() for c in p)):
            out.append(":id")
        else:
            out.append(p)
    return "/".join(out) or "/"


# --- authentication & RBAC -------------------------------------------------
def _resolve_principal(request: Request):
    """Identify the caller: session cookie → user; X-API-Key → admin service;
    else None. Returns a dict {user, role, kind} or None."""
    cfg = get_config()
    # 1. session cookie
    raw = request.cookies.get(auth_mod.SESSION_COOKIE)
    if raw:
        sess = _store().get_session(auth_mod.hash_token(raw))
        if sess:
            return {"user": sess["username"], "role": sess["role"], "kind": "session"}
    # 2. API key → full-access service principal (machine/automation)
    supplied = request.headers.get("x-api-key", "")
    if supplied and cfg.security.api_key and \
            secrets.compare_digest(supplied, cfg.security.api_key):
        return {"user": "api", "role": "admin", "kind": "apikey"}
    return None


@app.middleware("http")
async def auth_guard(request: Request, call_next):
    path = request.url.path
    cfg = get_config()
    request.state.principal = None

    # auth disabled → fully open (local/demo); attribute to console as admin
    if not cfg.security.auth_enabled:
        request.state.principal = None
        return await call_next(request)

    principal = _resolve_principal(request)
    request.state.principal = principal

    # console shell: bounce browsers to the login page when unauthenticated
    if path == "/" and principal is None:
        return RedirectResponse("/login", status_code=302)

    if path.startswith("/api/") and not auth_mod.is_public_path(path):
        # coarse per-caller rate limit (abuse brake; per-process window)
        limit = cfg.security.rate_limit_per_minute
        if limit > 0:
            ident = principal["user"] if principal else (
                request.client.host if request.client else "anon")
            retry = auth_mod.RATE_LIMITER.hit(ident, limit)
            if retry > 0:
                _METRICS["athena_http_rate_limited_total"] += 1
                return JSONResponse(
                    {"detail": "rate limit exceeded"}, status_code=429,
                    headers={"Retry-After": str(int(retry) + 1)})
        if principal is None:
            _METRICS["athena_http_unauthorized_total"] += 1
            return JSONResponse({"detail": "authentication required"}, status_code=401)
        # role check
        need = auth_mod.required_role(request.method, path)
        if not auth_mod.role_at_least(principal["role"], need):
            _METRICS["athena_http_forbidden_total"] += 1
            return JSONResponse(
                {"detail": f"role '{principal['role']}' lacks '{need}' permission"},
                status_code=403)
        # CSRF double-submit for cookie-authenticated mutations
        if principal["kind"] == "session" and request.method not in ("GET", "HEAD", "OPTIONS"):
            hdr = request.headers.get(auth_mod.CSRF_HEADER, "")
            cookie = request.cookies.get(auth_mod.CSRF_COOKIE, "")
            if not hdr or not cookie or not secrets.compare_digest(hdr, cookie):
                _METRICS["athena_http_forbidden_total"] += 1
                return JSONResponse({"detail": "missing or invalid CSRF token"},
                                    status_code=403)
    return await call_next(request)


# --- security headers + metrics + access log -------------------------------
@app.middleware("http")
async def hardening(request: Request, call_next):
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:                       # noqa: BLE001 — count then re-raise
        _METRICS["athena_http_errors_total"] += 1
        _log.exception("unhandled error on %s %s", request.method, request.url.path)
        raise
    elapsed = time.perf_counter() - start

    # response headers: safe defaults that don't break the self-contained SPA
    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("X-XSS-Protection", "0")
    h.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    # only advertise HSTS when the request actually arrived over TLS
    if request.url.scheme == "https" or \
            request.headers.get("x-forwarded-proto") == "https":
        h.setdefault("Strict-Transport-Security",
                     "max-age=31536000; includeSubDomains")

    # metrics
    key = _bucket(request.url.path)
    _METRICS["athena_http_requests_total"] += 1
    _LATENCY_SUM[key] += elapsed
    _LATENCY_CNT[key] += 1
    if response.status_code >= 500:
        _METRICS["athena_http_5xx_total"] += 1

    # structured-ish access log (uvicorn access log is disabled in serve)
    _log.info("%s %s -> %s %.1fms", request.method, request.url.path,
              response.status_code, elapsed * 1000)
    return response


# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    cfg = get_config()
    return _TEMPLATES.TemplateResponse(
        request, "dashboard.html",
        {"organization": cfg.organization, "version": __version__},
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    cfg = get_config()
    # already authenticated → straight to the console
    if not cfg.security.auth_enabled or _resolve_principal(request):
        return RedirectResponse("/", status_code=302)
    return _TEMPLATES.TemplateResponse(
        request, "login.html",
        {"organization": cfg.organization, "allow_signup": cfg.security.allow_signup})


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request) -> HTMLResponse:
    cfg = get_config()
    if not cfg.security.auth_enabled or _resolve_principal(request):
        return RedirectResponse("/", status_code=302)
    if not cfg.security.allow_signup:
        return RedirectResponse("/login", status_code=302)
    return _TEMPLATES.TemplateResponse(
        request, "signup.html",
        {"organization": cfg.organization, "signup_role": cfg.security.signup_role})


# --- authentication endpoints ----------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


def _set_session_cookies(resp: JSONResponse, raw_token: str, secure: bool) -> None:
    csrf = secrets.token_urlsafe(24)
    resp.set_cookie(auth_mod.SESSION_COOKIE, raw_token, httponly=True,
                    samesite="lax", secure=secure, path="/")
    # readable by JS for the double-submit CSRF check
    resp.set_cookie(auth_mod.CSRF_COOKIE, csrf, httponly=False,
                    samesite="lax", secure=secure, path="/")


@app.post("/api/login")
def api_login(req: LoginRequest, request: Request) -> JSONResponse:
    cfg = get_config()
    ip = request.client.host if request.client else ""
    if not cfg.security.auth_enabled:
        return JSONResponse({"detail": "authentication is disabled"}, status_code=400)

    wait = auth_mod.THROTTLE.check(req.username, ip)
    if wait > 0:
        _METRICS["athena_login_throttled_total"] += 1
        return JSONResponse(
            {"detail": f"too many attempts; retry in {int(wait)}s"}, status_code=429)

    user = cfg.security.users.get(req.username)
    ok = bool(user) and user.get("active", True) and \
        auth_mod.verify_password(req.password, user.get("password_hash", ""))
    if not ok:
        auth_mod.THROTTLE.record_failure(req.username, ip)
        _METRICS["athena_login_failed_total"] += 1
        _store().log_audit(req.username, "login_failed", detail="bad credentials",
                           source_ip=ip)
        return JSONResponse({"detail": "invalid username or password"}, status_code=401)

    auth_mod.THROTTLE.record_success(req.username, ip)
    raw, token_hash = auth_mod.new_session_token()
    role = user.get("role", "viewer")
    _store().create_session(token_hash, req.username, role,
                            cfg.security.session_ttl_minutes, ip)
    _store().log_audit(req.username, "login", detail=f"role={role}", source_ip=ip)
    secure = request.url.scheme == "https" or \
        request.headers.get("x-forwarded-proto") == "https"
    resp = JSONResponse({"user": req.username, "role": role})
    _set_session_cookies(resp, raw, secure)
    return resp


class SignupRequest(BaseModel):
    username: str
    password: str


@app.post("/api/signup")
def api_signup(req: SignupRequest, request: Request) -> JSONResponse:
    """Self-service registration. Always creates a NON-admin account and, on
    success, signs the new user straight in."""
    import re

    cfg = get_config()
    if not cfg.security.auth_enabled:
        return JSONResponse({"detail": "authentication is disabled"}, status_code=400)
    if not cfg.security.allow_signup:
        return JSONResponse({"detail": "sign-up is disabled by the administrator"},
                            status_code=403)
    # registration is a rare human action — cap it per source IP so an open
    # sign-up page can't be used for bulk account creation
    ip = request.client.host if request.client else ""
    retry = auth_mod.RATE_LIMITER.hit(f"signup:{ip}", 10)
    if retry > 0:
        _METRICS["athena_http_rate_limited_total"] += 1
        return JSONResponse({"detail": "too many sign-up attempts; try again shortly"},
                            status_code=429,
                            headers={"Retry-After": str(int(retry) + 1)})
    username = (req.username or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,32}", username):
        return JSONResponse(
            {"detail": "username must be 3–32 characters: letters, digits, . _ -"},
            status_code=400)
    if username in cfg.security.users:
        return JSONResponse({"detail": "that username is already taken"}, status_code=409)
    try:
        pw_hash = auth_mod.hash_password(req.password)      # enforces 8-char minimum
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)

    # self-registration can never grant admin; fall back to viewer if misconfigured
    role = cfg.security.signup_role
    if role not in auth_mod.ROLES or role == "admin":
        role = "viewer"
    cfg.security.users[username] = {
        "password_hash": pw_hash, "role": role, "active": True}
    cfg.save()

    raw, token_hash = auth_mod.new_session_token()
    _store().create_session(token_hash, username, role,
                            cfg.security.session_ttl_minutes, ip)
    _store().log_audit(username, "signup", detail=f"role={role}", source_ip=ip)
    secure = request.url.scheme == "https" or \
        request.headers.get("x-forwarded-proto") == "https"
    resp = JSONResponse({"user": username, "role": role})
    _set_session_cookies(resp, raw, secure)
    return resp


@app.post("/api/logout")
def api_logout(request: Request) -> JSONResponse:
    raw = request.cookies.get(auth_mod.SESSION_COOKIE)
    if raw:
        _store().delete_session(auth_mod.hash_token(raw))
        _audit(request, "logout")
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth_mod.SESSION_COOKIE, path="/")
    resp.delete_cookie(auth_mod.CSRF_COOKIE, path="/")
    return resp


@app.get("/api/me")
def api_me(request: Request) -> dict:
    cfg = get_config()
    p = getattr(request.state, "principal", None)
    return {
        "authenticated": p is not None or not cfg.security.auth_enabled,
        "auth_enabled": cfg.security.auth_enabled,
        "user": (p or {}).get("user", "console" if not cfg.security.auth_enabled else None),
        "role": (p or {}).get("role", "admin" if not cfg.security.auth_enabled else None),
    }


# --- user management (admin only) ------------------------------------------
class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class UserUpdate(BaseModel):
    password: str | None = None
    role: str | None = None
    active: bool | None = None


@app.get("/api/accounts")
def api_users_list() -> list[dict]:
    cfg = get_config()
    return [{"username": u, "role": v.get("role", "viewer"),
             "active": v.get("active", True)}
            for u, v in sorted(cfg.security.users.items())]


@app.post("/api/accounts")
def api_users_create(req: UserCreate, request: Request) -> dict:
    cfg = get_config()
    if req.role not in auth_mod.ROLES:
        raise HTTPException(400, f"role must be one of {auth_mod.ROLES}")
    if req.username in cfg.security.users:
        raise HTTPException(409, "user already exists")
    try:
        pw_hash = auth_mod.hash_password(req.password)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    cfg.security.users[req.username] = {
        "password_hash": pw_hash, "role": req.role, "active": True}
    cfg.save()
    _audit(request, "user_created", req.username, f"role={req.role}")
    return {"username": req.username, "role": req.role, "active": True}


@app.patch("/api/accounts/{username}")
def api_users_update(username: str, req: UserUpdate, request: Request) -> dict:
    cfg = get_config()
    user = cfg.security.users.get(username)
    if not user:
        raise HTTPException(404, "no such user")
    # demoting or deactivating the only remaining active admin would lock the
    # platform out of its own administration — refuse (mirrors the delete guard)
    if user.get("role") == "admin" and user.get("active", True) and \
            ((req.role is not None and req.role != "admin") or req.active is False):
        admins = [u for u, v in cfg.security.users.items()
                  if v.get("role") == "admin" and v.get("active", True)]
        if admins == [username]:
            raise HTTPException(400, "cannot demote or deactivate the last active admin")
    if req.role is not None:
        if req.role not in auth_mod.ROLES:
            raise HTTPException(400, f"role must be one of {auth_mod.ROLES}")
        user["role"] = req.role
    if req.password is not None:
        try:
            user["password_hash"] = auth_mod.hash_password(req.password)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        _store().delete_user_sessions(username)   # force re-login after reset
    if req.active is not None:
        user["active"] = req.active
        if not req.active:
            _store().delete_user_sessions(username)
    cfg.security.users[username] = user
    cfg.save()
    _audit(request, "user_updated", username,
           f"role={user.get('role')} active={user.get('active', True)}")
    return {"username": username, "role": user.get("role"), "active": user.get("active", True)}


@app.delete("/api/accounts/{username}")
def api_users_delete(username: str, request: Request) -> dict:
    cfg = get_config()
    if username not in cfg.security.users:
        raise HTTPException(404, "no such user")
    admins = [u for u, v in cfg.security.users.items()
              if v.get("role") == "admin" and v.get("active", True)]
    if cfg.security.users[username].get("role") == "admin" and admins == [username]:
        raise HTTPException(400, "cannot delete the last active admin")
    del cfg.security.users[username]
    cfg.save()
    _store().delete_user_sessions(username)
    _audit(request, "user_deleted", username)
    return {"ok": True, "deleted": username}


# --- active session management (admin only) --------------------------------
@app.get("/api/sessions")
def api_sessions_list(request: Request) -> list[dict]:
    """Live sign-in sessions. The token hash is an opaque id (cannot re-auth)."""
    current = request.cookies.get(auth_mod.SESSION_COOKIE)
    current_hash = auth_mod.hash_token(current) if current else None
    out = []
    for s in _store().list_sessions():
        out.append({
            "id": s["token_hash"],
            "username": s["username"], "role": s["role"],
            "created_at": s["created_at"], "expires_at": s["expires_at"],
            "source_ip": s.get("source_ip", ""),
            "current": s["token_hash"] == current_hash,
        })
    return out


@app.delete("/api/sessions/{sid}")
def api_sessions_revoke(sid: str, request: Request) -> dict:
    """Revoke a single session by its id (immediately signs that browser out)."""
    if not _store().delete_session(sid):
        raise HTTPException(404, "no such session")
    _audit(request, "session_revoked", sid[:12])
    return {"ok": True, "revoked": sid[:12]}


# --- overview & summary ----------------------------------------------------
@app.get("/api/summary")
def api_summary() -> dict:
    cfg = get_config()
    store = _store()
    alerts = store.get_alerts()
    counts = {lvl.value: 0 for lvl in RiskLevel}
    open_by_status: dict[str, int] = {}
    for a in alerts:
        counts[a.risk_level.value] += 1
        open_by_status[a.status.value] = open_by_status.get(a.status.value, 0) + 1
    per_day: dict[str, int] = {}
    bytes_per_day: dict[str, int] = {}
    for e in store.iter_events():
        key = e.timestamp.date().isoformat()
        per_day[key] = per_day.get(key, 0) + 1
        bytes_per_day[key] = bytes_per_day.get(key, 0) + e.bytes
    trend = sorted(per_day.items())[-30:]
    model_info = {"fitted": False}
    if cfg.model_path.exists():
        try:
            model_info = Analyzer.load(cfg.model_path).info()
        except Exception:
            model_info = {"fitted": False}
    top = [
        {"user": a.user, "risk_score": a.risk_score, "risk_level": a.risk_level.value,
         "department": a.department, "status": a.status.value,
         "top_factor": a.explanations[0].factor if a.explanations else "—"}
        for a in alerts[:6]
    ]
    threat = "NONE"
    for lvl in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW):
        if counts[lvl.value]:
            threat = lvl.value
            break
    cases_open = len(store.get_cases(open_only=True))
    return {
        "organization": cfg.organization,
        "version": __version__,
        "total_events": store.event_count(),
        "total_users": len(store.distinct_users()),
        "analyzed": len(alerts),
        "counts": counts,
        "open_by_status": open_by_status,
        "flagged": counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"],
        "threat_level": threat,
        "top_users": top,
        "trend_labels": [d for d, _ in trend],
        "trend_values": [v for _, v in trend],
        "trend_bytes": [bytes_per_day.get(d, 0) for d, _ in trend],
        "model": model_info,
        "stream": ENGINE.status(),
        "response_count": len(store.get_responses()),
        "cases_open": cases_open,
        "watchlist_count": len(store.watchlist()),
        "auth_enabled": cfg.security.auth_enabled,
    }


# --- users -----------------------------------------------------------------
@app.get("/api/users")
def api_users(q: str = "", department: str = "", min_level: str = "LOW") -> list[dict]:
    store = _store()
    try:
        lvl = RiskLevel(min_level.upper())
    except ValueError:
        raise HTTPException(400, f"invalid level: {min_level}")
    alerts = {a.user: a for a in store.get_alerts()}
    watched = {w.user for w in store.watchlist()}
    rows = []
    for u in store.user_directory():
        a = alerts.get(u["user"])
        level = a.risk_level.value if a else "LOW"
        score = a.risk_score if a else 0.0
        if RiskLevel(level).rank < lvl.rank:
            continue
        if q and q.lower() not in u["user"].lower():
            continue
        if department and department.lower() != (u["department"] or "").lower():
            continue
        rows.append({
            "user": u["user"], "department": u["department"], "role": u["role"],
            "host": u["host"], "source_ip": u["source_ip"],
            "first_seen": u["first_seen"], "last_seen": u["last_seen"],
            "event_count": u["event_count"],
            "risk_score": score, "risk_level": level,
            "status": a.status.value if a else "",
            "watchlisted": u["user"] in watched,
            "top_factor": (a.explanations[0].factor if a and a.explanations else "—"),
        })
    rows.sort(key=lambda r: r["risk_score"], reverse=True)
    return rows


@app.get("/api/departments")
def api_departments() -> list[str]:
    return sorted({u["department"] for u in _store().user_directory() if u["department"]})


# --- alerts & triage -------------------------------------------------------
@app.get("/api/alerts")
def api_alerts(min_level: str = "LOW", q: str = "", status: str = "") -> list[dict]:
    store = _store()
    try:
        lvl = RiskLevel(min_level.upper())
    except ValueError:
        raise HTTPException(400, f"invalid level: {min_level}")
    out = []
    for a in store.get_alerts(min_level=lvl, status=status or None):
        if q and q.lower() not in a.user.lower():
            continue
        d = a.model_dump(mode="json")
        d["dedup_key"] = a.dedup_key
        d["summary"] = a.summary
        out.append(d)
    return out


class StatusUpdate(BaseModel):
    status: str
    assignee: str | None = None


@app.post("/api/alert/{dedup_key}/status")
def api_alert_status(dedup_key: str, update: StatusUpdate, request: Request) -> dict:
    try:
        status = AlertStatus(update.status.lower())
    except ValueError:
        raise HTTPException(400, f"invalid status: {update.status}")
    if not _store().set_alert_status(dedup_key, status, update.assignee):
        raise HTTPException(404, f"unknown alert {dedup_key}")
    _audit(request, "alert_triage", dedup_key,
           f"status={status.value} assignee={update.assignee or '-'}")
    return {"ok": True, "dedup_key": dedup_key, "status": status.value}


class FeedbackRequest(BaseModel):
    verdict: str
    detector: str = ""
    analyst: str = ""
    note: str = ""


@app.post("/api/alert/{dedup_key}/feedback")
def api_alert_feedback(dedup_key: str, req: FeedbackRequest, request: Request) -> dict:
    store = _store()
    alert = store.get_alert(dedup_key)
    if alert is None:
        raise HTTPException(404, f"unknown alert {dedup_key}")
    try:
        verdict = Verdict(req.verdict.lower())
    except ValueError:
        raise HTTPException(400, f"invalid verdict: {req.verdict}")
    detectors = [req.detector] if req.detector else (alert.detectors or [""])
    for det in detectors:
        store.add_feedback(Feedback(alert_key=dedup_key, user=alert.user,
                                    detector=det, verdict=verdict,
                                    analyst=req.analyst, note=req.note))
    if verdict == Verdict.FALSE_POSITIVE:
        store.set_alert_status(dedup_key, AlertStatus.FALSE_POSITIVE)
    _audit(request, "alert_feedback", dedup_key, f"verdict={verdict.value}")
    return {"ok": True, "verdict": verdict.value, "detectors": detectors}


@app.get("/api/feedback/stats")
def api_feedback_stats() -> dict:
    return {"detectors": _store().detector_precision(),
            "feedback": _store().get_feedback()[:100]}


# --- investigation ---------------------------------------------------------
@app.get("/api/user/{user}")
def api_user(user: str) -> dict:
    store = _store()
    match = [a for a in store.get_alerts() if a.user == user]
    events = store.events_for_user(user)
    if not match and not events:
        raise HTTPException(404, f"unknown user {user}")
    tail = [
        {"timestamp": e.timestamp.isoformat(), "action": e.action.value,
         "resource": e.resource, "source_ip": e.source_ip, "country": e.country,
         "host": e.host, "bytes": e.bytes, "success": e.success}
        for e in events[-80:]
    ]
    hours = [0] * 24
    actions: dict[str, int] = {}
    daily: dict[str, dict] = {}
    for e in events:
        hours[e.timestamp.hour] += 1
        actions[e.action.value] = actions.get(e.action.value, 0) + 1
        d = daily.setdefault(e.timestamp.date().isoformat(),
                             {"events": 0, "bytes": 0})
        d["events"] += 1
        d["bytes"] += e.bytes
    days = sorted(daily.items())[-30:]
    alert = None
    if match:
        alert = match[0].model_dump(mode="json")
        alert["dedup_key"] = match[0].dedup_key
        alert["mitre_detail"] = mitre_mod.describe(match[0].mitre_techniques)
    watched = {w.user: w for w in store.watchlist()}
    return {
        "alert": alert,
        "events": tail,
        "event_total": len(events),
        "hour_histogram": hours,
        "action_breakdown": dict(sorted(actions.items(), key=lambda kv: -kv[1])),
        "daily_labels": [d for d, _ in days],
        "daily_events": [v["events"] for _, v in days],
        "daily_bytes": [v["bytes"] for _, v in days],
        "notes": [n.model_dump(mode="json") for n in store.get_notes("user", user)],
        "watchlisted": (watched[user].model_dump(mode="json")
                        if user in watched else None),
    }


# --- notes -----------------------------------------------------------------
class NoteRequest(BaseModel):
    body: str
    author: str = "analyst"


@app.get("/api/notes/{target_type}/{target_id}")
def api_get_notes(target_type: str, target_id: str) -> list[dict]:
    return [n.model_dump(mode="json")
            for n in _store().get_notes(target_type, target_id)]


@app.post("/api/notes/{target_type}/{target_id}")
def api_add_note(target_type: str, target_id: str, req: NoteRequest,
                 request: Request) -> dict:
    if target_type not in ("alert", "case", "user"):
        raise HTTPException(400, "target_type must be alert|case|user")
    if not req.body.strip():
        raise HTTPException(400, "empty note")
    note = _store().add_note(Note(target_type=target_type, target_id=target_id,
                                  author=req.author, body=req.body.strip()))
    _audit(request, "note_added", f"{target_type}:{target_id}")
    return note.model_dump(mode="json")


# --- cases -----------------------------------------------------------------
class CaseRequest(BaseModel):
    title: str
    subject_user: str
    severity: str = "MEDIUM"
    owner: str = ""
    summary: str = ""
    alert_key: str | None = None
    tags: list[str] = []


@app.get("/api/cases")
def api_cases(open_only: bool = False) -> list[dict]:
    return [c.model_dump(mode="json") for c in _store().get_cases(open_only=open_only)]


@app.post("/api/cases")
def api_create_case(req: CaseRequest, request: Request) -> dict:
    store = _store()
    try:
        severity = RiskLevel(req.severity.upper())
    except ValueError:
        raise HTTPException(400, f"invalid severity: {req.severity}")
    case = store.create_case(Case(
        title=req.title, subject_user=req.subject_user, severity=severity,
        owner=req.owner, summary=req.summary, tags=req.tags,
        alert_keys=[req.alert_key] if req.alert_key else []))
    if req.alert_key:
        store.link_alert_case(req.alert_key, case.id)
        store.set_alert_status(req.alert_key, AlertStatus.INVESTIGATING)
    _audit(request, "case_created", str(case.id), case.title)
    return case.model_dump(mode="json")


class CaseUpdate(BaseModel):
    title: str | None = None
    status: str | None = None
    severity: str | None = None
    owner: str | None = None
    summary: str | None = None
    verdict: str | None = None
    tags: list[str] | None = None


@app.get("/api/case/{case_id}")
def api_get_case(case_id: int) -> dict:
    store = _store()
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(404, f"unknown case {case_id}")
    d = case.model_dump(mode="json")
    d["notes"] = [n.model_dump(mode="json")
                  for n in store.get_notes("case", str(case_id))]
    d["alerts"] = [
        {**a.model_dump(mode="json"), "dedup_key": a.dedup_key}
        for a in store.get_alerts() if a.case_id == case_id
    ]
    return d


@app.patch("/api/case/{case_id}")
def api_update_case(case_id: int, update: CaseUpdate, request: Request) -> dict:
    store = _store()
    if store.get_case(case_id) is None:
        raise HTTPException(404, f"unknown case {case_id}")
    fields: dict = {}
    if update.status is not None:
        try:
            status = CaseStatus(update.status.lower())
        except ValueError:
            raise HTTPException(400, f"invalid status: {update.status}")
        fields["status"] = status.value
        if not status.is_open:
            fields["closed_at"] = datetime.now(timezone.utc).isoformat()
    if update.severity is not None:
        try:
            fields["severity"] = RiskLevel(update.severity.upper()).value
        except ValueError:
            raise HTTPException(400, f"invalid severity: {update.severity}")
    if update.verdict is not None:
        try:
            fields["verdict"] = Verdict(update.verdict.lower()).value
        except ValueError:
            raise HTTPException(400, f"invalid verdict: {update.verdict}")
    for key in ("title", "owner", "summary", "tags"):
        val = getattr(update, key)
        if val is not None:
            fields[key] = val
    store.update_case(case_id, **fields)
    _audit(request, "case_updated", str(case_id), ", ".join(fields))
    return _store().get_case(case_id).model_dump(mode="json")


class CaseLink(BaseModel):
    alert_key: str


@app.post("/api/case/{case_id}/link")
def api_link_case(case_id: int, req: CaseLink, request: Request) -> dict:
    store = _store()
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(404, f"unknown case {case_id}")
    if not store.link_alert_case(req.alert_key, case_id):
        raise HTTPException(404, f"unknown alert {req.alert_key}")
    keys = sorted(set(case.alert_keys) | {req.alert_key})
    store.update_case(case_id, alert_keys=keys)
    _audit(request, "case_alert_linked", str(case_id), req.alert_key)
    return {"ok": True, "case_id": case_id, "alert_keys": keys}


# --- watchlist -------------------------------------------------------------
class WatchRequest(BaseModel):
    user: str
    reason: str
    multiplier: float = 1.35
    expires_days: int | None = None
    added_by: str = "analyst"


@app.get("/api/watchlist")
def api_watchlist() -> list[dict]:
    return [w.model_dump(mode="json") for w in _store().watchlist(active_only=False)]


@app.post("/api/watchlist")
def api_watchlist_add(req: WatchRequest, request: Request) -> dict:
    expires = (datetime.now(timezone.utc) + timedelta(days=req.expires_days)
               if req.expires_days else None)
    entry = WatchlistEntry(user=req.user, reason=req.reason,
                           multiplier=max(1.0, min(3.0, req.multiplier)),
                           added_by=req.added_by, expires_at=expires)
    _store().watchlist_add(entry)
    _audit(request, "watchlist_add", req.user, req.reason)
    return entry.model_dump(mode="json")


@app.delete("/api/watchlist/{user}")
def api_watchlist_remove(user: str, request: Request) -> dict:
    if not _store().watchlist_remove(user):
        raise HTTPException(404, f"{user} not on watchlist")
    _audit(request, "watchlist_remove", user)
    return {"ok": True, "user": user}


# --- MITRE / compliance / geo ---------------------------------------------
@app.get("/api/mitre")
def api_mitre() -> dict:
    store = _store()
    hits: dict[str, int] = {}
    for a in store.get_alerts():
        for t in a.mitre_techniques:
            hits[t] = hits.get(t, 0) + 1
    return mitre_mod.coverage_matrix(detector_mitre_map(), hits)


@app.get("/api/compliance")
def api_compliance() -> dict:
    store = _store()
    evidence: dict[str, int] = {}
    for a in store.get_alerts():
        for d in a.detectors:
            evidence[d] = evidence.get(d, 0) + 1
    report = compliance_mod.coverage_report(detector_compliance_map(), evidence)
    report["frameworks_meta"] = compliance_mod.list_frameworks()
    return report


@app.get("/api/geo")
def api_geo() -> dict:
    store = _store()
    points = geo_points(store.country_counts())
    # Reputation summary over the distinct source addresses seen.
    categories: dict[str, int] = {}
    flagged: list[dict] = []
    seen: set[str] = set()
    for u in store.user_directory():
        ip = u["source_ip"]
        if not ip or ip in seen:
            continue
        seen.add(ip)
        info = classify_ip(ip)
        categories[info["category"]] = categories.get(info["category"], 0) + 1
        if info["category"] in ("tor", "vpn", "hosting"):
            flagged.append({**info, "user": u["user"]})
    return {"points": points, "ip_categories": categories, "flagged_ips": flagged}


@app.get("/api/ip/{ip}")
def api_ip(ip: str) -> dict:
    return classify_ip(ip)


# --- audit -----------------------------------------------------------------
@app.get("/api/audit")
def api_audit(limit: int = 200) -> list[dict]:
    return _store().get_audit(limit=limit)


# --- detection catalogue ---------------------------------------------------
@app.get("/api/detections")
def api_detections() -> dict:
    cfg = get_config()
    detectors = []
    for key, d in DETECTORS.items():
        detectors.append({
            "key": key, "name": d.name, "type": d.kind, "detail": d.detail,
            "max_points": d.max_points, "mitre": list(d.mitre),
            "enabled": key not in cfg.disabled_detectors,
            "weight": cfg.detector_weights.get(key, 1.0),
        })
    return {"detectors": detectors, "thresholds": _thresholds_dict()}


class DetectorUpdate(BaseModel):
    key: str
    enabled: bool | None = None
    weight: float | None = None


@app.post("/api/detections")
def api_update_detector(update: DetectorUpdate, request: Request) -> dict:
    if update.key not in DETECTORS:
        raise HTTPException(400, f"unknown detector: {update.key}")
    cfg = get_config()
    if update.enabled is not None:
        disabled = set(cfg.disabled_detectors)
        (disabled.discard if update.enabled else disabled.add)(update.key)
        cfg.disabled_detectors = sorted(disabled)
    if update.weight is not None:
        w = max(0.1, min(3.0, update.weight))
        if abs(w - 1.0) < 1e-9:
            cfg.detector_weights.pop(update.key, None)
        else:
            cfg.detector_weights[update.key] = w
    cfg.save()
    _audit(request, "detector_updated", update.key,
           f"enabled={update.enabled} weight={update.weight}")
    return api_detections()


# --- config ----------------------------------------------------------------
def _thresholds_dict() -> dict:
    th = get_config().thresholds
    return {
        "low": th.low, "medium": th.medium, "high": th.high, "critical": th.critical,
        "contamination": th.contamination,
        "business_start_hour": th.business_start_hour,
        "business_end_hour": th.business_end_hour,
        "failed_login_burst": th.failed_login_burst,
        "data_exfil_zscore": th.data_exfil_zscore,
        "new_geo_penalty": th.new_geo_penalty,
        "peer_deviation_sigma": th.peer_deviation_sigma,
        "mass_access_files": th.mass_access_files,
        "mass_delete_files": th.mass_delete_files,
        "lateral_host_count": th.lateral_host_count,
        "dormancy_days": th.dormancy_days,
        "weight_ml": th.weight_ml, "weight_rules": th.weight_rules,
        "weight_peer": th.weight_peer, "weight_sequence": th.weight_sequence,
    }


@app.get("/api/config")
def api_get_config() -> dict:
    return get_config().redacted()


class ConfigUpdate(BaseModel):
    organization: str | None = None
    timezone: str | None = None
    thresholds: dict | None = None
    integrations: dict | None = None
    security: dict | None = None
    retention: dict | None = None


@app.post("/api/config")
def api_set_config(update: ConfigUpdate, request: Request) -> dict:
    cfg = get_config()
    if update.organization is not None:
        cfg.organization = update.organization
    if update.timezone is not None:
        cfg.timezone = update.timezone
    if update.thresholds:
        valid = set(Thresholds.__dataclass_fields__)
        current = {f: getattr(cfg.thresholds, f) for f in valid}
        merged = {**current,
                  **{k: v for k, v in update.thresholds.items() if k in valid}}
        try:
            cfg.thresholds = Thresholds(**merged)
        except (TypeError, ValueError):
            raise HTTPException(400, "invalid threshold values")
    for section_name in ("integrations", "security", "retention"):
        patch = getattr(update, section_name)
        if not patch:
            continue
        section = getattr(cfg, section_name)
        for key, value in patch.items():
            if not hasattr(section, key):
                continue
            if value == "••••••••":     # redaction marker round-tripped: keep
                continue
            setattr(section, key, value)
    if cfg.security.auth_enabled:
        cfg.security.ensure_api_key()
    cfg.save()
    _audit(request, "config_updated", detail=", ".join(
        k for k in ("organization", "timezone", "thresholds", "integrations",
                    "security", "retention")
        if getattr(update, k, None) is not None))
    return {"ok": True, "config": cfg.redacted(),
            # Shown once so the operator can copy it when enabling auth.
            "api_key": cfg.security.api_key if cfg.security.auth_enabled else None}


# --- pipeline actions ------------------------------------------------------
class GenerateRequest(BaseModel):
    users: int = 25
    days: int = 30
    seed: int = 1337


@app.post("/api/generate")
def api_generate(req: GenerateRequest, request: Request) -> dict:
    store = _store()
    store.reset()
    events, planted = generate_synthetic(users=req.users, days=req.days, seed=req.seed)
    n = store.add_events(events)
    _audit(request, "data_generated", detail=f"{n} events / {req.users} users")
    return {"ingested": n, "planted": planted}


@app.post("/api/analyze")
def api_analyze(request: Request) -> dict:
    cfg = get_config()
    store = _store()
    events = store.iter_events()
    if not events:
        raise HTTPException(400, "no events; generate, ingest or load a dataset first")
    analyzer = Analyzer(config=cfg)
    alerts = analyzer.analyze(events, watchlist=store.watchlist_multipliers())
    store.replace_alerts(alerts)
    forwarded = 0
    for a in alerts:
        if a.risk_level.rank >= cfg.min_forward_rank:
            result = forward_alert(cfg, a)
            if any(v.startswith("delivered") for v in result.values()):
                forwarded += 1
    _audit(request, "analysis_run", detail=f"{len(alerts)} users scored")
    return {"analyzed": len(alerts), "forwarded": forwarded}


@app.post("/api/train")
def api_train(request: Request) -> dict:
    cfg = get_config()
    store = _store()
    events = store.iter_events()
    if not events:
        raise HTTPException(400, "no events to train on")
    analyzer = Analyzer(config=cfg).fit(events)
    analyzer.save(cfg.model_path)
    _audit(request, "model_trained", detail=str(analyzer.info()))
    return {"ok": True, "model": analyzer.info()}


@app.post("/api/ingest")
async def api_ingest(request: Request, file: UploadFile = File(...),
                     reset: bool = False) -> dict:
    store = _store()
    if reset:
        store.reset()
    suffix = Path(file.filename or "upload").suffix or ".csv"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name
    try:
        events = load_events_from_file(tmp_path)
    except Exception as exc:
        raise HTTPException(400, f"could not parse file: {exc}")
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    if not events:
        raise HTTPException(400, "no events parsed (check columns/format)")
    n = store.add_events(events)
    _audit(request, "file_ingested", file.filename or "?", f"{n} events")
    return {"ingested": n, "filename": file.filename}


# --- datasets --------------------------------------------------------------
@app.get("/api/datasets")
def api_datasets() -> list[dict]:
    return [d.__dict__ for d in list_datasets()]


class DatasetLoadRequest(BaseModel):
    key: str
    path: str | None = None
    limit: int | None = None
    users: int = 30
    days: int = 30
    reset: bool = True


@app.post("/api/dataset/load")
def api_dataset_load(req: DatasetLoadRequest, request: Request) -> dict:
    store = _store()
    if req.reset:
        store.reset()
    try:
        if req.key.lower() == "cert":
            if not req.path:
                raise HTTPException(400, "cert dataset requires 'path'")
            events = load_dataset("cert", path=req.path, limit_per_source=req.limit)
        else:
            events = load_dataset(req.key, users=req.users, days=req.days)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, f"dataset load failed: {exc}")
    n = store.add_events(events)
    _audit(request, "dataset_loaded", req.key, f"{n} events")
    return {"ingested": n, "users": len(store.distinct_users())}


# --- response --------------------------------------------------------------
@app.get("/api/response/actions")
def api_response_actions() -> list[dict]:
    return [{"action": a.value, "description": desc}
            for a, desc in ACTION_CATALOG.items()]


class RespondRequest(BaseModel):
    user: str
    action: str
    force: bool = False
    reason: str = ""


@app.post("/api/respond")
def api_respond(req: RespondRequest, request: Request) -> JSONResponse:
    cfg = get_config()
    store = _store()
    try:
        act = ResponseAction(req.action.lower())
    except ValueError:
        raise HTTPException(400, f"unknown action: {req.action}")
    match = [a for a in store.get_alerts() if a.user == req.user]
    res = dispatch(store, cfg, req.user, act, force=req.force, reason=req.reason,
                   alert=match[0] if match else None)
    _audit(request, "response_dispatched", req.user, f"{act.value} ({res['mode']})")
    return JSONResponse(res)


@app.post("/api/respond/auto/{user}")
def api_respond_auto(user: str, request: Request, force: bool = False) -> dict:
    cfg = get_config()
    store = _store()
    match = [a for a in store.get_alerts() if a.user == user]
    if not match:
        raise HTTPException(404, f"no alert for {user}")
    results = auto_respond(store, cfg, match[0], force=force)
    _audit(request, "auto_response", user, f"{len(results)} action(s)")
    return {"results": results}


@app.get("/api/responses")
def api_responses() -> list[dict]:
    return _store().get_responses()


# --- real-time stream ------------------------------------------------------
class StreamStart(BaseModel):
    eps: float = 5.0
    inject_prob: float = 0.06


@app.post("/api/stream/start")
def api_stream_start(req: StreamStart, request: Request) -> dict:
    _audit(request, "stream_started", detail=f"eps={req.eps}")
    return ENGINE.start(eps=req.eps, inject_prob=req.inject_prob)


@app.post("/api/stream/stop")
def api_stream_stop(request: Request) -> dict:
    _audit(request, "stream_stopped")
    return ENGINE.stop()


@app.get("/api/stream/status")
def api_stream_status() -> dict:
    return ENGINE.status()


@app.get("/api/stream/feed")
def api_stream_feed(limit: int = 50) -> list[dict]:
    return ENGINE.recent_feed(limit)


@app.get("/api/stream")
async def api_stream() -> StreamingResponse:
    q = ENGINE.subscribe()

    async def gen():
        try:
            while True:
                try:
                    item = await asyncio.to_thread(q.get, True, 15)
                except Exception:
                    yield ": keep-alive\n\n"
                    continue
                yield sse_format(item)
        finally:
            ENGINE.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# --- export & health -------------------------------------------------------
@app.get("/api/export")
def api_export() -> dict:
    store = _store()
    return {"generated_at": datetime.now().isoformat(),
            "alerts": [{**a.model_dump(mode="json"), "dedup_key": a.dedup_key}
                       for a in store.get_alerts()]}


@app.get("/api/export.csv")
def api_export_csv() -> Response:
    store = _store()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["user", "window_start", "risk_score", "risk_level", "status",
                     "assignee", "department", "role", "event_count", "detectors",
                     "mitre", "top_factor"])
    for a in store.get_alerts():
        writer.writerow([
            a.user, a.window_start.isoformat(), a.risk_score, a.risk_level.value,
            a.status.value, a.assignee, a.department, a.role, a.event_count,
            ";".join(a.detectors), ";".join(a.mitre_techniques),
            a.explanations[0].factor if a.explanations else "",
        ])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=athena-alerts.csv"})


@app.post("/api/purge")
def api_purge(request: Request) -> dict:
    cfg = get_config()
    removed = _store().purge(cfg.retention.event_days, cfg.retention.alert_days,
                             cfg.retention.audit_days)
    _audit(request, "retention_purge", detail=str(removed))
    return {"ok": True, "removed": removed,
            "policy": {"event_days": cfg.retention.event_days,
                       "alert_days": cfg.retention.alert_days,
                       "audit_days": cfg.retention.audit_days}}


class ResetRequest(BaseModel):
    full: bool = False       # also drop cases + watchlist, not just the corpus


@app.post("/api/reset")
def api_reset(req: ResetRequest, request: Request) -> dict:
    """Purpose-built corpus reset (replaces the old generate-with-zero hack).

    Clears events/alerts/responses/notes/feedback — and, with ``full``, cases
    and the watchlist too. The audit trail is always kept.
    """
    removed = _store().reset(full=req.full)
    ENGINE.stop()
    _audit(request, "data_reset",
           detail=("full " if req.full else "") + str(removed))
    return {"ok": True, "full": req.full, "removed": removed}


@app.get("/api/health")
def api_health() -> dict:
    """Liveness probe — always cheap, never touches the database."""
    return {"status": "ok", "version": __version__}


@app.get("/api/version")
def api_version() -> dict:
    """Build/runtime identity for clients, dashboards and support tickets."""
    import platform
    import sys
    cfg = get_config()
    return {
        "name": "ATHENA ITD",
        "version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "auth_enabled": cfg.security.auth_enabled,
    }


@app.get("/api/ready")
def api_ready() -> JSONResponse:
    """Readiness probe — verifies the datastore is reachable and writable."""
    try:
        _store().event_count()
        return JSONResponse({"status": "ready", "version": __version__})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"status": "unready", "detail": str(exc)},
                            status_code=503)


@app.get("/api/metrics")
def api_metrics() -> Response:
    """Prometheus text-format metrics (no external client library needed)."""
    lines = [
        "# HELP athena_http_requests_total Total HTTP requests served.",
        "# TYPE athena_http_requests_total counter",
        f"athena_http_requests_total {_METRICS['athena_http_requests_total']:.0f}",
        "# HELP athena_http_5xx_total Total 5xx responses.",
        "# TYPE athena_http_5xx_total counter",
        f"athena_http_5xx_total {_METRICS['athena_http_5xx_total']:.0f}",
        "# HELP athena_http_errors_total Unhandled exceptions.",
        "# TYPE athena_http_errors_total counter",
        f"athena_http_errors_total {_METRICS['athena_http_errors_total']:.0f}",
        "# HELP athena_http_unauthorized_total Requests rejected as unauthenticated.",
        "# TYPE athena_http_unauthorized_total counter",
        f"athena_http_unauthorized_total {_METRICS['athena_http_unauthorized_total']:.0f}",
        "# HELP athena_http_forbidden_total Requests rejected by RBAC/CSRF.",
        "# TYPE athena_http_forbidden_total counter",
        f"athena_http_forbidden_total {_METRICS['athena_http_forbidden_total']:.0f}",
        "# HELP athena_login_failed_total Failed login attempts.",
        "# TYPE athena_login_failed_total counter",
        f"athena_login_failed_total {_METRICS['athena_login_failed_total']:.0f}",
        "# HELP athena_login_throttled_total Login attempts blocked by lockout.",
        "# TYPE athena_login_throttled_total counter",
        f"athena_login_throttled_total {_METRICS['athena_login_throttled_total']:.0f}",
        "# HELP athena_http_rate_limited_total Requests rejected by the rate limiter.",
        "# TYPE athena_http_rate_limited_total counter",
        f"athena_http_rate_limited_total {_METRICS['athena_http_rate_limited_total']:.0f}",
    ]
    try:
        store = _store()
        cfg = get_config()
        lines += [
            "# HELP athena_events Ingested events currently stored.",
            "# TYPE athena_events gauge",
            f"athena_events {store.event_count():.0f}",
            "# HELP athena_alerts Stored alerts.",
            "# TYPE athena_alerts gauge",
            f"athena_alerts {len(store.get_alerts()):.0f}",
            "# HELP athena_stream_running Live engine running (1/0).",
            "# TYPE athena_stream_running gauge",
            f"athena_stream_running {1 if ENGINE.status().get('running') else 0}",
            "# HELP athena_auth_enabled API-key auth enabled (1/0).",
            "# TYPE athena_auth_enabled gauge",
            f"athena_auth_enabled {1 if cfg.security.auth_enabled else 0}",
        ]
    except Exception:  # noqa: BLE001 — metrics must never 500
        pass
    # per-route average latency
    lines += ["# HELP athena_route_latency_ms Mean latency per route (ms).",
              "# TYPE athena_route_latency_ms gauge"]
    for route, cnt in sorted(_LATENCY_CNT.items()):
        if cnt:
            avg = 1000 * _LATENCY_SUM[route] / cnt
            safe = route.replace('"', "")
            lines.append(f'athena_route_latency_ms{{route="{safe}"}} {avg:.2f}')
    return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
