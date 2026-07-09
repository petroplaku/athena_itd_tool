"""FastAPI application powering the Aegis UBA enterprise SOC console.

Exposes a full JSON API (summary, users, alerts, investigation, detection
config, model training, dataset loading, file ingest, response actions and a
Server-Sent-Events live feed) behind a single-page dashboard. Every capability
in the GUI maps to an endpoint here, so the same backend can drive a SIEM
integration or an automation script.
"""
from __future__ import annotations

import asyncio
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

from aegis_uba import __version__
from aegis_uba.config import Thresholds, get_config
from aegis_uba.datasets import list_datasets, load_dataset
from aegis_uba.detect import Analyzer
from aegis_uba.ingest import generate_synthetic, load_events_from_file
from aegis_uba.models import RiskLevel
from aegis_uba.response import ResponseAction, auto_respond, dispatch
from aegis_uba.storage import Store
from aegis_uba.stream import ENGINE, sse_format

_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

app = FastAPI(title="Aegis UBA", version=__version__)


def _store() -> Store:
    return Store(get_config().db_path)


# Human-readable catalogue of the detectors for the Detection Config view.
_DETECTORS = [
    {"key": "ml", "name": "ML behavioral anomaly", "type": "unsupervised",
     "detail": "Isolation Forest over 16-feature user-day behavior vectors.", "max_points": 35},
    {"key": "exfil", "name": "Possible data exfiltration", "type": "rule+baseline",
     "detail": "Data volume σ above the user's baseline, or a very large single transfer.", "max_points": 55},
    {"key": "failed", "name": "Failed-login burst", "type": "rule",
     "detail": "Many failed authentications in the window (brute force / stuffing).", "max_points": 45},
    {"key": "offhours", "name": "Off-hours access", "type": "rule",
     "detail": "Sustained activity outside business hours / overnight.", "max_points": 40},
    {"key": "privesc", "name": "Privilege escalation", "type": "rule",
     "detail": "Elevation events + sensitive config changes.", "max_points": 50},
    {"key": "geo", "name": "Impossible travel / new geography", "type": "rule+baseline",
     "detail": "Authentications from multiple / never-before-seen countries.", "max_points": 45},
]


# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    cfg = get_config()
    return _TEMPLATES.TemplateResponse(
        request, "dashboard.html",
        {"organization": cfg.organization, "version": __version__},
    )


# --- overview & summary ----------------------------------------------------
@app.get("/api/summary")
def api_summary() -> dict:
    cfg = get_config()
    store = _store()
    alerts = store.get_alerts()
    counts = {lvl.value: 0 for lvl in RiskLevel}
    for a in alerts:
        counts[a.risk_level.value] += 1
    per_day: dict[str, int] = {}
    for e in store.iter_events():
        key = e.timestamp.date().isoformat()
        per_day[key] = per_day.get(key, 0) + 1
    trend = sorted(per_day.items())[-30:]
    model_info = {"fitted": False}
    if cfg.model_path.exists():
        try:
            model_info = Analyzer.load(cfg.model_path).info()
        except Exception:
            model_info = {"fitted": False}
    return {
        "organization": cfg.organization,
        "total_events": store.event_count(),
        "total_users": len(store.distinct_users()),
        "analyzed": len(alerts),
        "counts": counts,
        "flagged": counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"],
        "trend_labels": [d for d, _ in trend],
        "trend_values": [v for _, v in trend],
        "model": model_info,
        "stream": ENGINE.status(),
        "response_count": len(store.get_responses()),
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
            "host": u["host"], "source_ip": u["source_ip"], "last_seen": u["last_seen"],
            "risk_score": score, "risk_level": level,
            "top_factor": (a.explanations[0].factor if a and a.explanations else "—"),
        })
    rows.sort(key=lambda r: r["risk_score"], reverse=True)
    return rows


@app.get("/api/departments")
def api_departments() -> list[str]:
    return sorted({u["department"] for u in _store().user_directory() if u["department"]})


# --- alerts ----------------------------------------------------------------
@app.get("/api/alerts")
def api_alerts(min_level: str = "LOW", q: str = "") -> list[dict]:
    store = _store()
    try:
        lvl = RiskLevel(min_level.upper())
    except ValueError:
        raise HTTPException(400, f"invalid level: {min_level}")
    out = []
    for a in store.get_alerts(min_level=lvl):
        if q and q.lower() not in a.user.lower():
            continue
        out.append(a.model_dump(mode="json"))
    return out


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
         "bytes": e.bytes, "success": e.success}
        for e in events[-60:]
    ]
    alert = match[0].model_dump(mode="json") if match else None
    return {"alert": alert, "events": tail, "event_total": len(events)}


# --- detection catalogue ---------------------------------------------------
@app.get("/api/detections")
def api_detections() -> dict:
    return {"detectors": _DETECTORS, "thresholds": _thresholds_dict()}


# --- config ----------------------------------------------------------------
def _thresholds_dict() -> dict:
    th = get_config().thresholds
    return {
        "low": th.low, "medium": th.medium, "high": th.high,
        "contamination": th.contamination,
        "business_start_hour": th.business_start_hour,
        "business_end_hour": th.business_end_hour,
        "failed_login_burst": th.failed_login_burst,
        "data_exfil_zscore": th.data_exfil_zscore,
        "new_geo_penalty": th.new_geo_penalty,
    }


@app.get("/api/config")
def api_get_config() -> dict:
    cfg = get_config()
    return {"organization": cfg.organization, "webhook_url": cfg.webhook_url,
            "thresholds": _thresholds_dict(),
            "data_home": str(cfg.home), "model_path": str(cfg.model_path)}


class ConfigUpdate(BaseModel):
    organization: str | None = None
    webhook_url: str | None = None
    thresholds: dict | None = None


@app.post("/api/config")
def api_set_config(update: ConfigUpdate) -> dict:
    cfg = get_config()
    if update.organization is not None:
        cfg.organization = update.organization
    if update.webhook_url is not None:
        cfg.webhook_url = update.webhook_url or None
    if update.thresholds:
        valid = {f for f in Thresholds.__dataclass_fields__}
        merged = {**_thresholds_dict(), **{k: v for k, v in update.thresholds.items() if k in valid}}
        cfg.thresholds = Thresholds(**merged)
    cfg.save()
    return {"ok": True, "config": api_get_config()}


# --- pipeline actions ------------------------------------------------------
class GenerateRequest(BaseModel):
    users: int = 25
    days: int = 30
    seed: int = 1337


@app.post("/api/generate")
def api_generate(req: GenerateRequest) -> dict:
    store = _store()
    store.reset()
    events, planted = generate_synthetic(users=req.users, days=req.days, seed=req.seed)
    n = store.add_events(events)
    return {"ingested": n, "planted": planted}


@app.post("/api/analyze")
def api_analyze() -> dict:
    cfg = get_config()
    store = _store()
    events = store.iter_events()
    if not events:
        raise HTTPException(400, "no events; generate, ingest or load a dataset first")
    alerts = Analyzer(cfg.thresholds).analyze(events)
    store.replace_alerts(alerts)
    return {"analyzed": len(alerts)}


@app.post("/api/train")
def api_train() -> dict:
    cfg = get_config()
    store = _store()
    events = store.iter_events()
    if not events:
        raise HTTPException(400, "no events to train on")
    analyzer = Analyzer(cfg.thresholds).fit(events)
    analyzer.save(cfg.model_path)
    return {"ok": True, "model": analyzer.info()}


@app.post("/api/ingest")
async def api_ingest(file: UploadFile = File(...), reset: bool = False) -> dict:
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
def api_dataset_load(req: DatasetLoadRequest) -> dict:
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
    return {"ingested": n, "users": len(store.distinct_users())}


# --- response --------------------------------------------------------------
class RespondRequest(BaseModel):
    user: str
    action: str
    force: bool = False
    reason: str = ""


@app.post("/api/respond")
def api_respond(req: RespondRequest) -> JSONResponse:
    cfg = get_config()
    store = _store()
    try:
        act = ResponseAction(req.action.lower())
    except ValueError:
        raise HTTPException(400, f"unknown action: {req.action}")
    res = dispatch(store, cfg, req.user, act, force=req.force, reason=req.reason)
    return JSONResponse(res)


@app.post("/api/respond/auto/{user}")
def api_respond_auto(user: str, force: bool = False) -> dict:
    cfg = get_config()
    store = _store()
    match = [a for a in store.get_alerts() if a.user == user]
    if not match:
        raise HTTPException(404, f"no alert for {user}")
    return {"results": auto_respond(store, cfg, match[0], force=force)}


@app.get("/api/responses")
def api_responses() -> list[dict]:
    return _store().get_responses()


# --- real-time stream ------------------------------------------------------
class StreamStart(BaseModel):
    eps: float = 5.0
    inject_prob: float = 0.06


@app.post("/api/stream/start")
def api_stream_start(req: StreamStart) -> dict:
    return ENGINE.start(eps=req.eps, inject_prob=req.inject_prob)


@app.post("/api/stream/stop")
def api_stream_stop() -> dict:
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
            "alerts": [a.model_dump(mode="json") for a in store.get_alerts()]}


@app.get("/api/health")
def api_health() -> dict:
    return {"status": "ok", "version": __version__}
