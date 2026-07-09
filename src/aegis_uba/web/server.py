"""FastAPI application powering the Aegis UBA web dashboard.

The dashboard is a thin, dependency-light SPA served from a single Jinja2
template; all data is fetched from the JSON API below so the same endpoints can
back a SIEM integration or a future native client.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

from aegis_uba import __version__
from aegis_uba.config import get_config
from aegis_uba.detect import Analyzer
from aegis_uba.ingest import generate_synthetic
from aegis_uba.models import RiskLevel
from aegis_uba.response import ResponseAction, dispatch
from aegis_uba.storage import Store

_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

app = FastAPI(title="Aegis UBA", version=__version__)


def _store() -> Store:
    return Store(get_config().db_path)


# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    cfg = get_config()
    return _TEMPLATES.TemplateResponse(
        request,
        "dashboard.html",
        {"organization": cfg.organization, "version": __version__},
    )


@app.get("/api/summary")
def api_summary() -> dict:
    store = _store()
    alerts = store.get_alerts()
    counts = {lvl.value: 0 for lvl in RiskLevel}
    for a in alerts:
        counts[a.risk_level.value] += 1
    # Events per day for the trend chart.
    per_day: dict[str, int] = {}
    for e in store.iter_events():
        key = e.timestamp.date().isoformat()
        per_day[key] = per_day.get(key, 0) + 1
    trend = sorted(per_day.items())
    return {
        "organization": get_config().organization,
        "total_events": store.event_count(),
        "total_users": len(store.distinct_users()),
        "analyzed": len(alerts),
        "counts": counts,
        "flagged": counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"],
        "trend_labels": [d for d, _ in trend],
        "trend_values": [v for _, v in trend],
    }


@app.get("/api/alerts")
def api_alerts(min_level: str = "LOW") -> list[dict]:
    store = _store()
    try:
        lvl = RiskLevel(min_level.upper())
    except ValueError:
        raise HTTPException(400, f"invalid level: {min_level}")
    return [a.model_dump(mode="json") for a in store.get_alerts(min_level=lvl)]


@app.get("/api/user/{user}")
def api_user(user: str) -> dict:
    store = _store()
    match = [a for a in store.get_alerts() if a.user == user]
    if not match:
        raise HTTPException(404, f"no alert for {user}")
    alert = match[0]
    events = store.events_for_user(user)
    # Recent event tail for the drill-down.
    tail = [
        {
            "timestamp": e.timestamp.isoformat(),
            "action": e.action.value,
            "resource": e.resource,
            "source_ip": e.source_ip,
            "country": e.country,
            "bytes": e.bytes,
            "success": e.success,
        }
        for e in events[-40:]
    ]
    return {"alert": alert.model_dump(mode="json"), "events": tail,
            "event_total": len(events)}


@app.get("/api/responses")
def api_responses() -> list[dict]:
    return _store().get_responses()


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
        raise HTTPException(400, "no events; generate or ingest first")
    alerts = Analyzer(cfg.thresholds).analyze(events)
    store.replace_alerts(alerts)
    return {"analyzed": len(alerts)}


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


@app.get("/api/health")
def api_health() -> dict:
    return {"status": "ok", "version": __version__}
