"""Render standalone HTML and JSON reports from a set of alerts."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from aegis_uba.config import Config
from aegis_uba.models import Alert, RiskLevel

_env = Environment(
    loader=PackageLoader("aegis_uba.report", "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)


def _summary(alerts: list[Alert]) -> dict:
    counts = {lvl.value: 0 for lvl in RiskLevel}
    for a in alerts:
        counts[a.risk_level.value] += 1
    return {
        "total_users": len(alerts),
        "counts": counts,
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "flagged": counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"],
    }


def render_html_report(alerts: list[Alert], config: Config) -> str:
    template = _env.get_template("report.html")
    return template.render(
        organization=config.organization,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        alerts=alerts,
        summary=_summary(alerts),
    )


def write_json_report(alerts: list[Alert], path: Path) -> Path:
    path = Path(path)
    payload = {
        "generated_at": datetime.now().isoformat(),
        "summary": _summary(alerts),
        "alerts": [a.model_dump(mode="json") for a in alerts],
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def write_reports(alerts: list[Alert], config: Config, out_dir: Path | None = None) -> dict:
    """Write both HTML and JSON reports; return the paths written."""
    out_dir = Path(out_dir or config.reports_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    html_path = out_dir / f"aegis-report-{stamp}.html"
    json_path = out_dir / f"aegis-report-{stamp}.json"
    html_path.write_text(render_html_report(alerts, config), encoding="utf-8")
    write_json_report(alerts, json_path)
    return {"html": html_path, "json": json_path}
