"""Render standalone HTML and JSON reports from a set of alerts."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from athena_itd.config import Config
from athena_itd.models import Alert, RiskLevel

_env = Environment(
    loader=PackageLoader("athena_itd.report", "templates"),
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
    from athena_itd import compliance as compliance_mod
    from athena_itd import mitre as mitre_mod
    from athena_itd.detect import detector_compliance_map, detector_mitre_map

    hits: dict[str, int] = {}
    evidence: dict[str, int] = {}
    for a in alerts:
        for t in a.mitre_techniques:
            hits[t] = hits.get(t, 0) + 1
        for d in a.detectors:
            evidence[d] = evidence.get(d, 0) + 1

    template = _env.get_template("report.html")
    return template.render(
        organization=config.organization,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        alerts=alerts,
        summary=_summary(alerts),
        mitre=mitre_mod.coverage_matrix(detector_mitre_map(), hits),
        compliance=compliance_mod.coverage_report(detector_compliance_map(), evidence),
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
    html_path = out_dir / f"athena-report-{stamp}.html"
    json_path = out_dir / f"athena-report-{stamp}.json"
    html_path.write_text(render_html_report(alerts, config), encoding="utf-8")
    write_json_report(alerts, json_path)
    return {"html": html_path, "json": json_path}
