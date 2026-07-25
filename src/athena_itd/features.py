"""Feature engineering: turn raw events into per-user/per-day behavior vectors.

Each row summarizes one user's activity on one calendar day. These vectors feed
the behavioral baseline (per-user rolling statistics), the unsupervised ML
ensemble (population-wide anomaly detection) and the peer-group analytics
(department-relative deviation).

The vector deliberately over-represents *exfiltration channels* (USB, personal
cloud, print, repo clone, external email) and *evasion signals* (log clearing,
security-tool tampering, mass deletion) because those are the behaviors that
separate a malicious insider from a merely busy employee.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import date

import pandas as pd

from athena_itd.config import Config, Thresholds
from athena_itd.models import (
    ADMIN_ACTIONS,
    DESTRUCTIVE_ACTIONS,
    EVASION_ACTIONS,
    EXFIL_ACTIONS,
    Action,
    Event,
    Sensitivity,
)

# The ordered feature columns used by the ML ensemble (kept explicit so a saved
# model can detect a feature-schema mismatch instead of silently mis-scoring).
FEATURE_COLUMNS = [
    # Volume / cadence
    "n_events",
    "n_logins",
    "n_failed_logins",
    "failed_login_ratio",
    "burst_max_per_hour",
    "hour_entropy",
    "session_span_hours",
    # Data movement
    "n_file_access",
    "n_downloads",
    "n_uploads",
    "n_deletes",
    "n_usb",
    "n_print",
    "n_cloud_upload",
    "n_repo_clone",
    "n_db_query",
    "n_email_external",
    "n_email_forward_rule",
    "total_bytes",
    "max_single_bytes",
    "exfil_bytes",
    "distinct_resources",
    "sensitive_access_score",
    # Administration / evasion
    "n_priv_esc",
    "n_config_change",
    "n_admin_actions",
    "n_evasion",
    "n_destructive",
    # Footprint
    "distinct_hosts",
    "distinct_ips",
    "distinct_countries",
    "anon_ip_events",
    "high_risk_country_events",
    # Temporal
    "after_hours_ratio",
    "night_events",
    "weekend",
]

_EMAIL_EXTERNAL = {Action.EMAIL_EXTERNAL, Action.EMAIL_SEND}


def _is_after_hours(hour: int, th: Thresholds) -> bool:
    return hour < th.business_start_hour or hour >= th.business_end_hour


def _hour_entropy(hours: list[int]) -> float:
    """Shannon entropy (bits) of the activity's hour-of-day distribution.

    Low entropy = concentrated activity (a script or a smash-and-grab session);
    high entropy relative to the user's norm = activity smeared across the clock.
    Both directions are informative, so the raw value is left to the model.
    """
    if not hours:
        return 0.0
    counts = Counter(hours)
    total = len(hours)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _sensitivity_of(resource: str, sensitive_paths: dict[str, str]) -> float:
    """Weight of the most sensitive configured prefix matching ``resource``."""
    if not resource:
        return 0.0
    best = 0.0
    for prefix, level in sensitive_paths.items():
        if resource.startswith(prefix):
            try:
                best = max(best, Sensitivity(level).weight)
            except ValueError:
                continue
    return best


def build_feature_frame(
    events: list[Event],
    th: Thresholds,
    config: Config | None = None,
) -> pd.DataFrame:
    """Return a DataFrame indexed by ``(user, day)`` with :data:`FEATURE_COLUMNS`."""
    # Imported here to avoid a circular import at module load.
    from athena_itd.geo import HIGH_RISK_COUNTRIES, is_anonymised

    sensitive_paths = (config.sensitive_paths if config else {})
    personal_domains = set(config.personal_email_domains) if config else set()
    cloud_hosts = list(config.personal_cloud_hosts) if config else []

    buckets: dict[tuple[str, date], list[Event]] = defaultdict(list)
    meta: dict[str, dict[str, str]] = {}
    for e in events:
        buckets[(e.user, e.timestamp.date())].append(e)
        meta.setdefault(e.user, {"department": e.department, "role": e.role})

    rows = []
    for (user, day), evs in buckets.items():
        n_events = len(evs)
        by_action = Counter(e.action for e in evs)
        n_logins = by_action[Action.LOGIN]
        n_failed = by_action[Action.FAILED_LOGIN]
        login_attempts = n_logins + n_failed

        # Data movement --------------------------------------------------
        n_dl = by_action[Action.FILE_DOWNLOAD] + by_action[Action.DATA_TRANSFER]
        n_ul = by_action[Action.FILE_UPLOAD]
        n_usb = by_action[Action.USB_WRITE] + by_action[Action.USB_INSERT]
        n_cloud = by_action[Action.CLOUD_UPLOAD]
        # Personal-cloud uploads sometimes arrive as generic uploads/web hits
        # with a telltale destination; count those too.
        if cloud_hosts:
            n_cloud += sum(
                1 for e in evs
                if e.action in (Action.FILE_UPLOAD, Action.WEB_BROWSE, Action.DATA_TRANSFER)
                and any(h in (e.resource or "") or h in (e.dest_ip or "") for h in cloud_hosts)
            )
        n_email_ext = by_action[Action.EMAIL_EXTERNAL]
        if personal_domains:
            n_email_ext += sum(
                1 for e in evs
                if e.action in _EMAIL_EXTERNAL
                and any((e.resource or "").lower().endswith("@" + d)
                        or ("@" + d) in (e.resource or "").lower()
                        for d in personal_domains)
                and e.action != Action.EMAIL_EXTERNAL
            )
        exfil_bytes = sum(e.bytes for e in evs if e.action in EXFIL_ACTIONS)
        total_bytes = sum(e.bytes for e in evs)
        max_bytes = max((e.bytes for e in evs), default=0)

        sens_score = sum(
            _sensitivity_of(e.resource, sensitive_paths)
            for e in evs
            if e.action in (Action.FILE_ACCESS, Action.FILE_DOWNLOAD,
                            Action.FILE_UPLOAD, Action.DB_QUERY, Action.FILE_DELETE)
        )

        # Temporal -------------------------------------------------------
        hours = [e.timestamp.hour for e in evs]
        after_hours = sum(_is_after_hours(h, th) for h in hours)
        night = sum(0 <= h < 5 for h in hours)
        per_hour = Counter(hours)
        first = min(e.timestamp for e in evs)
        last = max(e.timestamp for e in evs)
        span_hours = (last - first).total_seconds() / 3600.0

        # Footprint ------------------------------------------------------
        ips = {e.source_ip for e in evs}
        anon_events = sum(1 for e in evs if is_anonymised(e.source_ip))
        risky_geo = sum(1 for e in evs if e.country in HIGH_RISK_COUNTRIES)

        rows.append(
            {
                "user": user,
                "day": day,
                "department": meta[user]["department"],
                "role": meta[user]["role"],
                "n_events": n_events,
                "n_logins": n_logins,
                "n_failed_logins": n_failed,
                "failed_login_ratio": (n_failed / login_attempts) if login_attempts else 0.0,
                "burst_max_per_hour": max(per_hour.values(), default=0),
                "hour_entropy": _hour_entropy(hours),
                "session_span_hours": span_hours,
                "n_file_access": by_action[Action.FILE_ACCESS],
                "n_downloads": n_dl,
                "n_uploads": n_ul,
                "n_deletes": by_action[Action.FILE_DELETE],
                "n_usb": n_usb,
                "n_print": by_action[Action.PRINT],
                "n_cloud_upload": n_cloud,
                "n_repo_clone": by_action[Action.REPO_CLONE],
                "n_db_query": by_action[Action.DB_QUERY],
                "n_email_external": n_email_ext,
                "n_email_forward_rule": by_action[Action.EMAIL_FORWARD_RULE],
                "total_bytes": total_bytes,
                "max_single_bytes": max_bytes,
                "exfil_bytes": exfil_bytes,
                "distinct_resources": len({e.resource for e in evs if e.resource}),
                "sensitive_access_score": sens_score,
                "n_priv_esc": by_action[Action.PRIVILEGE_ESCALATION],
                "n_config_change": by_action[Action.CONFIG_CHANGE],
                "n_admin_actions": sum(by_action[a] for a in ADMIN_ACTIONS),
                "n_evasion": sum(by_action[a] for a in EVASION_ACTIONS),
                "n_destructive": sum(by_action[a] for a in DESTRUCTIVE_ACTIONS),
                "distinct_hosts": len({e.host for e in evs}),
                "distinct_ips": len(ips),
                "distinct_countries": len({e.country for e in evs}),
                "anon_ip_events": anon_events,
                "high_risk_country_events": risky_geo,
                "after_hours_ratio": (after_hours / n_events) if n_events else 0.0,
                "night_events": night,
                "weekend": 1 if day.weekday() >= 5 else 0,
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(columns=["user", "day", "department", "role", *FEATURE_COLUMNS])
    return df.sort_values(["user", "day"]).reset_index(drop=True)
