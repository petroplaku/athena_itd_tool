"""Feature engineering: turn raw events into per-user/per-day behavior vectors.

Each row summarizes one user's activity on one calendar day. These vectors feed
both the behavioral baseline (per-user rolling statistics) and the unsupervised
ML model (population-wide anomaly detection).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date

import pandas as pd

from aegis_uba.config import Thresholds
from aegis_uba.models import Action, Event

# The ordered feature columns used by the ML model (kept explicit for stability).
FEATURE_COLUMNS = [
    "n_events",
    "n_logins",
    "n_failed_logins",
    "failed_login_ratio",
    "n_file_access",
    "n_downloads",
    "total_bytes",
    "max_single_bytes",
    "n_priv_esc",
    "n_config_change",
    "distinct_hosts",
    "distinct_ips",
    "distinct_countries",
    "after_hours_ratio",
    "night_events",
    "weekend",
]


def _is_after_hours(hour: int, th: Thresholds) -> bool:
    return hour < th.business_start_hour or hour >= th.business_end_hour


def build_feature_frame(events: list[Event], th: Thresholds) -> pd.DataFrame:
    """Return a DataFrame indexed by ``(user, day)`` with :data:`FEATURE_COLUMNS`."""
    buckets: dict[tuple[str, date], list[Event]] = defaultdict(list)
    meta: dict[str, dict[str, str]] = {}
    for e in events:
        buckets[(e.user, e.timestamp.date())].append(e)
        meta.setdefault(e.user, {"department": e.department, "role": e.role})

    rows = []
    for (user, day), evs in buckets.items():
        n_events = len(evs)
        n_logins = sum(e.action == Action.LOGIN for e in evs)
        n_failed = sum(e.action == Action.FAILED_LOGIN for e in evs)
        n_file = sum(e.action == Action.FILE_ACCESS for e in evs)
        n_dl = sum(e.action in (Action.FILE_DOWNLOAD, Action.DATA_TRANSFER) for e in evs)
        n_priv = sum(e.action == Action.PRIVILEGE_ESCALATION for e in evs)
        n_cfg = sum(e.action == Action.CONFIG_CHANGE for e in evs)
        total_bytes = sum(e.bytes for e in evs)
        max_bytes = max((e.bytes for e in evs), default=0)
        hosts = {e.host for e in evs}
        ips = {e.source_ip for e in evs}
        countries = {e.country for e in evs}
        after_hours = sum(_is_after_hours(e.timestamp.hour, th) for e in evs)
        night = sum(0 <= e.timestamp.hour < 5 for e in evs)
        login_attempts = n_logins + n_failed

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
                "n_file_access": n_file,
                "n_downloads": n_dl,
                "total_bytes": total_bytes,
                "max_single_bytes": max_bytes,
                "n_priv_esc": n_priv,
                "n_config_change": n_cfg,
                "distinct_hosts": len(hosts),
                "distinct_ips": len(ips),
                "distinct_countries": len(countries),
                "after_hours_ratio": (after_hours / n_events) if n_events else 0.0,
                "night_events": night,
                "weekend": 1 if day.weekday() >= 5 else 0,
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(columns=["user", "day", "department", "role", *FEATURE_COLUMNS])
    return df.sort_values(["user", "day"]).reset_index(drop=True)
