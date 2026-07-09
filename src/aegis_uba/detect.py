"""Detection engine: ML anomaly detection + rule heuristics + risk scoring.

The :class:`Analyzer` produces one explainable :class:`Alert` per user for their
most recent activity window. The final 0-100 risk score is a weighted blend of:

* an unsupervised **Isolation Forest** anomaly score computed across the whole
  population of user-day behavior vectors, and
* a set of **rule detectors** (data exfiltration, off-hours access, failed-login
  bursts, privilege escalation, impossible travel / new geo) evaluated against
  each user's own behavioral baseline.

Every contributing factor is captured as an :class:`Explanation` so analysts,
HR and compliance can see *why* a user was flagged.
"""
from __future__ import annotations

from datetime import date, datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from aegis_uba.config import Thresholds
from aegis_uba.features import FEATURE_COLUMNS, build_feature_frame
from aegis_uba.models import Action, Alert, Event, Explanation, RiskLevel

# Maximum points each detector can contribute to the 0-100 risk score.
# Rule weights are deliberately high so that a single unambiguous indicator
# (bulk exfiltration, privilege abuse, brute force) escalates on its own, while
# the ML term supplies corroborating "this looks off overall" signal.
_ML_MAX = 35.0
_EXFIL_MAX = 55.0
_FAILED_MAX = 45.0
_OFFHOURS_MAX = 40.0
_PRIVESC_MAX = 50.0
_GEO_MAX = 45.0


class Analyzer:
    def __init__(self, thresholds: Thresholds | None = None, window_days: int = 3):
        self.th = thresholds or Thresholds()
        self.window_days = max(1, window_days)
        self.model: IsolationForest | None = None
        self.scaler: RobustScaler | None = None

    # ------------------------------------------------------------------
    def analyze(self, events: list[Event]) -> list[Alert]:
        df = build_feature_frame(events, self.th)
        if df.empty:
            return []

        df = self._score_ml(df)

        # Pre-compute per-user baseline context from raw events.
        ctx = self._baseline_context(events)

        alerts: list[Alert] = []
        for user, udf in df.groupby("user"):
            udf = udf.sort_values("day").reset_index(drop=True)
            # Evaluate each day in the recent monitoring window and keep the
            # highest-risk one, so a benign spill-over day can't mask a real
            # anomaly on the preceding day.
            n_candidates = min(self.window_days, len(udf))
            best: Alert | None = None
            for i in range(len(udf) - n_candidates, len(udf)):
                scored = udf.iloc[i]
                hist = udf.drop(index=i) if len(udf) > 1 else udf
                alert = self._score_user(user, scored, hist, ctx[user])
                if best is None or alert.risk_score > best.risk_score:
                    best = alert
            if best is not None:
                alerts.append(best)

        alerts.sort(key=lambda a: a.risk_score, reverse=True)
        return alerts

    # ------------------------------------------------------------------
    def _score_ml(self, df: pd.DataFrame) -> pd.DataFrame:
        X = df[FEATURE_COLUMNS].to_numpy(dtype=float)
        self.scaler = RobustScaler()
        Xs = self.scaler.fit_transform(X)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.th.contamination,
            random_state=42,
        )
        self.model.fit(Xs)
        # score_samples: higher = more normal. Normalize to 0..1 anomaly severity.
        raw = self.model.score_samples(Xs)
        lo, hi = raw.min(), raw.max()
        span = (hi - lo) or 1.0
        df = df.copy()
        df["ml_anomaly"] = (hi - raw) / span  # 0 (normal) .. 1 (most anomalous)
        return df

    # ------------------------------------------------------------------
    def _baseline_context(self, events: list[Event]) -> dict[str, dict]:
        """Per-user sets of historically-seen countries/IPs and the latest day."""
        ctx: dict[str, dict] = {}
        # Determine each user's most recent active day.
        latest: dict[str, date] = {}
        for e in events:
            d = e.timestamp.date()
            if e.user not in latest or d > latest[e.user]:
                latest[e.user] = d
        for e in events:
            c = ctx.setdefault(e.user, {"prior_countries": set(), "prior_ips": set(),
                                        "latest_day": latest[e.user]})
            if e.timestamp.date() < latest[e.user]:
                c["prior_countries"].add(e.country)
                c["prior_ips"].add(e.source_ip)
        return ctx

    # ------------------------------------------------------------------
    def _score_user(self, user: str, scored: pd.Series, hist: pd.DataFrame,
                    ctx: dict) -> Alert:
        th = self.th
        explanations: list[Explanation] = []
        score = 0.0

        # --- ML anomaly ------------------------------------------------
        ml_anom = float(scored["ml_anomaly"])
        ml_points = ml_anom * _ML_MAX
        if ml_points >= 6:
            explanations.append(Explanation(
                factor="ML behavioral anomaly",
                detail=(f"Isolation-Forest flagged this day's activity profile as "
                        f"{ml_anom*100:.0f}% anomalous vs the organization baseline."),
                weight=round(ml_points, 1),
            ))
        score += ml_points

        # --- Data exfiltration ----------------------------------------
        total_bytes = float(scored["total_bytes"])
        max_bytes = float(scored["max_single_bytes"])
        hist_mean = float(hist["total_bytes"].mean()) if len(hist) else total_bytes
        hist_std = float(hist["total_bytes"].std(ddof=0)) if len(hist) > 1 else 0.0
        z = (total_bytes - hist_mean) / hist_std if hist_std > 0 else 0.0
        if z >= th.data_exfil_zscore or max_bytes >= 500_000_000:
            sev = min(1.0, max(z / (th.data_exfil_zscore * 2), max_bytes / 1_000_000_000))
            pts = _EXFIL_MAX * max(sev, 0.6)
            explanations.append(Explanation(
                factor="Possible data exfiltration",
                detail=(f"Transferred {_human_bytes(total_bytes)} "
                        f"({z:.1f}σ above their normal {_human_bytes(hist_mean)}); "
                        f"largest single transfer {_human_bytes(max_bytes)}."),
                weight=round(pts, 1),
            ))
            score += pts

        # --- Failed-login burst ---------------------------------------
        n_failed = int(scored["n_failed_logins"])
        if n_failed >= th.failed_login_burst:
            sev = min(1.0, n_failed / (th.failed_login_burst * 4))
            pts = _FAILED_MAX * max(sev, 0.65)
            explanations.append(Explanation(
                factor="Failed-login burst",
                detail=(f"{n_failed} failed authentications in the window — "
                        f"consistent with brute-force or credential stuffing."),
                weight=round(pts, 1),
            ))
            score += pts

        # --- Off-hours / night activity -------------------------------
        after_ratio = float(scored["after_hours_ratio"])
        night = int(scored["night_events"])
        if night >= 4 or (after_ratio >= 0.4 and night >= 2):
            sev = min(1.0, max(after_ratio, night / 12))
            pts = _OFFHOURS_MAX * max(sev, 0.6)
            explanations.append(Explanation(
                factor="Off-hours access",
                detail=(f"{after_ratio*100:.0f}% of activity outside business hours "
                        f"with {night} events between midnight and 5am."),
                weight=round(pts, 1),
            ))
            score += pts

        # --- Privilege escalation -------------------------------------
        n_priv = int(scored["n_priv_esc"])
        n_cfg = int(scored["n_config_change"])
        if n_priv > 0:
            sev = min(1.0, (n_priv + n_cfg) / 8)
            pts = _PRIVESC_MAX * max(sev, 0.65)
            explanations.append(Explanation(
                factor="Privilege escalation",
                detail=(f"{n_priv} privilege-escalation events and {n_cfg} sensitive "
                        f"config changes — potential abuse of elevated rights."),
                weight=round(pts, 1),
            ))
            score += pts

        # --- Impossible travel / new geography ------------------------
        n_countries = int(scored["distinct_countries"])
        prior = ctx.get("prior_countries", set())
        if n_countries > 1 or (prior and n_countries >= 1):
            # A country never seen before for this user is the strong signal.
            new_geo = n_countries > 1 and bool(prior)
            if new_geo or n_countries > 1:
                pts = th.new_geo_penalty + (_GEO_MAX - th.new_geo_penalty) * (n_countries > 1)
                explanations.append(Explanation(
                    factor="Impossible travel / new geography",
                    detail=(f"Authenticated from {n_countries} distinct countries in one "
                            f"day (baseline: {', '.join(sorted(prior)) or 'US'})."),
                    weight=round(pts, 1),
                ))
                score += pts

        score = float(np.clip(score, 0, 100))
        level = self._band(score)
        explanations.sort(key=lambda e: e.weight, reverse=True)
        actions = self._recommend(level, explanations)

        return Alert(
            user=user,
            window_start=datetime.combine(scored["day"], datetime.min.time()),
            window_end=datetime.combine(scored["day"], datetime.max.time()),
            risk_score=round(score, 1),
            risk_level=level,
            ml_score=round(ml_anom, 3),
            department=str(scored["department"]),
            role=str(scored["role"]),
            event_count=int(scored["n_events"]),
            explanations=explanations,
            recommended_actions=actions,
        )

    # ------------------------------------------------------------------
    def _band(self, score: float) -> RiskLevel:
        th = self.th
        if score >= th.high:
            return RiskLevel.CRITICAL if score >= (th.high + 100) / 2 else RiskLevel.HIGH
        if score >= th.medium:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @staticmethod
    def _recommend(level: RiskLevel, explanations: list[Explanation]) -> list[str]:
        factors = {e.factor for e in explanations}
        actions: list[str] = []
        if "Possible data exfiltration" in factors:
            actions += ["Revoke active sessions", "Block outbound file transfers / USB",
                        "Preserve endpoint for forensic review"]
        if "Failed-login burst" in factors:
            actions += ["Lock account", "Force password reset", "Enforce MFA challenge"]
        if "Privilege escalation" in factors:
            actions += ["Revoke elevated privileges", "Open IR ticket for admin review"]
        if "Off-hours access" in factors:
            actions += ["Require step-up MFA for off-hours sessions"]
        if "Impossible travel / new geography" in factors:
            actions += ["Challenge session with MFA", "Verify travel with the user/manager"]
        if level in (RiskLevel.HIGH, RiskLevel.CRITICAL) and not actions:
            actions.append("Escalate to SOC tier-2 for manual review")
        if not actions:
            actions.append("Continue monitoring")
        # De-duplicate while preserving order.
        seen: set[str] = set()
        return [a for a in actions if not (a in seen or seen.add(a))]


def _human_bytes(n: float) -> str:
    step = 1024.0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < step:
            return f"{n:.1f} {unit}"
        n /= step
    return f"{n:.1f} PB"
