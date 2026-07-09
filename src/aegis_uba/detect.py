"""Detection engine: ML anomaly detection + rule heuristics + risk scoring.

The :class:`Analyzer` produces one explainable :class:`Alert` per user for their
most recent activity window. The final 0-100 risk score is a weighted blend of:

* an unsupervised **Isolation Forest** anomaly score computed across the whole
  population of user-day behavior vectors, and
* a set of **rule detectors** (data exfiltration, off-hours access, failed-login
  bursts, privilege escalation, impossible travel / new geo) evaluated against
  each user's own behavioral baseline.

The analyzer can be **fit** on a historical corpus and **persisted** (joblib),
then loaded to **score** live / streaming telemetry against the trained baseline
— the workflow an enterprise SOC uses for continuous assessment. ``analyze()``
remains a convenience that fits and scores the same batch in one call.

Every contributing factor is captured as an :class:`Explanation` so analysts,
HR and compliance can see *why* a user was flagged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from aegis_uba.config import Thresholds
from aegis_uba.features import FEATURE_COLUMNS, build_feature_frame
from aegis_uba.models import Alert, Event, Explanation, RiskLevel

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

MODEL_FORMAT = 2


@dataclass
class UserBaseline:
    """Historical behavior summary for one user, learned at fit time."""

    bytes_mean: float = 0.0
    bytes_std: float = 0.0
    prior_countries: set[str] = field(default_factory=set)
    prior_ips: set[str] = field(default_factory=set)
    active_days: int = 0


@dataclass
class ModelBundle:
    """Everything needed to score new telemetry against a trained baseline."""

    scaler: RobustScaler
    model: IsolationForest
    feature_columns: list[str]
    baselines: dict[str, UserBaseline]
    thresholds: Thresholds
    trained_at: str
    n_train_events: int
    n_train_users: int
    ml_lo: float
    ml_hi: float
    format: int = MODEL_FORMAT


class Analyzer:
    def __init__(self, thresholds: Thresholds | None = None, window_days: int = 3):
        self.th = thresholds or Thresholds()
        self.window_days = max(1, window_days)
        self.bundle: ModelBundle | None = None

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def fit(self, events: list[Event]) -> "Analyzer":
        """Learn the population Isolation Forest and per-user baselines."""
        df = build_feature_frame(events, self.th)
        if df.empty:
            raise ValueError("cannot fit on an empty event set")

        X = df[FEATURE_COLUMNS].to_numpy(dtype=float)
        scaler = RobustScaler().fit(X)
        model = IsolationForest(
            n_estimators=200, contamination=self.th.contamination, random_state=42,
        ).fit(scaler.transform(X))
        raw = model.score_samples(scaler.transform(X))

        baselines = self._learn_baselines(df, events)
        self.bundle = ModelBundle(
            scaler=scaler,
            model=model,
            feature_columns=list(FEATURE_COLUMNS),
            baselines=baselines,
            thresholds=self.th,
            trained_at=datetime.now().isoformat(timespec="seconds"),
            n_train_events=len(events),
            n_train_users=int(df["user"].nunique()),
            ml_lo=float(raw.min()),
            ml_hi=float(raw.max()),
        )
        return self

    @staticmethod
    def _learn_baselines(df: pd.DataFrame, events: list[Event]) -> dict[str, UserBaseline]:
        countries: dict[str, set[str]] = {}
        ips: dict[str, set[str]] = {}
        for e in events:
            countries.setdefault(e.user, set()).add(e.country)
            ips.setdefault(e.user, set()).add(e.source_ip)
        baselines: dict[str, UserBaseline] = {}
        for user, udf in df.groupby("user"):
            baselines[str(user)] = UserBaseline(
                bytes_mean=float(udf["total_bytes"].mean()),
                bytes_std=float(udf["total_bytes"].std(ddof=0)) if len(udf) > 1 else 0.0,
                prior_countries=set(countries.get(user, set())),
                prior_ips=set(ips.get(user, set())),
                active_days=int(len(udf)),
            )
        return baselines

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------
    def score(self, events: list[Event]) -> list[Alert]:
        """Score events against the fitted model (call :meth:`fit` first)."""
        if self.bundle is None:
            raise RuntimeError("model is not fitted; call fit() or load() first")
        df = build_feature_frame(events, self.th)
        if df.empty:
            return []
        df = self._apply_ml(df)

        alerts: list[Alert] = []
        for user, udf in df.groupby("user"):
            udf = udf.sort_values("day").reset_index(drop=True)
            base = self.bundle.baselines.get(str(user))
            n_candidates = min(self.window_days, len(udf))
            best: Alert | None = None
            for i in range(len(udf) - n_candidates, len(udf)):
                scored = udf.iloc[i]
                bmean, bstd, prior = self._baseline_for(user, udf, i, base)
                alert = self._score_user(str(user), scored, bmean, bstd, prior)
                if best is None or alert.risk_score > best.risk_score:
                    best = alert
            if best is not None:
                alerts.append(best)
        alerts.sort(key=lambda a: a.risk_score, reverse=True)
        return alerts

    def analyze(self, events: list[Event]) -> list[Alert]:
        """Convenience: fit and score the same batch (back-compatible API)."""
        if not events:
            return []
        return self.fit(events).score(events)

    def _baseline_for(self, user, udf, i, base):
        """Prefer the trained baseline; fall back to in-batch history for new users."""
        if base is not None and base.active_days > 1:
            return base.bytes_mean, base.bytes_std, base.prior_countries
        hist = udf.drop(index=i) if len(udf) > 1 else udf
        bmean = float(hist["total_bytes"].mean()) if len(hist) else float(udf.iloc[i]["total_bytes"])
        bstd = float(hist["total_bytes"].std(ddof=0)) if len(hist) > 1 else 0.0
        prior = set(base.prior_countries) if base else set()
        return bmean, bstd, prior

    def _apply_ml(self, df: pd.DataFrame) -> pd.DataFrame:
        b = self.bundle
        X = df[b.feature_columns].to_numpy(dtype=float)
        raw = b.model.score_samples(b.scaler.transform(X))
        span = (b.ml_hi - b.ml_lo) or 1.0
        df = df.copy()
        df["ml_anomaly"] = np.clip((b.ml_hi - raw) / span, 0.0, 1.0)
        return df

    # ------------------------------------------------------------------
    def _score_user(self, user: str, scored: pd.Series, bytes_mean: float,
                    bytes_std: float, prior_countries: set[str]) -> Alert:
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
        z = (total_bytes - bytes_mean) / bytes_std if bytes_std > 0 else 0.0
        if z >= th.data_exfil_zscore or max_bytes >= 500_000_000:
            sev = min(1.0, max(z / (th.data_exfil_zscore * 2), max_bytes / 1_000_000_000))
            pts = _EXFIL_MAX * max(sev, 0.6)
            explanations.append(Explanation(
                factor="Possible data exfiltration",
                detail=(f"Transferred {_human_bytes(total_bytes)} "
                        f"({z:.1f}σ above their normal {_human_bytes(bytes_mean)}); "
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
        if n_countries > 1:
            pts = th.new_geo_penalty + (_GEO_MAX - th.new_geo_penalty)
            explanations.append(Explanation(
                factor="Impossible travel / new geography",
                detail=(f"Authenticated from {n_countries} distinct countries in one "
                        f"day (baseline: {', '.join(sorted(prior_countries)) or 'US'})."),
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
        seen: set[str] = set()
        return [a for a in actions if not (a in seen or seen.add(a))]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save(self, path: str | Path) -> Path:
        if self.bundle is None:
            raise RuntimeError("nothing to save; fit the model first")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.bundle, path)
        return path

    @classmethod
    def load(cls, path: str | Path) -> "Analyzer":
        bundle: ModelBundle = joblib.load(Path(path))
        analyzer = cls(thresholds=bundle.thresholds)
        analyzer.bundle = bundle
        return analyzer

    @property
    def is_fitted(self) -> bool:
        return self.bundle is not None

    def info(self) -> dict:
        if self.bundle is None:
            return {"fitted": False}
        b = self.bundle
        return {
            "fitted": True,
            "trained_at": b.trained_at,
            "train_events": b.n_train_events,
            "train_users": b.n_train_users,
            "features": len(b.feature_columns),
            "contamination": b.thresholds.contamination,
            "format": b.format,
        }


def _human_bytes(n: float) -> str:
    step = 1024.0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < step:
            return f"{n:.1f} {unit}"
        n /= step
    return f"{n:.1f} PB"
