"""Detection engine: ML ensemble + rule detectors + peer & sequence analytics.

The :class:`Analyzer` produces one explainable :class:`Alert` per user for their
most recent activity window. The final 0-100 risk score fuses four signals:

* **ML ensemble** — Isolation Forest, Local Outlier Factor, PCA reconstruction
  error and a Ledoit-Wolf Mahalanobis distance, each normalized against the
  training population and averaged (composition set by :class:`MLConfig`).
* **Rule detectors** — sixteen behavioral detectors (exfiltration, USB, personal
  cloud, email forwarding, brute force, off-hours, privilege abuse, impossible
  travel, anonymised networks, mass collection, mass deletion, defense evasion,
  lateral movement, dormant-account activation, sensitive-data access) evaluated
  against each user's own learned baseline.
* **Peer-group deviation** — how far the user sits from their department's norm.
* **Sequence rarity** — how improbable the user-day's action bigrams are against
  the population's learned transition model.

The analyzer is **fit** on a historical corpus, **persisted** (joblib) and
loaded to **score** live telemetry — the continuous-assessment loop a production
SOC runs. Every detector declares the MITRE ATT&CK techniques it observes and
the compliance controls it evidences, which powers the console's coverage maps.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.covariance import LedoitWolf
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler

from athena_itd.config import Config, MLConfig, Thresholds
from athena_itd.features import FEATURE_COLUMNS, build_feature_frame
from athena_itd.geo import (
    HIGH_RISK_COUNTRIES,
    classify_ip,
    country_name,
    worst_travel_leg,
)
from athena_itd.models import (
    Action,
    Alert,
    Event,
    Explanation,
    FeatureContribution,
    RiskLevel,
)

MODEL_FORMAT = 3

_ML_MAX = 35.0


# ---------------------------------------------------------------------------
# Detector catalogue
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DetectorSpec:
    """Static description of one detector: scoring cap, ATT&CK and controls."""

    key: str
    name: str
    kind: str                 # "unsupervised" | "rule" | "rule+baseline" | "analytic"
    detail: str
    max_points: float
    mitre: tuple[str, ...] = ()
    compliance: dict[str, list[str]] = field(default_factory=dict)


DETECTORS: dict[str, DetectorSpec] = {
    d.key: d
    for d in [
        DetectorSpec(
            "ml", "ML behavioral anomaly", "unsupervised",
            "Ensemble of Isolation Forest, LOF, PCA reconstruction and Mahalanobis "
            "distance over the full behavior vector.", _ML_MAX,
            ("T1078",),
            {"nist80053": ["AC-2(12)", "SI-4"], "nistcsf": ["DE.AE-02", "DE.CM-03"],
             "iso27001": ["A.8.16"], "soc2": ["CC7.2"]},
        ),
        DetectorSpec(
            "exfil", "Data exfiltration volume", "rule+baseline",
            "Outbound data volume σ above the user's own baseline, or a very large "
            "single transfer.", 55,
            ("T1048", "T1567", "T1029", "T1074"),
            {"gdpr": ["Art.5(1)(f)", "Art.32", "Art.33"], "hipaa": ["164.312(a)(1)"],
             "iso27001": ["A.8.12"], "soc2": ["CC6.7"], "pcidss": ["10.4"],
             "nist80053": ["SI-4", "AU-6"], "nistcsf": ["DE.CM-01"]},
        ),
        DetectorSpec(
            "usb", "Removable-media exfiltration", "rule+baseline",
            "USB writes by a user whose baseline shows no removable-media use.", 45,
            ("T1052", "T1052.001"),
            {"iso27001": ["A.8.12"], "soc2": ["CC6.7"], "nist80053": ["SI-4"],
             "nistcsf": ["DE.CM-03"]},
        ),
        DetectorSpec(
            "cloud", "Personal cloud upload", "rule+baseline",
            "Uploads to personal cloud storage / paste / transfer services from a "
            "managed identity.", 45,
            ("T1567", "T1567.002"),
            {"gdpr": ["Art.32"], "iso27001": ["A.8.12"], "soc2": ["CC6.7"],
             "nistcsf": ["DE.CM-01"]},
        ),
        DetectorSpec(
            "email", "Suspicious email egress", "rule+baseline",
            "Auto-forward rules to external mailboxes or a spike of mail to personal "
            "domains.", 40,
            ("T1114", "T1114.003"),
            {"gdpr": ["Art.5(1)(f)"], "iso27001": ["A.5.16", "A.8.12"],
             "soc2": ["CC6.7"], "nistcsf": ["DE.CM-01"]},
        ),
        DetectorSpec(
            "failed", "Failed-login burst", "rule",
            "Many failed authentications in the window — brute force, spraying or "
            "credential stuffing.", 45,
            ("T1110", "T1110.003", "T1110.004"),
            {"hipaa": ["164.308(a)(5)(ii)(C)"], "iso27001": ["A.5.16"],
             "soc2": ["CC6.1"], "pcidss": ["8.3", "10.2"],
             "nist80053": ["AC-2", "AU-6"], "nistcsf": ["DE.CM-01"]},
        ),
        DetectorSpec(
            "offhours", "Off-hours access", "rule+baseline",
            "Sustained activity outside business hours or overnight.", 40,
            ("T1078", "T1029"),
            {"hipaa": ["164.308(a)(1)(ii)(D)"], "iso27001": ["A.8.16"],
             "pcidss": ["10.2"], "nist80053": ["AC-2(12)"], "nistcsf": ["DE.CM-03"]},
        ),
        DetectorSpec(
            "privesc", "Privilege escalation & abuse", "rule",
            "Elevation events, sensitive configuration changes and account "
            "manipulation.", 50,
            ("T1548", "T1548.003", "T1098", "T1136"),
            {"hipaa": ["164.312(a)(1)"], "iso27001": ["A.5.15", "A.5.18"],
             "soc2": ["CC6.1", "CC6.2"], "pcidss": ["7.2", "10.2"],
             "nist80053": ["AC-6(9)", "SI-4(20)"], "nistcsf": ["PR.AA-05"]},
        ),
        DetectorSpec(
            "geo", "Impossible travel / new geography", "rule+baseline",
            "Authentications whose implied travel speed is physically impossible, or "
            "from never-before-seen / high-risk countries.", 50,
            ("T1078", "T1078.004"),
            {"hipaa": ["164.308(a)(1)(ii)(D)"], "iso27001": ["A.8.16"],
             "soc2": ["CC6.6"], "nist80053": ["AC-2(12)"], "nistcsf": ["DE.CM-01"]},
        ),
        DetectorSpec(
            "anonip", "Anonymised network origin", "rule",
            "Sessions arriving from Tor exits, commercial VPN egress or bulletproof "
            "hosting.", 40,
            ("T1090",),
            {"soc2": ["CC6.6"], "nist80053": ["SI-4"], "nistcsf": ["DE.CM-01"]},
        ),
        DetectorSpec(
            "masscollect", "Mass data collection", "rule+baseline",
            "Bulk file/share/database reads far beyond the user's role-normal "
            "footprint — staging before exfiltration.", 45,
            ("T1005", "T1039", "T1083", "T1213"),
            {"gdpr": ["Art.30", "Art.32"], "hipaa": ["164.312(b)"],
             "iso27001": ["A.8.15"], "soc2": ["CC6.1"], "pcidss": ["10.2"],
             "nist80053": ["AU-6"], "nistcsf": ["DE.AE-02"]},
        ),
        DetectorSpec(
            "massdelete", "Mass deletion / destruction", "rule",
            "Deletion or encryption of files at a scale consistent with sabotage or "
            "evidence destruction.", 50,
            ("T1485", "T1486", "T1070.004"),
            {"gdpr": ["Art.5(1)(f)", "Art.33"], "hipaa": ["164.308(a)(6)"],
             "iso27001": ["A.8.12"], "soc2": ["CC7.4"], "pcidss": ["12.10"],
             "nist80053": ["IR-4"], "nistcsf": ["RS.MA-01"]},
        ),
        DetectorSpec(
            "evasion", "Defense evasion", "rule",
            "Log clearing or security-tool tampering — the actor is covering "
            "tracks.", 55,
            ("T1070", "T1562"),
            {"hipaa": ["164.312(b)"], "iso27001": ["A.8.15"], "soc2": ["CC7.3"],
             "pcidss": ["10.7"], "nist80053": ["AU-6(3)"], "nistcsf": ["DE.AE-03"]},
        ),
        DetectorSpec(
            "lateral", "Lateral movement", "rule+baseline",
            "Interactive sessions across many hosts beyond the user's normal "
            "footprint.", 40,
            ("T1021", "T1021.001"),
            {"iso27001": ["A.8.16"], "soc2": ["CC6.6"], "nist80053": ["SI-4"],
             "nistcsf": ["DE.CM-01"]},
        ),
        DetectorSpec(
            "dormant", "Dormant account activation", "rule+baseline",
            "A long-inactive identity suddenly active — classic account takeover or "
            "orphaned-account abuse.", 35,
            ("T1078",),
            {"iso27001": ["A.5.16", "A.5.18"], "soc2": ["CC6.2"],
             "nist80053": ["AC-2"], "nistcsf": ["PR.AA-05"]},
        ),
        DetectorSpec(
            "sensitive", "Sensitive-data access spike", "rule+baseline",
            "Access to classified resource paths (payroll, HR, legal, keys) far "
            "above the user's norm.", 45,
            ("T1213", "T1530", "T1005"),
            {"gdpr": ["Art.25", "Art.30", "Art.35"], "hipaa": ["164.308(a)(3)"],
             "iso27001": ["A.5.15"], "soc2": ["CC6.1"], "pcidss": ["7.2"],
             "nist80053": ["AC-6(9)"], "nistcsf": ["PR.AA-05"]},
        ),
        DetectorSpec(
            "peer", "Peer-group deviation", "analytic",
            "Behavior far outside the norm of the user's own department.", 15,
            ("T1078",),
            {"nist80053": ["AC-2(12)"], "nistcsf": ["DE.AE-02"]},
        ),
        DetectorSpec(
            "sequence", "Rare action sequence", "analytic",
            "Action orderings (e.g. login → mass read → USB write) that are "
            "improbable under the organisation's transition model.", 10,
            ("T1074",),
            {"nistcsf": ["DE.AE-03"], "nist80053": ["AU-6(3)"]},
        ),
    ]
}


def detector_mitre_map() -> dict[str, list[str]]:
    return {k: list(d.mitre) for k, d in DETECTORS.items()}


def detector_compliance_map() -> dict[str, dict[str, list[str]]]:
    return {k: {fw: list(c) for fw, c in d.compliance.items()}
            for k, d in DETECTORS.items()}


# ---------------------------------------------------------------------------
# Baselines & bundle
# ---------------------------------------------------------------------------
@dataclass
class UserBaseline:
    """Historical behavior summary for one user, learned at fit time."""

    bytes_mean: float = 0.0
    bytes_std: float = 0.0
    exfil_mean: float = 0.0
    exfil_std: float = 0.0
    sens_mean: float = 0.0
    sens_std: float = 0.0
    prior_countries: set[str] = field(default_factory=set)
    prior_ips: set[str] = field(default_factory=set)
    prior_hosts: set[str] = field(default_factory=set)
    usb_days: int = 0
    cloud_days: int = 0
    active_days: int = 0
    last_day: str = ""        # ISO date of the last training-corpus activity


@dataclass
class ModelBundle:
    """Everything needed to score new telemetry against a trained baseline."""

    scaler: RobustScaler
    members: dict[str, object]            # ensemble name -> fitted estimator
    member_range: dict[str, tuple[float, float]]
    feature_columns: list[str]
    col_median: np.ndarray
    col_mad: np.ndarray
    baselines: dict[str, UserBaseline]
    peer_stats: dict[str, dict[str, tuple[float, float]]]
    bigram_logp: dict[str, float]
    bigram_floor: float
    thresholds: Thresholds
    ml_config: MLConfig
    trained_at: str
    n_train_events: int
    n_train_users: int
    format: int = MODEL_FORMAT


_PEER_FEATURES = ["total_bytes", "n_events", "exfil_bytes",
                  "sensitive_access_score", "distinct_hosts", "after_hours_ratio"]


# ---------------------------------------------------------------------------
class Analyzer:
    def __init__(self, thresholds: Thresholds | None = None,
                 window_days: int = 3, config: Config | None = None):
        self.config = config
        self.th = thresholds or (config.thresholds if config else Thresholds())
        self.mlc = config.ml if config else MLConfig()
        self.window_days = max(1, window_days)
        self.bundle: ModelBundle | None = None
        self._disabled = set(config.disabled_detectors) if config else set()
        self._weight_overrides = dict(config.detector_weights) if config else {}

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def fit(self, events: list[Event]) -> Analyzer:
        """Learn the ML ensemble, per-user baselines, peer stats and sequences."""
        df = build_feature_frame(events, self.th, self.config)
        if df.empty:
            raise ValueError("cannot fit on an empty event set")

        X = df[FEATURE_COLUMNS].to_numpy(dtype=float)
        scaler = RobustScaler().fit(X)
        Xs = scaler.transform(X)
        mlc = self.mlc

        members: dict[str, object] = {}
        member_range: dict[str, tuple[float, float]] = {}

        def register(name: str, estimator, raw: np.ndarray) -> None:
            members[name] = estimator
            lo, hi = float(np.min(raw)), float(np.max(raw))
            member_range[name] = (lo, hi if hi > lo else lo + 1.0)

        if mlc.use_isolation_forest:
            iso = IsolationForest(
                n_estimators=mlc.n_estimators,
                contamination=self.th.contamination,
                random_state=mlc.random_state,
            ).fit(Xs)
            register("iforest", iso, -iso.score_samples(Xs))
        if mlc.use_lof and len(Xs) > mlc.lof_neighbors + 1:
            lof = LocalOutlierFactor(
                n_neighbors=mlc.lof_neighbors, novelty=True,
            ).fit(Xs)
            register("lof", lof, -lof.score_samples(Xs))
        if mlc.use_pca_reconstruction and len(Xs) >= mlc.min_train_rows:
            pca = PCA(n_components=mlc.pca_variance,
                      random_state=mlc.random_state).fit(Xs)
            recon = pca.inverse_transform(pca.transform(Xs))
            register("pca", pca, np.linalg.norm(Xs - recon, axis=1))
        if mlc.use_mahalanobis and len(Xs) >= mlc.min_train_rows:
            lw = LedoitWolf().fit(Xs)
            register("mahalanobis", lw, lw.mahalanobis(Xs))
        if not members:  # tiny corpora: guarantee at least one member
            iso = IsolationForest(
                n_estimators=100, contamination=self.th.contamination,
                random_state=mlc.random_state).fit(Xs)
            register("iforest", iso, -iso.score_samples(Xs))

        med = np.median(X, axis=0)
        mad = np.median(np.abs(X - med), axis=0)
        bigram_logp, bigram_floor = self._learn_bigrams(events)

        self.bundle = ModelBundle(
            scaler=scaler,
            members=members,
            member_range=member_range,
            feature_columns=list(FEATURE_COLUMNS),
            col_median=med,
            col_mad=mad,
            baselines=self._learn_baselines(df, events),
            peer_stats=self._learn_peer_stats(df),
            bigram_logp=bigram_logp,
            bigram_floor=bigram_floor,
            thresholds=self.th,
            ml_config=mlc,
            trained_at=datetime.now().isoformat(timespec="seconds"),
            n_train_events=len(events),
            n_train_users=int(df["user"].nunique()),
        )
        return self

    @staticmethod
    def _learn_baselines(df: pd.DataFrame, events: list[Event]) -> dict[str, UserBaseline]:
        countries: dict[str, set[str]] = {}
        ips: dict[str, set[str]] = {}
        hosts: dict[str, set[str]] = {}
        for e in events:
            countries.setdefault(e.user, set()).add(e.country)
            ips.setdefault(e.user, set()).add(e.source_ip)
            hosts.setdefault(e.user, set()).add(e.host)
        baselines: dict[str, UserBaseline] = {}
        for user, udf in df.groupby("user"):
            u = str(user)
            baselines[u] = UserBaseline(
                bytes_mean=float(udf["total_bytes"].mean()),
                bytes_std=float(udf["total_bytes"].std(ddof=0)) if len(udf) > 1 else 0.0,
                exfil_mean=float(udf["exfil_bytes"].mean()),
                exfil_std=float(udf["exfil_bytes"].std(ddof=0)) if len(udf) > 1 else 0.0,
                sens_mean=float(udf["sensitive_access_score"].mean()),
                sens_std=float(udf["sensitive_access_score"].std(ddof=0)) if len(udf) > 1 else 0.0,
                prior_countries=set(countries.get(u, set())),
                prior_ips=set(ips.get(u, set())),
                prior_hosts=set(hosts.get(u, set())),
                usb_days=int((udf["n_usb"] > 0).sum()),
                cloud_days=int((udf["n_cloud_upload"] > 0).sum()),
                active_days=int(len(udf)),
                last_day=str(udf["day"].max()),
            )
        return baselines

    @staticmethod
    def _learn_peer_stats(df: pd.DataFrame) -> dict[str, dict[str, tuple[float, float]]]:
        stats: dict[str, dict[str, tuple[float, float]]] = {}
        for dept, ddf in df.groupby("department"):
            per_user = ddf.groupby("user")[_PEER_FEATURES].mean()
            if len(per_user) < 3:
                continue  # too small a peer group to compare against
            dept_stats = {}
            for col in _PEER_FEATURES:
                med = float(per_user[col].median())
                mad = float((per_user[col] - med).abs().median())
                dept_stats[col] = (med, mad)
            stats[str(dept)] = dept_stats
        return stats

    @staticmethod
    def _learn_bigrams(events: list[Event]) -> tuple[dict[str, float], float]:
        """Population action-transition log-probabilities per user session stream."""
        counts: dict[str, int] = {}
        total = 0
        by_user: dict[str, list[Event]] = {}
        for e in sorted(events, key=lambda e: (e.user, e.timestamp)):
            by_user.setdefault(e.user, []).append(e)
        for evs in by_user.values():
            for a, b in zip(evs, evs[1:]):
                if (b.timestamp - a.timestamp) > timedelta(hours=4):
                    continue  # different sessions
                key = f"{a.action.value}|{b.action.value}"
                counts[key] = counts.get(key, 0) + 1
                total += 1
        if not total:
            return {}, math.log(1e-4)
        logp = {k: math.log(v / total) for k, v in counts.items()}
        floor = math.log(0.5 / total)   # unseen transitions get half a count
        return logp, floor

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------
    def score(self, events: list[Event],
              watchlist: dict[str, float] | None = None) -> list[Alert]:
        """Score events against the fitted model (call :meth:`fit` first)."""
        if self.bundle is None:
            raise RuntimeError("model is not fitted; call fit() or load() first")
        df = build_feature_frame(events, self.th, self.config)
        if df.empty:
            return []
        df = self._apply_ml(df)
        watchlist = watchlist or {}

        day_events: dict[tuple[str, str], list[Event]] = {}
        for e in events:
            day_events.setdefault((e.user, e.timestamp.date().isoformat()), []).append(e)

        alerts: list[Alert] = []
        for user, udf in df.groupby("user"):
            udf = udf.sort_values("day").reset_index(drop=True)
            base = self.bundle.baselines.get(str(user))
            n_candidates = min(self.window_days, len(udf))
            best: Alert | None = None
            for i in range(len(udf) - n_candidates, len(udf)):
                row = udf.iloc[i]
                evs = day_events.get((str(user), str(row["day"])), [])
                alert = self._score_user(str(user), row, evs, udf, i, base,
                                         watchlist.get(str(user)))
                if best is None or alert.risk_score > best.risk_score:
                    best = alert
            if best is not None:
                alerts.append(best)
        alerts.sort(key=lambda a: a.risk_score, reverse=True)
        return alerts

    def analyze(self, events: list[Event],
                watchlist: dict[str, float] | None = None) -> list[Alert]:
        """Convenience: fit and score the same batch (back-compatible API)."""
        if not events:
            return []
        return self.fit(events).score(events, watchlist=watchlist)

    def _apply_ml(self, df: pd.DataFrame) -> pd.DataFrame:
        b = self.bundle
        X = df[b.feature_columns].to_numpy(dtype=float)
        Xs = b.scaler.transform(X)
        parts: list[np.ndarray] = []
        for name, est in b.members.items():
            lo, hi = b.member_range[name]
            if name == "iforest":
                raw = -est.score_samples(Xs)
            elif name == "lof":
                raw = -est.score_samples(Xs)
            elif name == "pca":
                recon = est.inverse_transform(est.transform(Xs))
                raw = np.linalg.norm(Xs - recon, axis=1)
            elif name == "mahalanobis":
                raw = est.mahalanobis(Xs)
            else:  # pragma: no cover - future members
                continue
            parts.append(np.clip((raw - lo) / (hi - lo), 0.0, 1.0))
        df = df.copy()
        df["ml_anomaly"] = np.mean(parts, axis=0) if parts else 0.0
        return df

    # ------------------------------------------------------------------
    def _points(self, key: str, raw_points: float) -> float:
        """Apply operator weight overrides; return 0 for disabled detectors."""
        if key in self._disabled:
            return 0.0
        return raw_points * float(self._weight_overrides.get(key, 1.0))

    def _explain(self, key: str, factor: str, detail: str, points: float,
                 severity: RiskLevel = RiskLevel.MEDIUM,
                 evidence: dict | None = None,
                 confidence: float = 1.0) -> Explanation | None:
        pts = self._points(key, points)
        if pts <= 0:
            return None
        spec = DETECTORS[key]
        return Explanation(
            factor=factor, detail=detail, weight=round(pts, 1), detector=key,
            confidence=round(confidence, 2), severity=severity,
            mitre=list(spec.mitre), evidence=evidence or {},
        )

    # ------------------------------------------------------------------
    def _score_user(self, user: str, row: pd.Series, evs: list[Event],
                    udf: pd.DataFrame, i: int, base: UserBaseline | None,
                    watch_multiplier: float | None) -> Alert:
        th = self.th
        b = self.bundle
        explanations: list[Explanation] = []

        bytes_mean, bytes_std, prior_countries = self._baseline_for(user, udf, i, base)

        # === ML ensemble ==============================================
        ml_anom = float(row["ml_anomaly"])
        exp = None
        if ml_anom * _ML_MAX >= 6:
            names = " + ".join(sorted(b.members))
            exp = self._explain(
                "ml", "ML behavioral anomaly",
                f"The ensemble ({names}) scored this day's behavior vector "
                f"{ml_anom*100:.0f}% anomalous against the organisation baseline.",
                ml_anom * _ML_MAX,
                severity=RiskLevel.HIGH if ml_anom > 0.75 else RiskLevel.MEDIUM,
                evidence={"ml_anomaly": round(ml_anom, 3),
                          "members": sorted(b.members)})
        if exp:
            explanations.append(exp)
        ml_points = self._points("ml", ml_anom * _ML_MAX)

        # === Rule detectors ===========================================
        checks = (
            self._check_exfil(row, bytes_mean, bytes_std, base),
            self._check_usb(row, base),
            self._check_cloud(row, base),
            self._check_email(row),
            self._check_failed(row),
            self._check_offhours(row),
            self._check_privesc(row),
            self._check_geo(row, evs, prior_countries),
            self._check_anonip(evs),
            self._check_masscollect(row),
            self._check_massdelete(row),
            self._check_evasion(evs),
            self._check_lateral(row, base),
            self._check_dormant(row, base),
            self._check_sensitive(row, base),
        )
        rule_points = 0.0
        for exp in checks:
            if exp is not None:
                explanations.append(exp)
                rule_points += exp.weight
        rule_points = min(rule_points, 100.0)

        # === Peer-group deviation =====================================
        peer_z, peer_col = self._peer_deviation(row)
        peer_norm = min(1.0, max(0.0, (peer_z - 1.0) / (th.peer_deviation_sigma * 2)))
        if peer_z >= th.peer_deviation_sigma:
            exp = self._explain(
                "peer", "Deviation from peer group",
                f"'{_FEATURE_LABELS.get(peer_col, peer_col)}' sits {peer_z:.1f}σ above "
                f"the {row['department']} department norm.",
                DETECTORS["peer"].max_points * peer_norm,
                evidence={"feature": peer_col, "z": round(peer_z, 2),
                          "department": str(row["department"])})
            if exp:
                explanations.append(exp)

        # === Sequence rarity ==========================================
        seq_anom, rare_pairs = self._sequence_rarity(evs)
        if rare_pairs and seq_anom > 0.5:
            exp = self._explain(
                "sequence", "Rare action sequence",
                "Unusual activity ordering: " +
                ", ".join(p.replace("|", " → ") for p in rare_pairs[:3]) + ".",
                DETECTORS["sequence"].max_points * seq_anom,
                evidence={"rare_transitions": rare_pairs[:5],
                          "rarity": round(seq_anom, 2)})
            if exp:
                explanations.append(exp)

        # === Fusion ===================================================
        w = th
        score = (
            ml_points * (w.weight_ml / 0.30)
            + rule_points * (w.weight_rules / 0.45)
            + peer_norm * 100.0 * w.weight_peer
            + seq_anom * 100.0 * w.weight_sequence
        )

        confidence = 1.0
        if base is not None:
            confidence = min(1.0, 0.35 + base.active_days / 20.0)
        elif len(udf) < 5:
            confidence = 0.5

        if watch_multiplier and watch_multiplier > 1.0:
            score *= watch_multiplier
            explanations.append(Explanation(
                factor="Watchlisted user", detector="watchlist",
                detail=f"Risk boosted ×{watch_multiplier:.2f}: user is on the "
                       f"active watchlist.",
                weight=0.0, severity=RiskLevel.MEDIUM))

        score = float(np.clip(score, 0.0, 100.0))
        level = self._band(score)
        explanations.sort(key=lambda e: e.weight, reverse=True)
        fired = [e.detector for e in explanations if e.detector]
        mitre = sorted({t for e in explanations for t in e.mitre})

        day = row["day"]
        return Alert(
            user=user,
            window_start=datetime.combine(day, datetime.min.time()),
            window_end=datetime.combine(day, datetime.max.time()),
            risk_score=round(score, 1),
            risk_level=level,
            ml_score=round(ml_anom, 3),
            rule_score=round(rule_points, 1),
            peer_score=round(peer_norm, 3),
            sequence_score=round(seq_anom, 3),
            confidence=round(confidence, 2),
            department=str(row["department"]),
            role=str(row["role"]),
            event_count=int(row["n_events"]),
            explanations=explanations,
            contributions=self._contributions(row),
            recommended_actions=self._recommend(level, fired),
            mitre_techniques=mitre,
            detectors=fired,
        )

    def _baseline_for(self, user, udf, i, base):
        """Prefer the trained baseline; fall back to in-batch history for new users."""
        if base is not None and base.active_days > 1:
            return base.bytes_mean, base.bytes_std, base.prior_countries
        hist = udf.drop(index=i) if len(udf) > 1 else udf
        bmean = float(hist["total_bytes"].mean()) if len(hist) else float(udf.iloc[i]["total_bytes"])
        bstd = float(hist["total_bytes"].std(ddof=0)) if len(hist) > 1 else 0.0
        prior = set(base.prior_countries) if base else set()
        return bmean, bstd, prior

    # --- individual rule detectors ------------------------------------
    def _check_exfil(self, row, bytes_mean, bytes_std, base) -> Explanation | None:
        th = self.th
        total = float(row["total_bytes"])
        exfil = float(row["exfil_bytes"])
        max_single = float(row["max_single_bytes"])
        if base is not None and base.exfil_std > 0:
            z = (exfil - base.exfil_mean) / base.exfil_std
            ref_mean = base.exfil_mean
            measured = exfil
        else:
            z = (total - bytes_mean) / bytes_std if bytes_std > 0 else 0.0
            ref_mean = bytes_mean
            measured = total
        if z < th.data_exfil_zscore and max_single < 500_000_000:
            return None
        sev = min(1.0, max(z / (th.data_exfil_zscore * 2), max_single / 1_000_000_000))
        return self._explain(
            "exfil", "Possible data exfiltration",
            f"Moved {_human_bytes(measured)} through exfiltration channels "
            f"({z:.1f}σ above their normal {_human_bytes(ref_mean)}); largest "
            f"single transfer {_human_bytes(max_single)}.",
            DETECTORS["exfil"].max_points * max(sev, 0.6),
            severity=RiskLevel.CRITICAL if sev > 0.8 else RiskLevel.HIGH,
            evidence={"bytes": int(measured), "zscore": round(z, 2),
                      "max_single_bytes": int(max_single)})

    def _check_usb(self, row, base) -> Explanation | None:
        n_usb = int(row["n_usb"])
        if n_usb == 0:
            return None
        never_before = base is not None and base.usb_days == 0
        if not never_before and n_usb < 5:
            return None
        sev = min(1.0, n_usb / 10 + (0.5 if never_before else 0.0))
        hist = ("no removable-media use in their baseline"
                if never_before else f"{base.usb_days if base else '?'} prior USB days")
        return self._explain(
            "usb", "Removable-media exfiltration",
            f"{n_usb} USB events on a user with {hist}.",
            DETECTORS["usb"].max_points * max(sev, 0.6),
            severity=RiskLevel.HIGH,
            evidence={"usb_events": n_usb, "first_time": never_before})

    def _check_cloud(self, row, base) -> Explanation | None:
        n = int(row["n_cloud_upload"])
        if n == 0:
            return None
        never_before = base is not None and base.cloud_days == 0
        if not never_before and n < 4:
            return None
        sev = min(1.0, n / 8 + (0.4 if never_before else 0.0))
        return self._explain(
            "cloud", "Personal cloud upload",
            f"{n} uploads to personal cloud / file-transfer services"
            f"{' — a channel this user has never used before' if never_before else ''}.",
            DETECTORS["cloud"].max_points * max(sev, 0.6),
            severity=RiskLevel.HIGH,
            evidence={"cloud_uploads": n, "first_time": never_before})

    def _check_email(self, row) -> Explanation | None:
        rules = int(row["n_email_forward_rule"])
        ext = int(row["n_email_external"])
        if rules == 0 and ext < 8:
            return None
        if rules > 0:
            detail = (f"{rules} inbox auto-forward rule change(s) plus {ext} messages "
                      f"to external/personal domains — silent mail siphon.")
            sev = 1.0
        else:
            detail = f"{ext} messages to external/personal domains in one day."
            sev = min(1.0, ext / 20)
        return self._explain(
            "email", "Suspicious email egress", detail,
            DETECTORS["email"].max_points * max(sev, 0.6),
            severity=RiskLevel.HIGH if rules else RiskLevel.MEDIUM,
            evidence={"forward_rules": rules, "external_messages": ext})

    def _check_failed(self, row) -> Explanation | None:
        n = int(row["n_failed_logins"])
        if n < self.th.failed_login_burst:
            return None
        sev = min(1.0, n / (self.th.failed_login_burst * 4))
        return self._explain(
            "failed", "Failed-login burst",
            f"{n} failed authentications in the window — consistent with "
            f"brute-force or credential stuffing.",
            DETECTORS["failed"].max_points * max(sev, 0.65),
            severity=RiskLevel.HIGH,
            evidence={"failed_logins": n})

    def _check_offhours(self, row) -> Explanation | None:
        after_ratio = float(row["after_hours_ratio"])
        night = int(row["night_events"])
        if not (night >= 4 or (after_ratio >= 0.4 and night >= 2)):
            return None
        sev = min(1.0, max(after_ratio, night / 12))
        return self._explain(
            "offhours", "Off-hours access",
            f"{after_ratio*100:.0f}% of activity outside business hours with "
            f"{night} events between midnight and 5am.",
            DETECTORS["offhours"].max_points * max(sev, 0.6),
            evidence={"after_hours_ratio": round(after_ratio, 2),
                      "night_events": night})

    def _check_privesc(self, row) -> Explanation | None:
        n_priv = int(row["n_priv_esc"])
        n_cfg = int(row["n_config_change"])
        n_admin = int(row["n_admin_actions"])
        if n_priv == 0 and n_admin < 4:
            return None
        sev = min(1.0, (n_priv + n_cfg + n_admin * 0.5) / 8)
        return self._explain(
            "privesc", "Privilege escalation",
            f"{n_priv} privilege-escalation events, {n_cfg} sensitive config "
            f"changes and {n_admin} administrative actions — potential abuse of "
            f"elevated rights.",
            DETECTORS["privesc"].max_points * max(sev, 0.65),
            severity=RiskLevel.HIGH,
            evidence={"priv_esc": n_priv, "config_changes": n_cfg,
                      "admin_actions": n_admin})

    def _check_geo(self, row, evs, prior_countries) -> Explanation | None:
        sightings = [(e.country, e.timestamp.timestamp()) for e in evs
                     if e.country]
        leg = worst_travel_leg(sightings) if len(sightings) > 1 else None
        countries = {e.country for e in evs if e.country}
        new = countries - (prior_countries or set())
        risky = countries & HIGH_RISK_COUNTRIES

        if leg and leg.impossible:
            detail = (f"Physically impossible travel: {leg.summary}. "
                      f"Baseline countries: "
                      f"{', '.join(sorted(prior_countries)) or 'unknown'}.")
            sev = 1.0
        elif new and risky:
            detail = (f"First-ever authentication from high-risk "
                      f"jurisdiction(s): "
                      f"{', '.join(country_name(c) for c in sorted(risky))}.")
            sev = 0.9
        elif new and len(countries) > 1:
            detail = (f"Authenticated from {len(countries)} countries in one day, "
                      f"including never-before-seen "
                      f"{', '.join(country_name(c) for c in sorted(new))}.")
            sev = 0.75
        elif risky:
            detail = ("Activity from high-risk jurisdiction "
                      f"{', '.join(country_name(c) for c in sorted(risky))}.")
            sev = 0.6
        else:
            return None
        evidence = {"countries": sorted(countries),
                    "new_countries": sorted(new),
                    "high_risk": sorted(risky)}
        if leg:
            evidence["travel"] = leg.as_dict()
        return self._explain(
            "geo", "Impossible travel / new geography", detail,
            DETECTORS["geo"].max_points * sev,
            severity=RiskLevel.CRITICAL if (leg and leg.impossible) else RiskLevel.HIGH,
            evidence=evidence)

    def _check_anonip(self, evs) -> Explanation | None:
        hits: dict[str, dict] = {}
        for e in evs:
            info = classify_ip(e.source_ip)
            if info["category"] in {"tor", "vpn", "hosting"}:
                hits[e.source_ip] = info
        if not hits:
            return None
        worst = max(hits.values(), key=lambda h: h["risk"])
        sev = min(1.0, worst["risk"] * (0.7 + 0.1 * len(hits)))
        return self._explain(
            "anonip", "Anonymised network origin",
            f"{len(hits)} source address(es) with anonymising reputation — "
            f"worst: {worst['ip']} ({worst['label']}).",
            DETECTORS["anonip"].max_points * max(sev, 0.5),
            severity=RiskLevel.HIGH if worst["category"] == "tor" else RiskLevel.MEDIUM,
            evidence={"addresses": {ip: h["label"] for ip, h in hits.items()}})

    def _check_masscollect(self, row) -> Explanation | None:
        th = self.th
        reads = int(row["n_file_access"]) + int(row["n_db_query"])
        resources = int(row["distinct_resources"])
        if reads < th.mass_access_files and resources < th.mass_access_files:
            return None
        sev = min(1.0, max(reads, resources) / (th.mass_access_files * 3))
        return self._explain(
            "masscollect", "Mass data collection",
            f"{reads} read/query operations across {resources} distinct resources "
            f"in one day — bulk staging behavior.",
            DETECTORS["masscollect"].max_points * max(sev, 0.6),
            severity=RiskLevel.HIGH,
            evidence={"reads": reads, "distinct_resources": resources})

    def _check_massdelete(self, row) -> Explanation | None:
        th = self.th
        n_del = int(row["n_deletes"])
        n_destr = int(row["n_destructive"])
        if n_del < th.mass_delete_files and n_destr < th.mass_delete_files:
            return None
        sev = min(1.0, max(n_del, n_destr) / (th.mass_delete_files * 3))
        return self._explain(
            "massdelete", "Mass deletion / destruction",
            f"{max(n_del, n_destr)} destructive operations in one day — "
            f"consistent with sabotage or evidence destruction.",
            DETECTORS["massdelete"].max_points * max(sev, 0.7),
            severity=RiskLevel.CRITICAL,
            evidence={"deletes": n_del, "destructive": n_destr})

    def _check_evasion(self, evs) -> Explanation | None:
        clears = [e for e in evs if e.action == Action.LOG_CLEAR]
        disables = [e for e in evs if e.action == Action.SECURITY_TOOL_DISABLE]
        if not clears and not disables:
            return None
        parts = []
        if clears:
            parts.append(f"{len(clears)} audit-log clearing event(s)")
        if disables:
            parts.append(f"{len(disables)} security-tool tampering event(s)")
        sev = min(1.0, (len(clears) + len(disables)) / 3)
        return self._explain(
            "evasion", "Defense evasion",
            " and ".join(parts) + " — the account is actively covering tracks.",
            DETECTORS["evasion"].max_points * max(sev, 0.8),
            severity=RiskLevel.CRITICAL,
            evidence={"log_clears": len(clears), "tool_disables": len(disables)})

    def _check_lateral(self, row, base) -> Explanation | None:
        th = self.th
        hosts = int(row["distinct_hosts"])
        if hosts < th.lateral_host_count:
            return None
        prior = len(base.prior_hosts) if base else 0
        sev = min(1.0, hosts / (th.lateral_host_count * 2.5))
        return self._explain(
            "lateral", "Lateral movement",
            f"Sessions on {hosts} distinct hosts in one day "
            f"(baseline footprint: {prior or 'unknown'} hosts).",
            DETECTORS["lateral"].max_points * max(sev, 0.6),
            severity=RiskLevel.HIGH,
            evidence={"distinct_hosts": hosts, "baseline_hosts": prior})

    def _check_dormant(self, row, base) -> Explanation | None:
        th = self.th
        if base is None or not base.last_day or int(row["n_events"]) < 4:
            return None
        try:
            last = datetime.fromisoformat(base.last_day).date()
        except ValueError:
            return None
        gap = (row["day"] - last).days
        if gap < th.dormancy_days:
            return None
        sev = min(1.0, gap / (th.dormancy_days * 3))
        return self._explain(
            "dormant", "Dormant account activation",
            f"Account inactive for {gap} days suddenly produced "
            f"{int(row['n_events'])} events — possible takeover of a forgotten "
            f"identity.",
            DETECTORS["dormant"].max_points * max(sev, 0.7),
            severity=RiskLevel.HIGH,
            evidence={"dormant_days": gap})

    def _check_sensitive(self, row, base) -> Explanation | None:
        score = float(row["sensitive_access_score"])
        if score < 3.0:
            return None
        if base is not None and base.sens_std > 0:
            z = (score - base.sens_mean) / base.sens_std
            if z < 2.5:
                return None
            detail = (f"Weighted sensitive-resource access of {score:.1f} is "
                      f"{z:.1f}σ above their norm ({base.sens_mean:.1f}) — "
                      f"restricted paths include payroll/HR/legal/keys.")
            sev = min(1.0, z / 6)
        else:
            if score < 8.0:
                return None
            detail = (f"Weighted sensitive-resource access of {score:.1f} against "
                      f"restricted paths (payroll/HR/legal/keys) with no "
                      f"prior baseline.")
            sev = min(1.0, score / 20)
        return self._explain(
            "sensitive", "Sensitive-data access spike", detail,
            DETECTORS["sensitive"].max_points * max(sev, 0.6),
            severity=RiskLevel.HIGH,
            evidence={"sensitive_score": round(score, 1)})

    # --- analytics ----------------------------------------------------
    def _peer_deviation(self, row) -> tuple[float, str]:
        stats = self.bundle.peer_stats.get(str(row["department"]))
        if not stats:
            return 0.0, ""
        worst_z, worst_col = 0.0, ""
        for col, (med, mad) in stats.items():
            scale = 1.4826 * mad if mad > 0 else 0.0
            if scale <= 0:
                continue
            z = (float(row[col]) - med) / scale
            if z > worst_z:
                worst_z, worst_col = z, col
        return worst_z, worst_col

    def _sequence_rarity(self, evs: list[Event]) -> tuple[float, list[str]]:
        b = self.bundle
        if not b.bigram_logp or len(evs) < 3:
            return 0.0, []
        evs = sorted(evs, key=lambda e: e.timestamp)
        rare: list[str] = []
        logps: list[float] = []
        rarity_logp = math.log(self.th.sequence_rarity)
        for a, e in zip(evs, evs[1:]):
            if (e.timestamp - a.timestamp) > timedelta(hours=4):
                continue
            key = f"{a.action.value}|{e.action.value}"
            lp = b.bigram_logp.get(key, b.bigram_floor)
            logps.append(lp)
            if lp <= rarity_logp and key not in rare:
                rare.append(key)
        if not logps:
            return 0.0, []
        mean_lp = sum(logps) / len(logps)
        # Map mean log-prob onto 0..1: at the rarity threshold → ~0.5.
        anom = 1.0 / (1.0 + math.exp((mean_lp - rarity_logp) * 1.2))
        return min(1.0, anom + 0.1 * len(rare)), rare

    def _contributions(self, row) -> list[FeatureContribution]:
        b = self.bundle
        zs: list[tuple[str, float, float, float]] = []
        for j, col in enumerate(b.feature_columns):
            med = float(b.col_median[j])
            scale = 1.4826 * float(b.col_mad[j])
            if scale <= 0:
                scale = max(abs(med), 1.0)
            z = (float(row[col]) - med) / scale
            zs.append((col, float(row[col]), med, z))
        total = sum(abs(z) for _, _, _, z in zs) or 1.0
        zs.sort(key=lambda t: abs(t[3]), reverse=True)
        return [
            FeatureContribution(
                feature=col, value=round(val, 3), baseline=round(med, 3),
                deviation=round(z, 2),
                contribution=round(abs(z) / total, 3),
                direction="high" if z >= 0 else "low",
            )
            for col, val, med, z in zs[:8] if abs(z) > 0.5
        ]

    # ------------------------------------------------------------------
    def _band(self, score: float) -> RiskLevel:
        th = self.th
        if score >= th.critical:
            return RiskLevel.CRITICAL
        if score >= th.high:
            return RiskLevel.HIGH
        if score >= th.medium:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @staticmethod
    def _recommend(level: RiskLevel, fired: list[str]) -> list[str]:
        fired_set = set(fired)
        actions: list[str] = []
        if {"exfil", "usb", "cloud", "masscollect"} & fired_set:
            actions += ["Revoke active sessions", "Block outbound file transfers / USB",
                        "Preserve endpoint for forensic review"]
        if "email" in fired_set:
            actions += ["Remove mail auto-forward rules", "Review mailbox audit log"]
        if "failed" in fired_set:
            actions += ["Lock account", "Force password reset", "Enforce MFA challenge"]
        if "privesc" in fired_set:
            actions += ["Revoke elevated privileges", "Open IR ticket for admin review"]
        if "offhours" in fired_set:
            actions += ["Require step-up MFA for off-hours sessions"]
        if {"geo", "anonip"} & fired_set:
            actions += ["Challenge session with MFA", "Verify travel with the user/manager"]
        if {"massdelete", "evasion"} & fired_set:
            actions += ["Isolate endpoint", "Snapshot volumes / verify backups",
                        "Escalate to incident response immediately"]
        if "lateral" in fired_set:
            actions += ["Audit host access paths", "Rotate credentials used on touched hosts"]
        if "dormant" in fired_set:
            actions += ["Disable account pending owner verification"]
        if "sensitive" in fired_set:
            actions += ["Review data-access entitlements with the data owner"]
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
    def load(cls, path: str | Path, config: Config | None = None) -> Analyzer:
        bundle: ModelBundle = joblib.load(Path(path))
        analyzer = cls(thresholds=bundle.thresholds, config=config)
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
            "ensemble": sorted(b.members),
            "peer_groups": len(b.peer_stats),
            "transitions": len(b.bigram_logp),
            "contamination": b.thresholds.contamination,
            "format": b.format,
        }


_FEATURE_LABELS = {
    "total_bytes": "data volume",
    "n_events": "activity volume",
    "exfil_bytes": "outbound data volume",
    "sensitive_access_score": "sensitive-resource access",
    "distinct_hosts": "host footprint",
    "after_hours_ratio": "off-hours activity",
}


def _human_bytes(n: float) -> str:
    step = 1024.0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < step:
            return f"{n:.1f} {unit}"
        n /= step
    return f"{n:.1f} PB"
