"""Cross-platform configuration, policy and path management.

Uses :mod:`platformdirs` so state lands in the correct location on Linux
(``~/.local/share/athena-itd``), Windows (``%LOCALAPPDATA%\\athena-itd``) and macOS
(``~/Library/Application Support/athena-itd``). Every path can be overridden via
``ATHENA_HOME``, which keeps the tool container- and CI-friendly.

Configuration is layered, lowest precedence first:

1. dataclass defaults (safe, opinionated, work with zero setup)
2. ``config.json`` in the data home
3. ``ATHENA_*`` environment variables

Environment override wins so that secrets (webhook URLs, API keys, SMTP
passwords) can be injected by a container orchestrator without ever being
written to disk.
"""
from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from platformdirs import user_data_dir

APP_NAME = "athena-itd"
APP_AUTHOR = "athena"


def _default_home() -> Path:
    # ATHENA_HOME is canonical; AEGIS_HOME is honoured as a deprecated alias so
    # environments provisioned before the rename keep working during migration.
    override = os.environ.get("ATHENA_HOME") or os.environ.get("AEGIS_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path(user_data_dir(APP_NAME, APP_AUTHOR))


@dataclass
class Thresholds:
    """Risk banding and detector sensitivity knobs (all tunable via config/UI)."""

    # Risk band cut-offs on a 0-100 scale.
    low: float = 25.0
    medium: float = 50.0
    high: float = 75.0
    critical: float = 88.0
    # Fraction of user-days an unsupervised model treats as anomalous.
    contamination: float = 0.08
    # Business day definition (local time of the monitored population).
    business_start_hour: int = 8
    business_end_hour: int = 19
    # Rule sensitivity.
    failed_login_burst: int = 5
    data_exfil_zscore: float = 3.0
    new_geo_penalty: float = 15.0
    peer_deviation_sigma: float = 2.5
    mass_access_files: int = 120
    mass_delete_files: int = 40
    lateral_host_count: int = 6
    sequence_rarity: float = 0.015
    dormancy_days: int = 21
    # Signal fusion weights — how much each analytic contributes before banding.
    weight_ml: float = 0.30
    weight_rules: float = 0.45
    weight_peer: float = 0.15
    weight_sequence: float = 0.10
    # Risk decay: a user's cumulative risk halves every N days without new signal.
    risk_halflife_days: float = 7.0


@dataclass
class MLConfig:
    """Ensemble composition and training hyper-parameters."""

    use_isolation_forest: bool = True
    use_lof: bool = True
    use_one_class_svm: bool = False   # O(n²) — off by default, on for small corpora
    use_pca_reconstruction: bool = True
    use_mahalanobis: bool = True
    n_estimators: int = 300
    lof_neighbors: int = 20
    pca_variance: float = 0.95
    random_state: int = 42
    min_train_rows: int = 30


@dataclass
class Integrations:
    """Outbound connections to SIEM, SOAR and notification platforms."""

    webhook_url: str | None = None
    splunk_hec_url: str | None = None
    splunk_hec_token: str | None = None
    elastic_url: str | None = None
    elastic_api_key: str | None = None
    elastic_index: str = "athena-alerts"
    sentinel_workspace_id: str | None = None
    sentinel_shared_key: str | None = None
    syslog_host: str | None = None
    syslog_port: int = 514
    syslog_format: str = "cef"        # cef | leef | rfc5424
    slack_webhook: str | None = None
    teams_webhook: str | None = None
    pagerduty_routing_key: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "athena@localhost"
    smtp_to: list[str] = field(default_factory=list)
    smtp_starttls: bool = True
    # Only forward findings at or above this level to external systems.
    min_forward_level: str = "HIGH"


@dataclass
class Security:
    """Console authentication, authorisation and hardening settings."""

    auth_enabled: bool = True
    api_key: str = ""
    session_ttl_minutes: int = 480
    # username -> {"password_hash": ..., "salt": ..., "role": admin|analyst|viewer}
    users: dict[str, dict[str, str]] = field(default_factory=dict)
    allow_signup: bool = True               # self-service account registration
    signup_role: str = "viewer"             # role granted to self-registered users
    allow_enforced_response: bool = False   # real (non-simulated) actions
    rate_limit_per_minute: int = 600
    cors_origins: list[str] = field(default_factory=list)

    def ensure_api_key(self) -> str:
        if not self.api_key:
            self.api_key = secrets.token_urlsafe(32)
        return self.api_key


@dataclass
class Retention:
    """Data-lifecycle policy — privacy regulators expect this to be explicit."""

    event_days: int = 180
    alert_days: int = 365
    audit_days: int = 730
    auto_purge: bool = False


@dataclass
class Config:
    """Top-level runtime configuration, persisted to ``config.json``."""

    home: Path = field(default_factory=_default_home)
    thresholds: Thresholds = field(default_factory=Thresholds)
    ml: MLConfig = field(default_factory=MLConfig)
    integrations: Integrations = field(default_factory=Integrations)
    security: Security = field(default_factory=Security)
    retention: Retention = field(default_factory=Retention)
    organization: str = "Your Organization"
    timezone: str = "UTC"
    # Detector keys the operator has switched off, and per-detector weight overrides.
    disabled_detectors: list[str] = field(default_factory=list)
    detector_weights: dict[str, float] = field(default_factory=dict)
    # Resource path prefixes considered sensitive, mapped to a Sensitivity value.
    sensitive_paths: dict[str, str] = field(default_factory=lambda: {
        "/finance/payroll": "restricted",
        "/hr/records": "restricted",
        "/legal/contracts": "restricted",
        "/it/keys": "restricted",
        "/eng/src": "confidential",
        "/sales/crm": "confidential",
        "/shared/reports": "internal",
    })
    # Domains treated as "personal / external" for email exfil detection.
    personal_email_domains: list[str] = field(default_factory=lambda: [
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me",
        "protonmail.com", "icloud.com", "aol.com", "mail.ru", "yandex.ru", "gmx.com",
    ])
    # Hosts/services associated with personal cloud storage uploads.
    personal_cloud_hosts: list[str] = field(default_factory=lambda: [
        "dropbox.com", "drive.google.com", "mega.nz", "wetransfer.com",
        "pastebin.com", "box.com", "sendspace.com", "anonfiles.com",
    ])

    # --- derived paths -------------------------------------------------
    @property
    def db_path(self) -> Path:
        return self.home / "athena.sqlite3"

    @property
    def model_path(self) -> Path:
        return self.home / "model.joblib"

    @property
    def reports_dir(self) -> Path:
        return self.home / "reports"

    @property
    def config_path(self) -> Path:
        return self.home / "config.json"

    @property
    def intel_path(self) -> Path:
        return self.home / "intel.json"

    @property
    def min_forward_rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(
            self.integrations.min_forward_level.upper(), 2)

    # --- persistence ---------------------------------------------------
    def ensure_dirs(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> dict:
        return {
            "organization": self.organization,
            "timezone": self.timezone,
            "thresholds": asdict(self.thresholds),
            "ml": asdict(self.ml),
            "integrations": asdict(self.integrations),
            "security": asdict(self.security),
            "retention": asdict(self.retention),
            "disabled_detectors": list(self.disabled_detectors),
            "detector_weights": dict(self.detector_weights),
            "sensitive_paths": dict(self.sensitive_paths),
            "personal_email_domains": list(self.personal_email_domains),
            "personal_cloud_hosts": list(self.personal_cloud_hosts),
        }

    def redacted(self) -> dict:
        """Config safe to return over the API — secrets replaced with a marker."""
        data = self.to_dict()
        secret_keys = {"splunk_hec_token", "elastic_api_key", "sentinel_shared_key",
                       "smtp_password", "pagerduty_routing_key"}
        for key in secret_keys:
            if data["integrations"].get(key):
                data["integrations"][key] = "••••••••"
        if data["security"].get("api_key"):
            data["security"]["api_key"] = "••••••••"
        data["security"]["users"] = {
            u: {"role": v.get("role", "viewer")} for u, v in self.security.users.items()
        }
        data["paths"] = {"home": str(self.home), "database": str(self.db_path),
                         "model": str(self.model_path), "reports": str(self.reports_dir)}
        return data

    def save(self) -> None:
        self.ensure_dirs()
        tmp = self.config_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        tmp.replace(self.config_path)   # atomic: a crash never truncates the config
        try:
            os.chmod(self.config_path, 0o600)   # it holds integration secrets
        except OSError:
            pass

    @classmethod
    def load(cls) -> Config:
        cfg = cls()
        if cfg.config_path.exists():
            try:
                data = json.loads(cfg.config_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {}   # corrupt config falls back to defaults rather than crashing
            cfg._apply(data)
        cfg._apply_env()
        return cfg

    def _apply(self, data: dict) -> None:
        self.organization = data.get("organization", self.organization)
        self.timezone = data.get("timezone", self.timezone)
        self.disabled_detectors = list(data.get("disabled_detectors", []))
        self.detector_weights = dict(data.get("detector_weights", {}))
        for key in ("sensitive_paths", "personal_email_domains", "personal_cloud_hosts"):
            if key in data and data[key]:
                setattr(self, key, data[key])
        self.thresholds = _rebuild(Thresholds, data.get("thresholds"), self.thresholds)
        self.ml = _rebuild(MLConfig, data.get("ml"), self.ml)
        self.integrations = _rebuild(Integrations, data.get("integrations"), self.integrations)
        self.security = _rebuild(Security, data.get("security"), self.security)
        self.retention = _rebuild(Retention, data.get("retention"), self.retention)
        # v1/v2 configs stored the webhook at the top level.
        if data.get("webhook_url") and not self.integrations.webhook_url:
            self.integrations.webhook_url = data["webhook_url"]

    def _apply_env(self) -> None:
        """Overlay ``ATHENA_*`` environment variables (highest precedence)."""
        env_map: list[tuple[str, Any, str]] = [
            ("ATHENA_ORG", self, "organization"),
            ("ATHENA_TIMEZONE", self, "timezone"),
            ("ATHENA_WEBHOOK_URL", self.integrations, "webhook_url"),
            ("ATHENA_SPLUNK_HEC_URL", self.integrations, "splunk_hec_url"),
            ("ATHENA_SPLUNK_HEC_TOKEN", self.integrations, "splunk_hec_token"),
            ("ATHENA_ELASTIC_URL", self.integrations, "elastic_url"),
            ("ATHENA_ELASTIC_API_KEY", self.integrations, "elastic_api_key"),
            ("ATHENA_SENTINEL_WORKSPACE_ID", self.integrations, "sentinel_workspace_id"),
            ("ATHENA_SENTINEL_SHARED_KEY", self.integrations, "sentinel_shared_key"),
            ("ATHENA_SLACK_WEBHOOK", self.integrations, "slack_webhook"),
            ("ATHENA_TEAMS_WEBHOOK", self.integrations, "teams_webhook"),
            ("ATHENA_PAGERDUTY_KEY", self.integrations, "pagerduty_routing_key"),
            ("ATHENA_SYSLOG_HOST", self.integrations, "syslog_host"),
            ("ATHENA_SMTP_HOST", self.integrations, "smtp_host"),
            ("ATHENA_SMTP_USER", self.integrations, "smtp_user"),
            ("ATHENA_SMTP_PASSWORD", self.integrations, "smtp_password"),
            ("ATHENA_API_KEY", self.security, "api_key"),
        ]
        for var, target, attr in env_map:
            val = os.environ.get(var)
            if val:
                setattr(target, attr, val)
        if os.environ.get("ATHENA_AUTH_ENABLED"):
            self.security.auth_enabled = _as_bool(os.environ["ATHENA_AUTH_ENABLED"])
        if os.environ.get("ATHENA_ALLOW_SIGNUP"):
            self.security.allow_signup = _as_bool(os.environ["ATHENA_ALLOW_SIGNUP"])
        if os.environ.get("ATHENA_SIGNUP_ROLE"):
            self.security.signup_role = os.environ["ATHENA_SIGNUP_ROLE"].strip().lower()
        if os.environ.get("ATHENA_SYSLOG_PORT"):
            try:
                self.integrations.syslog_port = int(os.environ["ATHENA_SYSLOG_PORT"])
            except ValueError:
                pass


def _as_bool(v: str) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


def _rebuild(cls, data: dict | None, current):
    """Rebuild a config dataclass from stored data, ignoring unknown/renamed keys.

    Forward and backward compatibility matter here: a config written by a newer
    build must not crash an older one, and a v1 config must still load.
    """
    if not isinstance(data, dict):
        return current
    valid = {f.name: f for f in fields(cls)}
    kwargs = {}
    for key, value in data.items():
        if key not in valid:
            continue
        target_type = valid[key].type
        # Guard against a stored null for a non-optional field.
        if value is None and not _optional(target_type):
            continue
        kwargs[key] = value
    try:
        return cls(**kwargs)
    except (TypeError, ValueError):
        return current


def _optional(annotation: Any) -> bool:
    return "None" in str(annotation) or "Optional" in str(annotation)


def get_config() -> Config:
    """Return the active configuration, creating directories on first use."""
    cfg = Config.load()
    cfg.ensure_dirs()
    return cfg


__all__ = ["APP_NAME", "APP_AUTHOR", "Config", "Thresholds", "MLConfig",
           "Integrations", "Security", "Retention", "get_config"]
