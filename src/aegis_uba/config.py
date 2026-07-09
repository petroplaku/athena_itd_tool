"""Cross-platform configuration and path management.

Uses :mod:`platformdirs` so the tool stores its state in the correct location on
Linux (``~/.local/share/aegis-uba``), Windows (``%LOCALAPPDATA%\\aegis-uba``) and
macOS (``~/Library/Application Support/aegis-uba``). Every path can be overridden
via the ``AEGIS_HOME`` environment variable, which keeps the tool container- and
CI-friendly.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from platformdirs import user_data_dir

APP_NAME = "aegis-uba"
APP_AUTHOR = "aegis"


def _default_home() -> Path:
    override = os.environ.get("AEGIS_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path(user_data_dir(APP_NAME, APP_AUTHOR))


@dataclass
class Thresholds:
    """Risk banding and detector sensitivity knobs (all tunable via config.json)."""

    # Risk band cut-offs on a 0-100 scale.
    low: float = 25.0
    medium: float = 50.0
    high: float = 75.0
    # Fraction of events an unsupervised model treats as anomalous.
    contamination: float = 0.08
    # Hours considered "after hours" (outside typical business day).
    business_start_hour: int = 8
    business_end_hour: int = 19
    # Rule sensitivity.
    failed_login_burst: int = 5
    data_exfil_zscore: float = 3.0
    new_geo_penalty: float = 15.0


@dataclass
class Config:
    """Top-level runtime configuration, persisted to ``config.json``."""

    home: Path = field(default_factory=_default_home)
    thresholds: Thresholds = field(default_factory=Thresholds)
    webhook_url: str | None = None
    organization: str = "Acme Corp"

    # --- derived paths -------------------------------------------------
    @property
    def db_path(self) -> Path:
        return self.home / "aegis.sqlite3"

    @property
    def model_path(self) -> Path:
        return self.home / "model.joblib"

    @property
    def reports_dir(self) -> Path:
        return self.home / "reports"

    @property
    def config_path(self) -> Path:
        return self.home / "config.json"

    # --- persistence ---------------------------------------------------
    def ensure_dirs(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def save(self) -> None:
        self.ensure_dirs()
        payload = {
            "thresholds": asdict(self.thresholds),
            "webhook_url": self.webhook_url,
            "organization": self.organization,
        }
        self.config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @classmethod
    def load(cls) -> "Config":
        cfg = cls()
        if cfg.config_path.exists():
            try:
                data = json.loads(cfg.config_path.read_text(encoding="utf-8"))
                cfg.thresholds = Thresholds(**data.get("thresholds", {}))
                cfg.webhook_url = data.get("webhook_url")
                cfg.organization = data.get("organization", cfg.organization)
            except (json.JSONDecodeError, TypeError):
                # Corrupt config falls back to defaults rather than crashing.
                pass
        return cfg


def get_config() -> Config:
    """Return the active configuration, creating directories on first use."""
    cfg = Config.load()
    cfg.ensure_dirs()
    return cfg
