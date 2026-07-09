"""Domain models shared across ingest, detection, response and reporting."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Action(str, Enum):
    """Canonical activity types the platform understands."""

    LOGIN = "login"
    LOGOUT = "logout"
    FAILED_LOGIN = "failed_login"
    FILE_ACCESS = "file_access"
    FILE_DOWNLOAD = "file_download"
    FILE_DELETE = "file_delete"
    DATA_TRANSFER = "data_transfer"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CONFIG_CHANGE = "config_change"
    VPN_CONNECT = "vpn_connect"
    EMAIL_SEND = "email_send"
    OTHER = "other"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[self.value]


class Event(BaseModel):
    """A single normalized activity event from any collector."""

    timestamp: datetime
    user: str
    action: Action = Action.OTHER
    host: str = "unknown"
    source_ip: str = "0.0.0.0"
    resource: str = ""
    bytes: int = 0
    success: bool = True
    department: str = "unknown"
    role: str = "unknown"
    country: str = "US"
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("action", mode="before")
    @classmethod
    def _coerce_action(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = v.strip().lower()
            try:
                return Action(v)
            except ValueError:
                return Action.OTHER
        return v

    @field_validator("bytes", mode="before")
    @classmethod
    def _coerce_bytes(cls, v: Any) -> int:
        try:
            return max(0, int(float(v)))
        except (TypeError, ValueError):
            return 0


class Explanation(BaseModel):
    """A single human-readable contributing factor for a risk score."""

    factor: str
    detail: str
    weight: float


class Alert(BaseModel):
    """A scored, explainable finding for a user over an analysis window."""

    user: str
    window_start: datetime
    window_end: datetime
    risk_score: float
    risk_level: RiskLevel
    ml_score: float = 0.0
    department: str = "unknown"
    role: str = "unknown"
    event_count: int = 0
    explanations: list[Explanation] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def summary(self) -> str:
        top = self.explanations[0].factor if self.explanations else "behavioral anomaly"
        return f"{self.user} flagged {self.risk_level.value} ({self.risk_score:.0f}/100): {top}"
