"""Domain models shared across ingest, detection, response, triage and reporting.

These types are the contract between every layer of the platform. They are
Pydantic models so that the same definitions validate file ingest, serialize the
REST API, and round-trip through SQLite without a second schema to maintain.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Action(str, Enum):
    """Canonical activity types the platform understands.

    Collectors map vendor-specific event names onto this vocabulary so every
    detector downstream is source-agnostic — a SharePoint bulk download and an
    SMB share read both arrive as :attr:`FILE_DOWNLOAD`.
    """

    # Authentication
    LOGIN = "login"
    LOGOUT = "logout"
    FAILED_LOGIN = "failed_login"
    MFA_CHALLENGE = "mfa_challenge"
    MFA_DENIED = "mfa_denied"
    PASSWORD_CHANGE = "password_change"
    VPN_CONNECT = "vpn_connect"
    # Data
    FILE_ACCESS = "file_access"
    FILE_DOWNLOAD = "file_download"
    FILE_UPLOAD = "file_upload"
    FILE_DELETE = "file_delete"
    FILE_RENAME = "file_rename"
    FILE_ENCRYPT = "file_encrypt"
    DATA_TRANSFER = "data_transfer"
    USB_INSERT = "usb_insert"
    USB_WRITE = "usb_write"
    PRINT = "print"
    CLOUD_UPLOAD = "cloud_upload"
    REPO_CLONE = "repo_clone"
    DB_QUERY = "db_query"
    # Communication
    EMAIL_SEND = "email_send"
    EMAIL_FORWARD_RULE = "email_forward_rule"
    EMAIL_EXTERNAL = "email_external"
    # Administration
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CONFIG_CHANGE = "config_change"
    ACCOUNT_CREATE = "account_create"
    ACCOUNT_MODIFY = "account_modify"
    ACCOUNT_DELETE = "account_delete"
    PERMISSION_GRANT = "permission_grant"
    SECURITY_TOOL_DISABLE = "security_tool_disable"
    LOG_CLEAR = "log_clear"
    # Movement / misc
    REMOTE_SESSION = "remote_session"
    PROCESS_EXEC = "process_exec"
    WEB_BROWSE = "web_browse"
    OTHER = "other"


# Action groupings the feature builder and rule detectors reason about.
AUTH_ACTIONS = {Action.LOGIN, Action.FAILED_LOGIN, Action.VPN_CONNECT, Action.REMOTE_SESSION}
EXFIL_ACTIONS = {Action.FILE_DOWNLOAD, Action.DATA_TRANSFER, Action.USB_WRITE,
                 Action.CLOUD_UPLOAD, Action.FILE_UPLOAD, Action.PRINT, Action.REPO_CLONE}
DESTRUCTIVE_ACTIONS = {Action.FILE_DELETE, Action.FILE_ENCRYPT, Action.ACCOUNT_DELETE,
                       Action.LOG_CLEAR}
ADMIN_ACTIONS = {Action.PRIVILEGE_ESCALATION, Action.CONFIG_CHANGE, Action.ACCOUNT_CREATE,
                 Action.ACCOUNT_MODIFY, Action.PERMISSION_GRANT,
                 Action.SECURITY_TOOL_DISABLE, Action.ACCOUNT_DELETE}
EVASION_ACTIONS = {Action.LOG_CLEAR, Action.SECURITY_TOOL_DISABLE, Action.FILE_DELETE}
COLLECTION_ACTIONS = {Action.FILE_ACCESS, Action.DB_QUERY, Action.REPO_CLONE}


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[self.value]


class AlertStatus(str, Enum):
    """Triage lifecycle of a finding, driven from the console's alert queue."""

    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"

    @property
    def is_open(self) -> bool:
        return self in {AlertStatus.NEW, AlertStatus.TRIAGED,
                        AlertStatus.INVESTIGATING, AlertStatus.ESCALATED}


class CaseStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING_HR = "pending_hr"
    PENDING_LEGAL = "pending_legal"
    CLOSED_CONFIRMED = "closed_confirmed"
    CLOSED_UNSUBSTANTIATED = "closed_unsubstantiated"

    @property
    def is_open(self) -> bool:
        return self in {CaseStatus.OPEN, CaseStatus.IN_PROGRESS,
                        CaseStatus.PENDING_HR, CaseStatus.PENDING_LEGAL}


class Verdict(str, Enum):
    """Analyst feedback on an alert — the signal that tunes detector weights."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_TRUE_POSITIVE = "benign_true_positive"  # real, but authorised
    UNKNOWN = "unknown"


class Sensitivity(str, Enum):
    """Business sensitivity of a resource, driving the data-classification weight."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def weight(self) -> float:
        return {"public": 0.25, "internal": 0.5,
                "confidential": 0.8, "restricted": 1.0}[self.value]


class Event(BaseModel):
    """A single normalized activity event from any collector."""

    timestamp: datetime
    user: str
    action: Action = Action.OTHER
    host: str = "unknown"
    source_ip: str = "0.0.0.0"
    dest_ip: str = ""
    resource: str = ""
    bytes: int = 0
    success: bool = True
    department: str = "unknown"
    role: str = "unknown"
    country: str = "US"
    source: str = "generic"          # collector that produced the event
    process: str = ""
    user_agent: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("action", mode="before")
    @classmethod
    def _coerce_action(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = v.strip().lower().replace("-", "_").replace(" ", "_")
            try:
                return Action(v)
            except ValueError:
                return Action(_ACTION_SYNONYMS.get(v, "other"))
        return v

    @field_validator("bytes", mode="before")
    @classmethod
    def _coerce_bytes(cls, v: Any) -> int:
        try:
            return max(0, int(float(v)))
        except (TypeError, ValueError):
            return 0

    @field_validator("country", mode="before")
    @classmethod
    def _coerce_country(cls, v: Any) -> str:
        s = str(v or "US").strip().upper()
        return s[:2] if len(s) >= 2 else "US"

    @field_validator("timestamp", mode="after")
    @classmethod
    def _coerce_ts(cls, v: datetime) -> datetime:
        # Naive and aware timestamps both occur in real exports; normalize to
        # naive UTC so arithmetic across mixed sources never raises. Runs after
        # parsing so ISO strings carrying an offset are normalized too.
        if v.tzinfo is not None:
            return v.astimezone(timezone.utc).replace(tzinfo=None)
        return v

    @property
    def fingerprint(self) -> str:
        """Stable hash for de-duplicating replayed or overlapping log exports."""
        raw = (f"{self.timestamp.isoformat()}|{self.user}|{self.action.value}|"
               f"{self.host}|{self.source_ip}|{self.resource}|{self.bytes}")
        return hashlib.sha256(raw.encode()).hexdigest()[:32]


# Vendor event names that map onto the canonical vocabulary.
_ACTION_SYNONYMS: dict[str, str] = {
    "signin": "login", "sign_in": "login", "logon": "login", "authentication": "login",
    "user_login": "login", "session_start": "login", "accepted_password": "login",
    "signinfailed": "failed_login", "logon_failure": "failed_login",
    "authentication_failure": "failed_login", "failed_password": "failed_login",
    "invalid_login": "failed_login", "4625": "failed_login", "4624": "login",
    "4672": "privilege_escalation", "4720": "account_create", "4726": "account_delete",
    "4728": "permission_grant", "1102": "log_clear", "4688": "process_exec",
    "session_end": "logout", "sign_out": "logout",
    "filedownloaded": "file_download", "download": "file_download",
    "fileuploaded": "file_upload", "upload": "file_upload",
    "filedeleted": "file_delete", "delete": "file_delete",
    "filerenamed": "file_rename", "filemodified": "file_access",
    "fileaccessed": "file_access", "read": "file_access", "open": "file_access",
    "filecopiedtoremovablemedia": "usb_write", "removable_media": "usb_write",
    "usb": "usb_insert", "thumbdrive": "usb_insert",
    "sudo": "privilege_escalation", "elevate": "privilege_escalation",
    "runas": "privilege_escalation", "su": "privilege_escalation",
    "add_member": "permission_grant", "grant": "permission_grant",
    "new_inboxrule": "email_forward_rule", "set_inboxrule": "email_forward_rule",
    "send": "email_send", "mail_send": "email_send",
    "git_clone": "repo_clone", "clone": "repo_clone",
    "query": "db_query", "select": "db_query",
    "printjob": "print", "printed": "print",
    "vpn": "vpn_connect", "rdp": "remote_session", "ssh": "remote_session",
    "http": "web_browse", "browse": "web_browse", "visit": "web_browse",
    "disable_av": "security_tool_disable", "stop_service": "security_tool_disable",
    "clearlog": "log_clear", "wevtutil": "log_clear",
}


class Explanation(BaseModel):
    """A single human-readable contributing factor for a risk score.

    Explanations are the product's core deliverable: HR and legal read ``detail``
    verbatim, so every detector must state the observation, the baseline it
    deviates from, and the magnitude — never just a label.
    """

    factor: str
    detail: str
    weight: float
    detector: str = ""
    confidence: float = 1.0
    severity: RiskLevel = RiskLevel.MEDIUM
    mitre: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class FeatureContribution(BaseModel):
    """One feature's attributed share of the ML anomaly score."""

    feature: str
    value: float
    baseline: float
    deviation: float          # robust z-score against the population
    contribution: float       # 0-1 share of the total anomaly signal
    direction: str = "high"   # "high" or "low" relative to normal


class Alert(BaseModel):
    """A scored, explainable finding for a user over an analysis window."""

    user: str
    window_start: datetime
    window_end: datetime
    risk_score: float
    risk_level: RiskLevel
    ml_score: float = 0.0
    rule_score: float = 0.0
    peer_score: float = 0.0
    sequence_score: float = 0.0
    confidence: float = 1.0
    department: str = "unknown"
    role: str = "unknown"
    event_count: int = 0
    explanations: list[Explanation] = Field(default_factory=list)
    contributions: list[FeatureContribution] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    detectors: list[str] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.NEW
    assignee: str = ""
    case_id: int | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def summary(self) -> str:
        top = self.explanations[0].factor if self.explanations else "behavioral anomaly"
        return f"{self.user} flagged {self.risk_level.value} ({self.risk_score:.0f}/100): {top}"

    @property
    def dedup_key(self) -> str:
        """Identity used to carry triage state across re-analysis runs."""
        return f"{self.user}|{self.window_start.date().isoformat()}"


class Case(BaseModel):
    """An investigation grouping one or more alerts, with an audit trail."""

    id: int | None = None
    title: str
    subject_user: str
    status: CaseStatus = CaseStatus.OPEN
    severity: RiskLevel = RiskLevel.MEDIUM
    owner: str = ""
    summary: str = ""
    alert_keys: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    verdict: Verdict = Verdict.UNKNOWN
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    closed_at: datetime | None = None


class Note(BaseModel):
    """An analyst note attached to an alert, a case or a user."""

    id: int | None = None
    target_type: str          # "alert" | "case" | "user"
    target_id: str
    author: str
    body: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WatchlistEntry(BaseModel):
    """A user under heightened scrutiny — the multiplier is applied at scoring time."""

    user: str
    reason: str
    multiplier: float = 1.35
    added_by: str = "system"
    expires_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Feedback(BaseModel):
    """Analyst verdict on an alert, fed back into detector weighting."""

    alert_key: str
    user: str
    detector: str
    verdict: Verdict
    analyst: str = ""
    note: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditEntry(BaseModel):
    """Immutable record of an operator action against the platform itself."""

    actor: str
    action: str
    target: str = ""
    detail: str = ""
    source_ip: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UserProfile(BaseModel):
    """Directory view of an entity, enriched with its current risk posture."""

    user: str
    department: str = "unknown"
    role: str = "unknown"
    host: str = "unknown"
    source_ip: str = "0.0.0.0"
    country: str = "US"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_count: int = 0
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    watchlisted: bool = False
    open_alerts: int = 0
