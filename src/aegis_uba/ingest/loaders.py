"""File-based collectors: CSV, JSON/JSONL, and Linux ``auth.log``.

Every loader normalizes its input into :class:`Event` objects so the rest of the
pipeline is source-agnostic. Field names are matched flexibly (case-insensitive,
several common aliases) so real-world exports usually work without remapping.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

from dateutil import parser as dtparser

from aegis_uba.models import Action, Event

# Accept several column spellings for each canonical field.
_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "time", "datetime", "date", "@timestamp", "ts", "eventtime"),
    "user": ("user", "username", "user_name", "account", "actor", "subject", "uid"),
    "action": ("action", "event", "event_type", "activity", "operation", "type"),
    "host": ("host", "hostname", "device", "computer", "machine", "asset"),
    "source_ip": ("source_ip", "src_ip", "ip", "ipaddress", "client_ip", "remote_addr"),
    "resource": ("resource", "object", "file", "path", "target", "url"),
    "bytes": ("bytes", "size", "bytes_out", "data_size", "volume"),
    "success": ("success", "result", "status", "outcome"),
    "department": ("department", "dept", "team", "org_unit"),
    "role": ("role", "title", "job_title", "position"),
    "country": ("country", "geo", "country_code", "location"),
}


def sniff_format(path: Path) -> str:
    """Best-effort format detection based on extension and a content peek."""
    suffix = path.suffix.lower()
    if suffix in {".json", ".jsonl", ".ndjson"}:
        return "json"
    if suffix == ".csv":
        return "csv"
    name = path.name.lower()
    if "auth" in name or "secure" in name or suffix == ".log":
        return "authlog"
    # Peek at the first non-empty line.
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line[0] in "{[":
                return "json"
            if "," in line and ("user" in line.lower() or "timestamp" in line.lower()):
                return "csv"
            return "authlog"
    return "csv"


def _pick(row: dict[str, Any], field: str) -> Any:
    lowered = {k.lower(): v for k, v in row.items()}
    for alias in _ALIASES[field]:
        if alias in lowered and lowered[alias] not in (None, ""):
            return lowered[alias]
    return None


def _row_to_event(row: dict[str, Any]) -> Event | None:
    ts_raw = _pick(row, "timestamp")
    user = _pick(row, "user")
    if not ts_raw or not user:
        return None
    try:
        ts = dtparser.parse(str(ts_raw))
    except (ValueError, OverflowError):
        return None
    success_raw = _pick(row, "success")
    success = True
    if success_raw is not None:
        success = str(success_raw).strip().lower() not in {
            "0", "false", "fail", "failed", "failure", "denied", "no",
        }
    return Event(
        timestamp=ts,
        user=str(user),
        action=_pick(row, "action") or "other",
        host=str(_pick(row, "host") or "unknown"),
        source_ip=str(_pick(row, "source_ip") or "0.0.0.0"),
        resource=str(_pick(row, "resource") or ""),
        bytes=_pick(row, "bytes") or 0,
        success=success,
        department=str(_pick(row, "department") or "unknown"),
        role=str(_pick(row, "role") or "unknown"),
        country=str(_pick(row, "country") or "US"),
    )


def _load_csv(path: Path) -> list[Event]:
    events: list[Event] = []
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
        for row in csv.DictReader(fh):
            ev = _row_to_event(row)
            if ev:
                events.append(ev)
    return events


def _load_json(path: Path) -> list[Event]:
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    records: list[Any] = []
    if text.startswith("["):
        records = json.loads(text)
    else:  # JSONL / NDJSON
        for line in text.splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
    events: list[Event] = []
    for rec in records:
        if isinstance(rec, dict):
            ev = _row_to_event(rec)
            if ev:
                events.append(ev)
    return events


# Matches typical sshd / PAM lines in /var/log/auth.log
_AUTH_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+?):\s+(?P<msg>.*)$"
)
_ACCEPT_RE = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>\S+)")
_FAIL_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
# The syslog "sudo:" tag is consumed as the process field, so match the body.
_SUDO_RE = re.compile(r"^(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.*)$")


def _load_authlog(path: Path, default_year: int | None = None) -> list[Event]:
    import datetime as _dt

    year = default_year or _dt.datetime.now().year
    events: list[Event] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = _AUTH_RE.match(raw.strip())
        if not m:
            continue
        try:
            ts = dtparser.parse(f"{m['mon']} {m['day']} {year} {m['time']}")
        except (ValueError, OverflowError):
            continue
        host = m["host"]
        proc = m["proc"].rstrip(":")
        msg = m["msg"]
        if (a := _ACCEPT_RE.search(msg)):
            events.append(Event(timestamp=ts, user=a["user"], action=Action.LOGIN,
                                host=host, source_ip=a["ip"], resource="sshd"))
        elif (f := _FAIL_RE.search(msg)):
            events.append(Event(timestamp=ts, user=f["user"], action=Action.FAILED_LOGIN,
                                host=host, source_ip=f["ip"], resource="sshd", success=False))
        elif proc.startswith("sudo") and (s := _SUDO_RE.search(msg)):
            events.append(Event(timestamp=ts, user=s["user"], action=Action.PRIVILEGE_ESCALATION,
                                host=host, resource=f"sudo:{s['cmd'][:60]}"))
    return events


def load_events_from_file(path: str | Path, fmt: str | None = None) -> list[Event]:
    """Load and normalize events from ``path``; ``fmt`` overrides auto-detection."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    fmt = fmt or sniff_format(path)
    if fmt == "csv":
        return _load_csv(path)
    if fmt == "json":
        return _load_json(path)
    if fmt == "authlog":
        return _load_authlog(path)
    raise ValueError(f"Unsupported format: {fmt}")
