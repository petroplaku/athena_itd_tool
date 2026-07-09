"""Adapter for the CMU CERT Insider Threat Test Dataset.

The CERT releases (r4.2 / r5.2 / r6.2) ship a set of CSVs describing a modelled
organization's telemetry. This adapter streams those CSVs and normalizes them
into Aegis :class:`~aegis_uba.models.Event` objects:

    logon.csv   -> LOGIN / LOGOUT
    device.csv  -> DATA_TRANSFER (removable-media connect)  [USB]
    file.csv    -> FILE_ACCESS / DATA_TRANSFER (copy to removable media)
    email.csv   -> EMAIL_SEND (bytes = size; flags external recipients)
    http.csv    -> OTHER (web activity; optional, high volume)
    LDAP/*.csv  -> per-user department / role enrichment

Files can be very large, so reading is chunked and every source supports row
caps, user filters and date ranges. Download a release from:
https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247
and point ``load_cert`` at the extracted directory.
"""
from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

from dateutil import parser as dtparser

from aegis_uba.models import Action, Event

# In the CERT scenarios the modelled company's mail domain is dtaa.com; anything
# else is an external recipient (a weak data-egress signal).
_COMPANY_DOMAIN = "dtaa.com"

_SOURCES = ("logon", "device", "file", "email", "http")


def detect_cert_release(path: str | Path) -> dict:
    """Report which CERT CSVs and LDAP snapshots are present in ``path``."""
    path = Path(path)
    files = {name: (path / f"{name}.csv").exists() for name in _SOURCES}
    ldap_dir = path / "LDAP"
    ldap = sorted(p.name for p in ldap_dir.glob("*.csv")) if ldap_dir.is_dir() else []
    return {"path": str(path), "sources": files, "ldap_snapshots": ldap,
            "present": [k for k, v in files.items() if v]}


def _load_ldap(path: Path) -> dict[str, dict[str, str]]:
    """Build user_id -> {department, role} from the latest LDAP snapshot."""
    ldap_dir = path / "LDAP"
    if not ldap_dir.is_dir():
        return {}
    snapshots = sorted(ldap_dir.glob("*.csv"))
    if not snapshots:
        return {}
    out: dict[str, dict[str, str]] = {}
    for snap in snapshots:  # later snapshots overwrite earlier -> most recent wins
        with snap.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
            for row in csv.DictReader(fh):
                low = {k.lower().strip(): (v or "").strip() for k, v in row.items()}
                uid = low.get("user_id") or low.get("user") or low.get("employee_id")
                if not uid:
                    continue
                dept = (low.get("department") or low.get("functional_unit")
                        or low.get("business_unit") or "unknown")
                out[uid] = {"department": dept or "unknown",
                            "role": low.get("role") or "unknown"}
    return out


def _parse_date(raw: str) -> datetime | None:
    try:
        return dtparser.parse(raw)  # CERT uses MM/DD/YYYY HH:MM:SS
    except (ValueError, OverflowError, TypeError):
        return None


def _iter_rows(csv_path: Path, limit: int | None) -> Iterator[dict[str, str]]:
    with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
        reader = csv.DictReader(fh)
        for n, row in enumerate(reader):
            if limit is not None and n >= limit:
                break
            yield {(k or "").lower().strip(): v for k, v in row.items()}


def _meta(uid: str, ldap: dict) -> tuple[str, str]:
    m = ldap.get(uid, {})
    return m.get("department", "unknown"), m.get("role", "unknown")


def load_cert(
    path: str | Path,
    *,
    sources: Iterable[str] | None = None,
    users: set[str] | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit_per_source: int | None = None,
    include_http: bool = False,
) -> list[Event]:
    """Load and normalize a CERT release directory into events.

    Parameters mirror what an operator needs for a scoped assessment: pick
    ``sources`` (default all but http), restrict to a set of ``users``, a date
    window, and cap rows per source for a fast slice.
    """
    path = Path(path)
    if not path.is_dir():
        raise NotADirectoryError(path)

    wanted = set(sources) if sources else {"logon", "device", "file", "email"}
    if include_http:
        wanted.add("http")
    ldap = _load_ldap(path)
    events: list[Event] = []

    def keep(ts: datetime | None, uid: str) -> bool:
        if ts is None:
            return False
        if users and uid not in users:
            return False
        if start and ts < start:
            return False
        if end and ts > end:
            return False
        return True

    # --- logon.csv ----------------------------------------------------
    if "logon" in wanted and (path / "logon.csv").exists():
        for r in _iter_rows(path / "logon.csv", limit_per_source):
            uid = r.get("user", "")
            ts = _parse_date(r.get("date", ""))
            if not keep(ts, uid):
                continue
            act = (r.get("activity") or "").strip().lower()
            dept, role = _meta(uid, ldap)
            events.append(Event(
                timestamp=ts, user=uid,
                action=Action.LOGIN if act == "logon" else Action.LOGOUT,
                host=r.get("pc", "unknown"), resource="workstation",
                department=dept, role=role))

    # --- device.csv (removable media) --------------------------------
    if "device" in wanted and (path / "device.csv").exists():
        for r in _iter_rows(path / "device.csv", limit_per_source):
            uid = r.get("user", "")
            ts = _parse_date(r.get("date", ""))
            if not keep(ts, uid):
                continue
            act = (r.get("activity") or "").strip().lower()
            if act and act != "connect":
                continue  # only the connect edge is interesting
            dept, role = _meta(uid, ldap)
            events.append(Event(
                timestamp=ts, user=uid, action=Action.DATA_TRANSFER,
                host=r.get("pc", "unknown"), resource="usb://removable-media",
                department=dept, role=role))

    # --- file.csv -----------------------------------------------------
    if "file" in wanted and (path / "file.csv").exists():
        for r in _iter_rows(path / "file.csv", limit_per_source):
            uid = r.get("user", "")
            ts = _parse_date(r.get("date", ""))
            if not keep(ts, uid):
                continue
            to_usb = (r.get("to_removable_media") or "").strip().lower() in {"true", "1"}
            content = r.get("content") or ""
            dept, role = _meta(uid, ldap)
            # CERT r4.2 gives no byte size; use the content field as a proxy and
            # floor copy-to-USB events at a plausible file size so bulk egress
            # (the real exfil signal) shows up as a data-volume spike.
            proxy = len(content) * 64
            nbytes = max(proxy, 20_000_000) if to_usb else proxy
            events.append(Event(
                timestamp=ts, user=uid,
                action=Action.DATA_TRANSFER if to_usb else Action.FILE_ACCESS,
                host=r.get("pc", "unknown"),
                resource=r.get("filename", ""),
                bytes=nbytes,
                department=dept, role=role))

    # --- email.csv ----------------------------------------------------
    if "email" in wanted and (path / "email.csv").exists():
        for r in _iter_rows(path / "email.csv", limit_per_source):
            uid = r.get("user", "")
            ts = _parse_date(r.get("date", ""))
            if not keep(ts, uid):
                continue
            recipients = ";".join(filter(None, [r.get("to", ""), r.get("cc", ""),
                                                 r.get("bcc", "")]))
            external = any(addr and _COMPANY_DOMAIN not in addr
                           for addr in recipients.replace(",", ";").split(";"))
            try:
                size = int(float(r.get("size") or 0))
            except (TypeError, ValueError):
                size = 0
            dept, role = _meta(uid, ldap)
            events.append(Event(
                timestamp=ts, user=uid, action=Action.EMAIL_SEND,
                host=r.get("pc", "unknown"),
                resource=("external:" if external else "internal:") + recipients[:80],
                bytes=size,
                department=dept, role=role,
                extra={"external": external,
                       "attachments": r.get("attachments", "")}))

    # --- http.csv (optional; high volume) -----------------------------
    if "http" in wanted and (path / "http.csv").exists():
        for r in _iter_rows(path / "http.csv", limit_per_source):
            uid = r.get("user", "")
            ts = _parse_date(r.get("date", ""))
            if not keep(ts, uid):
                continue
            dept, role = _meta(uid, ldap)
            events.append(Event(
                timestamp=ts, user=uid, action=Action.OTHER,
                host=r.get("pc", "unknown"), resource=(r.get("url") or "")[:120],
                department=dept, role=role))

    events.sort(key=lambda e: e.timestamp)
    return events
