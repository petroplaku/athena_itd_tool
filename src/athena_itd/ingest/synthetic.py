"""Synthetic activity generator.

Produces a realistic corpus of user-activity events for a fictional org, then
plants a handful of well-known insider-threat scenarios so the detection engine
has something meaningful to find out of the box:

* **data_exfiltration** — a leaver copying/downloading large volumes of data.
* **off_hours_access** — sustained 2-4am activity from a day-shift worker.
* **failed_login_burst** — credential-stuffing / brute force against an account.
* **privilege_escalation** — sudden sudo/admin actions plus config changes.
* **impossible_travel** — logins from a new country the user never uses.

The generator is deterministic given a seed so demos and tests are reproducible.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from athena_itd.models import Action, Event

_DEPARTMENTS = {
    "engineering": ["developer", "sre", "staff_engineer"],
    "finance": ["analyst", "controller", "ap_clerk"],
    "sales": ["account_exec", "sdr", "sales_manager"],
    "hr": ["recruiter", "hr_generalist"],
    "it": ["helpdesk", "sysadmin", "secops"],
}
_FIRST = ["ava", "liam", "noah", "emma", "olivia", "ethan", "mia", "lucas",
          "sofia", "leo", "aria", "kai", "nina", "omar", "zoe", "raj"]
_LAST = ["nguyen", "patel", "garcia", "smith", "kim", "hassan", "lopez",
         "clark", "rossi", "haxhi", "meier", "oconnor"]
_FILE_SHARES = ["/finance/payroll", "/eng/src", "/hr/records", "/sales/crm",
                "/shared/reports", "/it/keys", "/legal/contracts"]


def _make_users(n: int, rng: random.Random) -> list[dict]:
    users: list[dict] = []
    seen: set[str] = set()
    while len(users) < n:
        name = f"{rng.choice(_FIRST)}.{rng.choice(_LAST)}"
        if name in seen:
            continue
        seen.add(name)
        dept = rng.choice(list(_DEPARTMENTS))
        users.append(
            {
                "user": name,
                "department": dept,
                "role": rng.choice(_DEPARTMENTS[dept]),
                "home_ip_prefix": f"10.{rng.randint(0, 4)}.{rng.randint(0, 255)}",
                "host": f"WS-{rng.randint(1000, 9999)}",
                "country": "US",
            }
        )
    return users


def _business_hour(rng: random.Random) -> int:
    # Most activity clusters in the 9-18 business window.
    return int(min(23, max(6, rng.gauss(13, 2.4))))


def _normal_day(u: dict, day: datetime, rng: random.Random) -> list[Event]:
    events: list[Event] = []
    n_logins = rng.randint(1, 3)
    ip = f"{u['home_ip_prefix']}.{rng.randint(2, 254)}"
    for _ in range(n_logins):
        hour = _business_hour(rng)
        ts = day.replace(hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59))
        events.append(_ev(u, ts, Action.LOGIN, ip=ip))
        # A cluster of file activity during the session.
        for _ in range(rng.randint(2, 9)):
            ats = ts + timedelta(minutes=rng.randint(1, 240))
            share = rng.choice(_FILE_SHARES)
            events.append(
                _ev(
                    u,
                    ats,
                    rng.choice([Action.FILE_ACCESS, Action.FILE_ACCESS, Action.EMAIL_SEND,
                                Action.FILE_DOWNLOAD]),
                    ip=ip,
                    resource=f"{share}/file_{rng.randint(1, 400)}.dat",
                    nbytes=int(abs(rng.gauss(2_000_000, 1_500_000))),
                )
            )
        events.append(_ev(u, ts + timedelta(hours=rng.randint(1, 8)), Action.LOGOUT, ip=ip))
    # Occasional benign failed login (typo).
    if rng.random() < 0.05:
        events.append(_ev(u, day.replace(hour=_business_hour(rng)), Action.FAILED_LOGIN,
                          ip=ip, success=False))
    return events


def _ev(u: dict, ts: datetime, action: Action, *, ip: str, resource: str = "",
        nbytes: int = 0, success: bool = True, country: str | None = None) -> Event:
    return Event(
        timestamp=ts,
        user=u["user"],
        action=action,
        host=u["host"],
        source_ip=ip,
        resource=resource,
        bytes=nbytes,
        success=success,
        department=u["department"],
        role=u["role"],
        country=country or u["country"],
    )


def generate_synthetic(
    *,
    users: int = 25,
    days: int = 30,
    seed: int = 1337,
    anomaly_users: int | None = None,
) -> tuple[list[Event], list[dict]]:
    """Return ``(events, planted_scenarios)``.

    ``planted_scenarios`` is a ground-truth list of dicts (user + scenario) that
    the CLI/tests can use to report detection recall.
    """
    rng = random.Random(seed)
    roster = _make_users(users, rng)
    start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days)

    events: list[Event] = []
    for u in roster:
        for d in range(days):
            day = start + timedelta(days=d)
            if day.weekday() >= 5 and rng.random() < 0.75:
                continue  # most people idle on weekends
            events.extend(_normal_day(u, day, rng))

    # --- plant anomalies on the most recent few days -------------------
    n_anom = anomaly_users if anomaly_users is not None else max(3, users // 6)
    victims = rng.sample(roster, min(n_anom, len(roster)))
    scenarios = ["data_exfiltration", "off_hours_access", "failed_login_burst",
                 "privilege_escalation", "impossible_travel"]
    planted: list[dict] = []
    recent = start + timedelta(days=days - 1)

    for i, u in enumerate(victims):
        scenario = scenarios[i % len(scenarios)]
        ip = f"{u['home_ip_prefix']}.{rng.randint(2, 254)}"
        planted.append({"user": u["user"], "scenario": scenario})

        if scenario == "data_exfiltration":
            ts = recent.replace(hour=21)
            for k in range(60):
                events.append(_ev(u, ts + timedelta(minutes=k), Action.FILE_DOWNLOAD, ip=ip,
                                  resource=f"/finance/payroll/dump_{k}.zip",
                                  nbytes=int(abs(rng.gauss(80_000_000, 20_000_000)))))
            events.append(_ev(u, ts + timedelta(hours=1), Action.DATA_TRANSFER, ip=ip,
                              resource="usb://external", nbytes=2_400_000_000))

        elif scenario == "off_hours_access":
            for k in range(14):
                ts = recent.replace(hour=(2 + k % 3), minute=rng.randint(0, 59))
                events.append(_ev(u, ts, Action.LOGIN, ip=ip))
                events.append(_ev(u, ts + timedelta(minutes=20), Action.FILE_ACCESS, ip=ip,
                                  resource="/hr/records/all.csv", nbytes=5_000_000))

        elif scenario == "failed_login_burst":
            ts = recent.replace(hour=3)
            for k in range(40):
                events.append(_ev(u, ts + timedelta(seconds=k * 20), Action.FAILED_LOGIN,
                                  ip="203.0.113.66", success=False))
            events.append(_ev(u, ts + timedelta(minutes=15), Action.LOGIN, ip="203.0.113.66"))

        elif scenario == "privilege_escalation":
            ts = recent.replace(hour=15)
            for k in range(8):
                events.append(_ev(u, ts + timedelta(minutes=k * 5), Action.PRIVILEGE_ESCALATION,
                                  ip=ip, resource="sudo:root"))
                events.append(_ev(u, ts + timedelta(minutes=k * 5 + 2), Action.CONFIG_CHANGE,
                                  ip=ip, resource="/etc/shadow"))

        elif scenario == "impossible_travel":
            base = recent.replace(hour=10)
            events.append(_ev(u, base, Action.LOGIN, ip=ip, country="US"))
            events.append(_ev(u, base + timedelta(hours=1), Action.LOGIN,
                              ip="185.220.101.5", country="RU"))
            events.append(_ev(u, base + timedelta(hours=1, minutes=5), Action.FILE_DOWNLOAD,
                              ip="185.220.101.5", country="RU",
                              resource="/legal/contracts/merger.pdf", nbytes=40_000_000))

    events.sort(key=lambda e: e.timestamp)
    return events, planted
