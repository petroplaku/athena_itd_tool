"""Automated-response layer.

By design the built-in actions are **simulated** (dry-run): they are recorded to
the audit trail and, if configured, forwarded to a SIEM/SOAR webhook — but they
do not touch real accounts. This keeps the platform safe to run in a demo,
portfolio or evaluation setting while preserving the exact integration surface a
production deployment would use. Real enforcement can be added behind an
explicit ``--force`` path per organization policy.
"""
from __future__ import annotations

from enum import Enum

import httpx

from aegis_uba.config import Config
from aegis_uba.models import Alert
from aegis_uba.storage import Store


class ResponseAction(str, Enum):
    LOCK_ACCOUNT = "lock_account"
    REVOKE_SESSIONS = "revoke_sessions"
    REQUIRE_MFA = "require_mfa"
    DISABLE_DOWNLOADS = "disable_downloads"
    NOTIFY_SOC = "notify_soc"


def dispatch(
    store: Store,
    config: Config,
    user: str,
    action: ResponseAction,
    *,
    force: bool = False,
    reason: str = "",
) -> dict:
    """Execute (simulate) a response action and record it in the audit trail."""
    mode = "ENFORCED" if force else "SIMULATED"
    detail = reason or f"{action.value} triggered for {user}"
    store.log_response(user, action.value, mode, detail)

    payload = {
        "tool": "aegis-uba",
        "user": user,
        "action": action.value,
        "mode": mode,
        "reason": detail,
        "organization": config.organization,
    }
    webhook_status = _emit_webhook(config, payload)

    return {"user": user, "action": action.value, "mode": mode,
            "detail": detail, "webhook": webhook_status}


def auto_respond(store: Store, config: Config, alert: Alert, *, force: bool = False) -> list[dict]:
    """Map an alert's recommended actions onto response primitives and dispatch them."""
    mapping = {
        "Revoke active sessions": ResponseAction.REVOKE_SESSIONS,
        "Lock account": ResponseAction.LOCK_ACCOUNT,
        "Enforce MFA challenge": ResponseAction.REQUIRE_MFA,
        "Require step-up MFA for off-hours sessions": ResponseAction.REQUIRE_MFA,
        "Challenge session with MFA": ResponseAction.REQUIRE_MFA,
        "Block outbound file transfers / USB": ResponseAction.DISABLE_DOWNLOADS,
    }
    results: list[dict] = []
    dispatched: set[ResponseAction] = set()
    for rec in alert.recommended_actions:
        act = mapping.get(rec)
        if act and act not in dispatched:
            dispatched.add(act)
            results.append(dispatch(store, config, alert.user, act, force=force,
                                    reason=f"[{alert.risk_level.value}] {rec}"))
    if not results:
        results.append(dispatch(store, config, alert.user, ResponseAction.NOTIFY_SOC,
                                force=force, reason=f"[{alert.risk_level.value}] monitor"))
    return results


def _emit_webhook(config: Config, payload: dict) -> str:
    if not config.webhook_url:
        return "no-webhook-configured"
    try:
        resp = httpx.post(config.webhook_url, json=payload, timeout=5.0)
        return f"delivered:{resp.status_code}"
    except httpx.HTTPError as exc:  # pragma: no cover - network dependent
        return f"error:{type(exc).__name__}"
