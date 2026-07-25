"""Automated-response and SIEM/SOAR forwarding layer.

By design the built-in actions are **simulated** (dry-run): they are recorded to
the audit trail and forwarded to every configured integration — but they do not
touch real accounts. This keeps the platform safe to run in a demo, portfolio or
evaluation setting while preserving the exact integration surface a production
deployment would use. Real enforcement requires both ``force=True`` *and*
``security.allow_enforced_response`` in the config — a deliberate two-key
arrangement.

Forwarding fan-out (each activates only when configured, and failures in one
sink never block another):

* generic **webhook** (JSON POST — the SOAR entry point)
* **Slack** / **Microsoft Teams** incoming webhooks
* **Splunk** HTTP Event Collector
* **Elasticsearch** index API
* **PagerDuty** Events v2
* **syslog** (CEF over UDP) for any traditional SIEM
* **SMTP** email to the SOC distribution list
"""
from __future__ import annotations

import json
import smtplib
import socket
from datetime import datetime, timezone
from email.message import EmailMessage
from enum import Enum

import httpx

from athena_itd.config import Config
from athena_itd.models import Alert, RiskLevel
from athena_itd.storage import Store

_TIMEOUT = 5.0


class ResponseAction(str, Enum):
    LOCK_ACCOUNT = "lock_account"
    REVOKE_SESSIONS = "revoke_sessions"
    REQUIRE_MFA = "require_mfa"
    DISABLE_DOWNLOADS = "disable_downloads"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    REVOKE_PRIVILEGES = "revoke_privileges"
    NOTIFY_SOC = "notify_soc"
    NOTIFY_MANAGER = "notify_manager"


#: Analyst-facing description of what each action would do when enforced.
ACTION_CATALOG: dict[ResponseAction, str] = {
    ResponseAction.LOCK_ACCOUNT: "Disable interactive sign-in for the account.",
    ResponseAction.REVOKE_SESSIONS: "Invalidate every active session and refresh token.",
    ResponseAction.REQUIRE_MFA: "Force a step-up MFA challenge on next access.",
    ResponseAction.DISABLE_DOWNLOADS: "Block file downloads, USB writes and sync clients.",
    ResponseAction.ISOLATE_ENDPOINT: "Network-quarantine the user's endpoint via EDR.",
    ResponseAction.REVOKE_PRIVILEGES: "Strip elevated roles/groups pending review.",
    ResponseAction.NOTIFY_SOC: "Page the on-call SOC analyst with full context.",
    ResponseAction.NOTIFY_MANAGER: "Send a verification request to the user's manager.",
}


def dispatch(
    store: Store,
    config: Config,
    user: str,
    action: ResponseAction,
    *,
    force: bool = False,
    reason: str = "",
    alert: Alert | None = None,
) -> dict:
    """Execute (simulate) a response action, audit it and fan out to integrations."""
    enforced = force and config.security.allow_enforced_response
    mode = "ENFORCED" if enforced else "SIMULATED"
    detail = reason or f"{action.value} triggered for {user}"
    store.log_response(user, action.value, mode, detail)

    payload = {
        "tool": "athena-itd",
        "type": "response",
        "user": user,
        "action": action.value,
        "action_description": ACTION_CATALOG.get(action, ""),
        "mode": mode,
        "reason": detail,
        "organization": config.organization,
        "risk_score": alert.risk_score if alert else None,
        "risk_level": alert.risk_level.value if alert else None,
        "mitre": alert.mitre_techniques if alert else [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    deliveries = forward(config, payload,
                         level=alert.risk_level if alert else RiskLevel.HIGH)
    return {"user": user, "action": action.value, "mode": mode,
            "detail": detail, "deliveries": deliveries,
            # Back-compat key consumed by older tests/clients.
            "webhook": deliveries.get("webhook", "no-webhook-configured")}


def auto_respond(store: Store, config: Config, alert: Alert, *,
                 force: bool = False) -> list[dict]:
    """Map an alert's recommended actions onto response primitives and dispatch them."""
    mapping = {
        "Revoke active sessions": ResponseAction.REVOKE_SESSIONS,
        "Lock account": ResponseAction.LOCK_ACCOUNT,
        "Enforce MFA challenge": ResponseAction.REQUIRE_MFA,
        "Require step-up MFA for off-hours sessions": ResponseAction.REQUIRE_MFA,
        "Challenge session with MFA": ResponseAction.REQUIRE_MFA,
        "Block outbound file transfers / USB": ResponseAction.DISABLE_DOWNLOADS,
        "Isolate endpoint": ResponseAction.ISOLATE_ENDPOINT,
        "Revoke elevated privileges": ResponseAction.REVOKE_PRIVILEGES,
        "Disable account pending owner verification": ResponseAction.LOCK_ACCOUNT,
        "Verify travel with the user/manager": ResponseAction.NOTIFY_MANAGER,
    }
    results: list[dict] = []
    dispatched: set[ResponseAction] = set()
    for rec in alert.recommended_actions:
        act = mapping.get(rec)
        if act and act not in dispatched:
            dispatched.add(act)
            results.append(dispatch(store, config, alert.user, act, force=force,
                                    reason=f"[{alert.risk_level.value}] {rec}",
                                    alert=alert))
    if not results:
        results.append(dispatch(store, config, alert.user, ResponseAction.NOTIFY_SOC,
                                force=force,
                                reason=f"[{alert.risk_level.value}] monitor",
                                alert=alert))
    return results


# ---------------------------------------------------------------------------
# Alert forwarding (SIEM / notification fan-out)
# ---------------------------------------------------------------------------
def forward_alert(config: Config, alert: Alert) -> dict[str, str]:
    """Forward a finding to every configured sink, honouring min_forward_level."""
    if alert.risk_level.rank < config.min_forward_rank:
        return {"skipped": f"below {config.integrations.min_forward_level}"}
    payload = {
        "tool": "athena-itd",
        "type": "alert",
        "organization": config.organization,
        "user": alert.user,
        "risk_score": alert.risk_score,
        "risk_level": alert.risk_level.value,
        "summary": alert.summary,
        "detectors": alert.detectors,
        "mitre": alert.mitre_techniques,
        "explanations": [
            {"factor": e.factor, "detail": e.detail, "weight": e.weight}
            for e in alert.explanations
        ],
        "recommended_actions": alert.recommended_actions,
        "window_start": alert.window_start.isoformat(),
        "window_end": alert.window_end.isoformat(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return forward(config, payload, level=alert.risk_level)


def forward(config: Config, payload: dict,
            level: RiskLevel = RiskLevel.HIGH) -> dict[str, str]:
    """Deliver ``payload`` to each configured sink; per-sink status, never raises."""
    integ = config.integrations
    results: dict[str, str] = {}

    if integ.webhook_url:
        results["webhook"] = _post_json(integ.webhook_url, payload)
    if integ.slack_webhook:
        results["slack"] = _post_json(integ.slack_webhook, _slack_message(payload))
    if integ.teams_webhook:
        results["teams"] = _post_json(integ.teams_webhook, _teams_card(payload))
    if integ.splunk_hec_url and integ.splunk_hec_token:
        results["splunk"] = _post_json(
            integ.splunk_hec_url.rstrip("/") + "/services/collector/event",
            {"event": payload, "sourcetype": "athena:itd"},
            headers={"Authorization": f"Splunk {integ.splunk_hec_token}"})
    if integ.elastic_url and integ.elastic_api_key:
        results["elastic"] = _post_json(
            f"{integ.elastic_url.rstrip('/')}/{integ.elastic_index}/_doc",
            payload,
            headers={"Authorization": f"ApiKey {integ.elastic_api_key}"})
    if integ.pagerduty_routing_key and level.rank >= RiskLevel.HIGH.rank:
        results["pagerduty"] = _post_json(
            "https://events.pagerduty.com/v2/enqueue",
            {
                "routing_key": integ.pagerduty_routing_key,
                "event_action": "trigger",
                "payload": {
                    "summary": payload.get("summary")
                               or f"ATHENA {payload.get('type')}: {payload.get('user')}",
                    "source": "athena-itd",
                    "severity": "critical" if level == RiskLevel.CRITICAL else "error",
                    "custom_details": payload,
                },
            })
    if integ.syslog_host:
        results["syslog"] = _send_syslog(integ.syslog_host, integ.syslog_port,
                                         integ.syslog_format, payload)
    if integ.smtp_host and integ.smtp_to:
        results["email"] = _send_email(config, payload)
    if not results:
        results["webhook"] = "no-webhook-configured"
    return results


# --- sink implementations ---------------------------------------------------
def _post_json(url: str, body: dict, headers: dict | None = None) -> str:
    try:
        resp = httpx.post(url, json=body, headers=headers or {}, timeout=_TIMEOUT)
        return f"delivered:{resp.status_code}"
    except httpx.HTTPError as exc:  # pragma: no cover - network dependent
        return f"error:{type(exc).__name__}"


def _slack_message(payload: dict) -> dict:
    level = payload.get("risk_level") or "INFO"
    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(level, "🔵")
    lines = [f"{emoji} *ATHENA ITD {payload.get('type', 'event')}* — "
             f"*{payload.get('user', '?')}* [{level}]"]
    if payload.get("summary"):
        lines.append(payload["summary"])
    if payload.get("reason"):
        lines.append(payload["reason"])
    for e in (payload.get("explanations") or [])[:3]:
        lines.append(f"• {e['factor']}: {e['detail']}")
    return {"text": "\n".join(lines)}


def _teams_card(payload: dict) -> dict:
    level = payload.get("risk_level") or "INFO"
    color = {"CRITICAL": "d13438", "HIGH": "ff8c00", "MEDIUM": "ffd700"}.get(level, "0078d4")
    facts = [{"name": "User", "value": str(payload.get("user", "?"))},
             {"name": "Level", "value": level}]
    if payload.get("risk_score") is not None:
        facts.append({"name": "Score", "value": str(payload["risk_score"])})
    if payload.get("mitre"):
        facts.append({"name": "ATT&CK", "value": ", ".join(payload["mitre"][:6])})
    return {
        "@type": "MessageCard", "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": payload.get("summary") or f"ATHENA ITD {payload.get('type')}",
        "sections": [{
            "activityTitle": f"ATHENA ITD — {payload.get('type', 'event')}",
            "facts": facts,
            "text": payload.get("summary") or payload.get("reason") or "",
        }],
    }


_CEF_SEVERITY = {"LOW": 3, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}


def _send_syslog(host: str, port: int, fmt: str, payload: dict) -> str:
    level = payload.get("risk_level") or "MEDIUM"
    user = payload.get("user", "unknown")
    fmt = (fmt or "cef").strip().lower()          # accept CEF/LEEF/Cef etc.
    if fmt == "cef":
        ext = (f"suser={user} cs1={','.join(payload.get('detectors', []) or [])} "
               f"cs1Label=detectors cs2={','.join(payload.get('mitre', []) or [])} "
               f"cs2Label=mitre msg={payload.get('summary') or payload.get('reason') or ''}")
        msg = (f"CEF:0|ATHENA|ITD|3.0|{payload.get('type', 'alert')}|"
               f"Insider threat {payload.get('type', 'alert')}|"
               f"{_CEF_SEVERITY.get(level, 5)}|{ext}")
    elif fmt == "leef":
        msg = (f"LEEF:2.0|ATHENA|ITD|3.0|{payload.get('type', 'alert')}|"
               f"usrName={user}\tseverity={_CEF_SEVERITY.get(level, 5)}\t"
               f"msg={payload.get('summary') or ''}")
    else:  # rfc5424-ish JSON
        msg = f"<134>1 {datetime.now(timezone.utc).isoformat()} athena-itd - - - {json.dumps(payload)}"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(_TIMEOUT)
            sock.sendto(msg.encode("utf-8", errors="replace"), (host, port))
        return "delivered:udp"
    except OSError as exc:  # pragma: no cover - network dependent
        return f"error:{type(exc).__name__}"


def _send_email(config: Config, payload: dict) -> str:
    integ = config.integrations
    msg = EmailMessage()
    level = payload.get("risk_level") or "INFO"
    msg["Subject"] = (f"[ATHENA ITD][{level}] {payload.get('type', 'event')} — "
                      f"{payload.get('user', '?')}")
    msg["From"] = integ.smtp_from
    msg["To"] = ", ".join(integ.smtp_to)
    body = [payload.get("summary") or payload.get("reason") or "", ""]
    for e in (payload.get("explanations") or []):
        body.append(f"- {e['factor']} (+{e['weight']}): {e['detail']}")
    if payload.get("recommended_actions"):
        body += ["", "Recommended actions:"]
        body += [f"* {a}" for a in payload["recommended_actions"]]
    msg.set_content("\n".join(body))
    try:
        with smtplib.SMTP(integ.smtp_host, integ.smtp_port, timeout=_TIMEOUT) as smtp:
            if integ.smtp_starttls:
                smtp.starttls()
            if integ.smtp_user and integ.smtp_password:
                smtp.login(integ.smtp_user, integ.smtp_password)
            smtp.send_message(msg)
        return "delivered:smtp"
    except (OSError, smtplib.SMTPException) as exc:  # pragma: no cover
        return f"error:{type(exc).__name__}"
