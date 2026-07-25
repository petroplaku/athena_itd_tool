"""SIEM/SOAR fan-out tests: sink selection, payload shape, syslog CEF/LEEF."""
from __future__ import annotations

from datetime import datetime, timezone

from athena_itd import response
from athena_itd.config import Config
from athena_itd.models import Alert, Explanation, RiskLevel


def _alert(level=RiskLevel.CRITICAL, score=87.0):
    return Alert(
        user="m.reyes", risk_score=score, risk_level=level,
        summary="142GB egress to personal cloud",
        detectors=["exfiltration_volume", "off_hours"],
        mitre_techniques=["T1567", "T1029"],
        explanations=[Explanation(factor="Exfiltration", detail="142GB", weight=0.9)],
        recommended_actions=["revoke_sessions"],
        window_start=datetime(2026, 7, 20, tzinfo=timezone.utc),
        window_end=datetime(2026, 7, 21, tzinfo=timezone.utc),
    )


def _capture_http(monkeypatch):
    calls = []

    class _Resp:
        status_code = 200

    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append({"url": url, "json": json, "headers": headers or {}})
        return _Resp()

    monkeypatch.setattr(response.httpx, "post", fake_post)
    return calls


def test_forward_hits_every_configured_http_sink(monkeypatch):
    calls = _capture_http(monkeypatch)
    cfg = Config()
    i = cfg.integrations
    i.webhook_url = "https://soar.example/hook"
    i.slack_webhook = "https://hooks.slack/x"
    i.splunk_hec_url = "https://splunk:8088"
    i.splunk_hec_token = "tok"
    i.elastic_url = "https://es:9200"
    i.elastic_api_key = "k"
    i.pagerduty_routing_key = "pd"
    i.min_forward_level = "LOW"

    res = response.forward_alert(cfg, _alert())
    urls = " ".join(c["url"] for c in calls)
    assert "delivered:200" in res["webhook"]
    assert "soar.example/hook" in urls
    assert "services/collector/event" in urls          # splunk HEC path
    assert "/_doc" in urls                              # elastic index doc
    assert any("events.pagerduty.com" in c["url"] for c in calls)
    # splunk carries its auth scheme
    splunk = next(c for c in calls if "collector" in c["url"])
    assert splunk["headers"].get("Authorization", "").startswith("Splunk ")
    # webhook payload integrity
    hook = next(c for c in calls if c["url"].endswith("/hook"))
    assert hook["json"]["user"] == "m.reyes"
    assert hook["json"]["mitre"] == ["T1567", "T1029"]


def test_forward_respects_min_level(monkeypatch):
    _capture_http(monkeypatch)
    cfg = Config()
    cfg.integrations.webhook_url = "https://soar.example/hook"
    cfg.integrations.min_forward_level = "CRITICAL"
    # a HIGH alert is below the CRITICAL threshold → skipped
    res = response.forward_alert(cfg, _alert(level=RiskLevel.HIGH, score=70))
    assert "skipped" in res


def test_slack_and_teams_payload_shape():
    payload = {"type": "alert", "user": "m.reyes", "risk_score": 87.0,
               "risk_level": "CRITICAL", "summary": "egress"}
    assert "text" in response._slack_message(payload)
    card = response._teams_card(payload)
    assert card.get("@type") == "MessageCard" or "text" in card or "sections" in card


def test_syslog_cef_and_leef_are_case_insensitive(monkeypatch):
    sent = []

    class _Sock:
        def __init__(self, *a): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def settimeout(self, *a): pass
        def sendto(self, data, addr): sent.append(data.decode())

    monkeypatch.setattr(response.socket, "socket", _Sock)
    payload = {"type": "alert", "user": "m.reyes", "risk_level": "CRITICAL",
               "detectors": ["exfil"], "mitre": ["T1567"], "summary": "egress"}

    response._send_syslog("127.0.0.1", 514, "CEF", payload)      # uppercase
    assert sent[-1].startswith("CEF:0|ATHENA|ITD|")
    response._send_syslog("127.0.0.1", 514, "LEEF", payload)
    assert sent[-1].startswith("LEEF:2.0|ATHENA|ITD|")
