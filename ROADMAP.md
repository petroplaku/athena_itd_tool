# ATHENA ITD — Product Roadmap

ATHENA ITD is deliberately a **focused insider-threat analytics engine**, not a
do-everything security suite. This roadmap is honest about that: it maps the full
enterprise insider-risk problem space (IAM, UEBA, SOAR, DLP, EDR, XDR, threat
intel, AI copilot) onto what ATHENA **ships today**, what is **next**, and what is
**out of scope** unless the project grows a team around it. Hollow checkbox
features help nobody; everything listed as shipped is implemented and tested.

## Shipped in v3.2.0

**Analytics core (UEBA)**
- 18 explainable detectors: ML behavioral anomaly (Isolation-Forest ensemble,
  36 features), data-exfiltration volume, removable-media exfiltration, personal
  cloud upload, suspicious email egress, failed-login burst, off-hours access,
  privilege escalation & abuse, impossible travel / new geography, anonymised
  network origin (Tor/VPN/hosting), mass collection, mass deletion, defense
  evasion, lateral movement, dormant-account activation, sensitive-data access
  spike, peer-group deviation, rare action sequences.
- Behavioral baselines per user, peer-group comparison, watchlist risk
  multipliers, dynamic 0–100 risk scoring with per-factor explanations.
- Analyst feedback loop (true/false-positive verdicts, per-detector precision).

**Detection management**
- Per-detector enable/disable and weighting, tunable thresholds, MITRE ATT&CK
  mapping for every detector, compliance mapping to GDPR, HIPAA, ISO 27001,
  SOC 2, PCI DSS, NIST 800-53 and NIST CSF.

**SOC workflow**
- Alert triage (status, assignee, dedup), case management with linked alerts,
  notes, timelines; watchlist; full operator audit trail; live event stream
  (SSE) with on-the-fly scoring.
- 13-view web console (overview, users, alerts, cases, live, geo intel, MITRE,
  compliance, detections, responses, data, audit, settings).

**Response (SOAR-lite)**
- 8 response actions (lock account, revoke sessions, require MFA, disable
  downloads, isolate endpoint, revoke privileges, notify SOC/manager) —
  simulated by default, real enforcement behind an explicit double gate.
- Alert forwarding: Splunk HEC, Elastic, Microsoft Sentinel, generic webhook,
  Slack, Teams, PagerDuty, SMTP email, syslog (CEF / LEEF / RFC 5424).

**Platform & security**
- Accounts + RBAC (viewer/analyst/admin), scrypt password hashing, DB-backed
  revocable sessions, CSRF protection, login throttling, per-caller rate
  limiting, generated first-admin password, API-key automation principal,
  security headers, TLS support, Prometheus metrics, health/readiness probes,
  retention policies with purge, Docker (non-root, multi-stage), `athena doctor`
  deployment self-check, full REST API, CSV/JSON/HTML reporting.

## Next (v3.3 – v4.x) — planned, in priority order

1. **Sigma rule import** — compile a practical subset of Sigma rules into
   native threshold/sequence detectors, so existing community content runs on
   ATHENA event streams.
2. **Scheduled reporting** — daily/weekly executive and SOC digests (HTML/PDF)
   delivered over the existing SMTP/webhook integrations.
3. **IOC allow/deny lists** — operator-managed IP/domain/hash lists feeding the
   geo/anon-IP detectors; STIX 2.1 import for indicator bundles.
4. **Honey users & canary credentials** — decoy accounts whose *any* activity
   raises a critical alert; the highest signal-to-noise insider tripwire that a
   log-analytics engine can offer without an endpoint agent.
5. **Device & department risk rollups** — aggregate risk scoring beyond the
   per-user score.
6. **SSO/OIDC login** — delegate console authentication to an identity
   provider; local accounts remain as break-glass.
7. **Alert SLA tracking & escalation** — time-to-triage targets with
   escalation notifications.
8. **Model registry** — versioned trained models with drift metrics and
   one-click rollback.

## Out of scope (without a dedicated team)

These belong to adjacent product categories that require agents, collectors, or
vendor API estates of their own. ATHENA integrates with such systems (ingest +
forwarding) rather than pretending to replace them:

- **Endpoint agents / EDR** (process trees, DLL injection, credential-dump
  detection, clipboard/screenshot capture) — ingest your EDR's events instead.
- **Network sensors** (NetFlow/Zeek/Suricata capture, DNS-tunnel detection at
  wire level) — ingest sensor logs.
- **Cloud-vendor connector fleets** (native AWS/Azure/GCP/M365/GitHub/Slack
  pollers) — export those audit logs to ATHENA's CSV/JSONL ingest.
- **Email/DLP content inspection** (attachment OCR, document fingerprinting),
  **database activity monitoring**, **physical badge systems**, **AI-usage
  proxies** — same pattern: bring the logs, ATHENA scores the behavior.
- **Multi-tenant SaaS control plane, microservices/Kubernetes-scale HA** —
  ATHENA is a single-node engine by design; front it with your proxy and HA
  tooling.

Contributions toward any roadmap item are welcome — see CONTRIBUTING.md.
