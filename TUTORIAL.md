# ATHENA ITD — The Complete Hands-On Tutorial

*From zero to a running insider-threat program: how the tool works inside, and
how to use every part of it. Every command below is real — type along.*

---

## Contents

1. [How ATHENA works under the hood](#1-how-athena-works-under-the-hood)
2. [Part 1 — Install and first run (15 min)](#2-part-1--install-and-first-run)
3. [Part 2 — The web console, hands-on](#3-part-2--the-web-console-hands-on)
4. [Part 3 — Bringing in your real logs](#4-part-3--bringing-in-your-real-logs)
5. [Part 4 — The triage workflow, end to end](#5-part-4--the-triage-workflow-end-to-end)
6. [Part 5 — Tuning detection for your environment](#6-part-5--tuning-detection-for-your-environment)
7. [Part 6 — Wiring up integrations](#7-part-6--wiring-up-integrations)
8. [Part 7 — Setting up your team (accounts & roles)](#8-part-7--setting-up-your-team)
9. [Part 8 — Automating with the API](#9-part-8--automating-with-the-api)
10. [Part 9 — Day-2 operations](#10-part-9--day-2-operations)
11. [Troubleshooting recipes](#11-troubleshooting-recipes)

---

## 1. How ATHENA works under the hood

Understanding the pipeline makes every screen and command obvious, so start here.

```
 raw logs ──▶ INGEST ──▶ EVENTS ──▶ FEATURES ──▶ 4 SCORING PILLARS ──▶ FUSION ──▶ ALERTS
 (csv/json/   normalize   SQLite     36 per       ML · rules ·          0–100     triage,
  authlog)    to Event    corpus     user-day     peer · sequence       score     cases,
                                                                                  response
```

**Step 1 — Ingest.** Every input format (CSV, JSON lines, Linux auth logs, the
CERT research dataset, the synthetic generator, the live stream) is normalized
into one `Event` shape: *who* (`user`), *did what* (`action`, one of 35
recognized values), *when* (`timestamp`), plus optional context (*where from*
— `host`, `source_ip`, `country`; *to what* — `resource`, `bytes`, `success`;
*who they are* — `department`, `role`). Events are stored in a local SQLite
corpus under `ATHENA_HOME`.

**Step 2 — Feature extraction.** For each user and each day, ATHENA computes a
36-dimensional feature vector: event volume, byte volumes by channel, action
mix, hour-of-day distribution, failed-login counts, distinct hosts/resources,
off-hours ratios, and so on. These vectors are what the ML sees.

**Step 3 — Four scoring pillars.** Each pillar looks at the same behavior from
a different angle, and each produces evidence, not just numbers:

| Pillar | Weight | What it does |
|---|---|---|
| **ML ensemble** | 0.30 | An Isolation-Forest ensemble scores each user-day vector against the whole organization's baseline. Catches *weird* even when no rule names it. |
| **Rule detectors** | 0.45 | 15 named detectors (exfil volume, USB, failed-login bursts, off-hours, impossible travel, mass delete, defense evasion, dormant accounts, …) each add weighted points with a human-readable reason. |
| **Peer deviation** | 0.15 | Compares the user to their department/role peer group; 2.5σ+ deviations score. Catches "normal for a sysadmin, alarming for a recruiter". |
| **Sequence analysis** | 0.10 | Scores rare action n-grams (e.g. `login → privilege_escalation → mass download → log_clear`) against observed sequence frequencies. |

**Step 4 — Fusion.** Pillar scores are combined with the weights above,
watchlist multipliers are applied (1–3× for users under scrutiny), and the
result is banded: **LOW** (0–49), **MEDIUM** (50–74), **HIGH** (75–87),
**CRITICAL** (88–100). Every alert keeps its full factor list — you always see
*why*.

**Step 5 — Alert lifecycle.** Each alert has a stable **dedup key**
(user + window), so re-running analysis updates alerts instead of duplicating
them, and your triage status survives. Alerts flow through statuses
(`new → triaged → investigating → escalated → contained → resolved`, or
`false_positive` / `suppressed`), can be linked into **cases**, annotated,
fed back with verdicts, and answered with **response actions**.

Everything else — the console, CLI and API — is a different window onto this
one pipeline.

---

## 2. Part 1 — Install and first run

### 2.1 Install

```bash
python3 -m venv athena && source athena/bin/activate
pip install athena_itd-3.2.0-py3-none-any.whl      # or your install source
athena version
```

You should see the version banner and three paths (data home, database,
reports). `athena init` creates them:

```bash
athena init
```

### 2.2 Generate a demo corpus with planted threats

```bash
athena generate --users 25 --days 30 --seed 1337
```

Expected output:

```
✓ Ingested ~5000 events for 25 users over 30 days.
Planted scenarios (ground truth): data_exfiltration, failed_login_burst, off_hours_access
```

The generator plants real attacker behavior in otherwise-normal traffic — your
job in the next steps is to watch ATHENA find it.

### 2.3 Train and analyze

```bash
athena train        # fits the ML ensemble, saves model.joblib
athena analyze      # scores every user
athena alerts       # the results, highest risk first
```

`alerts` prints a table like:

```
│ User       │ Dept/Role        │ Risk │ Level    │ Top factor                 │
│ aria.lopez │ it/helpdesk      │  100 │ CRITICAL │ Failed-login burst         │
│ leo.meier  │ engineering/sre  │  100 │ CRITICAL │ Possible data exfiltration │
│ mia.haxhi  │ finance/ap_clerk │   70 │ MEDIUM   │ Off-hours access           │
```

Those are the planted scenarios — caught.

### 2.4 Read a full finding

```bash
athena show leo.meier
```

You get the complete explanation: each factor with its point weight and
evidence sentence ("Moved 1.7 GB through exfiltration channels, 3.2σ above
their normal 40 MB; largest single transfer 1.2 GB"), the MITRE techniques
involved, and the recommended response actions. **This is the core promise of
the tool: no unexplained scores, ever.**

---

## 3. Part 2 — The web console, hands-on

### 3.1 First login

```bash
athena serve
```

Watch the log for one line — it appears only on the very first start:

```
bootstrapped admin 'admin' with a generated one-time password: XXXXXXXXXXXX
```

Open `http://127.0.0.1:8000`, sign in as `admin` with that password, then
immediately change it: **Settings → User Accounts → Reset pw** (or
`athena users passwd admin`).

> Prefer to choose the password yourself? Set it before first start:
> `ATHENA_ADMIN_PASSWORD='...' athena serve`

### 3.2 A guided lap around all 13 views

Do these in order — it's a natural investigation flow:

1. **Overview** — KPI tiles (events, users, flagged), the org threat level,
   30-day activity/byte trend charts, top risky users, model status. This is
   your morning screen.
2. **Users** — the directory. Type in the search box, filter by department or
   minimum risk level. Click a risky user: the **investigation drawer** opens
   with their raw event tail, hour-of-day histogram, action breakdown, 30-day
   charts, the alert explanation, notes, and a watchlist toggle.
3. **Alerts** — the triage queue. Try it now: set the top alert's status to
   `triaged`, assign it to yourself, then click **Classify** and record a
   verdict.
4. **Cases** — click **Create case** from an alert (or here): title, subject
   user, severity, owner. The alert links automatically.
5. **Live** — click **Start** to run the demo streamer and watch events scroll
   in with live scores; alerts fire in real time as thresholds are crossed.
   (In production, the live feed scores whatever you stream in.)
6. **Geo Intel** — country activity, source-IP reputation buckets
   (Tor / VPN / hosting / corporate), flagged anonymized origins; use the IP
   lookup box for any address.
7. **MITRE ATT&CK** — the coverage matrix, heat-mapped by how many live alerts
   hit each technique. Click a technique for detail.
8. **Compliance** — per-control coverage for GDPR, HIPAA, ISO 27001, SOC 2,
   PCI DSS, NIST 800-53, NIST CSF, with alert-evidence counts per control.
9. **Responses** — the action catalog and dispatch history (chapter 5 below).
10. **Data** — upload files, load datasets, generate demo data, reset, purge.
11. **Detections** — all 18 detectors with toggles and weight sliders, every
    threshold editable, per-detector precision from your verdicts.
12. **Audit** — every operator action: who, what, target, source IP, when.
13. **Settings** — organization, thresholds, integrations, security options,
    retention, **User Accounts**, **Active Sessions**, API key.

---

## 4. Part 3 — Bringing in your real logs

### 4.1 Reset the demo, prepare your CSV

```bash
athena reset          # clears events/alerts, keeps accounts & audit trail
```

Export activity from your sources into CSV with this header (only the first
three columns are mandatory):

```csv
timestamp,user,action,host,source_ip,resource,bytes,success,department,role,country
2026-02-01T09:02:11,alice.wong,login,WS-2201,10.0.1.15,sshd,0,true,finance,analyst,US
2026-02-01T09:14:03,alice.wong,file_download,WS-2201,10.0.1.15,/finance/q1.xlsx,2400000,true,finance,analyst,US
```

**Mapping tips from common sources:**

| Source | Map to |
|---|---|
| Windows Security 4624/4625 | `login` / `failed_login`, host, source IP |
| Windows 4663 (object access) | `file_access` / `file_delete`, resource, bytes |
| VPN concentrator logs | `vpn_connect`, source IP, country |
| O365/Google Workspace audit | `email_send`, `email_external`, `email_forward_rule`, `cloud_upload` |
| EDR USB telemetry | `usb_insert`, `usb_write`, bytes |
| Database audit logs | `db_query`, resource=table, bytes=rows×width |
| PAM/sudo logs | `privilege_escalation`, `permission_grant` |

The full action vocabulary (35 values) is in the user guide; unknown actions
become `other` (counted, but they feed fewer detectors).

### 4.2 Ingest, train, analyze

```bash
athena ingest export-january.csv           # appends; --reset replaces
athena ingest /var/log/auth.log            # ssh/sudo lines mix right in
athena train
athena analyze
```

Rules of thumb:

- **Volume**: 2+ weeks of history per user makes baselines meaningful; 30–90
  days is ideal.
- **Context columns pay off**: `bytes` unlocks exfil detection, `department`/
  `role` unlock peer analysis, `country` unlocks impossible travel.
- **Re-train** when the corpus grows substantially or the org changes shape;
  re-analyze whenever you ingest.
- Rows that fail to parse are skipped and counted — ingest never dies mid-file.

### 4.3 Alternative inputs

```bash
athena dataset load cert --path ~/datasets/r4.2   # CMU CERT research corpus
athena ingest audit.jsonl --format json           # JSON lines
```

Web equivalents: **Data → Upload** (any of the same formats) and
**Data → Datasets**. API equivalent: `POST /api/ingest` (multipart file).

---

## 5. Part 4 — The triage workflow, end to end

Here is a complete investigation, CLI-first with the console/API equivalents.

**1. See what fired:**

```bash
athena alerts --min-level HIGH
```

**2. Understand it:**

```bash
athena show carol.diaz
```

Read the factors. Is 1.8 GB to USB at midnight explainable? Check the raw
events in the console (Users → carol.diaz → event tail).

**3. Put her under scrutiny while you investigate:**

```bash
athena watchlist add carol.diaz --reason "case pending" --multiplier 1.5 --days 14
```

**4. Open a case:**

```bash
athena cases open --title "USB exfil — carol.diaz" --user carol.diaz --severity HIGH
```

In the console you'd click **Create case** on the alert — that also links the
alert and flips it to `investigating`. Add notes as you work (console: the
notes panel on the case; API: `POST /api/notes/case/{id}`).

**5. Record the verdict** — this is not paperwork; it trains the tool:

- `true_positive` — real malicious activity
- `benign_true_positive` — the behavior was real but authorized (sanctioned
  bulk export, migration, backup script)
- `false_positive` — the detector was wrong (also hides the alert)

Console: **Classify** on the alert. API:
`POST /api/alert/{key}/feedback {"verdict":"true_positive"}`.
Check the effect anytime with `athena feedback-stats` — per-detector precision.

**6. Respond if warranted:**

```bash
athena respond carol.diaz revoke_sessions --reason "case #3"
athena respond carol.diaz disable_downloads --reason "case #3"
```

All actions are **simulated by default** — logged, audited, forwarded, but not
executed. Real enforcement requires *both* `allow_enforced_response=true` in
the config *and* `--force` per call. Keep it simulated until your playbooks are
mature; the audit trail is identical either way.

**7. Close:** set the case to `closed_confirmed` or `closed_unsubstantiated`
with its verdict, and resolve the alert. HR/Legal handoffs have their own case
states (`pending_hr`, `pending_legal`) because insider cases rarely stay in
the SOC.

---

## 6. Part 5 — Tuning detection for your environment

Every org's "normal" differs. Tune in this order:

**1. Fix the obvious mismatches** (console → Detections, or `POST /api/config`):

- Night-shift workforce? Move `business_start_hour`/`business_end_hour`.
- Developers cloning repos all day? Lower the weight of `masscollect` or raise
  `mass_access_files` from 120.
- No USB ports in the fleet? Disable the `usb` detector entirely.

**2. Watch precision for two weeks.** Record verdicts diligently; then look at
**Detections → precision** (or `athena feedback-stats`). A detector at 20%
precision is costing you attention — reweight it (0.1×–3.0×) or raise its
threshold. A detector at 95% deserves more weight.

**3. Adjust the pillar mix if needed.** The fusion weights (`weight_ml` 0.30,
`weight_rules` 0.45, `weight_peer` 0.15, `weight_sequence` 0.10) are config
values. Trust rules more than ML? Shift 10 points. Just keep the sum at 1.0.

**4. Leave the bands alone at first.** `medium=50, high=75, critical=88` are
sane; move them only after you know your score distribution (Overview shows
the spread).

All changes are audited, take effect on the next analysis, and can be made by
API for config-as-code setups.

---

## 7. Part 6 — Wiring up integrations

Alerts at or above the forwarding level are pushed to **every** configured
destination on each analysis. Two examples end-to-end:

**Slack (2 minutes):**

```bash
export ATHENA_SLACK_WEBHOOK='https://hooks.slack.com/services/T…/B…/…'
athena analyze          # delivery status printed per destination
```

**Splunk HEC:**

```bash
export ATHENA_SPLUNK_HEC_URL='https://splunk.example.com:8088/services/collector'
export ATHENA_SPLUNK_HEC_TOKEN='…'
athena analyze
```

Same pattern for Elastic, Microsoft Sentinel, Teams, PagerDuty, SMTP e-mail, a
generic webhook, and syslog in **CEF**, **LEEF** or **RFC 5424** (for any SIEM
that speaks syslog — QRadar, ArcSight, Wazuh…). Console path: **Settings →
Integrations** (secrets are stored redacted and never echoed back).

You can also enrich the IP intelligence side: `athena intel my-feed.csv`
overlays your own `ip,category` reputation feed on the built-in
Tor/VPN/hosting classifier.

---

## 8. Part 7 — Setting up your team

```bash
athena users add dchen --role analyst      # prompts for a password
athena users add mrossi --role viewer
athena users list
```

Role model — least privilege by construction:

- **viewer** — sees everything, changes nothing. Managers, auditors.
- **analyst** — triages alerts, works cases, dispatches responses. The SOC.
- **admin** — config, detectors, accounts, data, training. One or two people.

Housekeeping that matters:

- **Sign-up**: `/signup` is open by default (creates viewers only, rate-limited
  per IP). For a closed deployment: `ATHENA_ALLOW_SIGNUP=false`.
- **Sessions**: view and revoke live sign-ins in **Settings → Active Sessions**
  or `athena users sessions` / `athena users revoke <user>`. Password resets and
  disables revoke sessions automatically.
- **You cannot lock yourself out**: the last active admin can't be deleted,
  demoted or deactivated — the platform refuses.
- **Automation identity**: give scripts the API key (`ATHENA_API_KEY`), never a
  human's password.
- Run `athena doctor` after setup — it grades the whole security posture.

---

## 9. Part 8 — Automating with the API

Everything the console does is a JSON endpoint. The canonical nightly job:

```bash
#!/usr/bin/env bash
# nightly-athena.sh — ingest today's export, rescore, pull criticals
set -euo pipefail
H='https://athena.internal:8443'
K="$ATHENA_API_KEY"

curl -fsS -H "X-API-Key: $K" -F "file=@/exports/activity-$(date +%F).csv" \
     "$H/api/ingest"
curl -fsS -H "X-API-Key: $K" -X POST "$H/api/analyze"
curl -fsS -H "X-API-Key: $K" "$H/api/alerts?min_level=CRITICAL" \
     | jq -r '.[] | "\(.user)\t\(.risk_score)\t\(.explanations[0].factor)"'
```

Other high-value endpoints for automation:

| Call | Use |
|---|---|
| `GET /api/export.csv` | Nightly alert dump into a data lake |
| `GET /api/summary` | KPI feed for a wallboard |
| `GET /api/metrics` | Prometheus scrape (latency, auth failures, throttles) |
| `POST /api/watchlist` | Auto-watchlist leavers from your HR system |
| `POST /api/respond` | SOAR playbook actions |
| `GET /api/audit` | Ship the operator audit trail to your SIEM |

The API key is an admin-level principal that skips CSRF — treat it like a root
credential. Browser sessions need the CSRF header on mutations; scripts using
the key don't.

---

## 10. Part 9 — Day-2 operations

**Backups** (safe while serving):

```bash
athena backup /backups/athena-$(date +%F).sqlite3
athena restore /backups/athena-2026-07-20.sqlite3   # asks for confirmation
```

**Retention** — set day limits for events/alerts/audit in **Settings →
Retention**, then either enable auto-purge or cron `athena purge`. This is
your GDPR/works-council story: monitoring data expires on schedule, and the
purge itself is audited.

**Monitoring** — scrape `GET /api/metrics` with Prometheus; alert on
`athena_http_unauthorized_total` and `athena_login_throttled_total` spikes
(someone probing) and `athena_http_5xx_total` (something broken). Wire
`/api/health` (liveness) and `/api/ready` (readiness) into your orchestrator —
the shipped Docker image already has a healthcheck.

**Health check ritual** — `athena doctor` before and after any change: it
verifies data-home writability, DB integrity, model state, auth posture
(admins exist, no default passwords, sign-up stance), the response-enforcement
gate, and retention.

**Upgrades** — back up, install the new wheel/image, run `athena doctor`,
re-train at the next convenient window. The database schema migrates in place.

---

## 11. Troubleshooting recipes

| Symptom | Cause → Fix |
|---|---|
| `401 authentication required` | No session/key → sign in, or send `X-API-Key` |
| `403 missing or invalid CSRF token` | Session mutation without header → send the `athena_csrf` cookie value as `X-CSRF-Token` |
| `403 role 'viewer' lacks 'analyst' permission` | RBAC working as intended → use a higher-role account |
| `429 too many attempts; retry in Ns` | Login throttle → wait; check `athena_login_throttled_total` for who's probing |
| Lost the admin password | On the host: `athena users passwd admin` (CLI has direct data access) |
| `no events; generate, ingest or load a dataset first` | Empty corpus → Part 3 |
| Ingest skipped many rows | Check the 3 required columns and ISO-ish timestamps; force `--format` if sniffing guessed wrong |
| All users score LOW on real data | Corpus too short (need 2+ weeks) or missing context columns (`bytes`, `department`) |
| One detector dominates every alert | Reweight or raise its threshold (Part 5), and record verdicts so precision data accumulates |
| Console unreachable from another machine | `--host 0.0.0.0`, open the firewall port, front with TLS |
| HSTS/cookies behaving oddly behind a proxy | Run with `--proxy-headers` so `X-Forwarded-Proto` is honored |

---

*© 2026 Petro Plaku. ATHENA ITD is proprietary software — see LICENSE.md.
Deeper reference material: the User Guide in `docs/`, plus README, SECURITY,
DEPLOYMENT and ARCHITECTURE.*
