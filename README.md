# 🛡️ Aegis UBA — AI-Driven Insider Threat & User Behavior Analytics

Aegis UBA is a cross-platform (**Linux · Windows · macOS**) platform that detects
**compromised accounts and malicious insiders** by learning each user's normal
behavior and flagging deviations in **real time**. It ships with a professional
**CLI** and a modern **web SOC console**, backed by a trainable machine-learning
+ rules engine that produces **explainable, prioritized risk scores** — and can
run continuously against live telemetry or public benchmark datasets.

> Traditional monitoring misses the subtle behavioral changes that precede data
> theft, sabotage and privilege abuse. Aegis continuously baselines user activity
> (logins, file access, data transfer, privilege use, geography), scores every
> user against a trained model, and surfaces the handful who warrant an analyst's
> attention — each with a clear explanation of *why* and a recommended response.

---

## ✨ What's inside

| Capability | Detail |
|---|---|
| **Trainable ML model** | Isolation Forest over 16-feature user-day vectors, **fit → persisted (joblib) → reused** to score live/streaming data. |
| **Rule detectors + baselines** | Data exfiltration, off-hours access, failed-login bursts, privilege escalation, impossible travel — each scored against the user's own learned baseline. |
| **Explainable risk scoring** | Weighted 0–100 score, `LOW/MEDIUM/HIGH/CRITICAL` bands, per-factor explanations for SOC / HR / compliance. |
| **⚡ Real-time monitoring** | Background engine ingests live telemetry, re-scores the recent window continuously, and raises threat notifications over Server-Sent-Events. |
| **📊 Web SOC console** | 8-view cybersecurity dashboard: Overview, Live Monitor, Users, Alerts, Response Log, Data & Model, Detection Config, Settings. |
| **🎓 Real datasets** | First-class adapter for the **CMU CERT Insider Threat** benchmark (logon/device/email/file/http/LDAP) + a synthetic enterprise generator. |
| **Flexible ingest** | CSV / JSON / JSONL / Linux `auth.log`, drag-and-drop upload, or dataset loaders — all normalized to one schema. |
| **Automated response** | Simulated (safe-by-default) lock / revoke-session / MFA / disable-download, audit trail, and SIEM/SOAR **webhook**. |
| **Tunable detection** | Thresholds, sensitivity and contamination editable from the GUI or `config.json`. |
| **Reporting & export** | Standalone HTML + JSON reports and a JSON alert export API. |
| **Ships anywhere** | Python package, `python -m aegis_uba`, or a standalone per-OS binary (PyInstaller + CI). |

---

## 🚀 Quick start

```bash
pip install .
aegis init

# Option A — instant demo with planted insider scenarios
aegis generate --users 30 --days 30
aegis analyze --respond

# Option B — train on a real dataset (CMU CERT) and score it
aegis dataset load cert --path /path/to/cert/r4.2   # or: examples/cert_sample
aegis train                                          # persists the model
aegis analyze

# Investigate & report
aegis alerts
aegis show <user>
aegis report

# Real-time: terminal live monitor …
aegis monitor --eps 8 --inject-prob 0.05

# … or the full web SOC console (opens your browser)
aegis serve --open        # then use the "Live Monitor" view
```

`make demo` runs the batch flow; `make serve` launches the console.

---

## 📊 The web SOC console

`aegis serve --open` (or `aegis gui`) serves a dark, modern cybersecurity
dashboard at <http://127.0.0.1:8000> with a sidebar of eight views:

| View | What you can do |
|---|---|
| **Overview** | KPI cards, activity-trend & risk-distribution charts, model status, top critical users, global threat level. |
| **⚡ Live Monitor** | Start/stop the real-time engine (tunable EPS + injection rate), watch a **live event stream** and **threat notifications** as they're detected, with pop toasts for HIGH/CRITICAL. |
| **Users** | Searchable, department- and level-filterable risk-ranked workforce; click any user to investigate. |
| **Alerts** | Explainable alert cards with contributing factors and **one-click (simulated) response** actions. |
| **Response Log** | Full audit trail of every dispatched action (simulated / enforced). |
| **Data & Model** | Generate synthetic data, **upload logs**, **load the CERT dataset**, inspect the corpus, and **train / retrain** the model. |
| **Detection Config** | Catalogue of active detectors with weights, and editable thresholds / sensitivity. |
| **Settings** | Organization name, SIEM/SOAR webhook, deployment paths, JSON export, API docs. |

Every view is backed by the JSON API under `/api/*` (see `/docs`), so the same
backend can drive a SIEM integration or automation.

---

## ⚡ Real-time monitoring

The live engine (`aegis_uba/stream.py`) simulates a continuous stream of
enterprise telemetry (the kind a SIEM/EDR forwards), persists it, and every few
seconds re-scores the recent window against the **trained model**, publishing
raw events and detected findings to subscribers:

```
collector ─► normalize ─► store ─┬─► live feed (SSE)        ─► dashboard / CLI
                                 └─► incremental scoring    ─► threat alerts + toasts
```

In production you replace the `_produce()` simulator with a real collector
(tailing logs / consuming a bus); everything downstream — scoring, alerting,
response — is identical. Drive it from the **Live Monitor** view, the
`aegis monitor` CLI, or the `/api/stream/*` endpoints.

---

## 🎓 Datasets & model training

Aegis trains on realistic data so live assessment is meaningful.

- **CMU CERT Insider Threat Test Dataset** — the standard benchmark. Download a
  release (r4.2 / r5.2 / r6.2) from
  [kilthub.cmu.edu](https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247)
  (DOI `10.1184/R1/12841247`), extract it, and:
  ```bash
  aegis dataset inspect /path/to/cert/r4.2      # see which CSVs are present
  aegis dataset load cert --path /path/to/cert/r4.2 --limit 200000
  aegis train && aegis analyze
  ```
  The adapter maps `logon/device/email/file/http` + `LDAP` into the Aegis schema,
  with department/role enrichment and external-recipient egress flags. A tiny
  CERT-format sample is bundled at `examples/cert_sample/` (with a planted
  insider) so you can try the whole flow offline.

- **Synthetic enterprise** — `aegis dataset load synthetic` (or `aegis generate`)
  produces deterministic org telemetry with five planted insider scenarios;
  ideal for demos, tests and threshold calibration.

`aegis train` fits the Isolation Forest, learns per-user baselines, and persists
the model (`model.joblib`). The live engine and `aegis analyze` reuse it.

---

## 🧠 How detection works

```
 events ─► feature engineering ─► ┌───────────────────────────┐
 (per user/day vectors)          │  Isolation Forest (trained)│──┐  weighted
                                 └───────────────────────────┘  ├─► risk 0–100 ─► band ─► alert
                                 ┌───────────────────────────┐  │   + explanations
                                 │ rule detectors + baselines │──┘   + recommended response
                                 └───────────────────────────┘
```

Rules compare each user against **their own learned baseline** (e.g. bytes moved
in σ over their normal), so a data-heavy role isn't perpetually flagged. The
analyzer evaluates a short **monitoring window** per user and reports their worst
day, so a benign end-of-day spill-over can't mask a real anomaly.

**Validated:** on the synthetic benchmark the engine catches **100 % of planted
insider scenarios** with **zero HIGH+ false positives** across seeds, and the
CERT sample's planted insider surfaces as HIGH.

---

## ⌨️ CLI reference

| Command | Description |
|---|---|
| `aegis init` | Initialize config + database. |
| `aegis generate` | Synthetic activity with planted threats. |
| `aegis dataset list / info / inspect / load` | Manage & load real datasets (CERT, synthetic). |
| `aegis ingest <file>` | Ingest CSV / JSON / `auth.log`. |
| `aegis train` | Train & persist the anomaly model for live scoring. |
| `aegis analyze [--respond]` | Score users, store explainable alerts. |
| `aegis monitor` | Real-time terminal monitor (live feed + rolling alerts). |
| `aegis alerts / show <user>` | Review findings. |
| `aegis respond <user> --action …` | Dispatch a (simulated) response. |
| `aegis report` | HTML + JSON reports. |
| `aegis serve [--open] / aegis gui` | Launch the web SOC console. |
| `aegis reset` | Clear all local data. |

Run `aegis --help` or `aegis <cmd> --help` for options.

---

## 🔌 Configuration & integrations

State lives in an OS-appropriate directory (override with `AEGIS_HOME`):
Linux `~/.local/share/aegis-uba`, macOS `~/Library/Application Support/aegis-uba`,
Windows `%LOCALAPPDATA%\aegis-uba`. `config.json` holds detection thresholds,
organization name and a `webhook_url` (forwards every response action as JSON to
Splunk / Sentinel / ELK / a generic SOAR endpoint). All of it is editable from
the GUI's **Detection Config** and **Settings** views.

### Ingest schema
Fields are matched case-insensitively with common aliases:
`timestamp, user, action, host, source_ip, resource, bytes, success,
department, role, country` (only `timestamp` + `user` required).

---

## 🛡️ Safety model

Response actions are **simulated by default** — recorded to the audit trail and
optionally forwarded to your webhook, but they do **not** modify real accounts.
Safe for demos, evaluations and labs. Real enforcement is gated behind an
explicit `--force` flag, per your organization's policy.

---

## 📦 Standalone binaries (no Python required)

```bash
bash packaging/build.sh                                         # Linux / macOS
powershell -ExecutionPolicy Bypass -File packaging\build.ps1    # Windows
```

The bundled **GitHub Actions** workflow tests on Linux/macOS/Windows ×
Python 3.10/3.12 and publishes a per-OS binary artifact on every push.

---

## 🧪 Development

```bash
make dev && make test && make lint
```

## 🗂️ Layout

```
src/aegis_uba/
├── cli.py            # Typer CLI (train, dataset, monitor, serve, …)
├── detect.py         # trainable Isolation Forest + rules + scoring + persistence
├── stream.py         # real-time engine (SSE feed, incremental scoring)
├── datasets/         # CERT adapter + dataset registry
├── ingest/           # synthetic generator + CSV/JSON/auth.log loaders
├── features.py       # per-user/day feature engineering
├── response.py       # simulated response + webhook
├── report/           # HTML + JSON reporting
├── storage.py        # SQLite persistence
└── web/              # FastAPI + SOC-console SPA (server + dashboard.html)
packaging/            # PyInstaller spec + build scripts
examples/             # sample CSV, auth.log, and a CERT-format sample
tests/                # pytest suite
```

## 📄 License — MIT (see [LICENSE](LICENSE)).
