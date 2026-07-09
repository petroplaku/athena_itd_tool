# 🛡️ Aegis UBA — AI-Driven Insider Threat & User Behavior Analytics

Aegis UBA is a cross-platform (**Linux · Windows · macOS**) platform that detects
**compromised accounts and malicious insiders** by learning each user's normal
behavior and flagging deviations. It ships with both a **professional CLI** and a
**web dashboard GUI**, backed by a machine-learning + rules detection engine that
produces **explainable, SOC-ready risk scores**.

> Traditional monitoring misses the subtle behavioral changes that precede data
> theft, sabotage and privilege abuse. Aegis continuously baselines user activity
> (logins, file access, data transfer, privilege use, geography) and surfaces the
> handful of users who genuinely warrant an analyst's attention — with a clear
> explanation of *why*.

---

## ✨ Features

| Capability | What it does |
|---|---|
| **Behavioral baselines** | Per-user profiles of normal logins, file access, data volume, hosts, IPs and geography. |
| **AI anomaly detection** | Unsupervised **Isolation Forest** over population-wide behavior vectors, robust-scaled. |
| **Rule detectors** | Data exfiltration, off-hours access, failed-login bursts, privilege escalation, impossible travel / new geography. |
| **Risk scoring** | Weighted 0–100 score with `LOW / MEDIUM / HIGH / CRITICAL` bands, prioritized for SOC triage. |
| **Explainability** | Every alert lists the contributing factors + human-readable detail for HR, compliance and SOC. |
| **Automated response** | Simulated (safe-by-default) lock / revoke-session / MFA / disable-download actions, with an audit trail and SIEM/SOAR **webhook** emitter. |
| **Reporting** | Self-contained **HTML** and **JSON** reports. |
| **Web dashboard GUI** | FastAPI dashboard with charts, a risk table, user drill-down and one-click response. |
| **Cross-platform CLI** | Single `aegis` command; ships as a Python package or a standalone binary per OS. |
| **Flexible ingest** | Synthetic generator, generic CSV/JSON/JSONL, and Linux `auth.log`. Source-agnostic schema. |

---

## 🚀 Quick start

```bash
# 1. Install (Python 3.10+)
pip install .

# 2. Initialize local state (creates an OS-appropriate data directory)
aegis init

# 3a. Try it instantly with realistic synthetic data (with planted threats)
aegis generate --users 30 --days 30

# 3b. …or ingest your own data
aegis ingest examples/sample_events.csv       # CSV / JSON / JSONL
aegis ingest /var/log/auth.log                # Linux auth log

# 4. Detect + score every user (and simulate response for HIGH/CRITICAL)
aegis analyze --respond

# 5. Investigate
aegis alerts                 # ranked table
aegis show carol.diaz        # full explainable finding for one user
aegis report                 # HTML + JSON reports

# 6. Launch the web dashboard GUI (opens your browser)
aegis serve --open
```

`make demo` runs steps 2–5 in one shot; `make serve` launches the dashboard.

---

## 🖥️ The web dashboard (GUI)

`aegis serve --open` (or `aegis gui`) starts a local FastAPI server and opens a
dark, SOC-style dashboard at <http://127.0.0.1:8000>:

- KPI cards (events, users, risk-band counts)
- Activity-volume trend + risk-distribution charts
- A **users-by-risk** table with inline risk bars and severity badges
- Click any user for a **drill-down**: factors, recommended actions (one-click,
  simulated), and a tail of their recent raw activity

Everything the GUI shows is also available as JSON under `/api/*`, so the same
backend can feed a SIEM or a future native client.

---

## 🧠 How detection works

```
 events ──► feature engineering ──► ┌───────────────────────────┐
 (per user/day vectors)            │  Isolation Forest (ML)     │──┐
                                   └───────────────────────────┘  │  weighted
                                   ┌───────────────────────────┐  ├─► risk 0–100 ─► band ─► alert
                                   │  rule detectors + baseline │──┘   + explanations
                                   └───────────────────────────┘      + recommended response
```

1. **Feature engineering** (`features.py`) summarizes each user's day into a
   16-dimensional behavior vector (login counts, failed-login ratio, bytes
   moved, distinct hosts/IPs/countries, after-hours ratio, privilege use, …).
2. **ML** (`detect.py`) trains an Isolation Forest across the whole population and
   converts each vector's anomaly score to a 0–1 severity.
3. **Rules** compare the user against **their own baseline** (e.g. bytes moved in
   σ over their normal) so a naturally data-heavy role isn't perpetually flagged.
4. **Scoring** blends ML + rule contributions into a 0–100 score, bands it, and
   records the top contributing factors as the alert's explanation.

The analyzer evaluates a short **monitoring window** per user and reports their
worst day, so a benign end-of-day spill-over can't mask a real anomaly.

---

## ⌨️ CLI reference

| Command | Description |
|---|---|
| `aegis init` | Initialize config + database. |
| `aegis generate` | Generate synthetic activity with planted threat scenarios. |
| `aegis ingest <file>` | Ingest CSV / JSON / `auth.log` (auto-detected). |
| `aegis analyze [--respond] [--force]` | Run ML + rules, score users, store alerts. |
| `aegis alerts [--min-level]` | List alerts, highest risk first. |
| `aegis show <user>` | Full explainable finding for a user. |
| `aegis respond <user> --action …` | Dispatch a single (simulated) response. |
| `aegis responses` | Show the response audit trail. |
| `aegis report [--out DIR]` | Generate HTML + JSON reports. |
| `aegis serve [--open] / aegis gui` | Launch the web dashboard. |
| `aegis reset` | Delete all local data. |
| `aegis version` | Version + data-path info. |

Run `aegis --help` or `aegis <command> --help` for full options.

---

## 🔌 Integrations & configuration

State lives in an OS-appropriate directory (override with `AEGIS_HOME`):

- **Linux** `~/.local/share/aegis-uba`
- **macOS** `~/Library/Application Support/aegis-uba`
- **Windows** `%LOCALAPPDATA%\aegis-uba`

`config.json` there controls detection thresholds, the organization name, and a
`webhook_url`. Set the webhook to forward every response action as JSON to
Splunk / Microsoft Sentinel / ELK / a generic SOAR endpoint.

### Ingest schema

CSV/JSON fields are matched case-insensitively with common aliases. The useful
columns are: `timestamp, user, action, host, source_ip, resource, bytes,
success, department, role, country`. Only `timestamp` and `user` are required.
`action` is normalized to a known verb (`login`, `failed_login`, `file_download`,
`data_transfer`, `privilege_escalation`, `config_change`, …).

---

## 🛡️ Safety model

Automated-response actions are **simulated by default**: they are written to the
audit trail and optionally forwarded to your webhook, but they do **not** modify
real accounts. This makes Aegis safe to run in demos, evaluations and labs. Real
enforcement is gated behind an explicit `--force` flag so it can only be enabled
deliberately, per your organization's policy.

---

## 📦 Standalone binaries (no Python required)

Build a single self-contained executable for the current OS:

```bash
# Linux / macOS
bash packaging/build.sh          # -> dist/aegis  + release/aegis-<os>-<arch>.tar.gz

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File packaging\build.ps1   # -> dist\aegis.exe
```

The included **GitHub Actions** workflow (`.github/workflows/build.yml`) runs the
test suite on Linux/macOS/Windows × Python 3.10/3.12 and publishes a binary
artifact for each OS on every push.

---

## 🧪 Development

```bash
make dev      # editable install with dev extras
make test     # pytest
make lint     # ruff
```

---

## 🗂️ Project layout

```
src/aegis_uba/
├── cli.py              # Typer CLI (Linux/Windows/macOS)
├── config.py           # cross-platform paths + tunable thresholds
├── models.py           # Event / Alert / Explanation (pydantic)
├── storage.py          # SQLite persistence (stdlib)
├── features.py         # per-user/day feature engineering
├── detect.py           # Isolation Forest + rules + risk scoring
├── response.py         # simulated response + webhook emitter
├── ingest/             # synthetic generator + CSV/JSON/auth.log loaders
├── report/             # HTML + JSON report generation (+ template)
└── web/                # FastAPI dashboard (server + template)
packaging/              # PyInstaller spec + build scripts (build.sh / build.ps1)
examples/               # sample CSV + auth.log
tests/                  # pytest suite (detection recall, FP rate, IO, reports)
```

---

## 📄 License

MIT — see [LICENSE](LICENSE).
