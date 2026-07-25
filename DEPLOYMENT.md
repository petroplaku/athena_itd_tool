# Deploying ATHENA ITD

This guide covers running ATHENA ITD as a persistent service. For a laptop trial,
`athena serve --open` is enough; everything below is for shared/production use.

---

## 1. Container (recommended)

The repo ships a multi-stage `Dockerfile` (non-root, slim runtime) and a reference
`docker-compose.yml` that puts the app behind **Caddy** for automatic HTTPS.

```bash
# 1. Set a strong API key and your org name
cp .env.example .env        # then edit, or:
echo "ATHENA_API_KEY=$(openssl rand -hex 32)" >> .env
echo "ATHENA_ORG=Your Organization" >> .env

# 2. Point deploy/Caddyfile at your real hostname, then:
docker compose up -d --build

# 3. Verify
curl -fsSL https://athena.example.com/api/health
```

State (SQLite DB, trained model, generated reports) persists in the `athena-data`
named volume. Back it up by snapshotting that volume (see §5).

### Single container, no proxy
```bash
docker build -t athena-itd:3.2.0 .
docker run -d --name athena \
  -e ATHENA_AUTH_ENABLED=true -e ATHENA_API_KEY=$(openssl rand -hex 32) \
  -v athena-data:/data -p 8000:8000 athena-itd:3.2.0
```
Put your own TLS terminator (ALB, nginx, Caddy, Traefik) in front — do **not**
expose plain HTTP beyond localhost.

---

## 2. Bare metal / VM (systemd)

```bash
python3 -m venv /opt/athena/venv
/opt/athena/venv/bin/pip install athena-itd      # or: pip install -e . from source
```

`/etc/systemd/system/athena.service`:
```ini
[Unit]
Description=ATHENA ITD Insider Threat Detection
After=network.target

[Service]
User=athena
Environment=ATHENA_HOME=/var/lib/athena
Environment=ATHENA_AUTH_ENABLED=true
Environment=ATHENA_API_KEY=%I_set_a_real_secret_here%
ExecStart=/opt/athena/venv/bin/athena serve \
  --host 0.0.0.0 --port 8000 --workers 4 --proxy-headers --access-log
Restart=on-failure
# hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/athena
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```
```bash
systemctl daemon-reload && systemctl enable --now athena
```
Front it with nginx/Caddy for TLS (pass `X-Forwarded-Proto: https`; the app emits
HSTS only when it sees that header or a real TLS connection).

### Direct TLS (no proxy)
```bash
athena serve --host 0.0.0.0 --port 8443 \
  --tls-cert /etc/ssl/athena/fullchain.pem \
  --tls-key  /etc/ssl/athena/privkey.pem
```

---

## 3. Configuration & secrets

All settings can come from **environment variables** (highest precedence), so no
secret needs to touch disk. Canonical prefix is `ATHENA_` (`AEGIS_HOME` is still
honoured as a deprecated alias for a migration window).

| Variable | Purpose |
|---|---|
| `ATHENA_HOME` | Data directory (DB, model, reports). Default: OS data dir. |
| `ATHENA_AUTH_ENABLED` | Require sign-in (accounts + RBAC). **On by default**; `false` only for a local trial. |
| `ATHENA_ADMIN_USER` / `ATHENA_ADMIN_PASSWORD` | Bootstrap the first admin. If the password is unset, a **random one-time password** is generated and printed once in the first-start log — capture it and rotate after sign-in. |
| `ATHENA_ALLOW_SIGNUP` | `false` to disable self-service registration at `/signup` (default on; always creates non-admin accounts). |
| `ATHENA_SIGNUP_ROLE` | Role granted to self-registered users (default `viewer`; `admin` is refused). |
| `ATHENA_API_KEY` | Machine-to-machine key (admin-level, `X-API-Key`) for SIEM/SOAR automation. Generate with `openssl rand -hex 32`. |
| `ATHENA_ORG` | Organization name shown in the console. |
| `ATHENA_SPLUNK_HEC_URL` / `ATHENA_SPLUNK_HEC_TOKEN` | Splunk HEC forwarding. |
| `ATHENA_ELASTIC_URL` / `ATHENA_ELASTIC_API_KEY` | Elastic forwarding. |
| `ATHENA_SLACK_WEBHOOK` / `ATHENA_TEAMS_WEBHOOK` | Chat notifications. |
| `ATHENA_SYSLOG_HOST` / `ATHENA_SYSLOG_PORT` | CEF/LEEF syslog forwarding. |
| `ATHENA_SMTP_HOST` / `ATHENA_SMTP_USER` / `ATHENA_SMTP_PASSWORD` | Email alerts. |
| `ATHENA_PAGERDUTY_KEY` | PagerDuty Events API routing key. |

See `athena --help` and the in-app **Settings** view for the rest.

---

## 4. Health, readiness & metrics

| Endpoint | Auth | Use |
|---|---|---|
| `GET /api/health` | none | Liveness (never touches the DB). |
| `GET /api/ready` | none | Readiness (verifies the datastore; 503 if not). |
| `GET /api/metrics` | none | Prometheus text exposition. |

Prometheus scrape:
```yaml
scrape_configs:
  - job_name: athena-itd
    metrics_path: /api/metrics
    static_configs: [{ targets: ["athena:8000"] }]
```
Exposed series include `athena_http_requests_total`, `athena_http_5xx_total`,
`athena_http_unauthorized_total`, `athena_events`, `athena_alerts`,
`athena_stream_running`, and per-route `athena_route_latency_ms`.

---

## 5. Backup & restore

State is a single directory (`ATHENA_HOME`). The built-in commands take a
consistent online snapshot (safe while the server runs, even under SQLite WAL):

```bash
# Backup (writes <home>/backups/athena-<timestamp>.sqlite3 by default)
athena backup                       # or: athena backup --out /backups/athena.sqlite3
cp "$ATHENA_HOME/model.joblib" /backups/     # model is a separate artifact

# Restore (overwrites the current DB; stop the server first)
systemctl stop athena
athena restore /backups/athena-2026-07-23.sqlite3 --yes
cp /backups/model.joblib "$ATHENA_HOME/"
systemctl start athena
```

Run `athena doctor` after any restore or config change for a fast health check
(datastore integrity, model presence, auth posture, retention).
Docker volume snapshot: `docker run --rm -v athena-data:/data -v "$PWD":/out
alpine tar czf /out/athena-data.tgz -C /data .`

---

## 6. Data ingestion

- **Files / batch:** `athena ingest <file.csv|json|jsonl|auth.log>` or the
  console's *Data & Model → Ingest* uploader (auto-maps columns).
- **Benchmark datasets:** `athena dataset load cert --path /data/cert/r4.2`.
- **Synthetic (demo/tuning):** `athena generate --users 30 --days 30`.

> The bundled real-time engine is a **simulator** for demos and load-testing the
> scoring path. Wiring live telemetry (syslog/Kafka receiver, IdP/EDR/CASB pull
> connectors) is the main integration task for a production rollout — see the
> roadmap in `README.md`.

---

## 7. Upgrades

```bash
git pull && docker compose up -d --build      # container
# or
pip install -U athena-itd && systemctl restart athena   # venv
```
The SQLite schema is created/upgraded idempotently on start. Back up first (§5).
