# Changelog

All notable changes to ATHENA ITD are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versioning is SemVer.

## [3.2.0] — 2026-07-23

Final hardening & operations release — the publish-ready cut.

### Changed
- **License:** the project is now distributed under a proprietary
  all-rights-reserved license (see LICENSE.md); any use beyond local evaluation
  requires the author's written permission. Bundled Chart.js remains MIT.

### Added
- **Active session management:** `GET /api/sessions` lists live sign-ins (with the
  caller's own flagged) and `DELETE /api/sessions/{id}` revokes one instantly; a
  **Settings → Active Sessions** console panel and `athena users sessions` /
  `athena users revoke <user>` CLI. Only the opaque token *hash* is ever exposed.
- **Self-service sign-up:** a `/signup` page and `POST /api/signup` let users register
  and are signed straight in. Registration **always** creates a non-admin account
  (`security.signup_role`, default `viewer`; `admin` is refused), enforces the 8-char
  password policy, and can be turned off with `ATHENA_ALLOW_SIGNUP=false`. The login
  page links to it.
- **Auth on by default:** `security.auth_enabled` now defaults to `true`. On first start
  with no accounts, an admin is seeded from `ATHENA_ADMIN_USER` / `ATHENA_ADMIN_PASSWORD`;
  when no password is supplied, a **random one-time password** is generated and printed
  once in the server log — there is no shared built-in default credential.
- **Sign-up throttling:** `POST /api/signup` is capped per source IP (10/minute,
  `429` + `Retry-After`) so an open registration page can't be used for bulk
  account creation.
- **Last-admin lockout guard:** demoting or deactivating the only remaining active
  admin via `PATCH /api/accounts/{user}` is refused (mirrors the existing delete guard).
- **Rate limiting:** per-caller fixed-window request limiter on authenticated
  `/api/*` traffic (`security.rate_limit_per_minute`, `429` + `Retry-After` when
  exceeded), surfaced as `athena_http_rate_limited_total`.
- **CORS:** optional cross-origin allow-list (`security.cors_origins`) for
  first-party SPAs on another host; off by default.
- **`/api/version`** endpoint (name, version, Python, platform, auth state) for
  clients, dashboards and support.
- **`athena doctor`** — deployment self-check (data-home writability, SQLite
  integrity, model presence, auth posture / active-admin, response-enforcement
  gate, retention) with PASS/WARN/FAIL output and a non-zero exit on failure.
- **`athena backup` / `athena restore`** — consistent SQLite online-backup
  snapshot and guarded restore (drops stale WAL sidecars).
- Community/repo files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue & PR
  templates; CI now runs `ruff` lint alongside the test matrix.

### Fixed
- **Users view "Load failed / `risk_score is undefined`":** the account-management
  routes collided with the risk-scored users endpoint on `GET /api/users`. Account
  management moved to **`/api/accounts`**; `/api/users` again returns risk data and
  is viewer-readable.
- **Syslog CEF/LEEF format** was case-sensitive, silently emitting JSON for `CEF`/
  `LEEF` (uppercase). Format matching is now case-insensitive.

### Changed
- Curated `ruff` ruleset; the tree is lint-clean. Docs (README/SECURITY/
  DEPLOYMENT/`.env.example`/compose) updated for RBAC + the bootstrap-admin flow.
- Verified end-to-end: log-file ingest (auth.log/CSV/JSONL) and SIEM/SOAR fan-out
  (webhook/Slack/Splunk HEC/Elastic/PagerDuty/syslog) against live receivers.
- Test suite grown to **66** tests (added SIEM/SOAR, session, and sign-up coverage).

## [3.1.0] — 2026-07-22

Production-hardening, access-control and deployment release.

### Added
- **Authentication & RBAC:** optional sign-in (`ATHENA_AUTH_ENABLED=true`) with
  individual accounts and three roles (viewer · analyst · admin) enforced on every
  route. Passwords hashed with `scrypt`; server-side sessions store only a SHA-256
  hash and carry a configurable TTL; CSRF double-submit protection on cookie
  mutations; login throttling with escalating lockout. Audit rows are attributed to
  the signed-in user. First admin bootstraps from `ATHENA_ADMIN_USER` /
  `ATHENA_ADMIN_PASSWORD`. The `X-API-Key` remains for machine-to-machine automation.
- **User management:** `athena users` CLI (list/add/passwd/role/disable/remove/
  enable-auth) and a **Settings → User Accounts** console panel; last-admin
  protection; password reset / role change / disable all revoke active sessions.
- **Observability:** `/api/ready` readiness probe and `/api/metrics` Prometheus
  endpoint (request/5xx/unauthorized counters, event/alert/stream gauges, per-route
  latency). `/api/health` clarified as a DB-free liveness probe.
- **Security headers** on every response (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`, and `Strict-Transport-Security` when served
  over TLS / behind a TLS proxy).
- **TLS + proxy support** in `athena serve`: `--tls-cert`, `--tls-key`,
  `--proxy-headers`, `--workers`, `--access-log`; warns on plain HTTP off-loopback.
- **Container deployment:** multi-stage non-root `Dockerfile` with healthcheck,
  reference `docker-compose.yml` (app + Caddy auto-HTTPS), `deploy/Caddyfile`,
  `.dockerignore`, `.env.example`.
- **Docs:** `DEPLOYMENT.md`, `SECURITY.md`, `CHANGELOG.md`; README badges and a
  production-deployment section.
- Request access logging via `athena_itd.web` logger.

### Notes
- Accounts are local to ATHENA; **SSO/OIDC/SAML** is the next milestone (tracked in
  the README roadmap / SECURITY.md). Front with an authenticating proxy if you need
  centralized identity today.

## [3.0.0] — 2026-07-21

Rebrand and console overhaul (previously "Aegis UBA").

### Changed
- **Renamed** to **ATHENA ITD** end-to-end: package `athena_itd`, CLI `athena` /
  `athena-itd`, env vars `ATHENA_*` (with `AEGIS_HOME` honoured as a deprecated
  alias), data home `athena-itd`, DB `athena.sqlite3`, SIEM payload identifiers,
  report filenames, and PyInstaller artifacts. New Athena/owl brand + theme.
- **Web console redesign** — "midnight bronze" cyber theme, full-height responsive
  layout, collapsible sidebar rail, compact density mode, command palette (Ctrl+K),
  keyboard shortcuts, clickable KPIs, trend range selector.

### Added
- Purpose-built reset: `POST /api/reset {full}` and `athena reset --full`
  (clears corpus; `full` also drops cases + watchlist; audit always preserved).
- Regression test that compiles/renders the console template.

## [2.x] — earlier

Trainable IsolationForest ensemble with joblib persistence, real-time SSE engine,
CMU CERT dataset adapter, enterprise REST API, and the multi-view SOC console.
