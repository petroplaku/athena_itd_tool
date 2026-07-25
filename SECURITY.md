# Security Model & Hardening

ATHENA ITD is a monitoring tool that handles sensitive workforce activity data.
This document states plainly what protections exist today, what does **not**, and
how to deploy it responsibly.

## Authentication & authorization

Access control is **on by default** (`ATHENA_AUTH_ENABLED=true`); set it to `false`
only for an isolated local trial. When on, the web console and every `/api/*` route
(except the unauthenticated probes `/api/health`, `/api/ready`, `/api/metrics`,
`/api/version`) require an authenticated principal.

> **First admin.** On first start with no accounts, ATHENA seeds an admin from
> `ATHENA_ADMIN_USER` / `ATHENA_ADMIN_PASSWORD`. If the password variable is unset, a
> **random one-time password is generated and printed once in the server log** — there
> is deliberately no shared built-in default credential. Sign in and rotate it with
> `athena users passwd admin`. `athena doctor` flags a weak/default posture.

**Self-service sign-up.** With `security.allow_signup` (default on), visitors can
register at `/signup`. Self-registration **always** creates a non-admin account —
role `security.signup_role` (default `viewer`), and any attempt to configure it as
`admin` is silently downgraded to `viewer`. New sign-ups still pass the 8-character
password policy. Disable it with `ATHENA_ALLOW_SIGNUP=false` for a closed deployment.

**Individual accounts + RBAC.** Users sign in with a username and password and are
issued a **server-side session**. Three roles gate every route:

| Role | Can do |
|---|---|
| **viewer** | Read dashboards, alerts, cases, reports (all `GET`s). |
| **analyst** | Everything a viewer can, **plus** triage mutations — alert status, notes, case work, responses. |
| **admin** | Everything, **plus** configuration, model training, data ingest/reset/purge, and user management. |

- **Passwords** are hashed with `scrypt` (n=2¹⁴, r=8, p=1) in a self-describing
  `scrypt$…` format; verification is constant-time. A minimum length is enforced.
- **Sessions** live in the database; only their SHA-256 hash is stored, they carry a
  configurable TTL (`session_ttl_minutes`, default 480), and are revoked on logout,
  password reset, role change, or account disable — surviving restarts and multiple
  workers. The session cookie is `HttpOnly`/`SameSite=Lax` (and `Secure` over HTTPS).
- **CSRF**: state-changing requests made with a session cookie require a matching
  double-submit token (`X-CSRF-Token` header vs. `athena_csrf` cookie).
- **Login throttling**: repeated failures lock an account/IP with escalating backoff.
- **Audit attribution**: the `actor` on every administrative audit row is the
  authenticated signed-in user, not a self-asserted label.
- **Automation**: set `ATHENA_API_KEY` (`openssl rand -hex 32`) for machine-to-machine
  access via the `X-API-Key` header — an admin-level principal that skips CSRF, meant
  for SIEM/SOAR. Guard it like any admin credential.
- Bootstrap the first admin non-interactively with `ATHENA_ADMIN_USER` /
  `ATHENA_ADMIN_PASSWORD`, or manage accounts with `athena users …` / the console's
  **Settings → User Accounts** panel.

**Current limit — local accounts only.** There is **no SSO/OIDC/SAML** yet; accounts
are managed inside ATHENA. For centralized identity, you can additionally front it
with an authenticating reverse proxy (e.g. oauth2-proxy). SSO is the top roadmap item.

## Transport

- Serve over **TLS in any shared deployment.** Either terminate at a reverse proxy
  (recommended — see `DEPLOYMENT.md`) or pass `--tls-cert/--tls-key`.
- The app sets `Strict-Transport-Security` only when it sees a real HTTPS
  connection or `X-Forwarded-Proto: https` (use `--proxy-headers` behind a proxy).
- Default response headers on every request: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`
  locking down geolocation/mic/camera.
- Do **not** bind `0.0.0.0` on plain HTTP outside a trusted network; the CLI warns
  when you do.

## Secrets

- All integration secrets (SIEM tokens, SMTP password, API key) can be supplied
  via `ATHENA_*` environment variables and never written to disk.
- If set through the console instead, they are stored in `config.json` under
  `ATHENA_HOME`. Protect that directory (`chmod 700`), or prefer env/secret-mounts.
- Secrets are redacted from logs; the audit log records *that* an action happened,
  not secret values.

## Data protection

- Storage is local SQLite under `ATHENA_HOME`. There is **no application-level
  encryption at rest** — rely on full-disk/volume encryption (LUKS, EBS/KMS).
- A **retention policy** (`Settings → Retention`, or `athena purge`) prunes events,
  alerts and audit rows past their configured age.
- The **audit trail is append-only from the app's side** and is preserved even by
  a full data reset, so administrative actions remain accountable.

## Automated response safety

- Response actions are **simulated by default.** Real enforcement requires *both*
  `allow_enforced_response=true` in config **and** an explicit per-call
  `force=true` — a deliberate two-key gate. Every dispatch is audited and can be
  forwarded to your SIEM/SOAR.

## Operational hardening checklist

- [ ] **Set the first admin's credentials deliberately** — `ATHENA_ADMIN_USER` /
      `ATHENA_ADMIN_PASSWORD` at bootstrap, or capture the generated one-time
      password from the first-start log and rotate it (`athena users passwd admin`).
- [ ] Auth stays enabled (`ATHENA_AUTH_ENABLED=true`, the default); create per-analyst
      accounts with least-privilege roles — avoid sharing one admin login.
- [ ] Decide on sign-up: keep `allow_signup` on only if open registration is intended;
      otherwise `ATHENA_ALLOW_SIGNUP=false`. Confirm `signup_role` is `viewer`.
- [ ] Issue a distinct `ATHENA_API_KEY` only if automation needs it.
- [ ] TLS everywhere (proxy or `--tls-*`); never plain HTTP off-host.
- [ ] Run as the non-root `athena` user (the container already does).
- [ ] Restrict network exposure (security group / firewall / private subnet).
- [ ] Front with an authenticating proxy if you need centralized SSO until it lands natively.
- [ ] Full-disk/volume encryption for `ATHENA_HOME`.
- [ ] Scrape `/api/metrics`; alert on `athena_http_unauthorized_total` spikes.
- [ ] Regular backups of `ATHENA_HOME` (see `DEPLOYMENT.md §5`).
- [ ] Set a retention policy that matches your legal obligations.

## Legal / privacy note

Employee-behavior monitoring is regulated differently across jurisdictions and may
require notice, a lawful basis, works-council consultation, or DPIA/consent (e.g.
GDPR in the EU). ATHENA provides the technical controls (retention, audit, access
gating, compliance mapping) but **your organization is responsible** for the legal
basis and governance of deploying it.

## Reporting a vulnerability

Email **pplaku799@gmail.com**. Please do not open a
public issue for security reports.
