# Contributing to ATHENA ITD

Thanks for your interest in improving ATHENA ITD. This guide covers how to set up a
development environment, the quality bar for changes, and how to report issues.

## Development setup

```bash
git clone <your-fork-url> athena-itd
cd athena-itd
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Verify the toolchain:

```bash
pytest -q          # full suite (51 tests)
ruff check .       # lint
python -m athena_itd version
```

## Making a change

1. **Open an issue first** for anything non-trivial so we can agree on the approach.
2. Create a branch off `main`: `git checkout -b feature/short-description`.
3. Keep changes focused. Match the surrounding code style — the codebase favors small,
   readable functions, explicit names, and no unnecessary dependencies.
4. **Add or update tests** for any behavior change. New detectors, endpoints, and
   auth/RBAC paths must have coverage.
5. Run `pytest -q` and `ruff check .` — both must pass.
6. Update docs (`README.md`, `SECURITY.md`, `DEPLOYMENT.md`, `CHANGELOG.md`) when
   behavior, configuration, or security posture changes.

## Pull requests

- Fill in the PR template.
- Reference the issue it closes (`Closes #123`).
- Describe the security impact of the change, if any.
- CI (tests on Linux/macOS/Windows × Python 3.10/3.12, plus lint) must be green.

## Security-sensitive changes

ATHENA handles sensitive workforce-monitoring data. Take extra care with:

- Authentication, sessions, CSRF, and RBAC (`auth.py`, the web middleware).
- Anything touching secrets, the audit log, or data retention/purge.
- Response enforcement (the two-key `allow_enforced_response` + `force` gate).

Do **not** weaken these without explicit discussion. Never commit real secrets,
credentials, or customer data — not even in tests or fixtures.

## Reporting vulnerabilities

Please do **not** open a public issue for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for the private reporting process.

## License

This project is proprietary (see [LICENSE.md](LICENSE.md)). By contributing,
you agree that your contribution is provided under the terms of Section 6 of
LICENSE.md — the author may use, modify, relicense and distribute it as part
of the project.
