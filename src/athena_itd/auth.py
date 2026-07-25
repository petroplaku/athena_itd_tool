"""Authentication & authorization for the console and API.

Provides three things, all stdlib-only (no external crypto dependency):

* **Password hashing** — ``scrypt`` (memory-hard) with a per-user random salt.
* **Roles / RBAC** — ``viewer < analyst < admin`` with a request classifier that
  decides the minimum role a given ``(method, path)`` requires.
* **Login throttling** — per identity+IP lockout to blunt credential stuffing.

Sessions themselves live in the database (see ``Store.create_session`` …) so they
survive restarts and are shared across worker processes; this module only defines
the token shape and cookie names.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

# ── roles ──────────────────────────────────────────────────────────────────
ROLES = ("viewer", "analyst", "admin")
_RANK = {r: i for i, r in enumerate(ROLES)}

SESSION_COOKIE = "athena_session"
CSRF_COOKIE = "athena_csrf"
CSRF_HEADER = "x-csrf-token"


def role_rank(role: str) -> int:
    return _RANK.get(role, -1)


def role_at_least(role: str, required: str) -> bool:
    return role_rank(role) >= role_rank(required)


# ── password hashing (scrypt) ──────────────────────────────────────────────
# Cost parameters: n=2**14 keeps a login well under ~100ms while being far
# stronger than a single-round hash. Tunable without breaking stored hashes
# because n/r/p are encoded in the stored string.
_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str, enforce_policy: bool = True) -> str:
    """Return a self-describing ``scrypt$n$r$p$salt$hash`` string.

    ``enforce_policy`` applies the 8-char minimum (used for interactive sign-up);
    seeding a preset bootstrap credential may set it False.
    """
    if not password:
        raise ValueError("password must not be empty")
    if enforce_policy and len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify against a ``hash_password`` string."""
    try:
        scheme, n, r, p, salt_hex, hash_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                            n=int(n), r=int(r), p=int(p), dklen=len(hash_hex) // 2)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def new_session_token() -> tuple[str, str]:
    """Return ``(raw_token, token_hash)``. The cookie carries the raw token;
    only its SHA-256 is stored, so a database leak cannot resurrect sessions."""
    raw = secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# ── RBAC request classifier ────────────────────────────────────────────────
# Endpoints that reconfigure the platform or touch the corpus require admin.
_ADMIN_PREFIXES = (
    "/api/config", "/api/detections", "/api/reset", "/api/generate",
    "/api/ingest", "/api/dataset", "/api/purge", "/api/train",
    "/api/accounts", "/api/sessions", "/api/stream/",
)
# Always reachable without a session (probes, static, the login flow).
_PUBLIC = {
    "/api/health", "/api/ready", "/api/metrics", "/api/version",
    "/api/login", "/api/logout", "/api/me", "/api/signup",
}
_PUBLIC_PREFIXES = ("/static/",)


def is_public_path(path: str) -> bool:
    return path in _PUBLIC or any(path.startswith(p) for p in _PUBLIC_PREFIXES)


def required_role(method: str, path: str) -> str:
    """Minimum role for a request. GET/HEAD → viewer; mutations → analyst,
    except platform-admin surfaces → admin."""
    if any(path.startswith(p) for p in _ADMIN_PREFIXES):
        return "admin"
    if method.upper() in ("GET", "HEAD", "OPTIONS"):
        return "viewer"
    return "analyst"


# ── login throttling (in-process) ──────────────────────────────────────────
@dataclass
class _Attempt:
    fails: int = 0
    locked_until: float = 0.0


class LoginThrottle:
    """Per (identity, ip) exponential-ish lockout after repeated failures."""

    def __init__(self, max_fails: int = 5, base_lock_seconds: int = 30,
                 window_seconds: int = 900):
        self.max_fails = max_fails
        self.base = base_lock_seconds
        self.window = window_seconds
        self._state: dict[str, _Attempt] = {}

    def _key(self, identity: str, ip: str) -> str:
        return f"{identity}\x00{ip}"

    def check(self, identity: str, ip: str, now: float | None = None) -> float:
        """Return seconds remaining on a lock (0 if allowed)."""
        now = time.time() if now is None else now
        a = self._state.get(self._key(identity, ip))
        if a and a.locked_until > now:
            return a.locked_until - now
        return 0.0

    def record_failure(self, identity: str, ip: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        key = self._key(identity, ip)
        a = self._state.get(key) or _Attempt()
        a.fails += 1
        if a.fails >= self.max_fails:
            # lock grows with the overage; capped so it can't lock out forever
            over = a.fails - self.max_fails
            a.locked_until = now + min(self.base * (2 ** over), self.window)
        self._state[key] = a

    def record_success(self, identity: str, ip: str) -> None:
        self._state.pop(self._key(identity, ip), None)


THROTTLE = LoginThrottle()


class RateLimiter:
    """Fixed-window request rate limiter keyed by caller identity.

    Per-process (each worker keeps its own window); intended as a coarse abuse
    brake, not a distributed quota. Set ``per_minute<=0`` to disable.
    """

    def __init__(self) -> None:
        # key -> (window_start_epoch_minute, count)
        self._buckets: dict[str, list[float]] = {}

    def hit(self, key: str, per_minute: int, now: float | None = None) -> float:
        """Register a request. Return seconds to wait (0 if allowed)."""
        if per_minute <= 0:
            return 0.0
        now = time.time() if now is None else now
        window = int(now // 60)
        b = self._buckets.get(key)
        if b is None or b[0] != window:
            self._buckets[key] = [window, 1]
            return 0.0
        b[1] += 1
        if b[1] > per_minute:
            return (window + 1) * 60 - now      # seconds until the window resets
        return 0.0


RATE_LIMITER = RateLimiter()
