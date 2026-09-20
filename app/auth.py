"""Demo identification for e-signatures: username + password (11.200(a)(1)(i)).

Users come from ``AUDIT_DEMO_USERS`` (``"user:pw,user:pw"``); passwords are hashed with
``hashlib.scrypt`` and a per-user random salt at load, and compared with
``hmac.compare_digest`` so timing does not leak which byte differed.

Production would require at least two distinct identification components (11.200(a)(1)),
i.e. MFA, plus the 11.300 controls (unique IDs, periodic credential revision, lockout and
loss-management procedures). This module is Attributable-by-username only.
# ponytail: demo credentials from an env var; ceiling: single-factor, no lockout or
# credential ageing. Upgrade path: identity provider (OIDC) with MFA and 11.300 controls.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

_SCRYPT = {"n": 2**14, "r": 8, "p": 1}
Users = dict[str, tuple[bytes, bytes]]  # username -> (salt, scrypt hash)


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)


def load_users(spec: str | None = None) -> Users:
    """Parse ``"user:pw,user:pw"`` (``AUDIT_DEMO_USERS`` by default) into salted hashes."""
    raw = spec if spec is not None else os.getenv("AUDIT_DEMO_USERS", "alice:alice-pw,bob:bob-pw")
    users: Users = {}
    for pair in filter(None, (p.strip() for p in raw.split(","))):
        username, _, password = pair.partition(":")
        salt = secrets.token_bytes(16)
        users[username] = (salt, _hash(password, salt))
    return users


_USERS = load_users()
_DUMMY = (secrets.token_bytes(16), b"\0" * 64)


def authenticate(username: str, password: str, users: Users | None = None) -> bool:
    """Constant-time credential check. Unknown users still pay the scrypt cost so timing
    does not reveal whether a username exists."""
    salt, expected = (users if users is not None else _USERS).get(username, _DUMMY)
    return hmac.compare_digest(_hash(password, salt), expected)
