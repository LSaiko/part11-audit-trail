"""Ed25519 signatures for Part 11 electronic signatures (11.70 signature/record linking).

Well-vetted primitive only: ``cryptography``'s Ed25519. Isolated: takes plain ``bytes`` /
``str`` and never imports ``app`` or ``schemas``. The private key is never logged.

Key source: ``AUDIT_SIGNING_KEY`` (base64 of a 32-byte Ed25519 seed). When unset, an
ephemeral key is generated at import and a WARNING is logged that signatures will not
verify after a restart (the key itself is never logged).
# ponytail: one server-held key signs on behalf of every authenticated signer, so the
# signature proves "this server, after authenticating <signer>, attested to this hash".
# Ceiling: non-repudiation rests on server trust. Upgrade path: per-signer keys held in an
# HSM / KMS, with the server key only countersigning.
"""

from __future__ import annotations

import base64
import logging
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_log = logging.getLogger(__name__)


def load_private_key(seed_b64: str | None = None) -> Ed25519PrivateKey:
    """Derive the server key from a base64 32-byte seed (``AUDIT_SIGNING_KEY`` by default),
    or generate an ephemeral one with a WARNING when no seed is configured."""
    seed = seed_b64 if seed_b64 is not None else os.getenv("AUDIT_SIGNING_KEY")
    if seed is None:
        _log.warning(
            "AUDIT_SIGNING_KEY is unset: using an ephemeral Ed25519 key; "
            "signatures will not verify after restart"
        )
        return Ed25519PrivateKey.generate()
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(seed, validate=True))


_PRIVATE_KEY = load_private_key()


def public_key_bytes() -> bytes:
    """Raw 32-byte Ed25519 public key of the server signing key."""
    return _PRIVATE_KEY.public_key().public_bytes_raw()


def sign(payload: bytes) -> str:
    """Sign ``payload`` with the server key; returns the base64 signature."""
    return base64.b64encode(_PRIVATE_KEY.sign(payload)).decode("ascii")


def verify(payload: bytes, sig_b64: str, public_key: bytes) -> bool:
    """True iff ``sig_b64`` is a valid Ed25519 signature of ``payload`` under ``public_key``
    (raw 32 bytes). Malformed input is reported as invalid, never raised."""
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            base64.b64decode(sig_b64, validate=True), payload
        )
    except (InvalidSignature, ValueError):
        return False
    return True
