"""E-signature workflow (11.50, 11.70, 11.100, 11.200).

``sign`` authenticates the signer, captures the record's current hash, builds an
``ESignature`` with an explicit ``meaning`` (11.50(a)(3)), Ed25519-signs its canonical
JSON, and appends an ``esign:<meaning>`` ``AuditEvent`` so the act of signing is itself in
the trail (Attributable, Contemporaneous). A failed authentication is also logged
(``esign:auth_failed``) before raising. ``verify`` re-checks the Ed25519 signature and
compares the captured record hash with the record's current hash, so any post-signature
change to the record is detectable (11.70 linking).
# ponytail: signatures kept in an in-memory dict. Upgrade path: a second append-only
# SQLite table with the same triggers as ``audit_events``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.auth import Users, authenticate
from app.log_service import AuditLog
from app.records import RecordStore
from crypto.hashing import canonical_json
from crypto.signing import public_key_bytes, sign, verify
from schemas import ESignature, SignatureMeaning, SignatureVerification

SIGNATURE_METHOD = "username_password_demo"


class AuthenticationError(PermissionError):
    """Raised when the signer's credentials are rejected (after logging the attempt)."""


def signature_payload(signature: ESignature) -> bytes:
    """Canonical bytes that the Ed25519 signature covers: every field except the signature."""
    return canonical_json(signature.model_dump(mode="json", exclude={"signature_value"}))


class SignatureService:
    def __init__(self, log: AuditLog, records: RecordStore, users: Users | None = None) -> None:
        self._log = log
        self._records = records
        self._users = users
        self._signatures: dict[str, ESignature] = {}

    def sign(
        self, username: str, password: str, record_id: str, meaning: SignatureMeaning
    ) -> ESignature:
        record_type = self._records.record_type(record_id)  # KeyError if unknown record
        if not authenticate(username, password, self._users):
            self._log.append(username, "esign:auth_failed", record_type, record_id)
            raise AuthenticationError(f"authentication failed for {username!r}")
        captured = self._records.current_hash(record_id)
        unsigned = ESignature(
            id=str(uuid.uuid4()),
            signer=username,
            signed_record_id=record_id,
            signed_record_hash=captured,
            timestamp=datetime.now(UTC),
            meaning=meaning,
            signature_method=SIGNATURE_METHOD,
            signature_value="",
        )
        signature = unsigned.model_copy(
            update={"signature_value": sign(signature_payload(unsigned))}
        )
        self._signatures[signature.id] = signature
        self._log.append(username, f"esign:{meaning}", record_type, record_id, captured)
        return signature

    def get(self, signature_id: str) -> ESignature:
        return self._signatures[signature_id]

    def verify(self, signature_id: str) -> SignatureVerification:
        signature = self._signatures[signature_id]
        current = self._records.current_hash(signature.signed_record_id)
        return SignatureVerification(
            signature_id=signature_id,
            record_hash_matches=signature.signed_record_hash == current,
            signature_valid=verify(
                signature_payload(signature), signature.signature_value, public_key_bytes()
            ),
            captured_hash=signature.signed_record_hash,
            current_hash=current,
            checked_at=datetime.now(UTC),
        )
