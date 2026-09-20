from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ValidationError

from schemas import (
    GENESIS_HASH,
    AuditEvent,
    AuditEventIn,
    ESignature,
    IntegrityCheckResult,
    SignatureVerification,
)

T = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
H = "a" * 64
EVENT = AuditEvent(
    id="evt-1",
    timestamp=T,
    actor="alice",
    action="create",
    record_type="batch_record",
    record_id="BR-1",
    before_hash=GENESIS_HASH,
    after_hash=H,
    entry_hash="b" * 64,
)
SIG = ESignature(
    id="sig-1",
    signer="alice",
    signed_record_id="BR-1",
    signed_record_hash=H,
    timestamp=T,
    meaning="approved",
    signature_method="username_password_demo",
    signature_value="c2ln",
)
VERIFICATION = SignatureVerification(
    signature_id="sig-1",
    record_hash_matches=True,
    signature_valid=True,
    captured_hash=H,
    current_hash=H,
    checked_at=T,
)
CHECK = IntegrityCheckResult(
    checked_at=T, chain_valid=False, first_broken_link=2, total_events_checked=5
)


@pytest.mark.parametrize("model", [EVENT, SIG, CHECK, VERIFICATION])
def test_json_round_trip(model: BaseModel) -> None:
    assert type(model).model_validate_json(model.model_dump_json()) == model


def test_event_in_rejects_client_timestamp_and_hashes() -> None:
    base = {"actor": "alice", "action": "create", "record_type": "batch", "record_id": "BR-1"}
    assert AuditEventIn(**base).after_hash is None
    for extra in ("timestamp", "id", "entry_hash", "before_hash"):
        with pytest.raises(ValidationError):
            AuditEventIn(**base, **{extra: "x"})


def test_models_are_frozen() -> None:
    with pytest.raises(ValidationError):
        EVENT.actor = "mallory"  # type: ignore[misc]


def test_hash_fields_must_be_sha256_hex() -> None:
    with pytest.raises(ValidationError):
        AuditEvent.model_validate(EVENT.model_dump() | {"entry_hash": "not-a-hash"})


def test_signature_meaning_must_be_explicit() -> None:
    with pytest.raises(ValidationError):
        ESignature.model_validate(SIG.model_dump() | {"meaning": "implied"})


def test_genesis_hash_is_64_zeros() -> None:
    assert GENESIS_HASH == "0" * 64 and EVENT.before_hash == GENESIS_HASH
