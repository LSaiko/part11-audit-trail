"""E-signature workflow: capture, Ed25519 verification, post-signature tamper detection."""

import base64
import logging

import pytest
from pydantic import ValidationError

from app.auth import authenticate, load_users
from app.log_service import AuditLog
from app.records import RecordStore
from app.signatures import AuthenticationError, SignatureService, signature_payload
from app.verifier import verify_chain
from crypto import signing
from schemas import ESignature

USERS = load_users("alice:alice-pw,bob:bob-pw")
CONTENT = {"lot": "L-42", "result": "pass"}


@pytest.fixture
def log() -> AuditLog:
    return AuditLog(":memory:")


@pytest.fixture
def records(log: AuditLog) -> RecordStore:
    store = RecordStore(log)
    store.put("alice", "batch_record", "BR-1", CONTENT)
    return store


@pytest.fixture
def service(log: AuditLog, records: RecordStore) -> SignatureService:
    return SignatureService(log, records, USERS)


# --- auth ---------------------------------------------------------------------------------


def test_authenticate_demo_users() -> None:
    assert authenticate("alice", "alice-pw", USERS)
    assert not authenticate("alice", "wrong", USERS)
    assert not authenticate("nobody", "alice-pw", USERS)


def test_default_users_come_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIT_DEMO_USERS", "carol:c-pw, dave:d-pw,")
    users = load_users()
    assert set(users) == {"carol", "dave"} and authenticate("dave", "d-pw", users)
    monkeypatch.delenv("AUDIT_DEMO_USERS")
    assert authenticate("alice", "alice-pw", load_users())
    assert authenticate("alice", "alice-pw")  # module-level default users


# --- crypto/signing ---------------------------------------------------------------------


def test_sign_and_verify_round_trip() -> None:
    sig = signing.sign(b"payload")
    assert signing.verify(b"payload", sig, signing.public_key_bytes())
    assert not signing.verify(b"payload!", sig, signing.public_key_bytes())
    assert not signing.verify(b"payload", "not base64!", signing.public_key_bytes())
    assert not signing.verify(b"payload", sig, b"\0" * 32)


def test_key_from_env_seed_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    seed = base64.b64encode(b"\x07" * 32).decode()
    monkeypatch.setenv("AUDIT_SIGNING_KEY", seed)
    a = signing.load_private_key().public_key().public_bytes_raw()
    b = signing.load_private_key(seed).public_key().public_bytes_raw()
    assert a == b


def test_missing_seed_warns_without_leaking_key(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("AUDIT_SIGNING_KEY", raising=False)
    with caplog.at_level(logging.WARNING, logger="crypto.signing"):
        key = signing.load_private_key()
    assert "ephemeral" in caplog.text and "restart" in caplog.text
    assert base64.b64encode(key.private_bytes_raw()).decode() not in caplog.text


# --- workflow -----------------------------------------------------------------------------


def test_sign_then_verify_ok(service: SignatureService, records: RecordStore) -> None:
    sig = service.sign("alice", "alice-pw", "BR-1", "approved")
    assert sig.signer == "alice" and sig.meaning == "approved"
    assert sig.signed_record_hash == records.current_hash("BR-1")
    assert sig.signature_method == "username_password_demo"
    assert service.get(sig.id) == sig
    result = service.verify(sig.id)
    assert result.signature_valid and result.record_hash_matches
    assert result.captured_hash == result.current_hash == sig.signed_record_hash


def test_record_change_after_signature_is_detected(
    service: SignatureService, records: RecordStore
) -> None:
    sig = service.sign("alice", "alice-pw", "BR-1", "approved")
    records.put("bob", "batch_record", "BR-1", {**CONTENT, "result": "fail"})
    result = service.verify(sig.id)
    assert not result.record_hash_matches
    assert result.signature_valid  # signature over the old hash is still authentic
    assert result.captured_hash == sig.signed_record_hash != result.current_hash


def test_tampered_signature_value_is_invalid(service: SignatureService) -> None:
    sig = service.sign("alice", "alice-pw", "BR-1", "approved")
    forged = base64.b64encode(b"\0" * 64).decode()
    service._signatures[sig.id] = sig.model_copy(update={"signature_value": forged})
    result = service.verify(sig.id)
    assert not result.signature_valid and result.record_hash_matches


def test_tampered_signature_meaning_is_invalid(service: SignatureService) -> None:
    sig = service.sign("alice", "alice-pw", "BR-1", "reviewed")
    service._signatures[sig.id] = sig.model_copy(update={"meaning": "approved"})
    assert not service.verify(sig.id).signature_valid


def test_wrong_password_raises_and_is_logged(service: SignatureService, log: AuditLog) -> None:
    with pytest.raises(AuthenticationError):
        service.sign("alice", "wrong", "BR-1", "approved")
    failed = [e for e in log.events_for("BR-1") if e.action == "esign:auth_failed"]
    assert len(failed) == 1 and failed[0].actor == "alice" and failed[0].after_hash is None
    assert not [e for e in log.events() if e.action.startswith("esign:approved")]
    assert verify_chain(log.events()).chain_valid


def test_signing_is_logged_as_audit_event(
    service: SignatureService, log: AuditLog, records: RecordStore
) -> None:
    service.sign("bob", "bob-pw", "BR-1", "approved")
    actions = [(e.actor, e.action) for e in log.events_for("BR-1")]
    assert actions == [("alice", "create"), ("bob", "esign:approved")]
    esign = log.events_for("BR-1")[-1]
    assert esign.after_hash == records.current_hash("BR-1")
    assert esign.record_type == "batch_record"
    assert verify_chain(log.events()).chain_valid


def test_unknown_record_raises(service: SignatureService) -> None:
    with pytest.raises(KeyError):
        service.sign("alice", "alice-pw", "BR-404", "approved")
    with pytest.raises(KeyError):
        service.verify("sig-404")


def test_meaning_must_be_explicit(service: SignatureService) -> None:
    sig = service.sign("alice", "alice-pw", "BR-1", "authored")
    with pytest.raises(ValidationError):
        ESignature.model_validate(sig.model_dump() | {"meaning": "implied"})
    with pytest.raises(ValidationError):
        ESignature.model_validate(sig.model_dump() | {"meaning": None})


def test_signature_payload_excludes_signature_and_is_canonical(
    service: SignatureService,
) -> None:
    sig = service.sign("alice", "alice-pw", "BR-1", "rejected")
    payload = signature_payload(sig)
    assert sig.signature_value.encode() not in payload
    assert payload == signature_payload(sig.model_copy(update={"signature_value": "x"}))
    assert payload.startswith(b'{"id":"')


def test_record_store_logs_create_then_update(records: RecordStore, log: AuditLog) -> None:
    first = log.events_for("BR-1")[0]
    assert first.action == "create" and first.after_hash == records.current_hash("BR-1")
    event = records.put("alice", "batch_record", "BR-1", {"lot": "L-43"})
    assert event.action == "update" and records.get("BR-1") == {"lot": "L-43"}
    assert records.record_type("BR-1") == "batch_record"
    assert event.after_hash == records.current_hash("BR-1") != first.after_hash
