"""HTTP surface: every endpoint, the ingest token guard, and the end-to-end signature flow."""

import logging
import shutil
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from app import main
from app.auth import load_users
from app.log_service import AuditLog
from app.records import RecordStore
from app.signatures import SignatureService
from schemas import ESignature, SignRequest

CONTENT = {"title": "Cleaning SOP", "revision": 3}
USERS = load_users("alice:alice-pw")


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """Fresh in-memory singletons per test so state never leaks between tests."""
    monkeypatch.delenv("AUDIT_INTERNAL_TOKEN", raising=False)
    monkeypatch.setattr(main, "log", AuditLog(":memory:"))
    monkeypatch.setattr(main, "records", RecordStore(main.log))
    monkeypatch.setattr(main, "signatures", SignatureService(main.log, main.records, USERS))
    with TestClient(main.app) as c:
        yield c


def put(client: TestClient, record_id: str = "SOP-017", **content: Any) -> dict[str, Any]:
    body = {"actor": "alice", "content": content or CONTENT}
    r = client.put(f"/records/sop/{record_id}", json=body)
    assert r.status_code == 200
    return dict(r.json())


def sign(client: TestClient, password: str = "alice-pw", record_id: str = "SOP-017") -> Response:
    body = {"username": "alice", "password": password, "record_id": record_id}
    r: Response = client.post("/sign", json=body | {"meaning": "approved"})
    return r


# --- health & ingest ----------------------------------------------------------------------


def test_health(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_post_event_returns_chained_event(client: TestClient) -> None:
    body = {"actor": "lims", "action": "export", "record_type": "batch", "record_id": "B-1"}
    first = client.post("/events", json=body).json()
    second = client.post("/events", json=body | {"after_hash": "a" * 64}).json()
    assert first["before_hash"] == "0" * 64 and second["before_hash"] == first["entry_hash"]
    assert second["after_hash"] == "a" * 64 and first["after_hash"] is None
    assert [e["id"] for e in client.get("/events").json()] == [first["id"], second["id"]]


def test_post_event_rejects_client_timestamp(client: TestClient) -> None:
    body = {"actor": "a", "action": "b", "record_type": "c", "record_id": "d"}
    stamped = body | {"timestamp": "2000-01-01T00:00:00Z"}
    assert client.post("/events", json=stamped).status_code == 422
    assert client.post("/events", json=body | {"entry_hash": "e" * 64}).status_code == 422
    assert client.get("/events").json() == []


def test_ingest_token_guard(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    body = {"actor": "a", "action": "b", "record_type": "c", "record_id": "d"}
    assert client.post("/events", json=body).status_code == 200  # unset: open (demo)
    monkeypatch.setenv("AUDIT_INTERNAL_TOKEN", "s3cret")
    assert client.post("/events", json=body).status_code == 401
    bad = client.post("/events", json=body, headers={"X-Audit-Token": "wrong"})
    assert bad.status_code == 401 and "X-Audit-Token" in bad.json()["detail"]
    ok = client.post("/events", json=body, headers={"X-Audit-Token": "s3cret"})
    assert ok.status_code == 200
    assert len(client.get("/events").json()) == 2


def test_open_ingest_warns_once_at_startup(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="app.main"):
        monkeypatch.delenv("AUDIT_INTERNAL_TOKEN", raising=False)
        main.warn_if_ingest_open()
        monkeypatch.setenv("AUDIT_INTERNAL_TOKEN", "t")
        main.warn_if_ingest_open()
    assert caplog.text.count("POST /events is open") == 1


# --- records & audit trail ----------------------------------------------------------------


def test_put_record_logs_create_then_update(client: TestClient) -> None:
    created = put(client)
    updated = put(client, revision=4)
    assert created["event"]["action"] == "create" and updated["event"]["action"] == "update"
    assert created["current_hash"] != updated["current_hash"]
    assert updated["event"]["after_hash"] == updated["current_hash"]
    assert updated["record_type"] == "sop" and updated["record_id"] == "SOP-017"


def test_audit_trail_is_per_record_with_full_chain_integrity(client: TestClient) -> None:
    put(client, "SOP-017")
    put(client, "CAPA-0042")
    put(client, "SOP-017", revision=4)
    trail = client.get("/audit-trail/SOP-017").json()
    assert trail["record_id"] == "SOP-017"
    assert [e["action"] for e in trail["events"]] == ["create", "update"]
    assert trail["integrity"]["chain_valid"] and trail["integrity"]["total_events_checked"] == 3
    assert client.get("/audit-trail/nope").status_code == 404


# --- signatures ---------------------------------------------------------------------------


def test_sign_then_verify_then_tamper_end_to_end(client: TestClient) -> None:
    put(client)
    sig = sign(client).json()
    assert sig["signer"] == "alice" and sig["meaning"] == "approved"
    assert "alice-pw" not in str(sig) and set(sig) == set(ESignature.model_fields)
    ok = client.get(f"/verify-signature/{sig['id']}").json()
    assert ok["signature_valid"] and ok["record_hash_matches"]
    put(client, revision=99)  # post-signature change (11.70 linking must expose it)
    changed = client.get(f"/verify-signature/{sig['id']}").json()
    assert changed["signature_valid"] and not changed["record_hash_matches"]
    assert changed["captured_hash"] == sig["signed_record_hash"] != changed["current_hash"]
    assert client.get("/signatures").json() == [sig]
    assert main.signatures.get(sig["id"]).model_dump(mode="json") == sig
    assert client.get("/verify-chain").json()["chain_valid"]
    actions = [e["action"] for e in client.get("/audit-trail/SOP-017").json()["events"]]
    assert actions == ["create", "esign:approved", "update"]


def test_sign_401_on_bad_password_and_is_logged_without_password(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    put(client)
    with caplog.at_level(logging.DEBUG):
        r = sign(client, password="wrong")
    assert r.status_code == 401 and "wrong" not in r.text and "wrong" not in caplog.text
    actions = [e["action"] for e in client.get("/events").json()]
    assert actions == ["create", "esign:auth_failed"]


def test_sign_404_on_unknown_record(client: TestClient) -> None:
    r = sign(client, record_id="SOP-404")
    assert r.status_code == 404 and "SOP-404" in r.json()["detail"]
    assert client.get("/events").json() == []


def test_sign_422_on_implicit_meaning(client: TestClient) -> None:
    put(client)
    body = {"username": "alice", "password": "alice-pw", "record_id": "SOP-017", "meaning": "ok"}
    assert client.post("/sign", json=body).status_code == 422


def test_verify_signature_404(client: TestClient) -> None:
    assert client.get("/verify-signature/sig-404").status_code == 404


def test_sign_request_repr_hides_password() -> None:
    req = SignRequest(username="alice", password="hunter2", record_id="R", meaning="reviewed")
    assert "hunter2" not in repr(req) and "hunter2" not in str(req)


# --- broken chain served from a corrupted database copy --------------------------------------


def test_verify_chain_reports_break_in_corrupted_db_copy(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulates an attacker with direct database access: the append-only triggers protect the
    live file, so the attack is modelled on a *copy* where the triggers are dropped first and a
    row is rewritten with plain SQL. A second service instance pointed at that copy must
    report the break at the rewritten row (the Documenter reports, never repairs)."""
    live = tmp_path / "live.db"
    monkeypatch.setattr(main, "log", AuditLog(live))
    monkeypatch.setattr(main, "records", RecordStore(main.log))
    for i in range(5):
        put(client, f"SOP-{i}")
    assert client.get("/verify-chain").json()["chain_valid"]

    copy = tmp_path / "stolen.db"
    shutil.copy(live, copy)
    conn = sqlite3.connect(copy)
    conn.execute("DROP TRIGGER audit_events_no_update")
    conn.execute("UPDATE audit_events SET actor = 'mallory' WHERE rowid = 3")
    conn.commit()
    conn.close()

    monkeypatch.setattr(main, "log", AuditLog(copy))  # "second instance" on the copy
    result = client.get("/verify-chain").json()
    assert not result["chain_valid"] and result["first_broken_link"] == 2
    assert result["total_events_checked"] == 5
    trail = client.get("/audit-trail/SOP-2").json()
    assert trail["events"][0]["actor"] == "mallory" and not trail["integrity"]["chain_valid"]
    assert AuditLog(live).events()[2].actor == "alice"  # the live file was never touched


# --- API boundary: server-owned fields -----------------------------------------------------


def test_post_event_rejects_every_server_owned_field(client: TestClient) -> None:
    """ALCOA+ Contemporaneous / Original: id, timestamp, before_hash and entry_hash are
    server-generated; a client that supplies any of them gets 422 and nothing is logged."""
    body = {"actor": "a", "action": "b", "record_type": "c", "record_id": "d"}
    for field, value in {
        "timestamp": "2000-01-01T00:00:00Z",
        "id": "chosen-by-client",
        "before_hash": "0" * 64,
        "entry_hash": "e" * 64,
    }.items():
        r = client.post("/events", json=body | {field: value})
        assert r.status_code == 422, field
        assert r.json()["detail"][0]["type"] == "extra_forbidden", field
    assert client.post("/events", json=body | {"after_hash": "short"}).status_code == 422
    assert client.get("/events").json() == []


def test_concurrent_http_appends_chain_correctly(client: TestClient) -> None:
    from concurrent.futures import ThreadPoolExecutor

    body = {"actor": "lims", "action": "export", "record_type": "batch", "record_id": "B"}
    with ThreadPoolExecutor(8) as pool:
        codes = list(pool.map(lambda _: client.post("/events", json=body).status_code, range(40)))
    assert codes == [200] * 40
    result = client.get("/verify-chain").json()
    assert result["chain_valid"] and result["total_events_checked"] == 40
