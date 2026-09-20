"""Tamper-evidence tests for the Part 11 hash chain: the centrepiece of the project."""

import sqlite3
from pathlib import Path

import pytest

from app.log_service import AuditLog
from app.verifier import verify_chain
from crypto.hashing import DELIMITER, entry_hash, record_hash
from schemas import GENESIS_HASH, AuditEvent

N = 7
TS = "2026-09-20T12:00:00+00:00"


@pytest.fixture
def log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.db")


@pytest.fixture
def events(log: AuditLog) -> list[AuditEvent]:
    for i in range(N):
        log.append(f"user{i}", "update", "batch_record", f"BR-{i % 2}", after_hash="c" * 64)
    return log.events()


# --- hashing primitives -------------------------------------------------------------------


def test_entry_hash_is_deterministic_sha256_hex() -> None:
    a = entry_hash(GENESIS_HASH, "alice", "create", "BR-1", TS)
    assert a == entry_hash(GENESIS_HASH, "alice", "create", "BR-1", TS)
    assert len(a) == 64 and int(a, 16) >= 0


def test_entry_hash_delimiter_prevents_field_boundary_ambiguity() -> None:
    assert DELIMITER == "\x1f"
    ambiguous = entry_hash(GENESIS_HASH, "a", "bc", "r", TS)
    assert entry_hash(GENESIS_HASH, "ab", "c", "r", TS) != ambiguous
    assert entry_hash(GENESIS_HASH, "a", "b", "r", TS) != entry_hash(
        GENESIS_HASH, "a", "b", "r", TS, record_type="t"
    )


def test_record_hash_is_key_order_and_whitespace_independent() -> None:
    assert record_hash({"b": 1, "a": [1, 2]}) == record_hash({"a": [1, 2], "b": 1})
    assert record_hash({"a": 1}) == record_hash(b'{"a":1}')
    assert record_hash({"a": 1}) != record_hash({"a": 2})


# --- append & storage ---------------------------------------------------------------------


def test_append_n_events_yields_valid_chain(events: list[AuditEvent]) -> None:
    result = verify_chain(events)
    assert result.chain_valid and result.first_broken_link is None
    assert result.total_events_checked == N
    assert result.checked_at.tzinfo is not None


def test_genesis_before_hash_and_links(events: list[AuditEvent]) -> None:
    assert events[0].before_hash == GENESIS_HASH == "0" * 64
    for prev, cur in zip(events, events[1:], strict=False):
        assert cur.before_hash == prev.entry_hash
    assert all(e.timestamp.tzinfo is not None for e in events)  # Contemporaneous, UTC
    assert len({e.id for e in events}) == N


def test_events_for_filters_and_orders_by_append(log: AuditLog) -> None:
    log.append("a", "create", "t", "R")
    log.append("b", "update", "t", "OTHER")
    log.append("c", "update", "t", "R")
    assert [e.actor for e in log.events_for("R")] == ["a", "c"]
    assert log.events_for("missing") == []


def test_env_default_is_in_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUDIT_DB_PATH", raising=False)
    assert AuditLog().path == ":memory:"
    assert AuditLog().append("a", "b", "c", "d").before_hash == GENESIS_HASH


def test_env_path_is_used(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    db = tmp_path / "env.db"
    monkeypatch.setenv("AUDIT_DB_PATH", str(db))
    AuditLog().append("a", "b", "c", "d")
    assert db.exists() and len(AuditLog().events()) == 1


def test_persists_across_reopen(tmp_path: Path) -> None:
    db = tmp_path / "audit.db"
    first = AuditLog(db).append("a", "b", "c", "d")
    reopened = AuditLog(db)
    second = reopened.append("e", "f", "g", "h")
    assert second.before_hash == first.entry_hash
    assert verify_chain(reopened.events()).chain_valid


def test_no_public_mutation_api() -> None:
    public = {n for n in dir(AuditLog) if not n.startswith("_")}
    assert public == {"append", "events", "events_for", "path"}


# --- storage-layer append-only enforcement --------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE audit_events SET actor = 'mallory' WHERE rowid = 2",
        "UPDATE audit_events SET entry_hash = '{h}' WHERE rowid = 2",
        "DELETE FROM audit_events WHERE rowid = 2",
        "DELETE FROM audit_events",
    ],
)
def test_raw_sql_update_and_delete_are_refused(
    events: list[AuditEvent], log: AuditLog, sql: str
) -> None:
    conn = sqlite3.connect(log.path)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute(sql.format(h="f" * 64))
    conn.close()
    assert log.events() == events  # history untouched
    assert verify_chain(log.events()).chain_valid


# --- tamper detection ---------------------------------------------------------------------


def _mutated(events: list[AuditEvent], k: int, **changes: str) -> list[AuditEvent]:
    copy = list(events)
    copy[k] = AuditEvent.model_validate(events[k].model_dump() | changes)
    return copy


@pytest.mark.parametrize("k", [0, N // 2, N - 1], ids=["first", "middle", "last"])
@pytest.mark.parametrize(
    "changes",
    [
        {"actor": "mallory"},
        {"action": "delete"},
        {"record_type": "other"},
        {"record_id": "BR-99"},
        {"after_hash": "d" * 64},
        {"timestamp": "2000-01-01T00:00:00+00:00"},
        {"entry_hash": "e" * 64},
        {"before_hash": "f" * 64},
    ],
    ids=lambda c: next(iter(c)),
)
def test_corrupting_entry_k_breaks_chain_at_k(
    events: list[AuditEvent], k: int, changes: dict[str, str]
) -> None:
    result = verify_chain(_mutated(events, k, **changes))
    assert not result.chain_valid
    assert result.first_broken_link == k
    assert result.total_events_checked == N


def test_reordering_two_entries_is_detected(events: list[AuditEvent]) -> None:
    swapped = list(events)
    swapped[2], swapped[3] = swapped[3], swapped[2]
    result = verify_chain(swapped)
    assert not result.chain_valid and result.first_broken_link == 2


def test_removing_a_middle_entry_is_detected(events: list[AuditEvent]) -> None:
    result = verify_chain(events[:2] + events[3:])
    assert not result.chain_valid and result.first_broken_link == 2


def test_inserting_a_forged_entry_is_detected(events: list[AuditEvent]) -> None:
    forged = AuditEvent.model_validate(events[4].model_dump() | {"id": "forged"})
    result = verify_chain(events[:4] + [forged] + events[4:])
    assert not result.chain_valid and result.first_broken_link == 5


def test_tail_truncation_is_not_detectable_by_hash_alone(events: list[AuditEvent]) -> None:
    """Documented limitation: dropping the newest entries leaves a valid (shorter) chain.
    Upgrade path: periodic signed checkpoint of the head hash (see app.log_service)."""
    result = verify_chain(events[:-2])
    assert result.chain_valid and result.total_events_checked == N - 2


def test_empty_chain_is_valid() -> None:
    result = verify_chain([])
    assert result.chain_valid and result.total_events_checked == 0


def test_concurrent_appends_chain_correctly(log: AuditLog) -> None:
    """FastAPI runs sync endpoints in a threadpool; the lock must serialise read-head + insert
    so no two entries chain to the same predecessor (ALCOA+ Complete, Consistent)."""
    import threading

    def worker(i: int) -> None:
        for j in range(20):
            log.append(f"user{i}", "update", "t", f"R-{j}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    events = log.events()
    assert len(events) == 160
    assert len({e.before_hash for e in events}) == 160  # every predecessor used exactly once
    assert verify_chain(events).chain_valid


def test_swapping_after_hash_between_entries_breaks_chain(log: AuditLog) -> None:
    """Moving a content fingerprint from one entry to another (both stay well-formed sha256
    values, so schema validation passes) still breaks the chain at the first entry touched:
    entry_hash covers after_hash, so the swap is not a silent re-labelling."""
    for i in range(4):
        log.append("alice", "update", "t", "R", after_hash=str(i) * 64)
    events = log.events()
    swapped = _mutated(
        _mutated(events, 1, after_hash=events[2].after_hash or ""),
        2,
        after_hash=events[1].after_hash or "",
    )
    result = verify_chain(swapped)
    assert not result.chain_valid and result.first_broken_link == 1


def test_raw_sql_insert_bypassing_the_service_is_detected(
    events: list[AuditEvent], log: AuditLog
) -> None:
    """The triggers stop rewrites, not inserts: an attacker with the file can still INSERT a
    row that skips the service. The chain then breaks at that row because its hashes were
    never computed (or, if copied from a real row, its before_hash does not match the head)."""
    conn = sqlite3.connect(log.path)
    forged = events[3].model_dump()
    forged["timestamp"] = events[3].timestamp.isoformat()
    forged["id"] = "forged"
    cols = ", ".join(forged)
    conn.execute(
        f"INSERT INTO audit_events ({cols}) VALUES ({', '.join('?' * len(forged))})",
        tuple(forged.values()),
    )
    conn.commit()
    conn.close()
    result = verify_chain(log.events())
    assert not result.chain_valid and result.first_broken_link == N
    assert result.total_events_checked == N + 1


def test_verifier_reports_only_the_first_break(events: list[AuditEvent]) -> None:
    doubly = _mutated(_mutated(events, 2, actor="mallory"), 5, actor="trent")
    assert verify_chain(doubly).first_broken_link == 2


def test_persisted_file_can_be_verified_read_only(tmp_path: Path) -> None:
    """The Documenter role: open the file, verify, never write. A second, read-only handle on
    the same SQLite file must see exactly the chain the service wrote."""
    db = tmp_path / "audit.db"
    log = AuditLog(db)
    for i in range(3):
        log.append("alice", "update", "t", f"R-{i}")
    rows = (
        sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        .execute("SELECT entry_hash FROM audit_events ORDER BY rowid")
        .fetchall()
    )
    assert [r[0] for r in rows] == [e.entry_hash for e in log.events()]
