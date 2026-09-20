"""Append-only audit log: the only write path into the Part 11 trail (11.10(e)).

Every entry is Attributable (``actor``), Contemporaneous (server-set UTC timestamp) and
Original (``entry_hash`` chained to the previous entry's hash). Storage is stdlib
``sqlite3``; append-only is enforced *at the storage layer* by ``BEFORE UPDATE`` /
``BEFORE DELETE`` triggers that ``RAISE(ABORT)``, so even raw SQL cannot alter or remove
history (ALCOA+ Enduring, Complete). This class exposes no modify/delete method.

Limitation: truncating the *tail* of the log (dropping the newest N rows, e.g. by restoring
an older copy of the file) is not detectable by the hash chain alone, because every
remaining link still verifies.
# ponytail: single SQLite file, no checkpoints. Ceiling: tail truncation undetectable.
# Upgrade path: periodically sign the head ``entry_hash`` + row count with the Ed25519
# server key and store it out-of-band; the verifier then checks the current head against
# the last checkpoint.
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

from crypto.hashing import entry_hash
from schemas import GENESIS_HASH, AuditEvent

_COLUMNS = (
    "id",
    "timestamp",
    "actor",
    "action",
    "record_type",
    "record_id",
    "before_hash",
    "after_hash",
    "entry_hash",
)
_COLS = ", ".join(_COLUMNS)
_DDL = f"""
CREATE TABLE IF NOT EXISTS audit_events (
    rowid INTEGER PRIMARY KEY AUTOINCREMENT,
    {", ".join(f"{c} TEXT" for c in _COLUMNS)}
);
CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
"""
_INSERT = f"INSERT INTO audit_events ({_COLS}) VALUES ({', '.join('?' * len(_COLUMNS))})"
_SELECT = f"SELECT {_COLS} FROM audit_events"


class AuditLog:
    """Append-only, hash-chained audit trail backed by SQLite.

    ``path`` defaults to ``os.getenv("AUDIT_DB_PATH", ":memory:")``; ``":memory:"`` keeps
    the trail in-process (tests, demos), any other value is a ``pathlib.Path``.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        raw = str(path) if path is not None else os.getenv("AUDIT_DB_PATH", ":memory:")
        target = raw if raw == ":memory:" else Path(raw)
        self._conn = sqlite3.connect(target, isolation_level=None)  # autocommit
        self._conn.executescript(_DDL)

    @property
    def path(self) -> str:
        """Resolved database location (``":memory:"`` or the file path)."""
        return str(self._conn.execute("PRAGMA database_list").fetchone()[2] or ":memory:")

    def append(
        self,
        actor: str,
        action: str,
        record_type: str,
        record_id: str,
        after_hash: str | None = None,
    ) -> AuditEvent:
        """Append one entry. Timestamp is server-generated UTC (Contemporaneous);
        ``before_hash`` is the previous entry's ``entry_hash`` (``GENESIS_HASH`` first)."""
        last = self._conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        before = last[0] if last else GENESIS_HASH
        timestamp = datetime.now(UTC)
        event = AuditEvent(
            id=str(uuid.uuid4()),
            timestamp=timestamp,
            actor=actor,
            action=action,
            record_type=record_type,
            record_id=record_id,
            before_hash=before,
            after_hash=after_hash,
            entry_hash=entry_hash(
                before,
                actor,
                action,
                record_id,
                timestamp.isoformat(),
                record_type=record_type,
                after_hash=after_hash or "",
            ),
        )
        row = event.model_dump()
        row["timestamp"] = timestamp.isoformat()
        self._conn.execute(_INSERT, tuple(row[c] for c in _COLUMNS))
        return event

    def events(self) -> list[AuditEvent]:
        """All entries in append order (ordered by rowid)."""
        return self._rows(f"{_SELECT} ORDER BY rowid", ())

    def events_for(self, record_id: str) -> list[AuditEvent]:
        """Entries touching one electronic record, in append order."""
        return self._rows(f"{_SELECT} WHERE record_id = ? ORDER BY rowid", (record_id,))

    def _rows(self, sql: str, params: tuple[str, ...]) -> list[AuditEvent]:
        return [
            AuditEvent.model_validate(dict(zip(_COLUMNS, row, strict=True)))
            for row in self._conn.execute(sql, params)
        ]
