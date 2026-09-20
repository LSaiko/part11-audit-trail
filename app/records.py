"""Minimal electronic record store: every write is logged to the append-only audit trail.

Records are the Part 11 "electronic records" that get signed. Each ``put`` appends an
``AuditEvent`` whose ``after_hash`` is the sha256 of the new content, so the trail carries
an Accurate, Original fingerprint of every version (11.10(e)).
# ponytail: in-memory dict, current version only. Ceiling: history lives solely in the
# audit trail's ``after_hash`` values. Upgrade path: versioned table keyed by record hash.
"""

from __future__ import annotations

from typing import Any

from app.log_service import AuditLog
from crypto.hashing import record_hash
from schemas import AuditEvent


class RecordStore:
    def __init__(self, log: AuditLog) -> None:
        self._log = log
        self._records: dict[str, tuple[str, dict[str, Any]]] = {}  # id -> (type, content)

    def put(
        self, actor: str, record_type: str, record_id: str, content: dict[str, Any]
    ) -> AuditEvent:
        """Create or replace a record and log it (``create`` / ``update``) with its hash."""
        action = "update" if record_id in self._records else "create"
        self._records[record_id] = (record_type, dict(content))
        return self._log.append(actor, action, record_type, record_id, record_hash(content))

    def get(self, record_id: str) -> dict[str, Any]:
        return dict(self._records[record_id][1])

    def record_type(self, record_id: str) -> str:
        return self._records[record_id][0]

    def current_hash(self, record_id: str) -> str:
        return record_hash(self._records[record_id][1])
