"""Integrity verifier: walks the hash chain and reports the first broken link.

The Documenter reports a broken chain as a finding; it never repairs or re-orders entries.
Detects mutated fields, mutated ``entry_hash`` / ``before_hash``, re-ordered entries, and
entries deleted from or inserted into the middle. Does NOT detect truncation of the tail
(see ``app.log_service`` for the signed-checkpoint upgrade path).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from crypto.hashing import entry_hash
from schemas import GENESIS_HASH, AuditEvent, IntegrityCheckResult


def verify_chain(events: Sequence[AuditEvent]) -> IntegrityCheckResult:
    """Recompute every ``entry_hash`` and check each ``before_hash`` links to its predecessor
    (``GENESIS_HASH`` for the first). ``first_broken_link`` is the 0-based index of the first
    entry that fails either check."""
    expected_before = GENESIS_HASH
    first_broken: int | None = None
    for index, event in enumerate(events):
        recomputed = entry_hash(
            event.before_hash,
            event.actor,
            event.action,
            event.record_id,
            event.timestamp.isoformat(),
            record_type=event.record_type,
            after_hash=event.after_hash or "",
        )
        if event.before_hash != expected_before or event.entry_hash != recomputed:
            first_broken = index
            break
        expected_before = event.entry_hash
    return IntegrityCheckResult(
        checked_at=datetime.now(UTC),
        chain_valid=first_broken is None,
        first_broken_link=first_broken,
        total_events_checked=len(events),
    )
