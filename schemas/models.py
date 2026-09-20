"""Pydantic v2 schemas for part11-audit-trail (21 CFR Part 11 electronic records / signatures).

ALCOA+ mapping: every ``AuditEvent`` is Attributable (``actor``), Contemporaneous (server-set
``timestamp``), Original and Accurate (``entry_hash`` chains to ``before_hash``, 11.10(e)),
Complete and Consistent (append-only, ordered), Enduring and Available (SQLite file), and
Legible (plain JSON export). Every ``ESignature`` carries an explicit ``meaning`` (11.50) and
is linked to its record by hash (11.70).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

GENESIS_HASH = "0" * 64
_SHA256_HEX = r"^[0-9a-f]{64}$"
SignatureMeaning = Literal["reviewed", "approved", "authored", "rejected"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuditEventIn(_Strict):
    """Client-supplied part of an audit event.

    Deliberately has no ``id``, ``timestamp`` or hash fields: the server generates them so
    the trail is Contemporaneous and cannot be back-dated (11.10(e)); ``extra="forbid"``
    rejects a client-supplied ``timestamp`` at the API boundary.
    """

    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    record_type: str = Field(min_length=1)
    record_id: str = Field(min_length=1)
    after_hash: str | None = Field(default=None, pattern=_SHA256_HEX)


class AuditEvent(_Frozen):
    """One immutable, hash-chained audit trail entry (11.10(e)).

    ``before_hash`` is the previous entry's ``entry_hash`` (``GENESIS_HASH`` for the first
    entry); ``after_hash`` is the sha256 of the record content after the action, when known;
    ``entry_hash`` is the sha256 of this entry's canonical fields chained to ``before_hash``.
    """

    id: str = Field(min_length=1)
    timestamp: datetime
    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    record_type: str = Field(min_length=1)
    record_id: str = Field(min_length=1)
    before_hash: str = Field(pattern=_SHA256_HEX)
    after_hash: str | None = Field(default=None, pattern=_SHA256_HEX)
    entry_hash: str = Field(pattern=_SHA256_HEX)


class ESignature(_Frozen):
    """An electronic signature bound to a record hash with an explicit meaning (11.50, 11.70)."""

    id: str = Field(min_length=1)
    signer: str = Field(min_length=1)
    signed_record_id: str = Field(min_length=1)
    signed_record_hash: str = Field(pattern=_SHA256_HEX)
    timestamp: datetime
    meaning: SignatureMeaning
    signature_method: str = Field(min_length=1)


class IntegrityCheckResult(_Frozen):
    """Outcome of walking the hash chain; ``first_broken_link`` is the 0-based index of the
    first entry whose hashes do not verify (``None`` when the chain is intact)."""

    checked_at: datetime
    chain_valid: bool
    first_broken_link: int | None = Field(default=None, ge=0)
    total_events_checked: int = Field(ge=0)
