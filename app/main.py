"""FastAPI surface for the Documenter: audit narratives and integrity reports out.

Every write goes through the module-level singletons (``log`` -> ``records`` ->
``signatures``), so the process has exactly one append-only write path into the Part 11
trail (11.10(e)). The database location comes from ``AUDIT_DB_PATH`` (``os.getenv``, default
in-memory), the signing key from ``AUDIT_SIGNING_KEY`` (see ``crypto/signing.py``).

``POST /events`` is the internal ingest used by other services. It is guarded by a shared
header token, ``X-Audit-Token``, read from ``AUDIT_INTERNAL_TOKEN``. When the variable is
unset the endpoint is open (demo mode) and a single WARNING is logged at startup.
# ponytail: static shared secret compared with ``hmac.compare_digest``. Ceiling: one token
# for all callers, no rotation. Upgrade path: per-service mTLS or signed JWTs.

A record's trail (``GET /audit-trail/{record_id}``) is only trustworthy when the *whole*
chain verifies, so that endpoint returns the full-chain ``IntegrityCheckResult`` alongside
the record's events (ALCOA+ Complete, Consistent). Passwords are never logged or echoed.
"""

from __future__ import annotations

import hmac
import logging
import os
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.log_service import AuditLog
from app.records import RecordStore
from app.signatures import AuthenticationError, SignatureService
from app.verifier import verify_chain
from schemas import (
    AuditEvent,
    AuditEventIn,
    AuditTrail,
    ESignature,
    IntegrityCheckResult,
    RecordIn,
    RecordState,
    SignatureVerification,
    SignRequest,
)

_log = logging.getLogger(__name__)

log = AuditLog()
records = RecordStore(log)
signatures = SignatureService(log, records)


def warn_if_ingest_open() -> None:
    """Log once at startup when ``AUDIT_INTERNAL_TOKEN`` is unset (``POST /events`` is open)."""
    if os.getenv("AUDIT_INTERNAL_TOKEN") is None:
        _log.warning(
            "AUDIT_INTERNAL_TOKEN is unset: POST /events is open (demo mode); "
            "set it to require the X-Audit-Token header"
        )


warn_if_ingest_open()


def require_internal_token(x_audit_token: Annotated[str | None, Header()] = None) -> None:
    """Reject ``POST /events`` unless the header matches ``AUDIT_INTERNAL_TOKEN`` (when set)."""
    expected = os.getenv("AUDIT_INTERNAL_TOKEN")
    if expected is not None and not hmac.compare_digest(x_audit_token or "", expected):
        raise HTTPException(401, "invalid or missing X-Audit-Token")


app = FastAPI(title="part11-audit-trail")
# ponytail: allow-all CORS for the local Vite dev server. Upgrade path: allow-list origins.
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/events", dependencies=[Depends(require_internal_token)])
def post_event(body: AuditEventIn) -> AuditEvent:
    """Internal ingest: the client never supplies ``timestamp`` or hashes (schema forbids)."""
    return log.append(**body.model_dump())


@app.get("/events")
def get_events() -> list[AuditEvent]:
    return log.events()


@app.put("/records/{record_type}/{record_id}")
def put_record(record_type: str, record_id: str, body: RecordIn) -> RecordState:
    event = records.put(body.actor, record_type, record_id, body.content)
    return RecordState(
        record_type=record_type,
        record_id=record_id,
        current_hash=records.current_hash(record_id),
        event=event,
    )


@app.get("/audit-trail/{record_id}")
def get_audit_trail(record_id: str) -> AuditTrail:
    events = log.events_for(record_id)
    if not events:
        raise HTTPException(404, f"no audit events for record {record_id!r}")
    return AuditTrail(record_id=record_id, events=events, integrity=verify_chain(log.events()))


@app.post("/sign")
def post_sign(body: SignRequest) -> ESignature:
    try:
        return signatures.sign(body.username, body.password, body.record_id, body.meaning)
    except KeyError:
        raise HTTPException(404, f"unknown record {body.record_id!r}") from None
    except AuthenticationError:
        raise HTTPException(401, "authentication failed") from None


@app.get("/signatures")
def get_signatures() -> list[ESignature]:
    return signatures.all()


@app.get("/verify-chain")
def get_verify_chain() -> IntegrityCheckResult:
    return verify_chain(log.events())


@app.get("/verify-signature/{signature_id}")
def get_verify_signature(signature_id: str) -> SignatureVerification:
    try:
        return signatures.verify(signature_id)
    except KeyError:
        raise HTTPException(404, f"unknown signature {signature_id!r}") from None
