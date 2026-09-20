# Architecture

`part11-audit-trail` demonstrates 21 CFR Part 11 electronic records and electronic
signatures with ALCOA+ data-integrity properties enforced in code rather than by procedure.

## Write path (11.10(e) audit trail)

```
client -> app (only writer) -> AuditLog.append() -> SQLite audit_events (append-only triggers)
                                     |
                                     +-> entry_hash = sha256(before_hash US actor US action ...)
```

- `app/log_service.py` — `AuditLog` is the single write path. Timestamps are server-set UTC
  (Contemporaneous); `before_hash` links to the previous `entry_hash`, genesis is `"0"*64`.
  `BEFORE UPDATE` / `BEFORE DELETE` triggers `RAISE(ABORT)`, so raw SQL cannot rewrite
  history (Enduring, Complete). No public modify/delete method exists.
- `crypto/hashing.py` — `entry_hash` joins fields with ASCII Unit Separator `\x1f` so field
  boundaries are unambiguous; `record_hash` canonicalises JSON (`sort_keys`, compact
  separators) so equivalent content always hashes the same (Consistent).
- `app/verifier.py` — `verify_chain` recomputes every hash and reports
  `first_broken_link`. Detects mutation, re-ordering, mid-chain deletion or insertion.
  **Limitation:** tail truncation is invisible to the chain alone; upgrade path is a
  periodically signed checkpoint of the head hash.

## Signature path (11.50, 11.70, 11.100, 11.200)

- `app/auth.py` — demo username/password (scrypt, `hmac.compare_digest`). Production needs
  two identification components (11.200(a)(1)) and the 11.300 credential controls.
- `app/records.py` — the electronic records; every `put` is logged with the content hash.
- `app/signatures.py` — `SignatureService.sign` authenticates, captures the record hash,
  builds an `ESignature` with an explicit `meaning` (11.50(a)(3)), Ed25519-signs its
  canonical JSON (`crypto/signing.py`), and appends an `esign:<meaning>` event. Failed
  authentication is logged as `esign:auth_failed` before raising. `verify` re-checks the
  signature and compares the captured hash with the record's current hash, so a
  post-signature edit shows as `record_hash_matches=False` while the signature itself stays
  authentic (11.70 linking).
- Signing key: `AUDIT_SIGNING_KEY` (base64 32-byte seed) via `os.getenv`; ephemeral key
  with a WARNING when unset. The key is never logged or hardcoded.

## The Documenter

The agent role for this repo reads the trail and writes narratives and integrity reports;
it never writes, alters, deletes or re-orders entries, and reports a broken chain as a
finding rather than repairing it (see `CLAUDE.md`).

## Layering rule

`/crypto` takes plain `str` / `bytes` / `dict` and never imports `/app` or `/schemas`
(`grep -r "from app\|import app\|from schemas" crypto/` must stay empty).
