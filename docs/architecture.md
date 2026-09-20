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

## HTTP surface (`app/main.py`)

Module-level singletons `log -> records -> signatures` give the process exactly one write
path. `POST /events` is the internal ingest for other services: `AuditEventIn` forbids
`timestamp` and hash fields (server-set, Contemporaneous), and the endpoint is guarded by the
`X-Audit-Token` header compared against `AUDIT_INTERNAL_TOKEN` with `hmac.compare_digest`;
when the variable is unset the endpoint is open for demos and one WARNING is logged at
startup. `PUT /records/{type}/{id}` is the demo record write (logged with the content hash),
`POST /sign` returns 401 on bad credentials (the attempt is logged as `esign:auth_failed`,
the password never is) and 404 for an unknown record.

`GET /audit-trail/{record_id}` returns the record's events **plus the integrity result of the
full chain**: a per-record view is only trustworthy if every link in the log verifies, since
a break anywhere means entries touching this record could have been altered, re-ordered or
removed. `first_broken_link` therefore indexes the full chain, and the dashboard maps each
row back to its global position.

## Dashboard (`dashboard/`)

React/TS viewer: record selector, chronological trail table (hashes truncated to 8 chars,
full digest on hover), chain-integrity banner (`CHAIN INTACT - N events verified` /
`CHAIN BROKEN at entry #k` with row *k* highlighted) and a signatures panel with a status
pill per signature (`VERIFIED`, `RECORD CHANGED SINCE SIGNING`, `SIGNATURE INVALID`). Status
is always carried by text; colour (`#22d3ee` ok, `#f97316` broken, `#94a3b8` neutral) only
reinforces it.

- **Live mode** (`VITE_BASE=/`, API answering `/health`): the server is the verifier.
- **Seed mode** (Pages, or API unreachable): `seed.ts` builds 12 events across three
  records at load time, hashing them with `verify.ts`, a mirror of `crypto/hashing.py` +
  `app/verifier.py` (same `\x1f` delimiter, field order and sorted-key compact JSON with
  `ensure_ascii` escaping). The "Simulate tampering" toggle (`?tamper=1` pre-enables it)
  rewrites entry #5's actor in place and edits SOP-017 after its signature, then re-runs the
  client-side verifier, so the broken state is detected, not painted on.
- **Parity proof**: `tests/seed_parity.json` holds fixed inputs and the digests Python
  produces (pinned by `tests/test_seed_parity.py`); `dashboard/scripts/check-seed.mjs` runs
  in `npm run build` and asserts the TypeScript verifier reproduces every digest, that the
  seed chain is intact, and that the tampered copy breaks at index 4.

Screenshots: `docs/dashboard.png` (intact), `docs/dashboard-tampered.png` (tampered).

## The Documenter

The agent role for this repo reads the trail and writes narratives and integrity reports;
it never writes, alters, deletes or re-orders entries, and reports a broken chain as a
finding rather than repairing it (see `CLAUDE.md`).

## Layering rule

`/crypto` takes plain `str` / `bytes` / `dict` and never imports `/app` or `/schemas`
(`grep -r "from app\|import app\|from schemas" crypto/` must stay empty).
