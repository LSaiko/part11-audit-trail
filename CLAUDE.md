# part11-audit-trail

## Role: The Documenter

You are the Documenter. You read the raw hash-chained event log and produce human-readable audit narratives and integrity reports. You never write, alter, delete, or re-order log entries yourself — all log writes happen through the append-only logging service, never through you directly. If you detect a broken hash chain (evidence of tampering) you report it as a finding; you do not attempt to repair or explain it away.

## Project summary

`part11-audit-trail` is a portfolio project demonstrating 21 CFR Part 11 electronic records
and electronic signatures as structural properties, grounded in ALCOA+ (every principle maps
to one tested decision in the README). Built:

- `app/log_service.py` `AuditLog`: the only write path. SQLite `audit_events` with
  `BEFORE UPDATE` / `BEFORE DELETE` triggers that `RAISE(ABORT)`; server-set UTC timestamps;
  `entry_hash = sha256(before_hash US actor US action US record_type US record_id US ts US
  after_hash)` chained to the previous entry (`GENESIS_HASH = "0"*64`); a lock serialises
  read-head + insert so concurrent appends chain correctly (11.10(e)).
- `app/verifier.py` `verify_chain`: recomputes every hash, reports `first_broken_link` (the
  Documenter reports, never repairs). Tail truncation is the documented blind spot
  (`# ponytail:` upgrade path: signed head checkpoint).
- `app/auth.py` (scrypt + `hmac.compare_digest`, demo single-factor), `app/records.py`
  (in-memory records, every put logged with `record_hash`), `app/signatures.py`
  (`POST /sign`: authenticate, capture record hash, Ed25519-sign the canonical JSON of an
  `ESignature` with explicit `meaning`, log `esign:<meaning>`; failed auth logged as
  `esign:auth_failed`; `verify` reports `signature_valid` and `record_hash_matches`
  independently, 11.50 / 11.70).
- `app/main.py`: `POST /events` internal ingest guarded by `X-Audit-Token`
  (`AUDIT_INTERNAL_TOKEN`), `AuditEventIn extra="forbid"` rejects client `timestamp` / hashes
  with 422; `GET /audit-trail/{id}` returns one record's events plus full-chain integrity.
- `crypto/` (`hashing.py`, `signing.py`): stdlib sha256 + `cryptography` Ed25519, isolated.
- `dashboard/`: React/TS viewer; `src/verify.ts` mirrors the Python hashing;
  `scripts/check-seed.mjs` (Node >= 22.18) proves digest parity against
  `tests/seed_parity.json` at build time; seed mode on Pages with `?tamper=1` simulation.
- `tests/`: 94 tests, 100% line + branch coverage gated in CI (`--cov-fail-under=100`);
  tamper tests cover mutation of every field at first/middle/last, re-order, mid-chain
  delete/insert, raw-SQL bypass, concurrent appends, signature replay / re-attribution /
  transplant, cross-key verification.

Known limitations (README): tail truncation, single server signing key, demo auth,
in-memory records and signatures. Related projects: `sop-review-tool` and `capa-tracker`
(`ClosureRecord.closed_by` hook) consume the signature workflow; `traceability-matrix-dhf`
consumes audit records as DHF evidence; `ml-samd-validator` is the sibling Inspector.

## Non-negotiable constraints

- Pydantic v2 syntax for every schema
- `pathlib.Path` exclusively, no `os.path`; no OS-specific paths
- `os.getenv()` for all secrets/API keys/config, never hardcoded; signing keys are never
  hardcoded and never logged
- Climb the ladder before writing custom code: stdlib -> platform native -> installed
  dependency -> one-liner -> only then custom logic (ponytail discipline); mark deliberate
  simplifications with `# ponytail:` comments naming the ceiling and upgrade path
- Well-vetted crypto primitives only: `hashlib.sha256` for chaining, the `cryptography`
  library (Ed25519) for signatures; never a homegrown scheme
- `/crypto` never imports from `/app` or `/schemas`; it takes plain `str` / `bytes`
- 21 CFR Part 11 and ALCOA+ language in every doc, docstring and report
- Portfolio palette for any UI: `#22d3ee`, `#f97316`, `#94a3b8`

## Layout

- `/app` FastAPI backend (`log_service.py`, `verifier.py`, `auth.py`, `records.py`, `signatures.py`)
- `/crypto` hashing and signing primitives (stdlib `hashlib` + `cryptography`); isolated
- `/dashboard` React/TS frontend (Vite, Chart.js)
- `/schemas` Pydantic v2 models
- `/tests` pytest
- `/docs` architecture, integrity-report docs
- `/.github/workflows` CI + Pages deploy

## Dev commands

- `python -m venv .venv` then `.venv/Scripts/pip install -e .[dev]`
- `.venv/Scripts/python -m pytest`; `ruff check .`; `mypy app schemas crypto`
- `uvicorn app.main:app --reload --port 8011`
- `cd dashboard && npm install && npm run build` (runs `scripts/check-seed.mjs` hash-parity proof)
