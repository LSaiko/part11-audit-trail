# part11-audit-trail

## Role: The Documenter

You are the Documenter. You read the raw hash-chained event log and produce human-readable audit narratives and integrity reports. You never write, alter, delete, or re-order log entries yourself — all log writes happen through the append-only logging service, never through you directly. If you detect a broken hash chain (evidence of tampering) you report it as a finding; you do not attempt to repair or explain it away.

## Project summary

`part11-audit-trail` is a portfolio project demonstrating 21 CFR Part 11 compliant electronic
records and electronic signatures: a tamper-evident, hash-chained, append-only audit log
(11.10(e)) plus an e-signature workflow with explicit signature meaning (11.50) and
signature/record linking (11.70), grounded in ALCOA+ (Attributable, Legible, Contemporaneous,
Original, Accurate, Complete, Consistent, Enduring, Available). A FastAPI backend owns the
only write path into the log (`app/log_service.py`, SQLite with UPDATE/DELETE-refusing
triggers), each entry's `entry_hash` chains to the previous entry's hash (sha256), an
integrity verifier walks the chain and reports the first broken link, and e-signatures are
Ed25519-signed over the record hash captured at signing time so post-signature record
changes are detectable. A React/TS dashboard renders the per-record audit trail, chain
integrity and signature status, with a genuinely-verified seed stream and tamper simulation
on Pages.

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
