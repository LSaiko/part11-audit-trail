# part11-audit-trail

21 CFR Part 11 compliant electronic records / electronic signatures demo: a tamper-evident,
hash-chained, append-only audit log plus an e-signature workflow, grounded in ALCOA+
(Attributable, Legible, Contemporaneous, Original, Accurate, Complete, Consistent, Enduring,
Available).

[![Dashboard: chain intact](docs/dashboard.png)](docs/dashboard.png)

Tampered state (`?tamper=1` or the "Simulate tampering" toggle): [docs/dashboard-tampered.png](docs/dashboard-tampered.png)

## What it demonstrates

- **11.10(e) audit trail** -- `AuditLog` is the only write path; SQLite `BEFORE UPDATE` /
  `BEFORE DELETE` triggers refuse rewrites; every `entry_hash` is sha256 over the entry's
  canonical fields chained to the previous entry's hash.
- **Integrity verifier** -- `verify_chain` recomputes every hash and reports the first broken
  link as a finding (the Documenter never repairs).
- **11.50 / 11.70 e-signatures** -- explicit `meaning`, Ed25519 signature over the record hash
  captured at signing time, so a post-signature edit is reported as
  `record_hash_matches=false` while the signature itself stays authentic.
- **Dashboard** -- per-record audit trail, chain-integrity banner with the offending row
  highlighted, signature status pills. On Pages it runs on a seed stream whose hashes are
  computed in the browser by a verifier proven equivalent to the Python one
  (`tests/test_seed_parity.py` + `dashboard/scripts/check-seed.mjs` share one fixture).

## Run it

```
python -m venv .venv && .venv/Scripts/pip install -e .[dev]
.venv/Scripts/python -m pytest --cov=app --cov=schemas --cov=crypto --cov-branch
.venv/Scripts/python -m uvicorn app.main:app --port 8011      # AUDIT_DB_PATH=audit.db to persist
cd dashboard && npm install && npm run dev                     # live mode against :8011
```

```
# create, sign, edit, verify
curl -X PUT localhost:8011/records/sop/SOP-017 -H 'content-type: application/json' \
     -d '{"actor":"alice","content":{"title":"Cleaning SOP","revision":3}}'
curl -X POST localhost:8011/sign -H 'content-type: application/json' \
     -d '{"username":"alice","password":"alice-pw","record_id":"SOP-017","meaning":"approved"}'
curl -X PUT localhost:8011/records/sop/SOP-017 -H 'content-type: application/json' \
     -d '{"actor":"bob","content":{"title":"Cleaning SOP","revision":4}}'
curl localhost:8011/verify-signature/<signature id>   # record_hash_matches: false
curl localhost:8011/verify-chain                      # chain_valid: true (the edit was logged, not hidden)
```

Environment: `AUDIT_DB_PATH` (default in-memory), `AUDIT_SIGNING_KEY` (base64 32-byte seed;
ephemeral key + warning when unset), `AUDIT_DEMO_USERS` (`user:pw,...`, default
`alice:alice-pw,bob:bob-pw`), `AUDIT_INTERNAL_TOKEN` (guards `POST /events`; open + warning
when unset).

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/events` | Internal ingest (`X-Audit-Token`); client cannot supply `timestamp` or hashes |
| `GET` | `/events` | Full chain in append order |
| `PUT` | `/records/{type}/{id}` | Create / replace a record; logged with its content hash |
| `GET` | `/audit-trail/{id}` | One record's events + integrity of the **whole** chain |
| `POST` | `/sign` | Authenticate, capture record hash, Ed25519-sign, log `esign:<meaning>` |
| `GET` | `/signatures` | All captured signatures |
| `GET` | `/verify-chain` | `IntegrityCheckResult` over every event |
| `GET` | `/verify-signature/{id}` | Ed25519 check + captured-vs-current record hash |
