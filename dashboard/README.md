# dashboard

React/TS (Vite) audit viewer in the portfolio palette `#22d3ee` (valid) / `#f97316` (broken) /
`#94a3b8` (neutral). Live mode talks to the FastAPI backend on `:8011` (`VITE_API_BASE` to
override); seed mode (Pages, or API unreachable) verifies a synthetic stream in the browser
with `src/verify.ts`, a mirror of `crypto/hashing.py` + `app/verifier.py`.

- `npm run dev` -- live mode against `uvicorn app.main:app --port 8011`
- `npm run build` -- `tsc -b`, then `scripts/check-seed.mjs` (hash parity with Python via
  `tests/seed_parity.json`; requires Node >= 22.18), then `vite build`
- `VITE_BASE=/part11-audit-trail/ npm run build` -- Pages build (seed mode)
- `?tamper=1` -- open with the "Simulate tampering" toggle pre-enabled
