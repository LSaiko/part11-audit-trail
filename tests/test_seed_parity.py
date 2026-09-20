"""Hash parity between crypto/hashing.py and dashboard/src/verify.ts.

``tests/seed_parity.json`` holds fixed inputs plus the sha256 digests Python produces for them.
This test pins the Python side; ``dashboard/scripts/check-seed.mjs`` (run in ``npm run build``)
computes the same inputs with the TypeScript verifier and asserts the identical digests, so the
Pages seed chain is verified by code proven equivalent to the server's (ALCOA+ Consistent).
"""

import json
from pathlib import Path

from crypto.hashing import entry_hash, record_hash

FIXTURE = Path(__file__).with_name("seed_parity.json")


def test_python_side_matches_fixture() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for case in fixture["entry_hash"]:
        args = case["args"]
        assert entry_hash(*args[:5], record_type=args[5], after_hash=args[6]) == case["expected"]
    for case in fixture["record_hash"]:
        assert record_hash(case["content"]) == case["expected"]
    assert len(fixture["entry_hash"]) >= 3 and len(fixture["record_hash"]) >= 3
