"""sha256 primitives for the Part 11 hash chain (11.10(e)). Pure functions, stdlib only.

Isolated by design: takes plain ``str`` / ``bytes`` / ``dict`` and never imports ``app`` or
``schemas``. Well-vetted primitive only (``hashlib.sha256``); no homegrown scheme.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# ASCII Unit Separator: a control character that never appears in actor/action/record-id
# strings, so field boundaries are unambiguous ("ab"+"c" can never collide with "a"+"bc").
# A printable delimiter such as "|" could legitimately occur inside a field.
DELIMITER = "\x1f"


def entry_hash(
    before_hash: str,
    actor: str,
    action: str,
    record_id: str,
    timestamp_iso: str,
    *,
    record_type: str = "",
    after_hash: str = "",
) -> str:
    """sha256 over the canonical, delimiter-separated entry fields chained to ``before_hash``.

    ``record_type`` and ``after_hash`` are keyword-only extras so the chain stays Complete
    (ALCOA+): a tampered record type or content hash breaks the chain too. ``after_hash`` is
    ``""`` when the event carries none.
    """
    canonical = DELIMITER.join(
        (before_hash, actor, action, record_type, record_id, timestamp_iso, after_hash)
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def record_hash(content: dict[str, Any] | bytes) -> str:
    """sha256 of an electronic record's content.

    ``dict`` content is canonicalised with ``json.dumps(sort_keys=True, separators=(",", ":"))``
    so key order and whitespace never change the hash (ALCOA+ Consistent).
    """
    raw = (
        content
        if isinstance(content, bytes)
        else json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return hashlib.sha256(raw).hexdigest()
