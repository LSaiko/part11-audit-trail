"""FastAPI surface for the Documenter: audit narratives and integrity reports out.

# ponytail: health endpoint only until the log service and e-signature workflow land.
"""

from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="part11-audit-trail")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
