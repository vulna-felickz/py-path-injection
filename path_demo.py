from fastapi import FastAPI, HTTPException
from pathlib import Path
import re

app = FastAPI()

# ---------------------------------------------------------------------------
# Shared config
# ---------------------------------------------------------------------------

SCAN_RESULTS_DIR = Path("/app/scan-results").resolve()


# ---------------------------------------------------------------------------
# UNSAFE endpoint — user input flows directly into filesystem path
# ---------------------------------------------------------------------------

@app.get("/report-unsafe")
def fetch_report_unsafe(scan_id: str):
    """
    ⚠️  VULNERABLE: scan_id is concatenated into the base path with zero
    validation.  An attacker can supply  ../../etc  or any other traversal
    sequence and escape the intended directory entirely.

    Example attack:
        GET /report-unsafe?scan_id=../../etc
        → base resolves to /etc, rglob walks the whole subtree
    """
    # scan_id flows straight in — no resolve, no boundary check
    base = Path(f"/app/scan-results/{scan_id}")

    hits = list(base.rglob("findings_report.md"))
    if not hits:
        hits = [f for f in base.rglob("*.md") if f.is_file()]

    if not hits:
        raise HTTPException(status_code=404, detail="No report located for this scan.")

    # first match is returned — could be a file anywhere on disk
    return {"path": str(hits[0]), "content": hits[0].read_text()}


# ---------------------------------------------------------------------------
# SAFE endpoint — path is sanitized before touching the filesystem
# ---------------------------------------------------------------------------

_SAFE_SCAN_ID = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


@app.get("/report-safe")
def fetch_report_safe(scan_id: str):
    """
    ✅  SAFE: two independent guards prevent path traversal.

    Guard 1 — allowlist regex:
        Reject scan_id values that contain slashes, dots, or any other
        character that could be used to escape the directory.  This stops
        most attacks before the filesystem is touched at all.

    Guard 2 — resolve + boundary check:
        Even if guard 1 were somehow bypassed, resolve() collapses all
        ../ sequences into an absolute path and we verify that the result
        still sits under SCAN_RESULTS_DIR.
    """
    # Guard 1: only accept safe characters in the ID
    if not _SAFE_SCAN_ID.match(scan_id):
        raise HTTPException(status_code=400, detail="scan_id contains invalid characters.")

    # Guard 2: resolve to an absolute path and confirm it is inside the root
    base = (SCAN_RESULTS_DIR / scan_id).resolve()

    if not str(base).startswith(str(SCAN_RESULTS_DIR) + "/"):
        raise HTTPException(status_code=400, detail="Access denied — path traversal detected.")

    if not base.is_dir():
        raise HTTPException(status_code=404, detail="Scan directory not found.")

    hits = list(base.rglob("findings_report.md"))
    if not hits:
        hits = [f for f in base.rglob("*.md") if f.is_file()]

    if not hits:
        raise HTTPException(status_code=404, detail="No report located for this scan.")

    return {"path": str(hits[0]), "content": hits[0].read_text()}
