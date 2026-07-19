"""
EDDMC - Distributed Behavioural Fingerprint Registry Server

A standalone service, independent of any single EDDMC daemon instance.
Nodes submit confirmed CRITICAL-tier behavioural fingerprints here (via
daemon/fingerprint/submitter.py); other nodes download the confirmed set
(via daemon/fingerprint/matcher.py) to accelerate detection of known
mining variants without requiring a full local observation window.

No file paths, process arguments, usernames or raw hostnames are ever
received -- only normalised feature ratios, a one-way hostname hash, and
an optional miner-binary SHA-256.

Dev run:
    uvicorn registry.app:app --host 0.0.0.0 --port 8321 --reload

EDDMC_REGISTRY_AUTO_CONFIRM controls whether a submission that passes the
daemon-side confirmation gate is trusted immediately (dev/simulation
default) or held as "pending" for manual review via
POST /api/v1/fingerprints/{id}/confirm (the conservative mode described
in the thesis for a production deployment).
"""

from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from registry import db

AUTO_CONFIRM = os.environ.get("EDDMC_REGISTRY_AUTO_CONFIRM", "true").lower() == "true"

app = FastAPI(title="EDDMC Fingerprint Registry", version="0.1.0")


class FingerprintSubmission(BaseModel):
    fingerprint_id: str
    node_id: str
    submitted_at: float
    eddmc_version: Optional[str] = None
    kernel_version: Optional[str] = None
    process_name: Optional[str] = None
    score_at_submission: Optional[float] = None
    feature_names: list[str] = Field(default_factory=list)
    feature_vector: list[float] = Field(default_factory=list)
    evidence: dict = Field(default_factory=dict)


class AllowlistSubmission(BaseModel):
    sha256: str
    description: Optional[str] = None
    node_id: Optional[str] = None


@app.on_event("startup")
def _startup():
    db.init_db()


@app.post("/api/v1/fingerprints", status_code=202)
def submit_fingerprint(payload: FingerprintSubmission):
    status = db.upsert_submission(payload.model_dump(), auto_confirm=AUTO_CONFIRM)
    return {"fingerprint_id": payload.fingerprint_id, "status": status}


@app.get("/api/v1/fingerprints")
def get_confirmed_fingerprints():
    return db.list_confirmed()


@app.get("/api/v1/fingerprints/pending")
def get_pending_fingerprints():
    return db.list_pending()


@app.get("/api/v1/fingerprints/stats")
def get_stats():
    return db.stats()


@app.post("/api/v1/fingerprints/{fingerprint_id}/confirm")
def confirm_fingerprint(fingerprint_id: str):
    ok = db.confirm(fingerprint_id)
    if not ok:
        raise HTTPException(status_code=404, detail="not found or already confirmed")
    return {"fingerprint_id": fingerprint_id, "status": "confirmed"}


# ── Allowlist (known-good binary hashes) ────────────────────────────────────
# Deliberately no AUTO_CONFIRM here, unlike the fingerprint endpoints above:
# a poisoned entry in a shared allowlist makes every node blind to that exact
# binary, a far worse failure than a missed miner fingerprint, so every
# submission sits "pending" until a human explicitly confirms it -- no
# environment variable can bypass that for this channel.

@app.post("/api/v1/allowlist", status_code=202)
def submit_allowlist(payload: AllowlistSubmission):
    status = db.upsert_allowlist_submission(payload.model_dump())
    return {"sha256": payload.sha256, "status": status}


@app.get("/api/v1/allowlist")
def get_confirmed_allowlist():
    return db.list_allowlist_confirmed()


@app.get("/api/v1/allowlist/pending")
def get_pending_allowlist():
    return db.list_allowlist_pending()


@app.get("/api/v1/allowlist/stats")
def get_allowlist_stats():
    return db.allowlist_stats()


@app.post("/api/v1/allowlist/{sha256}/confirm")
def confirm_allowlist_entry(sha256: str):
    ok = db.confirm_allowlist(sha256)
    if not ok:
        raise HTTPException(status_code=404, detail="not found or already confirmed")
    return {"sha256": sha256, "status": "confirmed"}
