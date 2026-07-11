"""
EDDMC Distributed Behavioural Fingerprint Registry - SQLite storage layer.

A submission is stored the first time it is seen (status "pending" or,
in dev/auto-confirm mode, immediately "confirmed"). Re-submissions of an
identical fingerprint_id (the same behavioural signature re-observed,
possibly on a different node) only bump submission_count -- they never
create duplicate rows.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time

DB_PATH = os.environ.get(
    "EDDMC_REGISTRY_DB", os.path.join(os.path.dirname(__file__), "registry.db")
)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fingerprints (
                fingerprint_id       TEXT PRIMARY KEY,
                node_id              TEXT NOT NULL,
                process_name         TEXT,
                score_at_submission  REAL,
                feature_names        TEXT NOT NULL,
                feature_vector       TEXT NOT NULL,
                evidence             TEXT,
                eddmc_version        TEXT,
                kernel_version       TEXT,
                status               TEXT NOT NULL DEFAULT 'pending',
                submission_count     INTEGER NOT NULL DEFAULT 1,
                first_submitted_at   REAL NOT NULL,
                last_submitted_at    REAL NOT NULL,
                confirmed_at         REAL
            )
            """
        )
        conn.commit()


def upsert_submission(payload: dict, auto_confirm: bool) -> str:
    now = time.time()
    fid = payload["fingerprint_id"]
    with _connect() as conn:
        row = conn.execute(
            "SELECT status FROM fingerprints WHERE fingerprint_id = ?", (fid,)
        ).fetchone()

        if row is None:
            status = "confirmed" if auto_confirm else "pending"
            conn.execute(
                """INSERT INTO fingerprints
                   (fingerprint_id, node_id, process_name, score_at_submission,
                    feature_names, feature_vector, evidence, eddmc_version,
                    kernel_version, status, submission_count,
                    first_submitted_at, last_submitted_at, confirmed_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    fid,
                    payload.get("node_id"),
                    payload.get("process_name"),
                    payload.get("score_at_submission"),
                    json.dumps(payload.get("feature_names", [])),
                    json.dumps(payload.get("feature_vector", [])),
                    json.dumps(payload.get("evidence", {})),
                    payload.get("eddmc_version"),
                    payload.get("kernel_version"),
                    status,
                    1,
                    now,
                    now,
                    now if status == "confirmed" else None,
                ),
            )
            conn.commit()
            return status

        conn.execute(
            "UPDATE fingerprints SET submission_count = submission_count + 1, "
            "last_submitted_at = ? WHERE fingerprint_id = ?",
            (now, fid),
        )
        conn.commit()
        return row["status"]


def confirm(fingerprint_id: str) -> bool:
    with _connect() as conn:
        cur = conn.execute(
            "UPDATE fingerprints SET status='confirmed', confirmed_at=? "
            "WHERE fingerprint_id=? AND status!='confirmed'",
            (time.time(), fingerprint_id),
        )
        conn.commit()
        return cur.rowcount > 0


def list_confirmed() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT fingerprint_id, process_name, feature_names, feature_vector, "
            "confirmed_at FROM fingerprints WHERE status='confirmed'"
        ).fetchall()
    return [
        {
            "fingerprint_id": r["fingerprint_id"],
            "process_name": r["process_name"],
            "feature_names": json.loads(r["feature_names"]),
            "feature_vector": json.loads(r["feature_vector"]),
            "confirmed_at": r["confirmed_at"],
        }
        for r in rows
    ]


def list_pending() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT fingerprint_id, node_id, process_name, score_at_submission, "
            "evidence, first_submitted_at FROM fingerprints WHERE status='pending'"
        ).fetchall()
    return [dict(r) for r in rows]


def stats() -> dict:
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM fingerprints").fetchone()["c"]
        pending = conn.execute(
            "SELECT COUNT(*) c FROM fingerprints WHERE status='pending'"
        ).fetchone()["c"]
        confirmed = conn.execute(
            "SELECT COUNT(*) c FROM fingerprints WHERE status='confirmed'"
        ).fetchone()["c"]
        last_row = conn.execute(
            "SELECT MAX(last_submitted_at) t FROM fingerprints"
        ).fetchone()
        by_name = conn.execute(
            "SELECT process_name, COUNT(*) c FROM fingerprints GROUP BY process_name"
        ).fetchall()
    return {
        "total_submissions": total,
        "pending": pending,
        "confirmed": confirmed,
        "last_updated": last_row["t"],
        "by_process_name": {r["process_name"]: r["c"] for r in by_name},
    }
