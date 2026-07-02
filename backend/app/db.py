"""SQLite persistence for scans (ADR-005).

Stdlib `sqlite3` — no extra dependency. Each scan is stored as one row: a few
queryable columns for the history list plus the full `Report` serialized as
JSON, so a stored report round-trips exactly. Scans finish in seconds and the
writes are tiny, so we call these synchronously from the routes.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import Report, ScanSummary

# reconscribe.db lives at the backend/ root (next to requirements.txt).
DB_PATH = Path(__file__).resolve().parent.parent / "reconscribe.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the scans table if it doesn't exist. Called at app startup."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                domain        TEXT    NOT NULL,
                created_at    TEXT    NOT NULL,
                finding_count INTEGER NOT NULL,
                raw_count     INTEGER NOT NULL,
                model         TEXT    NOT NULL,
                report_json   TEXT    NOT NULL
            )
            """
        )


def save_report(report: Report) -> Report:
    """Persist a report, then stamp it with its new id + created_at."""
    created_at = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans "
            "(domain, created_at, finding_count, raw_count, model, report_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                report.domain,
                created_at,
                len(report.findings),
                report.raw_count,
                report.model,
                report.model_dump_json(),
            ),
        )
        report.id = cur.lastrowid
        report.created_at = created_at
    return report


def list_scans() -> list[ScanSummary]:
    """Most-recent-first history, without the findings body."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, domain, created_at, finding_count, raw_count, model "
            "FROM scans ORDER BY id DESC"
        ).fetchall()
    return [ScanSummary(**dict(row)) for row in rows]


def get_report(scan_id: int) -> Report | None:
    """Rehydrate a stored report, or None if the id is unknown."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, created_at, report_json FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    if row is None:
        return None
    report = Report.model_validate_json(row["report_json"])
    # The serialized JSON predates the id/created_at stamp — restore them.
    report.id = row["id"]
    report.created_at = row["created_at"]
    return report
