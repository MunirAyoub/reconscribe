"""Shared data shapes. See vault: Projects/ReconScribe/Architecture — Key Contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["Critical", "High", "Medium", "Low", "Info"]


class ScanRequest(BaseModel):
    domain: str = Field(..., examples=["example.com"])
    # The authorization gate — the UI must send this as true (ADR-001).
    authorized: bool = False


class RawFinding(BaseModel):
    """A dumb fact emitted by a recon module — no severity, no judgment."""

    module: str          # which recon check produced it, e.g. "headers"
    kind: str            # short machine label, e.g. "missing_csp"
    evidence: str        # the observed fact / snippet
    url: str = ""        # where it was observed


class Finding(BaseModel):
    """A finding after Claude has classified and explained it (llm/analyze.py)."""

    severity: Severity
    cwe: str
    cvss: float
    title: str
    impact: str
    recommendation: str
    evidence: str


class Report(BaseModel):
    domain: str
    findings: list[Finding]
    raw_count: int
    model: str
    note: str = ""       # e.g. warnings when the LLM step was skipped
    # Set once the report is persisted (db.py). Absent on a fresh, unsaved scan.
    id: int | None = None
    created_at: str | None = None   # ISO-8601 UTC


class ScanSummary(BaseModel):
    """A row in the scan-history list (GET /scans) — no findings body."""

    id: int
    domain: str
    created_at: str
    finding_count: int
    raw_count: int
    model: str
