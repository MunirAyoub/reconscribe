"""ReconScribe API — paste a domain, get an AI-drafted vulnerability report.

Passive recon only. See vault: Projects/ReconScribe/.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from . import db, export
from .config import settings
from .guardrails import ScanNotAllowed, assert_scannable, normalize_domain
from .llm.analyze import analyze
from .models import Report, ScanRequest, ScanSummary
from .scanner import collect_raw


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="ReconScribe", version="0.1.0", lifespan=lifespan)

# Dev CORS — the Vite frontend runs on :5173.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "model": settings.reconscribe_model}


@app.post("/scan", response_model=Report)
async def scan(req: ScanRequest) -> Report:
    if not req.authorized:
        raise HTTPException(
            status_code=403,
            detail="You must confirm you own or are authorized to scan this domain.",
        )

    try:
        domain = normalize_domain(req.domain)
        assert_scannable(domain)
    except ScanNotAllowed as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    raw = await collect_raw(domain)

    note = ""
    try:
        findings = analyze(domain, raw)
    except Exception as exc:  # LLM step failed — still return raw context
        findings = []
        note = f"Recon ran but the analysis step failed: {exc}"

    report = Report(
        domain=domain,
        findings=findings,
        raw_count=len(raw),
        model=settings.reconscribe_model,
        note=note,
    )
    return db.save_report(report)


@app.get("/scans", response_model=list[ScanSummary])
async def list_scans() -> list[ScanSummary]:
    return db.list_scans()


@app.get("/scans/{scan_id}", response_model=Report)
async def get_scan(scan_id: int) -> Report:
    report = db.get_report(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return report


def _load_or_404(scan_id: int) -> Report:
    report = db.get_report(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return report


@app.get("/scans/{scan_id}/report.md")
async def export_markdown(scan_id: int) -> Response:
    report = _load_or_404(scan_id)
    return Response(
        content=export.to_markdown(report),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="{export.report_filename(report, "md")}"'},
    )


@app.get("/scans/{scan_id}/report.pdf")
async def export_pdf(scan_id: int) -> Response:
    report = _load_or_404(scan_id)
    return Response(
        content=export.to_pdf(report),
        media_type="application/pdf",
        headers={"Content-Disposition":
                 f'attachment; filename="{export.report_filename(report, "pdf")}"'},
    )
