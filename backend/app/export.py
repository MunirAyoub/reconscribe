"""Render a stored Report as Markdown or PDF (roadmap: report export).

Both formats share the same structure: a header block (target, date, model,
counts) plus one section per finding, severity-sorted. The PDF uses fpdf2's
core Helvetica (latin-1), so text is sanitized to that range first.
"""

from __future__ import annotations

from fpdf import FPDF

from .models import Report

_PASSIVE_NOTE = "Passive reconnaissance only — no exploitation was performed."

# Severity → an RGB accent, matching the UI's severity colors.
_SEV_RGB = {
    "Critical": (255, 92, 92),
    "High": (255, 157, 77),
    "Medium": (230, 180, 40),
    "Low": (110, 168, 254),
    "Info": (122, 130, 144),
}


def report_filename(report: Report, ext: str) -> str:
    safe = report.domain.replace(".", "-")
    return f"reconscribe-{safe}-{report.id or 'scan'}.{ext}"


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def to_markdown(report: Report) -> str:
    lines = [
        f"# ReconScribe Report — {report.domain}",
        "",
        f"- **Target:** {report.domain}",
        f"- **Scan date:** {report.created_at or 'n/a'}",
        f"- **Analysis model:** {report.model}",
        f"- **Findings:** {len(report.findings)} "
        f"({report.raw_count} raw observations)",
        "",
        f"> {_PASSIVE_NOTE}",
        "",
    ]
    if report.note:
        lines += [f"**Note:** {report.note}", ""]

    if not report.findings:
        lines += ["## Findings", "", "_No findings — nothing notable was publicly exposed._", ""]
        return "\n".join(lines)

    lines += ["## Findings", ""]
    for i, f in enumerate(report.findings, 1):
        lines += [
            f"### {i}. {f.title}",
            "",
            f"- **Severity:** {f.severity}",
            f"- **CWE:** {f.cwe}",
            f"- **CVSS:** {f.cvss}",
            "",
            f"**Impact.** {f.impact}",
            "",
            f"**Recommendation.** {f.recommendation}",
            "",
            f"**Evidence.** `{f.evidence}`",
            "",
            "---",
            "",
        ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #
def _latin1(text: str) -> str:
    """Map common smart punctuation to ASCII, then drop anything outside latin-1."""
    for bad, good in (("’", "'"), ("‘", "'"), ("“", '"'),
                      ("”", '"'), ("–", "-"), ("—", "-"),
                      ("…", "..."), ("→", "->")):
        text = text.replace(bad, good)
    return text.encode("latin-1", "replace").decode("latin-1")


def to_pdf(report: Report) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    epw = pdf.epw  # effective page width

    pdf.set_font("Helvetica", "B", 18)
    pdf.multi_cell(epw, 9, _latin1(f"ReconScribe Report — {report.domain}"))
    pdf.ln(1)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(90, 90, 90)
    meta = (f"Target: {report.domain}    Scan date: {report.created_at or 'n/a'}\n"
            f"Model: {report.model}    Findings: {len(report.findings)} "
            f"({report.raw_count} raw observations)")
    pdf.multi_cell(epw, 5, _latin1(meta))
    pdf.ln(1)
    pdf.set_font("Helvetica", "I", 9)
    pdf.multi_cell(epw, 5, _latin1(_PASSIVE_NOTE))
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)

    if report.note:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(160, 60, 60)
        pdf.multi_cell(epw, 5, _latin1(f"Note: {report.note}"))
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

    if not report.findings:
        pdf.set_font("Helvetica", "I", 11)
        pdf.multi_cell(epw, 6, "No findings - nothing notable was publicly exposed.")
        return bytes(pdf.output())

    for i, f in enumerate(report.findings, 1):
        # Severity chip + title.
        r, g, b = _SEV_RGB.get(f.severity, (122, 130, 144))
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(pdf.get_string_width(f.severity) + 6, 6, f.severity,
                 align="C", fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(3)
        pdf.multi_cell(0, 6, _latin1(f"{i}. {f.title}"))
        pdf.ln(0.5)

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(90, 90, 90)
        pdf.multi_cell(epw, 5, _latin1(f"{f.cwe}  -  CVSS {f.cvss}"))
        pdf.set_text_color(0, 0, 0)

        for label, body in (("Impact.", f.impact),
                            ("Recommendation.", f.recommendation)):
            pdf.set_font("Helvetica", "B", 10)
            pdf.write(5, _latin1(label + " "))
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(epw, 5, _latin1(body))
            pdf.ln(0.5)

        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(90, 90, 90)
        pdf.multi_cell(epw, 4.5, _latin1(f.evidence))
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

    return bytes(pdf.output())
