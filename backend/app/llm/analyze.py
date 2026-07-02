"""Turn raw recon facts into structured Findings via Claude (ADR-002/003).

We force the `record_findings` tool so the model returns a strict JSON array,
never prose we'd have to parse.
"""

from __future__ import annotations

import json

from ..config import settings
from ..models import Finding, RawFinding
from .client import get_client
from .prompts import RECORD_FINDINGS_TOOL, SYSTEM

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def analyze(domain: str, raw: list[RawFinding]) -> list[Finding]:
    if not raw:
        return []

    facts = "\n".join(f"- [{f.module}] {f.evidence} ({f.url})" for f in raw)
    user = (
        f"Target: {domain}\n\n"
        f"Raw passive-recon observations:\n{facts}\n\n"
        "Produce the findings via the record_findings tool."
    )

    client = get_client()
    resp = client.messages.create(
        model=settings.reconscribe_model,
        max_tokens=4096,
        # Forced tool_choice is incompatible with extended thinking, so disable it
        # for this structured-extraction call.
        thinking={"type": "disabled"},
        system=SYSTEM,
        tools=[RECORD_FINDINGS_TOOL],
        tool_choice={"type": "tool", "name": "record_findings"},
        messages=[{"role": "user", "content": user}],
    )

    for block in resp.content:
        if block.type == "tool_use" and block.name == "record_findings":
            # block.input is already parsed JSON; validate through Pydantic.
            items = block.input.get("findings", []) if isinstance(block.input, dict) else []
            findings = [Finding(**item) for item in items]
            findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 5), -f.cvss))
            return findings

    # Model didn't emit the tool (rare with forced tool_choice) — fail loudly.
    raise RuntimeError(f"Claude did not return findings: {json.dumps([b.type for b in resp.content])}")
