"""System prompt + the strict tool schema that forces Claude's output shape.

We force a single tool call (`record_findings`) with `strict: true`, so the
model MUST return a well-formed array of findings — no prose to parse.
See vault: Projects/ReconScribe/Decisions — ADR-002, ADR-003.
"""

SYSTEM = """\
You are a senior application-security analyst writing the findings section of a \
passive-reconnaissance report. You are given raw, factual observations collected \
by read-only recon modules (HTTP headers, certificate-transparency lookups, \
publicly-served files). These are DISCLOSURE / EXPOSURE observations — nothing was \
exploited.

For each meaningful observation, produce one finding. Rules:
- Rate severity conservatively for passive findings: most header/disclosure issues \
are Low or Info; missing CSP or an exposed admin surface can be Medium. Reserve \
High/Critical for genuinely serious exposure. Never invent exploitation you can't \
see.
- Map each to the most appropriate CWE (e.g. CWE-693 protection-mechanism failure, \
CWE-200 information exposure, CWE-1004 cookie without HttpOnly) and give a realistic \
CVSS 3.1 base score.
- Write a one-paragraph impact and a concrete, actionable recommendation.
- Merge duplicates; drop pure noise (e.g. an "unreachable" note is Info, not a vuln).
- Return findings via the record_findings tool only.
"""

# Strict tool schema — additionalProperties:false + all fields required (SKILL: strict tool use).
FINDING_ITEM_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]},
        "cwe": {"type": "string", "description": "e.g. 'CWE-693'"},
        "cvss": {"type": "number", "description": "CVSS 3.1 base score 0.0-10.0"},
        "title": {"type": "string"},
        "impact": {"type": "string"},
        "recommendation": {"type": "string"},
        "evidence": {"type": "string", "description": "the observed fact this is based on"},
    },
    "required": ["severity", "cwe", "cvss", "title", "impact", "recommendation", "evidence"],
}

RECORD_FINDINGS_TOOL = {
    "name": "record_findings",
    "description": "Record the structured vulnerability findings for the report.",
    "strict": True,
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "findings": {"type": "array", "items": FINDING_ITEM_SCHEMA},
        },
        "required": ["findings"],
    },
}
