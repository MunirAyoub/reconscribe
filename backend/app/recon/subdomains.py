"""Subdomain enumeration via crt.sh certificate-transparency logs.

Maps to pentest finding F-01 (subdomains discoverable via CT logs). This is a
public lookup against crt.sh — we never probe the discovered hosts here.
"""

from __future__ import annotations

import httpx

from ..models import RawFinding

CRT_SH = "https://crt.sh/"

# Subdomain prefixes that are interesting if they show up (admin surfaces, etc.).
SENSITIVE_PREFIXES = ("admin", "myadmin", "internal", "interno", "dev", "staging",
                      "test", "vpn", "portal", "api", "git", "jenkins", "doe")


async def run(client: httpx.AsyncClient, domain: str) -> list[RawFinding]:
    try:
        resp = await client.get(CRT_SH, params={"q": f"%.{domain}", "output": "json"})
        resp.raise_for_status()
        rows = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        return [RawFinding(module="subdomains", kind="lookup_failed",
                           evidence=f"crt.sh lookup failed: {exc}", url=CRT_SH)]

    names: set[str] = set()
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain):
                names.add(name)

    if not names:
        return []

    findings = [RawFinding(
        module="subdomains", kind="ct_exposure",
        evidence=f"{len(names)} subdomains of {domain} are discoverable via "
                 f"certificate-transparency logs (crt.sh).", url=CRT_SH)]

    sensitive = sorted(n for n in names if n.split(".")[0] in SENSITIVE_PREFIXES)
    if sensitive:
        findings.append(RawFinding(
            module="subdomains", kind="sensitive_subdomains",
            evidence="Sensitive-looking subdomains found in CT logs: "
                     + ", ".join(sensitive[:15]), url=CRT_SH))
    return findings
