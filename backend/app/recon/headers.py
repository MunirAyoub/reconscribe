"""HTTP security-header + cookie-flag inspection.

Maps to pentest findings F-03 (missing CSP), F-04 (cookie without HttpOnly),
F-05 (infra disclosure via Server header). Pure GET, read-only.
"""

from __future__ import annotations

import httpx

from ..models import RawFinding

# Headers whose absence is worth flagging, with a human label.
EXPECTED_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security (HSTS)",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}

# Server-ish headers that leak infrastructure detail.
DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-envoy-upstream-service-time"]


async def run(client: httpx.AsyncClient, domain: str) -> list[RawFinding]:
    url = f"https://{domain}"
    findings: list[RawFinding] = []
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        return [RawFinding(module="headers", kind="unreachable",
                           evidence=f"Could not fetch {url}: {exc}", url=url)]

    headers = {k.lower(): v for k, v in resp.headers.items()}

    for key, label in EXPECTED_HEADERS.items():
        if key not in headers:
            findings.append(RawFinding(
                module="headers", kind=f"missing_{key}",
                evidence=f"Response from {url} is missing the {label} header.", url=url))

    for key in DISCLOSURE_HEADERS:
        if key in headers:
            findings.append(RawFinding(
                module="headers", kind=f"disclosure_{key}",
                evidence=f"Response exposes '{key}: {headers[key]}'.", url=url))

    # Cookie flag analysis (F-04): look for Set-Cookie without HttpOnly / Secure.
    for cookie in resp.headers.get_list("set-cookie"):
        low = cookie.lower()
        name = cookie.split("=", 1)[0].strip()
        if "httponly" not in low:
            findings.append(RawFinding(
                module="headers", kind="cookie_no_httponly",
                evidence=f"Cookie '{name}' set without the HttpOnly flag.", url=url))
        if "secure" not in low:
            findings.append(RawFinding(
                module="headers", kind="cookie_no_secure",
                evidence=f"Cookie '{name}' set without the Secure flag.", url=url))

    return findings
