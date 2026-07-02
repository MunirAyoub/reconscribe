"""TLS certificate inspection — validity window + issuer.

Maps to pentest findings F-08 / F-16. Passive: we perform the same TLS
handshake any HTTPS client makes, read the certificate the server presents,
and inspect its dates. Nothing is sent to the application layer.

We only surface a finding when something is actually notable — an expired /
soon-to-expire cert or a verification failure (self-signed, hostname mismatch).
A healthy cert produces no finding (that would be noise).
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

import httpx

from ..models import RawFinding

# OpenSSL renders notAfter like "Jun  1 12:00:00 2026 GMT".
_CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"
EXPIRY_WARN_DAYS = 30


def _fetch_cert(domain: str) -> dict:
    """Verified TLS handshake; returns the parsed peer certificate dict."""
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            return ssock.getpeercert()


async def run(client: httpx.AsyncClient, domain: str) -> list[RawFinding]:
    url = f"https://{domain}"
    try:
        cert = await asyncio.to_thread(_fetch_cert, domain)
    except ssl.SSLCertVerificationError as exc:
        # Expired, self-signed, or hostname-mismatch certs land here — itself a finding.
        reason = getattr(exc, "verify_message", None) or str(exc)
        return [RawFinding(module="ssl_cert", kind="cert_verification_failed",
                           evidence=f"TLS certificate for {domain} failed verification: {reason}.",
                           url=url)]
    except (ssl.SSLError, OSError) as exc:
        return [RawFinding(module="ssl_cert", kind="handshake_failed",
                           evidence=f"TLS handshake with {domain}:443 failed: {exc}", url=url)]

    not_after = cert.get("notAfter")
    if not not_after:
        return []
    try:
        expires = datetime.strptime(not_after, _CERT_DATE_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return []

    days_left = (expires - datetime.now(timezone.utc)).days
    issuer = _issuer_org(cert)

    if days_left < 0:
        return [RawFinding(module="ssl_cert", kind="cert_expired",
                           evidence=f"TLS certificate for {domain} expired {abs(days_left)} "
                                    f"day(s) ago (issuer: {issuer}).", url=url)]
    if days_left <= EXPIRY_WARN_DAYS:
        return [RawFinding(module="ssl_cert", kind="cert_expiring_soon",
                           evidence=f"TLS certificate for {domain} expires in {days_left} "
                                    f"day(s), on {expires.date()} (issuer: {issuer}).", url=url)]
    return []


def _issuer_org(cert: dict) -> str:
    """Pull the issuer organization (or CN) out of the cert dict."""
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            if key in ("organizationName", "commonName"):
                return value
    return "unknown"
