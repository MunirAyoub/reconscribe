"""Keep ReconScribe legal and polite (ADR-001).

- Refuse obviously out-of-bounds targets (localhost / private ranges).
- The authorization checkbox is enforced in main.py before any scan runs.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class ScanNotAllowed(Exception):
    pass


def normalize_domain(raw: str) -> str:
    """Accept 'example.com' or 'https://example.com/path' → 'example.com'."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    host = urlparse(raw).hostname
    if not host:
        raise ScanNotAllowed("Could not parse a hostname from that input.")
    return host.lower()


def assert_scannable(domain: str) -> None:
    """Block localhost and private/reserved IPs — passive recon of the public
    web only, never someone's internal network."""
    if domain in {"localhost", ""} or domain.endswith(".local"):
        raise ScanNotAllowed("Refusing to scan localhost / .local.")

    try:
        for res in socket.getaddrinfo(domain, None):
            ip = ipaddress.ip_address(res[4][0])
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                raise ScanNotAllowed(
                    f"{domain} resolves to a non-public address ({ip}); refusing."
                )
    except socket.gaierror:
        raise ScanNotAllowed(f"Could not resolve {domain}.")
