"""Recon module registry. Each module is an async callable:

    async def run(client: httpx.AsyncClient, domain: str) -> list[RawFinding]

All modules are PASSIVE / read-only (ADR-001): public cert-transparency
lookups, HTTP header inspection, and fetching publicly-served files. No
exploitation, no auth attacks, no fuzzing.
"""

from __future__ import annotations

from . import dns, headers, robots, ssl_cert, subdomains, wordpress

# Each module maps to a real finding from the ceappedreira pentest.
MODULES = [
    headers.run,     # F-03 / F-04 / F-05
    subdomains.run,  # F-01
    wordpress.run,   # F-06 / F-15
    ssl_cert.run,    # F-08 / F-16
    robots.run,      # F-14
    dns.run,         # F-02 / F-09
]
