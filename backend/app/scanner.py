"""Run all recon modules against a domain, politely and concurrently-ish."""

from __future__ import annotations

import asyncio

import httpx

from .config import settings
from .models import RawFinding
from .recon import MODULES


async def collect_raw(domain: str) -> list[RawFinding]:
    headers = {"User-Agent": settings.user_agent}
    raw: list[RawFinding] = []
    async with httpx.AsyncClient(
        timeout=15.0, follow_redirects=True, headers=headers
    ) as client:
        # Run modules sequentially with a small politeness delay between them
        # so we never hammer a target (ADR-001).
        for module in MODULES:
            try:
                raw.extend(await module(client, domain))
            except Exception as exc:  # a broken module shouldn't kill the scan
                raw.append(RawFinding(
                    module=getattr(module, "__module__", "unknown"),
                    kind="module_error", evidence=f"Module raised: {exc}"))
            await asyncio.sleep(settings.reconscribe_request_delay)
    return raw
