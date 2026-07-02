"""Thin wrapper around the Anthropic client (lazily constructed)."""

from __future__ import annotations

from functools import lru_cache

from anthropic import Anthropic

from ..config import settings


@lru_cache(maxsize=1)
def get_client() -> Anthropic:
    # If ANTHROPIC_API_KEY is unset, the SDK also resolves an `ant auth login`
    # profile — so a bare Anthropic() still works in that case.
    if settings.anthropic_api_key:
        return Anthropic(api_key=settings.anthropic_api_key)
    return Anthropic()
