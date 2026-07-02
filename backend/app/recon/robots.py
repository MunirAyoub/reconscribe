"""robots.txt sensitive-path disclosure.

Maps to pentest finding F-14. Read-only GET of a publicly-served file — we only
read what robots.txt itself advertises, we never fetch the disallowed paths.
A robots.txt often names admin/backup/internal directories the owner would
rather not point at.
"""

from __future__ import annotations

import httpx

from ..models import RawFinding

# Disallowed paths worth flagging when they name a sensitive-looking directory.
SENSITIVE_HINTS = (
    "admin", "login", "backup", "config", "wp-admin", "private", "secret",
    "db", "sql", "phpmyadmin", "internal", "staging", "test", "upload",
    "tmp", ".git", ".env", "api", "console", "dashboard",
)


async def run(client: httpx.AsyncClient, domain: str) -> list[RawFinding]:
    url = f"https://{domain}/robots.txt"
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return []  # no reachable robots.txt is not a finding

    # Guard against soft-404 HTML pages served with 200: require a real directive.
    if resp.status_code != 200 or "disallow" not in resp.text.lower():
        return []

    disallowed: list[str] = []
    for line in resp.text.splitlines():
        low = line.strip().lower()
        if low.startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                disallowed.append(path)

    sensitive = sorted({p for p in disallowed if any(h in p.lower() for h in SENSITIVE_HINTS)})
    if not sensitive:
        return []

    return [RawFinding(
        module="robots", kind="sensitive_paths",
        evidence="robots.txt discloses sensitive-looking paths: "
                 + ", ".join(sensitive[:15]), url=url)]
