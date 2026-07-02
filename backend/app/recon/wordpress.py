"""WordPress version disclosure.

Maps to pentest findings F-06 (version via /feed/ generator tag) and F-15
(plugin readme.txt exposing versions). Read-only GETs on publicly-served files.
"""

from __future__ import annotations

import re

import httpx

from ..models import RawFinding

GENERATOR_RE = re.compile(r"wordpress\.org/?\?v=([0-9.]+)", re.IGNORECASE)
META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress ([0-9.]+)', re.IGNORECASE)


async def run(client: httpx.AsyncClient, domain: str) -> list[RawFinding]:
    findings: list[RawFinding] = []

    # 1. RSS feed generator tag (F-06).
    feed_url = f"https://{domain}/feed/"
    try:
        resp = await client.get(feed_url)
        if resp.status_code == 200:
            m = GENERATOR_RE.search(resp.text)
            if m:
                findings.append(RawFinding(
                    module="wordpress", kind="version_via_feed",
                    evidence=f"WordPress {m.group(1)} disclosed via the <generator> "
                             f"tag in {feed_url}.", url=feed_url))
    except httpx.HTTPError:
        pass

    # 2. Homepage meta generator (also F-06).
    home = f"https://{domain}/"
    try:
        resp = await client.get(home)
        m = META_GENERATOR_RE.search(resp.text)
        if m and not any(f.kind == "version_via_feed" for f in findings):
            findings.append(RawFinding(
                module="wordpress", kind="version_via_meta",
                evidence=f"WordPress {m.group(1)} disclosed via the meta generator "
                         f"tag on {home}.", url=home))
    except httpx.HTTPError:
        pass

    # 3. Publicly readable plugin readme.txt (F-15) — only worth checking if WP is present.
    if findings:
        readme = f"https://{domain}/wp-content/plugins/akismet/readme.txt"
        try:
            resp = await client.get(readme)
            if resp.status_code == 200 and "stable tag" in resp.text.lower():
                tag = re.search(r"stable tag:\s*([0-9.]+)", resp.text, re.IGNORECASE)
                ver = f" (v{tag.group(1)})" if tag else ""
                findings.append(RawFinding(
                    module="wordpress", kind="plugin_readme_exposed",
                    evidence=f"Plugin readme.txt is publicly readable{ver}, enabling "
                             f"plugin version enumeration.", url=readme))
        except httpx.HTTPError:
            pass

    return findings
