"""Forward + reverse DNS and hosting/CDN/WAF fingerprinting.

Maps to pentest findings F-02 (infrastructure exposure) and F-09 (hosting/WAF
disclosure). Passive: standard resolver lookups (A/AAAA + reverse DNS) via the
OS resolver, plus infra fingerprinting inferred from the reverse-DNS names. No
packets are sent to the target's application layer.
"""

from __future__ import annotations

import asyncio
import socket

import httpx

from ..models import RawFinding

# Reverse-DNS / hostname substrings that reveal the provider, CDN, or WAF.
FINGERPRINTS = {
    "cloudflare": "Cloudflare (CDN/WAF)",
    "cloudfront": "Amazon CloudFront (CDN)",
    "amazonaws": "Amazon AWS",
    "akamai": "Akamai (CDN)",
    "fastly": "Fastly (CDN)",
    "azure": "Microsoft Azure",
    "googleusercontent": "Google Cloud",
    "1e100": "Google",
    "sucuri": "Sucuri (WAF)",
    "incapsula": "Imperva Incapsula (WAF)",
    "imperva": "Imperva (WAF)",
    "vercel": "Vercel",
    "netlify": "Netlify",
    "github": "GitHub Pages",
}


def _resolve(domain: str) -> tuple[set[str], dict[str, str]]:
    ips: set[str] = set()
    for res in socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP):
        ips.add(res[4][0])
    rdns: dict[str, str] = {}
    for ip in ips:
        try:
            rdns[ip] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            rdns[ip] = ""
    return ips, rdns


async def run(client: httpx.AsyncClient, domain: str) -> list[RawFinding]:
    url = f"https://{domain}"
    try:
        ips, rdns = await asyncio.to_thread(_resolve, domain)
    except (socket.gaierror, OSError) as exc:
        return [RawFinding(module="dns", kind="resolve_failed",
                           evidence=f"DNS resolution for {domain} failed: {exc}", url=url)]

    findings = [RawFinding(
        module="dns", kind="a_records",
        evidence=f"{domain} resolves to: {', '.join(sorted(ips))}.", url=url)]

    named: list[str] = []
    labels: set[str] = set()
    for ip, name in sorted(rdns.items()):
        if not name:
            continue
        named.append(f"{ip} -> {name}")
        low = name.lower()
        for key, label in FINGERPRINTS.items():
            if key in low:
                labels.add(label)

    if named:
        findings.append(RawFinding(
            module="dns", kind="reverse_dns",
            evidence="Reverse DNS: " + "; ".join(named), url=url))
    if labels:
        findings.append(RawFinding(
            module="dns", kind="infra_fingerprint",
            evidence="Hosting/CDN/WAF inferred from reverse DNS: "
                     + ", ".join(sorted(labels)), url=url))
    return findings
