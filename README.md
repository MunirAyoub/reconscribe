# ReconScribe

**Paste a domain → passive reconnaissance → a Claude-drafted, CWE/CVSS-mapped vulnerability report.**

An AI recon-to-report tool. Read-only recon modules gather facts about a public
web target (HTTP security headers, certificate-transparency subdomains, WordPress
version disclosure); Claude then classifies severity, maps CWE/CVSS, and writes the
findings. Built after conducting a real authorized pentest — it automates the
recon-and-reporting half of that work.

> **Passive recon only.** No exploitation, no auth attacks, no fuzzing. There is an
> authorization gate, a "passive only" banner, and a politeness delay between
> requests. Only scan domains you own or are authorized to test.

## Stack
- **Backend:** Python + FastAPI, `httpx` for recon, the `anthropic` SDK for analysis.
- **LLM:** Claude (`claude-sonnet-5` by default) via **strict tool use** — the model must
  return a well-formed findings array, not prose.
- **Frontend:** React 19 + Vite.

## Run it

### 1. Backend
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate   |   macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then put your ANTHROPIC_API_KEY in .env
uvicorn app.main:app --reload
```
Backend runs at http://localhost:8000 (`GET /health` to check).

> No `ANTHROPIC_API_KEY`? If you've run `ant auth login`, a bare client picks up the
> profile automatically. Otherwise recon still runs and the report comes back with a
> `note` explaining the analysis step was skipped.

### 2. Frontend
```bash
cd frontend
npm install
npm run dev
```
Open http://localhost:5173, enter a domain, tick the authorization box, Scan.

## How it works
```
[React UI] --POST /scan {domain, authorized}--> [FastAPI]
                                                    │
        passive recon (read-only): headers · crt.sh · WordPress · TLS · robots · DNS
                                                    │  raw findings[]
                                                    ▼
                                   [Claude, strict tool use] → Finding[] (severity/CWE/CVSS)
                                                    ▼
                                       severity-sorted report in the UI
```

## Layout
```
backend/app/
  main.py         # FastAPI routes: /health, /scan, /scans, /scans/{id}, export
  config.py       # settings (.env)
  models.py       # ScanRequest, RawFinding, Finding, Report, ScanSummary
  guardrails.py   # authorization + private-IP refusal
  scanner.py      # runs recon modules politely
  db.py           # SQLite persistence (scan history)
  export.py       # render a report as Markdown or PDF
  recon/          # headers, subdomains, wordpress, ssl_cert, robots, dns (all passive)
  llm/            # client.py, prompts.py (strict tool schema), analyze.py
frontend/src/     # App.jsx, api.js, index.css
```

## Features
- Six passive recon modules: HTTP security headers, crt.sh subdomains, WordPress
  version, TLS certificate, robots.txt paths, DNS/rDNS + hosting/WAF fingerprint.
- Claude structured-output analysis (strict tool use) → severity/CWE/CVSS findings.
- Scan history persisted in SQLite (`GET /scans`, `GET /scans/{id}`).
- Report export as Markdown or PDF (`GET /scans/{id}/report.md|.pdf`).
- Authorization gate, private-IP refusal, and a polite request delay.

## Roadmap
- More recon modules (SPF/DMARC, security.txt, open-directory checks).
- Postgres + a job queue for durable/concurrent scans.
- Auth + multi-user scan history.

Full design notes live in the Obsidian vault: `Projects/ReconScribe/`.
