import { useEffect, useRef, useState } from 'react'
import { scan, listScans, getScan, exportUrl } from './api'

const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info']
const SEVERITY_CLASS = {
  Critical: 'sev-critical',
  High: 'sev-high',
  Medium: 'sev-medium',
  Low: 'sev-low',
  Info: 'sev-info',
}

// The passive checks, in the order the backend runs them — shown as a live
// log while a scan is in flight.
const CHECKS = [
  'HTTP security headers',
  'crt.sh subdomains',
  'WordPress version',
  'TLS certificate',
  'robots.txt paths',
  'DNS / rDNS fingerprint',
]

function fmtDate(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function severityCounts(findings) {
  const counts = Object.fromEntries(SEV_ORDER.map((s) => [s, 0]))
  for (const f of findings) if (counts[f.severity] != null) counts[f.severity]++
  return counts
}

export default function App() {
  const [domain, setDomain] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [loading, setLoading] = useState(false)
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')
  const [history, setHistory] = useState([])
  const [step, setStep] = useState(0)   // which check the live log is on
  const timer = useRef(null)

  async function refreshHistory() {
    try {
      setHistory(await listScans())
    } catch {
      /* history is non-critical — ignore fetch errors */
    }
  }

  useEffect(() => { refreshHistory() }, [])

  // Advance the live scan log while a request is in flight; hold on the last
  // check until the response lands.
  useEffect(() => {
    if (!loading) { clearInterval(timer.current); return }
    setStep(0)
    timer.current = setInterval(() => {
      setStep((s) => Math.min(s + 1, CHECKS.length - 1))
    }, 650)
    return () => clearInterval(timer.current)
  }, [loading])

  async function onSubmit(e) {
    e.preventDefault()
    setError('')
    setReport(null)
    setLoading(true)
    try {
      setReport(await scan(domain.trim(), authorized))
      refreshHistory()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function openScan(id) {
    setError('')
    try {
      setReport(await getScan(id))
    } catch (err) {
      setError(err.message)
    }
  }

  const counts = report ? severityCounts(report.findings) : null

  return (
    <div className="page">
      <main className="wrap">
        <header className="masthead">
          <div className="brand">
            <span className="mark">RECON<span className="mark-accent">SCRIBE</span></span>
            <span className="status">passive recon</span>
          </div>
          <p className="tagline">
            Paste a domain. Read-only reconnaissance gathers the facts; Claude
            classifies each one by severity, CWE, and CVSS.
          </p>
        </header>

        <form onSubmit={onSubmit} className="console">
          <div className="prompt-row">
            <span className="sigil" aria-hidden="true">recon@scribe ~ %</span>
            <span className="cmd">scan</span>
            <input
              type="text"
              className="target"
              placeholder="example.com"
              aria-label="Domain to scan"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              autoComplete="off"
              spellCheck="false"
              required
            />
          </div>
          <div className="console-foot">
            <label className="flag">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
              />
              <span className="flag-name">--authorized</span>
              <span className="flag-hint">I own this domain or am cleared to test it.</span>
            </label>
            <button type="submit" disabled={loading || !domain || !authorized}>
              {loading ? 'Scanning' : 'Run scan'}
            </button>
          </div>
        </form>

        {loading && (
          <section className="scanlog" aria-live="polite">
            {CHECKS.map((c, i) => (
              <div
                key={c}
                className={'logline ' + (i < step ? 'done' : i === step ? 'active' : 'wait')}
              >
                <span className="tick">{i < step ? '✓' : i === step ? '›' : '·'}</span>
                {c}
              </div>
            ))}
          </section>
        )}

        {error && <p className="error" role="alert">{error}</p>}

        {report && !loading && (
          <section className="report">
            <div className="report-head">
              <div className="report-title">
                <span className="eyebrow">Report</span>
                <h2>{report.domain}</h2>
              </div>
              {report.id != null && (
                <span className="export">
                  <a href={exportUrl(report.id, 'md')}>Markdown</a>
                  <a href={exportUrl(report.id, 'pdf')}>PDF</a>
                </span>
              )}
            </div>

            <p className="report-meta">
              {report.findings.length} findings · {report.raw_count} observations
              · {report.model}
              {report.created_at && <> · {fmtDate(report.created_at)}</>}
            </p>

            {report.findings.length > 0 && (
              <div className="sevbar" role="img"
                aria-label={SEV_ORDER.filter((s) => counts[s])
                  .map((s) => `${counts[s]} ${s}`).join(', ')}>
                {SEV_ORDER.filter((s) => counts[s] > 0).map((s) => (
                  <span
                    key={s}
                    className={'seg ' + SEVERITY_CLASS[s]}
                    style={{ flexGrow: counts[s] }}
                  >
                    <b>{counts[s]}</b> {s}
                  </span>
                ))}
              </div>
            )}

            {report.note && <p className="note">{report.note}</p>}
            {report.findings.length === 0 && !report.note && (
              <p className="empty">No findings. Nothing notable is publicly exposed.</p>
            )}

            <ol className="findings">
              {report.findings.map((f, i) => (
                <li
                  key={i}
                  className={`finding ${SEVERITY_CLASS[f.severity]}`}
                  style={{ '--i': i }}
                >
                  <div className="finding-index">{String(i + 1).padStart(2, '0')}</div>
                  <div className="finding-body">
                    <div className="finding-head">
                      <span className="sev-chip">{f.severity}</span>
                      <h3>{f.title}</h3>
                      <span className="tag">{f.cwe} · CVSS {f.cvss}</span>
                    </div>
                    <p><span className="lead">Impact.</span> {f.impact}</p>
                    <p><span className="lead">Recommendation.</span> {f.recommendation}</p>
                    <p className="evidence">{f.evidence}</p>
                  </div>
                </li>
              ))}
            </ol>
          </section>
        )}

        {history.length > 0 && (
          <section className="history">
            <span className="eyebrow">Recent scans</span>
            <ul>
              {history.map((s) => (
                <li key={s.id}>
                  <button
                    className={report && report.id === s.id ? 'active' : ''}
                    onClick={() => openScan(s.id)}
                  >
                    <span className="h-domain">{s.domain}</span>
                    <span className="h-meta">
                      {s.finding_count} findings · {fmtDate(s.created_at)}
                    </span>
                    <span className="h-arrow" aria-hidden="true">→</span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        )}
      </main>
    </div>
  )
}
