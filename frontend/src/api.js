const BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000'

async function json(res) {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.detail || `Request failed (${res.status})`)
  }
  return res.json()
}

export async function scan(domain, authorized) {
  const res = await fetch(`${BASE}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, authorized }),
  })
  return json(res)
}

export async function listScans() {
  return json(await fetch(`${BASE}/scans`))
}

export async function getScan(id) {
  return json(await fetch(`${BASE}/scans/${id}`))
}

// Direct download URLs for a persisted report (fmt: 'md' | 'pdf').
export function exportUrl(id, fmt) {
  return `${BASE}/scans/${id}/report.${fmt}`
}
