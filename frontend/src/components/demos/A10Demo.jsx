import React, { useState } from 'react'
import api from '../../api/client'
import { ResultBox, CodeBlock } from './DemoShell'

const CODE = `// A10: Server-Side Request Forgery (SSRF)

const PRIVATE_IP_REGEX =
  /^(10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.|127\\.|169\\.254\\.)/

function ssrfGuard(rawUrl, req = {}) {
  let parsed
  try { parsed = new URL(rawUrl) }
  catch { return { blocked: true, reason: 'Invalid URL' } }

  const hostname = parsed.hostname

  // Block private IP ranges
  if (PRIVATE_IP_REGEX.test(hostname)) {
    const isMeta = /^169\\.254\\.169\\.254/.test(hostname)
    const reason = isMeta
      ? 'AWS/GCP metadata endpoint — credential theft vector'
      : 'Private IP range — internal network access denied'
    logEvent('SSRF_BLOCKED', { url: rawUrl, hostname, reason })
    return { blocked: true, reason, hostname, owasp: 'A10' }
  }

  // Block cloud metadata hostnames
  if (['metadata.google.internal'].includes(hostname))
    return { blocked: true, reason: 'Cloud metadata hostname' }

  // Only allow http/https
  if (!['http:','https:'].includes(parsed.protocol))
    return { blocked: true, reason: 'Protocol not allowed' }

  logEvent('SSRF_ALLOWED', { url: rawUrl, hostname })
  return { blocked: false, hostname }
}`

const PRESETS = [
  { label:'AWS Metadata',   url:'http://169.254.169.254/latest/meta-data/iam/security-credentials/', desc:'Cloud credential theft' },
  { label:'Internal DB',    url:'http://192.168.1.10:27017/admin', desc:'Private network access' },
  { label:'Loopback',       url:'http://127.0.0.1:5000/api/admin', desc:'Localhost access' },
  { label:'Class A Private',url:'http://10.0.0.1/internal-api',   desc:'Private range 10.x.x.x' },
  { label:'Legit URL',      url:'https://api.github.com/repos',    desc:'This should pass' },
  { label:'File Protocol',  url:'file:///etc/passwd',              desc:'File system access attempt' },
]

export default function A10Demo() {
  const [url,    setUrl]    = useState('')
  const [result, setResult] = useState(null)
  const [error,  setError]  = useState(null)
  const [loading,setLoading]= useState(false)

  const run = async () => {
    if (!url.trim()) return
    setLoading(true); setError(null)
    try {
      const r = await api.post('/demo/a10/ssrf-test', { url })
      setResult(r.data)
    } catch(err) {
      setError({ status: err.response?.status, data: err.response?.data })
    } finally { setLoading(false) }
  }

  return (
    <div className="grid lg:grid-cols-2 gap-6">
      <div className="space-y-4">
        <div className="card">
          <h3 className="font-semibold text-white mb-2">What is SSRF?</h3>
          <p className="text-sm text-gray-400">The app fetches a URL supplied by the user without validation — attacker can reach cloud metadata, internal services, or steal IAM credentials.</p>
          <div className="mt-3 p-3 bg-red-950/30 border border-red-500/30 rounded-lg text-xs text-red-300">
            <strong>LivingAI Example:</strong> Media360's RSS importer fetches <code>http://169.254.169.254/latest/meta-data/iam</code> and leaks AWS credentials to the attacker.
          </div>
        </div>

        <div className="card space-y-3">
          <div className="text-sm font-semibold text-white">Test the SSRF Guard</div>
          <div className="flex flex-wrap gap-2">
            {PRESETS.map(p => (
              <button key={p.label} onClick={() => setUrl(p.url)}
                className="text-xs border border-white/20 hover:border-red-500/50 rounded-lg px-2 py-1 text-gray-400 hover:text-red-300 transition-all">
                {p.label}
              </button>
            ))}
          </div>
          <input className="input font-mono text-xs" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com or http://192.168.1.1" />
          <button onClick={run} disabled={loading || !url.trim()} className="btn-primary w-full">
            {loading ? '⏳ Checking…' : '▶ Test SSRF Guard'}
          </button>

          {result && (
            <div className={`rounded-lg p-4 border text-sm ${result.blocked ? 'bg-red-950/40 border-red-500/50' : 'bg-green-950/40 border-teal/50'}`}>
              <div className="font-bold text-white mb-2">
                {result.blocked ? '🚫 REQUEST BLOCKED' : '✅ REQUEST ALLOWED'}
              </div>
              <div className="text-xs space-y-1 text-gray-300">
                <div>Host: <code className="text-teal">{result.hostname || 'N/A'}</code></div>
                {result.reason && <div className="text-red-300">{result.reason}</div>}
                {!result.blocked && <div>Protocol: <code className="text-teal">{result.protocol}</code></div>}
              </div>
            </div>
          )}
          {error && <ResultBox error={error} />}
        </div>
      </div>
      <CodeBlock code={CODE} title="middleware/ssrfGuard.js" />
    </div>
  )
}
