import React, { useState } from 'react'
import api from '../../api/client'
import { ResultBox, CodeBlock } from './DemoShell'

const CODE = `// A06: Vulnerable & Outdated Components
// package.json — pinned versions (no ^ or ~)
{
  "dependencies": {
    "express":            "4.18.2",   // pinned
    "mongoose":           "8.0.3",    // pinned
    "helmet":             "7.1.0"     // pinned
    // No floating: "^4.x" or "~4.18"
  }
}

// CI/CD — npm audit in pipeline (.github/workflows)
// steps:
//   - run: npm audit --audit-level=high
//   - run: npx snyk test

// Patch SLA enforcement (D-16):
// CRITICAL → 24h → CTO + CEO alert
// HIGH     → 7d  → CTO alert
// MEDIUM   → 30d → sprint backlog
// LOW      → 90d → backlog

// SBOM maintained in D-10 (42 tracked components)
// Dependabot auto-creates PRs for CVEs`

export default function A06Demo() {
  const [result, setResult] = useState(null)
  const [error,  setError]  = useState(null)
  const [loading,setLoading]= useState(false)

  const run = async () => {
    setLoading(true); setError(null)
    try {
      const r = await api.get('/demo/a06/sbom')
      setResult(r.data)
    } catch(err) {
      setError({ status: err.response?.status, data: err.response?.data })
    } finally { setLoading(false) }
  }

  const STATUS_COLOR = { OK:'text-green-400', WARN:'text-yellow-400', FAIL:'text-red-400' }

  return (
    <div className="grid lg:grid-cols-2 gap-6">
      <div className="space-y-4">
        <div className="card">
          <h3 className="font-semibold text-white mb-2">What are Vulnerable & Outdated Components?</h3>
          <p className="text-sm text-gray-400">Using libraries with known CVEs, not scanning regularly, or not patching in time. Your D-10 SBOM tracks 42 components.</p>
        </div>
        <button onClick={run} disabled={loading} className="btn-primary w-full">
          {loading ? '⏳ Scanning…' : '▶ Run SBOM / Dependency Scan'}
        </button>
        {result && (
          <div className="card space-y-3">
            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="bg-navy rounded-lg p-3">
                <div className="text-2xl font-black text-white">{result.totalDependencies}</div>
                <div className="text-xs text-gray-400">Dependencies</div>
              </div>
              <div className="bg-navy rounded-lg p-3">
                <div className={`text-2xl font-black ${result.criticalVulnerabilities===0?'text-green-400':'text-red-400'}`}>
                  {result.criticalVulnerabilities}
                </div>
                <div className="text-xs text-gray-400">Critical CVEs</div>
              </div>
              <div className="bg-navy rounded-lg p-3">
                <div className={`text-2xl font-black ${result.highVulnerabilities===0?'text-green-400':'text-orange-400'}`}>
                  {result.highVulnerabilities}
                </div>
                <div className="text-xs text-gray-400">High CVEs</div>
              </div>
            </div>
            <div className="space-y-1 max-h-52 overflow-y-auto">
              {result.dependencies?.map(d => (
                <div key={d.name} className="flex items-center justify-between text-xs py-1 border-b border-white/5">
                  <span className="font-mono text-gray-300">{d.name}</span>
                  <span className="text-gray-500 font-mono">{d.version}</span>
                  <span className={STATUS_COLOR[d.status] || 'text-gray-400'}>✓ {d.status}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {error && <ResultBox error={error} />}
      </div>
      <CodeBlock code={CODE} title="package.json + CI/CD pipeline" />
    </div>
  )
}
