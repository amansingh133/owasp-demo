import React, { useState } from 'react'
import api from '../../api/client'
import { ResultBox, CodeBlock } from './DemoShell'

const CODE = `// A05: Security Misconfiguration
// All headers set via helmet() in server.js

const helmet = require('helmet')

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],    // no unsafe-inline
      objectSrc:  ["'none'"],    // block plugins
    },
  },
  hsts: { maxAge: 15552000, includeSubDomains: true },
}))

// CORS — specific origins, no wildcards
app.use(cors({
  origin: process.env.CLIENT_ORIGIN,
  credentials: true,
}))

// A05: Remove default credentials, debug mode
// NODE_ENV=production disables:
//   - stack traces in error responses
//   - verbose logging
//   - Vite debug endpoints
//   - X-Powered-By: Express header (hidden by helmet)`

export default function A05Demo() {
  const [result, setResult] = useState(null)
  const [error,  setError]  = useState(null)
  const [loading,setLoading]= useState(false)

  const run = async () => {
    setLoading(true); setError(null)
    try {
      const r = await api.get('/demo/a05/headers')
      setResult(r.data)
    } catch(err) {
      setError({ status: err.response?.status, data: err.response?.data })
    } finally { setLoading(false) }
  }

  return (
    <div className="grid lg:grid-cols-2 gap-6">
      <div className="space-y-4">
        <div className="card">
          <h3 className="font-semibold text-white mb-2">What is Security Misconfiguration?</h3>
          <p className="text-sm text-gray-400">Default accounts unchanged, debug mode in production, unnecessary ports open, insecure cloud storage, missing security headers.</p>
          <div className="mt-3 p-3 bg-red-950/30 border border-red-500/30 rounded-lg text-xs text-red-300">
            <strong>LivingAI Example:</strong> Kubernetes dashboard exposed without auth. PostgreSQL with default 'postgres' password. S3 buckets set to public.
          </div>
        </div>
        <button onClick={run} disabled={loading} className="btn-primary w-full">
          {loading ? '⏳ Fetching…' : '▶ Show Active Security Headers'}
        </button>
        {result && (
          <div className="card space-y-2">
            <div className="text-sm font-semibold text-teal mb-2">Active HTTP Security Headers</div>
            {Object.entries(result.activeHeaders || {}).map(([k,v]) => (
              <div key={k} className="flex items-start gap-2 text-xs border-b border-white/5 pb-1.5">
                <span className="text-green-400 shrink-0 mt-0.5">✓</span>
                <div>
                  <div className="text-white font-mono">{k}</div>
                  <div className="text-gray-500">{v}</div>
                </div>
              </div>
            ))}
            {result.disabled?.map(d => (
              <div key={d} className="flex gap-2 text-xs text-gray-500">
                <span className="text-teal">🚫</span>{d}
              </div>
            ))}
          </div>
        )}
        {error && <ResultBox error={error} />}
        <div className="card text-xs space-y-1.5">
          <div className="text-white font-semibold mb-2">Active Controls</div>
          {['helmet() security headers (auto-configured)','Default credentials removed before deploy','Debug mode disabled in production','CORS: specific origins only (no wildcards)','No .env / .git accessible via HTTP'].map(c => (
            <div key={c} className="flex gap-2 text-gray-400"><span className="text-teal shrink-0">✓</span>{c}</div>
          ))}
        </div>
      </div>
      <CodeBlock code={CODE} title="server.js — helmet + CORS config" />
    </div>
  )
}
