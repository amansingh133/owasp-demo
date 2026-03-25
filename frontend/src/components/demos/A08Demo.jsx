import React, { useState } from 'react'
import api from '../../api/client'
import { ResultBox, CodeBlock } from './DemoShell'

const CODE = `// A08: Software & Data Integrity Failures

// 1. Lock file hash verification in CI
// package-lock.json integrity checked before install
// npm ci (not npm install) — uses lock file exactly

// 2. Subresource Integrity for CDN assets
<script
  src="https://cdn.example.com/lib.js"
  integrity="sha384-abc123..."
  crossorigin="anonymous"
/>

// 3. AI model weights verification
const crypto = require('crypto')
const MODEL_EXPECTED_HASH = process.env.MODEL_SHA256

async function loadModel(modelPath) {
  const content = await fs.readFile(modelPath)
  const hash = crypto
    .createHash('sha256')
    .update(content)
    .digest('hex')
  if (hash !== MODEL_EXPECTED_HASH)
    throw new Error('Model integrity check FAILED — tampered file')
  return loadFromBuffer(content)
}

// 4. CI/CD pipeline security
// - Signed commits required (GPG)
// - Branch protection: PR review required
// - No direct pushes to main
// - SAST (CodeQL) on every PR`

export default function A08Demo() {
  const [result, setResult] = useState(null)
  const [error,  setError]  = useState(null)
  const [loading,setLoading]= useState(false)

  const run = async () => {
    setLoading(true); setError(null)
    try {
      const r = await api.get('/demo/a08/integrity')
      setResult(r.data)
    } catch(err) {
      setError({ status: err.response?.status, data: err.response?.data })
    } finally { setLoading(false) }
  }

  return (
    <div className="grid lg:grid-cols-2 gap-6">
      <div className="space-y-4">
        <div className="card">
          <h3 className="font-semibold text-white mb-2">What are Integrity Failures?</h3>
          <p className="text-sm text-gray-400">Code and infrastructure that doesn't protect against integrity violations — insecure CI/CD, unverified auto-updates, tampered AI models.</p>
          <div className="mt-3 p-3 bg-red-950/30 border border-red-500/30 rounded-lg text-xs text-red-300">
            <strong>LivingAI Example:</strong> Medha AI model weights loaded from S3 without hash verification — a tampered model could produce manipulated results.
          </div>
        </div>
        <button onClick={run} disabled={loading} className="btn-primary w-full">
          {loading ? '⏳ Verifying…' : '▶ Check Build & Model Integrity'}
        </button>
        {result && (
          <div className="card space-y-2">
            {Object.entries(result.cicdIntegrity || {}).map(([k,v]) => (
              <div key={k} className="flex items-center justify-between text-xs py-1 border-b border-white/5">
                <span className="text-gray-400 capitalize">{k.replace(/([A-Z])/g,' $1')}</span>
                <span className={typeof v === 'boolean' ? (v?'text-green-400':'text-red-400') : 'text-teal font-mono text-xs truncate max-w-48'}>
                  {typeof v === 'boolean' ? (v ? '✓ Enabled' : '✗ Disabled') : String(v).slice(0,40)}
                </span>
              </div>
            ))}
            <div className="pt-1 space-y-1">
              {[result.subresourceIntegrity, result.codeSigningStatus, result.aiModelIntegrity].map(c => c && (
                <div key={c} className="flex gap-2 text-xs text-gray-400"><span className="text-teal shrink-0">✓</span>{c}</div>
              ))}
            </div>
          </div>
        )}
        {error && <ResultBox error={error} />}
      </div>
      <CodeBlock code={CODE} title="ci/integrity.yml + utils/modelLoader.js" />
    </div>
  )
}
