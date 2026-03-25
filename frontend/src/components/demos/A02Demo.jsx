import React, { useState } from 'react'
import api from '../../api/client'
import { ResultBox, CodeBlock } from './DemoShell'

const CODE = `// A02: Cryptographic Failures — AES-256-GCM
const { createCipheriv, randomBytes } = require('crypto')

// 1. AES-256-GCM for PII fields at rest
function encryptField(plaintext) {
  const iv     = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', KEY, iv)
  const enc    = Buffer.concat([cipher.update(plaintext,'utf8'), cipher.final()])
  const tag    = cipher.getAuthTag()
  return [iv, enc, tag].map(b => b.toString('hex')).join(':')
}

// 2. Mongoose schema — transparent encryption
const devoteeSchema = new mongoose.Schema({
  aadhaar: {
    type: String,
    set: (v) => encryptField(v),   // encrypt on save
    get: (v) => decryptField(v),   // decrypt on read
  }
})

// 3. bcrypt for passwords — cost factor 12
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next()
  this.password = await bcrypt.hash(this.password, 12)
  next()
})

// 4. TLS 1.3 enforced at infrastructure level
// 5. Secrets in env → AWS Secrets Manager in prod`

export default function A02Demo() {
  const [result, setResult] = useState(null)
  const [error,  setError]  = useState(null)
  const [loading,setLoading]= useState(false)

  const run = async () => {
    setLoading(true); setError(null)
    try {
      const r = await api.get('/demo/a02/encryption-demo')
      setResult(r.data)
    } catch (err) {
      setError({ status: err.response?.status, data: err.response?.data })
    } finally { setLoading(false) }
  }

  return (
    <div className="grid lg:grid-cols-2 gap-6">
      <div className="space-y-4">
        <div className="card">
          <h3 className="font-semibold text-white mb-2">What are Cryptographic Failures?</h3>
          <p className="text-sm text-gray-400">Failures in encryption lead to sensitive data exposure — transmitting in plaintext, using MD5/SHA1, or storing API keys unencrypted.</p>
          <div className="mt-3 p-3 bg-red-950/30 border border-red-500/30 rounded-lg text-xs text-red-300">
            <strong>LivingAI Example:</strong> GuruBoard stores devotee Aadhaar numbers with reversible encryption. Herd Management IoT sends GPS over HTTP.
          </div>
        </div>

        <div className="space-y-3">
          <div className="card bg-navy/50 space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-gray-400">Encryption Algorithm</span><span className="text-teal font-mono">AES-256-GCM</span></div>
            <div className="flex justify-between"><span className="text-gray-400">Password Hashing</span><span className="text-teal font-mono">bcrypt (cost=12)</span></div>
            <div className="flex justify-between"><span className="text-gray-400">TLS Version</span><span className="text-teal font-mono">TLS 1.3</span></div>
            <div className="flex justify-between"><span className="text-gray-400">Key Storage</span><span className="text-teal font-mono">env → AWS Vault</span></div>
            <div className="flex justify-between"><span className="text-gray-400">PII in logs</span><span className="text-green-400 font-mono">NEVER</span></div>
          </div>

          <button onClick={run} disabled={loading} className="btn-primary w-full">
            {loading ? '⏳ Encrypting…' : '▶ Live Encrypt PII Field (Aadhaar demo)'}
          </button>
          <ResultBox data={result} error={error} />
        </div>

        <div className="card text-xs space-y-1.5">
          <div className="text-white font-semibold mb-2">Active Controls</div>
          {['TLS 1.3 enforced for all traffic','AES-256-GCM for PII data at rest','bcrypt password hashing (cost ≥ 12)','Secrets in env vars (→ Vault in prod)','No sensitive data in logs, URLs, or errors'].map(c => (
            <div key={c} className="flex gap-2 text-gray-400"><span className="text-teal shrink-0">✓</span>{c}</div>
          ))}
        </div>
      </div>
      <CodeBlock code={CODE} title="utils/crypto.js + models/User.js" />
    </div>
  )
}
