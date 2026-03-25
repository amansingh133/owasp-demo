import React, { useState } from 'react'
import api from '../../api/client'
import { ResultBox, CodeBlock } from './DemoShell'

const CODE = `// A07: Identification & Authentication Failures

// 1. Rate limiting — 5 failures = 15-min lockout
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  handler: (req, res) => res.status(429).json({
    error: 'Too many attempts. Locked for 15 minutes.',
    owasp: 'A07'
  }),
})

// 2. Short-lived JWT access token (15 minutes)
const accessToken = jwt.sign(
  { id, role, orgId },
  process.env.JWT_SECRET,
  { expiresIn: '15m' }    // ← 15 minutes only
)

// 3. Refresh token rotation on every use
// Old token → invalidated in MongoDB
// New token → re-issued + stored as bcrypt hash

// 4. HttpOnly + Secure + SameSite cookies
res.cookie('accessToken', token, {
  httpOnly: true,          // JS cannot read
  secure:   true,          // HTTPS only
  sameSite: 'strict',      // CSRF protection
  maxAge:   15 * 60 * 1000
})

// 5. Account lock after 5 failed attempts
if (user.loginAttempts >= 5)
  user.lockUntil = new Date(Date.now() + 15*60*1000)`

export default function A07Demo() {
  const [result, setResult] = useState(null)
  const [error,  setError]  = useState(null)
  const [loading,setLoading]= useState(false)

  const run = async () => {
    setLoading(true); setError(null)
    try {
      const r = await api.get('/demo/a07/session-info')
      setResult(r.data)
    } catch(err) {
      setError({ status: err.response?.status, data: err.response?.data })
    } finally { setLoading(false) }
  }

  return (
    <div className="grid lg:grid-cols-2 gap-6">
      <div className="space-y-4">
        <div className="card">
          <h3 className="font-semibold text-white mb-2">What are Auth Failures?</h3>
          <p className="text-sm text-gray-400">Weak passwords, credential stuffing, missing MFA, session fixation, no logout token invalidation, permanent JWTs.</p>
          <div className="mt-3 p-3 bg-red-950/30 border border-red-500/30 rounded-lg text-xs text-red-300">
            <strong>LivingAI Example:</strong> Media360 allows unlimited login attempts. JWT tokens don't expire — a stolen token gives permanent access.
          </div>
        </div>
        <button onClick={run} disabled={loading} className="btn-primary w-full">
          {loading ? '⏳ Checking…' : '▶ Inspect Your Session Token'}
        </button>
        {result && (
          <div className="card space-y-3">
            <div className="text-sm font-semibold text-teal">Session Details</div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="bg-navy rounded p-2">
                <div className="text-gray-500">Issued At</div>
                <div className="text-white">{new Date(result.tokenInfo?.issuedAt).toLocaleTimeString()}</div>
              </div>
              <div className="bg-navy rounded p-2">
                <div className="text-gray-500">Expires</div>
                <div className="text-white">{new Date(result.tokenInfo?.expiresAt).toLocaleTimeString()}</div>
              </div>
              <div className="bg-navy rounded p-2 col-span-2">
                <div className="text-gray-500">Seconds Remaining</div>
                <div className="text-teal font-bold">{result.tokenInfo?.secondsRemaining}s</div>
              </div>
            </div>
            <div className="space-y-1">
              {result.securityControls?.map(c => (
                <div key={c} className="flex gap-2 text-xs text-gray-400">
                  <span className="text-teal shrink-0">✓</span>{c}
                </div>
              ))}
            </div>
          </div>
        )}
        {error && <ResultBox error={error} />}
      </div>
      <CodeBlock code={CODE} title="routes/auth.routes.js + middleware/rateLimiter.js" />
    </div>
  )
}
