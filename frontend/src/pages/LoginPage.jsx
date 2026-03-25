import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import api from '../api/client'

const DEMO_USERS = [
  { email: 'admin@demo.com',   role: 'SuperAdmin', color: 'text-red-400'    },
  { email: 'manager@demo.com', role: 'Manager',    color: 'text-yellow-400' },
  { email: 'analyst@demo.com', role: 'Analyst',    color: 'text-teal-light' },
  { email: 'viewer@demo.com',  role: 'Viewer',     color: 'text-gray-400'   },
  { email: 'other@demo.com',   role: 'Analyst (org-beta)', color: 'text-purple-400' },
]

export default function LoginPage() {
  const { login } = useAuth()
  const navigate  = useNavigate()
  const [email, setEmail]     = useState('')
  const [password, setPassword] = useState('')
  const [error, setError]     = useState(null)
  const [info, setInfo]       = useState(null)
  const [loading, setLoading] = useState(false)
  const [seeding, setSeeding] = useState(false)
  const [attempts, setAttempts] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null); setInfo(null)
    setLoading(true)
    try {
      await login(email, password)
      navigate('/')
    } catch (err) {
      const d = err.response?.data
      setError(d?.error || 'Login failed')
      if (d?.attemptsRemaining !== undefined) setAttempts(d.attemptsRemaining)
      if (err.response?.status === 423) setAttempts(0)
    } finally {
      setLoading(false)
    }
  }

  const quickLogin = (u) => {
    setEmail(u.email)
    setPassword('Demo@Password123')
    setError(null); setAttempts(null)
  }

  const handleSeed = async () => {
    setSeeding(true); setError(null)
    try {
      const r = await api.post('/auth/seed')
      setInfo(`✅ ${r.data.message} — ${r.data.users.filter(u=>u.created).length} users created`)
    } catch (err) {
      setError(err.response?.data?.error || 'Seed failed')
    } finally { setSeeding(false) }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <div className="w-full max-w-4xl grid md:grid-cols-2 gap-6">

        {/* Left — Login form */}
        <div className="card space-y-5">
          <div className="flex items-center gap-3">
            <svg className="w-9 h-9 text-teal shrink-0" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 2L3 7v5c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V7L12 2z"/>
            </svg>
            <div>
              <h1 className="text-xl font-bold text-white">OWASP Security Demo</h1>
              <p className="text-xs text-gray-400">LivingAI Solutions — D-16 Compliance</p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-3">
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Email</label>
              <input className="input" type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="admin@demo.com" required />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Password</label>
              <input className="input" type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="••••••••••••" required />
            </div>
            {error && (
              <div className="bg-red-900/40 border border-red-500/50 rounded-lg p-3 text-sm text-red-300">
                <span className="font-semibold">⚠ {error}</span>
                {attempts !== null && <div className="text-xs mt-1 text-red-400">Attempts remaining: <span className="font-bold">{attempts}</span> / 5 before lockout</div>}
              </div>
            )}
            {info && <div className="bg-teal/10 border border-teal/40 rounded-lg p-3 text-sm text-teal-light">{info}</div>}
            <button type="submit" disabled={loading} className="btn-primary w-full">
              {loading ? 'Authenticating…' : 'Login'}
            </button>
          </form>

          <div className="border-t border-white/10 pt-4 text-center">
            <p className="text-xs text-gray-500 mb-2">First time? Seed demo users into MongoDB Atlas</p>
            <button onClick={handleSeed} disabled={seeding} className="btn-ghost text-sm w-full">
              {seeding ? 'Seeding…' : '🌱 Seed Demo Users'}
            </button>
          </div>

          {/* A07 badge */}
          <div className="bg-navy rounded-lg p-3 text-xs space-y-1 text-gray-400">
            <div className="text-teal font-semibold text-xs mb-1">🔒 A07 Controls Active</div>
            <div>• Rate limit: 5 failures → 15-min lockout</div>
            <div>• JWT: 15-min access + 7-day refresh rotation</div>
            <div>• HttpOnly + Secure + SameSite cookies</div>
            <div>• bcrypt (cost=12) password hashing</div>
          </div>
        </div>

        {/* Right — quick-login cards */}
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-gray-300">Quick Login — Demo Users</h2>
          <p className="text-xs text-gray-500">Click to auto-fill credentials. All share password: <code className="text-teal">Demo@Password123</code></p>
          {DEMO_USERS.map(u => (
            <button key={u.email} onClick={() => quickLogin(u)}
              className="w-full text-left card hover:border-teal/50 transition-colors p-3 space-y-0.5">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-white">{u.email}</span>
                <span className={`text-xs font-bold ${u.color}`}>{u.role}</span>
              </div>
              <div className="text-xs text-gray-500">
                {u.role === 'SuperAdmin' && 'Full access — all endpoints'}
                {u.role === 'Manager' && 'Can access analyst endpoint, not admin'}
                {u.role === 'Analyst' && 'Standard data access'}
                {u.role === 'Viewer' && 'Read-only — blocked from most actions'}
                {u.role === 'Analyst (org-beta)' && 'Same role, different org — isolation demo'}
              </div>
            </button>
          ))}
          <div className="card text-xs text-gray-500 space-y-1">
            <div className="text-white font-semibold text-xs">What this demo covers</div>
            <div>All <span className="text-teal">OWASP Top 10 (2021)</span> + <span className="text-teal">API Security Top 10 (2023)</span></div>
            <div>Live Express.js code + MongoDB Atlas integration</div>
            <div>Real-time audit log streaming (SSE)</div>
          </div>
        </div>
      </div>
    </div>
  )
}
