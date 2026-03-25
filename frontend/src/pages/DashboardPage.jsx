import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import api from '../api/client'

const SEV_STYLE = { CRITICAL:'badge-critical', HIGH:'badge-high', MEDIUM:'badge-medium' }

const OWASP_META = {
  A01:{ icon:'🔐', color:'border-red-500/50 hover:border-red-400' },
  A02:{ icon:'🔑', color:'border-red-500/50 hover:border-red-400' },
  A03:{ icon:'💉', color:'border-red-500/50 hover:border-red-400' },
  A04:{ icon:'🏗️', color:'border-orange-500/50 hover:border-orange-400' },
  A05:{ icon:'⚙️', color:'border-orange-500/50 hover:border-orange-400' },
  A06:{ icon:'📦', color:'border-orange-500/50 hover:border-orange-400' },
  A07:{ icon:'🔓', color:'border-orange-500/50 hover:border-orange-400' },
  A08:{ icon:'🧬', color:'border-orange-500/50 hover:border-orange-400' },
  A09:{ icon:'📋', color:'border-amber-500/50 hover:border-amber-400' },
  A10:{ icon:'🌐', color:'border-amber-500/50 hover:border-amber-400' },
}

export default function DashboardPage() {
  const { user } = useAuth()
  const [status, setStatus] = useState(null)
  const [apiSec, setApiSec] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      api.get('/compliance/status'),
      api.get('/compliance/api-security'),
    ]).then(([s, a]) => {
      setStatus(s.data)
      setApiSec(a.data)
    }).finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="flex items-center justify-center h-64 text-teal animate-pulse">Loading compliance status…</div>
  )

  const score = status?.overallScore ?? 0
  const total = status?.totalControls ?? 10

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">OWASP Security Compliance Dashboard</h1>
          <p className="text-sm text-gray-400 mt-1">LivingAI Solutions — Document D-16 v1.0 • Express.js + MongoDB Atlas</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-3xl font-black text-teal">{score}/{total}</div>
            <div className="text-xs text-gray-400">Controls Compliant</div>
          </div>
          <div className="w-14 h-14 rounded-full border-4 border-teal flex items-center justify-center">
            <span className="text-sm font-bold text-teal">{Math.round(score/total*100)}%</span>
          </div>
        </div>
      </div>

      {/* Role banner */}
      <div className="bg-navy border border-teal/30 rounded-xl p-4 flex flex-wrap items-center gap-4 text-sm">
        <div className="flex items-center gap-2">
          <span className="text-gray-400">Logged in as:</span>
          <span className="font-bold text-white">{user?.email}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-gray-400">Role:</span>
          <span className="badge-compliant">{user?.role}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-gray-400">Org:</span>
          <span className="text-teal font-mono text-xs">{user?.orgId}</span>
        </div>
        <div className="ml-auto">
          <Link to="/logs" className="btn-ghost text-xs py-1.5 px-3">📡 Live Audit Logs →</Link>
        </div>
      </div>

      {/* OWASP Web Top 10 grid */}
      <section>
        <h2 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
          <span className="w-2 h-5 bg-teal rounded inline-block"/>
          OWASP Web Application Top 10 (2021)
        </h2>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {status?.items?.map(item => {
            const meta = OWASP_META[item.id] || {}
            return (
              <Link key={item.id} to={`/demo/${item.id.toLowerCase()}`}
                className={`card border transition-all group cursor-pointer ${meta.color}`}>
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xl">{meta.icon}</span>
                    <div>
                      <div className="text-xs text-gray-500 font-mono">{item.id}</div>
                      <div className="font-semibold text-white text-sm leading-tight">{item.name}</div>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-1">
                    <span className={SEV_STYLE[item.severity]}>{item.severity}</span>
                    <span className="badge-compliant">✓ PASS</span>
                  </div>
                </div>
                <div className="space-y-1 mb-3">
                  {item.controls.slice(0,3).map(c => (
                    <div key={c.name} className="flex items-center gap-2 text-xs text-gray-400">
                      <span className="text-teal shrink-0">✓</span>
                      <span className="truncate">{c.name}</span>
                    </div>
                  ))}
                  {item.controls.length > 3 && (
                    <div className="text-xs text-gray-600">+{item.controls.length-3} more controls</div>
                  )}
                </div>
                <div className="text-xs text-teal group-hover:text-teal-light transition-colors">
                  {item.demoEndpoint ? '▶ Run Interactive Demo →' : '📖 View Controls →'}
                </div>
              </Link>
            )
          })}
        </div>
      </section>

      {/* API Security Top 10 */}
      <section>
        <h2 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
          <span className="w-2 h-5 bg-teal rounded inline-block"/>
          OWASP API Security Top 10 (2023)
        </h2>
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 text-xs border-b border-white/10">
                <th className="pb-2 pr-4">ID</th>
                <th className="pb-2 pr-4">Vulnerability</th>
                <th className="pb-2 pr-4">Status</th>
                <th className="pb-2">Fix Applied</th>
              </tr>
            </thead>
            <tbody>
              {apiSec?.items?.map((item, i) => (
                <tr key={item.id} className={`${i%2===0?'bg-white/[0.02]':''} border-b border-white/5`}>
                  <td className="py-2 pr-4 font-mono text-xs text-teal">{item.id}</td>
                  <td className="py-2 pr-4 font-medium text-white text-xs">{item.name}</td>
                  <td className="py-2 pr-4"><span className="badge-compliant">✓ PASS</span></td>
                  <td className="py-2 text-xs text-gray-400">{item.fix}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
