import React, { useEffect, useRef, useState } from 'react'

const SEV_COLORS = {
  LOGIN_SUCCESS:    'text-green-400',  LOGIN_FAIL:        'text-red-400',
  LOGIN_LOCKED:     'text-red-500',    LOGOUT:            'text-gray-400',
  AUTHZ_FAILURE:    'text-red-400',    AUTHZ_SUCCESS:     'text-teal-light',
  RATE_LIMIT_HIT:   'text-orange-400', SSRF_BLOCKED:      'text-red-400',
  SSRF_ALLOWED:     'text-green-400',  HTTP_REQUEST:      'text-gray-400',
  STREAM_CONNECTED: 'text-teal',       COMPLIANCE_CHECK:  'text-blue-400',
  TOKEN_REFRESHED:  'text-yellow-400', SERVER_ERROR:      'text-red-600',
}

const OWASP_BADGE = {
  A01:'bg-red-900/50 text-red-300',  A02:'bg-red-900/50 text-red-300',
  A03:'bg-red-900/50 text-red-300',  A07:'bg-orange-900/50 text-orange-300',
  A09:'bg-amber-900/50 text-amber-300', A10:'bg-amber-900/50 text-amber-300',
  API4:'bg-orange-900/50 text-orange-300',
}

export default function LogsPage() {
  const [logs, setLogs] = useState([])
  const [connected, setConnected] = useState(false)
  const [filter, setFilter] = useState('ALL')
  const bottomRef = useRef(null)
  const esRef = useRef(null)

  useEffect(() => {
    const es = new EventSource('/api/compliance/logs/stream', { withCredentials: true })
    esRef.current = es

    es.onopen    = () => setConnected(true)
    es.onerror   = () => setConnected(false)
    es.onmessage = (e) => {
      try {
        const entry = JSON.parse(e.data)
        setLogs(prev => [entry, ...prev].slice(0, 200))
      } catch (_) {}
    }
    return () => { es.close(); setConnected(false) }
  }, [])

  // Auto-scroll when new logs arrive
  useEffect(() => {
    if (logs.length > 0) bottomRef.current?.scrollIntoView({ behavior:'smooth', block:'nearest' })
  }, [logs.length])

  const EVENT_TYPES = ['ALL', 'LOGIN_SUCCESS','LOGIN_FAIL','AUTHZ_FAILURE','SSRF_BLOCKED','RATE_LIMIT_HIT','HTTP_REQUEST']
  const filtered = filter === 'ALL' ? logs : logs.filter(l => l.event === filter)

  const clear = () => setLogs([])

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            📡 Live Security Audit Logs
            <span className={`inline-block w-2 h-2 rounded-full ${connected?'bg-green-400 animate-pulse':'bg-red-500'}`}/>
            <span className={`text-xs font-normal ${connected?'text-green-400':'text-red-400'}`}>
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </h1>
          <p className="text-sm text-gray-400 mt-0.5">A09 — Real-time SSE event stream. Every security event logged here.</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500">{logs.length} events</span>
          <button onClick={clear} className="btn-ghost text-xs py-1.5 px-3">Clear</button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap gap-2">
        {EVENT_TYPES.map(t => (
          <button key={t} onClick={() => setFilter(t)}
            className={`text-xs px-3 py-1 rounded-full border transition-all ${
              filter===t
                ? 'bg-teal border-teal text-white'
                : 'border-white/20 text-gray-400 hover:border-teal/50'
            }`}>
            {t}
          </button>
        ))}
      </div>

      {/* Log terminal */}
      <div className="bg-gray-950 border border-white/10 rounded-xl overflow-hidden">
        {/* Terminal bar */}
        <div className="flex items-center gap-2 px-4 py-2 border-b border-white/10 bg-navy">
          <span className="w-3 h-3 rounded-full bg-red-500/70"/>
          <span className="w-3 h-3 rounded-full bg-yellow-500/70"/>
          <span className="w-3 h-3 rounded-full bg-green-500/70"/>
          <span className="ml-2 text-xs text-gray-500 font-mono">security-audit-stream — {filter}</span>
        </div>
        <div className="h-[60vh] overflow-y-auto p-4 font-mono text-xs space-y-1" id="log-container">
          {filtered.length === 0 ? (
            <div className="text-gray-600 text-center mt-8">
              {connected ? 'Waiting for security events… Try logging in or running a demo.' : 'Stream disconnected. Reconnecting…'}
            </div>
          ) : (
            filtered.map((log, i) => (
              <div key={log.id || i} className="flex gap-3 hover:bg-white/[0.02] px-2 py-1 rounded group">
                <span className="text-gray-600 shrink-0 w-20 text-right">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
                <span className={`shrink-0 w-40 truncate font-semibold ${SEV_COLORS[log.event] || 'text-gray-300'}`}>
                  {log.event}
                </span>
                {log.owasp && (
                  <span className={`shrink-0 text-xs px-1.5 py-0.5 rounded font-bold ${OWASP_BADGE[log.owasp] || 'bg-gray-800 text-gray-400'}`}>
                    {log.owasp}
                  </span>
                )}
                <span className="text-gray-400 truncate">
                  {log.userId && <span className="text-teal/70">uid:{log.userId?.slice(-6)} </span>}
                  {log.role && <span className="text-yellow-400/70">[{log.role}] </span>}
                  {log.ip && <span className="text-gray-600">{log.ip} </span>}
                  {log.path && <span>{log.path} </span>}
                  {log.message && <span className="italic">{log.message}</span>}
                  {log.reason && <span className="text-red-300/80"> — {log.reason}</span>}
                  {log.url && <span className="text-orange-300/80"> url:{log.url?.slice(0,60)}</span>}
                </span>
              </div>
            ))
          )}
          <div ref={bottomRef} />
        </div>
      </div>

      <div className="card text-xs text-gray-500 space-y-1">
        <div className="text-white font-semibold text-xs mb-1">A09 Controls Active</div>
        <div className="grid sm:grid-cols-3 gap-2">
          <div>• All auth events logged (success + fail)</div>
          <div>• Authorization failures with context</div>
          <div>• Real-time SSE stream to UI</div>
          <div>• Centralized winston structured logging</div>
          <div>• DPDP Act: 1-year retention (TTL index)</div>
          <div>• Tamper-proof persistent storage in Atlas</div>
        </div>
      </div>
    </div>
  )
}
