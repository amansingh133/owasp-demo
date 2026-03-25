import React, { useState } from 'react'
import { useAuth } from '../../context/AuthContext'
import api from '../../api/client'
import { ResultBox, CodeBlock } from './DemoShell'

const CODE = `// middleware/rbac.js — A01: Broken Access Control
const requireRole = (...allowed) => (req, res, next) => {
  if (!req.user || !allowed.includes(req.user.role))
    return res.status(403).json({
      error: 'Forbidden — insufficient role',
      yourRole: req.user.role,
      requiredRoles: allowed,
      owasp: 'A01',
      blocked: true,
    });
  next();
};

// routes — deny by default, explicit grants only
router.get('/analyst-endpoint',
  authenticateJWT,
  requireRole('SuperAdmin','OrgAdmin','Manager','Analyst'),
  handler
);
router.get('/admin-endpoint',
  authenticateJWT,
  requireRole('SuperAdmin'),  // only SuperAdmin
  handler
);

// Object-level auth — multi-tenant isolation
router.get('/my-data', authenticateJWT, async (req, res) => {
  const data = await Report.find({
    orgId: req.user.orgId  // locked to your org
  });
  res.json(data);
});`

export default function A01Demo() {
  const { user } = useAuth()
  const [results, setResults] = useState({})
  const [errors,  setErrors]  = useState({})
  const [loading, setLoading] = useState({})

  const run = async (key, fn) => {
    setLoading(l => ({ ...l, [key]: true }))
    setErrors(e  => ({ ...e, [key]: null }))
    try {
      const r = await fn()
      setResults(r => ({ ...r, [key]: r.data }))
    } catch (err) {
      setErrors(e => ({ ...e, [key]: { status: err.response?.status, data: err.response?.data } }))
    } finally {
      setLoading(l => ({ ...l, [key]: false }))
    }
  }

  return (
    <div className="grid lg:grid-cols-2 gap-6">
      {/* Left: controls */}
      <div className="space-y-4">
        {/* Concept */}
        <div className="card">
          <h3 className="font-semibold text-white mb-2">What is Broken Access Control?</h3>
          <p className="text-sm text-gray-400">Users act outside their intended permissions. 94% of tested apps had this flaw — it's been #1 since 2021.</p>
          <div className="mt-3 p-3 bg-red-950/30 border border-red-500/30 rounded-lg text-xs text-red-300">
            <strong>LivingAI Example:</strong> A Media360 analyst changes <code>/my-reports</code> → <code>/all-reports</code> and reads every org's CRI data.
          </div>
        </div>

        {/* Your role */}
        <div className="card">
          <div className="text-sm text-gray-400 mb-2">Your current role:</div>
          <div className="text-lg font-bold text-teal">{user?.role} <span className="text-sm text-gray-500">({user?.orgId})</span></div>
          <p className="text-xs text-gray-500 mt-1">Try each button below — some will be blocked based on your role.</p>
        </div>

        {/* Demo buttons */}
        <div className="space-y-3">
          {[
            { key:'analyst', label:'Analyst Endpoint', sub:'Requires: Analyst+', fn: () => api.get('/demo/a01/analyst-endpoint') },
            { key:'admin',   label:'Admin Endpoint',   sub:'Requires: SuperAdmin only', fn: () => api.get('/demo/a01/admin-endpoint') },
            { key:'tenant',  label:'My Org Data',      sub:'Object-level isolation', fn: () => api.get('/demo/a01/my-data') },
          ].map(({ key, label, sub, fn }) => (
            <div key={key}>
              <button onClick={() => run(key, fn)} disabled={loading[key]}
                className="btn-primary w-full text-left flex items-center justify-between">
                <div>
                  <div className="font-semibold">{label}</div>
                  <div className="text-xs opacity-70 font-normal">{sub}</div>
                </div>
                <span>{loading[key] ? '⏳' : '▶ Run'}</span>
              </button>
              {(results[key] || errors[key]) && (
                <div className="mt-2">
                  <ResultBox data={results[key]} error={errors[key]} />
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Controls checklist */}
        <div className="card text-xs space-y-1.5">
          <div className="text-white font-semibold mb-2">Active Controls</div>
          {['RBAC Middleware (6 roles)','Object-level Authorization','Deny by Default (explicit grants)','Multi-tenant DB Isolation','JWT with short expiry (15 min)'].map(c => (
            <div key={c} className="flex gap-2 text-gray-400"><span className="text-teal shrink-0">✓</span>{c}</div>
          ))}
        </div>
      </div>

      {/* Right: code */}
      <CodeBlock code={CODE} title="middleware/rbac.js + routes.js" />
    </div>
  )
}
