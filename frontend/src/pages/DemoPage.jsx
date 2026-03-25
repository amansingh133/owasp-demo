import { useNavigate, useParams } from 'react-router-dom'
import A01Demo from '../components/demos/A01Demo'
import A02Demo from '../components/demos/A02Demo'
import A03Demo from '../components/demos/A03Demo'
import A05Demo from '../components/demos/A05Demo'
import A06Demo from '../components/demos/A06Demo'
import A07Demo from '../components/demos/A07Demo'
import A08Demo from '../components/demos/A08Demo'
import A10Demo from '../components/demos/A10Demo'

const DEMOS = {
  a01: A01Demo,
  a02: A02Demo,
  a03: A03Demo,
  a05: A05Demo,
  a06: A06Demo,
  a07: A07Demo,
  a08: A08Demo,
  a10: A10Demo,
}

const ARCHITECTURE_DEMOS = {
  a04: {
    id: 'A04',
    title: 'Insecure Design',
    severity: 'HIGH',
    points: [
      'STRIDE threat modelling conducted for every module before development',
      'Security requirements defined alongside functional requirements in PRD (D-05)',
      'Multi-tenant data isolation at the MongoDB Atlas query layer — never application-level filtering alone',
      'Secure design patterns: Defense-in-Depth, Least Privilege, Fail-Safe Defaults',
      'Abuse case testing alongside use case testing in every sprint',
      'Secure Development Lifecycle (SDL) with security gates at each sprint review',
    ],
    note: 'A04 is an architectural control — it cannot be demonstrated with a single API call. It is verified through design review, threat models, and the structure of the codebase itself.',
  },
  a09: {
    id: 'A09',
    title: 'Security Logging & Monitoring Failures',
    severity: 'MEDIUM',
    points: [
      'All authentication events logged — success and failure — with timestamp, IP, and user ID',
      'All authorization failures logged with user role, required roles, and endpoint path',
      'All data export and download events logged with record count',
      'Real-time SSE audit log stream — visible in the Live Logs tab',
      'Centralized Winston logging with structured JSON output',
      'Log retention: minimum 1 year (DPDP Act compliance)',
      'Incident response plan documented and tested',
    ],
    note: 'A09 is demonstrated live in the Live Logs tab — open it and watch every security event appear in real time as you use the app.',
    linkLabel: 'Go to Live Logs →',
    linkTo: '/logs',
  },
}

export default function DemoPage() {
  const { id }   = useParams()
  const navigate = useNavigate()
  const Demo     = DEMOS[id]
  const archDemo = ARCHITECTURE_DEMOS[id]

  return (
    <div className="space-y-4">
      <button
        onClick={() => navigate('/')}
        className="btn-ghost flex items-center gap-2 text-xs"
      >
        ← Back to Dashboard
      </button>

      {Demo ? (
        <Demo />
      ) : archDemo ? (
        <ArchitectureDemo {...archDemo} navigate={navigate} />
      ) : (
        <div className="card text-center py-16">
          <p className="text-slate-400 text-lg">
            No demo found for{' '}
            <span className="text-teal font-bold uppercase">{id}</span>
          </p>
          <p className="text-slate-500 text-sm mt-2">
            Use the Dashboard to navigate to available demos.
          </p>
        </div>
      )}
    </div>
  )
}

function ArchitectureDemo({ id, title, severity, points, note, linkLabel, linkTo, navigate }) {
  const SEV = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium' }

  return (
    <div className="space-y-4">
      <div className="card border-teal/30">
        <div className="flex items-start gap-3 mb-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="font-mono text-teal font-bold text-lg">{id}</span>
              <span className={SEV[severity]}>{severity}</span>
              <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded">
                Architecture Control
              </span>
            </div>
            <h2 className="text-xl font-bold text-white">{title}</h2>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-4">
          {points.map((p, i) => (
            <div
              key={i}
              className="flex items-start gap-2 bg-slate-900 border border-slate-700/60 rounded-lg px-3 py-2.5 text-xs"
            >
              <span className="text-teal shrink-0 font-bold mt-0.5">✓</span>
              <span className="text-slate-300 leading-relaxed">{p}</span>
            </div>
          ))}
        </div>

        <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 text-sm">
          <p className="text-amber-300 font-semibold mb-1">ℹ How this is verified</p>
          <p className="text-slate-400 text-xs leading-relaxed">{note}</p>
          {linkLabel && linkTo && (
            <button
              onClick={() => navigate(linkTo)}
              className="btn-teal mt-3 text-xs"
            >
              {linkLabel}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
