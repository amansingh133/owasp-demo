import React from 'react'

export function ResultBox({ data, error }) {
  if (error) return (
    <div className="bg-red-950/50 border border-red-500/50 rounded-lg p-4">
      <div className="text-red-400 font-semibold text-sm mb-2">⚠ Response ({error.status || 'Error'})</div>
      <pre className="text-xs text-red-300 whitespace-pre-wrap overflow-auto max-h-64">{JSON.stringify(error.data || error.message, null, 2)}</pre>
    </div>
  )
  if (!data) return null
  return (
    <div className={`border rounded-lg p-4 ${data.blocked || data.status==='BLOCKED' || data.owasp ? 'bg-green-950/30 border-teal/40' : 'bg-navy border-white/10'}`}>
      <div className="text-teal font-semibold text-sm mb-2">✓ Response</div>
      <pre className="text-xs text-gray-300 whitespace-pre-wrap overflow-auto max-h-72">{JSON.stringify(data, null, 2)}</pre>
    </div>
  )
}

export function CodeBlock({ code, title }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard?.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div className="border border-white/10 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between bg-navy px-4 py-2 border-b border-white/10">
        <span className="text-xs text-gray-400 font-mono">{title || 'Express.js'}</span>
        <button onClick={copy} className="text-xs text-gray-500 hover:text-teal transition-colors">{copied ? '✓ Copied' : 'Copy'}</button>
      </div>
      <div className="flex gap-2 px-4 pt-3 pb-1">
        <span className="w-2.5 h-2.5 rounded-full bg-red-500/70"/>
        <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/70"/>
        <span className="w-2.5 h-2.5 rounded-full bg-green-500/70"/>
      </div>
      <pre className="code-block border-0 rounded-none rounded-b-lg text-xs max-h-64 overflow-auto">{code}</pre>
    </div>
  )
}

// need useState import
import { useState } from 'react'
export { useState }
