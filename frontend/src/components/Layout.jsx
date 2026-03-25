import React from 'react'
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const ROLE_COLORS = {
  SuperAdmin: 'text-red-400',  OrgAdmin: 'text-orange-400',
  Manager:    'text-yellow-400', Analyst: 'text-teal-light',
  Viewer:     'text-gray-400',  API: 'text-purple-400',
}

export default function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <div className="min-h-screen flex flex-col">
      {/* Top Nav */}
      <nav className="bg-navy border-b border-white/10 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 h-14 flex items-center justify-between">
          <div className="flex items-center gap-6">
            {/* Logo */}
            <NavLink to="/" className="flex items-center gap-2 font-bold text-white">
              <svg className="w-7 h-7 text-teal" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 2L3 7v5c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V7L12 2z"/>
              </svg>
              <span className="hidden sm:block text-sm">OWASP<span className="text-teal"> Demo</span></span>
            </NavLink>
            <NavLink to="/"         end className={({isActive})=>`text-sm transition-colors ${isActive?'text-teal':'text-gray-400 hover:text-white'}`}>Dashboard</NavLink>
            <NavLink to="/logs"         className={({isActive})=>`text-sm transition-colors ${isActive?'text-teal':'text-gray-400 hover:text-white'}`}>Live Logs</NavLink>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-xs text-right hidden sm:block">
              <div className={`font-semibold ${ROLE_COLORS[user?.role] || 'text-white'}`}>{user?.role}</div>
              <div className="text-gray-500">{user?.orgId}</div>
            </div>
            <button onClick={handleLogout} className="btn-ghost text-sm py-1.5 px-3">Logout</button>
          </div>
        </div>
      </nav>

      {/* Page content */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 py-6">
        <Outlet />
      </main>
    </div>
  )
}
