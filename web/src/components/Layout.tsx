import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Monitor, Shield, Users,
  CheckSquare, LogOut
} from 'lucide-react'
import { api, type Me } from '../api'
import { useEffect, useState } from 'react'

interface Props { children: React.ReactNode; title: string }

// Only routes that exist are listed (Policy Catalog / Settings pages are not
// implemented yet, so their nav links were removed to avoid dead navigation).
const navItems = [
  { to: '/',          icon: LayoutDashboard, label: 'Overview' },
  { to: '/devices',   icon: Monitor,         label: 'Devices' },
  { to: '/profiles',  icon: Shield,          label: 'Profiles' },
  { to: '/groups',    icon: Users,           label: 'Groups' },
  { to: '/compliance',icon: CheckSquare,     label: 'Compliance' },
]

export function Layout({ children, title }: Props) {
  const [me, setMe] = useState<Me | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    // Auth gate: on failure, redirect to login (api also redirects on 401).
    api.me().then(setMe).catch(() => navigate('/login'))
  }, [])

  // Do not mount the authenticated layout (or its children, which fetch data)
  // until the session is confirmed.
  if (!me) {
    return <div className="app-layout" style={{ minHeight: '100vh' }} />
  }

  const initials = me?.display_name
    ? me.display_name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase()
    : me?.email?.slice(0, 2).toUpperCase() ?? '??'

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="sidebar-logo-icon">
            <Shield size={22} strokeWidth={2.5} />
          </div>
          <span className="sidebar-logo-text">Latchz</span>
        </div>

        <nav className="sidebar-nav">
          <span className="nav-section-label" style={{ fontSize: '0.7rem', fontWeight: 700, opacity: 0.4, margin: '16px 12px 8px', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Management</span>
          {navItems.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
            >
              <item.icon size={18} />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          {me && (
            <div className="user-chip" style={{ cursor: 'pointer' }} onClick={() => {
              api.logout().then(() => navigate('/login'))
            }}>
              <div className="detail-icon" style={{ width: 32, height: 32, borderRadius: 10, fontSize: '0.75rem', fontWeight: 800 }}>{initials}</div>
              <div className="user-info">
                <div className="user-name" style={{ fontSize: '0.85rem', fontWeight: 700 }}>{me.display_name || me.email}</div>
                <div className="user-role" style={{ fontSize: '0.7rem', opacity: 0.6 }}>{me.role}</div>
              </div>
              <LogOut size={14} style={{ marginLeft: 'auto', opacity: 0.3 }} />
            </div>
          )}
        </div>
      </aside>

      {/* Main */}
      <div className="page-content">
        <header className="topbar">
          <h1 className="topbar-title">{title}</h1>
          <div className="topbar-right">
            <span style={{ fontSize: '0.8rem', fontWeight: 500, opacity: 0.6 }}>
              {new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' })}
            </span>
          </div>
        </header>
        <main className="page-body fade-in">
          {children}
        </main>
      </div>
    </div>
  )
}
