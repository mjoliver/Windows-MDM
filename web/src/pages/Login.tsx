import { useEffect, useState } from 'react'
import { Shield, Lock } from 'lucide-react'
import { safeHttpUrl } from '../format'

export function LoginPage() {
  const [supportUrl, setSupportUrl] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/config')
      .then(r => r.json())
      .then(d => { if (d.support_url) setSupportUrl(safeHttpUrl(d.support_url)) })
      .catch(() => {})
  }, [])
  return (
    <div className="login-page" style={{ 
      display: 'flex', 
      alignItems: 'center', 
      justifyContent: 'center', 
      minHeight: '100vh',
      background: 'radial-gradient(circle at center, rgba(79, 55, 139, 0.15), var(--md-sys-color-surface) 70%)'
    }}>
      <div className="card fade-in" style={{ width: '100%', maxWidth: 440, textAlign: 'center', padding: 48 }}>
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 32 }}>
          <div className="sidebar-logo-icon" style={{ width: 64, height: 64, borderRadius: 18 }}>
            <Shield size={32} />
          </div>
        </div>

        <h2 style={{ fontSize: '2rem', fontWeight: 800, marginBottom: 12, color: 'var(--md-sys-color-on-surface)' }}>Sign in to Latchz</h2>
        <p style={{ color: 'var(--md-sys-color-on-surface-variant)', fontSize: '1rem', marginBottom: 40, lineHeight: 1.5 }}>
          Enterprise-grade MDM for modern<br />device fleets.
        </p>

        <a href="/auth/login" className="btn btn-primary" style={{ width: '100%', padding: '16px', fontSize: '1.1rem', gap: 12 }}>
          <Lock size={20} />
          Sign In
        </a>

        <div style={{ marginTop: 40, paddingTop: 24, borderTop: '1px solid var(--md-sys-color-outline-variant)' }}>
          <p style={{ fontSize: '0.8rem', opacity: 0.5 }}>Access is restricted to authorized users.</p>
          <p style={{ marginTop: 8 }}>
            <a href="https://github.com/latchzmdm/latchz" target="_blank" rel="noreferrer" style={{ fontSize: '0.85rem', fontWeight: 600, opacity: 0.7 }}>
              Latchz MDM — v1.0.0
            </a>
          </p>
          {supportUrl && (
            <p style={{ marginTop: 16 }}>
              <a
                href={supportUrl}
                target="_blank"
                rel="noreferrer"
                style={{ fontSize: '0.72rem', opacity: 0.3, letterSpacing: '0.02em' }}
              >
                setup guide
              </a>
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
