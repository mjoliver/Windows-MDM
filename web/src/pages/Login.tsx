import { useEffect, useState } from 'react'
import { Shield } from 'lucide-react'

export function LoginPage() {
  const [supportUrl, setSupportUrl] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/config')
      .then(r => r.json())
      .then(d => { if (d.support_url) setSupportUrl(d.support_url) })
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
          Enterprise-grade MDM for modern<br />Windows fleets.
        </p>

        <a href="/auth/login" className="btn btn-primary" style={{ width: '100%', padding: '16px', fontSize: '1.1rem', gap: 12 }}>
          <svg width="20" height="20" viewBox="0 0 48 48">
            <path fill="currentColor" opacity="0.8" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
            <path fill="currentColor" opacity="0.9" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
            <path fill="currentColor" opacity="0.8" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
            <path fill="currentColor" opacity="1" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
          </svg>
          Sign in with Google
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
