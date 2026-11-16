import { useCallback, useEffect, useState } from 'react'
import { UserCog, Plus, Pencil, Trash2, RefreshCw, KeyRound, ShieldCheck, Copy, Lock } from 'lucide-react'
import { Layout } from '../components/Layout'
import { SearchBar } from '../components/SearchBar'
import { EmptyState } from '../components/EmptyState'
import { Modal } from '../components/Modal'
import { api, type UserSummary, type Me, type APIKeyItem, type SecurityGovernanceSettings } from '../api'
import { timeAgo } from '../format'
import { useToast } from '../hooks/useToast'

function roleBadgeClass(role: UserSummary['role']): string {
  switch (role) {
    case 'super_admin':
      return 'badge badge-success'
    case 'admin':
      return 'badge badge-warning'
    default:
      return 'badge badge-neutral'
  }
}

function CreateUserModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (u: UserSummary) => void
}) {
  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [role, setRole] = useState<'super_admin' | 'admin' | 'user'>('user')
  const [provider, setProvider] = useState<'builtin' | 'oidc'>('builtin')
  const [password, setPassword] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const toast = useToast()

  const submit = async () => {
    if (!email.trim()) {
      setError('Email is required')
      return
    }
    if (provider === 'builtin' && password.length < 8) {
      setError('Builtin accounts require a password of at least 8 characters')
      return
    }
    setSaving(true)
    setError('')
    try {
      const created = await api.users.create({
        email: email.trim(),
        display_name: displayName.trim(),
        role,
        auth_provider: provider,
        password: password || undefined,
      })
      toast.success(`User "${created.email}" created`)
      onCreated(created)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to create user')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      open={true}
      onClose={onClose}
      title="New User Account"
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={saving}>
            {saving ? 'Creating…' : 'Create User'}
          </button>
        </>
      }
    >
      <div className="form-group">
        <label className="form-label">Email address *</label>
        <input
          className="input"
          type="email"
          value={email}
          onChange={e => setEmail(e.target.value)}
          placeholder="user@example.com"
          autoFocus
        />
      </div>
      <div className="form-group">
        <label className="form-label">Display name</label>
        <input
          className="input"
          value={displayName}
          onChange={e => setDisplayName(e.target.value)}
          placeholder="Optional full name"
        />
      </div>
      <div className="grid-2" style={{ marginBottom: 0 }}>
        <div className="form-group">
          <label className="form-label">Role</label>
          <select
            className="input"
            value={role}
            onChange={e => setRole(e.target.value as 'super_admin' | 'admin' | 'user')}
          >
            <option value="user">user (Device Enrollment & Read-Only)</option>
            <option value="admin">admin (Manage Fleet, Profiles & Groups)</option>
            <option value="super_admin">super_admin (Full Control + Users)</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Auth Provider</label>
          <select
            className="input"
            value={provider}
            onChange={e => setProvider(e.target.value as 'builtin' | 'oidc')}
          >
            <option value="builtin">builtin (Local Password)</option>
            <option value="oidc">oidc (SSO / Identity Provider)</option>
          </select>
        </div>
      </div>
      {provider === 'builtin' && (
        <div className="form-group">
          <label className="form-label">Initial Password * (min 8 characters)</label>
          <input
            className="input"
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="••••••••"
          />
        </div>
      )}
      {error && <p style={{ color: 'var(--md-sys-color-error)', fontSize: '0.82rem', marginTop: 8 }}>{error}</p>}
    </Modal>
  )
}

function EditUserModal({
  user,
  isSelf,
  onClose,
  onUpdated,
}: {
  user: UserSummary
  isSelf: boolean
  onClose: () => void
  onUpdated: (u: UserSummary) => void
}) {
  const [displayName, setDisplayName] = useState(user.display_name)
  const [role, setRole] = useState<'super_admin' | 'admin' | 'user'>(user.role)
  const [password, setPassword] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const toast = useToast()

  const submit = async () => {
    if (password && password.length < 8) {
      setError('New password must be at least 8 characters')
      return
    }
    setSaving(true)
    setError('')
    try {
      const updated = await api.users.update(user.id, {
        display_name: displayName.trim(),
        role,
        password: password || undefined,
      })
      toast.success(`Updated "${updated.email}"`)
      onUpdated(updated)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to update user')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      open={true}
      onClose={onClose}
      title={`Edit User: ${user.email}`}
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={saving}>
            {saving ? 'Saving…' : 'Save Changes'}
          </button>
        </>
      }
    >
      <div className="form-group">
        <label className="form-label">Display name</label>
        <input
          className="input"
          value={displayName}
          onChange={e => setDisplayName(e.target.value)}
          placeholder="Optional full name"
        />
      </div>
      <div className="form-group">
        <label className="form-label">Role</label>
        <select
          className="input"
          value={role}
          disabled={isSelf && user.role === 'super_admin'}
          onChange={e => setRole(e.target.value as 'super_admin' | 'admin' | 'user')}
        >
          <option value="user">user</option>
          <option value="admin">admin</option>
          <option value="super_admin">super_admin</option>
        </select>
        {isSelf && user.role === 'super_admin' && (
          <p style={{ fontSize: '0.78rem', opacity: 0.6, marginTop: 6 }}>
            You cannot demote your own super_admin account.
          </p>
        )}
      </div>
      <div className="form-group">
        <label className="form-label">Reset Builtin Password (leave blank to keep unchanged)</label>
        <input
          className="input"
          type="password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          placeholder="New password (min 8 characters)"
        />
      </div>
      {error && <p style={{ color: 'var(--md-sys-color-error)', fontSize: '0.82rem', marginTop: 8 }}>{error}</p>}
    </Modal>
  )
}

export function UsersPage() {
  const [users, setUsers] = useState<UserSummary[]>([])
  const [me, setMe] = useState<Me | null>(null)
  const [totpStatus, setTotpStatus] = useState<{ enabled: boolean; recovery_codes_remaining: number } | null>(null)
  const [totpSetup, setTotpSetup] = useState<{ secret: string; otpauth_url: string } | null>(null)
  const [totpCode, setTotpCode] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null)
  const [apiKeys, setApiKeys] = useState<APIKeyItem[]>([])
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyScope, setNewKeyScope] = useState<'read_only' | 'ops' | 'admin'>('read_only')
  const [newKeyDays, setNewKeyDays] = useState(90)
  const [mintedRawKey, setMintedRawKey] = useState<string | null>(null)
  const [gov, setGov] = useState<SecurityGovernanceSettings | null>(null)
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [editing, setEditing] = useState<UserSummary | null>(null)
  const [deleting, setDeleting] = useState<UserSummary | null>(null)
  const [busyDelete, setBusyDelete] = useState(false)
  const toast = useToast()

  const load = useCallback(() => {
    setLoading(true)
    Promise.all([
      api.users.list(),
      api.me(),
      api.totp.status().catch(() => null),
      api.apiKeys.list().catch(() => []),
      api.governance.get().catch(() => null),
    ])
      .then(([u, current, ts, keys, gv]) => {
        setUsers(u)
        setMe(current)
        setTotpStatus(ts)
        setApiKeys(keys)
        setGov(gv)
      })
      .catch(e => toast.error(e instanceof Error ? e.message : 'Failed to load users'))
      .finally(() => setLoading(false))
  }, [toast])

  useEffect(() => {
    load()
  }, [load])

  const isSuperAdmin = me?.role === 'super_admin'

  const filtered = users.filter(u =>
    !search ||
    u.email.toLowerCase().includes(search.toLowerCase()) ||
    u.display_name.toLowerCase().includes(search.toLowerCase()) ||
    u.role.toLowerCase().includes(search.toLowerCase())
  )

  const confirmDelete = async () => {
    if (!deleting) return
    setBusyDelete(true)
    try {
      await api.users.delete(deleting.id)
      setUsers(prev => prev.filter(u => u.id !== deleting.id))
      toast.success(`Deleted user "${deleting.email}"`)
      setDeleting(null)
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to delete user')
    } finally {
      setBusyDelete(false)
    }
  }

  return (
    <Layout title="Users & Roles">
      <div className="page-header">
        <div className="page-header-left">
          <h1>Users & Roles</h1>
          <p>
            {users.length} registered account{users.length !== 1 ? 's' : ''} — role-based access control & enrollment accounts
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-secondary" onClick={load} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            Refresh
          </button>
          {isSuperAdmin && (
            <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
              <Plus size={15} />
              New User
            </button>
          )}
        </div>
      </div>

      <div className="table-wrap">
        <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--md-sys-color-outline-variant)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
          <SearchBar
            value={search}
            onChange={setSearch}
            placeholder="Search by email, name, or role..."
            style={{ maxWidth: 340 }}
          />
          {!isSuperAdmin && (
            <span style={{ fontSize: '0.8rem', opacity: 0.65, display: 'flex', alignItems: 'center', gap: 6 }}>
              <ShieldCheck size={14} />
              Read-only view (super_admin required to modify accounts)
            </span>
          )}
        </div>

        {filtered.length === 0 ? (
          <EmptyState
            icon={<UserCog size={48} style={{ opacity: 0.3 }} />}
            title={search ? 'No matching users' : 'No users found'}
            description={search ? 'Try a different search term' : 'Create a user to grant enrollment or dashboard access'}
          />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Account</th>
                <th>Role</th>
                <th>Auth Provider</th>
                <th>Credentials</th>
                <th>Last Login</th>
                {isSuperAdmin && <th style={{ textAlign: 'right' }}>Actions</th>}
              </tr>
            </thead>
            <tbody>
              {filtered.map(u => {
                const isSelf = !!me && u.email.toLowerCase() === me.email.toLowerCase()
                return (
                  <tr key={u.id}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                        <div className="detail-icon">
                          <UserCog size={17} />
                        </div>
                        <div>
                          <div style={{ fontWeight: 700, color: 'var(--md-sys-color-on-surface)' }}>
                            {u.email}
                            {isSelf && <span style={{ marginLeft: 8, fontSize: '0.72rem', opacity: 0.55 }}>(you)</span>}
                          </div>
                          <div style={{ fontSize: '0.8rem', opacity: 0.55 }}>
                            {u.display_name || `Created ${timeAgo(u.created_at)}`}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td>
                      <span className={roleBadgeClass(u.role)}>
                        <span className="badge-dot" />
                        {u.role}
                      </span>
                    </td>
                    <td style={{ textTransform: 'uppercase', fontSize: '0.78rem', letterSpacing: '0.04em', opacity: 0.8 }}>
                      {u.auth_provider}
                    </td>
                    <td>
                      {u.auth_provider === 'builtin' ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: '0.82rem', opacity: u.has_password ? 0.9 : 0.5 }}>
                            <KeyRound size={13} />
                            {u.has_password ? 'Password set' : 'No password set'}
                          </span>
                          {u.totp_enabled && (
                            <span style={{ fontSize: '0.72rem', color: 'var(--success)', fontWeight: 700 }}>
                              • TOTP 2FA Enabled
                            </span>
                          )}
                        </div>
                      ) : (
                        <span style={{ fontSize: '0.82rem', opacity: 0.6 }}>Federated SSO</span>
                      )}
                    </td>
                    <td style={{ opacity: 0.65 }}>{timeAgo(u.last_login)}</td>
                    {isSuperAdmin && (
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: 8 }}>
                          <button className="btn btn-sm btn-secondary" onClick={() => setEditing(u)}>
                            <Pencil size={13} />
                            Edit
                          </button>
                          {isSelf ? (
                            <span
                              className="tooltip-wrap"
                              data-tooltip="You cannot delete your own currently signed-in account."
                            >
                              <button className="btn btn-sm btn-secondary" disabled style={{ opacity: 0.4, cursor: 'not-allowed' }}>
                                <Trash2 size={13} />
                              </button>
                            </span>
                          ) : (
                            <button className="btn btn-sm btn-danger" onClick={() => setDeleting(u)}>
                              <Trash2 size={13} />
                            </button>
                          )}
                        </div>
                      </td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* TOTP 2FA Self-Service + Secret Reveal Governance */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 20, marginTop: 24 }}>
        <div className="card" style={{ padding: 24 }}>
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <Lock size={17} />
            Two-Factor Authentication (RFC 6238 TOTP)
          </div>
          <div style={{ fontSize: '0.82rem', opacity: 0.72, marginBottom: 14 }}>
            Protect your builtin administrator account with a 6-digit authenticator code and 8 single-use recovery codes.
          </div>

          {totpStatus?.enabled ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
              <span style={{ fontSize: '0.85rem', color: 'var(--success)', fontWeight: 700 }}>
                Active ({totpStatus.recovery_codes_remaining} recovery code(s) remaining)
              </span>
              <button
                className="btn btn-sm btn-secondary"
                style={{ color: 'var(--md-sys-color-error)' }}
                onClick={async () => {
                  try {
                    await api.totp.disable()
                    setTotpSetup(null)
                    setRecoveryCodes(null)
                    toast.success('Disabled TOTP two-factor authentication.')
                    load()
                  } catch (e) {
                    toast.error(e instanceof Error ? e.message : String(e))
                  }
                }}
              >
                Disable 2FA
              </button>
            </div>
          ) : !totpSetup ? (
            <button
              className="btn btn-secondary btn-sm"
              onClick={async () => {
                try {
                  const s = await api.totp.setup()
                  setTotpSetup(s)
                  setRecoveryCodes(null)
                } catch (e) {
                  toast.error(e instanceof Error ? e.message : String(e))
                }
              }}
            >
              Enroll Authenticator App
            </button>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ fontSize: '0.78rem', opacity: 0.8 }}>
                Add this Base32 key (or <code className="mono">otpauth://</code> URI) in your authenticator app, then enter the 6-digit code:
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <code className="mono" style={{ padding: '6px 10px', borderRadius: 8, background: 'rgba(0,0,0,0.28)', fontSize: '0.82rem', flex: 1 }}>
                  {totpSetup.secret}
                </code>
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  onClick={() => {
                    navigator.clipboard?.writeText(totpSetup.otpauth_url)
                    toast.success('Copied otpauth:// URI.')
                  }}
                >
                  <Copy size={12} /> URI
                </button>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  className="form-input mono"
                  placeholder="123456"
                  maxLength={8}
                  value={totpCode}
                  onChange={e => setTotpCode(e.target.value)}
                />
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  disabled={totpCode.trim().length < 6}
                  onClick={async () => {
                    try {
                      const res = await api.totp.enable(totpCode.trim())
                      setRecoveryCodes(res.recovery_codes)
                      setTotpSetup(null)
                      setTotpCode('')
                      toast.success('TOTP 2FA enabled! Save your recovery codes.')
                      load()
                    } catch (e) {
                      toast.error(e instanceof Error ? e.message : String(e))
                    }
                  }}
                >
                  Verify &amp; Enable
                </button>
              </div>
            </div>
          )}

          {recoveryCodes && (
            <div style={{ marginTop: 14, padding: 12, borderRadius: 10, background: 'rgba(180,225,151,0.08)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
              <div style={{ fontSize: '0.76rem', fontWeight: 700, marginBottom: 6 }}>
                Save Your 8 Single-Use Recovery Codes (shown once):
              </div>
              <div className="mono" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4, fontSize: '0.8rem' }}>
                {recoveryCodes.map(c => <span key={c}>{c}</span>)}
              </div>
            </div>
          )}
        </div>

        <div className="card" style={{ padding: 24 }}>
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <ShieldCheck size={17} />
            Secret Reveal Governance
          </div>
          <div style={{ fontSize: '0.82rem', opacity: 0.72, marginBottom: 16 }}>
            Require administrators to enter a ticket or incident justification before decrypting BitLocker 48-digit recovery keys or Cloud LAPS local administrator passwords.
          </div>
          {gov && (
            <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: '0.88rem', fontWeight: 600, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={gov.require_reveal_justification}
                onChange={async e => {
                  try {
                    const updated = await api.governance.update(e.target.checked)
                    setGov(updated)
                    toast.success(updated.require_reveal_justification ? 'Mandatory reveal justification enabled.' : 'Mandatory reveal justification disabled.')
                  } catch (err) {
                    toast.error(err instanceof Error ? err.message : String(err))
                  }
                }}
              />
              Require Justification Reason on BitLocker &amp; LAPS Reveals
            </label>
          )}
        </div>
      </div>

      {/* Scoped Automation API Keys (lzak_...) */}
      <div className="card" style={{ marginTop: 24, padding: 24 }}>
        <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <KeyRound size={18} />
          Scoped Automation API Keys (<code className="mono">lzak_…</code>)
        </div>
        <div style={{ fontSize: '0.82rem', opacity: 0.72, marginBottom: 16 }}>
          Mint SHA-256-hashed Bearer tokens (<code className="mono">Authorization: Bearer lzak_…</code>) for SIEM collectors, Grafana, or CI automation with <code className="mono">read_only</code>, <code className="mono">ops</code>, or <code className="mono">admin</code> scope.
        </div>

        <form
          onSubmit={async e => {
            e.preventDefault()
            if (!newKeyName.trim()) return
            try {
              const created = await api.apiKeys.create({
                name: newKeyName.trim(),
                scope: newKeyScope,
                expires_in_days: newKeyDays,
              })
              setMintedRawKey(created.key ?? null)
              setNewKeyName('')
              toast.success(`Minted '${created.name}' (${created.scope}) API key.`)
              load()
            } catch (err) {
              toast.error(err instanceof Error ? err.message : String(err))
            }
          }}
          style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 16 }}
        >
          <input
            className="form-input"
            style={{ flex: '1 1 220px' }}
            placeholder="Key label (e.g. Splunk Collector)"
            value={newKeyName}
            onChange={e => setNewKeyName(e.target.value)}
          />
          <select
            className="form-input"
            style={{ width: 190 }}
            value={newKeyScope}
            onChange={e => setNewKeyScope(e.target.value as 'read_only' | 'ops' | 'admin')}
          >
            <option value="read_only">read_only (GET only)</option>
            <option value="ops">ops (Sync/Scan, no Wipe)</option>
            <option value="admin">admin (Full Fleet API)</option>
          </select>
          <input
            type="number"
            className="form-input"
            style={{ width: 130 }}
            min={0}
            max={3650}
            value={newKeyDays}
            onChange={e => setNewKeyDays(Number(e.target.value))}
            title="Expiry in days (0 = never expires)"
          />
          <button type="submit" className="btn btn-primary" disabled={!newKeyName.trim()}>
            <Plus size={14} /> Mint Key
          </button>
        </form>

        {mintedRawKey && (
          <div style={{ marginBottom: 16, padding: '12px 14px', borderRadius: 10, background: 'rgba(208,188,255,0.1)', border: '1px solid var(--md-sys-color-outline-variant)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ overflow: 'hidden' }}>
              <div style={{ fontSize: '0.74rem', fontWeight: 700, opacity: 0.8 }}>Copy API Key Now (will not be shown again):</div>
              <div className="mono" style={{ fontSize: '0.84rem', wordBreak: 'break-all' }}>{mintedRawKey}</div>
            </div>
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              onClick={() => {
                navigator.clipboard?.writeText(mintedRawKey)
                toast.success('Copied Bearer API key to clipboard.')
              }}
            >
              <Copy size={13} /> Copy
            </button>
          </div>
        )}

        {apiKeys.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Prefix</th>
                  <th>Scope</th>
                  <th>Last Used</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {apiKeys.map(k => (
                  <tr key={k.id}>
                    <td style={{ fontWeight: 700 }}>{k.name}</td>
                    <td className="mono">{k.key_prefix}…</td>
                    <td><span className="badge badge-neutral">{k.scope}</span></td>
                    <td style={{ opacity: 0.65 }}>{k.last_used_at ? timeAgo(k.last_used_at) : 'Never'}</td>
                    <td>
                      <span className={k.revoked ? 'badge badge-danger' : 'badge badge-success'}>
                        {k.revoked ? 'Revoked' : 'Active'}
                      </span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        type="button"
                        className="btn btn-sm btn-secondary"
                        style={{ color: 'var(--md-sys-color-error)' }}
                        onClick={async () => {
                          try {
                            await api.apiKeys.revoke(k.id, k.revoked)
                            toast.success(k.revoked ? 'Deleted API key.' : 'Revoked API key.')
                            load()
                          } catch (e) {
                            toast.error(e instanceof Error ? e.message : String(e))
                          }
                        }}
                      >
                        <Trash2 size={13} /> {k.revoked ? 'Delete' : 'Revoke'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onCreated={u => {
            setUsers(prev => [...prev, u])
            setShowCreate(false)
          }}
        />
      )}

      {editing && (
        <EditUserModal
          user={editing}
          isSelf={!!me && editing.email.toLowerCase() === me.email.toLowerCase()}
          onClose={() => setEditing(null)}
          onUpdated={updated => {
            setUsers(prev => prev.map(u => (u.id === updated.id ? updated : u)))
            setEditing(null)
          }}
        />
      )}

      {deleting && (
        <Modal
          open={true}
          onClose={() => setDeleting(null)}
          title="Delete User Account"
          footer={
            <>
              <button className="btn btn-secondary" onClick={() => setDeleting(null)}>Cancel</button>
              <button className="btn btn-danger" onClick={confirmDelete} disabled={busyDelete}>
                {busyDelete ? 'Deleting…' : 'Delete User'}
              </button>
            </>
          }
        >
          <p style={{ lineHeight: 1.6 }}>
            Remove <strong>{deleting.email}</strong> ({deleting.role})? Existing devices enrolled by this user remain managed,
            but this account will no longer be able to sign in or enroll new devices.
          </p>
        </Modal>
      )}
    </Layout>
  )
}
