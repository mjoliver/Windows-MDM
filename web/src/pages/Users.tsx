import { useCallback, useEffect, useState } from 'react'
import { UserCog, Plus, Pencil, Trash2, RefreshCw, KeyRound, ShieldCheck } from 'lucide-react'
import { Layout } from '../components/Layout'
import { SearchBar } from '../components/SearchBar'
import { EmptyState } from '../components/EmptyState'
import { Modal } from '../components/Modal'
import { api, type UserSummary, type Me } from '../api'
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
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [editing, setEditing] = useState<UserSummary | null>(null)
  const [deleting, setDeleting] = useState<UserSummary | null>(null)
  const [busyDelete, setBusyDelete] = useState(false)
  const toast = useToast()

  const load = useCallback(() => {
    setLoading(true)
    Promise.all([api.users.list(), api.me()])
      .then(([u, current]) => {
        setUsers(u)
        setMe(current)
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
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: '0.82rem', opacity: u.has_password ? 0.9 : 0.5 }}>
                          <KeyRound size={13} />
                          {u.has_password ? 'Password set' : 'No password set'}
                        </span>
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
