import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Plus, Trash2, Edit2, X } from 'lucide-react'
import { Layout } from '../components/Layout'
import { api, type Profile } from '../api'

function CreateModal({ onClose, onCreated }: { onClose: () => void; onCreated: (p: Profile) => void }) {
  const [name, setName]   = useState('')
  const [desc, setDesc]   = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState('')

  const submit = async () => {
    if (!name.trim()) { setError('Name is required'); return }
    setSaving(true)
    try {
      const p = await api.profiles.create({ name: name.trim(), description: desc.trim() })
      onCreated(p)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to create profile')
    } finally { setSaving(false) }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <span className="modal-title">New Profile</span>
          <button className="btn btn-icon btn-secondary" onClick={onClose}><X size={14} /></button>
        </div>
        <div className="modal-body">
          <div className="form-group">
            <label className="form-label">Profile name *</label>
            <input className="input" value={name} onChange={e => setName(e.target.value)}
              placeholder="e.g. Security Baseline" autoFocus />
          </div>
          <div className="form-group">
            <label className="form-label">Description</label>
            <input className="input" value={desc} onChange={e => setDesc(e.target.value)}
              placeholder="Brief description of what this profile enforces" />
          </div>
          {error && <p style={{ color: 'var(--danger)', fontSize: '0.82rem', marginTop: 8 }}>{error}</p>}
          <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: 8, lineHeight: 1.6 }}>
            After creating the profile you can add policy settings from the Policy Catalog.
          </p>
        </div>
        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={saving}>
            {saving ? 'Creating…' : 'Create Profile'}
          </button>
        </div>
      </div>
    </div>
  )
}

export function ProfilesPage() {
  const [profiles, setProfiles]   = useState<Profile[]>([])
  const [loading, setLoading]     = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [deleteId, setDeleteId]   = useState<string | null>(null)
  const navigate = useNavigate()

  const load = () => api.profiles.list().then(setProfiles).finally(() => setLoading(false))
  useEffect(() => { load() }, [])

  const handleDelete = async (id: string) => {
    await api.profiles.delete(id)
    setProfiles(ps => ps.filter(p => p.id !== id))
    setDeleteId(null)
  }

  return (
    <Layout title="Profiles">
      <div className="page-header">
        <div className="page-header-left">
          <h1>Configuration Profiles</h1>
          <p>Policy bundles assigned to device groups</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
          <Plus size={14} /> New Profile
        </button>
      </div>

      {profiles.length === 0 && !loading ? (
        <div className="table-wrap">
          <div className="empty-state">
            <Shield size={40} />
            <h3>No profiles yet</h3>
            <p>Create a profile to start enforcing policies on your devices</p>
            <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
              <Plus size={14} /> New Profile
            </button>
          </div>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Profile</th>
                <th>Policies</th>
                <th>Created by</th>
                <th>Last updated</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {profiles.map(p => (
                <tr key={p.id}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                      <div className="detail-icon">
                        <Shield size={18} />
                      </div>
                      <div>
                        <div style={{ fontWeight: 700, color: 'var(--md-sys-color-on-surface)' }}>{p.name}</div>
                        {p.description && (
                          <div style={{ fontSize: '0.8rem', opacity: 0.5 }}>{p.description}</div>
                        )}
                      </div>
                    </div>
                  </td>
                  <td>
                    <span style={{ fontWeight: 600, color: 'var(--md-sys-color-primary)' }}>
                      {p.settings ? `${p.settings.length} Policies` : '—'}
                    </span>
                  </td>
                  <td style={{ opacity: 0.6 }}>{p.created_by || 'Admin'}</td>
                  <td style={{ opacity: 0.6 }}>
                    {new Date(p.updated_at).toLocaleDateString()}
                  </td>
                  <td onClick={e => e.stopPropagation()}>
                    <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                      <button className="btn btn-secondary btn-sm btn-icon" title="Edit"
                        onClick={() => navigate(`/profiles/${p.id}`)}>
                        <Edit2 size={13} />
                      </button>
                      <button className="btn btn-secondary btn-sm btn-icon" 
                        style={{ color: 'var(--md-sys-color-error)' }}
                        title="Delete" onClick={() => setDeleteId(p.id)}>
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <CreateModal
          onClose={() => setShowCreate(false)}
          onCreated={p => { setProfiles(ps => [p, ...ps]); setShowCreate(false) }}
        />
      )}

      {deleteId && (
        <div className="modal-overlay" onClick={() => setDeleteId(null)}>
          <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 400 }}>
            <div className="modal-header">
              <span className="modal-title">Delete Profile</span>
            </div>
            <div className="modal-body">
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.7 }}>
                Are you sure? This profile will be removed from all groups and devices.
              </p>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setDeleteId(null)}>Cancel</button>
              <button className="btn btn-danger" onClick={() => handleDelete(deleteId)}>
                <Trash2 size={13} /> Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </Layout>
  )
}
