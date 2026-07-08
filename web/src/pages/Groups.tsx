import { useEffect, useState } from 'react'
import { Users, Plus, Trash2, Monitor, Shield } from 'lucide-react'
import { Layout } from '../components/Layout'
import { ActionButton } from '../components/ActionButton'
import { api, type Group, type Device, type Profile } from '../api'
import { EmptyState } from '../components/EmptyState'
import { Modal } from '../components/Modal'
import { useToast } from '../context/ToastContext'

function CreateGroupModal({ onClose, onCreated }: { onClose: () => void; onCreated: (g: Group) => void }) {
  const [name, setName]     = useState('')
  const [desc, setDesc]     = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState('')

  const submit = async () => {
    if (!name.trim()) { setError('Name is required'); return }
    setSaving(true)
    try {
      const g = await api.groups.create({ name: name.trim(), description: desc.trim() })
      onCreated(g)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed')
    } finally { setSaving(false) }
  }

  return (
    <Modal
      open={true}
      onClose={onClose}
      title="New Group"
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={saving}>
            {saving ? 'Creating…' : 'Create Group'}
          </button>
        </>
      }
    >
      <div className="form-group">
        <label className="form-label">Group name *</label>
        <input className="input" value={name} onChange={e => setName(e.target.value)}
          placeholder="e.g. Engineering, Sales, Servers" autoFocus />
      </div>
      <div className="form-group">
        <label className="form-label">Description</label>
        <input className="input" value={desc} onChange={e => setDesc(e.target.value)}
          placeholder="What devices belong here?" />
      </div>
      {error && <p style={{ color: 'var(--danger)', fontSize: '0.82rem', marginTop: 8 }}>{error}</p>}
    </Modal>
  )
}

function ManageModal({
  group, devices, profiles, onClose
}: {
  group: Group
  devices: Device[]
  profiles: Profile[]
  onClose: () => void
}) {
  const [tab, setTab] = useState<'devices' | 'profiles'>('devices')
  const [saving, setSaving] = useState(false)
  const toast = useToast()

  const assign = async (ids: string[], action: 'add' | 'remove', type: 'devices' | 'profiles') => {
    setSaving(true)
    try {
      if (type === 'devices')  await api.groups.assignDevices(group.id, ids, action)
      if (type === 'profiles') await api.groups.assignProfiles(group.id, ids, action)
    } catch (e) { toast.error(`Failed to ${action} ${type}: ${e instanceof Error ? e.message : String(e)}`) }
    finally { setSaving(false) }
  }

  return (
    <Modal
      open={true}
      onClose={onClose}
      title={`Manage: ${group.name}`}
      maxWidth={580}
      footer={
        <button className="btn btn-secondary" onClick={onClose}>Done</button>
      }
    >
      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 16 }}>
        {(['devices', 'profiles'] as const).map(t => (
          <button key={t} className={`btn btn-sm ${tab === t ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setTab(t)}>
            {t === 'devices' ? <Monitor size={12} /> : <Shield size={12} />}
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'devices' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 320, overflowY: 'auto' }}>
          {devices.length === 0
            ? <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No devices enrolled yet</p>
            : devices.map(d => (
              <div key={d.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }}>
                <Monitor size={14} color="var(--text-muted)" style={{ flexShrink: 0 }} />
                <span style={{ flex: 1, fontSize: '0.875rem' }}>{d.device_name || d.hardware_id}</span>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button className="btn btn-sm btn-primary" disabled={saving}
                    onClick={() => assign([d.id], 'add', 'devices')}>Add</button>
                  <button className="btn btn-sm btn-secondary" disabled={saving}
                    onClick={() => assign([d.id], 'remove', 'devices')}>Remove</button>
                </div>
              </div>
            ))
          }
        </div>
      )}

      {tab === 'profiles' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 320, overflowY: 'auto' }}>
          {profiles.length === 0
            ? <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No profiles yet — create one first</p>
            : profiles.map(p => (
              <div key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }}>
                <Shield size={14} color="var(--accent)" style={{ flexShrink: 0 }} />
                <span style={{ flex: 1, fontSize: '0.875rem' }}>{p.name}</span>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button className="btn btn-sm btn-primary" disabled={saving}
                    onClick={() => assign([p.id], 'add', 'profiles')}>Assign</button>
                  <button className="btn btn-sm btn-secondary" disabled={saving}
                    onClick={() => assign([p.id], 'remove', 'profiles')}>Remove</button>
                </div>
              </div>
            ))
          }
        </div>
      )}
    </Modal>
  )
}

export function GroupsPage() {
  const [groups, setGroups]     = useState<Group[]>([])
  const [devices, setDevices]   = useState<Device[]>([])
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [loading, setLoading]   = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [managing, setManaging]     = useState<Group | null>(null)
  const [deleteId, setDeleteId]     = useState<string | null>(null)

  const load = () => {
    setLoading(true)
    Promise.all([
      api.groups.list(),
      api.devices.list(),
      api.profiles.list(),
    ]).then(([g, d, p]) => {
      setGroups(g)
      setDevices(d)
      setProfiles(p)
    }).finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const handleDelete = async (id: string) => {
    await api.groups.delete(id)
    setGroups(gs => gs.filter(g => g.id !== id))
    setDeleteId(null)
  }

  return (
    <Layout title="Groups">
      <div className="page-header">
        <div className="page-header-left">
          <h1>Device Groups</h1>
          <p>Organise devices and apply profiles at scale</p>
        </div>
        <ActionButton icon={<Plus size={14} />} label="New Group" onClick={() => setShowCreate(true)} variant="primary" />
      </div>

       {groups.length === 0 && !loading ? (
          <div className="table-wrap">
            <EmptyState
              icon={<Users size={40} />}
              title="No groups yet"
              description="Create a group, add devices, then assign a profile to enforce policy"
            />
          </div>
       ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Group</th>
                <th>Devices</th>
                <th>Profiles</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {groups.map(g => (
                <tr key={g.id}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                      <div className="detail-icon">
                        <Users size={18} />
                      </div>
                      <div>
                        <div style={{ fontWeight: 700, color: 'var(--md-sys-color-on-surface)' }}>{g.name}</div>
                        {g.description && <div style={{ fontSize: '0.8rem', opacity: 0.5 }}>{g.description}</div>}
                      </div>
                    </div>
                  </td>
                  <td>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 8, opacity: 0.8 }}>
                      <Monitor size={14} /> {g.device_count}
                    </span>
                  </td>
                  <td>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 8, opacity: 0.8 }}>
                      <Shield size={14} /> {g.profile_count}
                    </span>
                  </td>
                  <td style={{ opacity: 0.6 }}>{new Date(g.created_at).toLocaleDateString()}</td>
                  <td onClick={e => e.stopPropagation()}>
                    <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                      <button className="btn btn-secondary btn-sm" onClick={() => setManaging(g)}>Manage</button>
                      <button className="btn btn-danger btn-sm btn-icon" onClick={() => setDeleteId(g.id)}>
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
        <CreateGroupModal
          onClose={() => setShowCreate(false)}
          onCreated={g => { setGroups(gs => [g, ...gs]); setShowCreate(false) }}
        />
      )}

      {managing && (
        <ManageModal
          group={managing}
          devices={devices}
          profiles={profiles}
          onClose={() => { setManaging(null); load() }}
        />
      )}

       <Modal
         open={!!deleteId}
         onClose={() => setDeleteId(null)}
         title="Delete Group"
         maxWidth={400}
         footer={
           <>
             <button className="btn btn-secondary" onClick={() => setDeleteId(null)}>Cancel</button>
             <button className="btn btn-danger" onClick={() => handleDelete(deleteId!)}>
               <Trash2 size={13} /> Delete Group
             </button>
           </>
         }
       >
         <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.7 }}>
           Devices in this group will be ungrouped. Existing profiles will no longer be applied.
         </p>
       </Modal>
    </Layout>
  )
}
