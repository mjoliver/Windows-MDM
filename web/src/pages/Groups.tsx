import { useEffect, useState } from 'react'
import { Users, Plus, Trash2, Monitor, Shield, Sparkles, RefreshCw } from 'lucide-react'
import { Layout } from '../components/Layout'
import { ActionButton } from '../components/ActionButton'
import { api, type Group, type Device, type Profile, type DynamicGroupRule } from '../api'
import { EmptyState } from '../components/EmptyState'
import { Modal } from '../components/Modal'
import { Badge } from '../components/Badge'
import { useToast } from '../hooks/useToast'

const RULE_FIELDS = [
  { value: 'hostname', label: 'Hostname' },
  { value: 'os_version', label: 'OS Version' },
  { value: 'os_build', label: 'OS Build' },
  { value: 'manufacturer', label: 'Manufacturer' },
  { value: 'model', label: 'Model' },
  { value: 'serial_number', label: 'Serial Number' },
  { value: 'compliance_status', label: 'Compliance Status' },
  { value: 'secure_boot', label: 'Secure Boot (true/false)' },
  { value: 'bitlocker', label: 'BitLocker Encrypted (true/false)' },
]

const RULE_OPERATORS = [
  { value: 'contains', label: 'Contains' },
  { value: 'starts_with', label: 'Starts with' },
  { value: 'ends_with', label: 'Ends with' },
  { value: 'equals', label: 'Equals' },
  { value: 'not_equals', label: 'Does not equal' },
]

function RuleBuilder({
  matchMode,
  setMatchMode,
  rules,
  setRules,
}: {
  matchMode: 'all' | 'any'
  setMatchMode: (m: 'all' | 'any') => void
  rules: DynamicGroupRule[]
  setRules: (r: DynamicGroupRule[]) => void
}) {
  const [previewCount, setPreviewCount] = useState<number | null>(null)
  const [previewNames, setPreviewNames] = useState<string[]>([])
  const [previewBusy, setPreviewBusy] = useState(false)
  const toast = useToast()

  const updateRule = (idx: number, patch: Partial<DynamicGroupRule>) => {
    setRules(rules.map((r, i) => (i === idx ? { ...r, ...patch } : r)))
    setPreviewCount(null)
  }

  const addRule = () => {
    setRules([...rules, { field: 'os_version', operator: 'contains', value: '' }])
    setPreviewCount(null)
  }

  const removeRule = (idx: number) => {
    if (rules.length <= 1) return
    setRules(rules.filter((_, i) => i !== idx))
    setPreviewCount(null)
  }

  const runPreview = async () => {
    setPreviewBusy(true)
    try {
      const res = await api.groups.previewRules(matchMode, rules)
      setPreviewCount(res.match_count)
      setPreviewNames(res.devices.slice(0, 5).map(d => d.device_name || d.id))
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setPreviewBusy(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: 14, borderRadius: 12, background: 'rgba(208, 188, 255, 0.05)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
        <span style={{ fontSize: '0.8rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6 }}>
          <Sparkles size={14} /> Dynamic Membership Rules
        </span>
        <select
          className="input"
          style={{ width: 'auto', padding: '4px 10px', fontSize: '0.8rem' }}
          value={matchMode}
          onChange={e => { setMatchMode(e.target.value as 'all' | 'any'); setPreviewCount(null) }}
        >
          <option value="all">Match ALL rules (AND)</option>
          <option value="any">Match ANY rule (OR)</option>
        </select>
      </div>

      {rules.map((r, idx) => (
        <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1.1fr 1fr 1.2fr auto', gap: 8, alignItems: 'center' }}>
          <select className="input" value={r.field} onChange={e => updateRule(idx, { field: e.target.value })}>
            {RULE_FIELDS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
          </select>
          <select className="input" value={r.operator} onChange={e => updateRule(idx, { operator: e.target.value })}>
            {RULE_OPERATORS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <input
            className="input"
            value={r.value}
            onChange={e => updateRule(idx, { value: e.target.value })}
            placeholder="e.g. 10.0.26100 or DESKTOP-"
          />
          <button
            type="button"
            className="btn btn-secondary btn-sm btn-icon"
            disabled={rules.length <= 1}
            onClick={() => removeRule(idx)}
            title="Remove rule"
          >
            <Trash2 size={12} />
          </button>
        </div>
      ))}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
        <button type="button" className="btn btn-secondary btn-sm" onClick={addRule}>
          <Plus size={12} /> Add Rule
        </button>
        <button type="button" className="btn btn-secondary btn-sm" onClick={runPreview} disabled={previewBusy}>
          {previewBusy ? 'Evaluating…' : 'Preview Matches'}
        </button>
      </div>

      {previewCount !== null && (
        <div style={{ fontSize: '0.78rem', opacity: 0.85 }}>
          Matches <strong>{previewCount}</strong> active device(s)
          {previewNames.length > 0 ? `: ${previewNames.join(', ')}${previewCount > previewNames.length ? '…' : ''}` : '.'}
        </div>
      )}
    </div>
  )
}

function CreateGroupModal({ onClose, onCreated }: { onClose: () => void; onCreated: (g: Group) => void }) {
  const [name, setName]         = useState('')
  const [desc, setDesc]         = useState('')
  const [isDynamic, setDynamic] = useState(false)
  const [matchMode, setMatchMode] = useState<'all' | 'any'>('all')
  const [rules, setRules]       = useState<DynamicGroupRule[]>([
    { field: 'os_version', operator: 'starts_with', value: '10.0.2' },
  ])
  const [saving, setSaving]     = useState(false)
  const [error, setError]       = useState('')
  const toast = useToast()

  const submit = async () => {
    if (!name.trim()) { setError('Name is required'); return }
    setSaving(true)
    setError('')
    try {
      const g = await api.groups.create({
        name: name.trim(),
        description: desc.trim(),
        is_dynamic: isDynamic,
        match_mode: isDynamic ? matchMode : undefined,
        dynamic_rules: isDynamic ? rules : undefined,
      })
      toast.success(isDynamic
        ? `Dynamic Smart Group "${g.name}" created (${g.device_count} device(s) matched)`
        : `Group "${g.name}" created`)
      onCreated(g)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed')
    } finally { setSaving(false) }
  }

  return (
    <Modal
      open={true}
      onClose={onClose}
      title="New Device Group"
      maxWidth={620}
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={saving}>
            {saving ? 'Creating…' : isDynamic ? 'Create Smart Group' : 'Create Group'}
          </button>
        </>
      }
    >
      <div className="form-group">
        <label className="form-label">Group Type</label>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            type="button"
            className={`btn btn-sm ${!isDynamic ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setDynamic(false)}
          >
            <Users size={13} /> Static Group
          </button>
          <button
            type="button"
            className={`btn btn-sm ${isDynamic ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setDynamic(true)}
          >
            <Sparkles size={13} /> Dynamic Smart Group
          </button>
        </div>
      </div>

      <div className="form-group">
        <label className="form-label">Group name *</label>
        <input className="input" value={name} onChange={e => setName(e.target.value)}
          placeholder={isDynamic ? 'e.g. All Windows 11 Workstations' : 'e.g. Engineering, Sales, Servers'} autoFocus />
      </div>
      <div className="form-group">
        <label className="form-label">Description</label>
        <input className="input" value={desc} onChange={e => setDesc(e.target.value)}
          placeholder={isDynamic ? 'Auto-assigns policies whenever telemetry matches' : 'What devices belong here?'} />
      </div>

      {isDynamic && (
        <RuleBuilder
          matchMode={matchMode}
          setMatchMode={setMatchMode}
          rules={rules}
          setRules={setRules}
        />
      )}

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
  const [tab, setTab] = useState<'devices' | 'profiles' | 'rules'>(group.is_dynamic ? 'rules' : 'devices')
  const [busy, setBusy] = useState<Record<string, boolean>>({})
  const [matchMode, setMatchMode] = useState<'all' | 'any'>(group.match_mode || 'all')
  const [rules, setRules] = useState<DynamicGroupRule[]>(
    group.dynamic_rules && group.dynamic_rules.length > 0
      ? group.dynamic_rules
      : [{ field: 'os_version', operator: 'starts_with', value: '10.0.2' }]
  )
  const [savingRules, setSavingRules] = useState(false)
  const toast = useToast()

  const isBusy = (key: string) => !!busy[key]

  const setOp = (key: string, val: boolean) => {
    setBusy(prev => ({ ...prev, [key]: val }))
  }

  const assign = async (ids: string[], action: 'add' | 'remove', type: 'devices' | 'profiles', labelKey: string, label: string) => {
    const opKey = `${action}-${labelKey}`
    setOp(opKey, true)
    try {
      if (type === 'devices')  await api.groups.assignDevices(group.id, ids, action)
      if (type === 'profiles') await api.groups.assignProfiles(group.id, ids, action)
      const noun = type === 'profiles' ? 'Profile' : 'Device'
      if (action === 'add') {
        toast.success(`${noun} "${label}" ${type === 'profiles' ? 'assigned' : 'added'} to group "${group.name}"`)
      } else {
        toast.success(`${noun} "${label}" removed from group "${group.name}"`)
      }
    } catch (e) { toast.error(`Failed to ${action} ${type}: ${e instanceof Error ? e.message : String(e)}`) }
    finally { setOp(opKey, false) }
  }

  const saveDynamicRules = async () => {
    setSavingRules(true)
    try {
      await api.groups.update(group.id, {
        name: group.name,
        description: group.description,
        is_dynamic: true,
        match_mode: matchMode,
        dynamic_rules: rules,
      })
      toast.success(`Updated rules & reconciled Smart Group "${group.name}"`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setSavingRules(false)
    }
  }

  return (
    <Modal
      open={true}
      onClose={onClose}
      title={`Manage: ${group.name}`}
      maxWidth={620}
      footer={
        <button className="btn btn-secondary" onClick={onClose}>Done</button>
      }
    >
      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 16 }}>
        {group.is_dynamic ? (
          <button className={`btn btn-sm ${tab === 'rules' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setTab('rules')}>
            <Sparkles size={12} /> Smart Rules
          </button>
        ) : (
          <button className={`btn btn-sm ${tab === 'devices' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setTab('devices')}>
            <Monitor size={12} /> Devices
          </button>
        )}
        <button className={`btn btn-sm ${tab === 'profiles' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setTab('profiles')}>
          <Shield size={12} /> Profiles
        </button>
      </div>

      {tab === 'rules' && group.is_dynamic && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <RuleBuilder
            matchMode={matchMode}
            setMatchMode={setMatchMode}
            rules={rules}
            setRules={setRules}
          />
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button className="btn btn-primary btn-sm" onClick={saveDynamicRules} disabled={savingRules}>
              {savingRules ? 'Saving & Reconciling…' : 'Save Rules & Reconcile'}
            </button>
          </div>
        </div>
      )}

      {tab === 'devices' && !group.is_dynamic && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 320, overflowY: 'auto' }}>
          {devices.length === 0
            ? <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No devices enrolled yet</p>
            : devices.map(d => (
              <div key={d.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }}>
                <Monitor size={14} color="var(--text-muted)" style={{ flexShrink: 0 }} />
                <span style={{ flex: 1, fontSize: '0.875rem' }}>{d.device_name || d.hardware_id}</span>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button className="btn btn-sm btn-primary" disabled={isBusy(`device-add-${d.id}`)}
                    onClick={() => assign([d.id], 'add', 'devices', `device-add-${d.id}`, d.device_name || d.hardware_id)}>
                    {isBusy(`device-add-${d.id}`) ? 'Adding…' : 'Add'}
                  </button>
                  <button className="btn btn-sm btn-secondary" disabled={isBusy(`device-remove-${d.id}`)}
                    onClick={() => assign([d.id], 'remove', 'devices', `device-remove-${d.id}`, d.device_name || d.hardware_id)}>
                    {isBusy(`device-remove-${d.id}`) ? 'Removing…' : 'Remove'}
                  </button>
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
                  <button className="btn btn-sm btn-primary" disabled={isBusy(`profile-add-${p.id}`)}
                    onClick={() => assign([p.id], 'add', 'profiles', `profile-add-${p.id}`, p.name)}>
                    {isBusy(`profile-add-${p.id}`) ? 'Assigning…' : 'Assign'}
                  </button>
                  <button className="btn btn-sm btn-secondary" disabled={isBusy(`profile-remove-${p.id}`)}
                    onClick={() => assign([p.id], 'remove', 'profiles', `profile-remove-${p.id}`, p.name)}>
                    {isBusy(`profile-remove-${p.id}`) ? 'Removing…' : 'Remove'}
                  </button>
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
  const [reconcilingId, setReconcilingId] = useState<string | null>(null)
  const toast = useToast()

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

  const [deleting, setDeleting] = useState(false)

  const handleDelete = async (id: string) => {
    const target = groups.find(g => g.id === id)
    setDeleting(true)
    try {
      await api.groups.delete(id)
      setGroups(gs => gs.filter(g => g.id !== id))
      setDeleteId(null)
      if (target) toast.success(`Group "${target.name}" deleted`)
    } catch (e) {
      toast.error(`Failed to delete group: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setDeleting(false)
    }
  }

  const handleReconcile = async (g: Group) => {
    setReconcilingId(g.id)
    try {
      const res = await api.groups.reconcile(g.id)
      toast.success(`Smart Group "${g.name}" reconciled (${res.device_count} members, +${res.added} / -${res.removed})`)
      load()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setReconcilingId(null)
    }
  }

  return (
    <Layout title="Groups">
      <div className="page-header">
        <div className="page-header-left">
          <h1>Device Groups</h1>
          <p>Organise devices manually or automatically via Dynamic Smart Group rules</p>
        </div>
        <ActionButton icon={<Plus size={14} />} label="New Group" onClick={() => setShowCreate(true)} variant="primary" />
      </div>

       {groups.length === 0 && !loading ? (
          <div className="table-wrap">
            <EmptyState
              icon={<Users size={40} />}
              title="No groups yet"
              description="Create a Static or Dynamic Smart Group to automatically enforce profiles, apps, and security baselines"
            />
          </div>
       ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Group</th>
                <th>Type</th>
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
                        {g.is_dynamic ? <Sparkles size={18} /> : <Users size={18} />}
                      </div>
                      <div>
                        <div style={{ fontWeight: 700, color: 'var(--md-sys-color-on-surface)' }}>{g.name}</div>
                        {g.description && <div style={{ fontSize: '0.8rem', opacity: 0.5 }}>{g.description}</div>}
                        {g.is_dynamic && g.dynamic_rules?.length > 0 && (
                          <div className="mono" style={{ fontSize: '0.72rem', opacity: 0.65, marginTop: 2 }}>
                            {g.dynamic_rules.map(r => `${r.field} ${r.operator} "${r.value}"`).join(g.match_mode === 'any' ? ' OR ' : ' AND ')}
                          </div>
                        )}
                      </div>
                    </div>
                  </td>
                  <td>
                    {g.is_dynamic
                      ? <Badge status="compliant" label={`Smart (${g.match_mode?.toUpperCase() || 'ALL'})`} />
                      : <Badge status="unknown" label="Static" />}
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
                      {g.is_dynamic && (
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleReconcile(g)}
                          disabled={reconcilingId === g.id}
                          title="Re-evaluate Dynamic Smart Group rules"
                        >
                          <RefreshCw size={12} className={reconcilingId === g.id ? 'spin' : ''} /> Reconcile
                        </button>
                      )}
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
              <button className="btn btn-danger" onClick={() => handleDelete(deleteId!)} disabled={deleting}>
                <Trash2 size={13} /> {deleting ? 'Deleting…' : 'Delete Group'}
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
