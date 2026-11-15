import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, Plus, Pause, Play, Trash2, Edit2, Clock, ShieldAlert } from 'lucide-react'
import { Layout } from '../components/Layout'
import { Badge } from '../components/Badge'
import { EmptyState } from '../components/EmptyState'
import { Modal } from '../components/Modal'
import { api, type UpdateRing, type Group } from '../api'
import { useToast } from '../hooks/useToast'

interface RingFormState {
  id?: string
  name: string
  description: string
  allow_auto_update: number
  quality_deferral_days: number
  feature_deferral_days: number
  active_hours_start: number
  active_hours_end: number
  quality_deadline_days: number
  feature_deadline_days: number
  grace_period_days: number
  target_all_devices: boolean
  priority: number
  group_ids: string[]
}

const DEFAULT_FORM: RingFormState = {
  name: '',
  description: '',
  allow_auto_update: 2,
  quality_deferral_days: 7,
  feature_deferral_days: 30,
  active_hours_start: 8,
  active_hours_end: 17,
  quality_deadline_days: 7,
  feature_deadline_days: 14,
  grace_period_days: 2,
  target_all_devices: false,
  priority: 100,
  group_ids: [],
}

export function UpdatesPage() {
  const [rings, setRings]     = useState<UpdateRing[]>([])
  const [groups, setGroups]   = useState<Group[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [saving, setSaving]   = useState(false)
  const [busyId, setBusyId]   = useState<string | null>(null)
  const [form, setForm]       = useState<RingFormState>(DEFAULT_FORM)
  const toast = useToast()

  const refresh = useCallback(() => {
    setLoading(true)
    Promise.all([
      api.updates.listRings(),
      api.groups.list().catch(() => []),
    ])
      .then(([r, g]) => {
        setRings(r ?? [])
        setGroups(g ?? [])
      })
      .catch(e => toast.error(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false))
  }, [toast])

  useEffect(() => { refresh() }, [refresh])

  const openCreate = () => {
    setForm(DEFAULT_FORM)
    setModalOpen(true)
  }

  const openEdit = (r: UpdateRing) => {
    setForm({
      id: r.id,
      name: r.name,
      description: r.description,
      allow_auto_update: r.allow_auto_update,
      quality_deferral_days: r.quality_deferral_days,
      feature_deferral_days: r.feature_deferral_days,
      active_hours_start: r.active_hours_start,
      active_hours_end: r.active_hours_end,
      quality_deadline_days: r.quality_deadline_days,
      feature_deadline_days: r.feature_deadline_days,
      grace_period_days: r.grace_period_days,
      target_all_devices: r.target_all_devices,
      priority: r.priority,
      group_ids: r.group_ids ?? [],
    })
    setModalOpen(true)
  }

  const applyPreset = (preset: 'pilot' | 'broad' | 'critical') => {
    if (preset === 'pilot') {
      setForm(f => ({
        ...f,
        name: f.name || 'Ring 0 — IT Pilot',
        description: 'Immediate validation ring for IT & early adopters',
        quality_deferral_days: 0,
        feature_deferral_days: 7,
        quality_deadline_days: 3,
        feature_deadline_days: 7,
        grace_period_days: 1,
        priority: 10,
      }))
    } else if (preset === 'broad') {
      setForm(f => ({
        ...f,
        name: f.name || 'Ring 1 — Broad Production',
        description: 'Standard enterprise deployment ring with 7-day quality soak',
        quality_deferral_days: 7,
        feature_deferral_days: 30,
        quality_deadline_days: 7,
        feature_deadline_days: 14,
        grace_period_days: 2,
        priority: 50,
      }))
    } else {
      setForm(f => ({
        ...f,
        name: f.name || 'Ring 2 — Mission Critical',
        description: 'Extended deferral ring for executive & high-availability endpoints',
        quality_deferral_days: 14,
        feature_deferral_days: 90,
        quality_deadline_days: 14,
        feature_deadline_days: 21,
        grace_period_days: 3,
        priority: 100,
      }))
    }
  }

  const saveRing = async () => {
    setSaving(true)
    try {
      const payload = {
        name: form.name,
        description: form.description,
        allow_auto_update: form.allow_auto_update,
        quality_deferral_days: form.quality_deferral_days,
        feature_deferral_days: form.feature_deferral_days,
        active_hours_start: form.active_hours_start,
        active_hours_end: form.active_hours_end,
        quality_deadline_days: form.quality_deadline_days,
        feature_deadline_days: form.feature_deadline_days,
        grace_period_days: form.grace_period_days,
        target_all_devices: form.target_all_devices,
        priority: form.priority,
        group_ids: form.group_ids,
      }
      if (form.id) {
        const res = await api.updates.updateRing(form.id, payload)
        toast.success(`Updated "${res.name}" — queued ${res.commands_queued ?? 0} Update CSP command(s).`)
      } else {
        const res = await api.updates.createRing(payload)
        toast.success(`Created "${res.name}" — queued ${res.commands_queued ?? 0} Update CSP command(s).`)
      }
      setModalOpen(false)
      refresh()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  const togglePause = async (ring: UpdateRing, target: 'quality' | 'feature', paused: boolean) => {
    setBusyId(ring.id)
    try {
      const updated = await api.updates.pauseRing(ring.id, target, paused)
      toast.success(
        paused
          ? `Paused ${target} updates on "${ring.name}" for up to 35 days (${updated.commands_queued ?? 0} command(s) queued).`
          : `Resumed ${target} updates on "${ring.name}" (${updated.commands_queued ?? 0} command(s) queued).`
      )
      refresh()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setBusyId(null)
    }
  }

  const removeRing = async (ring: UpdateRing) => {
    setBusyId(ring.id)
    try {
      const res = await api.updates.deleteRing(ring.id)
      toast.success(`Deleted "${ring.name}" and queued ${res.commands_queued} retraction command(s).`)
      refresh()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setBusyId(null)
    }
  }

  const totalGoverned = rings.reduce((acc, r) => acc + r.device_count, 0)
  const pausedCount   = rings.filter(r => r.quality_paused || r.feature_paused).length

  return (
    <Layout title="Update Rings">
      <div className="page-header">
        <div className="page-header-left">
          <h1>Windows Update Rings</h1>
          <p>Agentless Windows Update for Business deferrals, active hours, deadlines, and emergency 35-day pause controls</p>
        </div>
        <button className="btn btn-primary" onClick={openCreate}>
          <Plus size={16} />
          New Update Ring
        </button>
      </div>

      <div className="stat-grid" style={{ marginBottom: 24 }}>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(129,140,248,0.12)' }}>
            <RefreshCw size={18} color="var(--accent)" />
          </div>
          <div className="stat-label">Configured Rings</div>
          <div className="stat-value">{rings.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'var(--success-dim)' }}>
            <Clock size={18} color="var(--success)" />
          </div>
          <div className="stat-label">Governed Devices</div>
          <div className="stat-value">{totalGoverned}</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: pausedCount > 0 ? 'var(--warning-dim, rgba(245,158,11,0.14))' : 'var(--neutral-dim)' }}>
            <ShieldAlert size={18} color={pausedCount > 0 ? 'var(--warning, #f59e0b)' : 'var(--neutral)'} />
          </div>
          <div className="stat-label">Paused Rings</div>
          <div className="stat-value">{pausedCount}</div>
        </div>
      </div>

      {!loading && rings.length === 0 ? (
        <div className="card">
          <EmptyState
            icon={<RefreshCw size={36} />}
            title="No Windows Update Rings configured"
            description="Create Pilot, Broad, and Production rollout rings to control Windows 11 quality & feature update deferrals, active hours, and compliance deadlines."
            action={
              <button className="btn btn-primary" onClick={openCreate}>
                <Plus size={16} />
                Create First Ring
              </button>
            }
          />
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          {rings.map(ring => (
            <div key={ring.id} className="card" style={{ padding: 24 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap', marginBottom: 16 }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                    <span style={{ fontSize: '1.15rem', fontWeight: 700 }}>{ring.name}</span>
                    <Badge status="unknown" label={`Priority ${ring.priority}`} />
                    <Badge
                      status={ring.target_all_devices ? 'compliant' : 'unknown'}
                      label={ring.target_all_devices ? 'All Devices' : `${ring.group_ids.length} Group(s)`}
                    />
                    <Badge status="compliant" label={`${ring.device_count} Device(s)`} />
                    {ring.quality_paused && <Badge status="non_compliant" label={`Quality Paused (${ring.quality_pause_start})`} />}
                    {ring.feature_paused && <Badge status="non_compliant" label={`Feature Paused (${ring.feature_pause_start})`} />}
                  </div>
                  {ring.description && (
                    <div style={{ fontSize: '0.85rem', opacity: 0.68 }}>{ring.description}</div>
                  )}
                </div>

                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button
                    className="btn btn-sm btn-secondary"
                    disabled={busyId === ring.id}
                    onClick={() => togglePause(ring, 'quality', !ring.quality_paused)}
                  >
                    {ring.quality_paused ? <Play size={13} /> : <Pause size={13} />}
                    {ring.quality_paused ? 'Resume Quality' : 'Pause Quality (35d)'}
                  </button>
                  <button
                    className="btn btn-sm btn-secondary"
                    disabled={busyId === ring.id}
                    onClick={() => togglePause(ring, 'feature', !ring.feature_paused)}
                  >
                    {ring.feature_paused ? <Play size={13} /> : <Pause size={13} />}
                    {ring.feature_paused ? 'Resume Feature' : 'Pause Feature (35d)'}
                  </button>
                  <button className="btn btn-sm btn-secondary" onClick={() => openEdit(ring)}>
                    <Edit2 size={13} />
                    Edit
                  </button>
                  <button
                    className="btn btn-sm btn-secondary"
                    style={{ color: 'var(--md-sys-color-error)' }}
                    disabled={busyId === ring.id}
                    onClick={() => removeRing(ring)}
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 12 }}>
                <div style={{ padding: '12px 14px', borderRadius: 10, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
                  <div style={{ fontSize: '0.72rem', opacity: 0.6 }}>Quality Deferral</div>
                  <div style={{ fontSize: '1.05rem', fontWeight: 700 }}>{ring.quality_deferral_days} day(s)</div>
                </div>
                <div style={{ padding: '12px 14px', borderRadius: 10, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
                  <div style={{ fontSize: '0.72rem', opacity: 0.6 }}>Feature Deferral</div>
                  <div style={{ fontSize: '1.05rem', fontWeight: 700 }}>{ring.feature_deferral_days} day(s)</div>
                </div>
                <div style={{ padding: '12px 14px', borderRadius: 10, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
                  <div style={{ fontSize: '0.72rem', opacity: 0.6 }}>Active Hours</div>
                  <div style={{ fontSize: '1.05rem', fontWeight: 700 }}>
                    {String(ring.active_hours_start).padStart(2, '0')}:00 – {String(ring.active_hours_end).padStart(2, '0')}:00
                  </div>
                </div>
                <div style={{ padding: '12px 14px', borderRadius: 10, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
                  <div style={{ fontSize: '0.72rem', opacity: 0.6 }}>Install Deadlines</div>
                  <div style={{ fontSize: '1.05rem', fontWeight: 700 }}>
                    {ring.quality_deadline_days}d Q / {ring.feature_deadline_days}d F (+{ring.grace_period_days}d grace)
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={form.id ? 'Edit Windows Update Ring' : 'Create Windows Update Ring'}
        maxWidth={600}
        footer={
          <>
            <button className="btn btn-secondary" onClick={() => setModalOpen(false)}>Cancel</button>
            <button className="btn btn-primary" disabled={saving || !form.name.trim()} onClick={saveRing}>
              {saving ? 'Saving…' : form.id ? 'Save Changes' : 'Create Ring'}
            </button>
          </>
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {!form.id && (
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <span style={{ fontSize: '0.78rem', opacity: 0.65, alignSelf: 'center', marginRight: 4 }}>Presets:</span>
              <button type="button" className="btn btn-sm btn-secondary" onClick={() => applyPreset('pilot')}>Pilot (0d / 7d)</button>
              <button type="button" className="btn btn-sm btn-secondary" onClick={() => applyPreset('broad')}>Broad (7d / 30d)</button>
              <button type="button" className="btn btn-sm btn-secondary" onClick={() => applyPreset('critical')}>Mission Critical (14d / 90d)</button>
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 120px', gap: 12 }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Ring Name</label>
              <input className="form-input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Ring 1 — Broad Production" />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Priority</label>
              <input type="number" min={1} max={9999} className="form-input" value={form.priority} onChange={e => setForm({ ...form, priority: Number(e.target.value) })} />
            </div>
          </div>

          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Description</label>
            <input className="form-input" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Optional rollout notes" />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Quality Deferral (0–30 days)</label>
              <input type="number" min={0} max={30} className="form-input" value={form.quality_deferral_days} onChange={e => setForm({ ...form, quality_deferral_days: Number(e.target.value) })} />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Feature Deferral (0–365 days)</label>
              <input type="number" min={0} max={365} className="form-input" value={form.feature_deferral_days} onChange={e => setForm({ ...form, feature_deferral_days: Number(e.target.value) })} />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Active Hours Start (0–23)</label>
              <input type="number" min={0} max={23} className="form-input" value={form.active_hours_start} onChange={e => setForm({ ...form, active_hours_start: Number(e.target.value) })} />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Active Hours End (0–23)</label>
              <input type="number" min={0} max={23} className="form-input" value={form.active_hours_end} onChange={e => setForm({ ...form, active_hours_end: Number(e.target.value) })} />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Quality Deadline (days)</label>
              <input type="number" min={0} max={30} className="form-input" value={form.quality_deadline_days} onChange={e => setForm({ ...form, quality_deadline_days: Number(e.target.value) })} />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Feature Deadline (days)</label>
              <input type="number" min={0} max={30} className="form-input" value={form.feature_deadline_days} onChange={e => setForm({ ...form, feature_deadline_days: Number(e.target.value) })} />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Grace Period (0–7d)</label>
              <input type="number" min={0} max={7} className="form-input" value={form.grace_period_days} onChange={e => setForm({ ...form, grace_period_days: Number(e.target.value) })} />
            </div>
          </div>

          <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', marginTop: 4 }}>
            <input
              type="checkbox"
              checked={form.target_all_devices}
              onChange={e => setForm({ ...form, target_all_devices: e.target.checked })}
            />
            <span style={{ fontSize: '0.86rem', fontWeight: 600 }}>Apply as fleet-wide ring to all active enrolled devices</span>
          </label>

          {!form.target_all_devices && groups.length > 0 && (
            <div>
              <div className="form-label" style={{ marginBottom: 8 }}>Target Device Groups</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {groups.map(g => {
                  const sel = form.group_ids.includes(g.id)
                  return (
                    <button
                      key={g.id}
                      type="button"
                      className={`btn btn-sm ${sel ? 'btn-primary' : 'btn-secondary'}`}
                      onClick={() => {
                        const next = sel ? form.group_ids.filter(x => x !== g.id) : [...form.group_ids, g.id]
                        setForm({ ...form, group_ids: next })
                      }}
                    >
                      {g.name}
                    </button>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      </Modal>
    </Layout>
  )
}
