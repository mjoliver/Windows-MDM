import { useEffect, useState, useCallback } from 'react'
import { Package, Plus, Trash2, Monitor, Users, Download, Search, RefreshCw } from 'lucide-react'
import { Layout } from '../components/Layout'
import { ActionButton } from '../components/ActionButton'
import { Badge } from '../components/Badge'
import { EmptyState } from '../components/EmptyState'
import { Modal } from '../components/Modal'
import { useToast } from '../hooks/useToast'
import {
  api,
  type MSIApp,
  type MSIAppDetail,
  type Device,
  type Group,
} from '../api'
import { timeAgo } from '../format'

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '—'
  const mb = bytes / (1024 * 1024)
  if (mb >= 1) return `${mb.toFixed(1)} MB`
  return `${(bytes / 1024).toFixed(0)} KB`
}

function appBadgeStatus(code: number | null, label: string): string {
  if (code === 70) return 'compliant'
  if (code === 30 || code === 60 || label.toLowerCase().includes('failed')) return 'non_compliant'
  return 'pending'
}

function CreateAppModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (app: MSIApp) => void
}) {
  const [contentUrl, setContentUrl]   = useState('')
  const [name, setName]               = useState('')
  const [publisher, setPublisher]     = useState('')
  const [version, setVersion]         = useState('')
  const [productCode, setProductCode] = useState('')
  const [upgradeCode, setUpgradeCode] = useState('')
  const [sha256, setSha256]           = useState('')
  const [fileSize, setFileSize]       = useState(0)
  const [cmdLine, setCmdLine]         = useState('/quiet /norestart')
  const [inspecting, setInspecting]   = useState(false)
  const [saving, setSaving]           = useState(false)
  const [error, setError]             = useState('')
  const toast = useToast()

  const inspectUrl = async () => {
    const trimmed = contentUrl.trim()
    if (!trimmed) {
      setError('Enter an HTTPS .msi download URL first')
      return
    }
    setError('')
    setInspecting(true)
    try {
      const meta = await api.apps.inspect(trimmed)
      setName(meta.name || '')
      setPublisher(meta.publisher || '')
      setVersion(meta.version || '1.0.0')
      setProductCode(meta.product_code || '')
      setUpgradeCode(meta.upgrade_code || '')
      setSha256(meta.sha256 || '')
      setFileSize(meta.file_size_bytes || 0)
      toast.success(`Extracted metadata for ${meta.name || meta.product_code} (${formatBytes(meta.file_size_bytes)})`)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to inspect MSI URL')
    } finally {
      setInspecting(false)
    }
  }

  const submit = async () => {
    if (!contentUrl.trim()) {
      setError('HTTPS MSI URL is required')
      return
    }
    setError('')
    setSaving(true)
    try {
      const created = await api.apps.create({
        content_url: contentUrl.trim(),
        name: name.trim(),
        publisher: publisher.trim(),
        version: version.trim(),
        product_code: productCode.trim(),
        upgrade_code: upgradeCode.trim(),
        sha256: sha256.trim(),
        file_size_bytes: fileSize,
        command_line: cmdLine.trim() || '/quiet /norestart',
      })
      toast.success(`Registered "${created.name}" (${created.version})`)
      onCreated(created)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to register application')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      open={true}
      onClose={onClose}
      title="Register Win32 MSI Application"
      maxWidth={640}
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose} disabled={saving || inspecting}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={saving || inspecting}>
            {saving ? 'Registering…' : 'Register Application'}
          </button>
        </>
      }
    >
      <div className="form-group">
        <label className="form-label">HTTPS Installer URL (.msi) *</label>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            className="input"
            style={{ flex: 1 }}
            value={contentUrl}
            onChange={e => setContentUrl(e.target.value)}
            placeholder="https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
            autoFocus
          />
          <button
            type="button"
            className="btn btn-secondary"
            onClick={inspectUrl}
            disabled={inspecting || saving}
            style={{ whiteSpace: 'nowrap' }}
          >
            <Search size={15} className={inspecting ? 'spin' : ''} />
            {inspecting ? 'Inspecting…' : 'Auto-Inspect'}
          </button>
        </div>
        <div style={{ fontSize: '0.75rem', opacity: 0.6, marginTop: 6 }}>
          Auto-Inspect streams the MSI over HTTPS to extract its ProductCode GUID, version, publisher, and SHA-256 FileHash automatically.
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div className="form-group">
          <label className="form-label">Application Name</label>
          <input className="input" value={name} onChange={e => setName(e.target.value)} placeholder="Auto-filled or custom" />
        </div>
        <div className="form-group">
          <label className="form-label">Publisher</label>
          <input className="input" value={publisher} onChange={e => setPublisher(e.target.value)} placeholder="e.g. Google LLC" />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '160px 1fr', gap: 12 }}>
        <div className="form-group">
          <label className="form-label">Version</label>
          <input className="input" value={version} onChange={e => setVersion(e.target.value)} placeholder="1.0.0" />
        </div>
        <div className="form-group">
          <label className="form-label">MSI ProductCode GUID</label>
          <input
            className="input mono"
            value={productCode}
            onChange={e => setProductCode(e.target.value)}
            placeholder="{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"
          />
        </div>
      </div>

      <div className="form-group">
        <label className="form-label">SHA-256 FileHash</label>
        <input
          className="input mono"
          value={sha256}
          onChange={e => setSha256(e.target.value)}
          placeholder="64-character SHA-256 hex digest (auto-computed if blank)"
        />
      </div>

      <div className="form-group">
        <label className="form-label">Silent Command-Line Arguments</label>
        <input
          className="input mono"
          value={cmdLine}
          onChange={e => setCmdLine(e.target.value)}
          placeholder="/quiet /norestart"
        />
      </div>

      {error && <p style={{ color: 'var(--md-sys-color-error)', fontSize: '0.82rem', marginTop: 8 }}>{error}</p>}
    </Modal>
  )
}

function DeployAppModal({
  app,
  devices,
  groups,
  onClose,
  onChanged,
}: {
  app: MSIApp
  devices: Device[]
  groups: Group[]
  onClose: () => void
  onChanged: () => void
}) {
  const [tab, setTab]         = useState<'status' | 'devices' | 'groups'>('status')
  const [detail, setDetail]   = useState<MSIAppDetail | null>(null)
  const [busy, setBusy]       = useState<string | null>(null)
  const toast = useToast()

  const loadDetail = useCallback(() => {
    api.apps.get(app.id).then(setDetail).catch(() => {})
  }, [app.id])

  useEffect(() => {
    loadDetail()
    const t = setInterval(loadDetail, 8000)
    return () => clearInterval(t)
  }, [loadDetail])

  const pushInstall = async (deviceId: string, label: string) => {
    setBusy(`inst-${deviceId}`)
    try {
      await api.apps.install(app.id, [deviceId])
      toast.success(`Queued "${app.name}" install on ${label}`)
      loadDetail()
      onChanged()
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to queue install')
    } finally {
      setBusy(null)
    }
  }

  const pushUninstall = async (deviceId: string, label: string) => {
    setBusy(`uninst-${deviceId}`)
    try {
      await api.apps.uninstall(app.id, [deviceId])
      toast.success(`Queued "${app.name}" uninstall on ${label}`)
      loadDetail()
      onChanged()
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to queue uninstall')
    } finally {
      setBusy(null)
    }
  }

  const toggleGroup = async (groupId: string, groupName: string, action: 'add' | 'remove') => {
    setBusy(`grp-${groupId}`)
    try {
      const res = await api.apps.assignGroups(app.id, [groupId], action)
      toast.success(
        action === 'add'
          ? `Assigned "${app.name}" to group "${groupName}" (${res.devices_targeted} device(s) queued)`
          : `Removed "${app.name}" from group "${groupName}"`
      )
      loadDetail()
      onChanged()
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to update group assignment')
    } finally {
      setBusy(null)
    }
  }

  const assignedGroups = new Set(detail?.group_ids ?? [])
  const installs = detail?.installs ?? []

  return (
    <Modal
      open={true}
      onClose={onClose}
      title={`Deploy: ${app.name} (${app.version})`}
      maxWidth={680}
      footer={
        <button className="btn btn-secondary" onClick={onClose}>Done</button>
      }
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 6 }}>
          <button className={`btn btn-sm ${tab === 'status' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setTab('status')}>
            <Package size={13} /> Deployment Status ({installs.length})
          </button>
          <button className={`btn btn-sm ${tab === 'devices' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setTab('devices')}>
            <Monitor size={13} /> Target Devices ({devices.length})
          </button>
          <button className={`btn btn-sm ${tab === 'groups' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setTab('groups')}>
            <Users size={13} /> Assign Groups ({assignedGroups.size})
          </button>
        </div>
        <button className="btn btn-sm btn-secondary" onClick={loadDetail} title="Refresh status">
          <RefreshCw size={13} />
        </button>
      </div>

      {tab === 'status' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 340, overflowY: 'auto' }}>
          {installs.length === 0 ? (
            <p style={{ opacity: 0.6, fontSize: '0.88rem', textAlign: 'center', padding: 28 }}>
              Not deployed to any devices yet — switch to <strong>Target Devices</strong> or <strong>Assign Groups</strong> to push this MSI.
            </p>
          ) : (
            installs.map(inst => (
              <div
                key={inst.device_id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: '10px 14px',
                  border: '1px solid var(--md-sys-color-outline-variant)',
                  borderRadius: 12,
                }}
              >
                <Monitor size={16} style={{ opacity: 0.6, flexShrink: 0 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{inst.device_name || inst.device_id}</div>
                  <div style={{ fontSize: '0.75rem', opacity: 0.6 }}>
                    Updated {timeAgo(inst.updated_at)}
                    {inst.last_error && inst.last_error !== '0' ? ` · Error ${inst.last_error}${inst.last_error_desc ? `: ${inst.last_error_desc}` : ''}` : ''}
                  </div>
                </div>
                <Badge status={appBadgeStatus(inst.status_code, inst.status_label)} label={inst.status_label} dot />
                <button
                  className="btn btn-sm btn-secondary"
                  disabled={busy !== null}
                  onClick={() => pushInstall(inst.device_id, inst.device_name || inst.device_id)}
                >
                  Re-push
                </button>
              </div>
            ))
          )}
        </div>
      )}

      {tab === 'devices' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 340, overflowY: 'auto' }}>
          {devices.length === 0 ? (
            <p style={{ opacity: 0.6, fontSize: '0.88rem' }}>No active enrolled devices.</p>
          ) : (
            devices.map(d => {
              const label = d.device_name || d.hardware_id
              return (
                <div
                  key={d.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    padding: '10px 14px',
                    border: '1px solid var(--md-sys-color-outline-variant)',
                    borderRadius: 12,
                  }}
                >
                  <Monitor size={16} style={{ opacity: 0.6 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{label}</div>
                    <div style={{ fontSize: '0.75rem', opacity: 0.55 }}>{d.os_version || 'Windows'}</div>
                  </div>
                  <button
                    className="btn btn-sm btn-primary"
                    disabled={busy !== null}
                    onClick={() => pushInstall(d.id, label)}
                  >
                    <Download size={13} />
                    {busy === `inst-${d.id}` ? 'Queueing…' : 'Install'}
                  </button>
                  <button
                    className="btn btn-sm btn-secondary"
                    disabled={busy !== null}
                    onClick={() => pushUninstall(d.id, label)}
                  >
                    {busy === `uninst-${d.id}` ? 'Queueing…' : 'Uninstall'}
                  </button>
                </div>
              )
            })
          )}
        </div>
      )}

      {tab === 'groups' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 340, overflowY: 'auto' }}>
          {groups.length === 0 ? (
            <p style={{ opacity: 0.6, fontSize: '0.88rem' }}>No device groups created yet.</p>
          ) : (
            groups.map(g => {
              const isAssigned = assignedGroups.has(g.id)
              return (
                <div
                  key={g.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    padding: '10px 14px',
                    border: '1px solid var(--md-sys-color-outline-variant)',
                    borderRadius: 12,
                  }}
                >
                  <Users size={16} style={{ opacity: 0.6 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{g.name}</div>
                    <div style={{ fontSize: '0.75rem', opacity: 0.55 }}>{g.device_count} member device(s)</div>
                  </div>
                  {isAssigned && <Badge status="compliant" label="Assigned" dot />}
                  {isAssigned ? (
                    <button
                      className="btn btn-sm btn-secondary"
                      disabled={busy !== null}
                      onClick={() => toggleGroup(g.id, g.name, 'remove')}
                    >
                      Remove
                    </button>
                  ) : (
                    <button
                      className="btn btn-sm btn-primary"
                      disabled={busy !== null}
                      onClick={() => toggleGroup(g.id, g.name, 'add')}
                    >
                      Assign Group
                    </button>
                  )}
                </div>
              )
            })
          )}
        </div>
      )}
    </Modal>
  )
}

export function AppsPage() {
  const [apps, setApps]               = useState<MSIApp[]>([])
  const [devices, setDevices]         = useState<Device[]>([])
  const [groups, setGroups]           = useState<Group[]>([])
  const [loading, setLoading]         = useState(true)
  const [creating, setCreating]       = useState(false)
  const [deploying, setDeploying]     = useState<MSIApp | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<MSIApp | null>(null)
  const toast = useToast()

  const load = useCallback(() => {
    Promise.all([
      api.apps.list().catch(() => [] as MSIApp[]),
      api.devices.list().catch(() => [] as Device[]),
      api.groups.list().catch(() => [] as Group[]),
    ])
      .then(([a, d, g]) => {
        setApps(a ?? [])
        setDevices(d ?? [])
        setGroups(g ?? [])
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const removeApp = async () => {
    if (!confirmDelete) return
    const target = confirmDelete
    setConfirmDelete(null)
    try {
      await api.apps.delete(target.id)
      setApps(prev => prev.filter(x => x.id !== target.id))
      toast.success(`Removed "${target.name}" from catalog`)
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to delete application')
    }
  }

  return (
    <Layout title="Applications">
      <div className="fade-in">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28 }}>
          <div style={{ opacity: 0.7, fontSize: '0.95rem' }}>
            Deploy silent Win32 <code>.msi</code> packages over HTTPS via Windows <code>EnterpriseDesktopAppManagement</code> CSP with SHA-256 hash verification.
          </div>
          <ActionButton icon={<Plus size={18} />} label="Add MSI Application" onClick={() => setCreating(true)} />
        </div>

        {loading ? (
          <div className="card" style={{ padding: 48, textAlign: 'center', opacity: 0.5 }}>Loading application catalog…</div>
        ) : apps.length === 0 ? (
          <div className="card">
            <EmptyState
              icon={<Package size={44} style={{ opacity: 0.25 }} />}
              title="No MSI Applications Registered"
              description="Register an HTTPS .msi installer (such as Google Chrome Enterprise) to push silent installs to Windows 10/11 devices and groups."
              action={<ActionButton icon={<Plus size={16} />} label="Add MSI Application" onClick={() => setCreating(true)} />}
            />
          </div>
        ) : (
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="table-wrap" style={{ border: 'none', borderRadius: 0 }}>
              <table className="table-static">
                <thead>
                  <tr>
                    <th>Application</th>
                    <th>Version & Size</th>
                    <th>MSI ProductCode</th>
                    <th>Installed</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {apps.map(app => (
                    <tr key={app.id}>
                      <td>
                        <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>{app.name}</div>
                        <div style={{ fontSize: '0.78rem', opacity: 0.6 }}>
                          {app.publisher || 'Unknown Publisher'} · <span className="mono">{app.command_line}</span>
                        </div>
                      </td>
                      <td>
                        <div style={{ fontWeight: 600 }}>{app.version}</div>
                        <div style={{ fontSize: '0.75rem', opacity: 0.55 }}>{formatBytes(app.file_size_bytes)}</div>
                      </td>
                      <td>
                        <div className="mono" style={{ fontSize: '0.78rem' }}>{app.product_code}</div>
                        <div className="mono" style={{ fontSize: '0.68rem', opacity: 0.45 }}>
                          SHA-256: {app.sha256.slice(0, 12)}…
                        </div>
                      </td>
                      <td>
                        <Badge
                          status={app.installed_count > 0 && app.installed_count >= app.target_device_count ? 'compliant' : 'pending'}
                          label={`${app.installed_count} / ${app.target_device_count} devices`}
                          dot
                        />
                        {app.group_count > 0 && (
                          <div style={{ fontSize: '0.72rem', opacity: 0.55, marginTop: 4 }}>
                            {app.group_count} group(s) assigned
                          </div>
                        )}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: 8 }}>
                          <button className="btn btn-sm btn-primary" onClick={() => setDeploying(app)}>
                            <Download size={14} /> Deploy
                          </button>
                          <button
                            className="btn btn-sm btn-secondary"
                            aria-label={`Delete ${app.name}`}
                            style={{ color: 'var(--md-sys-color-error)' }}
                            onClick={() => setConfirmDelete(app)}
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {creating && (
        <CreateAppModal
          onClose={() => setCreating(false)}
          onCreated={created => {
            setCreating(false)
            setApps(prev => [created, ...prev])
            setDeploying(created)
          }}
        />
      )}

      {deploying && (
        <DeployAppModal
          app={deploying}
          devices={devices}
          groups={groups}
          onClose={() => setDeploying(null)}
          onChanged={load}
        />
      )}

      {confirmDelete && (
        <Modal
          open={true}
          onClose={() => setConfirmDelete(null)}
          title="Remove Application"
          footer={
            <>
              <button className="btn btn-secondary" onClick={() => setConfirmDelete(null)}>Cancel</button>
              <button className="btn btn-primary" style={{ background: 'var(--md-sys-color-error)' }} onClick={removeApp}>
                Remove from Catalog
              </button>
            </>
          }
        >
          <p style={{ margin: 0, lineHeight: 1.5 }}>
            Remove <strong>{confirmDelete.name}</strong> ({confirmDelete.version}) from the Latchz catalog? Existing installations on devices will remain unless uninstalled first.
          </p>
        </Modal>
      )}
    </Layout>
  )
}
