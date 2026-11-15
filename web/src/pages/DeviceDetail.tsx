import { useEffect, useState, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Monitor, Lock, Trash2, RefreshCw, RotateCcw, HelpCircle, ShieldCheck, ShieldAlert, GlobeLock, Zap, Package, Layers, Search, KeyRound, UserCheck, Eye, Plus, Copy } from 'lucide-react'
import { Layout } from '../components/Layout'
import { Breadcrumb } from '../components/Breadcrumb'
import { Badge } from '../components/Badge'
import { api, type Device, type DeviceCompliance, type DeviceCommand, type DevicePosture, type DeviceAppInstall, type DeviceSoftwareInventory, type DeviceBitLocker, type DeviceUpdateTelemetry, type DeviceLAPSStatus, type RevealedLAPSCredentials, type DeviceSecurityState, type DeviceConnectivityItem } from '../api'
import { formatResultCode, timeAgo } from '../format'
import { EmptyState } from '../components/EmptyState'
import { Modal } from '../components/Modal'
import { InfoGrid } from '../components/InfoGrid'
import { SkeletonLine, SkeletonBlock } from '../components/SkeletonLoader'
import { useToast } from '../hooks/useToast'

function formatMBAsGB(mb: number | null | undefined): string {
  if (mb == null || mb <= 0) return '—'
  return `${(mb / 1024).toFixed(1)} GB`
}

function postureBadgeStatus(ok: boolean | null): string {
  if (ok === true) return 'compliant'
  if (ok === false) return 'non_compliant'
  return 'unknown'
}

export function DeviceDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [device, setDevice]           = useState<Device | null>(null)
  const [, setPendingCmds]             = useState(0)
  const [compliance, setCompliance]   = useState<DeviceCompliance | null>(null)
  const [posture, setPosture]         = useState<DevicePosture | null>(null)
  const [bitlocker, setBitlocker]     = useState<DeviceBitLocker | null>(null)
  const [laps, setLaps]               = useState<DeviceLAPSStatus | null>(null)
  const [secState, setSecState]       = useState<DeviceSecurityState | null>(null)
  const [connItems, setConnItems]     = useState<DeviceConnectivityItem[]>([])
  const [updateTel, setUpdateTel]     = useState<DeviceUpdateTelemetry | null>(null)
  const [apps, setApps]               = useState<DeviceAppInstall[]>([])
  const [inventory, setInventory]     = useState<DeviceSoftwareInventory | null>(null)
  const [invSearch, setInvSearch]     = useState('')
  const [commands, setCommands]       = useState<DeviceCommand[]>([])
  const [loading, setLoading]         = useState(true)
  const [error, setError]             = useState<string | null>(null)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [confirmReboot, setConfirmReboot] = useState(false)
  const [confirmWipe, setConfirmWipe]     = useState(false)
  const [escrowOpen, setEscrowOpen]       = useState(false)
  const [escrowVol, setEscrowVol]         = useState('C:')
  const [escrowProt, setEscrowProt]       = useState('')
  const [escrowPwd, setEscrowPwd]         = useState('')
  const [escrowBusy, setEscrowBusy]       = useState(false)
  const [revealedKey, setRevealedKey]     = useState<{ volume_letter: string; protector_id: string; recovery_password: string } | null>(null)
  const [revealedLAPS, setRevealedLAPS]   = useState<RevealedLAPSCredentials | null>(null)
  const toast = useToast()

  const refresh = useCallback(() => {
    setLoading(true)
    setError(null)
    // Fetch device first — if this fails, show error. Others are best-effort.
    api.devices.get(id!)
      .then(d => {
        setDevice(d.device)
        setPendingCmds(d.pending_commands)
      })
      .catch(e => setError(String(e)))
      .finally(() => setLoading(false))

    // Compliance and commands are independent — don't block the page if they fail
    api.compliance.device(id!)
      .then(c => setCompliance(c ?? null))
      .catch(() => setCompliance(null))

    api.devices.getCommands(id!)
      .then(cmd => setCommands(cmd.commands ?? []))   // Go nil slice → JSON null → guard here
      .catch(() => setCommands([]))

    api.devices.posture(id!)
      .then(setPosture)
      .catch(() => setPosture(null))

    api.devices.apps(id!)
      .then(a => setApps(a ?? []))
      .catch(() => setApps([]))

    api.devices.inventory(id!)
      .then(setInventory)
      .catch(() => setInventory(null))

    api.bitlocker.device(id!)
      .then(setBitlocker)
      .catch(() => setBitlocker(null))

    api.laps.device(id!)
      .then(setLaps)
      .catch(() => setLaps(null))

    api.devices.security(id!)
      .then(setSecState)
      .catch(() => setSecState(null))

    api.devices.connectivity(id!)
      .then(c => setConnItems(c ?? []))
      .catch(() => setConnItems([]))

    api.updates.device(id!)
      .then(setUpdateTel)
      .catch(() => setUpdateTel(null))
  }, [id])

  useEffect(() => {
    if (!id) return
    refresh()
  }, [id, refresh])

  // Background poll so check-ins / command results appear without a manual
  // reload. Silent: does not toggle the full-page loading skeleton.
  useEffect(() => {
    if (!id) return
    const t = setInterval(() => {
      api.devices.get(id).then(d => { setDevice(d.device); setPendingCmds(d.pending_commands) }).catch(() => {})
      api.compliance.device(id).then(c => setCompliance(c ?? null)).catch(() => {})
      api.devices.getCommands(id).then(cmd => setCommands(cmd.commands ?? [])).catch(() => {})
      api.devices.posture(id).then(setPosture).catch(() => {})
      api.devices.apps(id).then(a => setApps(a ?? [])).catch(() => {})
      api.devices.inventory(id).then(setInventory).catch(() => {})
      api.bitlocker.device(id).then(setBitlocker).catch(() => {})
      api.laps.device(id).then(setLaps).catch(() => {})
      api.devices.security(id).then(setSecState).catch(() => {})
      api.devices.connectivity(id).then(c => setConnItems(c ?? [])).catch(() => {})
      api.updates.device(id).then(setUpdateTel).catch(() => {})
    }, 10000)
    return () => clearInterval(t)
  }, [id])

  const action = async (name: string, fn: () => Promise<unknown>) => {
    setActionLoading(name)
    try { 
      const res = await fn()
      if (name === 'sync') {
        const queued = (res as { commands_queued?: number } | undefined)?.commands_queued ?? 0
        if (queued === 0) {
          toast.error('Nothing to sync — no profiles are assigned to this device\'s groups.')
        } else {
          toast.success(`Queued ${queued} command(s). They're delivered on the device's next check-in (Settings → Access work or school → Info → Sync).`)
        }
      } else if (name === 'reboot') {
        toast.success('Reboot queued — once synced, Windows gives signed-in users a 5-minute grace period before restarting.')
      } else if (name === 'posture') {
        const queued = (res as { commands_queued?: number } | undefined)?.commands_queued ?? 0
        toast.success(`Queued ${queued} inventory & security posture query command(s) for next check-in.`)
      } else if (name === 'inventory-sync') {
        const queued = (res as { commands_queued?: number } | undefined)?.commands_queued ?? 0
        toast.success(`Queued ${queued} agentless Win32 & MSI software inventory query command(s) for next check-in.`)
      } else if (name === 'push') {
        const st = (res as { status?: string; wns_status?: string } | undefined)?.status
        if (st === 'sent') {
          toast.success('Instant WNS wake-up push delivered — device is initiating an OMA-DM sync.')
        } else if (st === 'no_channel') {
          toast.error('No WNS channel registered for this device yet — channel URI will be collected on next check-in.')
        } else if (st === 'expired_channel') {
          toast.error('WNS channel had expired and was cleared — device will register a fresh channel on next check-in.')
        }
      }
      setTimeout(refresh, 500)
    } catch (e) { 
      toast.error(`Failed to ${name}: ${e instanceof Error ? e.message : String(e)}`)
    }
    finally { setActionLoading(null) }
  }

  if (loading)
    return (
      <Layout title="Device">
        <div className="fade-in" style={{ opacity: 0.5, pointerEvents: 'none' }}>
          <div style={{ height: 24 }} />
          {/* Hero skeleton */}
          <div className="card" style={{ padding: 40, display: 'flex', alignItems: 'center', gap: 40, marginBottom: 32 }}>
            <SkeletonBlock width={80} height={80} borderRadius={24} />
            <div style={{ flex: 1 }}>
              <SkeletonBlock width={300} height={36} style={{ marginBottom: 12 }} />
              <SkeletonLine count={2} />
            </div>
            <div style={{ display: 'flex', gap: 12 }}>
              <SkeletonBlock width={120} height={48} />
              <SkeletonBlock width={48} height={48} borderRadius={16} />
              <SkeletonBlock width={48} height={48} borderRadius={16} />
            </div>
          </div>
          {/* Grid skeleton */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 32 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
              <div className="card" style={{ padding: 24 }}>
                <SkeletonBlock width={140} height={18} style={{ marginBottom: 20 }} />
                <SkeletonLine count={6} />
              </div>
              <div className="card" style={{ padding: 24 }}>
                <SkeletonBlock width={140} height={18} style={{ marginBottom: 20 }} />
                <SkeletonLine count={4} />
              </div>
            </div>
            <div className="card" style={{ padding: 24 }}>
              <SkeletonBlock width={140} height={18} style={{ marginBottom: 20 }} />
              <SkeletonLine count={6} />
            </div>
          </div>
        </div>
      </Layout>
    )
  if (error)   return <Layout title="Device"><div style={{ color: 'var(--md-sys-color-error)', padding: 40 }}>Error loading device: {error}</div></Layout>
  if (!device) return <Layout title="Device"><div style={{ color: 'var(--md-sys-color-error)', padding: 40 }}>Device not found in registry</div></Layout>

  return (
    <Layout title="Device Management">
      <div className="fade-in">
        <Breadcrumb items={[
          { label: 'Devices', to: '/devices' },
          { label: device.device_name || 'Unnamed Device' },
        ]} />

        {/* Hero Banner */}
        <div className="card" style={{ position: 'relative', zIndex: 2, padding: 40, marginBottom: 32, display: 'flex', alignItems: 'center', gap: 40, background: 'radial-gradient(circle at top right, rgba(208, 188, 255, 0.1), transparent)' }}>
          <div className="detail-icon-large">
            <Monitor size={36} />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 8 }}>
              <h1 style={{ fontSize: '2.4rem', fontWeight: 800, margin: 0 }}>{device.device_name || 'Unnamed Device'}</h1>
              <Badge status={device.compliance_status} />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 24, opacity: 0.6, fontSize: '1rem', fontWeight: 500 }}>
              <span>{device.manufacturer} {device.model}</span>
              <span style={{ width: 4, height: 4, borderRadius: '50%', background: 'currentColor' }} />
              <span>{device.os_version}</span>
              <span style={{ width: 4, height: 4, borderRadius: '50%', background: 'currentColor' }} />
              <span>Checked in {timeAgo(device.last_checkin)}</span>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 12 }}>
            <button className="btn btn-primary"
              onClick={() => action('sync', () => api.devices.sync(id!))}
              disabled={!!actionLoading}
              style={{ padding: '14px 28px' }}>
              <RefreshCw size={18} className={actionLoading === 'sync' ? 'spin' : ''} />
              Force Sync
            </button>
            {posture?.wns_enabled && (
              <span
                className="tooltip-wrap"
                data-tooltip="Send instant WNS wake-up push">
                <button className="btn btn-secondary"
                  aria-label="Wake device via WNS"
                  onClick={() => action('push', () => api.devices.pushWake(id!))}
                  disabled={!!actionLoading}
                  style={{ width: 52, height: 52, padding: 0, borderRadius: 16 }}>
                  <Zap size={20} className={actionLoading === 'push' ? 'spin' : ''} />
                </button>
              </span>
            )}
            <span
              className="tooltip-wrap"
              data-tooltip="Restart device on next check-in">
              <button className="btn btn-secondary"
                aria-label="Restart device"
                onClick={() => setConfirmReboot(true)}
                disabled={!!actionLoading}
                style={{ width: 52, height: 52, padding: 0, borderRadius: 16 }}>
                <RotateCcw size={20} className={actionLoading === 'reboot' ? 'spin' : ''} />
              </button>
            </span>
            <span
              className="tooltip-wrap"
              tabIndex={0}
              aria-label="Remote Lock unavailable: Microsoft's RemoteLock CSP is unsupported on Windows 10/11 Desktop and returns 406 Not Acceptable."
              data-tooltip="Remote Lock is unsupported on Windows 10/11 Desktop — Microsoft's RemoteLock CSP returns 406 Not Acceptable on PCs (same as Intune)."
              style={{ cursor: 'not-allowed' }}>
              <button className="btn btn-secondary"
                disabled
                tabIndex={-1}
                aria-hidden="true"
                style={{ width: 52, height: 52, padding: 0, borderRadius: 16, opacity: 0.38, pointerEvents: 'none' }}>
                <Lock size={20} />
              </button>
            </span>
            <span
              className="tooltip-wrap"
              data-tooltip="Factory reset device">
              <button className="btn btn-secondary"
                aria-label="Factory reset device"
                style={{ color: 'var(--md-sys-color-error)', width: 52, height: 52, padding: 0, borderRadius: 16 }}
                onClick={() => setConfirmWipe(true)}
                disabled={!!actionLoading}>
                <Trash2 size={20} />
              </button>
            </span>
          </div>
        </div>

        <div className="grid-2" style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 32 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
            {/* Compliance Table */}
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '24px 32px' }}>
                <div className="card-title">Policy Compliance</div>
              </div>
              {compliance && compliance.records.length > 0 ? (
                <div className="table-wrap" style={{ border: 'none', borderRadius: 0 }}>
                  <table className="table-static">
                    <thead>
                      <tr>
                        <th>Policy</th>
                        <th>Desired State</th>
                        <th>Actual State</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {compliance.records.map((rec, i) => (
                        <tr key={i}>
                          <td>
                            <div style={{ fontWeight: 600 }}>{rec.display_name}</div>
                            <div style={{ fontSize: '0.7rem', opacity: 0.5, fontFamily: 'monospace' }}>{rec.oma_uri}</div>
                          </td>
                          <td className="mono" style={{ opacity: 0.7 }}>{rec.desired_value || '—'}</td>
                          <td className="mono">{rec.actual_value || '—'}</td>
                          <td>
                            {rec.is_compliant === true ? (
                              <Badge status="compliant" label="OK" dot />
                            ) : rec.is_compliant === false ? (
                              <Badge status="non_compliant" label="Violation" dot />
                            ) : (
                              <Badge status="unknown" label="Pending" dot />
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <EmptyState
                  icon={<HelpCircle size={40} style={{ opacity: 0.2 }} />}
                  title=""
                  description="No policy configuration received from device yet."
                  style={{ padding: 60 }}
                />
              )}
            </div>

            {/* Managed MSI Applications */}
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '24px 32px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Package size={18} />
                  Managed Applications
                </div>
                <button className="btn btn-sm btn-secondary" onClick={() => navigate('/apps')}>
                  Manage Catalog
                </button>
              </div>
              {apps.length > 0 ? (
                <div className="table-wrap" style={{ border: 'none', borderRadius: 0 }}>
                  <table className="table-static">
                    <thead>
                      <tr>
                        <th>Application</th>
                        <th>Version</th>
                        <th>Status</th>
                        <th>Updated</th>
                      </tr>
                    </thead>
                    <tbody>
                      {apps.map(app => (
                        <tr key={app.app_id}>
                          <td>
                            <div style={{ fontWeight: 600 }}>{app.app_name}</div>
                            <div className="mono" style={{ fontSize: '0.7rem', opacity: 0.5 }}>
                              {app.installed_product_code && app.installed_product_code !== app.product_code
                                ? `${app.installed_product_code} (auto-updated MSI)`
                                : app.product_code}
                            </div>
                          </td>
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                              <span className="mono" style={{ fontWeight: 600 }}>
                                {app.installed_version || app.version}
                              </span>
                              {app.version_state === 'auto_updated' && (
                                <Badge status="compliant" label="Auto-Updated" />
                              )}
                              {app.version_state === 'update_available' && (
                                <Badge status="pending" label={`Catalog ${app.version}`} />
                              )}
                            </div>
                            {app.version_state === 'auto_updated' && (
                              <div style={{ fontSize: '0.7rem', opacity: 0.55, marginTop: 2 }}>
                                Catalog seed: {app.version}
                              </div>
                            )}
                          </td>
                          <td>
                            <Badge
                              status={
                                app.status_code === 70
                                  ? 'compliant'
                                  : app.status_code === 30 || app.status_code === 60
                                    ? 'non_compliant'
                                    : 'pending'
                              }
                              label={app.status_label}
                              dot
                            />
                            {app.last_error && app.last_error !== '0' && (
                              <div style={{ fontSize: '0.7rem', color: 'var(--md-sys-color-error)', marginTop: 4 }}>
                                {app.last_error}{app.last_error_desc ? `: ${app.last_error_desc}` : ''}
                              </div>
                            )}
                          </td>
                          <td style={{ opacity: 0.6 }}>{timeAgo(app.updated_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div style={{ padding: '0 32px 28px', opacity: 0.55, fontSize: '0.88rem' }}>
                  No MSI applications deployed to this device yet.
                </div>
              )}
            </div>

            {/* Installed Software Inventory (Agentless Win32AppInventory + EnterpriseDesktopAppManagement CSP) */}
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '24px 32px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Layers size={18} />
                    Installed Software Inventory
                  </div>
                  <Badge
                    status={(inventory?.total ?? 0) > 0 ? 'compliant' : 'unknown'}
                    label={`${inventory?.total ?? 0} discovered`}
                  />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  {inventory?.last_synced_at && (
                    <span style={{ fontSize: '0.75rem', opacity: 0.55 }}>
                      Synced {timeAgo(inventory.last_synced_at)}
                    </span>
                  )}
                  <button
                    className="btn btn-sm btn-secondary"
                    disabled={!!actionLoading}
                    onClick={() => action('inventory-sync', () => api.devices.syncInventory(id!))}
                    title="Queue OMA-DM Win32AppInventory & MSI StructData queries"
                  >
                    <RefreshCw size={13} className={actionLoading === 'inventory-sync' ? 'spin' : ''} />
                    Sync Inventory
                  </button>
                </div>
              </div>

              {(inventory?.total ?? 0) > 0 ? (
                <>
                  <div style={{ padding: '0 32px 14px' }}>
                    <div style={{ position: 'relative' }}>
                      <Search
                        size={14}
                        style={{
                          position: 'absolute',
                          left: 12,
                          top: '50%',
                          transform: 'translateY(-50%)',
                          opacity: 0.5,
                          pointerEvents: 'none',
                        }}
                      />
                      <input
                        className="input"
                        style={{ paddingLeft: 34, fontSize: '0.84rem' }}
                        value={invSearch}
                        onChange={e => setInvSearch(e.target.value)}
                        placeholder="Filter installed applications by name, publisher, version, or MSI GUID…"
                      />
                    </div>
                  </div>
                  <div className="table-wrap" style={{ border: 'none', borderRadius: 0, maxHeight: 420, overflowY: 'auto' }}>
                    <table className="table-static">
                      <thead>
                        <tr>
                          <th>Application</th>
                          <th>Publisher</th>
                          <th>Live Version</th>
                          <th>Source</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(inventory?.items ?? [])
                          .filter(it => {
                            const q = invSearch.trim().toLowerCase()
                            if (!q) return true
                            return (
                              it.name.toLowerCase().includes(q) ||
                              it.publisher.toLowerCase().includes(q) ||
                              it.version.toLowerCase().includes(q) ||
                              it.product_code.toLowerCase().includes(q) ||
                              it.source.toLowerCase().includes(q)
                            )
                          })
                          .map(it => (
                            <tr key={it.app_key}>
                              <td>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                                  <span style={{ fontWeight: 600 }}>{it.name}</span>
                                  {it.managed_app_id && (
                                    <Badge
                                      status={it.version_state === 'update_available' ? 'pending' : 'compliant'}
                                      label={
                                        it.version_state === 'auto_updated'
                                          ? 'Managed · Auto-Updated'
                                          : it.version_state === 'update_available'
                                            ? `Managed · Catalog ${it.catalog_version}`
                                            : 'Managed'
                                      }
                                    />
                                  )}
                                </div>
                                {it.product_code && (
                                  <div className="mono" style={{ fontSize: '0.68rem', opacity: 0.45 }}>
                                    {it.product_code}
                                  </div>
                                )}
                              </td>
                              <td style={{ opacity: 0.78, fontSize: '0.85rem' }}>{it.publisher || '—'}</td>
                              <td>
                                <div className="mono" style={{ fontWeight: 600 }}>{it.version || '—'}</div>
                                {it.version_state === 'auto_updated' && it.catalog_version && (
                                  <div style={{ fontSize: '0.7rem', opacity: 0.55 }}>Seed: {it.catalog_version}</div>
                                )}
                              </td>
                              <td>
                                <span
                                  className="mono"
                                  style={{
                                    fontSize: '0.7rem',
                                    padding: '2px 8px',
                                    borderRadius: 999,
                                    background: 'rgba(255,255,255,0.06)',
                                    textTransform: 'uppercase',
                                  }}
                                >
                                  {it.source}
                                </span>
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                </>
              ) : (
                <div style={{ padding: '0 32px 28px', opacity: 0.55, fontSize: '0.88rem' }}>
                  Software inventory will populate automatically on the device&apos;s next OMA-DM check-in (or click <strong>Sync Inventory</strong> above).
                </div>
              )}
            </div>

            {/* BitLocker & Recovery Key Vault */}
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '24px 32px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <KeyRound size={18} />
                    BitLocker Recovery Key Vault
                  </div>
                  {bitlocker && (
                    <Badge
                      status={bitlocker.enforced ? 'compliant' : 'unknown'}
                      label={bitlocker.enforced ? 'Policy Enforced' : 'Not Enforced'}
                    />
                  )}
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    className="btn btn-sm btn-secondary"
                    disabled={!!actionLoading}
                    onClick={() => action('bitlocker-rotate', async () => {
                      await api.bitlocker.rotateKeys(id!)
                      toast.success('Queued BitLocker recovery password rotation on device.')
                    })}
                    title="Queue RotateRecoveryPasswords via BitLocker CSP"
                  >
                    <RefreshCw size={13} className={actionLoading === 'bitlocker-rotate' ? 'spin' : ''} />
                    Rotate Keys
                  </button>
                  <button className="btn btn-sm btn-primary" onClick={() => setEscrowOpen(true)}>
                    <Plus size={14} />
                    Escrow Key
                  </button>
                </div>
              </div>

              {bitlocker && bitlocker.status_reasons.length > 0 && (
                <div style={{ margin: '0 32px 20px', padding: '12px 16px', borderRadius: 10, background: 'rgba(242,184,181,0.08)', border: '1px solid rgba(242,184,181,0.2)', fontSize: '0.82rem' }}>
                  <div style={{ fontWeight: 700, marginBottom: 4, color: 'var(--md-sys-color-error)' }}>
                    BitLocker Status Telemetry ({bitlocker.encryption_label})
                  </div>
                  <ul style={{ margin: 0, paddingLeft: 18, opacity: 0.85, lineHeight: 1.5 }}>
                    {bitlocker.status_reasons.map((r, idx) => <li key={idx}>{r}</li>)}
                  </ul>
                </div>
              )}

              {bitlocker && bitlocker.recovery_keys.length > 0 ? (
                <div className="table-wrap" style={{ border: 'none', borderRadius: 0 }}>
                  <table className="table-static">
                    <thead>
                      <tr>
                        <th>Volume</th>
                        <th>Protector ID</th>
                        <th>Masked Key</th>
                        <th>Source</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bitlocker.recovery_keys.map(k => (
                        <tr key={k.id}>
                          <td className="mono" style={{ fontWeight: 700 }}>{k.volume_letter}</td>
                          <td className="mono" style={{ fontSize: '0.75rem', opacity: 0.75 }}>{k.protector_id}</td>
                          <td className="mono">{k.key_hint}</td>
                          <td>
                            <Badge
                              status={k.source === 'device_mtls' ? 'compliant' : 'unknown'}
                              label={k.source === 'device_mtls' ? 'Device mTLS' : 'Admin Escrow'}
                            />
                          </td>
                          <td>
                            <div style={{ display: 'flex', gap: 8 }}>
                              <button
                                className="btn btn-sm btn-secondary"
                                onClick={async () => {
                                  try {
                                    const res = await api.bitlocker.revealKey(id!, k.id)
                                    setRevealedKey(res)
                                  } catch (e) {
                                    toast.error(e instanceof Error ? e.message : String(e))
                                  }
                                }}
                              >
                                <Eye size={13} />
                                Reveal
                              </button>
                              <button
                                className="btn btn-sm btn-secondary"
                                style={{ color: 'var(--md-sys-color-error)' }}
                                onClick={async () => {
                                  try {
                                    await api.bitlocker.deleteKey(id!, k.id)
                                    toast.success('Removed escrowed protector record.')
                                    refresh()
                                  } catch (e) {
                                    toast.error(e instanceof Error ? e.message : String(e))
                                  }
                                }}
                              >
                                <Trash2 size={13} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div style={{ padding: '0 32px 28px', opacity: 0.55, fontSize: '0.88rem' }}>
                  No BitLocker recovery keys escrowed in the AES-256-GCM vault for this device yet.
                </div>
              )}
            </div>

            {/* Cloud LAPS — Ephemeral Local Administrator */}
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '24px 32px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <UserCheck size={18} />
                    Local Administrator (Cloud LAPS)
                  </div>
                  {laps && (
                    <Badge
                      status={
                        laps.status === 'active'
                          ? 'compliant'
                          : laps.status === 'provisioning' || laps.status === 'rotating'
                            ? 'pending'
                            : laps.status === 'failed'
                              ? 'non_compliant'
                              : 'unknown'
                      }
                      label={
                        laps.status === 'active'
                          ? 'Active'
                          : laps.status === 'provisioning'
                            ? 'Provisioning'
                            : laps.status === 'rotating'
                              ? 'Rotating'
                              : laps.status === 'revoked'
                                ? 'Revoked'
                                : laps.status === 'failed'
                                  ? 'Failed'
                                  : laps.governed
                                    ? 'Awaiting Sync'
                                    : 'Unmanaged'
                      }
                    />
                  )}
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  {(laps?.has_active_password || laps?.has_previous_password || laps?.has_pending_password) && (
                    <button
                      className="btn btn-sm btn-secondary"
                      disabled={!!actionLoading}
                      onClick={async () => {
                        try {
                          const res = await api.laps.reveal(id!)
                          setRevealedLAPS(res)
                          refresh()
                        } catch (e) {
                          toast.error(e instanceof Error ? e.message : String(e))
                        }
                      }}
                    >
                      <Eye size={13} />
                      Reveal Credentials
                    </button>
                  )}
                  <button
                    className="btn btn-sm btn-primary"
                    disabled={!!actionLoading}
                    onClick={() => action('laps-rotate', async () => {
                      const res = await api.laps.rotate(id!)
                      toast.success(`Queued ephemeral local admin rotation (${res.pending_account}) — will apply on next check-in.`)
                    })}
                  >
                    <RefreshCw size={13} className={actionLoading === 'laps-rotate' ? 'spin' : ''} />
                    {laps?.active_account ? 'Rotate Now' : 'Provision Admin'}
                  </button>
                </div>
              </div>

              {laps && (laps.active_account || laps.pending_account || laps.previous_account) ? (
                <div style={{ padding: '0 32px 26px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16 }}>
                  <div style={{ padding: '12px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
                    <div style={{ fontSize: '0.72rem', opacity: 0.6, marginBottom: 4 }}>Active Admin Account</div>
                    <div className="mono" style={{ fontWeight: 700, fontSize: '0.92rem' }}>
                      {laps.active_account ? `.\\${laps.active_account}` : '—'}
                    </div>
                  </div>
                  {laps.pending_account && (
                    <div style={{ padding: '12px 14px', borderRadius: 12, background: 'rgba(208,188,255,0.06)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
                      <div style={{ fontSize: '0.72rem', opacity: 0.65, marginBottom: 4 }}>Pending Rotation</div>
                      <div className="mono" style={{ fontWeight: 700, fontSize: '0.92rem', color: 'var(--md-sys-color-primary)' }}>
                        .\{laps.pending_account}
                      </div>
                    </div>
                  )}
                  <div style={{ padding: '12px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
                    <div style={{ fontSize: '0.72rem', opacity: 0.6, marginBottom: 4 }}>Last Rotated</div>
                    <div style={{ fontSize: '0.86rem' }}>
                      {laps.last_rotated_at ? timeAgo(laps.last_rotated_at) : 'Awaiting device ACK'}
                    </div>
                  </div>
                  <div style={{ padding: '12px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
                    <div style={{ fontSize: '0.72rem', opacity: 0.6, marginBottom: 4 }}>Next Auto-Rotation</div>
                    <div style={{ fontSize: '0.86rem' }}>
                      {laps.expires_at ? new Date(laps.expires_at).toLocaleString() : '—'}
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ padding: '0 32px 28px', opacity: 0.55, fontSize: '0.88rem' }}>
                  No ephemeral local administrator account provisioned yet. Enable Cloud LAPS on the Compliance page or click <strong>Provision Admin</strong> above.
                </div>
              )}
            </div>

            {/* Microsoft Defender Antivirus & Firewall CSP Controls */}
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '24px 32px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <ShieldAlert size={18} />
                    Defender Antivirus & Firewall
                  </div>
                  <Badge
                    status={secState?.baseline_enforced ? 'compliant' : 'unknown'}
                    label={secState?.baseline_enforced ? 'Baseline Enforced' : 'Unmanaged Baseline'}
                  />
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button
                    className="btn btn-sm btn-secondary"
                    disabled={!!actionLoading}
                    onClick={() => action('def-sig', async () => {
                      await api.devices.defenderUpdateSignatures(id!)
                      toast.success('Queued Microsoft Defender security intelligence update (UpdateSignature CSP).')
                    })}
                  >
                    <RefreshCw size={13} className={actionLoading === 'def-sig' ? 'spin' : ''} />
                    Update Signatures
                  </button>
                  <button
                    className="btn btn-sm btn-secondary"
                    disabled={!!actionLoading}
                    onClick={() => action('def-quick', async () => {
                      await api.devices.defenderScan(id!, 'quick')
                      toast.success('Queued Microsoft Defender Quick Scan via Defender CSP.')
                    })}
                  >
                    <ShieldCheck size={13} />
                    Quick Scan
                  </button>
                  <button
                    className="btn btn-sm btn-primary"
                    disabled={!!actionLoading}
                    onClick={() => action('def-full', async () => {
                      await api.devices.defenderScan(id!, 'full')
                      toast.success('Queued Microsoft Defender Full Scan via Defender CSP.')
                    })}
                  >
                    Full Scan
                  </button>
                </div>
              </div>
              <div style={{ padding: '0 32px 26px', display: 'flex', flexWrap: 'wrap', gap: 14, alignItems: 'center', fontSize: '0.84rem' }}>
                <span style={{ opacity: 0.7 }}>
                  Last Remote Action:{' '}
                  <strong>
                    {secState?.last_defender_action
                      ? `${secState.last_defender_action.replace(/_/g, ' ')} (${secState.last_defender_action_at ? timeAgo(secState.last_defender_action_at) : 'queued'})`
                      : 'None'}
                  </strong>
                </span>
                {(secState?.deployed_rule_keys?.length ?? 0) > 0 && (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                    <span style={{ opacity: 0.7 }}>Custom Firewall Rules:</span>
                    {secState!.deployed_rule_keys.map(rk => (
                      <code key={rk} className="mono" style={{ padding: '2px 8px', borderRadius: 6, background: 'rgba(255,255,255,0.06)', fontSize: '0.75rem' }}>
                        {rk}
                      </code>
                    ))}
                  </span>
                )}
              </div>
            </div>

            {/* Connectivity & PKI Profiles */}
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '24px 32px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <GlobeLock size={18} />
                    Connectivity &amp; PKI Profiles
                  </div>
                  <Badge status={connItems.length > 0 ? 'compliant' : 'unknown'} label={`${connItems.length} deployed`} />
                </div>
                <button className="btn btn-sm btn-secondary" onClick={() => navigate('/connectivity')}>
                  Manage Profiles
                </button>
              </div>
              {connItems.length > 0 ? (
                <div style={{ padding: '0 32px 26px', display: 'flex', flexWrap: 'wrap', gap: 10 }}>
                  {connItems.map(it => (
                    <div
                      key={it.profile_id}
                      style={{ padding: '10px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)' }}
                    >
                      <div style={{ fontWeight: 700, fontSize: '0.86rem' }}>{it.profile_name}</div>
                      <div className="mono" style={{ fontSize: '0.7rem', opacity: 0.6 }}>{it.profile_type} • {it.delete_oma_uri}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ padding: '0 32px 28px', opacity: 0.55, fontSize: '0.88rem' }}>
                  No Root CA certificates, Wi-Fi, or VPNv2 profiles deployed to this device yet.
                </div>
              )}
            </div>

            {/* History Table */}
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '24px 32px' }}>
                <div className="card-title">Action History</div>
              </div>
              <div className="table-wrap" style={{ border: 'none', borderRadius: 0 }}>
                <table className="table-static">
                  <thead>
                    <tr>
                      <th>Command</th>
                      <th>Status</th>
                      <th>Initiated</th>
                      <th>Response</th>
                    </tr>
                  </thead>
                  <tbody>
                    {commands.length === 0 ? (
                      <tr><td colSpan={4} style={{ textAlign: 'center', padding: 40, opacity: 0.5 }}>No recorded interactions for this device.</td></tr>
                    ) : (
                      commands.map(cmd => (
                        <tr key={cmd.id}>
                          <td>
                            <span style={{ fontWeight: 700, textTransform: 'uppercase', fontSize: '0.75rem', color: 'var(--md-sys-color-primary)' }}>{cmd.type}</span>
                            <div style={{ fontSize: '0.7rem', opacity: 0.5, fontFamily: 'monospace' }}>{cmd.oma_uri}</div>
                          </td>
                          <td>
                            <Badge status={cmd.status === 'sent' ? 'pending' : cmd.status === 'success' ? 'compliant' : cmd.status} label={cmd.status} />
                          </td>
                          <td style={{ opacity: 0.6 }}>{timeAgo(cmd.created_at)}</td>
                          <td>
                            {cmd.result_code ? (
                              <span
                                title={cmd.result_info || undefined}
                                style={{ 
                                  padding: '4px 8px', borderRadius: 6, fontSize: '0.75rem', fontFamily: 'monospace',
                                  background: cmd.status === 'failed' ? 'rgba(242,184,181,0.1)' : 'rgba(180,225,151,0.1)',
                                  color: cmd.status === 'failed' ? 'var(--md-sys-color-error)' : 'var(--md-sys-color-success)'
                                }}>
                                {formatResultCode(cmd.result_code)}
                              </span>
                            ) : '—'}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Sidebar Info */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                <div className="stat-label" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <ShieldCheck size={14} />
                  Security Posture
                </div>
                <button
                  className="btn btn-sm btn-secondary"
                  onClick={() => action('posture', () => api.devices.refreshPosture(id!))}
                  disabled={!!actionLoading}
                  title="Queue OMA-DM hardware & security posture queries"
                >
                  <RefreshCw size={12} className={actionLoading === 'posture' ? 'spin' : ''} />
                  Refresh
                </button>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {[
                  {
                    label: 'Secure Boot',
                    text: posture?.secure_boot_label ?? 'Unknown',
                    ok: posture?.secure_boot_state == null ? null : posture.secure_boot_state === 1,
                  },
                  {
                    label: 'BitLocker Drive',
                    text: posture?.encryption_label ?? 'Unknown',
                    ok: posture?.encryption_status == null ? null : posture.encryption_status === 0,
                  },
                  {
                    label: 'Defender Antivirus',
                    text: posture?.antivirus_label ?? 'Unknown',
                    ok: posture?.antivirus_status == null ? null : posture.antivirus_status === 0,
                  },
                  {
                    label: 'Windows Firewall',
                    text: posture?.firewall_label ?? 'Unknown',
                    ok: posture?.firewall_status == null ? null : posture.firewall_status === 0,
                  },
                ].map(item => (
                  <div
                    key={item.label}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 0',
                      borderBottom: '1px solid var(--md-sys-color-outline-variant)',
                    }}
                  >
                    <span style={{ fontSize: '0.84rem', opacity: 0.8 }}>{item.label}</span>
                    <Badge status={postureBadgeStatus(item.ok)} label={item.text} />
                  </div>
                ))}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--md-sys-color-outline-variant)' }}>
                  <span style={{ fontSize: '0.84rem', opacity: 0.8 }}>TPM Specification</span>
                  <span className="mono" style={{ fontSize: '0.82rem', fontWeight: 600 }}>
                    {posture?.tpm_version || '—'}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--md-sys-color-outline-variant)' }}>
                  <span style={{ fontSize: '0.84rem', opacity: 0.8 }}>Update Ring</span>
                  <Badge
                    status={
                      updateTel?.ring_name
                        ? updateTel.quality_paused || updateTel.feature_paused
                          ? 'non_compliant'
                          : 'compliant'
                        : 'unknown'
                    }
                    label={
                      updateTel?.ring_name
                        ? updateTel.quality_paused || updateTel.feature_paused
                          ? `${updateTel.ring_name} (Paused)`
                          : updateTel.ring_name
                        : 'Unmanaged'
                    }
                  />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 4 }}>
                  <span style={{ fontSize: '0.84rem', opacity: 0.8 }}>WNS Instant Wake</span>
                  <Badge
                    status={
                      posture?.wns_enabled
                        ? posture.wns_channel_active
                          ? 'compliant'
                          : 'pending'
                        : 'unknown'
                    }
                    label={
                      posture?.wns_enabled
                        ? posture.wns_channel_active
                          ? 'Connected'
                          : 'Awaiting Channel'
                        : 'Scheduled Poll'
                    }
                  />
                </div>
              </div>
            </div>

            <div className="card" style={{ padding: 24 }}>
              <div className="stat-label" style={{ marginBottom: 16 }}>Inventory Detail</div>
              <InfoGrid
                fields={[
                  { label: 'Manufacturer', value: device.manufacturer },
                  { label: 'Model', value: device.model },
                  { label: 'OS Platform', value: posture?.os_platform || device.os_version },
                  { label: 'OS Build', value: device.os_build },
                  { label: 'Physical RAM', value: formatMBAsGB(posture?.total_ram_mb) },
                  {
                    label: 'Disk Storage',
                    value:
                      posture?.total_storage_mb != null && posture?.free_storage_mb != null
                        ? `${formatMBAsGB(posture.free_storage_mb)} free of ${formatMBAsGB(posture.total_storage_mb)}`
                        : formatMBAsGB(posture?.total_storage_mb),
                  },
                  { label: 'BIOS / Firmware', value: posture?.bios_version || '—' },
                  { label: 'Serial Number', value: device.serial_number },
                  { label: 'Hardware ID', value: device.hardware_id, mono: true },
                ]}
                columns={1}
              />
            </div>

            <div className="card" style={{ padding: 24, background: 'rgba(242, 184, 181, 0.03)', borderColor: 'rgba(242, 184, 181, 0.1)' }}>
              <div className="stat-label" style={{ color: 'var(--md-sys-color-error)' }}>Threat Mitigation</div>
              <p style={{ fontSize: '0.8rem', opacity: 0.7, marginTop: 12, marginBottom: 20, lineHeight: 1.6 }}>
                Initiating a factory reset will permanently erase all data, profiles, and management tokens from this device.
              </p>
              <button className="btn btn-secondary" 
                style={{ width: '100%', color: 'var(--md-sys-color-error)', borderColor: 'rgba(242, 184, 181, 0.2)' }} 
                onClick={() => setConfirmWipe(true)}>
                Wipe Device
              </button>
            </div>
          </div>
        </div>

        <Modal
          open={confirmReboot}
          onClose={() => setConfirmReboot(false)}
          title="Confirm Reboot"
          maxWidth={440}
          footer={
            <>
              <button className="btn btn-secondary" onClick={() => setConfirmReboot(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={async () => {
                setConfirmReboot(false)
                await action('reboot', () => api.devices.reboot(id!))
              }}>
                Queue Reboot
              </button>
            </>
          }
        >
          <p style={{ opacity: 0.8, lineHeight: 1.6 }}>
            You are about to queue a <strong>Remote Reboot</strong> command (<code className="mono">RebootNow</code>). On its next check-in, Windows will notify any signed-in user and restart after a <strong>5-minute grace period</strong>.
          </p>
        </Modal>

        <Modal
          open={confirmWipe}
          onClose={() => setConfirmWipe(false)}
          title="Confirm Action"
          maxWidth={440}
          footer={
            <>
              <button className="btn btn-secondary" onClick={() => setConfirmWipe(false)}>Cancel</button>
              <button className="btn btn-danger" onClick={async () => {
                setConfirmWipe(false)
                await action('wipe', () => api.devices.wipe(id!))
                navigate('/devices')
              }}>
                Confirm Wipe
              </button>
            </>
          }
        >
          <p style={{ opacity: 0.8, lineHeight: 1.6 }}>
            You are about to issue a <strong>Remote Wipe</strong> command. This operation is irreversible.
          </p>
        </Modal>

        <Modal
          open={escrowOpen}
          onClose={() => setEscrowOpen(false)}
          title="Escrow BitLocker Recovery Key"
          maxWidth={480}
          footer={
            <>
              <button className="btn btn-secondary" onClick={() => setEscrowOpen(false)}>Cancel</button>
              <button
                className="btn btn-primary"
                disabled={escrowBusy || !escrowPwd.trim()}
                onClick={async () => {
                  setEscrowBusy(true)
                  try {
                    await api.bitlocker.escrow(id!, {
                      volume_letter: escrowVol,
                      protector_id: escrowProt || undefined,
                      recovery_password: escrowPwd,
                    })
                    toast.success('48-digit BitLocker recovery password encrypted with AES-256-GCM and stored in vault.')
                    setEscrowPwd('')
                    setEscrowProt('')
                    setEscrowOpen(false)
                    refresh()
                  } catch (e) {
                    toast.error(e instanceof Error ? e.message : String(e))
                  } finally {
                    setEscrowBusy(false)
                  }
                }}
              >
                {escrowBusy ? 'Encrypting…' : 'Encrypt & Store'}
              </button>
            </>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '110px 1fr', gap: 12 }}>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Volume</label>
                <input className="form-input mono" value={escrowVol} onChange={e => setEscrowVol(e.target.value)} placeholder="C:" />
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Protector GUID (optional)</label>
                <input className="form-input mono" value={escrowProt} onChange={e => setEscrowProt(e.target.value)} placeholder="{AUTO-GENERATED}" />
              </div>
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">48-Digit Recovery Password</label>
              <input
                className="form-input mono"
                value={escrowPwd}
                onChange={e => setEscrowPwd(e.target.value)}
                placeholder="123456-123456-123456-123456-123456-123456-123456-123456"
              />
              <div style={{ fontSize: '0.75rem', opacity: 0.6, marginTop: 6 }}>
                Sealed at rest using AES-256-GCM bound to this device ID. Every subsequent reveal is recorded in the Audit Log.
              </div>
            </div>
          </div>
        </Modal>

        <Modal
          open={!!revealedKey}
          onClose={() => setRevealedKey(null)}
          title="Audited BitLocker Recovery Key"
          maxWidth={520}
          footer={
            <>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  if (revealedKey) {
                    navigator.clipboard?.writeText(revealedKey.recovery_password)
                    toast.success('Copied 48-digit recovery password to clipboard.')
                  }
                }}
              >
                <Copy size={14} />
                Copy Key
              </button>
              <button className="btn btn-primary" onClick={() => setRevealedKey(null)}>Done</button>
            </>
          }
        >
          {revealedKey && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ fontSize: '0.82rem', opacity: 0.75 }}>
                This decryption event has been permanently recorded in the Latchz <strong>Audit Log</strong> (<code className="mono">bitlocker.reveal_key</code>).
              </div>
              <div style={{ padding: '16px 18px', borderRadius: 12, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
                <div style={{ fontSize: '0.74rem', opacity: 0.6, marginBottom: 6 }}>
                  Volume {revealedKey.volume_letter} • Protector {revealedKey.protector_id}
                </div>
                <div className="mono" style={{ fontSize: '1.05rem', fontWeight: 700, wordBreak: 'break-all', letterSpacing: '0.03em' }}>
                  {revealedKey.recovery_password}
                </div>
              </div>
            </div>
          )}
        </Modal>

        <Modal
          open={!!revealedLAPS}
          onClose={() => setRevealedLAPS(null)}
          title="Audited Local Administrator Credentials"
          maxWidth={540}
          footer={
            <button className="btn btn-primary" onClick={() => setRevealedLAPS(null)}>Done</button>
          }
        >
          {revealedLAPS && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ fontSize: '0.82rem', opacity: 0.78, lineHeight: 1.5 }}>
                This decryption has been recorded in the Latchz <strong>Audit Log</strong> (<code className="mono">laps.reveal_password</code>).
                {revealedLAPS.rotate_after_reveal_minutes > 0 && revealedLAPS.active_account
                  ? ` Credentials will automatically rotate after ${revealedLAPS.rotate_after_reveal_minutes} minutes.`
                  : ''}
              </div>

              {revealedLAPS.active_account && revealedLAPS.active_password && (
                <div style={{ padding: '16px 18px', borderRadius: 12, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--md-sys-color-outline-variant)', display: 'flex', flexDirection: 'column', gap: 10 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.74rem', opacity: 0.65, fontWeight: 600 }}>ACTIVE ADMINISTRATOR</span>
                    <button
                      className="btn btn-sm btn-secondary"
                      onClick={() => {
                        navigator.clipboard?.writeText(`.\\${revealedLAPS.active_account}`)
                        toast.success('Copied local username to clipboard.')
                      }}
                    >
                      <Copy size={12} /> Copy User
                    </button>
                  </div>
                  <div className="mono" style={{ fontSize: '0.96rem', fontWeight: 700 }}>
                    .\{revealedLAPS.active_account}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, paddingTop: 6, borderTop: '1px solid var(--md-sys-color-outline-variant)' }}>
                    <div className="mono" style={{ fontSize: '1.02rem', fontWeight: 700, wordBreak: 'break-all' }}>
                      {revealedLAPS.active_password}
                    </div>
                    <button
                      className="btn btn-sm btn-secondary"
                      onClick={() => {
                        if (revealedLAPS.active_password) {
                          navigator.clipboard?.writeText(revealedLAPS.active_password)
                          toast.success('Copied local admin password to clipboard.')
                        }
                      }}
                    >
                      <Copy size={12} /> Copy Password
                    </button>
                  </div>
                </div>
              )}

              {revealedLAPS.pending_account && revealedLAPS.pending_password && (
                <div style={{ padding: '14px 16px', borderRadius: 12, background: 'rgba(208,188,255,0.05)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
                  <div style={{ fontSize: '0.73rem', opacity: 0.7, marginBottom: 4 }}>
                    PENDING ROTATION (APPLIES ON NEXT DEVICE CHECK-IN)
                  </div>
                  <div className="mono" style={{ fontSize: '0.88rem' }}>
                    .\{revealedLAPS.pending_account} — <strong>{revealedLAPS.pending_password}</strong>
                  </div>
                </div>
              )}

              {revealedLAPS.previous_account && revealedLAPS.previous_password && (
                <div style={{ padding: '14px 16px', borderRadius: 12, background: 'rgba(255,255,255,0.02)', border: '1px solid var(--md-sys-color-outline-variant)', opacity: 0.85 }}>
                  <div style={{ fontSize: '0.73rem', opacity: 0.65, marginBottom: 4 }}>
                    PREVIOUS CREDENTIAL (STRIPPED FROM ADMINISTRATORS)
                  </div>
                  <div className="mono" style={{ fontSize: '0.85rem' }}>
                    .\{revealedLAPS.previous_account} — {revealedLAPS.previous_password}
                  </div>
                </div>
              )}
            </div>
          )}
        </Modal>
      </div>
    </Layout>
  )
}
