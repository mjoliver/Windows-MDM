import { useEffect, useState, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Monitor, Lock, Trash2, RefreshCw, RotateCcw, HelpCircle, ShieldCheck, Zap, Package } from 'lucide-react'
import { Layout } from '../components/Layout'
import { Breadcrumb } from '../components/Breadcrumb'
import { Badge } from '../components/Badge'
import { api, type Device, type DeviceCompliance, type DeviceCommand, type DevicePosture, type DeviceAppInstall } from '../api'
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
  const [apps, setApps]               = useState<DeviceAppInstall[]>([])
  const [commands, setCommands]       = useState<DeviceCommand[]>([])
  const [loading, setLoading]         = useState(true)
  const [error, setError]             = useState<string | null>(null)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [confirmReboot, setConfirmReboot] = useState(false)
  const [confirmWipe, setConfirmWipe]     = useState(false)
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
                            <div className="mono" style={{ fontSize: '0.7rem', opacity: 0.5 }}>{app.product_code}</div>
                          </td>
                          <td>{app.version}</td>
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
      </div>
    </Layout>
  )
}
