import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Monitor, ArrowLeft, Lock, Trash2, RefreshCw, HelpCircle } from 'lucide-react'
import { Layout } from '../components/Layout'
import { Badge } from '../components/Badge'
import { api, type Device, type DeviceCompliance, type DeviceCommand } from '../api'
import { formatResultCode } from '../format'

function timeAgo(iso: string | null) {
  if (!iso) return 'Never'
  const diff = Date.now() - new Date(iso).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1)  return 'Just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export function DeviceDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [device, setDevice]           = useState<Device | null>(null)
  const [, setPendingCmds]             = useState(0)
  const [compliance, setCompliance]   = useState<DeviceCompliance | null>(null)
  const [commands, setCommands]       = useState<DeviceCommand[]>([])
  const [loading, setLoading]         = useState(true)
  const [error, setError]             = useState<string | null>(null)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [confirmWipe, setConfirmWipe]     = useState(false)

  useEffect(() => {
    if (!id) return
    refresh()
  }, [id])

  const refresh = () => {
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
  }

  const action = async (name: string, fn: () => Promise<unknown>) => {
    setActionLoading(name)
    try { 
      await fn() 
      // Refresh after a short delay to see the queued state
      setTimeout(refresh, 500)
    } catch (e) { alert(`Failed: ${e}`) }
    finally { setActionLoading(null) }
  }

  if (loading) return <Layout title="Device"><div style={{ opacity: 0.6, padding: 40 }}>Initializing telemetry…</div></Layout>
  if (error)   return <Layout title="Device"><div style={{ color: 'var(--md-sys-color-error)', padding: 40 }}>Error loading device: {error}</div></Layout>
  if (!device) return <Layout title="Device"><div style={{ color: 'var(--md-sys-color-error)', padding: 40 }}>Device not found in registry</div></Layout>

  return (
    <Layout title="Device Management">
      <div className="fade-in">
        <button className="btn btn-secondary btn-sm" onClick={() => navigate('/devices')} style={{ marginBottom: 24, padding: '8px 16px' }}>
          <ArrowLeft size={14} /> Back to Fleet
        </button>

        {/* Hero Banner */}
        <div className="card" style={{ padding: 40, marginBottom: 32, display: 'flex', alignItems: 'center', gap: 40, background: 'radial-gradient(circle at top right, rgba(208, 188, 255, 0.1), transparent)' }}>
          <div className="detail-icon-large">
            <Monitor size={36} />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 8 }}>
              <h1 style={{ fontSize: '2.4rem', fontWeight: 800, margin: 0 }}>{device.device_name || 'Generic Windows Device'}</h1>
              <Badge status={device.compliance_status} label={device.compliance_status === 'compliant' ? 'Verified Healthy' : 'Action Required'} />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 24, opacity: 0.6, fontSize: '1rem', fontWeight: 500 }}>
              <span>{device.manufacturer} {device.model}</span>
              <span style={{ width: 4, height: 4, borderRadius: '50%', background: 'currentColor' }} />
              <span>Windows {device.os_version}</span>
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
            <button className="btn btn-secondary"
              onClick={() => action('lock', () => api.devices.lock(id!))}
              disabled={!!actionLoading}
              style={{ width: 52, height: 52, padding: 0, borderRadius: 16 }}>
              <Lock size={20} />
            </button>
            <button className="btn btn-secondary"
              style={{ color: 'var(--md-sys-color-error)', width: 52, height: 52, padding: 0, borderRadius: 16 }}
              onClick={() => setConfirmWipe(true)}
              disabled={!!actionLoading}>
              <Trash2 size={20} />
            </button>
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
                <div className="empty-state" style={{ padding: 60 }}>
                  <HelpCircle size={40} style={{ opacity: 0.2, marginBottom: 16 }} />
                  <p style={{ opacity: 0.6 }}>No policy configuration received from device yet.</p>
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
                          <td><span style={{ fontWeight: 700, textTransform: 'uppercase', fontSize: '0.75rem', color: 'var(--md-sys-color-primary)' }}>{cmd.type}</span></td>
                          <td>
                            <Badge status={cmd.status === 'sent' ? 'pending' : cmd.status === 'success' ? 'compliant' : cmd.status} label={cmd.status} />
                          </td>
                          <td style={{ opacity: 0.6 }}>{timeAgo(cmd.created_at)}</td>
                          <td>
                            {cmd.result_code ? (
                              <span style={{ 
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
              <div className="stat-label" style={{ marginBottom: 16 }}>Inventory Detail</div>
              <div className="info-grid" style={{ gridTemplateColumns: '1fr', gap: 20 }}>
                {[
                  { label: 'Manufacturer', value: device.manufacturer },
                  { label: 'Model', value: device.model },
                  { label: 'OS Version', value: device.os_version },
                  { label: 'OS Build', value: device.os_build },
                  { label: 'Serial Number', value: device.serial_number },
                  { label: 'Hardware ID', value: device.hardware_id, mono: true },
                ].map(item => (
                  <div key={item.label}>
                    <div className="info-label" style={{ marginBottom: 4, fontSize: '0.7rem' }}>{item.label}</div>
                    <div className="info-value" style={{ 
                      fontSize: '0.875rem', 
                      fontFamily: item.mono ? 'monospace' : 'inherit',
                      wordBreak: 'break-all',
                      color: 'var(--md-sys-color-on-surface)'
                    }}>
                      {item.value || 'Not reported'}
                    </div>
                  </div>
                ))}
              </div>
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

        {/* Wipe Confirm */}
        {confirmWipe && (
          <div className="modal-overlay" onClick={() => setConfirmWipe(false)}>
            <div className="modal" style={{ maxWidth: 440 }} onClick={e => e.stopPropagation()}>
              <div className="modal-header">
                <span className="modal-title" style={{ color: 'var(--md-sys-color-error)' }}>Confirm Action</span>
              </div>
              <div className="modal-body">
                <p style={{ opacity: 0.8, lineHeight: 1.6 }}>
                  You are about to issue a <strong>Remote Wipe</strong> command. This operation is irreversible.
                </p>
              </div>
              <div className="modal-footer">
                <button className="btn btn-secondary" onClick={() => setConfirmWipe(false)}>Cancel</button>
                <button className="btn btn-danger" onClick={async () => {
                  setConfirmWipe(false)
                  await action('wipe', () => api.devices.wipe(id!))
                  navigate('/devices')
                }}>
                  Confirm Wipe
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  )
}
