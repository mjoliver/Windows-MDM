import { useEffect, useState } from 'react'
import { CheckSquare, AlertTriangle, HelpCircle, Monitor, ShieldCheck, KeyRound, UserCheck, Save } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Layout } from '../components/Layout'
import { Badge } from '../components/Badge'
import { api, type FleetCompliance, type Device, type FleetPostureSummary, type BitLockerPolicy, type LAPSPolicy, type Group } from '../api'
import { EmptyState } from '../components/EmptyState'
import { useToast } from '../hooks/useToast'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'

const CIPHER_OPTIONS = [
  { value: 7, label: 'XTS-AES 256-bit (Recommended)' },
  { value: 6, label: 'XTS-AES 128-bit' },
  { value: 4, label: 'AES-CBC 256-bit' },
  { value: 3, label: 'AES-CBC 128-bit' },
]

export function CompliancePage() {
  const [fleet, setFleet]       = useState<FleetCompliance | null>(null)
  const [posture, setPosture]   = useState<FleetPostureSummary | null>(null)
  const [bitlocker, setBitlocker] = useState<BitLockerPolicy | null>(null)
  const [laps, setLaps]         = useState<LAPSPolicy | null>(null)
  const [groups, setGroups]     = useState<Group[]>([])
  const [savingBL, setSavingBL] = useState(false)
  const [savingLAPS, setSavingLAPS] = useState(false)
  const [devices, setDevices]   = useState<Device[]>([])
  const [, setLoading]          = useState(true)
  const navigate = useNavigate()
  const toast = useToast()

  useEffect(() => {
    Promise.all([
      api.compliance.fleet(),
      api.devices.list(),
      api.compliance.postureSummary().catch(() => null),
      api.bitlocker.policy().catch(() => null),
      api.laps.policy().catch(() => null),
      api.groups.list().catch(() => []),
    ]).then(([f, d, p, bl, lp, g]) => {
      setFleet(f)
      setDevices(d)
      setPosture(p)
      setBitlocker(bl)
      setLaps(lp)
      setGroups(g)
    }).finally(() => setLoading(false))
  }, [])

  const saveBitLockerPolicy = async () => {
    if (!bitlocker) return
    setSavingBL(true)
    try {
      const updated = await api.bitlocker.updatePolicy({
        enabled: bitlocker.enabled,
        require_device_encryption: bitlocker.require_device_encryption,
        silent_encryption: bitlocker.silent_encryption,
        allow_standard_user: bitlocker.allow_standard_user,
        os_drive_cipher: bitlocker.os_drive_cipher,
        fixed_drive_cipher: bitlocker.fixed_drive_cipher,
        removable_drive_cipher: bitlocker.removable_drive_cipher,
        target_all_devices: bitlocker.target_all_devices,
        group_ids: bitlocker.group_ids,
      })
      setBitlocker(updated)
      toast.success(
        updated.enabled
          ? `BitLocker policy saved — queued ${updated.commands_queued ?? 0} CSP command(s) across ${updated.enforced_devices ?? 0} device(s).`
          : 'BitLocker CSP enforcement disabled and ungoverned settings retracted.'
      )
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setSavingBL(false)
    }
  }

  const saveLAPSPolicy = async () => {
    if (!laps) return
    setSavingLAPS(true)
    try {
      const updated = await api.laps.updatePolicy({
        enabled: laps.enabled,
        account_prefix: laps.account_prefix,
        password_length: laps.password_length,
        rotation_days: laps.rotation_days,
        rotate_after_reveal_minutes: laps.rotate_after_reveal_minutes,
        target_all_devices: laps.target_all_devices,
        group_ids: laps.group_ids,
      })
      setLaps(updated)
      toast.success(
        updated.enabled
          ? `Cloud LAPS saved — reconciled ${updated.governed_devices ?? 0} device(s) (${updated.commands_queued ?? 0} CSP command(s) queued).`
          : 'Cloud LAPS disabled — queued Administrators privilege revocation across previously governed devices.'
      )
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setSavingLAPS(false)
    }
  }

  const pct   = fleet?.summary.compliance_percent ?? 0
  const total = fleet?.summary.total_devices ?? 0

  const pieData = !fleet ? [] : [
    { name: 'Compliant',     value: fleet.summary.compliant_devices,     color: '#10b981' },
    { name: 'Non-compliant', value: fleet.summary.non_compliant_devices, color: '#ef4444' },
    { name: 'Unknown',       value: fleet.summary.unknown_devices,       color: '#475569' },
  ].filter(d => d.value > 0)

  const rateColor = pct >= 80 ? 'var(--success)' : pct >= 50 ? 'var(--warning)' : 'var(--danger)'

  return (
    <Layout title="Compliance">
      <div className="page-header">
        <div className="page-header-left">
          <h1>Compliance</h1>
          <p>Fleet-wide policy enforcement status</p>
        </div>
      </div>

      {/* Summary cards */}
      <div className="stat-grid" style={{ marginBottom: 24 }}>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(129,140,248,0.12)' }}>
            <Monitor size={18} color="var(--accent)" />
          </div>
          <div className="stat-label">Total Devices</div>
          <div className="stat-value">{total}</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'var(--success-dim)' }}>
            <CheckSquare size={18} color="var(--success)" />
          </div>
          <div className="stat-label">Compliant</div>
          <div className="stat-value" style={{ color: 'var(--success)' }}>
            {fleet?.summary.compliant_devices ?? 0}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'var(--danger-dim)' }}>
            <AlertTriangle size={18} color="var(--danger)" />
          </div>
          <div className="stat-label">Non-compliant</div>
          <div className="stat-value" style={{ color: 'var(--danger)' }}>
            {fleet?.summary.non_compliant_devices ?? 0}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'var(--neutral-dim)' }}>
            <HelpCircle size={18} color="var(--neutral)" />
          </div>
          <div className="stat-label">Unknown</div>
          <div className="stat-value" style={{ color: 'var(--neutral)' }}>
            {fleet?.summary.unknown_devices ?? 0}
          </div>
        </div>
      </div>

      <div className="grid-2" style={{ marginBottom: 24 }}>
        {/* Donut */}
        <div className="card">
          <div className="card-header" style={{ marginBottom: 20 }}>
            <div className="card-title">Compliance Rate</div>
          </div>
          {total === 0 ? (
            <EmptyState icon={<Monitor size={28} />} title="No devices enrolled" description="" style={{ padding: '28px 0' }} />
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: 28 }}>
              <div style={{ position: 'relative', width: 160, height: 160, flexShrink: 0 }}>
                <ResponsiveContainer width={160} height={160}>
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={72}
                      dataKey="value" strokeWidth={0}>
                      {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                    </Pie>
                    <Tooltip
                      contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8 }}
                      itemStyle={{ color: 'var(--text-primary)' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
                  <span style={{ fontSize: '1.6rem', fontWeight: 800, color: rateColor, lineHeight: 1 }}>{pct}%</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 2 }}>compliant</span>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12, flex: 1 }}>
                {pieData.map(d => (
                  <div key={d.name}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ width: 8, height: 8, borderRadius: 2, background: d.color, display: 'inline-block' }} />
                        {d.name}
                      </span>
                      <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>{d.value}</span>
                    </div>
                    <div className="progress-bar">
                      <div className="progress-fill" style={{ width: `${total ? (d.value / total) * 100 : 0}%`, background: d.color }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Top issues */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Top Policy Issues</div>
            <div className="card-subtitle">Policies failing across the most devices</div>
          </div>
          {(fleet?.top_issues?.length ?? 0) === 0 ? (
            <EmptyState icon={<CheckSquare size={28} />} title="No issues detected" description="" style={{ padding: '28px 0' }} />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
              {fleet!.top_issues.map((issue, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                  <AlertTriangle size={14} color="var(--danger)" style={{ flexShrink: 0 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {issue.display_name || issue.oma_uri}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>{issue.oma_uri}</div>
                  </div>
                  <Badge status="danger" label={`${issue.non_compliant_count}`} dot={false} />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Fleet Hardware & Security Posture */}
      {posture && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div>
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <ShieldCheck size={18} />
                Hardware & Endpoint Security Posture
              </div>
              <div className="card-subtitle">
                {posture.posture_reported_devices} of {posture.total_active_devices} active device{posture.total_active_devices !== 1 ? 's' : ''} reporting OMA-DM security telemetry
              </div>
            </div>
          </div>
          <div className="stat-grid" style={{ marginBottom: 0 }}>
            {[
              { label: 'Secure Boot Enabled', count: posture.secure_boot_enabled },
              { label: 'BitLocker Encrypted', count: posture.bitlocker_encrypted },
              { label: 'Defender Active', count: posture.antivirus_healthy },
              { label: 'Firewall Active', count: posture.firewall_healthy },
            ].map(item => (
              <div key={item.label} style={{ padding: '16px 20px', borderRadius: 14, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
                <div style={{ fontSize: '0.78rem', opacity: 0.65, marginBottom: 6 }}>{item.label}</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 800 }}>
                  {item.count}
                  <span style={{ fontSize: '0.9rem', fontWeight: 500, opacity: 0.5 }}> / {posture.posture_reported_devices}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* BitLocker CSP Enforcement & Recovery Key Vault */}
      {bitlocker && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div>
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <KeyRound size={18} />
                BitLocker Drive Encryption & Key Escrow Policy
              </div>
              <div className="card-subtitle">
                Enforce Windows 10/11 <code className="mono">BitLocker</code> CSP ciphers silently and store AES-256-GCM encrypted 48-digit recovery passwords ({bitlocker.total_escrowed_keys} key{bitlocker.total_escrowed_keys !== 1 ? 's' : ''} escrowed across {bitlocker.escrowed_devices} device{bitlocker.escrowed_devices !== 1 ? 's' : ''})
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <Badge status={bitlocker.enabled ? 'compliant' : 'unknown'} label={bitlocker.enabled ? 'Enforced' : 'Disabled'} />
              <button className="btn btn-primary btn-sm" onClick={saveBitLockerPolicy} disabled={savingBL}>
                <Save size={14} />
                {savingBL ? 'Saving…' : 'Save Policy'}
              </button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, marginBottom: 16 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={bitlocker.enabled}
                onChange={e => setBitlocker({ ...bitlocker, enabled: e.target.checked })}
              />
              <div>
                <div style={{ fontSize: '0.84rem', fontWeight: 600 }}>Enable BitLocker Policy</div>
                <div style={{ fontSize: '0.72rem', opacity: 0.6 }}>Enforce via OMA-DM BitLocker CSP</div>
              </div>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={bitlocker.silent_encryption}
                onChange={e => setBitlocker({ ...bitlocker, silent_encryption: e.target.checked })}
              />
              <div>
                <div style={{ fontSize: '0.84rem', fontWeight: 600 }}>Silent Zero-Touch Mode</div>
                <div style={{ fontSize: '0.72rem', opacity: 0.6 }}>Suppress encryption warning UI</div>
              </div>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={bitlocker.allow_standard_user}
                onChange={e => setBitlocker({ ...bitlocker, allow_standard_user: e.target.checked })}
              />
              <div>
                <div style={{ fontSize: '0.84rem', fontWeight: 600 }}>Standard User Encryption</div>
                <div style={{ fontSize: '0.72rem', opacity: 0.6 }}>Encrypt without local admin login</div>
              </div>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={bitlocker.target_all_devices}
                onChange={e => setBitlocker({ ...bitlocker, target_all_devices: e.target.checked })}
              />
              <div>
                <div style={{ fontSize: '0.84rem', fontWeight: 600 }}>Target Entire Fleet</div>
                <div style={{ fontSize: '0.72rem', opacity: 0.6 }}>Apply to all active enrolled PCs</div>
              </div>
            </label>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16 }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">OS Drive Cipher</label>
              <select
                className="form-input"
                value={bitlocker.os_drive_cipher}
                onChange={e => setBitlocker({ ...bitlocker, os_drive_cipher: Number(e.target.value) })}
              >
                {CIPHER_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Fixed Data Drive Cipher</label>
              <select
                className="form-input"
                value={bitlocker.fixed_drive_cipher}
                onChange={e => setBitlocker({ ...bitlocker, fixed_drive_cipher: Number(e.target.value) })}
              >
                {CIPHER_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Removable Drive Cipher</label>
              <select
                className="form-input"
                value={bitlocker.removable_drive_cipher}
                onChange={e => setBitlocker({ ...bitlocker, removable_drive_cipher: Number(e.target.value) })}
              >
                {CIPHER_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
          </div>

          {!bitlocker.target_all_devices && groups.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div className="form-label" style={{ marginBottom: 8 }}>Assigned Device Groups</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {groups.map(g => {
                  const selected = bitlocker.group_ids.includes(g.id)
                  return (
                    <button
                      key={g.id}
                      type="button"
                      className={`btn btn-sm ${selected ? 'btn-primary' : 'btn-secondary'}`}
                      onClick={() => {
                        const next = selected
                          ? bitlocker.group_ids.filter(x => x !== g.id)
                          : [...bitlocker.group_ids, g.id]
                        setBitlocker({ ...bitlocker, group_ids: next })
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
      )}

      {/* Agentless Cloud LAPS Policy Card */}
      {laps && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, marginBottom: 18 }}>
            <div>
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <UserCheck size={17} color="var(--accent)" />
                Cloud LAPS — Ephemeral Local Administrator
                <Badge status={laps.enabled ? 'compliant' : 'unknown'} label={laps.enabled ? 'Enabled' : 'Disabled'} />
              </div>
              <div style={{ fontSize: '0.8rem', opacity: 0.65, marginTop: 4 }}>
                Agentless rotation via Windows <code className="mono">Accounts</code> & <code className="mono">LocalUsersAndGroups</code> CSPs • {laps.active_devices} active, {laps.rotating_devices} provisioning/rotating
              </div>
            </div>
            <button className="btn btn-primary btn-sm" onClick={saveLAPSPolicy} disabled={savingLAPS}>
              <Save size={14} />
              {savingLAPS ? 'Saving…' : 'Save LAPS Policy'}
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14, marginBottom: 18 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={laps.enabled}
                onChange={e => setLaps({ ...laps, enabled: e.target.checked })}
              />
              <div>
                <div style={{ fontSize: '0.84rem', fontWeight: 600 }}>Enable Cloud LAPS</div>
                <div style={{ fontSize: '0.72rem', opacity: 0.6 }}>Provision & rotate unique local admin per PC</div>
              </div>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={laps.target_all_devices}
                onChange={e => setLaps({ ...laps, target_all_devices: e.target.checked })}
              />
              <div>
                <div style={{ fontSize: '0.84rem', fontWeight: 600 }}>Target Entire Fleet</div>
                <div style={{ fontSize: '0.72rem', opacity: 0.6 }}>Govern all active enrolled Windows PCs</div>
              </div>
            </label>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 16 }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Username Prefix (≤12 chars)</label>
              <input
                className="form-input mono"
                value={laps.account_prefix}
                maxLength={12}
                onChange={e => setLaps({ ...laps, account_prefix: e.target.value })}
                placeholder="lzadm"
              />
              <div style={{ fontSize: '0.7rem', opacity: 0.55, marginTop: 4 }}>
                Provisions <code className="mono">{laps.account_prefix || 'lzadm'}-xxxx</code>
              </div>
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Password Length (14–32)</label>
              <input
                type="number"
                className="form-input"
                min={14}
                max={32}
                value={laps.password_length}
                onChange={e => setLaps({ ...laps, password_length: Number(e.target.value) })}
              />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Rotation Interval (Days)</label>
              <input
                type="number"
                className="form-input"
                min={1}
                max={90}
                value={laps.rotation_days}
                onChange={e => setLaps({ ...laps, rotation_days: Number(e.target.value) })}
              />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Post-Reveal Auto-Rotate (Min)</label>
              <input
                type="number"
                className="form-input"
                min={0}
                max={1440}
                value={laps.rotate_after_reveal_minutes}
                onChange={e => setLaps({ ...laps, rotate_after_reveal_minutes: Number(e.target.value) })}
              />
            </div>
          </div>

          {!laps.target_all_devices && groups.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div className="form-label" style={{ marginBottom: 8 }}>Assigned Device Groups</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {groups.map(g => {
                  const selected = laps.group_ids.includes(g.id)
                  return (
                    <button
                      key={g.id}
                      type="button"
                      className={`btn btn-sm ${selected ? 'btn-primary' : 'btn-secondary'}`}
                      onClick={() => {
                        const next = selected
                          ? laps.group_ids.filter(x => x !== g.id)
                          : [...laps.group_ids, g.id]
                        setLaps({ ...laps, group_ids: next })
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
      )}

      {/* Per-device table */}
      <div className="table-wrap">
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
          Device Compliance
        </div>
        {devices.length === 0 ? (
          <EmptyState icon={<Monitor size={36} />} title="No devices enrolled" description="Enrolled devices will appear here with their compliance status" />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>OS Version</th>
                <th>Last Check-In</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {devices.map(d => (
                <tr key={d.id}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <Monitor size={14} color="var(--text-muted)" />
                      {d.device_name || d.hardware_id}
                    </div>
                  </td>
                  <td style={{ color: 'var(--text-muted)' }}>{d.os_version || '—'}</td>
                  <td style={{ color: 'var(--text-muted)' }}>
                    {d.last_checkin ? new Date(d.last_checkin).toLocaleString() : 'Never'}
                  </td>
                  <td><Badge status={d.compliance_status} /></td>
                  <td>
                    <button className="btn btn-secondary btn-sm"
                      onClick={() => navigate(`/devices/${d.id}`)}>
                      Details →
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Layout>
  )
}
