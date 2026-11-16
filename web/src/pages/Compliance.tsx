import { useEffect, useState } from 'react'
import { CheckSquare, AlertTriangle, HelpCircle, Monitor, ShieldCheck, KeyRound, UserCheck, Save, ShieldAlert, Plus, Trash2, Usb, Shield, Bell, Send } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Layout } from '../components/Layout'
import { Badge } from '../components/Badge'
import { api, type FleetCompliance, type Device, type FleetPostureSummary, type BitLockerPolicy, type LAPSPolicy, type EndpointSecurityPolicy, type FirewallRule, type DeviceLockdownPolicy, type EndpointHardeningPolicy, type DesktopExperiencePolicy, type WebhookEndpoint, type WebhookDeliveryItem, type ComplianceAutomationSettings, type Group } from '../api'
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
  const [secPolicy, setSecPolicy] = useState<EndpointSecurityPolicy | null>(null)
  const [fwRules, setFwRules]   = useState<FirewallRule[]>([])
  const [lockdown, setLockdown] = useState<DeviceLockdownPolicy | null>(null)
  const [hardening, setHardening] = useState<EndpointHardeningPolicy | null>(null)
  const [experience, setExperience] = useState<DesktopExperiencePolicy | null>(null)
  const [savingExperience, setSavingExperience] = useState(false)
  const [automation, setAutomation] = useState<ComplianceAutomationSettings | null>(null)
  const [webhooks, setWebhooks] = useState<WebhookEndpoint[]>([])
  const [whDeliveries, setWhDeliveries] = useState<WebhookDeliveryItem[]>([])
  const [whName, setWhName]     = useState('')
  const [whUrl, setWhUrl]       = useState('')
  const [whFormat, setWhFormat] = useState<'json' | 'slack' | 'teams' | 'discord'>('json')
  const [whSecret, setWhSecret] = useState('')
  const [addingWh, setAddingWh] = useState(false)
  const [testingWhId, setTestingWhId] = useState<string | null>(null)
  const [groups, setGroups]     = useState<Group[]>([])
  const [savingBL, setSavingBL] = useState(false)
  const [savingLAPS, setSavingLAPS] = useState(false)
  const [savingSec, setSavingSec] = useState(false)
  const [savingLock, setSavingLock] = useState(false)
  const [savingHardening, setSavingHardening] = useState(false)
  const [fwName, setFwName]     = useState('')
  const [fwDir, setFwDir]       = useState<'IN' | 'OUT'>('IN')
  const [fwAction, setFwAction] = useState<number>(0)
  const [fwProto, setFwProto]   = useState<number>(6)
  const [fwPorts, setFwPorts]   = useState('')
  const [addingFw, setAddingFw] = useState(false)
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
      api.security.policy().catch(() => null),
      api.security.listFirewallRules().catch(() => []),
      api.lockdown.policy().catch(() => null),
      api.hardening.policy().catch(() => null),
      api.experience.policy().catch(() => null),
      api.webhooks.automation().catch(() => null),
      api.webhooks.list().catch(() => ({ endpoints: [], supported_events: [] })),
      api.webhooks.deliveries().catch(() => []),
      api.groups.list().catch(() => []),
    ]).then(([f, d, p, bl, lp, sp, fr, lk, hd, exp, auto, wh, whDeliv, g]) => {
      setFleet(f)
      setDevices(d)
      setPosture(p)
      setBitlocker(bl)
      setLaps(lp)
      setSecPolicy(sp)
      setFwRules(fr)
      setLockdown(lk)
      setHardening(hd)
      setExperience(exp)
      setAutomation(auto)
      setWebhooks(wh.endpoints)
      setWhDeliveries(whDeliv)
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

  const saveSecurityPolicy = async () => {
    if (!secPolicy) return
    setSavingSec(true)
    try {
      const updated = await api.security.updatePolicy({
        enabled: secPolicy.enabled,
        allow_realtime_monitoring: secPolicy.allow_realtime_monitoring,
        allow_behavior_monitoring: secPolicy.allow_behavior_monitoring,
        allow_cloud_protection: secPolicy.allow_cloud_protection,
        cloud_block_level: secPolicy.cloud_block_level,
        pua_protection: secPolicy.pua_protection,
        enable_network_protection: secPolicy.enable_network_protection,
        check_sigs_before_scan: secPolicy.check_sigs_before_scan,
        firewall_domain_enabled: secPolicy.firewall_domain_enabled,
        firewall_private_enabled: secPolicy.firewall_private_enabled,
        firewall_public_enabled: secPolicy.firewall_public_enabled,
        block_inbound_domain: secPolicy.block_inbound_domain,
        block_inbound_private: secPolicy.block_inbound_private,
        block_inbound_public: secPolicy.block_inbound_public,
        target_all_devices: secPolicy.target_all_devices,
        group_ids: secPolicy.group_ids,
      })
      setSecPolicy(updated)
      toast.success(
        updated.enabled
          ? `Defender & Firewall baseline saved — queued ${updated.commands_queued ?? 0} CSP command(s) across ${updated.enforced_devices} device(s).`
          : 'Defender CSP baseline disabled and retracted.'
      )
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setSavingSec(false)
    }
  }

  const addFirewallRule = async () => {
    if (!fwName.trim()) {
      toast.error('Enter a rule name first.')
      return
    }
    setAddingFw(true)
    try {
      const created = await api.security.createFirewallRule({
        name: fwName.trim(),
        direction: fwDir,
        action: fwAction,
        protocol: fwProto,
        local_port_ranges: (fwProto === 6 || fwProto === 17) ? fwPorts.trim() : '',
        profiles: 7,
      })
      setFwRules(prev => [created, ...prev])
      setFwName('')
      setFwPorts('')
      toast.success(`Deployed Atomic Firewall CSP rule '${created.rule_key}' (${created.commands_queued ?? 0} command(s) queued).`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setAddingFw(false)
    }
  }

  const removeFirewallRule = async (rule: FirewallRule) => {
    try {
      const res = await api.security.deleteFirewallRule(rule.id)
      setFwRules(prev => prev.filter(r => r.id !== rule.id))
      toast.success(`Deleted rule '${rule.rule_key}' (${res.commands_queued} <Delete> command(s) queued).`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    }
  }

  const saveLockdownPolicy = async () => {
    if (!lockdown) return
    setSavingLock(true)
    try {
      const updated = await api.lockdown.updatePolicy({
        enabled: lockdown.enabled,
        usb_storage_mode: lockdown.usb_storage_mode,
        require_password: lockdown.require_password,
        min_password_length: lockdown.min_password_length,
        alphanumeric_required: lockdown.alphanumeric_required,
        max_inactivity_minutes: lockdown.max_inactivity_minutes,
        max_failed_attempts: lockdown.max_failed_attempts,
        allow_camera: lockdown.allow_camera,
        allow_bluetooth: lockdown.allow_bluetooth,
        kiosk_mode: lockdown.kiosk_mode,
        kiosk_account: lockdown.kiosk_account,
        kiosk_app_aumid: lockdown.kiosk_app_aumid,
        target_all_devices: lockdown.target_all_devices,
        group_ids: lockdown.group_ids,
      })
      setLockdown(updated)
      toast.success(
        updated.enabled
          ? `Device Lockdown saved — queued ${updated.commands_queued ?? 0} CSP command(s) across ${updated.enforced_devices} device(s).`
          : 'Device Lockdown disabled and ungoverned Storage/DeviceLock policies retracted.'
      )
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setSavingLock(false)
    }
  }

  const applyASRPreset = (mode: 0 | 1 | 2) => {
    if (!hardening) return
    const next: Record<string, number> = {}
    if (mode !== 0) {
      for (const r of hardening.catalog) {
        next[r.guid] = mode
      }
    }
    setHardening({ ...hardening, asr_rules: next, active_asr_count: Object.keys(next).length })
  }

  const saveHardeningPolicy = async () => {
    if (!hardening) return
    setSavingHardening(true)
    try {
      const updated = await api.hardening.updatePolicy({
        enabled: hardening.enabled,
        asr_rules: hardening.asr_rules,
        enable_smartscreen_shell: hardening.enable_smartscreen_shell,
        prevent_smartscreen_override: hardening.prevent_smartscreen_override,
        app_install_control: hardening.app_install_control,
        submit_samples_consent: hardening.submit_samples_consent,
        disable_local_admin_merge: hardening.disable_local_admin_merge,
        target_all_devices: hardening.target_all_devices,
        group_ids: hardening.group_ids,
      })
      setHardening(updated)
      toast.success(
        updated.enabled
          ? `Defender ASR & SmartScreen hardening saved — ${updated.active_asr_count} active rule(s) queued across ${updated.enforced_devices} device(s) (${updated.commands_queued ?? 0} CSP commands).`
          : 'Defender ASR & SmartScreen hardening disabled and retracted via <Delete>.'
      )
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setSavingHardening(false)
    }
  }

  const toggleAutoRemediate = async (next: boolean) => {
    try {
      const updated = await api.webhooks.updateAutomation(next)
      setAutomation(updated)
      toast.success(
        next
          ? 'Compliance Auto-Remediation enabled — drifted CSP settings will re-queue automatically on OMA-DM check-in.'
          : 'Compliance Auto-Remediation disabled.'
      )
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    }
  }

  const addWebhook = async () => {
    if (!whName.trim() || !whUrl.trim()) {
      toast.error('Enter both a webhook name and destination URL.')
      return
    }
    setAddingWh(true)
    try {
      const created = await api.webhooks.create({
        name: whName.trim(),
        url: whUrl.trim(),
        format: whFormat,
        secret: whSecret.trim(),
      })
      setWebhooks(prev => [created, ...prev])
      setWhName('')
      setWhUrl('')
      setWhSecret('')
      toast.success(`Created ${created.format.toUpperCase()} webhook '${created.name}'.`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setAddingWh(false)
    }
  }

  const sendTestWebhook = async (ep: WebhookEndpoint) => {
    setTestingWhId(ep.id)
    try {
      const res = await api.webhooks.test(ep.id)
      const latest = await api.webhooks.deliveries().catch(() => [])
      setWhDeliveries(latest)
      if (res.success) {
        toast.success(`Test ping delivered to '${ep.name}' (HTTP ${res.status_code}).`)
      } else {
        toast.error(`Test ping failed for '${ep.name}': ${res.error || `HTTP ${res.status_code}`}`)
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setTestingWhId(null)
    }
  }

  const removeWebhook = async (ep: WebhookEndpoint) => {
    try {
      await api.webhooks.delete(ep.id)
      setWebhooks(prev => prev.filter(x => x.id !== ep.id))
      toast.success(`Deleted webhook '${ep.name}'.`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
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

      {/* Microsoft Defender Antivirus & Windows Firewall CSP Baseline */}
      {secPolicy && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, marginBottom: 18 }}>
            <div>
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <ShieldAlert size={18} color="var(--accent)" />
                Defender Antivirus & Firewall CSP Baseline
                <Badge status={secPolicy.enabled ? 'compliant' : 'unknown'} label={secPolicy.enabled ? 'Enforced' : 'Disabled'} />
              </div>
              <div style={{ fontSize: '0.8rem', opacity: 0.65, marginTop: 4 }}>
                Enforce <code className="mono">Policy/Config/Defender</code>, <code className="mono">Firewall/MdmStore</code> profiles & transactional <code className="mono">&lt;Atomic&gt;</code> custom firewall rules • {secPolicy.enforced_devices} device{secPolicy.enforced_devices !== 1 ? 's' : ''} enforced
              </div>
            </div>
            <button className="btn btn-primary btn-sm" onClick={saveSecurityPolicy} disabled={savingSec}>
              <Save size={14} />
              {savingSec ? 'Saving…' : 'Save Security Baseline'}
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14, marginBottom: 16 }}>
            {[
              { key: 'enabled', title: 'Enable Security Baseline', sub: 'Enforce Defender + Firewall CSPs', val: secPolicy.enabled },
              { key: 'allow_realtime_monitoring', title: 'Real-Time Monitoring', sub: 'Continuous Defender AV scanning', val: secPolicy.allow_realtime_monitoring },
              { key: 'allow_cloud_protection', title: 'MAPS Cloud Protection', sub: 'Real-time cloud block telemetry', val: secPolicy.allow_cloud_protection },
              { key: 'firewall_public_enabled', title: 'All Firewall Profiles On', sub: 'Domain, Private & Public inbound block', val: secPolicy.firewall_public_enabled },
            ].map(item => (
              <label key={item.key} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={item.val}
                  onChange={e => {
                    const v = e.target.checked
                    if (item.key === 'firewall_public_enabled') {
                      setSecPolicy({
                        ...secPolicy,
                        firewall_domain_enabled: v,
                        firewall_private_enabled: v,
                        firewall_public_enabled: v,
                        block_inbound_domain: v,
                        block_inbound_private: v,
                        block_inbound_public: v,
                      })
                    } else {
                      setSecPolicy({ ...secPolicy, [item.key]: v })
                    }
                  }}
                />
                <div>
                  <div style={{ fontSize: '0.84rem', fontWeight: 600 }}>{item.title}</div>
                  <div style={{ fontSize: '0.72rem', opacity: 0.6 }}>{item.sub}</div>
                </div>
              </label>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 16, marginBottom: 22 }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Cloud Block Level</label>
              <select
                className="form-input"
                value={secPolicy.cloud_block_level}
                onChange={e => setSecPolicy({ ...secPolicy, cloud_block_level: Number(e.target.value) })}
              >
                <option value={0}>Default</option>
                <option value={2}>High (Recommended)</option>
                <option value={4}>High Plus</option>
                <option value={6}>Zero Tolerance</option>
              </select>
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">PUA Protection</label>
              <select
                className="form-input"
                value={secPolicy.pua_protection}
                onChange={e => setSecPolicy({ ...secPolicy, pua_protection: Number(e.target.value) })}
              >
                <option value={1}>Block Potentially Unwanted Apps</option>
                <option value={2}>Audit Only</option>
                <option value={0}>Disabled</option>
              </select>
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">SmartScreen Network Protection</label>
              <select
                className="form-input"
                value={secPolicy.enable_network_protection}
                onChange={e => setSecPolicy({ ...secPolicy, enable_network_protection: Number(e.target.value) })}
              >
                <option value={1}>Block Malicious IPs/Domains</option>
                <option value={2}>Audit Mode</option>
                <option value={0}>Disabled</option>
              </select>
            </div>
          </div>

          {/* Custom Firewall Rules */}
          <div style={{ borderTop: '1px solid var(--border)', paddingTop: 18 }}>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, marginBottom: 10 }}>
              Custom Windows Firewall Rules (<code className="mono">Firewall/MdmStore/FirewallRules</code>)
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 110px 110px 120px 140px auto', gap: 10, alignItems: 'end', marginBottom: 14 }}>
              <div>
                <label className="form-label">Rule Name</label>
                <input
                  className="form-input"
                  placeholder="e.g. Block Inbound SMB 445"
                  value={fwName}
                  onChange={e => setFwName(e.target.value)}
                />
              </div>
              <div>
                <label className="form-label">Direction</label>
                <select className="form-input" value={fwDir} onChange={e => setFwDir(e.target.value as 'IN' | 'OUT')}>
                  <option value="IN">Inbound</option>
                  <option value="OUT">Outbound</option>
                </select>
              </div>
              <div>
                <label className="form-label">Action</label>
                <select className="form-input" value={fwAction} onChange={e => setFwAction(Number(e.target.value))}>
                  <option value={0}>Block</option>
                  <option value={1}>Allow</option>
                </select>
              </div>
              <div>
                <label className="form-label">Protocol</label>
                <select className="form-input" value={fwProto} onChange={e => setFwProto(Number(e.target.value))}>
                  <option value={6}>TCP</option>
                  <option value={17}>UDP</option>
                  <option value={1}>ICMPv4</option>
                  <option value={256}>Any</option>
                </select>
              </div>
              <div>
                <label className="form-label">Local Port(s)</label>
                <input
                  className="form-input mono"
                  placeholder="445 or 8000-8080"
                  disabled={fwProto !== 6 && fwProto !== 17}
                  value={fwPorts}
                  onChange={e => setFwPorts(e.target.value)}
                />
              </div>
              <button className="btn btn-secondary" onClick={addFirewallRule} disabled={addingFw}>
                <Plus size={14} />
                {addingFw ? 'Adding…' : 'Add Rule'}
              </button>
            </div>

            {fwRules.length > 0 && (
              <div className="table-wrap" style={{ marginTop: 8 }}>
                <table>
                  <thead>
                    <tr>
                      <th>Rule</th>
                      <th>Direction</th>
                      <th>Action</th>
                      <th>Protocol / Ports</th>
                      <th>Deployed</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {fwRules.map(r => (
                      <tr key={r.id}>
                        <td>
                          <div style={{ fontWeight: 600 }}>{r.name}</div>
                          <div className="mono" style={{ fontSize: '0.72rem', opacity: 0.55 }}>{r.rule_key}</div>
                        </td>
                        <td><Badge status="unknown" label={r.direction === 'IN' ? 'Inbound' : 'Outbound'} dot={false} /></td>
                        <td>
                          <Badge
                            status={r.action === 0 ? 'non_compliant' : 'compliant'}
                            label={r.action === 0 ? 'Block' : 'Allow'}
                            dot={false}
                          />
                        </td>
                        <td className="mono" style={{ fontSize: '0.8rem' }}>
                          {r.protocol === 6 ? 'TCP' : r.protocol === 17 ? 'UDP' : r.protocol === 1 ? 'ICMPv4' : 'Any'}
                          {r.local_port_ranges ? ` : ${r.local_port_ranges}` : ''}
                        </td>
                        <td>{r.deployed_devices} PC{r.deployed_devices !== 1 ? 's' : ''}</td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            className="btn btn-sm btn-secondary"
                            style={{ color: 'var(--md-sys-color-error)' }}
                            onClick={() => removeFirewallRule(r)}
                            title="Delete firewall rule from fleet"
                          >
                            <Trash2 size={13} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Device Lockdown, USB Storage & Kiosk Controls */}
      {lockdown && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, marginBottom: 18 }}>
            <div>
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Usb size={18} color="var(--accent)" />
                Device Lockdown, USB Storage &amp; Kiosk Policy
                <Badge status={lockdown.enabled ? 'compliant' : 'unknown'} label={lockdown.enabled ? 'Enforced' : 'Disabled'} />
              </div>
              <div style={{ fontSize: '0.8rem', opacity: 0.65, marginTop: 4 }}>
                Enforce <code className="mono">Policy/Config/Storage</code>, <code className="mono">DeviceLock</code>, peripheral privacy &amp; <code className="mono">AssignedAccess</code> kiosk • {lockdown.enforced_devices} device{lockdown.enforced_devices !== 1 ? 's' : ''} enforced
              </div>
            </div>
            <button className="btn btn-primary btn-sm" onClick={saveLockdownPolicy} disabled={savingLock}>
              <Save size={14} />
              {savingLock ? 'Saving…' : 'Save Lockdown Policy'}
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14, marginBottom: 18 }}>
            {[
              { key: 'enabled', title: 'Enable Device Lockdown', sub: 'Enforce Storage & DeviceLock CSPs', val: lockdown.enabled },
              { key: 'require_password', title: 'Require Password / PIN', sub: 'Enforce DeviceLock sign-in policy', val: lockdown.require_password },
              { key: 'alphanumeric_required', title: 'Alphanumeric Complexity', sub: 'Require letters + digits', val: lockdown.alphanumeric_required },
              { key: 'allow_camera', title: 'Allow Integrated Camera', sub: 'Uncheck to disable webcam', val: lockdown.allow_camera },
            ].map(item => (
              <label key={item.key} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={item.val}
                  onChange={e => setLockdown({ ...lockdown, [item.key]: e.target.checked })}
                />
                <div>
                  <div style={{ fontSize: '0.84rem', fontWeight: 600 }}>{item.title}</div>
                  <div style={{ fontSize: '0.72rem', opacity: 0.6 }}>{item.sub}</div>
                </div>
              </label>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(195px, 1fr))', gap: 16 }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Removable USB Storage</label>
              <select
                className="form-input"
                value={lockdown.usb_storage_mode}
                onChange={e => setLockdown({ ...lockdown, usb_storage_mode: e.target.value as 'allow' | 'read_only' | 'block_all' })}
              >
                <option value="allow">Allow Read &amp; Write</option>
                <option value="read_only">Read-Only (Block USB Write/Exec)</option>
                <option value="block_all">Block All Removable Storage</option>
              </select>
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Min Password Length (4–16)</label>
              <input
                type="number"
                className="form-input"
                min={4}
                max={16}
                value={lockdown.min_password_length}
                onChange={e => setLockdown({ ...lockdown, min_password_length: Number(e.target.value) })}
              />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Screen Lock Timeout (Min)</label>
              <input
                type="number"
                className="form-input"
                min={0}
                max={999}
                value={lockdown.max_inactivity_minutes}
                onChange={e => setLockdown({ ...lockdown, max_inactivity_minutes: Number(e.target.value) })}
              />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Kiosk Mode (AssignedAccess)</label>
              <select
                className="form-input"
                value={lockdown.kiosk_mode}
                onChange={e => setLockdown({ ...lockdown, kiosk_mode: e.target.value as 'none' | 'single_app' })}
              >
                <option value="none">Disabled (Standard Desktop)</option>
                <option value="single_app">Single-App Kiosk</option>
              </select>
            </div>
          </div>

          {lockdown.kiosk_mode === 'single_app' && (
            <div className="grid-2" style={{ gap: 16, marginTop: 14 }}>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Kiosk Local Account</label>
                <input
                  className="form-input mono"
                  value={lockdown.kiosk_account}
                  onChange={e => setLockdown({ ...lockdown, kiosk_account: e.target.value })}
                  placeholder="KioskUser"
                />
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">UWP Application User Model ID (AUMID)</label>
                <input
                  className="form-input mono"
                  value={lockdown.kiosk_app_aumid}
                  onChange={e => setLockdown({ ...lockdown, kiosk_app_aumid: e.target.value })}
                  placeholder="Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge"
                />
              </div>
            </div>
          )}
        </div>
      )}

      {/* Defender ASR Rules & SmartScreen Hardening */}
      {hardening && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, marginBottom: 18 }}>
            <div>
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Shield size={18} color="var(--accent)" />
                Defender Attack Surface Reduction (ASR) &amp; SmartScreen Hardening
                <Badge status={hardening.enabled ? 'compliant' : 'unknown'} label={hardening.enabled ? `Enforced (${Object.values(hardening.asr_rules).filter(v => v > 0).length} ASR)` : 'Disabled'} />
              </div>
              <div style={{ fontSize: '0.8rem', opacity: 0.65, marginTop: 4 }}>
                Enforce <code className="mono">Defender/AttackSurfaceReductionRules</code> &amp; <code className="mono">Policy/Config/SmartScreen</code> CSPs • {hardening.enforced_devices} device{hardening.enforced_devices !== 1 ? 's' : ''} enforced
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => applyASRPreset(2)}>
                Audit All (10)
              </button>
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => applyASRPreset(1)}>
                Block All Recommended
              </button>
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => applyASRPreset(0)}>
                Clear Rules
              </button>
              <button className="btn btn-primary btn-sm" onClick={saveHardeningPolicy} disabled={savingHardening}>
                <Save size={14} />
                {savingHardening ? 'Saving…' : 'Save Hardening Policy'}
              </button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14, marginBottom: 16 }}>
            {[
              { key: 'enabled', title: 'Enable ASR & SmartScreen', sub: 'Enforce Defender ASR + SmartScreen CSPs', val: hardening.enabled },
              { key: 'enable_smartscreen_shell', title: 'SmartScreen in Explorer', sub: 'Verify downloaded Win32 executables', val: hardening.enable_smartscreen_shell },
              { key: 'prevent_smartscreen_override', title: 'Prevent User Bypass', sub: 'Block "Run anyway" on SmartScreen prompts', val: hardening.prevent_smartscreen_override },
              { key: 'disable_local_admin_merge', title: 'Disable Local Admin Merge', sub: 'Ignore local Defender exclusion overrides', val: hardening.disable_local_admin_merge },
              { key: 'target_all_devices', title: 'Target Entire Fleet', sub: 'Apply across all active enrolled PCs', val: hardening.target_all_devices },
            ].map(item => (
              <label key={item.key} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={item.val}
                  onChange={e => setHardening({ ...hardening, [item.key]: e.target.checked })}
                />
                <div>
                  <div style={{ fontSize: '0.84rem', fontWeight: 600 }}>{item.title}</div>
                  <div style={{ fontSize: '0.72rem', opacity: 0.6 }}>{item.sub}</div>
                </div>
              </label>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, marginBottom: 18 }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">App Install Control (SmartScreen)</label>
              <select
                className="form-input"
                value={hardening.app_install_control}
                onChange={e => setHardening({ ...hardening, app_install_control: Number(e.target.value) })}
              >
                <option value={0}>Anywhere (Standard Desktop)</option>
                <option value={3}>Warn Before Installing Non-Store Apps</option>
                <option value={2}>Show Recommendations</option>
                <option value={1}>Microsoft Store Only</option>
              </select>
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Defender Sample Submission</label>
              <select
                className="form-input"
                value={hardening.submit_samples_consent}
                onChange={e => setHardening({ ...hardening, submit_samples_consent: Number(e.target.value) })}
              >
                <option value={1}>Send Safe Samples Automatically (Recommended)</option>
                <option value={3}>Send All Samples Automatically</option>
                <option value={0}>Always Prompt</option>
                <option value={2}>Never Send</option>
              </select>
            </div>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Microsoft Defender ASR Rule</th>
                  <th>Category</th>
                  <th style={{ width: 190 }}>Enforcement Mode</th>
                </tr>
              </thead>
              <tbody>
                {hardening.catalog.map(rule => {
                  const currentMode = hardening.asr_rules[rule.guid] ?? 0
                  return (
                    <tr key={rule.guid}>
                      <td>
                        <div style={{ fontWeight: 600, fontSize: '0.84rem' }}>{rule.name}</div>
                        <div className="mono" style={{ fontSize: '0.7rem', opacity: 0.5 }}>{rule.guid}</div>
                      </td>
                      <td>
                        <Badge status="unknown" label={rule.category} dot={false} />
                      </td>
                      <td>
                        <select
                          className="form-input"
                          style={{ padding: '6px 10px', fontSize: '0.8rem' }}
                          value={currentMode}
                          onChange={e => {
                            const nextMode = Number(e.target.value)
                            const nextRules = { ...hardening.asr_rules }
                            if (nextMode === 0) {
                              delete nextRules[rule.guid]
                            } else {
                              nextRules[rule.guid] = nextMode
                            }
                            setHardening({ ...hardening, asr_rules: nextRules })
                          }}
                        >
                          <option value={0}>Off (Not Configured)</option>
                          <option value={2}>Audit Only (2)</option>
                          <option value={1}>Block (1)</option>
                          <option value={6}>Warn — Allow User Bypass (6)</option>
                        </select>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {!hardening.target_all_devices && groups.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div className="form-label" style={{ marginBottom: 8 }}>Assigned Device Groups</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {groups.map(g => {
                  const selected = hardening.group_ids.includes(g.id)
                  return (
                    <button
                      key={g.id}
                      type="button"
                      className={`btn btn-sm ${selected ? 'btn-primary' : 'btn-secondary'}`}
                      onClick={() => {
                        const next = selected
                          ? hardening.group_ids.filter(x => x !== g.id)
                          : [...hardening.group_ids, g.id]
                        setHardening({ ...hardening, group_ids: next })
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

      {/* Compliance Auto-Remediation & SIEM / Chat Event Webhooks */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, marginBottom: 18 }}>
          <div>
            <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Bell size={18} color="var(--accent)" />
              Auto-Remediation &amp; SIEM / Chat Event Webhooks
              <Badge
                status={automation?.auto_remediate ? 'compliant' : 'unknown'}
                label={automation?.auto_remediate ? 'Auto-Remediate Active' : 'Notify Only'}
              />
            </div>
            <div style={{ fontSize: '0.8rem', opacity: 0.65, marginTop: 4 }}>
              Automatically re-apply drifted OMA-DM settings on check-in ({automation?.remediation_count ?? 0} remediation{automation?.remediation_count === 1 ? '' : 's'} performed) and stream HMAC-SHA256 signed events (<code className="mono">X-Latchz-Signature-256</code>) to SIEM, Slack, Teams, or Discord
            </div>
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', borderRadius: 12, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--md-sys-color-outline-variant)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={automation?.auto_remediate ?? false}
              onChange={e => toggleAutoRemediate(e.target.checked)}
            />
            <span style={{ fontSize: '0.84rem', fontWeight: 600 }}>Auto-Remediate Drifted PCs</span>
          </label>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 2fr 140px 1.4fr auto', gap: 10, alignItems: 'end', marginBottom: 16 }}>
          <div>
            <label className="form-label">Endpoint Name</label>
            <input
              className="form-input"
              placeholder="e.g. SOC Slack #mdm-alerts"
              value={whName}
              onChange={e => setWhName(e.target.value)}
            />
          </div>
          <div>
            <label className="form-label">Webhook URL</label>
            <input
              className="form-input mono"
              placeholder="https://hooks.slack.com/services/..."
              value={whUrl}
              onChange={e => setWhUrl(e.target.value)}
            />
          </div>
          <div>
            <label className="form-label">Payload Format</label>
            <select className="form-input" value={whFormat} onChange={e => setWhFormat(e.target.value as 'json' | 'slack' | 'teams' | 'discord')}>
              <option value="json">JSON (SIEM)</option>
              <option value="slack">Slack</option>
              <option value="teams">MS Teams</option>
              <option value="discord">Discord</option>
            </select>
          </div>
          <div>
            <label className="form-label">HMAC Signing Secret (Optional)</label>
            <input
              type="password"
              className="form-input mono"
              placeholder="whsec_..."
              value={whSecret}
              onChange={e => setWhSecret(e.target.value)}
            />
          </div>
          <button className="btn btn-primary" onClick={addWebhook} disabled={addingWh}>
            <Plus size={14} />
            {addingWh ? 'Adding…' : 'Add Webhook'}
          </button>
        </div>

        {webhooks.length > 0 && (
          <div className="table-wrap" style={{ marginBottom: whDeliveries.length > 0 ? 16 : 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Destination URL</th>
                  <th>Format</th>
                  <th>HMAC-SHA256</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {webhooks.map(ep => (
                  <tr key={ep.id}>
                    <td style={{ fontWeight: 600 }}>{ep.name}</td>
                    <td className="mono" style={{ fontSize: '0.76rem', opacity: 0.75 }}>{ep.url}</td>
                    <td><Badge status="unknown" label={ep.format.toUpperCase()} dot={false} /></td>
                    <td>
                      <Badge
                        status={ep.has_secret ? 'compliant' : 'unknown'}
                        label={ep.has_secret ? 'Vault Sealed' : 'Unsigned'}
                        dot={false}
                      />
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: 6 }}>
                        <button
                          className="btn btn-sm btn-secondary"
                          onClick={() => sendTestWebhook(ep)}
                          disabled={testingWhId === ep.id}
                        >
                          <Send size={12} />
                          {testingWhId === ep.id ? 'Pinging…' : 'Test Ping'}
                        </button>
                        <button
                          className="btn btn-sm btn-secondary"
                          style={{ color: 'var(--md-sys-color-error)' }}
                          onClick={() => removeWebhook(ep)}
                          title="Delete webhook"
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
        )}

        {whDeliveries.length > 0 && (
          <div style={{ fontSize: '0.78rem', opacity: 0.8 }}>
            <div style={{ fontWeight: 700, marginBottom: 6 }}>Recent Webhook Deliveries</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {whDeliveries.slice(0, 6).map(d => (
                <span
                  key={d.id}
                  className="mono"
                  style={{ padding: '4px 10px', borderRadius: 8, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--md-sys-color-outline-variant)' }}
                >
                  {d.webhook_name} • {d.event_type} •{' '}
                  <strong style={{ color: d.success ? 'var(--success)' : 'var(--danger)' }}>
                    {d.status_code > 0 ? `HTTP ${d.status_code}` : d.error || 'ERR'}
                  </strong>
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Windows 11 Privacy / Debloat, Corporate Branding & Edge Browser Baseline */}
      {experience && (
        <div className="card" style={{ marginBottom: 24, padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16, marginBottom: 18 }}>
            <div>
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Monitor size={18} />
                Windows 11 Privacy / Debloat, Edge Security &amp; Branding CSP
              </div>
              <div style={{ fontSize: '0.82rem', opacity: 0.72, marginTop: 4 }}>
                Agentless <code className="mono">Policy/Config/System</code>, <code className="mono">Privacy</code>, <code className="mono">Dsh</code> (Widgets), inbox <code className="mono">microsoft_edge</code> ADMX baseline, and optional Enterprise wallpaper/lockscreen URLs • Enforced on <strong>{experience.enforced_devices}</strong> device(s)
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.86rem', fontWeight: 600, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={experience.enabled}
                  onChange={e => setExperience({ ...experience, enabled: e.target.checked })}
                />
                Enforce Baseline
              </label>
              <button
                className="btn btn-primary btn-sm"
                disabled={savingExperience}
                onClick={async () => {
                  setSavingExperience(true)
                  try {
                    const saved = await api.experience.updatePolicy({
                      enabled: experience.enabled,
                      telemetry_level: experience.telemetry_level,
                      disable_advertising_id: experience.disable_advertising_id,
                      block_tailored_experiences: experience.block_tailored_experiences,
                      disable_widgets_news: experience.disable_widgets_news,
                      edge_smartscreen_enabled: experience.edge_smartscreen_enabled,
                      edge_prevent_ss_override: experience.edge_prevent_ss_override,
                      edge_smartscreen_pua: experience.edge_smartscreen_pua,
                      edge_block_password_manager: experience.edge_block_password_manager,
                      edge_typosquatting_checker: experience.edge_typosquatting_checker,
                      desktop_wallpaper_url: experience.desktop_wallpaper_url,
                      lockscreen_image_url: experience.lockscreen_image_url,
                      target_all_devices: experience.target_all_devices,
                      group_ids: experience.group_ids,
                    })
                    setExperience(saved)
                    toast.success(`Saved Windows Privacy & Edge policy (${saved.commands_queued ?? 0} OMA-DM command(s) queued).`)
                  } catch (e) {
                    toast.error(e instanceof Error ? e.message : String(e))
                  } finally {
                    setSavingExperience(false)
                  }
                }}
              >
                <Save size={14} />
                {savingExperience ? 'Saving…' : 'Save & Push'}
              </button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ fontSize: '0.78rem', fontWeight: 700, opacity: 0.7 }}>WINDOWS 11 PRIVACY &amp; DEBLOAT</div>
              <label className="form-label" style={{ marginBottom: 0 }}>
                Diagnostic Telemetry Level
                <select
                  className="form-input"
                  style={{ marginTop: 4 }}
                  value={experience.telemetry_level}
                  onChange={e => setExperience({ ...experience, telemetry_level: Number(e.target.value) })}
                >
                  <option value={1}>1 — Required / Basic Only (Pro &amp; Enterprise)</option>
                  <option value={0}>0 — Security Off (Enterprise / Education SKU)</option>
                  <option value={3}>3 — Optional / Full Diagnostic Data</option>
                </select>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.84rem' }}>
                <input
                  type="checkbox"
                  checked={experience.disable_advertising_id}
                  onChange={e => setExperience({ ...experience, disable_advertising_id: e.target.checked })}
                />
                Block Windows Advertising ID (<code className="mono">DisableAdvertisingId</code>)
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.84rem' }}>
                <input
                  type="checkbox"
                  checked={experience.block_tailored_experiences}
                  onChange={e => setExperience({ ...experience, block_tailored_experiences: e.target.checked })}
                />
                Block Tailored Ads &amp; Diagnostic Tips
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.84rem' }}>
                <input
                  type="checkbox"
                  checked={experience.disable_widgets_news}
                  onChange={e => setExperience({ ...experience, disable_widgets_news: e.target.checked })}
                />
                Disable Taskbar Widgets &amp; MSN News Feed (<code className="mono">Dsh</code>)
              </label>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ fontSize: '0.78rem', fontWeight: 700, opacity: 0.7 }}>MICROSOFT EDGE SECURITY BASELINE</div>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.84rem' }}>
                <input
                  type="checkbox"
                  checked={experience.edge_smartscreen_enabled}
                  onChange={e => setExperience({ ...experience, edge_smartscreen_enabled: e.target.checked })}
                />
                Enforce Edge Defender SmartScreen
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.84rem' }}>
                <input
                  type="checkbox"
                  checked={experience.edge_prevent_ss_override}
                  onChange={e => setExperience({ ...experience, edge_prevent_ss_override: e.target.checked })}
                />
                Prevent Phishing / Malware Warning Bypass
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.84rem' }}>
                <input
                  type="checkbox"
                  checked={experience.edge_smartscreen_pua}
                  onChange={e => setExperience({ ...experience, edge_smartscreen_pua: e.target.checked })}
                />
                Block Potentially Unwanted Apps (PUA) in Edge
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.84rem' }}>
                <input
                  type="checkbox"
                  checked={experience.edge_typosquatting_checker}
                  onChange={e => setExperience({ ...experience, edge_typosquatting_checker: e.target.checked })}
                />
                Enable Edge Typosquatting URL Protection
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.84rem' }}>
                <input
                  type="checkbox"
                  checked={experience.edge_block_password_manager}
                  onChange={e => setExperience({ ...experience, edge_block_password_manager: e.target.checked })}
                />
                Disable Built-In Edge Password Manager
              </label>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ fontSize: '0.78rem', fontWeight: 700, opacity: 0.7 }}>CORPORATE BRANDING (ENTERPRISE / EDU OPTIONAL)</div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Desktop Wallpaper URL (optional)</label>
                <input
                  className="form-input mono"
                  placeholder="https://cdn.example.com/wallpaper.jpg"
                  value={experience.desktop_wallpaper_url}
                  onChange={e => setExperience({ ...experience, desktop_wallpaper_url: e.target.value })}
                />
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Lock Screen Image URL (optional)</label>
                <input
                  className="form-input mono"
                  placeholder="https://cdn.example.com/lockscreen.jpg"
                  value={experience.lockscreen_image_url}
                  onChange={e => setExperience({ ...experience, lockscreen_image_url: e.target.value })}
                />
              </div>
            </div>
          </div>
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
