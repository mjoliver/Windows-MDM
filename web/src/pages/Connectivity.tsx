import { useEffect, useState } from 'react'
import { Wifi, GlobeLock, FileKey2, Plus, Trash2 } from 'lucide-react'
import { Layout } from '../components/Layout'
import { Badge } from '../components/Badge'
import { EmptyState } from '../components/EmptyState'
import { Modal } from '../components/Modal'
import { api, type ConnectivityProfile, type Group } from '../api'
import { useToast } from '../hooks/useToast'

type ProfileKind = 'root_ca' | 'intermediate_ca' | 'wifi' | 'vpn'

export function ConnectivityPage() {
  const [profiles, setProfiles] = useState<ConnectivityProfile[]>([])
  const [groups, setGroups] = useState<Group[]>([])
  const [loading, setLoading] = useState(true)
  const [openModal, setOpenModal] = useState(false)
  const [saving, setSaving] = useState(false)

  const [kind, setKind] = useState<ProfileKind>('root_ca')
  const [name, setName] = useState('')
  const [certPem, setCertPem] = useState('')
  const [ssid, setSsid] = useState('')
  const [wifiSec, setWifiSec] = useState<'WPA2PSK' | 'WPA3SAE' | 'Open'>('WPA2PSK')
  const [wifiPsk, setWifiPsk] = useState('')
  const [wifiAuto, setWifiAuto] = useState(true)
  const [wifiHidden, setWifiHidden] = useState(false)
  const [vpnServer, setVpnServer] = useState('')
  const [vpnProto, setVpnProto] = useState<'IKEv2' | 'Automatic' | 'L2TP' | 'SSTP'>('IKEv2')
  const [vpnAuth, setVpnAuth] = useState<'Eap' | 'Certificate'>('Eap')
  const [vpnSplit, setVpnSplit] = useState(true)
  const [vpnAlwaysOn, setVpnAlwaysOn] = useState(false)
  const [targetAll, setTargetAll] = useState(true)
  const [groupIds, setGroupIds] = useState<string[]>([])

  const toast = useToast()

  const load = () => {
    setLoading(true)
    Promise.all([
      api.connectivity.listProfiles(),
      api.groups.list().catch(() => []),
    ])
      .then(([p, g]) => {
        setProfiles(p)
        setGroups(g)
      })
      .catch(e => toast.error(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const resetForm = () => {
    setName('')
    setCertPem('')
    setSsid('')
    setWifiSec('WPA2PSK')
    setWifiPsk('')
    setWifiAuto(true)
    setWifiHidden(false)
    setVpnServer('')
    setVpnProto('IKEv2')
    setVpnAuth('Eap')
    setVpnSplit(true)
    setVpnAlwaysOn(false)
    setTargetAll(true)
    setGroupIds([])
  }

  const handleCertFileUpload = async (file: File) => {
    const buf = await file.arrayBuffer()
    const bytes = new Uint8Array(buf)
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
    if (text.includes('-----BEGIN')) {
      setCertPem(text.trim())
    } else {
      let binary = ''
      for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i])
      }
      setCertPem(btoa(binary))
    }
    if (!name.trim()) {
      setName(file.name.replace(/\.(cer|crt|pem|der)$/i, ''))
    }
  }

  const submitCreate = async () => {
    if (!name.trim()) {
      toast.error('Profile name is required.')
      return
    }
    setSaving(true)
    try {
      const created = await api.connectivity.createProfile({
        name: name.trim(),
        profile_type: kind,
        certificate_pem: kind === 'root_ca' || kind === 'intermediate_ca' ? certPem : undefined,
        wifi_ssid: kind === 'wifi' ? ssid.trim() : undefined,
        wifi_security: kind === 'wifi' ? wifiSec : undefined,
        wifi_auto_connect: kind === 'wifi' ? wifiAuto : undefined,
        wifi_hidden: kind === 'wifi' ? wifiHidden : undefined,
        wifi_psk: kind === 'wifi' && wifiSec !== 'Open' ? wifiPsk : undefined,
        vpn_server: kind === 'vpn' ? vpnServer.trim() : undefined,
        vpn_protocol: kind === 'vpn' ? vpnProto : undefined,
        vpn_auth_method: kind === 'vpn' ? vpnAuth : undefined,
        vpn_split_tunnel: kind === 'vpn' ? vpnSplit : undefined,
        vpn_always_on: kind === 'vpn' ? vpnAlwaysOn : undefined,
        target_all_devices: targetAll,
        group_ids: targetAll ? [] : groupIds,
      })
      setProfiles(prev => [created, ...prev])
      setOpenModal(false)
      resetForm()
      toast.success(`Provisioned '${created.name}' (${created.commands_queued ?? 0} OMA-DM command(s) queued).`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  const removeProfile = async (p: ConnectivityProfile) => {
    try {
      const res = await api.connectivity.deleteProfile(p.id)
      setProfiles(prev => prev.filter(x => x.id !== p.id))
      toast.success(`Removed '${p.name}' (${res.commands_queued} <Delete> command(s) queued).`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    }
  }

  const certsCount = profiles.filter(p => p.profile_type === 'root_ca' || p.profile_type === 'intermediate_ca').length
  const wifiCount = profiles.filter(p => p.profile_type === 'wifi').length
  const vpnCount = profiles.filter(p => p.profile_type === 'vpn').length

  return (
    <Layout title="Connectivity & PKI">
      <div className="page-header">
        <div className="page-header-left">
          <h1>Connectivity & PKI</h1>
          <p>Agentless Root/Intermediate CA certificates, WPA2/WPA3 Wi-Fi &amp; IKEv2 VPNv2 CSP provisioning</p>
        </div>
        <button className="btn btn-primary" onClick={() => setOpenModal(true)}>
          <Plus size={16} />
          New Profile
        </button>
      </div>

      <div className="stat-grid" style={{ marginBottom: 24 }}>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(129,140,248,0.12)' }}>
            <FileKey2 size={18} color="var(--accent)" />
          </div>
          <div className="stat-label">Trusted CA Certificates</div>
          <div className="stat-value">{certsCount}</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'var(--success-dim)' }}>
            <Wifi size={18} color="var(--success)" />
          </div>
          <div className="stat-label">Wi-Fi Profiles</div>
          <div className="stat-value">{wifiCount}</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(56,189,248,0.14)' }}>
            <GlobeLock size={18} color="#38bdf8" />
          </div>
          <div className="stat-label">VPNv2 Tunnels</div>
          <div className="stat-value">{vpnCount}</div>
        </div>
      </div>

      <div className="table-wrap">
        {!loading && profiles.length === 0 ? (
          <EmptyState
            icon={<GlobeLock size={38} />}
            title="No connectivity or PKI profiles yet"
            description="Push X.509 Root/Intermediate CA certificates, vault-encrypted Wi-Fi profiles, or Always-On IKEv2 VPN tunnels natively via Windows OMA-DM CSPs."
          />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Profile</th>
                <th>Type</th>
                <th>Configuration Summary</th>
                <th>Scope</th>
                <th>Deployed</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {profiles.map(p => (
                <tr key={p.id}>
                  <td>
                    <div style={{ fontWeight: 700 }}>{p.name}</div>
                    <div style={{ fontSize: '0.72rem', opacity: 0.55 }}>Created by {p.created_by || 'admin'}</div>
                  </td>
                  <td>
                    <Badge
                      status={p.profile_type === 'vpn' ? 'compliant' : p.profile_type === 'wifi' ? 'pending' : 'unknown'}
                      label={
                        p.profile_type === 'root_ca'
                          ? 'Trusted Root CA'
                          : p.profile_type === 'intermediate_ca'
                            ? 'Intermediate CA'
                            : p.profile_type === 'wifi'
                              ? 'Wi-Fi (WlanXml)'
                              : 'VPNv2 (Atomic)'
                      }
                      dot={false}
                    />
                  </td>
                  <td style={{ fontSize: '0.82rem' }}>
                    {(p.profile_type === 'root_ca' || p.profile_type === 'intermediate_ca') && (
                      <div>
                        <div style={{ fontWeight: 600 }}>{p.cert_subject}</div>
                        <div className="mono" style={{ fontSize: '0.72rem', opacity: 0.65 }}>
                          SHA-1: {p.cert_thumbprint}
                        </div>
                      </div>
                    )}
                    {p.profile_type === 'wifi' && (
                      <div>
                        SSID: <strong className="mono">{p.wifi_ssid}</strong> • {p.wifi_security}
                        {p.has_wifi_psk ? ' (AES-256-GCM Vault PSK)' : ''}
                      </div>
                    )}
                    {p.profile_type === 'vpn' && (
                      <div>
                        Server: <strong className="mono">{p.vpn_server}</strong> • {p.vpn_protocol} ({p.vpn_auth_method})
                        {p.vpn_split_tunnel ? ' • Split Tunnel' : ' • Force Tunnel'}
                      </div>
                    )}
                  </td>
                  <td>{p.target_all_devices ? 'All Devices' : `${p.group_ids.length} group(s)`}</td>
                  <td>{p.deployed_devices} PC{p.deployed_devices !== 1 ? 's' : ''}</td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className="btn btn-sm btn-secondary"
                      style={{ color: 'var(--md-sys-color-error)' }}
                      onClick={() => removeProfile(p)}
                      title="Delete profile and retract from devices"
                    >
                      <Trash2 size={13} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {openModal && (
        <Modal open={openModal} title="Create Connectivity / PKI Profile" onClose={() => setOpenModal(false)}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
            {([
              { id: 'root_ca', label: 'Root CA Cert' },
              { id: 'intermediate_ca', label: 'Intermediate CA' },
              { id: 'wifi', label: 'Wi-Fi Profile' },
              { id: 'vpn', label: 'VPNv2 Profile' },
            ] as const).map(tab => (
              <button
                key={tab.id}
                type="button"
                className={`btn btn-sm ${kind === tab.id ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setKind(tab.id)}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="form-group">
            <label className="form-label">Profile Display Name</label>
            <input
              className="form-input"
              placeholder={kind === 'vpn' ? 'Corp-IKEv2-VPN' : kind === 'wifi' ? 'Corp HQ Wi-Fi' : 'Internal Enterprise Root CA'}
              value={name}
              onChange={e => setName(e.target.value)}
            />
          </div>

          {(kind === 'root_ca' || kind === 'intermediate_ca') && (
            <>
              <div className="form-group">
                <label className="form-label">Upload .cer / .crt / .pem (Optional)</label>
                <input
                  type="file"
                  accept=".cer,.crt,.pem,.der"
                  className="form-input"
                  onChange={e => {
                    const f = e.target.files?.[0]
                    if (f) void handleCertFileUpload(f)
                  }}
                />
              </div>
              <div className="form-group">
                <label className="form-label">X.509 Certificate (PEM or Base64 DER)</label>
                <textarea
                  className="form-input mono"
                  rows={5}
                  placeholder="-----BEGIN CERTIFICATE-----..."
                  value={certPem}
                  onChange={e => setCertPem(e.target.value)}
                />
              </div>
            </>
          )}

          {kind === 'wifi' && (
            <>
              <div className="grid-2" style={{ gap: 12 }}>
                <div className="form-group">
                  <label className="form-label">SSID</label>
                  <input className="form-input mono" value={ssid} onChange={e => setSsid(e.target.value)} placeholder="Corp-5GHz" />
                </div>
                <div className="form-group">
                  <label className="form-label">Security</label>
                  <select className="form-input" value={wifiSec} onChange={e => setWifiSec(e.target.value as 'WPA2PSK' | 'WPA3SAE' | 'Open')}>
                    <option value="WPA2PSK">WPA2-Personal (AES)</option>
                    <option value="WPA3SAE">WPA3-Personal (SAE)</option>
                    <option value="Open">Open Network</option>
                  </select>
                </div>
              </div>
              {wifiSec !== 'Open' && (
                <div className="form-group">
                  <label className="form-label">Passphrase (Encrypted in AES-256-GCM Vault)</label>
                  <input
                    type="password"
                    className="form-input mono"
                    placeholder="8–63 character WPA passphrase"
                    value={wifiPsk}
                    onChange={e => setWifiPsk(e.target.value)}
                  />
                </div>
              )}
              <div style={{ display: 'flex', gap: 18, marginBottom: 14 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.84rem' }}>
                  <input type="checkbox" checked={wifiAuto} onChange={e => setWifiAuto(e.target.checked)} />
                  Connect automatically
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.84rem' }}>
                  <input type="checkbox" checked={wifiHidden} onChange={e => setWifiHidden(e.target.checked)} />
                  Hidden SSID
                </label>
              </div>
            </>
          )}

          {kind === 'vpn' && (
            <>
              <div className="form-group">
                <label className="form-label">VPN Server FQDN or IP</label>
                <input className="form-input mono" placeholder="vpn.corp.example.com" value={vpnServer} onChange={e => setVpnServer(e.target.value)} />
              </div>
              <div className="grid-2" style={{ gap: 12 }}>
                <div className="form-group">
                  <label className="form-label">Tunnel Protocol</label>
                  <select className="form-input" value={vpnProto} onChange={e => setVpnProto(e.target.value as 'IKEv2' | 'Automatic' | 'L2TP' | 'SSTP')}>
                    <option value="IKEv2">IKEv2 (Recommended)</option>
                    <option value="Automatic">Automatic</option>
                    <option value="SSTP">SSTP</option>
                    <option value="L2TP">L2TP</option>
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Authentication</label>
                  <select className="form-input" value={vpnAuth} onChange={e => setVpnAuth(e.target.value as 'Eap' | 'Certificate')}>
                    <option value="Eap">EAP-MSCHAPv2 (User)</option>
                    <option value="Certificate">Machine Certificate</option>
                  </select>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 18, marginBottom: 14 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.84rem' }}>
                  <input type="checkbox" checked={vpnSplit} onChange={e => setVpnSplit(e.target.checked)} />
                  Split Tunneling
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.84rem' }}>
                  <input type="checkbox" checked={vpnAlwaysOn} onChange={e => setVpnAlwaysOn(e.target.checked)} />
                  Always-On VPN
                </label>
              </div>
            </>
          )}

          <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.84rem', marginBottom: 14 }}>
            <input type="checkbox" checked={targetAll} onChange={e => setTargetAll(e.target.checked)} />
            Deploy to all active Windows devices
          </label>

          {!targetAll && groups.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 16 }}>
              {groups.map(g => {
                const sel = groupIds.includes(g.id)
                return (
                  <button
                    key={g.id}
                    type="button"
                    className={`btn btn-sm ${sel ? 'btn-primary' : 'btn-secondary'}`}
                    onClick={() => setGroupIds(sel ? groupIds.filter(x => x !== g.id) : [...groupIds, g.id])}
                  >
                    {g.name}
                  </button>
                )
              })}
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 18 }}>
            <button className="btn btn-secondary" onClick={() => setOpenModal(false)}>Cancel</button>
            <button className="btn btn-primary" onClick={submitCreate} disabled={saving}>
              {saving ? 'Deploying…' : 'Create & Deploy'}
            </button>
          </div>
        </Modal>
      )}
    </Layout>
  )
}
