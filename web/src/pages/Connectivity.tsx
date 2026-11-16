import { useEffect, useState } from 'react'
import { Wifi, GlobeLock, FileKey2, ShieldCheck, Plus, Trash2, Download, Copy, ShieldAlert } from 'lucide-react'
import { Layout } from '../components/Layout'
import { Badge } from '../components/Badge'
import { EmptyState } from '../components/EmptyState'
import { Modal } from '../components/Modal'
import { api, type ConnectivityProfile, type Group, type PKISummary, type IssuedCertificateItem } from '../api'
import { useToast } from '../hooks/useToast'

type ProfileKind = 'root_ca' | 'intermediate_ca' | 'client_cert' | 'wifi' | 'vpn'

export function ConnectivityPage() {
  const [profiles, setProfiles] = useState<ConnectivityProfile[]>([])
  const [groups, setGroups] = useState<Group[]>([])
  const [pkiSum, setPkiSum] = useState<PKISummary | null>(null)
  const [issuedCerts, setIssuedCerts] = useState<IssuedCertificateItem[]>([])
  const [loading, setLoading] = useState(true)
  const [openModal, setOpenModal] = useState(false)
  const [saving, setSaving] = useState(false)

  const [kind, setKind] = useState<ProfileKind>('root_ca')
  const [name, setName] = useState('')
  const [certPem, setCertPem] = useState('')
  const [ccTemplate, setCcTemplate] = useState('CN={{device_name}}')
  const [ccValidityDays, setCcValidityDays] = useState(365)
  const [ccExportable, setCcExportable] = useState(false)
  const [ccKeyLocation, setCcKeyLocation] = useState<2 | 3>(3)
  const [ssid, setSsid] = useState('')
  const [wifiSec, setWifiSec] = useState<'WPA2PSK' | 'WPA3SAE' | 'WPA2Enterprise' | 'Open'>('WPA2PSK')
  const [wifiPsk, setWifiPsk] = useState('')
  const [wifiEapServers, setWifiEapServers] = useState('')
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
      api.connectivity.pkiSummary().catch(() => null),
      api.connectivity.listCertificates().catch(() => []),
    ])
      .then(([p, g, sum, certs]) => {
        setProfiles(p)
        setGroups(g)
        setPkiSum(sum)
        setIssuedCerts(certs)
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
    setCcTemplate('CN={{device_name}}')
    setCcValidityDays(365)
    setCcExportable(false)
    setCcKeyLocation(3)
    setSsid('')
    setWifiSec('WPA2PSK')
    setWifiPsk('')
    setWifiEapServers('')
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
        client_cert_subject_template: kind === 'client_cert' ? ccTemplate.trim() : undefined,
        client_cert_validity_days: kind === 'client_cert' ? ccValidityDays : undefined,
        client_cert_exportable: kind === 'client_cert' ? ccExportable : undefined,
        client_cert_key_location: kind === 'client_cert' ? (ccExportable ? 3 : ccKeyLocation) : undefined,
        wifi_ssid: kind === 'wifi' ? ssid.trim() : undefined,
        wifi_security: kind === 'wifi' ? wifiSec : undefined,
        wifi_auto_connect: kind === 'wifi' ? wifiAuto : undefined,
        wifi_hidden: kind === 'wifi' ? wifiHidden : undefined,
        wifi_psk: kind === 'wifi' && wifiSec !== 'Open' && wifiSec !== 'WPA2Enterprise' ? wifiPsk : undefined,
        wifi_eap_server_names: kind === 'wifi' && wifiSec === 'WPA2Enterprise' ? wifiEapServers.trim() : undefined,
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
  const clientCertsCount = profiles.filter(p => p.profile_type === 'client_cert').length
  const wifiCount = profiles.filter(p => p.profile_type === 'wifi').length
  const vpnCount = profiles.filter(p => p.profile_type === 'vpn').length

  return (
    <Layout title="Connectivity & PKI">
      <div className="page-header">
        <div className="page-header-left">
          <h1>Connectivity & PKI</h1>
          <p>Agentless Root/Intermediate CA certs, per-device PKCS#12 client certs (PFXCertInstall), EAP-TLS Wi-Fi &amp; IKEv2 VPNv2</p>
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
          <div className="stat-icon" style={{ background: 'rgba(192,132,252,0.14)' }}>
            <ShieldCheck size={18} color="#c084fc" />
          </div>
          <div className="stat-label">Device Client Certs (PFX)</div>
          <div className="stat-value">{clientCertsCount}</div>
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
            description="Push X.509 Root/Intermediate CA certs, per-device PKCS#12 machine certs, WPA2/WPA3/EAP-TLS Wi-Fi profiles, or Always-On IKEv2 VPN tunnels natively via Windows OMA-DM CSPs."
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
                      status={
                        p.profile_type === 'vpn' || p.profile_type === 'client_cert'
                          ? 'compliant'
                          : p.profile_type === 'wifi'
                            ? 'pending'
                            : 'unknown'
                      }
                      label={
                        p.profile_type === 'root_ca'
                          ? 'Trusted Root CA'
                          : p.profile_type === 'intermediate_ca'
                            ? 'Intermediate CA'
                            : p.profile_type === 'client_cert'
                              ? 'Device PFX Cert'
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
                    {p.profile_type === 'client_cert' && (
                      <div>
                        <div>
                          Subject: <code className="mono">{p.client_cert_subject_template || 'CN={{device_name}}'}</code>
                        </div>
                        <div style={{ fontSize: '0.72rem', opacity: 0.65 }}>
                          Latchz Root CA • {p.client_cert_validity_days ?? 365}d •{' '}
                          {p.client_cert_exportable
                            ? 'Software KSP (Exportable)'
                            : p.client_cert_key_location === 2
                              ? 'TPM / Software KSP (Non-exportable)'
                              : 'Software KSP (Non-exportable)'}
                        </div>
                      </div>
                    )}
                    {p.profile_type === 'wifi' && (
                      <div>
                        SSID: <strong className="mono">{p.wifi_ssid}</strong> •{' '}
                        {p.wifi_security === 'WPA2Enterprise' ? '802.1X EAP-TLS' : p.wifi_security}
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

      {/* Internal Root CA, RFC 5280 CRL & RFC 6960 OCSP Responder */}
      {pkiSum && (
        <div className="card" style={{ marginTop: 28, padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16, marginBottom: 20 }}>
            <div>
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <ShieldCheck size={18} />
                Internal Certificate Authority, CRL &amp; OCSP Responder
              </div>
              <div style={{ fontSize: '0.82rem', opacity: 0.72, marginTop: 4 }}>
                <strong>{pkiSum.ca_subject}</strong> • SHA-1 <code className="mono">{pkiSum.ca_thumbprint_sha1}</code> • Valid through{' '}
                {new Date(pkiSum.ca_not_after).toLocaleDateString()}
              </div>
              <div style={{ fontSize: '0.76rem', opacity: 0.62, marginTop: 4 }}>
                Active: <strong>{pkiSum.active_certs}</strong> • Expiring (&le;30d): <strong>{pkiSum.expiring_30d}</strong> • Revoked: <strong>{pkiSum.revoked_certs}</strong> • CRL Sequence #{pkiSum.crl_sequence_number}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <a className="btn btn-sm btn-secondary" href="/pki/ca.pem" download="latchz-root-ca.pem">
                <Download size={13} /> Root CA (.pem)
              </a>
              <a className="btn btn-sm btn-secondary" href="/pki/crl.der" download="latchz-ca.crl">
                <Download size={13} /> CRL (.der)
              </a>
              <a className="btn btn-sm btn-secondary" href="/pki/crl.pem" download="latchz-ca-crl.pem">
                <Download size={13} /> CRL (.pem)
              </a>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => {
                  navigator.clipboard?.writeText(pkiSum.ocsp_url)
                  toast.success(`Copied OCSP Responder URL (${pkiSum.ocsp_url}).`)
                }}
              >
                <Copy size={13} /> Copy OCSP URL
              </button>
            </div>
          </div>

          {issuedCerts.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Subject / Device</th>
                    <th>Kind</th>
                    <th>Thumbprint / Serial</th>
                    <th>Validity</th>
                    <th>Status</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {issuedCerts.map(c => (
                    <tr key={c.id}>
                      <td>
                        <div style={{ fontWeight: 700, fontSize: '0.84rem' }}>{c.device_name || c.subject}</div>
                        <div className="mono" style={{ fontSize: '0.71rem', opacity: 0.6 }}>{c.subject}</div>
                      </td>
                      <td>
                        <Badge
                          status={c.cert_type === 'client_pfx' ? 'compliant' : 'unknown'}
                          label={c.cert_type === 'client_pfx' ? '802.1X / VPN PFX' : 'OMA-DM mTLS'}
                          dot={false}
                        />
                      </td>
                      <td className="mono" style={{ fontSize: '0.73rem' }}>
                        <div>{c.thumbprint.slice(0, 20)}…</div>
                        <div style={{ opacity: 0.55 }}>SN {c.serial_number.slice(0, 14)}…</div>
                      </td>
                      <td style={{ fontSize: '0.8rem' }}>
                        {new Date(c.not_after).toLocaleDateString()} ({c.days_remaining}d)
                      </td>
                      <td>
                        {c.revoked ? (
                          <Badge status="non_compliant" label={`Revoked (${c.revocation_reason_label})`} />
                        ) : c.days_remaining <= 30 ? (
                          <Badge status="pending" label="Expiring Soon" />
                        ) : (
                          <Badge status="compliant" label="Good (OCSP)" />
                        )}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        {!c.revoked && (
                          <button
                            type="button"
                            className="btn btn-sm btn-secondary"
                            style={{ color: 'var(--md-sys-color-error)' }}
                            title="Revoke certificate (published immediately on /pki/crl.der & /pki/ocsp)"
                            onClick={async () => {
                              try {
                                await api.connectivity.revokeCertificate(c.id, 1)
                                toast.success(`Revoked certificate ${c.thumbprint.slice(0, 12)}… (reason: Key Compromise).`)
                                load()
                              } catch (e) {
                                toast.error(e instanceof Error ? e.message : String(e))
                              }
                            }}
                          >
                            <ShieldAlert size={13} /> Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {openModal && (
        <Modal open={openModal} title="Create Connectivity / PKI Profile" onClose={() => setOpenModal(false)}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
            {([
              { id: 'root_ca', label: 'Root CA Cert' },
              { id: 'intermediate_ca', label: 'Intermediate CA' },
              { id: 'client_cert', label: 'Device Client Cert (PFX)' },
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
              placeholder={
                kind === 'vpn'
                  ? 'Corp-IKEv2-VPN'
                  : kind === 'wifi'
                    ? 'Corp HQ Wi-Fi'
                    : kind === 'client_cert'
                      ? '802.1X Machine Identity Cert'
                      : 'Internal Enterprise Root CA'
              }
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

          {kind === 'client_cert' && (
            <>
              <div style={{ fontSize: '0.8rem', opacity: 0.78, marginBottom: 12, lineHeight: 1.5 }}>
                Mints a unique RSA-2048 X.509 client authentication certificate per device signed by the Latchz Root CA, seals the PKCS#12 archive in the AES-256-GCM vault, and installs into <code className="mono">Cert:\LocalMachine\My</code> via <code className="mono">&lt;Atomic&gt; PFXCertInstall</code>.
              </div>
              <div className="grid-2" style={{ gap: 12 }}>
                <div className="form-group">
                  <label className="form-label">Subject Template</label>
                  <input
                    className="form-input mono"
                    value={ccTemplate}
                    onChange={e => setCcTemplate(e.target.value)}
                    placeholder="CN={{device_name}}"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Validity (Days)</label>
                  <input
                    type="number"
                    min={1}
                    max={3650}
                    className="form-input mono"
                    value={ccValidityDays}
                    onChange={e => setCcValidityDays(Number(e.target.value) || 365)}
                  />
                </div>
              </div>
              <div className="form-group">
                <label className="form-label">Private Key Storage Provider</label>
                <select
                  className="form-input"
                  value={ccExportable ? 3 : ccKeyLocation}
                  disabled={ccExportable}
                  onChange={e => setCcKeyLocation(Number(e.target.value) === 2 ? 2 : 3)}
                >
                  <option value={3}>Software KSP (Microsoft Software Key Storage Provider)</option>
                  <option value={2}>TPM KSP if present, fallback to Software KSP</option>
                </select>
              </div>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.84rem', marginBottom: 14 }}>
                <input type="checkbox" checked={ccExportable} onChange={e => setCcExportable(e.target.checked)} />
                Mark private key exportable (forces Software KSP per Microsoft CSP specification)
              </label>
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
                  <select
                    className="form-input"
                    value={wifiSec}
                    onChange={e => setWifiSec(e.target.value as 'WPA2PSK' | 'WPA3SAE' | 'WPA2Enterprise' | 'Open')}
                  >
                    <option value="WPA2PSK">WPA2-Personal (AES)</option>
                    <option value="WPA3SAE">WPA3-Personal (SAE)</option>
                    <option value="WPA2Enterprise">WPA2-Enterprise (802.1X EAP-TLS)</option>
                    <option value="Open">Open Network</option>
                  </select>
                </div>
              </div>
              {wifiSec === 'WPA2Enterprise' && (
                <div className="form-group">
                  <label className="form-label">Trusted RADIUS Server FQDN(s) (Optional, semicolon-separated)</label>
                  <input
                    className="form-input mono"
                    placeholder="radius1.corp.example.com;radius2.corp.example.com"
                    value={wifiEapServers}
                    onChange={e => setWifiEapServers(e.target.value)}
                  />
                </div>
              )}
              {wifiSec !== 'Open' && wifiSec !== 'WPA2Enterprise' && (
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
