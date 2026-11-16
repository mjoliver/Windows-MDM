import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Monitor, RefreshCw, Download, KeyRound, Plus, Copy, Trash2 } from 'lucide-react'
import { Layout } from '../components/Layout'
import { Badge } from '../components/Badge'
import { Modal } from '../components/Modal'
import { api, type Device, type BulkEnrollmentTokenItem, type Group } from '../api'
import { timeAgo } from '../format'
import { EmptyState } from '../components/EmptyState'
import { SearchBar } from '../components/SearchBar'
import { useToast } from '../hooks/useToast'

export function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([])
  const [search, setSearch]   = useState('')
  const [loading, setLoading] = useState(true)
  const [tokensOpen, setTokensOpen] = useState(false)
  const [tokens, setTokens]   = useState<BulkEnrollmentTokenItem[]>([])
  const [groups, setGroups]   = useState<Group[]>([])
  const [tokName, setTokName] = useState('')
  const [tokGroup, setTokGroup] = useState('')
  const [tokMaxUses, setTokMaxUses] = useState(25)
  const [tokExpDays, setTokExpDays] = useState(30)
  const [creatingTok, setCreatingTok] = useState(false)
  const [mintedSecret, setMintedSecret] = useState<string | null>(null)
  const navigate = useNavigate()
  const toast = useToast()

  const load = () => {
    setLoading(true)
    api.devices.list().then(setDevices).finally(() => setLoading(false))
  }

  const openTokensModal = () => {
    setTokensOpen(true)
    setMintedSecret(null)
    Promise.all([
      api.enrollmentTokens.list().catch(() => []),
      api.groups.list().catch(() => []),
    ]).then(([t, g]) => {
      setTokens(t)
      setGroups(g)
    })
  }

  const mintToken = async () => {
    if (!tokName.trim()) {
      toast.error('Enter a token label first (e.g. Warehouse OOBE Staging).')
      return
    }
    setCreatingTok(true)
    try {
      const created = await api.enrollmentTokens.create({
        name: tokName.trim(),
        auto_group_id: tokGroup,
        max_uses: tokMaxUses,
        expires_in_days: tokExpDays,
      })
      setMintedSecret(created.token ?? null)
      setTokens(prev => [created, ...prev])
      setTokName('')
      toast.success(`Minted Bulk Enrollment Token '${created.name}' (${created.token_prefix}…).`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setCreatingTok(false)
    }
  }

  const revokeOrDeleteToken = async (item: BulkEnrollmentTokenItem) => {
    try {
      const res = await api.enrollmentTokens.revoke(item.id, item.revoked)
      if (res.deleted) {
        setTokens(prev => prev.filter(x => x.id !== item.id))
        toast.success(`Deleted enrollment token '${item.name}'.`)
      } else {
        setTokens(prev => prev.map(x => (x.id === item.id ? { ...x, revoked: true } : x)))
        toast.success(`Revoked enrollment token '${item.name}'.`)
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    }
  }

  useEffect(load, [])

  const filtered = devices.filter(d =>
    !search ||
    d.device_name.toLowerCase().includes(search.toLowerCase()) ||
    d.os_version.toLowerCase().includes(search.toLowerCase()) ||
    d.manufacturer.toLowerCase().includes(search.toLowerCase()) ||
    d.hardware_id.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <Layout title="Devices">
      <div className="page-header">
        <div className="page-header-left">
          <h1>Devices</h1>
          <p>{devices.length} enrolled device{devices.length !== 1 ? 's' : ''}</p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button className="btn btn-primary" onClick={openTokensModal}>
            <KeyRound size={14} />
            Enroll / Bulk Tokens
          </button>
          <a className="btn btn-secondary" href="/api/export/devices?format=csv" download>
            <Download size={14} />
            Export CSV
          </a>
          <a className="btn btn-secondary" href="/api/export/devices?format=json" download>
            <Download size={14} />
            Export JSON
          </a>
          <button className="btn btn-secondary" onClick={load} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      <div className="table-wrap">
        <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--md-sys-color-outline-variant)' }}>
          <SearchBar
            value={search}
            onChange={setSearch}
            placeholder="Search fleet..."
            style={{ maxWidth: 320 }}
          />
        </div>

        {filtered.length === 0 ? (
          <EmptyState
            icon={<Monitor size={48} style={{ opacity: 0.3 }} />}
            title={search ? 'No results found' : 'No devices enrolled'}
            description={search ? 'Try a more general search term' : 'Waiting for devices to join the fleet'}
          />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>OS Version</th>
                <th>Manufacturer</th>
                <th>Last Seen</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(d => (
                <tr key={d.id} onClick={() => navigate(`/devices/${d.id}`)} style={{ cursor: 'pointer' }}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                      <div className="detail-icon">
                        <Monitor size={18} />
                      </div>
                      <div>
                        <div style={{ fontWeight: 700, color: 'var(--md-sys-color-on-surface)' }}>{d.device_name || 'Generic Device'}</div>
                        <div style={{ fontSize: '0.8rem', opacity: 0.5 }}>
                          {d.hardware_id.slice(0, 12)}…
                        </div>
                      </div>
                    </div>
                  </td>
                  <td>{d.os_version || '—'}</td>
                  <td>{d.manufacturer || '—'}</td>
                  <td style={{ opacity: 0.6 }}>{timeAgo(d.last_checkin)}</td>
                  <td><Badge status={d.compliance_status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <Modal
        open={tokensOpen}
        onClose={() => setTokensOpen(false)}
        title="Bulk Enrollment Tokens & OOBE Staging Bootstrap"
        maxWidth={780}
      >
        <div style={{ fontSize: '0.84rem', opacity: 0.75, marginBottom: 16 }}>
          Mint multi-use, time-bounded <code className="mono">lzbt_…</code> tokens for Windows 10/11 OOBE (<code className="mono">Shift+F10</code>) or technician staging without sharing administrator passwords. Devices enrolled with a group-bound token automatically join that group and receive its policies and MSI apps on first check-in.
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1.2fr 105px 115px auto', gap: 10, alignItems: 'end', marginBottom: 16 }}>
          <div>
            <label className="form-label">Token Label</label>
            <input
              className="form-input"
              placeholder="e.g. NYC Lab OOBE"
              value={tokName}
              onChange={e => setTokName(e.target.value)}
            />
          </div>
          <div>
            <label className="form-label">Auto-Join Group</label>
            <select className="form-input" value={tokGroup} onChange={e => setTokGroup(e.target.value)}>
              <option value="">None (Fleet Defaults Only)</option>
              {groups.filter(g => !g.is_dynamic).map(g => (
                <option key={g.id} value={g.id}>{g.name}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="form-label">Max Uses</label>
            <input
              type="number"
              className="form-input"
              min={0}
              max={100000}
              value={tokMaxUses}
              onChange={e => setTokMaxUses(Number(e.target.value))}
              title="0 = Unlimited uses"
            />
          </div>
          <div>
            <label className="form-label">Expires (Days)</label>
            <input
              type="number"
              className="form-input"
              min={0}
              max={3650}
              value={tokExpDays}
              onChange={e => setTokExpDays(Number(e.target.value))}
            />
          </div>
          <button className="btn btn-primary" onClick={mintToken} disabled={creatingTok}>
            <Plus size={14} />
            {creatingTok ? 'Minting…' : 'Mint Token'}
          </button>
        </div>

        {mintedSecret && (
          <div style={{ padding: '14px 16px', borderRadius: 12, background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.4)', marginBottom: 16 }}>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, marginBottom: 6, color: 'var(--success)' }}>
              One-Time Bulk Enrollment Token (copy now — only SHA-256 hash is stored):
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <code className="mono" style={{ flex: 1, padding: '8px 10px', borderRadius: 8, background: 'rgba(0,0,0,0.35)', fontSize: '0.82rem', wordBreak: 'break-all' }}>
                {mintedSecret}
              </code>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => {
                  void navigator.clipboard.writeText(mintedSecret)
                  toast.success('Copied Bulk Enrollment Token to clipboard.')
                }}
              >
                <Copy size={13} />
                Copy
              </button>
            </div>
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, padding: '10px 14px', borderRadius: 10, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--md-sys-color-outline-variant)' }}>
          <div style={{ fontSize: '0.8rem' }}>
            <strong>PowerShell OOBE Staging Script</strong> — trusts Latchz Root CA &amp; launches MDM enrollment
          </div>
          <a className="btn btn-secondary btn-sm" href="/api/enrollment/bootstrap.ps1" download>
            <Download size={13} />
            Download bootstrap.ps1
          </a>
        </div>

        {tokens.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Label / Prefix</th>
                  <th>Auto-Join Group</th>
                  <th>Uses</th>
                  <th>Status</th>
                  <th style={{ textAlign: 'right' }}></th>
                </tr>
              </thead>
              <tbody>
                {tokens.map(t => (
                  <tr key={t.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{t.name}</div>
                      <div className="mono" style={{ fontSize: '0.72rem', opacity: 0.6 }}>{t.token_prefix}…</div>
                    </td>
                    <td>{t.auto_group_name || <span style={{ opacity: 0.45 }}>—</span>}</td>
                    <td className="mono" style={{ fontSize: '0.8rem' }}>
                      {t.use_count} / {t.max_uses === 0 ? '∞' : t.max_uses}
                    </td>
                    <td>
                      <Badge
                        status={t.revoked ? 'non_compliant' : 'compliant'}
                        label={t.revoked ? 'Revoked' : 'Active'}
                        dot={false}
                      />
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn btn-sm btn-secondary"
                        style={{ color: 'var(--md-sys-color-error)' }}
                        onClick={() => revokeOrDeleteToken(t)}
                        title={t.revoked ? 'Delete revoked token' : 'Revoke token'}
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
      </Modal>
    </Layout>
  )
}
