import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Monitor, Search, RefreshCw } from 'lucide-react'
import { Layout } from '../components/Layout'
import { Badge } from '../components/Badge'
import { api, type Device } from '../api'

function timeAgo(iso: string | null) {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1)  return 'Just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([])
  const [search, setSearch]   = useState('')
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  const load = () => {
    setLoading(true)
    api.devices.list().then(setDevices).finally(() => setLoading(false))
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
        <button className="btn btn-secondary" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          Refresh
        </button>
      </div>

      <div className="table-wrap">
        {/* Search bar */}
        <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--md-sys-color-outline-variant)' }}>
          <div className="input-wrap" style={{ maxWidth: 320 }}>
            <Search size={14} className="input-icon" />
            <input
              className="input input-has-icon"
              placeholder="Search fleet..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="empty-state">
            <Monitor size={48} style={{ opacity: 0.3 }} />
            <h3>{search ? 'No results found' : 'No devices enrolled'}</h3>
            <p>{search ? 'Try a more general search term' : 'Waiting for Windows devices to join the fleet'}</p>
          </div>
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
                  <td><Badge status={d.compliance_status} label={d.compliance_status === 'compliant' ? 'Healthy' : 'Warning'} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Layout>
  )
}
