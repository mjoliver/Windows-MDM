import { useEffect, useState } from 'react'
import { CheckSquare, AlertTriangle, HelpCircle, Monitor } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Layout } from '../components/Layout'
import { Badge } from '../components/Badge'
import { api, type FleetCompliance, type Device } from '../api'
import { EmptyState } from '../components/EmptyState'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'

export function CompliancePage() {
  const [fleet, setFleet]       = useState<FleetCompliance | null>(null)
  const [devices, setDevices]   = useState<Device[]>([])
  const [_loading, setLoading]   = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    Promise.all([
      api.compliance.fleet(),
      api.devices.list(),
    ]).then(([f, d]) => { setFleet(f); setDevices(d) }).finally(() => setLoading(false))
  }, [])

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
          <div className="card-header">
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

      {/* Per-device table */}
      <div className="table-wrap">
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
          Device Compliance
        </div>
         {devices.length === 0 ? (
            <EmptyState icon={<Monitor size={36} />} title="No devices enrolled" description="" />
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
