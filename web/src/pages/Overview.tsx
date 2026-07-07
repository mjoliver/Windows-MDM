import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Monitor, Shield, Users, CheckSquare, AlertTriangle, Clock } from 'lucide-react'
import { Layout } from '../components/Layout'
import { Badge } from '../components/Badge'
import { api, type Device, type FleetCompliance } from '../api'
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'
import { timeAgo } from '../format'
import { EmptyState } from '../components/EmptyState'

export function OverviewPage() {
  const [devices, setDevices]           = useState<Device[]>([])
  const [compliance, setCompliance]     = useState<FleetCompliance | null>(null)
  const [_loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    Promise.all([
      api.devices.list(),
      api.compliance.fleet(),
    ]).then(([d, c]) => {
      setDevices(d)
      setCompliance(c)
    }).finally(() => setLoading(false))
  }, [])

  const compliant = compliance?.summary.compliant_devices ?? 0
  const total     = compliance?.summary.total_devices ?? 0
  const pct       = compliance?.summary.compliance_percent ?? 0

  const pieData = [
    { name: 'Compliant',     value: compliance?.summary.compliant_devices     ?? 0, color: '#10b981' },
    { name: 'Non-compliant', value: compliance?.summary.non_compliant_devices  ?? 0, color: '#ef4444' },
    { name: 'Unknown',       value: compliance?.summary.unknown_devices        ?? 0, color: '#475569' },
  ].filter(d => d.value > 0)

  const recentDevices = [...devices]
    .sort((a, b) => new Date(b.enrolled_at).getTime() - new Date(a.enrolled_at).getTime())
    .slice(0, 5)

  return (
    <Layout title="Fleet Overview">
      <div className="fade-in">
        <div className="stat-grid">
          <div className="stat-card">
            <div className="detail-icon" style={{ marginBottom: 16 }}>
              <Monitor size={20} />
            </div>
            <div className="stat-label">Provisioned Fleet</div>
            <div className="stat-value">{devices.length}</div>
          </div>

          <div className="stat-card">
            <div className="detail-icon" style={{ 
              marginBottom: 16, 
              background: 'var(--md-sys-color-primary-container)', 
              color: 'var(--md-sys-color-on-primary-container)' 
            }}>
              <CheckSquare size={20} />
            </div>
            <div className="stat-label">Compliant Nodes</div>
            <div className="stat-value" style={{ color: 'var(--md-sys-color-primary)' }}>{compliant}</div>
          </div>

          <div className="stat-card">
            <div className="detail-icon" style={{ 
              marginBottom: 16, 
              background: 'var(--md-sys-color-error-container)', 
              color: 'var(--md-sys-color-on-error-container)' 
            }}>
              <AlertTriangle size={20} />
            </div>
            <div className="stat-label">Security Violations</div>
            <div className="stat-value" style={{ color: 'var(--md-sys-color-error)' }}>
              {compliance?.summary.non_compliant_devices ?? 0}
            </div>
          </div>

          <div className="stat-card">
            <div className="detail-icon" style={{ marginBottom: 16 }}>
              <Shield size={20} />
            </div>
            <div className="stat-label">Policy Integrity</div>
            <div className="stat-value">{pct}%</div>
            <div className="progress-bar" style={{ marginTop: 16 }}>
              <div className="progress-fill" style={{
                width: `${pct}%`,
                background: pct >= 80 ? 'var(--md-sys-color-primary)' : pct >= 50 ? 'var(--md-sys-color-tertiary)' : 'var(--md-sys-color-error)'
              }} />
            </div>
          </div>
        </div>

        <div className="grid-2 mt-32" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 480px) 1fr', gap: 32 }}>
          {/* Compliance donut */}
          <div className="card">
            <div className="card-title" style={{ marginBottom: 24, padding: '0 8px' }}>Global Health Index</div>
            
            {total === 0 ? (
              <EmptyState
                icon={<Users size={48} style={{ opacity: 0.2 }} />}
                title=""
                description="Awaiting telemetry from enrolled devices…"
                style={{ padding: 60 }}
              />
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: 40, padding: '0 8px' }}>
                <div style={{ position: 'relative', width: 180, height: 180 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%" innerRadius={64} outerRadius={84}
                        dataKey="value" strokeWidth={0} animationDuration={1000} paddingAngle={3}>
                        {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                  <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                    <span style={{ fontSize: '1.8rem', fontWeight: 800 }}>{pct}%</span>
                    <span style={{ fontSize: '0.65rem', fontWeight: 600, opacity: 0.5, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Compliant</span>
                  </div>
                </div>
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 16 }}>
                  {pieData.map(d => (
                    <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <div style={{ width: 10, height: 10, borderRadius: '50%', background: d.color }} />
                      <span style={{ fontSize: '0.85rem', opacity: 0.8, fontWeight: 500 }}>{d.name}</span>
                      <span style={{ fontSize: '1rem', fontWeight: 800, marginLeft: 'auto' }}>{d.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Top failing policies */}
            {(compliance?.top_issues?.length ?? 0) > 0 && (
              <div style={{ marginTop: 40, paddingTop: 32, borderTop: '1px solid var(--md-sys-color-outline-variant)' }}>
                <div className="stat-label" style={{ marginBottom: 20 }}>Priority Compliance Risks</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {compliance!.top_issues.slice(0, 3).map(issue => (
                    <div key={issue.oma_uri} 
                      onClick={() => navigate('/profiles')}
                      style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', background: 'var(--md-sys-color-surface-container-low)', borderRadius: 16 }}>
                      <div style={{ overflow: 'hidden' }}>
                        <div style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--md-sys-color-on-surface)', textOverflow: 'ellipsis', whiteSpace: 'nowrap', overflow: 'hidden' }}>
                          {issue.display_name || issue.oma_uri}
                        </div>
                        <div style={{ fontSize: '0.7rem', opacity: 0.5, marginTop: 2 }}>{issue.oma_uri}</div>
                      </div>
                      <Badge label={`${issue.non_compliant_count} Devices`} status="non_compliant" />
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Recent devices */}
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '24px 32px' }}>
              <div className="card-title" style={{ margin: 0 }}>Fleet Activity</div>
              <button className="btn btn-secondary btn-sm" onClick={() => navigate('/devices')}>
                All Assets
              </button>
            </div>
            
            {recentDevices.length === 0 ? (
              <EmptyState
                icon={<Monitor size={48} style={{ opacity: 0.2 }} />}
                title=""
                description="No recently provisioned devices."
                style={{ padding: 60 }}
              />
            ) : (
              <div className="table-wrap" style={{ border: 'none', borderRadius: 0 }}>
                <table className="table-static">
                  <thead>
                    <tr>
                      <th style={{ paddingLeft: 32 }}>Device Entity</th>
                      <th>Last Heartbeat</th>
                      <th style={{ paddingRight: 32 }}>Security Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentDevices.map(d => (
                      <tr key={d.id} onClick={() => navigate(`/devices/${d.id}`)} style={{ cursor: 'pointer' }}>
                        <td style={{ paddingLeft: 32 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                            <div className="detail-icon" style={{ width: 36, height: 36, borderRadius: 10 }}>
                                <Monitor size={18} />
                            </div>
                            <div>
                                <div style={{ fontWeight: 700, color: 'var(--md-sys-color-on-surface)' }}>{d.device_name || 'Generic Endpoint'}</div>
                                <div style={{ fontSize: '0.75rem', opacity: 0.4 }}>{d.manufacturer} {d.model}</div>
                            </div>
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, opacity: 0.6, fontSize: '0.875rem' }}>
                            <Clock size={14} />
                            {timeAgo(d.last_checkin)}
                          </div>
                        </td>
                        <td style={{ paddingRight: 32 }}>
                          <Badge status={d.compliance_status} label={d.compliance_status === 'compliant' ? 'Verified' : 'Flagged'} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  )
}
