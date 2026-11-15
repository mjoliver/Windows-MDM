import { useCallback, useEffect, useState } from 'react'
import { ScrollText, RefreshCw, ChevronLeft, ChevronRight } from 'lucide-react'
import { Layout } from '../components/Layout'
import { SearchBar } from '../components/SearchBar'
import { EmptyState } from '../components/EmptyState'
import { api, type AuditEntry } from '../api'
import { timeAgo } from '../format'
import { useToast } from '../hooks/useToast'

const PAGE_SIZE = 50
const TARGET_FILTERS = [
  { value: '', label: 'All Events' },
  { value: 'device', label: 'Devices' },
  { value: 'profile', label: 'Profiles' },
  { value: 'group', label: 'Groups' },
  { value: 'user', label: 'Users' },
]

function actionBadgeClass(action: string): string {
  if (action.endsWith('.wipe') || action.endsWith('.delete') || action.endsWith('.unenroll')) {
    return 'badge badge-danger'
  }
  if (action.endsWith('.create') || action.endsWith('.enroll')) {
    return 'badge badge-success'
  }
  if (action.endsWith('.reboot') || action.endsWith('.lock') || action.endsWith('.update')) {
    return 'badge badge-warning'
  }
  return 'badge badge-neutral'
}

function formatDetails(raw: string): string {
  if (!raw) return '—'
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>
    const parts = Object.entries(parsed).map(([k, v]) => `${k}: ${String(v)}`)
    return parts.length > 0 ? parts.join(' · ') : raw
  } catch {
    return raw
  }
}

export function AuditLogPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [total, setTotal] = useState(0)
  const [search, setSearch] = useState('')
  const [targetType, setTargetType] = useState('')
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const toast = useToast()

  const load = useCallback(() => {
    setLoading(true)
    api.audit
      .list({
        search: search.trim() || undefined,
        target_type: targetType || undefined,
        limit: PAGE_SIZE,
        offset,
      })
      .then(page => {
        setEntries(page.entries)
        setTotal(page.total)
      })
      .catch(e => toast.error(e instanceof Error ? e.message : 'Failed to load audit log'))
      .finally(() => setLoading(false))
  }, [search, targetType, offset, toast])

  useEffect(() => {
    load()
  }, [load])

  const handleSearchChange = (v: string) => {
    setSearch(v)
    setOffset(0)
  }

  const handleTargetChange = (t: string) => {
    setTargetType(t)
    setOffset(0)
  }

  const showingFrom = total === 0 ? 0 : offset + 1
  const showingTo = Math.min(offset + entries.length, total)

  return (
    <Layout title="Audit Log">
      <div className="page-header">
        <div className="page-header-left">
          <h1>Audit Log</h1>
          <p>{total} recorded administrative & enrollment event{total !== 1 ? 's' : ''}</p>
        </div>
        <button className="btn btn-secondary" onClick={load} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          Refresh
        </button>
      </div>

      <div className="table-wrap">
        <div
          style={{
            padding: '16px 24px',
            borderBottom: '1px solid var(--md-sys-color-outline-variant)',
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
          }}
        >
          <SearchBar
            value={search}
            onChange={handleSearchChange}
            placeholder="Search actor, action, target ID, or details..."
            style={{ maxWidth: 360 }}
          />
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {TARGET_FILTERS.map(f => (
              <button
                key={f.value}
                className={`btn btn-sm ${targetType === f.value ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => handleTargetChange(f.value)}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {entries.length === 0 ? (
          <EmptyState
            icon={<ScrollText size={48} style={{ opacity: 0.3 }} />}
            title={search || targetType ? 'No matching audit events' : 'No audit events recorded yet'}
            description={
              search || targetType
                ? 'Try clearing your search or category filter'
                : 'Device actions, enrollments, profile changes, and user updates will appear here'
            }
          />
        ) : (
          <>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Details</th>
                  <th>Source IP</th>
                </tr>
              </thead>
              <tbody>
                {entries.map(e => (
                  <tr key={e.id}>
                    <td title={new Date(e.created_at).toISOString()} style={{ whiteSpace: 'nowrap', opacity: 0.75 }}>
                      {timeAgo(e.created_at)}
                    </td>
                    <td style={{ fontWeight: 600 }}>{e.user_email || 'system'}</td>
                    <td>
                      <span className={actionBadgeClass(e.action)}>
                        <span className="badge-dot" />
                        {e.action}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.8rem', opacity: 0.85 }}>
                      {e.target_type ? `${e.target_type}:` : ''}
                      {e.target_id ? (e.target_id.length > 18 ? `${e.target_id.slice(0, 18)}…` : e.target_id) : '—'}
                    </td>
                    <td style={{ fontSize: '0.82rem', opacity: 0.75, maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={e.details}>
                      {formatDetails(e.details)}
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.78rem', opacity: 0.6 }}>
                      {e.ip_address || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div
              style={{
                padding: '14px 24px',
                borderTop: '1px solid var(--md-sys-color-outline-variant)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '0.82rem',
                opacity: 0.8,
              }}
            >
              <span>
                Showing {showingFrom}–{showingTo} of {total}
              </span>
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  className="btn btn-sm btn-secondary"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                >
                  <ChevronLeft size={14} />
                  Previous
                </button>
                <button
                  className="btn btn-sm btn-secondary"
                  disabled={offset + PAGE_SIZE >= total}
                  onClick={() => setOffset(offset + PAGE_SIZE)}
                >
                  Next
                  <ChevronRight size={14} />
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </Layout>
  )
}
