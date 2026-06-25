import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Shield, Plus, Trash2, Search, Save } from 'lucide-react'
import { Layout } from '../components/Layout'
import { api, type Profile, type PolicySetting, type CatalogEntry } from '../api'

export function ProfileDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  
  const [profile, setProfile] = useState<Profile | null>(null)
  const [settings, setSettings] = useState<PolicySetting[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  // Catalog Drawer State
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [catalogQuery, setCatalogQuery] = useState('')
  const [catalogItems, setCatalogItems] = useState<CatalogEntry[]>([])
  const [searching, setSearching] = useState(false)

  useEffect(() => {
    if (!id) return
    api.profiles.get(id)
      .then(p => {
        setProfile(p)
        setSettings(p.settings || [])
      })
      .finally(() => setLoading(false))
  }, [id])

  useEffect(() => {
    if (!drawerOpen) return
    setSearching(true)
    const t = setTimeout(() => {
      api.catalog.list({ search: catalogQuery, limit: 50 })
        .then(res => setCatalogItems(res.entries))
        .finally(() => setSearching(false))
    }, 400)
    return () => clearTimeout(t)
  }, [drawerOpen, catalogQuery])

  const handleSave = async () => {
    if (!id) return
    setSaving(true)
    try {
      await api.profiles.update(id, { ...profile, settings })
      navigate('/profiles')
    } catch (e: unknown) {
      alert(`Failed to save: ${e instanceof Error ? e.message : 'Unknown error'}`)
    } finally {
      setSaving(false)
    }
  }

  const handleAddPolicy = (entry: CatalogEntry) => {
    // Only add if it doesn't exist
    if (settings.some(s => s.catalog_id === entry.id)) return
    
    // Set a default empty value, or default logic
    let fallback = entry.default_value || ''
    if (entry.data_type === 'boolean' && fallback === '') fallback = '0'
    if (entry.data_type === 'integer' && fallback === '') fallback = '0'

    let allowed: PolicySetting['allowed_values'] = undefined
    if (entry.allowed_values) {
      try {
        allowed = JSON.parse(entry.allowed_values)
      } catch {
        // Malformed catalog JSON must not crash the Add handler.
        allowed = undefined
      }
    }

    setSettings([...settings, {
      catalog_id: entry.id,
      oma_uri: entry.oma_uri,
      display_name: entry.display_name || entry.oma_uri.split('/').pop() || '',
      description: entry.description || '',
      data_type: entry.data_type,
      desired_value: fallback,
      allowed_values: allowed
    }])
  }

  const handleRemovePolicy = (catalog_id: number) => {
    setSettings(settings.filter(s => s.catalog_id !== catalog_id))
  }

  const handleUpdatePolicyValue = (catalog_id: number, val: string) => {
    setSettings(settings.map(s => 
      s.catalog_id === catalog_id ? { ...s, desired_value: val } : s
    ))
  }

  if (loading) return <Layout title="Loading..."><div style={{ padding: 40, color: 'var(--text-muted)' }}>Loading...</div></Layout>
  if (!profile) return <Layout title="Editor"><div style={{ padding: 40, color: 'var(--danger)' }}>Profile not found</div></Layout>

  return (
    <Layout title={`Edit Profile: ${profile.name}`}>
      {/* Editor Container - using grid/flex for split view */}
      <div className="fade-in" style={{ display: 'flex', height: 'calc(100vh - 120px)', gap: 24, overflow: 'hidden' }}>
        
        {/* Left Side: Profile Construction */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, flexShrink: 0 }}>
            <div>
              <button className="btn btn-secondary btn-sm" onClick={() => navigate('/profiles')} style={{ marginBottom: 16 }}>
                <ArrowLeft size={13} /> Back
              </button>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <div className="detail-icon" style={{ width: 48, height: 48, borderRadius: 16 }}>
                    <Shield size={24} />
                </div>
                <div>
                  <h2 className="topbar-title" style={{ fontSize: '1.5rem', margin: 0 }}>{profile.name}</h2>
                  <p style={{ margin: 0, fontSize: '0.9rem', color: 'var(--md-sys-color-on-surface-variant)' }}>{profile.description}</p>
                </div>
              </div>
            </div>
            
            <div style={{ display: 'flex', gap: 12 }}>
              <button className="btn btn-secondary" onClick={() => setDrawerOpen(!drawerOpen)} disabled={drawerOpen}>
                <Plus size={18} /> Add Policy
              </button>
              <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                <Save size={18} /> {saving ? 'Saving...' : 'Save Profile'}
              </button>
            </div>
          </div>

          <div className="card" style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', padding: 0 }}>
            <div style={{ padding: '20px 28px', borderBottom: '1px solid var(--md-sys-color-outline)', position: 'sticky', top: 0, background: 'var(--md-sys-color-surface-variant)', zIndex: 10 }}>
              <div className="card-title" style={{ margin: 0 }}>Configured Settings ({settings.length})</div>
            </div>
            
            {settings.length === 0 ? (
              <div className="empty-state" style={{ flex: 1, justifyContent: 'center' }}>
                <Shield size={48} style={{ marginBottom: 16 }} />
                <h3>No policies assigned</h3>
                <p>Start by adding security rules from the catalog.</p>
                <button className="btn btn-secondary mt-16" onClick={() => setDrawerOpen(true)}>Open Catalog</button>
              </div>
            ) : (
              <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
                {settings.map(s => (
                  <div key={s.catalog_id} className="stat-card" style={{ padding: 24, background: 'rgba(255,255,255,0.03)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
                      <div>
                        <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--md-sys-color-primary)', fontFamily: 'Outfit' }}>{s.display_name}</div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--md-sys-color-on-surface-variant)', opacity: 0.6, fontFamily: 'monospace', marginTop: 4 }}>{s.oma_uri}</div>
                      </div>
                      <button className="btn btn-icon btn-secondary btn-sm" onClick={() => handleRemovePolicy(s.catalog_id)} style={{ borderRadius: '50%' }}>
                        <Trash2 size={16} />
                      </button>
                    </div>

                    <div className="form-group" style={{ margin: 0 }}>
                      <label className="form-label" style={{ fontSize: '0.8rem', opacity: 0.7, marginBottom: 8, display: 'block' }}>Configured Value ({s.data_type})</label>
                      {s.allowed_values && s.allowed_values.length > 0 ? (
                        <select className="input" value={s.desired_value} onChange={e => handleUpdatePolicyValue(s.catalog_id, e.target.value)} style={{ width: '100%' }}>
                          {s.allowed_values.map(opt => (
                            <option key={opt.value} value={opt.value}>{opt.label} ({opt.value})</option>
                          ))}
                        </select>
                      ) : s.data_type === 'boolean' ? (
                        <select className="input" value={s.desired_value} onChange={e => handleUpdatePolicyValue(s.catalog_id, e.target.value)} style={{ width: 220 }}>
                          <option value="1">Enabled (1)</option>
                          <option value="0">Disabled (0)</option>
                        </select>
                      ) : (
                        <input 
                          className="input" 
                          type={s.data_type === 'integer' ? 'number' : 'text'} 
                          value={s.desired_value} 
                          onChange={e => handleUpdatePolicyValue(s.catalog_id, e.target.value)} 
                          placeholder="Enter value..." 
                        />
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Side: Catalog Drawer */}
        <div style={{ 
          width: drawerOpen ? '440px' : '0px', 
          opacity: drawerOpen ? 1 : 0, 
          transition: 'all 0.4s var(--ease)', 
          flexShrink: 0, 
          display: 'flex', 
          flexDirection: 'column',
          background: 'var(--md-sys-color-surface-variant)',
          border: '1px solid var(--md-sys-color-outline)',
          borderRadius: 'var(--radius-lg)',
          overflow: 'hidden',
          boxShadow: '-20px 0 60px rgba(0,0,0,0.3)'
        }}>
          {drawerOpen && (
            <>
              <div style={{ padding: '24px', borderBottom: '1px solid var(--md-sys-color-outline)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, fontFamily: 'Outfit', fontSize: '1.2rem' }}>Policy Catalog</span>
                <button className="btn btn-icon btn-secondary btn-sm" onClick={() => setDrawerOpen(false)} style={{ borderRadius: '50%' }}>×</button>
              </div>
              
              <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--md-sys-color-outline)' }}>
                 <div className="input-wrap">
                  <Search size={18} className="input-icon" />
                  <input
                    className="input input-has-icon"
                    placeholder="Search policies..."
                    value={catalogQuery}
                    onChange={e => setCatalogQuery(e.target.value)}
                    autoFocus
                  />
                </div>
              </div>

              <div style={{ flex: 1, overflowY: 'auto' }}>
                {searching ? (
                   <div style={{ padding: 40, textAlign: 'center', opacity: 0.5 }}>Searching...</div>
                ) : catalogItems.length === 0 ? (
                   <div style={{ padding: 40, textAlign: 'center', opacity: 0.5 }}>No results found.</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    {catalogItems.map(item => {
                      const isAdded = settings.some(s => s.catalog_id === item.id)
                      return (
                        <div key={item.id} style={{ 
                          padding: '24px', 
                          borderBottom: '1px solid var(--md-sys-color-outline-variant)',
                          background: isAdded ? 'rgba(208, 188, 255, 0.05)' : 'transparent',
                          transition: 'background 0.2s'
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16 }}>
                            <div style={{ minWidth: 0, flex: 1 }}>
                              <div style={{ fontSize: '1rem', fontWeight: 600, color: isAdded ? 'var(--md-sys-color-primary)' : 'inherit', wordBreak: 'break-all' }}>
                                {item.display_name || item.oma_uri.split('/').pop()}
                              </div>
                              <div style={{ fontSize: '0.72rem', opacity: 0.5, fontFamily: 'monospace', margin: '6px 0' }}>{item.csp_name}</div>
                              {item.description && <div style={{ fontSize: '0.85rem', opacity: 0.8, marginTop: 8, display: '-webkit-box', WebkitLineClamp: 3, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>{item.description}</div>}
                            </div>
                            <button 
                              className={`btn btn-sm ${isAdded ? 'btn-secondary' : 'btn-primary'}`} 
                              onClick={() => handleAddPolicy(item)}
                              disabled={isAdded}
                              style={{ flexShrink: 0 }}
                            >
                              {isAdded ? 'Added' : 'Add'}
                            </button>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </Layout>
  )
}
