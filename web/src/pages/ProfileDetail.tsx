import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Shield, Plus, Trash2, Save, Info, X } from 'lucide-react'
import { Layout } from '../components/Layout'
import { Breadcrumb } from '../components/Breadcrumb'
import { api, type Profile, type PolicySetting, type CatalogEntry } from '../api'
import { EmptyState } from '../components/EmptyState'
import { SearchBar } from '../components/SearchBar'
import { SkeletonLine, SkeletonBlock } from '../components/SkeletonLoader'
import { useToast } from '../context/ToastContext'

export function ProfileDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  
  const [profile, setProfile] = useState<Profile | null>(null)
  const [settings, setSettings] = useState<PolicySetting[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [searching, setSearching] = useState(false)

  // Catalog Drawer State
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [catalogQuery, setCatalogQuery] = useState('')
  const [catalogItems, setCatalogItems] = useState<CatalogEntry[]>([])
  
  // Detail Modal State
  const [detailModalOpen, setDetailModalOpen] = useState(false)
  const [detailModalItem, setDetailModalItem] = useState<CatalogEntry | null>(null)
  const [detailModalSetting, setDetailModalSetting] = useState<PolicySetting | null>(null)
  
  const toast = useToast()

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
      toast.error(`Failed to save profile: ${e instanceof Error ? e.message : 'Unknown error'}`)
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

  const handleOpenCatalogDetail = (item: CatalogEntry) => {
    setDetailModalItem(item)
    setDetailModalSetting(null)
    setDetailModalOpen(true)
  }

  const handleOpenSettingDetail = (setting: PolicySetting) => {
    setDetailModalSetting(setting)
    setDetailModalItem(null)
    setDetailModalOpen(true)
  }

  if (loading)
    return (
      <Layout title="Loading...">
        <div className="fade-in" style={{ display: 'flex', height: 'calc(100vh - 120px)', gap: 24, overflow: 'hidden', opacity: 0.5, pointerEvents: 'none' }}>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, flexShrink: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <SkeletonBlock width={48} height={48} borderRadius={16} />
                <div>
                  <SkeletonBlock width={200} height={24} style={{ marginBottom: 8 }} />
                  <SkeletonBlock width={300} height={16} />
                </div>
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                <SkeletonBlock width={120} height={40} />
                <SkeletonBlock width={120} height={40} />
              </div>
            </div>
            <div className="card" style={{ flex: 1, padding: 0 }}>
              <SkeletonBlock width="100%" height={56} borderRadius={0} />
              <div style={{ padding: 24 }}>
                <SkeletonLine count={5} />
              </div>
            </div>
          </div>
        </div>
      </Layout>
    )
  if (!profile) return <Layout title="Editor"><div style={{ padding: 40, color: 'var(--danger)' }}>Profile not found</div></Layout>

  return (
    <Layout title={`Edit Profile: ${profile.name}`}>
      {/* Editor Container - using grid/flex for split view */}
      <div className="fade-in" style={{ display: 'flex', height: 'calc(100vh - 120px)', gap: 24, overflow: 'hidden' }}>
        
        {/* Left Side: Profile Construction */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, flexShrink: 0 }}>
            <div>
              <Breadcrumb items={[
                { label: 'Profiles', to: '/profiles' },
                { label: profile.name },
              ]} />
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
              <EmptyState
                icon={<Shield size={48} />}
                title="No policies assigned"
                description="Start by adding security rules from the catalog."
                action={<button className="btn btn-secondary mt-16" onClick={() => setDrawerOpen(true)}>Open Catalog</button>}
                style={{ flex: 1, justifyContent: 'center' }}
              />
            ) : (
              <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
                {settings.map(s => (
                  <div key={s.catalog_id} className="stat-card" style={{ padding: 24, background: 'rgba(255,255,255,0.03)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--md-sys-color-primary)', fontFamily: 'Outfit', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {s.display_name}
                        </div>
                        <div 
                          className="setting-description-clickable"
                          style={{ fontSize: '0.72rem', color: 'var(--md-sys-color-on-surface-variant)', opacity: 0.5, fontFamily: 'monospace', marginTop: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', cursor: 'pointer' }}
                          onClick={() => handleOpenSettingDetail(s)}
                          title={s.oma_uri}
                        >
                          {s.oma_uri}
                        </div>
                        {s.description && (
                          <div 
                            className="setting-description-clickable"
                            style={{ fontSize: '0.78rem', color: 'var(--md-sys-color-on-surface-variant)', opacity: 0.6, marginTop: 6, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', cursor: 'pointer' }}
                            onClick={() => handleOpenSettingDetail(s)}
                            title={s.description}
                          >
                            {s.description}
                          </div>
                        )}
                      </div>
                      <button className="btn btn-icon btn-secondary btn-sm" onClick={() => handleRemovePolicy(s.catalog_id)} style={{ borderRadius: '50%', flexShrink: 0, marginLeft: 12 }}>
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
                 <SearchBar
                   value={catalogQuery}
                   onChange={setCatalogQuery}
                   placeholder="Search policies..."
                   style={{ width: '100%' }}
                 />
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
                      const displayName = item.display_name || item.oma_uri.split('/').pop() || ''
                      return (
                        <div key={item.id} style={{ 
                          padding: '20px 24px', 
                          borderBottom: '1px solid var(--md-sys-color-outline-variant)',
                          background: isAdded ? 'rgba(208, 188, 255, 0.05)' : 'transparent',
                          transition: 'background 0.2s'
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
                            <div style={{ minWidth: 0, flex: 1 }}>
                              <div 
                                style={{ fontSize: '0.95rem', fontWeight: 600, color: isAdded ? 'var(--md-sys-color-primary)' : 'inherit', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: 4 }}
                                onClick={() => !isAdded && handleOpenCatalogDetail(item)}
                                title={displayName}
                              >
                                {displayName}
                              </div>
                              <div style={{ fontSize: '0.7rem', opacity: 0.45, fontFamily: 'monospace', marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {item.csp_name}
                              </div>
                              {item.description && (
                                <div 
                                  className="catalog-detail-toggle"
                                  onClick={() => handleOpenCatalogDetail(item)}
                                  style={{ display: 'flex', alignItems: 'center', gap: 4 }}
                                >
                                  <Info size={12} />
                                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'inline-block', maxWidth: '100%' }}>
                                    {item.description}
                                  </span>
                                </div>
                              )}
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

      {/* Detail Modal for Catalog Entry or Policy Setting */}
      {detailModalOpen && (
        <div className="modal-overlay" onClick={() => setDetailModalOpen(false)}>
          <div 
            className="modal" 
            style={{ maxWidth: '520px' }}
            onClick={e => e.stopPropagation()}
          >
            <div className="modal-header">
              <span className="modal-title" style={{ fontSize: '1.2rem', fontFamily: 'Outfit', fontWeight: 700 }}>
                {detailModalItem ? 'Policy Details' : 'Setting Details'}
              </span>
              <button 
                className="btn btn-icon btn-secondary" 
                onClick={() => setDetailModalOpen(false)} 
                aria-label="Close dialog"
                style={{ padding: '8px' }}
              >
                <X size={14} />
              </button>
            </div>
            <div className="modal-body" style={{ padding: '24px 32px' }}>
              {detailModalItem ? (
                // Catalog entry detail
                <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                  <div>
                    <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Display Name</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 600, fontFamily: 'Outfit' }}>{detailModalItem.display_name || '(Unnamed)'}</div>
                  </div>
                  <div>
                    <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>OMA URI</div>
                    <div style={{ fontFamily: 'monospace', fontSize: '0.85rem', background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: '8px', wordBreak: 'break-all' }}>{detailModalItem.oma_uri}</div>
                  </div>
                  <div>
                    <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>CSP Name</div>
                    <div style={{ fontFamily: 'monospace', fontSize: '0.85rem', background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: '8px', wordBreak: 'break-all' }}>{detailModalItem.csp_name}</div>
                  </div>
                  {detailModalItem.description && (
                    <div>
                      <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Description</div>
                      <div style={{ fontSize: '0.9rem', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{detailModalItem.description}</div>
                    </div>
                  )}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                    <div>
                      <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Data Type</div>
                      <div style={{ fontSize: '0.9rem', textTransform: 'capitalize' }}>{detailModalItem.data_type}</div>
                    </div>
                    <div>
                      <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Category</div>
                      <div style={{ fontSize: '0.9rem' }}>{detailModalItem.category || 'General'}</div>
                    </div>
                  </div>
                  {detailModalItem.default_value && (
                    <div>
                      <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Default Value</div>
                      <div style={{ fontFamily: 'monospace', fontSize: '0.85rem', background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: '8px' }}>{detailModalItem.default_value}</div>
                    </div>
                  )}
                  {detailModalItem.allowed_values && detailModalItem.allowed_values !== '[]' && (
                    <div>
                      <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Allowed Values</div>
                      <div style={{ fontFamily: 'monospace', fontSize: '0.8rem', background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: '8px', whiteSpace: 'pre-wrap', maxHeight: 160, overflowY: 'auto' }}>
                        {detailModalItem.allowed_values}
                      </div>
                    </div>
                  )}
                  {detailModalItem.is_deprecated && (
                    <div style={{ color: 'var(--md-sys-color-error)', fontSize: '0.85rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                      ⚠️ This policy is deprecated
                    </div>
                  )}
                </div>
              ) : detailModalSetting ? (
                // Policy setting detail
                <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                  <div>
                    <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Display Name</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 600, fontFamily: 'Outfit' }}>{detailModalSetting.display_name || '(Unnamed)'}</div>
                  </div>
                  <div>
                    <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>OMA URI</div>
                    <div style={{ fontFamily: 'monospace', fontSize: '0.85rem', background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: '8px', wordBreak: 'break-all' }}>{detailModalSetting.oma_uri}</div>
                  </div>
                  {detailModalSetting.description && (
                    <div>
                      <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Description</div>
                      <div style={{ fontSize: '0.9rem', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{detailModalSetting.description}</div>
                    </div>
                  )}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                    <div>
                      <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Data Type</div>
                      <div style={{ fontSize: '0.9rem', textTransform: 'capitalize' }}>{detailModalSetting.data_type}</div>
                    </div>
                    <div>
                      <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Current Value</div>
                      <div style={{ fontFamily: 'monospace', fontSize: '0.85rem', background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: '8px' }}>{detailModalSetting.desired_value}</div>
                    </div>
                  </div>
                  {detailModalSetting.allowed_values && detailModalSetting.allowed_values.length > 0 && (
                    <div>
                      <div className="form-label" style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Allowed Values</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {detailModalSetting.allowed_values.map((opt, idx) => (
                          <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', fontSize: '0.85rem' }}>
                            <span style={{ opacity: 0.7 }}>{opt.label}</span>
                            <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>{opt.value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : null}
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setDetailModalOpen(false)}>Close</button>
              {detailModalItem && !settings.some(s => s.catalog_id === detailModalItem.id) && (
                <button 
                  className="btn btn-primary" 
                  onClick={() => {
                    handleAddPolicy(detailModalItem)
                    setDetailModalOpen(false)
                  }}
                >
                  <Plus size={16} /> Add to Profile
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </Layout>
  )
}