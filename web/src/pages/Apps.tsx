import { useEffect, useState, useCallback, useRef, type DragEvent } from 'react'
import {
  Package,
  Plus,
  Trash2,
  Monitor,
  Users,
  Download,
  Search,
  RefreshCw,
  Upload,
  Globe,
  FileArchive,
  Sparkles,
  X,
} from 'lucide-react'
import { Layout } from '../components/Layout'
import { ActionButton } from '../components/ActionButton'
import { Badge } from '../components/Badge'
import { EmptyState } from '../components/EmptyState'
import { Modal } from '../components/Modal'
import { useToast } from '../hooks/useToast'
import {
  api,
  type MSIApp,
  type MSIAppDetail,
  type WinGetSearchResult,
  type Device,
  type Group,
} from '../api'
import { previewLocalMSIFile } from '../msiPreview'
import { timeAgo } from '../format'

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '—'
  const mb = bytes / (1024 * 1024)
  if (mb >= 1) return `${mb.toFixed(1)} MB`
  return `${(bytes / 1024).toFixed(0)} KB`
}

function appBadgeStatus(code: number | null, label: string): string {
  if (code === 70) return 'compliant'
  if (code === 30 || code === 60 || label.toLowerCase().includes('failed')) return 'non_compliant'
  return 'pending'
}

function CreateAppModal({
  initialFile,
  initialMode = 'upload',
  onClose,
  onCreated,
}: {
  initialFile?: File | null
  initialMode?: 'upload' | 'url' | 'winget'
  onClose: () => void
  onCreated: (app: MSIApp) => void
}) {
  const [mode, setMode]               = useState<'upload' | 'url' | 'winget'>(initialFile ? 'upload' : initialMode)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [dragActive, setDragActive]   = useState(false)
  const [uploadPct, setUploadPct]     = useState(0)
  const [uploadLoaded, setUploadLoaded] = useState(0)

  const [wingetQuery, setWingetQuery]     = useState('')
  const [wingetResults, setWingetResults] = useState<WinGetSearchResult[]>([])
  const [wingetLoading, setWingetLoading] = useState(false)
  const [importingPkg, setImportingPkg]   = useState<string | null>(null)

  const [contentUrl, setContentUrl]   = useState('')
  const [name, setName]               = useState('')
  const [publisher, setPublisher]     = useState('')
  const [version, setVersion]         = useState('')
  const [productCode, setProductCode] = useState('')
  const [upgradeCode, setUpgradeCode] = useState('')
  const [sha256, setSha256]           = useState('')
  const [fileSize, setFileSize]       = useState(0)
  const [cmdLine, setCmdLine]         = useState('/quiet /norestart')
  const [inspecting, setInspecting]   = useState(false)
  const [saving, setSaving]           = useState(false)
  const [error, setError]             = useState('')
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const toast = useToast()

  const applyLocalFile = useCallback(async (file: File) => {
    if (!file.name.toLowerCase().endsWith('.msi')) {
      setError('Please select a Windows Installer (.msi) package file.')
      return
    }
    setError('')
    setMode('upload')
    setSelectedFile(file)
    setFileSize(file.size)
    setSha256('')
    setInspecting(true)
    try {
      const meta = await previewLocalMSIFile(file)
      setName(meta.name || file.name.replace(/\.msi$/i, ''))
      setPublisher(meta.publisher || '')
      setVersion(meta.version || '1.0.0')
      setProductCode(meta.productCode || '')
      setUpgradeCode(meta.upgradeCode || '')
    } catch (e: unknown) {
      setProductCode('')
      setUpgradeCode('')
      setError(e instanceof Error ? e.message : 'Could not read MSI metadata header.')
    } finally {
      setInspecting(false)
    }
  }, [])

  useEffect(() => {
    if (initialFile) {
      void applyLocalFile(initialFile)
    }
  }, [initialFile, applyLocalFile])

  useEffect(() => {
    if (mode !== 'winget') return
    let cancelled = false
    setWingetLoading(true)
    const timer = setTimeout(() => {
      api.apps
        .wingetSearch(wingetQuery)
        .then(res => {
          if (!cancelled) setWingetResults(res ?? [])
        })
        .catch(e => {
          if (!cancelled) setError(e instanceof Error ? e.message : 'WinGet catalog search failed')
        })
        .finally(() => {
          if (!cancelled) setWingetLoading(false)
        })
    }, wingetQuery.trim() ? 220 : 0)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [mode, wingetQuery])

  const importFromWinGet = async (pkg: WinGetSearchResult) => {
    setError('')
    setImportingPkg(pkg.package_id)
    setSaving(true)
    try {
      const created = await api.apps.wingetImport({
        package_id: pkg.package_id,
        architecture: 'x64',
        command_line: cmdLine.trim() || '/quiet /norestart',
      })
      toast.success(`Imported "${created.name}" (${created.version}) from WinGet`)
      onCreated(created)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : `Failed to import ${pkg.package_id} from WinGet`)
    } finally {
      setImportingPkg(null)
      setSaving(false)
    }
  }

  const handleDropZone = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    if (saving) return
    const f = e.dataTransfer.files?.[0]
    if (f) void applyLocalFile(f)
  }

  const clearSelectedFile = () => {
    setSelectedFile(null)
    setName('')
    setPublisher('')
    setVersion('')
    setProductCode('')
    setUpgradeCode('')
    setSha256('')
    setFileSize(0)
    setError('')
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const inspectUrl = async () => {
    const trimmed = contentUrl.trim()
    if (!trimmed) {
      setError('Enter an HTTPS .msi download URL first')
      return
    }
    setError('')
    setInspecting(true)
    try {
      const meta = await api.apps.inspect(trimmed)
      setName(meta.name || '')
      setPublisher(meta.publisher || '')
      setVersion(meta.version || '1.0.0')
      setProductCode(meta.product_code || '')
      setUpgradeCode(meta.upgrade_code || '')
      setSha256(meta.sha256 || '')
      setFileSize(meta.file_size_bytes || 0)
      toast.success(`Extracted metadata for ${meta.name || meta.product_code} (${formatBytes(meta.file_size_bytes)})`)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to inspect MSI URL')
    } finally {
      setInspecting(false)
    }
  }

  const submit = async () => {
    if (mode === 'upload') {
      if (!selectedFile) {
        setError('Drag and drop or browse for a local .msi file first')
        return
      }
      setError('')
      setSaving(true)
      setUploadPct(0)
      setUploadLoaded(0)
      try {
        const created = await api.apps.upload(
          selectedFile,
          {
            name: name.trim(),
            publisher: publisher.trim(),
            version: version.trim(),
            command_line: cmdLine.trim() || '/quiet /norestart',
          },
          (loaded, total) => {
            setUploadLoaded(loaded)
            setUploadPct(total > 0 ? Math.min(100, Math.round((loaded * 100) / total)) : 0)
          }
        )
        toast.success(`Uploaded & registered "${created.name}" (${created.version})`)
        onCreated(created)
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : 'Failed to upload MSI package')
      } finally {
        setSaving(false)
      }
      return
    }

    if (!contentUrl.trim()) {
      setError('HTTPS MSI URL is required')
      return
    }
    setError('')
    setSaving(true)
    try {
      const created = await api.apps.create({
        content_url: contentUrl.trim(),
        name: name.trim(),
        publisher: publisher.trim(),
        version: version.trim(),
        product_code: productCode.trim(),
        upgrade_code: upgradeCode.trim(),
        sha256: sha256.trim(),
        file_size_bytes: fileSize,
        command_line: cmdLine.trim() || '/quiet /norestart',
      })
      toast.success(`Registered "${created.name}" (${created.version})`)
      onCreated(created)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to register application')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal
      open={true}
      onClose={saving ? () => {} : onClose}
      title="Add Win32 MSI Application"
      maxWidth={680}
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose} disabled={saving || inspecting}>
            {mode === 'winget' ? 'Close' : 'Cancel'}
          </button>
          {mode !== 'winget' && (
            <button
              className="btn btn-primary"
              onClick={submit}
              disabled={saving || inspecting || (mode === 'upload' && !selectedFile)}
            >
              {saving
                ? mode === 'upload'
                  ? `Uploading (${uploadPct}%)…`
                  : 'Registering…'
                : mode === 'upload'
                  ? 'Upload & Register'
                  : 'Register Application'}
            </button>
          )}
        </>
      }
    >
      <div style={{ display: 'flex', gap: 8, marginBottom: 18, flexWrap: 'wrap' }}>
        <button
          type="button"
          className={`btn btn-sm ${mode === 'upload' ? 'btn-primary' : 'btn-secondary'}`}
          disabled={saving}
          onClick={() => { setMode('upload'); setError('') }}
        >
          <Upload size={14} /> Upload Local .msi
        </button>
        <button
          type="button"
          className={`btn btn-sm ${mode === 'winget' ? 'btn-primary' : 'btn-secondary'}`}
          disabled={saving}
          onClick={() => { setMode('winget'); setError('') }}
        >
          <Sparkles size={14} /> Browse WinGet Catalog
        </button>
        <button
          type="button"
          className={`btn btn-sm ${mode === 'url' ? 'btn-primary' : 'btn-secondary'}`}
          disabled={saving}
          onClick={() => { setMode('url'); setError('') }}
        >
          <Globe size={14} /> External HTTPS URL
        </button>
      </div>

      {mode === 'winget' ? (
        <div>
          <div className="form-group">
            <label className="form-label">Search WinGet MSI Packages</label>
            <div style={{ position: 'relative' }}>
              <Search
                size={15}
                style={{
                  position: 'absolute',
                  left: 12,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  opacity: 0.55,
                  pointerEvents: 'none',
                }}
              />
              <input
                className="input"
                style={{ paddingLeft: 36 }}
                value={wingetQuery}
                onChange={e => setWingetQuery(e.target.value)}
                disabled={saving}
                placeholder="Search 7zip, Firefox, Chrome, PowerShell, Tailscale, or enter Publisher.Package…"
                autoFocus
              />
            </div>
            <div style={{ fontSize: '0.75rem', opacity: 0.62, marginTop: 6 }}>
              100% agentless: Latchz resolves official <code>microsoft/winget-pkgs</code> YAML manifests with native MSI/WiX installers, verifies SHA-256 & ProductCode, and deploys via <code>EnterpriseDesktopAppManagement</code> CSP.
            </div>
          </div>

          <div
            style={{
              maxHeight: 300,
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: 8,
              marginBottom: 14,
              paddingRight: 4,
            }}
          >
            {wingetLoading && wingetResults.length === 0 ? (
              <div style={{ padding: 24, textAlign: 'center', opacity: 0.55, fontSize: '0.86rem' }}>
                Searching WinGet MSI catalog…
              </div>
            ) : wingetResults.length === 0 ? (
              <div style={{ padding: 24, textAlign: 'center', opacity: 0.55, fontSize: '0.86rem' }}>
                No matching WinGet packages found. Enter an exact <code>Publisher.Package</code> identifier (e.g. <code>7zip.7zip</code>) to inspect its manifest directly.
              </div>
            ) : (
              wingetResults.map(pkg => {
                const isImporting = importingPkg === pkg.package_id
                return (
                  <div
                    key={pkg.package_id}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 12,
                      padding: '11px 14px',
                      borderRadius: 12,
                      border: '1px solid var(--md-sys-color-outline-variant)',
                      background: 'var(--md-sys-color-surface-container-low)',
                    }}
                  >
                    <Package size={18} style={{ color: 'var(--md-sys-color-primary)', flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{pkg.name}</span>
                        <code style={{ fontSize: '0.73rem', opacity: 0.8 }}>{pkg.package_id}</code>
                        {pkg.curated_msi && <Badge status="compliant" label="Native MSI" />}
                      </div>
                      <div style={{ fontSize: '0.75rem', opacity: 0.65, marginTop: 2 }}>
                        {pkg.publisher ? `${pkg.publisher} · ` : ''}
                        {pkg.description || 'Resolves latest x64 MSI/WiX manifest from microsoft/winget-pkgs'}
                      </div>
                    </div>
                    <button
                      type="button"
                      className="btn btn-sm btn-primary"
                      disabled={saving}
                      onClick={() => void importFromWinGet(pkg)}
                      style={{ whiteSpace: 'nowrap' }}
                    >
                      <Download size={13} className={isImporting ? 'spin' : ''} />
                      {isImporting ? 'Importing…' : '1-Click Import'}
                    </button>
                  </div>
                )
              })
            )}
          </div>
        </div>
      ) : mode === 'upload' ? (
        <div className="form-group">
          <input
            ref={fileInputRef}
            type="file"
            accept=".msi,application/x-msi"
            style={{ display: 'none' }}
            onChange={e => {
              const f = e.target.files?.[0]
              if (f) void applyLocalFile(f)
            }}
          />

          {!selectedFile ? (
            <div
              role="button"
              tabIndex={0}
              onClick={() => !saving && fileInputRef.current?.click()}
              onKeyDown={e => {
                if ((e.key === 'Enter' || e.key === ' ') && !saving) {
                  e.preventDefault()
                  fileInputRef.current?.click()
                }
              }}
              onDragOver={e => { e.preventDefault(); e.stopPropagation(); if (!saving) setDragActive(true) }}
              onDragLeave={e => { e.preventDefault(); e.stopPropagation(); setDragActive(false) }}
              onDrop={handleDropZone}
              style={{
                border: `2px dashed ${dragActive ? 'var(--md-sys-color-primary)' : 'var(--md-sys-color-outline)'}`,
                background: dragActive ? 'rgba(208, 188, 255, 0.1)' : 'var(--md-sys-color-surface-container-low)',
                borderRadius: 16,
                padding: '28px 20px',
                textAlign: 'center',
                cursor: saving ? 'default' : 'pointer',
                transition: 'var(--transition-fast)',
              }}
            >
              <Upload
                size={28}
                style={{
                  color: dragActive ? 'var(--md-sys-color-primary)' : 'var(--md-sys-color-on-surface-variant)',
                  opacity: dragActive ? 1 : 0.75,
                  marginBottom: 8,
                }}
              />
              <div style={{ fontWeight: 600, fontSize: '0.95rem' }}>
                Drag & drop a <code>.msi</code> installer here, or click to browse
              </div>
              <div style={{ fontSize: '0.78rem', opacity: 0.6, marginTop: 4 }}>
                Latchz automatically extracts ProductCode, version & SHA-256 and hosts the package over HTTPS for Windows Delivery Optimization.
              </div>
            </div>
          ) : (
            <div
              onDragOver={e => { e.preventDefault(); e.stopPropagation(); if (!saving) setDragActive(true) }}
              onDragLeave={e => { e.preventDefault(); e.stopPropagation(); setDragActive(false) }}
              onDrop={handleDropZone}
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 10,
                padding: '14px 16px',
                borderRadius: 14,
                border: `1px solid ${dragActive ? 'var(--md-sys-color-primary)' : 'var(--md-sys-color-outline)'}`,
                background: 'rgba(208, 188, 255, 0.06)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <FileArchive size={22} style={{ color: 'var(--md-sys-color-primary)', flexShrink: 0 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: '0.92rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {selectedFile.name}
                  </div>
                  <div style={{ fontSize: '0.76rem', opacity: 0.65 }}>
                    {formatBytes(selectedFile.size)}
                    {productCode ? ` · ${productCode}` : ''}
                    {inspecting ? ' · Reading MSI header…' : ' · SHA-256 verified on upload'}
                  </div>
                </div>
                {!saving && (
                  <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    onClick={clearSelectedFile}
                    title="Choose a different .msi file"
                  >
                    <X size={14} /> Replace
                  </button>
                )}
              </div>

              {saving && (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', opacity: 0.8, marginBottom: 4 }}>
                    <span>{uploadPct >= 100 ? 'Verifying CFB metadata & SHA-256 on server…' : 'Uploading package to Latchz…'}</span>
                    <span>{formatBytes(uploadLoaded)} / {formatBytes(selectedFile.size)} ({uploadPct}%)</span>
                  </div>
                  <div style={{ height: 6, borderRadius: 999, background: 'rgba(255,255,255,0.08)', overflow: 'hidden' }}>
                    <div
                      style={{
                        width: `${uploadPct}%`,
                        height: '100%',
                        background: 'var(--md-sys-color-primary)',
                        transition: 'width 120ms linear',
                      }}
                    />
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      ) : (
        <div className="form-group">
          <label className="form-label">HTTPS Installer URL (.msi) *</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              className="input"
              style={{ flex: 1 }}
              value={contentUrl}
              onChange={e => setContentUrl(e.target.value)}
              placeholder="https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
              autoFocus
            />
            <button
              type="button"
              className="btn btn-secondary"
              onClick={inspectUrl}
              disabled={inspecting || saving}
              style={{ whiteSpace: 'nowrap' }}
            >
              <Search size={15} className={inspecting ? 'spin' : ''} />
              {inspecting ? 'Inspecting…' : 'Auto-Inspect'}
            </button>
          </div>
          <div style={{ fontSize: '0.75rem', opacity: 0.6, marginTop: 6 }}>
            Auto-Inspect streams the MSI over HTTPS to extract its ProductCode GUID, version, publisher, and SHA-256 FileHash automatically.
          </div>
        </div>
      )}

      {mode !== 'winget' && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="form-group">
              <label className="form-label">Application Name</label>
              <input
                className="input"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="Auto-filled from MSI"
                disabled={saving}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Publisher</label>
              <input
                className="input"
                value={publisher}
                onChange={e => setPublisher(e.target.value)}
                placeholder="e.g. Google LLC"
                disabled={saving}
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '160px 1fr', gap: 12 }}>
            <div className="form-group">
              <label className="form-label">Version</label>
              <input
                className="input"
                value={version}
                onChange={e => setVersion(e.target.value)}
                placeholder="1.0.0"
                disabled={saving}
              />
            </div>
            <div className="form-group">
              <label className="form-label">MSI ProductCode GUID</label>
              <input
                className="input mono"
                value={productCode}
                onChange={e => setProductCode(e.target.value)}
                readOnly={mode === 'upload'}
                disabled={saving}
                style={mode === 'upload' ? { opacity: 0.75 } : undefined}
                placeholder={mode === 'upload' ? 'Auto-extracted from .msi' : '{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}'}
              />
            </div>
          </div>
        </>
      )}

      {mode === 'url' && (
        <div className="form-group">
          <label className="form-label">SHA-256 FileHash</label>
          <input
            className="input mono"
            value={sha256}
            onChange={e => setSha256(e.target.value)}
            placeholder="64-character SHA-256 hex digest (auto-computed if blank)"
            disabled={saving}
          />
        </div>
      )}

      <div className="form-group">
        <label className="form-label">Silent Command-Line Arguments</label>
        <input
          className="input mono"
          value={cmdLine}
          onChange={e => setCmdLine(e.target.value)}
          placeholder="/quiet /norestart"
          disabled={saving}
        />
      </div>

      {error && <p style={{ color: 'var(--md-sys-color-error)', fontSize: '0.82rem', marginTop: 8 }}>{error}</p>}
    </Modal>
  )
}

function DeployAppModal({
  app,
  devices,
  groups,
  onClose,
  onChanged,
}: {
  app: MSIApp
  devices: Device[]
  groups: Group[]
  onClose: () => void
  onChanged: () => void
}) {
  const [tab, setTab]         = useState<'status' | 'devices' | 'groups'>('status')
  const [detail, setDetail]   = useState<MSIAppDetail | null>(null)
  const [busy, setBusy]       = useState<string | null>(null)
  const toast = useToast()

  const loadDetail = useCallback(() => {
    api.apps.get(app.id).then(setDetail).catch(() => {})
  }, [app.id])

  useEffect(() => {
    loadDetail()
    const t = setInterval(loadDetail, 8000)
    return () => clearInterval(t)
  }, [loadDetail])

  const pushInstall = async (deviceId: string, label: string) => {
    setBusy(`inst-${deviceId}`)
    try {
      await api.apps.install(app.id, [deviceId])
      toast.success(`Queued "${app.name}" install on ${label}`)
      loadDetail()
      onChanged()
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to queue install')
    } finally {
      setBusy(null)
    }
  }

  const pushUninstall = async (deviceId: string, label: string) => {
    setBusy(`uninst-${deviceId}`)
    try {
      await api.apps.uninstall(app.id, [deviceId])
      toast.success(`Queued "${app.name}" uninstall on ${label}`)
      loadDetail()
      onChanged()
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to queue uninstall')
    } finally {
      setBusy(null)
    }
  }

  const toggleGroup = async (groupId: string, groupName: string, action: 'add' | 'remove') => {
    setBusy(`grp-${groupId}`)
    try {
      const res = await api.apps.assignGroups(app.id, [groupId], action)
      toast.success(
        action === 'add'
          ? `Assigned "${app.name}" to group "${groupName}" (${res.devices_targeted} device(s) queued)`
          : `Removed "${app.name}" from group "${groupName}"`
      )
      loadDetail()
      onChanged()
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to update group assignment')
    } finally {
      setBusy(null)
    }
  }

  const assignedGroups = new Set(detail?.group_ids ?? [])
  const installs = detail?.installs ?? []

  return (
    <Modal
      open={true}
      onClose={onClose}
      title={`Deploy: ${app.name} (${app.version})`}
      maxWidth={680}
      footer={
        <button className="btn btn-secondary" onClick={onClose}>Done</button>
      }
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 6 }}>
          <button className={`btn btn-sm ${tab === 'status' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setTab('status')}>
            <Package size={13} /> Deployment Status ({installs.length})
          </button>
          <button className={`btn btn-sm ${tab === 'devices' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setTab('devices')}>
            <Monitor size={13} /> Target Devices ({devices.length})
          </button>
          <button className={`btn btn-sm ${tab === 'groups' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setTab('groups')}>
            <Users size={13} /> Assign Groups ({assignedGroups.size})
          </button>
        </div>
        <button className="btn btn-sm btn-secondary" onClick={loadDetail} title="Refresh status">
          <RefreshCw size={13} />
        </button>
      </div>

      {tab === 'status' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 340, overflowY: 'auto' }}>
          {installs.length === 0 ? (
            <p style={{ opacity: 0.6, fontSize: '0.88rem', textAlign: 'center', padding: 28 }}>
              Not deployed to any devices yet — switch to <strong>Target Devices</strong> or <strong>Assign Groups</strong> to push this MSI.
            </p>
          ) : (
            installs.map(inst => (
              <div
                key={inst.device_id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: '10px 14px',
                  border: '1px solid var(--md-sys-color-outline-variant)',
                  borderRadius: 12,
                }}
              >
                <Monitor size={16} style={{ opacity: 0.6, flexShrink: 0 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{inst.device_name || inst.device_id}</span>
                    {inst.installed_version && (
                      <span className="mono" style={{ fontSize: '0.75rem', opacity: 0.85 }}>
                        v{inst.installed_version}
                      </span>
                    )}
                    {inst.version_state === 'auto_updated' && (
                      <Badge status="compliant" label="Auto-Updated" />
                    )}
                    {inst.version_state === 'update_available' && (
                      <Badge status="pending" label={`Catalog v${inst.version}`} />
                    )}
                  </div>
                  <div style={{ fontSize: '0.75rem', opacity: 0.6 }}>
                    Updated {timeAgo(inst.updated_at)}
                    {inst.version_state === 'auto_updated' ? ` · Seed v${inst.version}` : ''}
                    {inst.installed_product_code && inst.installed_product_code !== inst.product_code
                      ? ` · Live MSI ${inst.installed_product_code}`
                      : ''}
                    {inst.last_error && inst.last_error !== '0' ? ` · Error ${inst.last_error}${inst.last_error_desc ? `: ${inst.last_error_desc}` : ''}` : ''}
                  </div>
                </div>
                <Badge status={appBadgeStatus(inst.status_code, inst.status_label)} label={inst.status_label} dot />
                <button
                  className="btn btn-sm btn-secondary"
                  disabled={busy !== null}
                  onClick={() => pushInstall(inst.device_id, inst.device_name || inst.device_id)}
                >
                  Re-push
                </button>
              </div>
            ))
          )}
        </div>
      )}

      {tab === 'devices' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 340, overflowY: 'auto' }}>
          {devices.length === 0 ? (
            <p style={{ opacity: 0.6, fontSize: '0.88rem' }}>No active enrolled devices.</p>
          ) : (
            devices.map(d => {
              const label = d.device_name || d.hardware_id
              return (
                <div
                  key={d.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    padding: '10px 14px',
                    border: '1px solid var(--md-sys-color-outline-variant)',
                    borderRadius: 12,
                  }}
                >
                  <Monitor size={16} style={{ opacity: 0.6 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{label}</div>
                    <div style={{ fontSize: '0.75rem', opacity: 0.55 }}>{d.os_version || 'Windows'}</div>
                  </div>
                  <button
                    className="btn btn-sm btn-primary"
                    disabled={busy !== null}
                    onClick={() => pushInstall(d.id, label)}
                  >
                    <Download size={13} />
                    {busy === `inst-${d.id}` ? 'Queueing…' : 'Install'}
                  </button>
                  <button
                    className="btn btn-sm btn-secondary"
                    disabled={busy !== null}
                    onClick={() => pushUninstall(d.id, label)}
                  >
                    {busy === `uninst-${d.id}` ? 'Queueing…' : 'Uninstall'}
                  </button>
                </div>
              )
            })
          )}
        </div>
      )}

      {tab === 'groups' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 340, overflowY: 'auto' }}>
          {groups.length === 0 ? (
            <p style={{ opacity: 0.6, fontSize: '0.88rem' }}>No device groups created yet.</p>
          ) : (
            groups.map(g => {
              const isAssigned = assignedGroups.has(g.id)
              return (
                <div
                  key={g.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    padding: '10px 14px',
                    border: '1px solid var(--md-sys-color-outline-variant)',
                    borderRadius: 12,
                  }}
                >
                  <Users size={16} style={{ opacity: 0.6 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{g.name}</div>
                    <div style={{ fontSize: '0.75rem', opacity: 0.55 }}>{g.device_count} member device(s)</div>
                  </div>
                  {isAssigned && <Badge status="compliant" label="Assigned" dot />}
                  {isAssigned ? (
                    <button
                      className="btn btn-sm btn-secondary"
                      disabled={busy !== null}
                      onClick={() => toggleGroup(g.id, g.name, 'remove')}
                    >
                      Remove
                    </button>
                  ) : (
                    <button
                      className="btn btn-sm btn-primary"
                      disabled={busy !== null}
                      onClick={() => toggleGroup(g.id, g.name, 'add')}
                    >
                      Assign Group
                    </button>
                  )}
                </div>
              )
            })
          )}
        </div>
      )}
    </Modal>
  )
}

export function AppsPage() {
  const [apps, setApps]                   = useState<MSIApp[]>([])
  const [devices, setDevices]             = useState<Device[]>([])
  const [groups, setGroups]               = useState<Group[]>([])
  const [loading, setLoading]             = useState(true)
  const [creating, setCreating]           = useState(false)
  const [createMode, setCreateMode]       = useState<'upload' | 'url' | 'winget'>('upload')
  const [droppedFile, setDroppedFile]     = useState<File | null>(null)
  const [pageDragActive, setPageDragActive] = useState(false)
  const [deploying, setDeploying]         = useState<MSIApp | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<MSIApp | null>(null)
  const [refreshingId, setRefreshingId]   = useState<string | null>(null)
  const toast = useToast()

  const load = useCallback(() => {
    Promise.all([
      api.apps.list().catch(() => [] as MSIApp[]),
      api.devices.list().catch(() => [] as Device[]),
      api.groups.list().catch(() => [] as Group[]),
    ])
      .then(([a, d, g]) => {
        setApps(a ?? [])
        setDevices(d ?? [])
        setGroups(g ?? [])
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const removeApp = async () => {
    if (!confirmDelete) return
    const target = confirmDelete
    setConfirmDelete(null)
    try {
      await api.apps.delete(target.id)
      setApps(prev => prev.filter(x => x.id !== target.id))
      toast.success(`Removed "${target.name}" from catalog`)
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to delete application')
    }
  }

  const refreshWinGetSeed = async (target: MSIApp) => {
    setRefreshingId(target.id)
    try {
      const res = await api.apps.wingetRefresh(target.id)
      setApps(prev => prev.map(x => (x.id === target.id ? res.app : x)))
      if (res.updated) {
        toast.success(`Updated "${res.app.name}" seed installer: ${res.previous_version} → ${res.latest_version}`)
      } else {
        toast.success(`"${res.app.name}" is already at the latest WinGet MSI version (${res.latest_version})`)
      }
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to check WinGet for updates')
    } finally {
      setRefreshingId(null)
    }
  }

  const handlePageDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setPageDragActive(false)
    if (creating || deploying || confirmDelete) return
    const f = e.dataTransfer.files?.[0]
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.msi')) {
      toast.error('Only Windows Installer (.msi) files can be uploaded here.')
      return
    }
    setDroppedFile(f)
    setCreating(true)
  }

  return (
    <Layout title="Applications">
      <div
        className="fade-in"
        onDragOver={e => {
          if (creating || deploying || confirmDelete) return
          if (e.dataTransfer.types.includes('Files')) {
            e.preventDefault()
            setPageDragActive(true)
          }
        }}
        onDragLeave={e => {
          if (e.currentTarget === e.target) setPageDragActive(false)
        }}
        onDrop={handlePageDrop}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28, gap: 12, flexWrap: 'wrap' }}>
          <div style={{ opacity: 0.7, fontSize: '0.95rem' }}>
            Drag & drop local <code>.msi</code> installers, import from WinGet, or register HTTPS URLs to deploy silently via Windows <code>EnterpriseDesktopAppManagement</code> CSP.
          </div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <a className="btn btn-secondary" href="/api/export/software?format=csv" download>
              <Download size={15} /> Export Inventory CSV
            </a>
            <a className="btn btn-secondary" href="/api/export/software?format=json" download>
              <Download size={15} /> Export JSON
            </a>
            <button
              className="btn btn-secondary"
              onClick={() => { setDroppedFile(null); setCreateMode('winget'); setCreating(true) }}
            >
              <Sparkles size={16} /> Browse WinGet
            </button>
            <ActionButton
              icon={<Plus size={18} />}
              label="Add MSI Application"
              onClick={() => { setDroppedFile(null); setCreateMode('upload'); setCreating(true) }}
            />
          </div>
        </div>

        {pageDragActive && (
          <div
            style={{
              marginBottom: 20,
              padding: '22px 24px',
              borderRadius: 16,
              border: '2px dashed var(--md-sys-color-primary)',
              background: 'rgba(208, 188, 255, 0.1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 10,
              fontWeight: 600,
              color: 'var(--md-sys-color-primary)',
            }}
          >
            <Upload size={20} /> Drop your <code>.msi</code> package anywhere to inspect & upload
          </div>
        )}

        {loading ? (
          <div className="card" style={{ padding: 48, textAlign: 'center', opacity: 0.5 }}>Loading application catalog…</div>
        ) : apps.length === 0 ? (
          <div className="card">
            <EmptyState
              icon={<Package size={44} style={{ opacity: 0.25 }} />}
              title="No MSI Applications Registered"
              description="Drag & drop a local .msi file onto this page or register an HTTPS installer URL to push silent installs to Windows 10/11 devices and groups."
              action={
                <ActionButton
                  icon={<Upload size={16} />}
                  label="Upload or Add MSI"
                  onClick={() => { setDroppedFile(null); setCreating(true) }}
                />
              }
            />
          </div>
        ) : (
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="table-wrap" style={{ border: 'none', borderRadius: 0 }}>
              <table className="table-static">
                <thead>
                  <tr>
                    <th>Application</th>
                    <th>Version & Size</th>
                    <th>MSI ProductCode</th>
                    <th>Installed</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {apps.map(app => {
                    const isLocal = app.source_type === 'upload'
                    return (
                      <tr key={app.id}>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                            <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>{app.name}</span>
                            <span
                              style={{
                                fontSize: '0.68rem',
                                fontWeight: 600,
                                padding: '2px 8px',
                                borderRadius: 999,
                                background: isLocal ? 'rgba(208, 188, 255, 0.14)' : 'rgba(255, 255, 255, 0.06)',
                                color: isLocal ? 'var(--md-sys-color-primary)' : 'var(--md-sys-color-on-surface-variant)',
                              }}
                              title={isLocal ? `Hosted locally by Latchz (${app.original_filename || 'package.msi'})` : app.content_url}
                            >
                              {isLocal
                                ? `Hosted · ${app.original_filename || 'local.msi'}`
                                : app.winget_package_id
                                  ? `WinGet · ${app.winget_package_id}`
                                  : 'HTTPS URL'}
                            </span>
                          </div>
                          <div style={{ fontSize: '0.78rem', opacity: 0.6 }}>
                            {app.publisher || 'Unknown Publisher'} · <span className="mono">{app.command_line}</span>
                          </div>
                        </td>
                        <td>
                          <div style={{ fontWeight: 600 }}>{app.version}</div>
                          <div style={{ fontSize: '0.75rem', opacity: 0.55 }}>{formatBytes(app.file_size_bytes)}</div>
                          {(app.auto_updated_count ?? 0) > 0 && (
                            <div style={{ fontSize: '0.71rem', color: 'var(--md-sys-color-primary)', marginTop: 2 }}>
                              {app.auto_updated_count} device(s) auto-updated newer
                            </div>
                          )}
                          {(app.outdated_count ?? 0) > 0 && (
                            <div style={{ fontSize: '0.71rem', opacity: 0.7, marginTop: 2 }}>
                              {app.outdated_count} device(s) behind catalog
                            </div>
                          )}
                        </td>
                        <td>
                          <div className="mono" style={{ fontSize: '0.78rem' }}>{app.product_code}</div>
                          <div className="mono" style={{ fontSize: '0.68rem', opacity: 0.45 }}>
                            SHA-256: {app.sha256.slice(0, 12)}…
                          </div>
                        </td>
                        <td>
                          <Badge
                            status={app.installed_count > 0 && app.installed_count >= app.target_device_count ? 'compliant' : 'pending'}
                            label={`${app.installed_count} / ${app.target_device_count} devices`}
                            dot
                          />
                          {app.group_count > 0 && (
                            <div style={{ fontSize: '0.72rem', opacity: 0.55, marginTop: 4 }}>
                              {app.group_count} group(s) assigned
                            </div>
                          )}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'inline-flex', gap: 8 }}>
                            {(!isLocal || !!app.winget_package_id) && (
                              <button
                                className="btn btn-sm btn-secondary"
                                disabled={refreshingId === app.id}
                                title="Check microsoft/winget-pkgs for a newer MSI seed installer"
                                onClick={() => void refreshWinGetSeed(app)}
                              >
                                <RefreshCw size={13} className={refreshingId === app.id ? 'spin' : ''} />
                                {refreshingId === app.id ? 'Checking…' : 'Check Update'}
                              </button>
                            )}
                            <button className="btn btn-sm btn-primary" onClick={() => setDeploying(app)}>
                              <Download size={14} /> Deploy
                            </button>
                            <button
                              className="btn btn-sm btn-secondary"
                              aria-label={`Delete ${app.name}`}
                              style={{ color: 'var(--md-sys-color-error)' }}
                              onClick={() => setConfirmDelete(app)}
                            >
                              <Trash2 size={14} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {creating && (
        <CreateAppModal
          initialFile={droppedFile}
          initialMode={createMode}
          onClose={() => { setCreating(false); setDroppedFile(null) }}
          onCreated={created => {
            setCreating(false)
            setDroppedFile(null)
            setApps(prev => [created, ...prev])
            setDeploying(created)
          }}
        />
      )}

      {deploying && (
        <DeployAppModal
          app={deploying}
          devices={devices}
          groups={groups}
          onClose={() => setDeploying(null)}
          onChanged={load}
        />
      )}

      {confirmDelete && (
        <Modal
          open={true}
          onClose={() => setConfirmDelete(null)}
          title="Remove Application"
          footer={
            <>
              <button className="btn btn-secondary" onClick={() => setConfirmDelete(null)}>Cancel</button>
              <button className="btn btn-primary" style={{ background: 'var(--md-sys-color-error)' }} onClick={removeApp}>
                Remove from Catalog
              </button>
            </>
          }
        >
          <p style={{ margin: 0, lineHeight: 1.5 }}>
            Remove <strong>{confirmDelete.name}</strong> ({confirmDelete.version}) from the Latchz catalog?
            {confirmDelete.source_type === 'upload' ? ' Its hosted .msi package file will also be deleted from server storage.' : ''}
            {' '}Existing installations on devices will remain unless uninstalled first.
          </p>
        </Modal>
      )}
    </Layout>
  )
}
