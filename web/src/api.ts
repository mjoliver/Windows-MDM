// API client — typed wrapper around fetch for all Latchz REST endpoints

const BASE = '/api'

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'include',
  })
  if (res.status === 401) {
    window.location.href = '/login'
    throw new Error('unauthenticated')
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error || res.statusText)
  }
  if (res.status === 204) return null as T
  return res.json()
}

const get  = <T>(path: string) => req<T>('GET', path)
const post = <T>(path: string, body?: unknown) => req<T>('POST', path, body)
const put  = <T>(path: string, body?: unknown) => req<T>('PUT', path, body)
const del  = <T>(path: string, body?: unknown) => req<T>('DELETE', path, body)

// enc encodes a path segment so an id containing / ? # .. cannot retarget the
// request (path injection).
const enc = encodeURIComponent

// ── Types ──────────────────────────────────────────────────────────────────

export interface Me {
  email: string
  display_name: string
  role: string
}

export interface Device {
  id: string
  hardware_id: string
  device_name: string
  pending_hostname?: string
  os_version: string
  os_build: string
  manufacturer: string
  model: string
  serial_number: string
  enrolled_at: string
  enrolled_by: string
  last_checkin: string | null
  compliance_status: 'compliant' | 'non_compliant' | 'unknown' | 'pending'
  enrollment_state?: 'enrolled' | 'retiring' | 'retired'
  retired_at?: string | null
  is_active: boolean
}

export interface DeviceCommand {
  id: number
  type: string
  oma_uri: string
  status: 'pending' | 'sent' | 'success' | 'failed'
  created_at: string
  sent_at: string | null
  completed_at: string | null
  result_code: string
  result_info: string
}

export interface Profile {
  id: string
  name: string
  description: string
  created_by: string
  created_at: string
  updated_at: string
  setting_count?: number
  settings?: PolicySetting[]
}

export interface PolicySetting {
  catalog_id: number
  oma_uri: string
  display_name: string
  description: string
  data_type: string
  desired_value: string
  allowed_values?: { value: string; label: string }[]
}

export interface DynamicGroupRule {
  field: string
  operator: string
  value: string
}

export interface Group {
  id: string
  name: string
  description: string
  is_dynamic: boolean
  match_mode: 'all' | 'any'
  dynamic_rules: DynamicGroupRule[]
  created_at: string
  device_count: number
  profile_count: number
}

export interface CatalogEntry {
  id: number
  oma_uri: string
  display_name: string
  description: string
  category: string
  csp_name: string
  data_type: string
  allowed_values: string
  default_value: string
  min_os_version: string
  is_deprecated: boolean
}

export interface CatalogPage {
  entries: CatalogEntry[]
  total: number
  limit: number
  offset: number
}

export interface FleetCompliance {
  summary: {
    total_devices: number
    compliant_devices: number
    non_compliant_devices: number
    unknown_devices: number
    compliance_percent: number
  }
  top_issues: { oma_uri: string; display_name: string; non_compliant_count: number }[]
}

export interface DeviceCompliance {
  device_id: string
  device_name: string
  compliant: number
  non_compliant: number
  unknown: number
  records: {
    oma_uri: string
    display_name: string
    csp_name: string
    desired_value: string
    actual_value: string
    is_compliant: boolean | null
    checked_at: string
  }[]
}

export interface DevicePosture {
  device_id: string
  collected: boolean
  total_ram_mb: number | null
  total_storage_mb: number | null
  free_storage_mb: number | null
  bios_version: string
  os_platform: string
  tpm_version: string
  secure_boot_state: number | null
  secure_boot_label: string
  encryption_status: number | null
  encryption_label: string
  antivirus_status: number | null
  antivirus_label: string
  firewall_status: number | null
  firewall_label: string
  updated_at: string | null
  wns_enabled: boolean
  wns_channel_active: boolean
  wns_updated_at: string | null
  wns_last_push_at: string | null
  wns_last_push_status: string
}

export interface FleetPostureSummary {
  total_active_devices: number
  posture_reported_devices: number
  secure_boot_enabled: number
  bitlocker_encrypted: number
  antivirus_healthy: number
  firewall_healthy: number
}

export interface UserSummary {
  id: string
  email: string
  display_name: string
  role: 'super_admin' | 'admin' | 'user'
  auth_provider: 'builtin' | 'oidc'
  has_password: boolean
  created_at: string
  last_login: string | null
}

export interface AuditEntry {
  id: number
  user_email: string
  action: string
  target_type: string
  target_id: string
  details: string
  ip_address: string
  created_at: string
}

export interface AuditPage {
  entries: AuditEntry[]
  total: number
  limit: number
  offset: number
}

export interface MSIInspectResult {
  product_code: string
  name: string
  version: string
  publisher: string
  upgrade_code: string
  sha256: string
  file_size_bytes: number
}

export interface MSIApp {
  id: string
  name: string
  publisher: string
  version: string
  product_code: string
  upgrade_code: string
  content_url: string
  source_type?: 'upload' | 'url'
  original_filename?: string
  winget_package_id?: string
  winget_arch?: string
  sha256: string
  file_size_bytes: number
  command_line: string
  timeout_minutes: number
  retry_count: number
  retry_interval_minutes: number
  created_at: string
  updated_at: string
  group_count: number
  installed_count: number
  target_device_count: number
  auto_updated_count?: number
  outdated_count?: number
}

export interface DeviceAppInstall {
  device_id: string
  device_name: string
  app_id: string
  app_name: string
  publisher: string
  version: string
  product_code: string
  installed_version: string
  installed_product_code: string
  version_state: 'up_to_date' | 'auto_updated' | 'update_available' | 'unknown' | string
  desired_action: 'install' | 'uninstall'
  status_code: number | null
  status_label: string
  last_error: string
  last_error_desc: string
  updated_at: string
}

export interface SoftwareInventoryItem {
  app_key: string
  name: string
  publisher: string
  version: string
  source: 'msi' | 'win32' | string
  product_code: string
  upgrade_code: string
  install_date: string
  install_location: string
  managed_app_id?: string
  catalog_version?: string
  version_state?: 'up_to_date' | 'auto_updated' | 'update_available' | 'unknown' | string
  updated_at: string
}

export interface DeviceSoftwareInventory {
  device_id: string
  total: number
  last_synced_at: string | null
  items: SoftwareInventoryItem[]
}

export interface MSIAppDetail {
  app: MSIApp
  group_ids: string[]
  installs: DeviceAppInstall[]
}

export interface WinGetSearchResult {
  package_id: string
  name: string
  publisher: string
  description: string
  homepage?: string
  tags?: string[]
  curated_msi: boolean
}

export interface WinGetResolvedMSI {
  package_id: string
  name: string
  publisher: string
  description: string
  version: string
  architecture: string
  installer_type: string
  installer_url: string
  sha256: string
  product_code: string
  upgrade_code: string
  silent_args: string
}

export interface BitLockerPolicy {
  enabled: boolean
  require_device_encryption: boolean
  silent_encryption: boolean
  allow_standard_user: boolean
  os_drive_cipher: number
  os_drive_cipher_label: string
  fixed_drive_cipher: number
  fixed_drive_cipher_label: string
  removable_drive_cipher: number
  removable_drive_cipher_label: string
  target_all_devices: boolean
  group_ids: string[]
  escrowed_devices: number
  total_escrowed_keys: number
  updated_by: string
  updated_at: string | null
  enforced_devices?: number
  commands_queued?: number
}

export interface RecoveryKeyMeta {
  id: string
  device_id: string
  volume_letter: string
  protector_id: string
  key_hint: string
  source: string
  escrowed_by: string
  created_at: string
  updated_at: string
}

export interface DeviceBitLocker {
  device_id: string
  enforced: boolean
  encryption_status: number | null
  encryption_label: string
  status_reasons: string[]
  recovery_keys: RecoveryKeyMeta[]
}

export interface UpdateRing {
  id: string
  name: string
  description: string
  allow_auto_update: number
  quality_deferral_days: number
  feature_deferral_days: number
  active_hours_start: number
  active_hours_end: number
  quality_deadline_days: number
  feature_deadline_days: number
  grace_period_days: number
  quality_pause_start: string
  feature_pause_start: string
  quality_paused: boolean
  feature_paused: boolean
  target_all_devices: boolean
  priority: number
  group_ids: string[]
  device_count: number
  created_at: string
  updated_at: string
  governed_devices?: number
  commands_queued?: number
}

export interface DeviceUpdateTelemetry {
  device_id: string
  ring_id: string
  ring_name: string
  quality_deferral_days: number | null
  feature_deferral_days: number | null
  active_hours_start: number | null
  active_hours_end: number | null
  quality_paused: boolean
  feature_paused: boolean
  last_scan_time: string
  updated_at: string | null
}

export interface LAPSPolicy {
  enabled: boolean
  account_prefix: string
  password_length: number
  rotation_days: number
  rotate_after_reveal_minutes: number
  target_all_devices: boolean
  group_ids: string[]
  active_devices: number
  rotating_devices: number
  updated_by: string
  updated_at: string | null
  governed_devices?: number
  commands_queued?: number
}

export interface DeviceLAPSStatus {
  device_id: string
  governed: boolean
  status: 'unconfigured' | 'provisioning' | 'active' | 'rotating' | 'revoked' | 'failed' | string
  active_account: string
  previous_account: string
  pending_account: string
  has_active_password: boolean
  has_previous_password: boolean
  has_pending_password: boolean
  last_error: string
  last_rotated_at: string | null
  expires_at: string | null
  updated_at: string | null
}

export interface RevealedLAPSCredentials {
  device_id: string
  status: string
  active_account: string
  active_password?: string
  previous_account?: string
  previous_password?: string
  pending_account?: string
  pending_password?: string
  expires_at: string | null
  rotate_after_reveal_minutes: number
}

export interface EndpointSecurityPolicy {
  enabled: boolean
  allow_realtime_monitoring: boolean
  allow_behavior_monitoring: boolean
  allow_cloud_protection: boolean
  cloud_block_level: number
  pua_protection: number
  enable_network_protection: number
  check_sigs_before_scan: boolean
  firewall_domain_enabled: boolean
  firewall_private_enabled: boolean
  firewall_public_enabled: boolean
  block_inbound_domain: boolean
  block_inbound_private: boolean
  block_inbound_public: boolean
  target_all_devices: boolean
  group_ids: string[]
  enforced_devices: number
  commands_queued?: number
  updated_by: string
  updated_at: string | null
}

export interface FirewallRule {
  id: string
  rule_key: string
  name: string
  description: string
  direction: 'IN' | 'OUT'
  action: number
  protocol: number
  local_port_ranges: string
  remote_port_ranges: string
  profiles: number
  enabled: boolean
  target_all_devices: boolean
  group_ids: string[]
  deployed_devices: number
  created_by: string
  created_at: string
  updated_at: string
  commands_queued?: number
}

export interface DeviceSecurityState {
  device_id: string
  baseline_enforced: boolean
  last_defender_action: string
  last_defender_action_at: string | null
  deployed_rule_keys: string[]
  updated_at: string | null
}

export interface ConnectivityProfile {
  id: string
  name: string
  profile_type: 'root_ca' | 'intermediate_ca' | 'client_cert' | 'wifi' | 'vpn'
  cert_thumbprint?: string
  cert_subject?: string
  cert_not_after?: string | null
  client_cert_subject_template?: string
  client_cert_validity_days?: number
  client_cert_exportable?: boolean
  client_cert_key_location?: number
  wifi_ssid?: string
  wifi_security?: string
  wifi_auto_connect: boolean
  wifi_hidden: boolean
  wifi_eap_server_names?: string
  has_wifi_psk: boolean
  vpn_server?: string
  vpn_protocol?: string
  vpn_auth_method?: string
  vpn_split_tunnel: boolean
  vpn_always_on: boolean
  vpn_trusted_network?: string
  target_all_devices: boolean
  group_ids: string[]
  deployed_devices: number
  created_by: string
  created_at: string
  updated_at: string
  commands_queued?: number
}

export interface DeviceConnectivityItem {
  profile_id: string
  profile_name: string
  profile_type: string
  delete_oma_uri: string
  issued_thumbprint?: string
  issued_subject?: string
  issued_not_after?: string | null
  updated_at: string
}

export interface DeviceLockdownPolicy {
  enabled: boolean
  usb_storage_mode: 'allow' | 'read_only' | 'block_all'
  require_password: boolean
  min_password_length: number
  alphanumeric_required: boolean
  max_inactivity_minutes: number
  max_failed_attempts: number
  allow_camera: boolean
  allow_bluetooth: boolean
  kiosk_mode: 'none' | 'single_app'
  kiosk_account: string
  kiosk_app_aumid: string
  target_all_devices: boolean
  group_ids: string[]
  enforced_devices: number
  commands_queued?: number
  updated_by: string
  updated_at: string | null
}

export interface DeviceLockdownState {
  device_id: string
  enforced: boolean
  kiosk_enforced: boolean
  updated_at: string | null
}

export interface ASRRuleCatalogEntry {
  guid: string
  name: string
  category: string
  recommended_mode: number
}

export interface EndpointHardeningPolicy {
  enabled: boolean
  asr_rules: Record<string, number>
  active_asr_count: number
  enable_smartscreen_shell: boolean
  prevent_smartscreen_override: boolean
  app_install_control: number
  submit_samples_consent: number
  disable_local_admin_merge: boolean
  target_all_devices: boolean
  group_ids: string[]
  enforced_devices: number
  commands_queued?: number
  updated_by: string
  updated_at: string | null
  catalog: ASRRuleCatalogEntry[]
}

export interface DeviceEndpointHardeningState {
  device_id: string
  enforced: boolean
  active_asr_count: number
  updated_at: string | null
}

export interface WebhookEndpoint {
  id: string
  name: string
  url: string
  format: 'json' | 'slack' | 'teams' | 'discord'
  has_secret: boolean
  events: string[]
  enabled: boolean
  created_by: string
  created_at: string
  updated_at: string
}

export interface WebhookDeliveryItem {
  id: number
  webhook_id: string
  webhook_name: string
  event_type: string
  status_code: number
  success: boolean
  error: string
  delivered_at: string
}

export interface ComplianceAutomationSettings {
  auto_remediate: boolean
  remediation_count: number
  last_remediated_at: string | null
  updated_by: string
  updated_at: string | null
}

export interface BulkEnrollmentTokenItem {
  id: string
  name: string
  token_prefix: string
  token?: string
  auto_group_id: string
  auto_group_name: string
  max_uses: number
  use_count: number
  expires_at: string | null
  revoked: boolean
  created_by: string
  created_at: string
}

// ── API calls ──────────────────────────────────────────────────────────────

export const api = {
  me: () => get<Me>('/me'),

  // Logout hits the auth endpoint (outside /api base path)
  logout: () =>
    fetch('/auth/logout', { method: 'POST', credentials: 'include' })
      .then(r => { if (!r.ok) throw new Error('logout failed'); return { ok: true } as const })
      .catch(e => { throw e }),

  // Devices
  devices: {
    list:    ()          => get<Device[]>('/devices'),
    get:     (id: string) => get<{ device: Device; pending_commands: number }>(`/devices/${enc(id)}`),
    unenroll:(id: string) => del<{ status: string }>(`/devices/${enc(id)}`),
    lock:    (id: string) => post<{ status: string; queue_id: number }>(`/devices/${enc(id)}/lock`),
    reboot:  (id: string) => post<{ status: string; queue_id: number }>(`/devices/${enc(id)}/reboot`),
    rename:  (id: string, hostname: string, rebootNow = false) =>
      post<{ status: string; hostname: string; reboot_now: boolean; queue_id: number }>(`/devices/${enc(id)}/rename`, { hostname, reboot_now: rebootNow }),
    retire:  (id: string) => post<{ status: string; enrollment_state: string; queue_id: number }>(`/devices/${enc(id)}/retire`, { confirm: true }),
    wipe:    (id: string) => post<{ status: string }>(`/devices/${enc(id)}/wipe`, { confirm: true }),
    sync:    (id: string) => post<{ status: string; commands_queued: number }>(`/devices/${enc(id)}/sync`),
    getCommands: (id: string) => get<{ commands: DeviceCommand[] }>(`/devices/${enc(id)}/commands`),
    apps:    (id: string) => get<DeviceAppInstall[]>(`/devices/${enc(id)}/apps`),
    inventory: (id: string, q = '') =>
      get<DeviceSoftwareInventory>(`/devices/${enc(id)}/inventory${q.trim() ? `?q=${enc(q.trim())}` : ''}`),
    syncInventory: (id: string) =>
      post<{ status: string; commands_queued: number }>(`/devices/${enc(id)}/inventory/sync`),
    posture: (id: string) => get<DevicePosture>(`/devices/${enc(id)}/posture`),
    refreshPosture: (id: string) => post<{ status: string; commands_queued: number }>(`/devices/${enc(id)}/posture/refresh`),
    security: (id: string) => get<DeviceSecurityState>(`/devices/${enc(id)}/security`),
    defenderScan: (id: string, scanType: 'quick' | 'full' = 'quick') =>
      post<{ status: string; scan_type: string; commands_queued: number }>(`/devices/${enc(id)}/defender/scan`, { scan_type: scanType }),
    defenderUpdateSignatures: (id: string) =>
      post<{ status: string; commands_queued: number }>(`/devices/${enc(id)}/defender/update-signatures`),
    connectivity: (id: string) => get<DeviceConnectivityItem[]>(`/devices/${enc(id)}/connectivity`),
    lockdown: (id: string) => get<DeviceLockdownState>(`/devices/${enc(id)}/lockdown`),
    hardening: (id: string) => get<DeviceEndpointHardeningState>(`/devices/${enc(id)}/hardening`),
    pushWake: (id: string) => post<{ status: string; wns_status?: string }>(`/devices/${enc(id)}/push`),
  },

  // Profiles
  profiles: {
    list:   () => get<Profile[]>('/profiles'),
    get:    (id: string) => get<Profile>(`/profiles/${enc(id)}`),
    create: (data: { name: string; description: string }) => post<Profile>('/profiles', data),
    update: (id: string, data: Partial<Profile & { settings: PolicySetting[] }>) =>
      put<Profile>(`/profiles/${enc(id)}`, data),
    delete: (id: string) => del<{ status: string }>(`/profiles/${enc(id)}`),
  },

  // Groups
  groups: {
    list:   () => get<Group[]>('/groups'),
    create: (data: {
      name: string
      description: string
      is_dynamic?: boolean
      match_mode?: 'all' | 'any'
      dynamic_rules?: DynamicGroupRule[]
    }) => post<Group>('/groups', data),
    update: (id: string, data: {
      name: string
      description: string
      is_dynamic?: boolean
      match_mode?: 'all' | 'any'
      dynamic_rules?: DynamicGroupRule[]
    }) => put(`/groups/${enc(id)}`, data),
    delete: (id: string) => del(`/groups/${enc(id)}`),
    reconcile: (id: string) =>
      post<{ status: string; added: number; removed: number; device_count: number }>(`/groups/${enc(id)}/reconcile`),
    previewRules: (matchMode: 'all' | 'any', dynamicRules: DynamicGroupRule[]) =>
      post<{ match_count: number; devices: { id: string; device_name: string; os_version: string; model: string }[] }>('/groups/preview-rules', {
        match_mode: matchMode,
        dynamic_rules: dynamicRules,
      }),
    assignDevices: (id: string, deviceIds: string[], action: 'add'|'remove') =>
      put(`/groups/${enc(id)}/devices`, { device_ids: deviceIds, action }),
    assignProfiles: (id: string, profileIds: string[], action: 'add'|'remove') =>
      put(`/groups/${enc(id)}/profiles`, { profile_ids: profileIds, action }),
  },

  // Catalog
  catalog: {
    list:  (params?: { search?: string; csp?: string; limit?: number; offset?: number }) => {
      const q = new URLSearchParams()
      if (params?.search) q.set('search', params.search)
      if (params?.csp)    q.set('csp', params.csp)
      if (params?.limit)  q.set('limit', String(params.limit))
      if (params?.offset) q.set('offset', String(params.offset))
      return get<CatalogPage>(`/catalog?${q}`)
    },
    csps: () => get<{ name: string; count: number }[]>('/catalog/csps'),
  },

  // Compliance & Security Posture
  compliance: {
    fleet:          () => get<FleetCompliance>('/compliance'),
    device:         (id: string) => get<DeviceCompliance>(`/compliance/${enc(id)}`),
    postureSummary: () => get<FleetPostureSummary>('/posture/summary'),
  },

  // Administration: Users & Roles
  users: {
    list:   () => get<UserSummary[]>('/users'),
    create: (data: { email: string; display_name?: string; role: string; auth_provider?: string; password?: string }) =>
      post<UserSummary>('/users', data),
    update: (id: string, data: { display_name?: string; role?: string; auth_provider?: string; password?: string }) =>
      put<UserSummary>(`/users/${enc(id)}`, data),
    delete: (id: string) => del<{ status: string; id: string }>(`/users/${enc(id)}`),
  },

  // Administration: Audit Log
  audit: {
    list: (params?: { search?: string; action?: string; target_type?: string; limit?: number; offset?: number }) => {
      const q = new URLSearchParams()
      if (params?.search)      q.set('search', params.search)
      if (params?.action)      q.set('action', params.action)
      if (params?.target_type) q.set('target_type', params.target_type)
      if (params?.limit)       q.set('limit', String(params.limit))
      if (params?.offset)      q.set('offset', String(params.offset))
      return get<AuditPage>(`/audit?${q}`)
    },
  },

  // Applications (Win32 MSI via EnterpriseDesktopAppManagement CSP)
  apps: {
    list:    () => get<MSIApp[]>('/apps'),
    get:     (id: string) => get<MSIAppDetail>(`/apps/${enc(id)}`),
    inspect: (contentUrl: string) => post<MSIInspectResult>('/apps/inspect', { content_url: contentUrl }),
    upload:  (
      file: File,
      fields?: {
        name?: string
        publisher?: string
        version?: string
        command_line?: string
      },
      onProgress?: (loaded: number, total: number) => void
    ): Promise<MSIApp> =>
      new Promise((resolve, reject) => {
        const fd = new FormData()
        if (fields?.name)         fd.append('name', fields.name)
        if (fields?.publisher)    fd.append('publisher', fields.publisher)
        if (fields?.version)      fd.append('version', fields.version)
        if (fields?.command_line) fd.append('command_line', fields.command_line)
        fd.append('file', file)

        const xhr = new XMLHttpRequest()
        xhr.open('POST', `${BASE}/apps/upload`, true)
        xhr.withCredentials = true
        if (onProgress) {
          xhr.upload.onprogress = evt => {
            if (evt.lengthComputable) onProgress(evt.loaded, evt.total)
          }
        }
        xhr.onload = () => {
          if (xhr.status === 401) {
            window.location.href = '/login'
            reject(new Error('unauthenticated'))
            return
          }
          if (xhr.status >= 200 && xhr.status < 300) {
            try {
              resolve(JSON.parse(xhr.responseText) as MSIApp)
            } catch {
              reject(new Error('Invalid JSON response from server'))
            }
            return
          }
          let msg = xhr.statusText || `HTTP ${xhr.status}`
          try {
            const parsed = JSON.parse(xhr.responseText) as { error?: string }
            if (parsed.error) msg = parsed.error
          } catch {
            // ignore non-JSON body
          }
          reject(new Error(msg))
        }
        xhr.onerror = () => reject(new Error('Network error while uploading MSI package'))
        xhr.send(fd)
      }),
    create:  (data: {
      content_url: string
      name?: string
      publisher?: string
      version?: string
      product_code?: string
      upgrade_code?: string
      sha256?: string
      file_size_bytes?: number
      command_line?: string
      timeout_minutes?: number
      retry_count?: number
      retry_interval_minutes?: number
    }) => post<MSIApp>('/apps', data),
    delete:  (id: string) => del<{ status: string }>(`/apps/${enc(id)}`),
    assignGroups: (id: string, groupIds: string[], action: 'add' | 'remove') =>
      put<{ status: string; devices_targeted: number }>(`/apps/${enc(id)}/groups`, { group_ids: groupIds, action }),
    install: (id: string, deviceIds: string[]) =>
      post<{ status: string; devices_targeted: number; commands_queued: number }>(`/apps/${enc(id)}/install`, { device_ids: deviceIds }),
    uninstall: (id: string, deviceIds: string[]) =>
      post<{ status: string; devices_targeted: number }>(`/apps/${enc(id)}/uninstall`, { device_ids: deviceIds }),
    wingetSearch: (q = '') =>
      get<WinGetSearchResult[]>(`/apps/winget/search${q.trim() ? `?q=${enc(q.trim())}` : ''}`),
    wingetResolve: (packageId: string, arch = 'x64') =>
      get<WinGetResolvedMSI>(`/apps/winget/resolve?package_id=${enc(packageId)}&arch=${enc(arch)}`),
    wingetImport: (data: { package_id: string; architecture?: string; command_line?: string }) =>
      post<MSIApp>('/apps/winget/import', data),
    wingetRefresh: (id: string, packageId?: string) =>
      post<{ updated: boolean; previous_version: string; latest_version: string; app: MSIApp }>(
        `/apps/${enc(id)}/winget-refresh`,
        packageId ? { package_id: packageId } : {}
      ),
  },

  // BitLocker CSP & AES-256-GCM Recovery Key Vault
  bitlocker: {
    policy: () => get<BitLockerPolicy>('/bitlocker/policy'),
    updatePolicy: (data: {
      enabled: boolean
      require_device_encryption: boolean
      silent_encryption: boolean
      allow_standard_user: boolean
      os_drive_cipher: number
      fixed_drive_cipher: number
      removable_drive_cipher: number
      target_all_devices: boolean
      group_ids: string[]
    }) => put<BitLockerPolicy>('/bitlocker/policy', data),
    device: (deviceId: string) => get<DeviceBitLocker>(`/devices/${enc(deviceId)}/bitlocker`),
    escrow: (deviceId: string, data: { volume_letter: string; protector_id?: string; recovery_password: string }) =>
      post<RecoveryKeyMeta>(`/devices/${enc(deviceId)}/bitlocker/escrow`, data),
    revealKey: (deviceId: string, keyId: string) =>
      post<{ id: string; device_id: string; volume_letter: string; protector_id: string; recovery_password: string }>(
        `/devices/${enc(deviceId)}/bitlocker/keys/${enc(keyId)}/reveal`
      ),
    deleteKey: (deviceId: string, keyId: string) =>
      del<{ status: string }>(`/devices/${enc(deviceId)}/bitlocker/keys/${enc(keyId)}`),
    rotateKeys: (deviceId: string) =>
      post<{ status: string; request_id: string; commands_queued: number }>(`/devices/${enc(deviceId)}/bitlocker/rotate`),
  },

  // Windows Update Rings (Policy/Config/Update & Update CSPs)
  updates: {
    listRings: () => get<UpdateRing[]>('/updates/rings'),
    getRing:   (id: string) => get<UpdateRing>(`/updates/rings/${enc(id)}`),
    createRing: (data: {
      name: string
      description?: string
      allow_auto_update?: number
      quality_deferral_days: number
      feature_deferral_days: number
      active_hours_start: number
      active_hours_end: number
      quality_deadline_days: number
      feature_deadline_days: number
      grace_period_days: number
      target_all_devices: boolean
      priority?: number
      group_ids: string[]
    }) => post<UpdateRing>('/updates/rings', data),
    updateRing: (id: string, data: {
      name: string
      description?: string
      allow_auto_update?: number
      quality_deferral_days: number
      feature_deferral_days: number
      active_hours_start: number
      active_hours_end: number
      quality_deadline_days: number
      feature_deadline_days: number
      grace_period_days: number
      target_all_devices: boolean
      priority?: number
      group_ids: string[]
    }) => put<UpdateRing>(`/updates/rings/${enc(id)}`, data),
    deleteRing: (id: string) => del<{ status: string; commands_queued: number }>(`/updates/rings/${enc(id)}`),
    pauseRing: (id: string, target: 'quality' | 'feature' | 'both', paused: boolean) =>
      post<UpdateRing>(`/updates/rings/${enc(id)}/pause`, { target, paused }),
    device: (deviceId: string) => get<DeviceUpdateTelemetry>(`/devices/${enc(deviceId)}/updates`),
  },

  // Agentless Cloud LAPS (Accounts CSP + Policy/Config/LocalUsersAndGroups + AES-256-GCM Vault)
  laps: {
    policy: () => get<LAPSPolicy>('/laps/policy'),
    updatePolicy: (data: {
      enabled: boolean
      account_prefix: string
      password_length: number
      rotation_days: number
      rotate_after_reveal_minutes: number
      target_all_devices: boolean
      group_ids: string[]
    }) => put<LAPSPolicy>('/laps/policy', data),
    device: (deviceId: string) => get<DeviceLAPSStatus>(`/devices/${enc(deviceId)}/laps`),
    reveal: (deviceId: string) => post<RevealedLAPSCredentials>(`/devices/${enc(deviceId)}/laps/reveal`),
    rotate: (deviceId: string) =>
      post<{ status: string; pending_account: string; commands_queued: number }>(`/devices/${enc(deviceId)}/laps/rotate`),
  },

  // Endpoint Security: Defender Antivirus + Windows Firewall CSP Baseline & Atomic Rules
  security: {
    policy: () => get<EndpointSecurityPolicy>('/security/policy'),
    updatePolicy: (data: {
      enabled: boolean
      allow_realtime_monitoring: boolean
      allow_behavior_monitoring: boolean
      allow_cloud_protection: boolean
      cloud_block_level: number
      pua_protection: number
      enable_network_protection: number
      check_sigs_before_scan: boolean
      firewall_domain_enabled: boolean
      firewall_private_enabled: boolean
      firewall_public_enabled: boolean
      block_inbound_domain: boolean
      block_inbound_private: boolean
      block_inbound_public: boolean
      target_all_devices: boolean
      group_ids: string[]
    }) => put<EndpointSecurityPolicy>('/security/policy', data),
    listFirewallRules: () => get<FirewallRule[]>('/security/firewall-rules'),
    createFirewallRule: (data: {
      name: string
      rule_key?: string
      description?: string
      direction: 'IN' | 'OUT'
      action: number
      protocol: number
      local_port_ranges?: string
      remote_port_ranges?: string
      profiles?: number
      enabled?: boolean
      target_all_devices?: boolean
      group_ids?: string[]
    }) => post<FirewallRule>('/security/firewall-rules', data),
    deleteFirewallRule: (id: string) =>
      del<{ deleted: boolean; rule_key: string; commands_queued: number }>(`/security/firewall-rules/${enc(id)}`),
  },

  // Connectivity & PKI: RootCATrustedCertificates, PFXCertInstall, WiFi & VPNv2 CSPs
  connectivity: {
    listProfiles: () => get<ConnectivityProfile[]>('/connectivity/profiles'),
    createProfile: (data: {
      name: string
      profile_type: 'root_ca' | 'intermediate_ca' | 'client_cert' | 'wifi' | 'vpn'
      certificate_pem?: string
      client_cert_subject_template?: string
      client_cert_validity_days?: number
      client_cert_exportable?: boolean
      client_cert_key_location?: number
      wifi_ssid?: string
      wifi_security?: string
      wifi_auto_connect?: boolean
      wifi_hidden?: boolean
      wifi_psk?: string
      wifi_eap_server_names?: string
      vpn_server?: string
      vpn_protocol?: string
      vpn_auth_method?: string
      vpn_split_tunnel?: boolean
      vpn_always_on?: boolean
      vpn_trusted_network?: string
      target_all_devices?: boolean
      group_ids?: string[]
    }) => post<ConnectivityProfile>('/connectivity/profiles', data),
    deleteProfile: (id: string) =>
      del<{ deleted: boolean; commands_queued: number }>(`/connectivity/profiles/${enc(id)}`),
  },

  // Device Lockdown: Storage, DeviceLock, Camera/Bluetooth & AssignedAccess Kiosk CSPs
  lockdown: {
    policy: () => get<DeviceLockdownPolicy>('/lockdown/policy'),
    updatePolicy: (data: {
      enabled: boolean
      usb_storage_mode: 'allow' | 'read_only' | 'block_all'
      require_password: boolean
      min_password_length: number
      alphanumeric_required: boolean
      max_inactivity_minutes: number
      max_failed_attempts: number
      allow_camera: boolean
      allow_bluetooth: boolean
      kiosk_mode: 'none' | 'single_app'
      kiosk_account?: string
      kiosk_app_aumid?: string
      target_all_devices: boolean
      group_ids: string[]
    }) => put<DeviceLockdownPolicy>('/lockdown/policy', data),
  },

  // Defender ASR Rules & SmartScreen Hardening CSPs
  hardening: {
    policy: () => get<EndpointHardeningPolicy>('/hardening/policy'),
    updatePolicy: (data: {
      enabled: boolean
      asr_rules: Record<string, number>
      enable_smartscreen_shell: boolean
      prevent_smartscreen_override: boolean
      app_install_control: number
      submit_samples_consent: number
      disable_local_admin_merge: boolean
      target_all_devices: boolean
      group_ids: string[]
    }) => put<EndpointHardeningPolicy>('/hardening/policy', data),
  },

  // Outbound SIEM / Chat Webhooks, Auto-Remediation & Fleet Exports
  webhooks: {
    list: () => get<{ endpoints: WebhookEndpoint[]; supported_events: string[] }>('/webhooks'),
    create: (data: {
      name: string
      url: string
      format: 'json' | 'slack' | 'teams' | 'discord'
      secret?: string
      events?: string[]
      enabled?: boolean
    }) => post<WebhookEndpoint>('/webhooks', data),
    delete: (id: string) => del<{ deleted: boolean; id: string }>(`/webhooks/${enc(id)}`),
    test: (id: string) =>
      post<{ webhook_id: string; event_type: string; status_code: number; success: boolean; error?: string; delivered_at: string }>(
        `/webhooks/${enc(id)}/test`
      ),
    deliveries: () => get<WebhookDeliveryItem[]>('/webhooks/deliveries'),
    automation: () => get<ComplianceAutomationSettings>('/compliance/automation'),
    updateAutomation: (autoRemediate: boolean) =>
      put<ComplianceAutomationSettings>('/compliance/automation', { auto_remediate: autoRemediate }),
  },

  // Bulk Enrollment Tokens & OOBE Staging Bootstrap
  enrollmentTokens: {
    list: () => get<BulkEnrollmentTokenItem[]>('/enrollment/tokens'),
    create: (data: {
      name: string
      auto_group_id?: string
      max_uses: number
      expires_in_days: number
    }) => post<BulkEnrollmentTokenItem>('/enrollment/tokens', data),
    revoke: (id: string, hard = false) =>
      del<{ deleted: boolean; revoked: boolean; id: string }>(`/enrollment/tokens/${enc(id)}${hard ? '?hard=1' : ''}`),
  },
}
