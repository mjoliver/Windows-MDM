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
  os_version: string
  os_build: string
  manufacturer: string
  model: string
  serial_number: string
  enrolled_at: string
  enrolled_by: string
  last_checkin: string | null
  compliance_status: 'compliant' | 'non_compliant' | 'unknown' | 'pending'
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

export interface Group {
  id: string
  name: string
  description: string
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

// ── API calls ──────────────────────────────────────────────────────────────

export const api = {
  me: () => get<Me>('/me'),

  // Devices
  devices: {
    list:    ()          => get<Device[]>('/devices'),
    get:     (id: string) => get<{ device: Device; pending_commands: number }>(`/devices/${id}`),
    unenroll:(id: string) => del<{ status: string }>(`/devices/${id}`),
    lock:    (id: string) => post<{ status: string; queue_id: number }>(`/devices/${id}/lock`),
    wipe:    (id: string) => post<{ status: string }>(`/devices/${id}/wipe`, { confirm: true }),
    sync:    (id: string) => post<{ status: string; commands_queued: number }>(`/devices/${id}/sync`),
    getCommands: (id: string) => get<{ commands: DeviceCommand[] }>(`/devices/${id}/commands`),
  },

  // Profiles
  profiles: {
    list:   () => get<Profile[]>('/profiles'),
    get:    (id: string) => get<Profile>(`/profiles/${id}`),
    create: (data: { name: string; description: string }) => post<Profile>('/profiles', data),
    update: (id: string, data: Partial<Profile & { settings: PolicySetting[] }>) =>
      put<Profile>(`/profiles/${id}`, data),
    delete: (id: string) => del<{ status: string }>(`/profiles/${id}`),
  },

  // Groups
  groups: {
    list:   () => get<Group[]>('/groups'),
    create: (data: { name: string; description: string }) => post<Group>('/groups', data),
    update: (id: string, data: { name: string; description: string }) => put(`/groups/${id}`, data),
    delete: (id: string) => del(`/groups/${id}`),
    assignDevices: (id: string, deviceIds: string[], action: 'add'|'remove') =>
      put(`/groups/${id}/devices`, { device_ids: deviceIds, action }),
    assignProfiles: (id: string, profileIds: string[], action: 'add'|'remove') =>
      put(`/groups/${id}/profiles`, { profile_ids: profileIds, action }),
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

  // Compliance
  compliance: {
    fleet:  () => get<FleetCompliance>('/compliance'),
    device: (id: string) => get<DeviceCompliance>(`/compliance/${id}`),
  },
}
