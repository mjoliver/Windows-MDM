// Pure formatting/validation helpers (no DOM dependencies) so they are easy to
// unit test and reuse across pages.

// formatResultCode renders a SyncML status code as hex when numeric, leaving
// already-hex or non-numeric codes intact (avoids rendering "0xNaN").
export function formatResultCode(code: string): string {
  if (code.startsWith('0x')) return code.toUpperCase()
  const n = Number(code)
  return Number.isFinite(n) && code.trim() !== '' ? `0x${n.toString(16).toUpperCase()}` : code
}

// safeHttpUrl returns the URL only if it is an absolute http(s) URL; otherwise
// null. This blocks javascript:/data: scheme injection via untrusted URLs (e.g.
// the server-provided support_url shown on the login page).
export function safeHttpUrl(raw: string): string | null {
  try {
    const u = new URL(raw)
    return (u.protocol === 'http:' || u.protocol === 'https:') ? u.href : null
  } catch {
    return null
  }
}

// timeAgo returns a human-readable relative time string for the given ISO date.
// Returns the fallback string when iso is null or invalid.
export function timeAgo(iso: string | null, fallback = 'Never'): string {
  if (!iso) return fallback
  const diff = Date.now() - new Date(iso).getTime()
  if (Number.isNaN(diff)) return fallback
  const m = Math.floor(diff / 60000)
  if (m < 1)   return 'Just now'
  if (m < 60)  return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24)  return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}