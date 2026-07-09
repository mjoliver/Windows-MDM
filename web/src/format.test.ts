import { describe, it, expect } from 'vitest'
import { formatResultCode, safeHttpUrl, timeAgo } from './format'

describe('formatResultCode', () => {
  it('formats numeric codes as uppercase hex', () => {
    expect(formatResultCode('200')).toBe('0xC8')
    expect(formatResultCode('404')).toBe('0x194')
  })
  it('passes through already-hex codes', () => {
    expect(formatResultCode('0x80070002')).toBe('0X80070002')
  })
  it('does not render NaN for non-numeric codes', () => {
    expect(formatResultCode('not-a-number')).toBe('not-a-number')
    expect(formatResultCode('')).toBe('')
  })
})

describe('safeHttpUrl', () => {
  it('allows http(s) URLs', () => {
    expect(safeHttpUrl('https://example.com/x')).toBe('https://example.com/x')
    expect(safeHttpUrl('http://example.com/')).toBe('http://example.com/')
  })
  it('rejects dangerous schemes', () => {
    expect(safeHttpUrl('javascript:alert(1)')).toBeNull()
    expect(safeHttpUrl('data:text/html,x')).toBeNull()
  })
  it('rejects malformed/relative input', () => {
    expect(safeHttpUrl('not a url')).toBeNull()
    expect(safeHttpUrl('/relative/path')).toBeNull()
  })
})

describe('timeAgo', () => {
  it('returns fallback for null input', () => {
    expect(timeAgo(null)).toBe('Never')
    expect(timeAgo(null, 'Unknown')).toBe('Unknown')
  })

  it('returns fallback for empty string', () => {
    expect(timeAgo('')).toBe('Never')
  })

  it('returns fallback for invalid date', () => {
    expect(timeAgo('not-a-date')).toBe('Never')
  })

  it('returns "Just now" for very recent times', () => {
    const now = new Date().toISOString()
    expect(timeAgo(now)).toBe('Just now')
  })

  it('returns minutes ago for recent times', () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60_000).toISOString()
    expect(timeAgo(fiveMinAgo)).toBe('5m ago')
  })

  it('returns hours ago for times within 24h', () => {
    const threeHoursAgo = new Date(Date.now() - 3 * 3_600_000).toISOString()
    expect(timeAgo(threeHoursAgo)).toBe('3h ago')
  })

  it('returns days ago for older times', () => {
    const twoDaysAgo = new Date(Date.now() - 2 * 86_400_000).toISOString()
    expect(timeAgo(twoDaysAgo)).toBe('2d ago')
  })

  it('handles future dates without crashing', () => {
    const future = new Date(Date.now() + 3_600_000).toISOString()
    // Future date produces negative diff, Math.floor of negative minutes/60 = 0, so "0h ago"
    const result = timeAgo(future)
    expect(result).not.toBe('Never')
  })
})
