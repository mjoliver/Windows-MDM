import { describe, it, expect } from 'vitest'
import { formatResultCode, safeHttpUrl } from './format'

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
