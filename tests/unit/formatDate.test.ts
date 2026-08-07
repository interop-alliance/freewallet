import { describe, expect, it } from 'vitest'
import { formatDate, formatDateTime } from '@/lib/viewMappers/formatDate'

describe('formatDate', () => {
  it('formats an ISO date into a human-readable form', () => {
    // Noon UTC keeps the calendar day stable across test-runner timezones.
    const formatted = formatDate({
      isoDate: '2025-06-15T12:00:00Z',
      locale: 'en-US'
    })
    expect(formatted).toMatch(/Jun\s+\d{1,2},\s+2025/)
  })

  it('honors an explicit locale', () => {
    const formatted = formatDate({
      isoDate: '2025-06-15T12:00:00Z',
      locale: 'es-ES'
    })
    expect(formatted).toMatch(/2025/)
  })

  it('returns an empty string for falsy input', () => {
    expect(formatDate({ isoDate: '', locale: 'en-US' })).toBe('')
  })

  it('falls back to the raw string on an unparseable date', () => {
    expect(formatDate({ isoDate: 'not-a-date', locale: 'en-US' })).toBe(
      'not-a-date'
    )
  })
})

describe('formatDateTime', () => {
  it('formats a Date into a medium date with short time', () => {
    const formatted = formatDateTime(new Date('2025-06-15T12:00:00Z'), 'en-US')
    expect(formatted).toMatch(/2025/)
  })
})
