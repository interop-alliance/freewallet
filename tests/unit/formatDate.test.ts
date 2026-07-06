import { describe, expect, it } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import {
  formatDate,
  formatDateTime,
  getExpirationDateIso,
  getExpirationInstant
} from '@/lib/viewMappers/formatDate'

describe('formatDate', () => {
  it('formats an ISO date into a human-readable form', () => {
    // Noon UTC keeps the calendar day stable across test-runner timezones.
    const formatted = formatDate({ isoDate: '2025-06-15T12:00:00Z' })
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
    expect(formatDate({ isoDate: '' })).toBe('')
  })

  it('falls back to the raw string on an unparseable date', () => {
    expect(formatDate({ isoDate: 'not-a-date' })).toBe('not-a-date')
  })
})

describe('formatDateTime', () => {
  it('formats a Date into a medium date with short time', () => {
    const formatted = formatDateTime(new Date('2025-06-15T12:00:00Z'))
    expect(formatted).toMatch(/2025/)
  })
})

describe('getExpirationDateIso', () => {
  it('prefers validUntil over expirationDate', () => {
    const vc = {
      validUntil: '2030-01-01T00:00:00Z',
      expirationDate: '2020-01-01T00:00:00Z'
    } as unknown as IVerifiableCredential
    expect(getExpirationDateIso(vc)).toBe('2030-01-01T00:00:00Z')
  })

  it('falls back to the VC 1.x expirationDate', () => {
    const vc = {
      expirationDate: '2020-01-01T00:00:00Z'
    } as unknown as IVerifiableCredential
    expect(getExpirationDateIso(vc)).toBe('2020-01-01T00:00:00Z')
  })

  it('returns an empty string when neither field is present', () => {
    expect(getExpirationDateIso({} as IVerifiableCredential)).toBe('')
  })
})

describe('getExpirationInstant', () => {
  it('returns a Date for a valid expiration', () => {
    const vc = {
      validUntil: '2030-01-01T00:00:00Z'
    } as unknown as IVerifiableCredential
    expect(getExpirationInstant(vc)?.toISOString()).toBe(
      '2030-01-01T00:00:00.000Z'
    )
  })

  it('returns null when there is no expiration date', () => {
    expect(getExpirationInstant({} as IVerifiableCredential)).toBeNull()
  })

  it('returns null for an unparseable expiration date', () => {
    const vc = {
      validUntil: 'not-a-date'
    } as unknown as IVerifiableCredential
    expect(getExpirationInstant(vc)).toBeNull()
  })
})
