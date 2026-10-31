// @vitest-environment node
import { describe, it, expect } from 'vitest'
import {
  PwsError,
  NotFoundError,
  ValidationError,
  AuthRequiredError,
  PwsServerError
} from '@interop/pws-client'
import { isStorageUnreachable } from '../../src/lib/storageErrors'

describe('isStorageUnreachable', () => {
  it('returns true for a network failure (PwsError with no status)', () => {
    const err = new PwsError('NetworkError when attempting to fetch resource', {
      cause: new TypeError('NetworkError when attempting to fetch resource')
    })
    expect(isStorageUnreachable(err)).toBe(true)
  })

  it('returns true for a 5xx server fault', () => {
    const err = new PwsServerError('Bad Gateway', { status: 502 })
    expect(isStorageUnreachable(err)).toBe(true)
  })

  it('returns false for a 404 not-found / unauthorized', () => {
    const err = new NotFoundError('Not Found', { status: 404 })
    expect(isStorageUnreachable(err)).toBe(false)
  })

  it('returns false for a 400 validation error', () => {
    const err = new ValidationError('Bad Request', { status: 400 })
    expect(isStorageUnreachable(err)).toBe(false)
  })

  it('returns false for a 401 auth-required error', () => {
    const err = new AuthRequiredError('Unauthorized', { status: 401 })
    expect(isStorageUnreachable(err)).toBe(false)
  })

  it('returns false for a non-PwsError', () => {
    expect(isStorageUnreachable(new Error('boom'))).toBe(false)
    expect(isStorageUnreachable(undefined)).toBe(false)
  })

  it('returns true for a PwsError (no status) wrapped via cause', () => {
    const inner = new PwsError(
      'NetworkError when attempting to fetch resource',
      {
        cause: new TypeError('NetworkError when attempting to fetch resource')
      }
    )
    const wrapped = new Error('Failed to configure space', { cause: inner })
    expect(isStorageUnreachable(wrapped)).toBe(true)
  })

  it('returns true for a PwsServerError wrapped via cause', () => {
    const inner = new PwsServerError('Bad Gateway', { status: 502 })
    const wrapped = new Error('Failed to configure collection', {
      cause: inner
    })
    expect(isStorageUnreachable(wrapped)).toBe(true)
  })

  it('returns false for an ordinary error wrapped via cause', () => {
    const wrapped = new Error('Failed to configure space', {
      cause: new Error('something else')
    })
    expect(isStorageUnreachable(wrapped)).toBe(false)
  })

  it('returns true for a PwsError double-wrapped via nested cause', () => {
    const inner = new PwsServerError('Service Unavailable', { status: 503 })
    const mid = new Error('collection.configure failed', { cause: inner })
    const outer = new Error('setup failed', { cause: mid })
    expect(isStorageUnreachable(outer)).toBe(true)
  })

  it('does not hang on a cause cycle', () => {
    const first = new Error('first')
    const second = new Error('second')
    ;(first as { cause?: unknown }).cause = second
    ;(second as { cause?: unknown }).cause = first
    expect(isStorageUnreachable(first)).toBe(false)
  })
})
