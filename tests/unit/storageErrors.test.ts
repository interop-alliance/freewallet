// @vitest-environment node
import { describe, it, expect } from 'vitest'
import {
  WasError,
  NotFoundError,
  ValidationError,
  AuthRequiredError,
  WasServerError
} from '@interop/was-client'
import { isStorageUnreachable } from '../../src/lib/storageErrors'

describe('isStorageUnreachable', () => {
  it('returns true for a network failure (WasError with no status)', () => {
    const err = new WasError('NetworkError when attempting to fetch resource', {
      cause: new TypeError('NetworkError when attempting to fetch resource')
    })
    expect(isStorageUnreachable(err)).toBe(true)
  })

  it('returns true for a 5xx server fault', () => {
    const err = new WasServerError('Bad Gateway', { status: 502 })
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

  it('returns false for a non-WasError', () => {
    expect(isStorageUnreachable(new Error('boom'))).toBe(false)
    expect(isStorageUnreachable(undefined)).toBe(false)
  })

  it('returns true for a WasError (no status) wrapped via cause', () => {
    const inner = new WasError(
      'NetworkError when attempting to fetch resource',
      {
        cause: new TypeError('NetworkError when attempting to fetch resource')
      }
    )
    const wrapped = new Error('Failed to configure space', { cause: inner })
    expect(isStorageUnreachable(wrapped)).toBe(true)
  })

  it('returns true for a WasServerError wrapped via cause', () => {
    const inner = new WasServerError('Bad Gateway', { status: 502 })
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

  it('returns true for a WasError double-wrapped via nested cause', () => {
    const inner = new WasServerError('Service Unavailable', { status: 503 })
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
