// @vitest-environment node
/**
 * Unit tests for the login-failure copy mapping
 * (`src/session/loginErrorKey.ts`): the typed outcome (the key beside the
 * transient refusal's reason), and the per-reason mapping of
 * `TransientLoginUnavailableError` -- the failed-heal pair, the
 * annex-generation family, the copy-less `no-standing` state, and the two
 * configuration refusals.
 */
import { describe, expect, it } from 'vitest'
import { loginErrorKey } from '@/session/loginErrorKey'
import {
  TransientLoginUnavailableError,
  type TransientLoginUnavailableReason
} from '@/session/transientLogin'

function keyFor(reason: TransientLoginUnavailableReason) {
  return loginErrorKey({
    err: new TransientLoginUnavailableError({ reason }),
    label: 'Login'
  })
}

describe('loginErrorKey', () => {
  it('returns the key alone for a non-transient failure', () => {
    const outcome = loginErrorKey({ err: new Error('boom'), label: 'Login' })
    expect(outcome).toEqual({ key: 'auth.errors.setupFailed' })
    expect(outcome.transientReason).toBeUndefined()
  })

  it('carries the transient refusal reason beside the key', () => {
    const outcome = keyFor('no-delegated-clients')
    expect(outcome.transientReason).toBe('no-delegated-clients')
  })

  it('maps the failed-heal pair onto the setup-did-not-finish copy', () => {
    for (const reason of [
      'unpromoted-account',
      'no-user-key-roster'
    ] as const) {
      expect(keyFor(reason).key).toBe('auth.errors.transientSetupIncomplete')
    }
  })

  it('maps the annex-generation family onto the honest refusal', () => {
    for (const reason of [
      'no-delegated-clients',
      'no-clientAnnex-generation',
      'no-generation-delegation'
    ] as const) {
      expect(keyFor(reason).key).toBe('auth.errors.transientUnavailable')
    }
  })

  it('gives no-standing no copy of its own', () => {
    expect(keyFor('no-standing').key).toBe('auth.errors.transientUnavailable')
  })

  it('keeps the configuration refusals on the generic developer arm', () => {
    for (const reason of ['no-was-server', 'remote-direct'] as const) {
      expect(keyFor(reason).key).toBe('auth.errors.setupFailed')
    }
  })

  it('never maps a transient refusal onto the not-enrolled guidance', () => {
    const reasons: TransientLoginUnavailableReason[] = [
      'no-was-server',
      'remote-direct',
      'no-standing',
      'no-delegated-clients',
      'unpromoted-account',
      'no-clientAnnex-generation',
      'no-generation-delegation',
      'no-user-key-roster'
    ]
    for (const reason of reasons) {
      expect(keyFor(reason).key).not.toBe('auth.errors.clientNotEnrolled')
    }
  })
})
