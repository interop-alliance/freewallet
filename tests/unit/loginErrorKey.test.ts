// @vitest-environment node
/**
 * Unit tests for the login-failure copy mapping
 * (`src/session/loginErrorKey.ts`): the typed outcome (the key beside the
 * transient refusal's reason), and the per-reason mapping of
 * `TransientLoginUnavailableError` -- the failed-heal pair, the
 * annex-generation family, and the two configuration refusals.
 */
import { describe, expect, it } from 'vitest'
import { loginErrorKey } from '@/session/loginErrorKey'
import {
  TransientLoginUnavailableError,
  type TransientLoginUnavailableReason
} from '@/session/transientLogin'
import {
  PendingEnrollmentDiscardedError,
  PendingEnrollmentError,
  PendingResumeLogUnavailableError
} from '@/session/pendingEnrollment'
import { SelfEnrollmentSkewError } from '@/session/standingUnlock'
import enLocale from '@/i18n/locales/en.json'
import esLocale from '@/i18n/locales/es.json'

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

  it('keeps the configuration refusals on the generic developer arm', () => {
    for (const reason of ['no-was-server', 'remote-direct'] as const) {
      expect(keyFor(reason).key).toBe('auth.errors.setupFailed')
    }
  })

  it('never maps a transient refusal onto the not-enrolled guidance', () => {
    const reasons: TransientLoginUnavailableReason[] = [
      'no-was-server',
      'remote-direct',
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

describe('loginErrorKey -- the pending-enrollment outcomes (FW-280)', () => {
  it('maps the fail-closed pending refusal onto its own copy', () => {
    const outcome = loginErrorKey({
      err: new PendingEnrollmentError({ reason: 'resume-failed' }),
      label: 'Login'
    })
    expect(outcome.key).toBe('auth.errors.pendingEnrollment')
  })

  it("maps a spend-written record's refusal onto the go-to-/recover copy", () => {
    const outcome = loginErrorKey({
      err: new PendingEnrollmentError({ reason: 'recovery-spend' }),
      label: 'Login'
    })
    expect(outcome.key).toBe('auth.errors.pendingRecoveryResume')
  })

  it('maps the discard onto its own dropped-connection copy', () => {
    const outcome = loginErrorKey({
      err: new PendingEnrollmentDiscardedError(),
      label: 'Login'
    })
    expect(outcome.key).toBe('auth.errors.pendingEnrollmentDiscarded')
  })

  it('maps a lagging served log (BuiltOnHeadNotReachedError) onto the transport state', () => {
    const err = new Error('behind the recorded head')
    err.name = 'BuiltOnHeadNotReachedError'
    const outcome = loginErrorKey({ err, label: 'Login' })
    expect(outcome.key).toBe('auth.errors.storageUnreachable')
  })

  it('maps an unfetchable account log during the resume onto the transport state', () => {
    const outcome = loginErrorKey({
      err: new PendingResumeLogUnavailableError({
        cause: new TypeError('Failed to fetch')
      }),
      label: 'Login'
    })
    expect(outcome.key).toBe('auth.errors.storageUnreachable')
  })

  it('maps the build-skew refusal onto its own copy', () => {
    const outcome = loginErrorKey({
      err: new SelfEnrollmentSkewError(),
      label: 'Login'
    })
    expect(outcome.key).toBe('auth.errors.selfEnrollmentSkew')
  })

  it('carries every new key in both locales', () => {
    const locales = [enLocale, esLocale] as Array<{
      auth: { errors: Record<string, string> }
    }>
    for (const locale of locales) {
      for (const key of [
        'pendingEnrollment',
        'pendingEnrollmentDiscarded',
        'pendingRecoveryResume',
        'selfEnrollmentSkew'
      ]) {
        expect(typeof locale.auth.errors[key]).toBe('string')
        expect(locale.auth.errors[key]!.length).toBeGreaterThan(0)
      }
    }
  })
})
