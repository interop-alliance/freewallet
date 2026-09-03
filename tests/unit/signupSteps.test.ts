/**
 * The signup wizard's URL contract: the one shape SignupPage writes through
 * `setSearchParams` and the lobby builds when it hands a failed run back.
 * Both defaults (the passphrase method, the `start` step) are omitted, so a
 * bare `/signup` is the wizard's first step.
 */
import { describe, expect, it } from 'vitest'
import {
  signupMethodOf,
  signupStepOf,
  signupStepParams,
  signupStepPath
} from '@/lib/signupSteps'

describe('signupSteps', () => {
  it('omits both defaults', () => {
    expect(signupStepParams({ method: 'passphrase', step: 'start' })).toEqual(
      {}
    )
    expect(signupStepPath({ method: 'passphrase', step: 'start' })).toBe(
      '/signup'
    )
  })

  it('names the step for the passphrase method', () => {
    expect(signupStepParams({ method: 'passphrase', step: 'storage' })).toEqual(
      {
        step: 'storage'
      }
    )
    expect(signupStepPath({ method: 'passphrase', step: 'email' })).toBe(
      '/signup?step=email'
    )
  })

  it('carries the passkey method through every step', () => {
    expect(signupStepPath({ method: 'passkey', step: 'storage' })).toBe(
      '/signup?method=passkey&step=storage'
    )
    expect(signupStepPath({ method: 'passkey', step: 'start' })).toBe(
      '/signup?method=passkey'
    )
  })

  it('reads back what it wrote', () => {
    const params = new URLSearchParams(
      signupStepParams({ method: 'passkey', step: 'email' })
    )
    expect(signupMethodOf(params)).toBe('passkey')
    expect(signupStepOf(params)).toBe('email')
  })

  it('falls back to the first step and the passphrase method', () => {
    const params = new URLSearchParams({ step: 'not-a-step', method: 'nope' })
    expect(signupStepOf(params)).toBe('start')
    expect(signupMethodOf(params)).toBe('passphrase')
    expect(signupStepOf(new URLSearchParams())).toBe('start')
  })
})
