import { describe, expect, it } from 'vitest'
import { FakeTimeService } from '@interop/verifier-core'
import type {
  VerificationContext,
  VerificationSubject
} from '@interop/verifier-core'
import {
  EXPIRED_PROBLEM_TYPE,
  expirationSuite
} from '@/lib/verifierSuites/expirationSuite'

const expirationCheck = expirationSuite.checks[0]

const NOW = new Date('2026-06-05T00:00:00Z').getTime()

function contextAt(nowMs: number): VerificationContext {
  // baseDateMs + 1 is returned on first dateNowMs() call, so subtract 1.
  return {
    timeService: FakeTimeService({ baseDateMs: nowMs - 1 })
  } as unknown as VerificationContext
}

function subjectWith(credential: Record<string, unknown>): VerificationSubject {
  return { verifiableCredential: credential }
}

describe('expirationSuite', () => {
  it('succeeds for a credential within its validity period (validUntil)', async () => {
    const outcome = await expirationCheck.execute(
      subjectWith({ validUntil: '2030-01-01T00:00:00Z' }),
      contextAt(NOW)
    )
    expect(outcome.status).toBe('success')
  })

  it('falls back to VC 1.x expirationDate', async () => {
    const outcome = await expirationCheck.execute(
      subjectWith({ expirationDate: '2030-01-01T00:00:00Z' }),
      contextAt(NOW)
    )
    expect(outcome.status).toBe('success')
  })

  it('fails for an expired credential with the EXPIRED problem type', async () => {
    const outcome = await expirationCheck.execute(
      subjectWith({ validUntil: '2020-01-01T00:00:00Z' }),
      contextAt(NOW)
    )
    expect(outcome.status).toBe('failure')
    if (outcome.status === 'failure') {
      expect(outcome.problems[0]?.type).toBe(EXPIRED_PROBLEM_TYPE)
    }
  })

  it('skips when the credential has no expiration date', async () => {
    const outcome = await expirationCheck.execute(
      subjectWith({ id: 'urn:example:1' }),
      contextAt(NOW)
    )
    expect(outcome.status).toBe('skipped')
  })

  it('skips when the expiration date is not a valid date', async () => {
    const outcome = await expirationCheck.execute(
      subjectWith({ validUntil: 'not-a-date' }),
      contextAt(NOW)
    )
    expect(outcome.status).toBe('skipped')
  })
})
