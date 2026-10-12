import { describe, expect, it, vi, beforeEach } from 'vitest'
import type { TFunction } from 'i18next'
import type {
  CheckResult,
  CheckOutcome,
  CredentialVerificationResult,
  ProblemDetail
} from '@interop/verifier-core'

const coreVerifyMock = vi.fn()

vi.mock('@interop/verifier-core', async importActual => {
  const actual = await importActual<typeof import('@interop/verifier-core')>()
  return {
    ...actual,
    verifyCredential: (...args: unknown[]) => coreVerifyMock(...args)
  }
})

const { ProblemTypes } = await import('@interop/verifier-core')
const { verifyCredential } = await import('@/lib/verify')
const { isExpiredOnly } = await import('@interop/vc-display')
const { verifyResultToChecklist } =
  await import('@/lib/viewMappers/mapVerificationToUi')

const CREDENTIAL = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:key:zABC'
} as never

function check(checkId: string, outcome: CheckOutcome): CheckResult {
  return {
    id: checkId,
    check: checkId,
    suite: checkId.split('.')[0],
    outcome
  }
}

function coreResult(results: CheckResult[]): CredentialVerificationResult {
  return {
    verified: !results.some(r => r.fatal && r.outcome.status === 'failure'),
    verifiableCredential: CREDENTIAL as never,
    results,
    summary: []
  }
}

type LogEntry = {
  id: string
  valid?: boolean
  matchingIssuers?: unknown[]
  error?: { message?: string; name?: string }
}

/**
 * An identity `TFunction`: the checklist labels read back as their keys.
 */
const t = ((key: string) => key) as unknown as TFunction

function logOf(
  payload: Awaited<ReturnType<typeof verifyCredential>>
): LogEntry[] {
  return (payload.results?.[0]?.log ?? payload.log ?? []) as LogEntry[]
}

function logById(payload: Awaited<ReturnType<typeof verifyCredential>>) {
  const log = logOf(payload)
  return (id: string) => log.find(entry => entry.id === id)
}

const EXPIRED_PROBLEM = {
  type: ProblemTypes.CREDENTIAL_EXPIRED,
  title: 'Credential Expired',
  detail: 'Credential expired on 2020-01-01T00:00:00Z.'
}

const NOT_YET_VALID_PROBLEM = {
  type: ProblemTypes.CREDENTIAL_NOT_YET_VALID,
  title: 'Credential Not Yet Valid',
  detail: 'Credential is not valid until 2099-01-01T00:00:00Z.'
}

/**
 * A fatal `proof.signature` failure carrying one problem.
 */
function fatalSignatureFailure(problem: ProblemDetail): CheckResult {
  return {
    ...check('proof.signature', { status: 'failure', problems: [problem] }),
    fatal: true
  }
}

const MATCHING_ISSUERS = [
  {
    registry: {
      federation_entity: { organization_name: 'DCC Pilot Registry' }
    },
    issuer: {
      federation_entity: { organization_name: 'Example University' }
    }
  }
]

const ISSUER_OK = check('trust.issuer-details', {
  status: 'success',
  message: 'ok',
  payload: { matchingIssuers: MATCHING_ISSUERS }
})

describe('verify.ts adapter', () => {
  beforeEach(() => {
    coreVerifyMock.mockReset()
  })

  it('disables the default registry suite (registries: [])', async () => {
    coreVerifyMock.mockResolvedValue(coreResult([]))

    await verifyCredential(CREDENTIAL)

    expect(coreVerifyMock).toHaveBeenCalledWith(
      expect.objectContaining({ registries: [] })
    )
  })

  it('maps a fully valid result to a passing legacy payload', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult([
        check('proof.signature', { status: 'success', message: 'ok' }),
        check('status.bitstring', { status: 'success', message: 'ok' }),
        check('validity.expiration', { status: 'success', message: 'ok' }),
        ISSUER_OK
      ])
    )

    const payload = await verifyCredential(CREDENTIAL)
    const byId = logById(payload)

    expect(payload.verified).toBe(true)
    expect(byId('valid_signature')?.valid).toBe(true)
    expect(byId('revocation_status')?.valid).toBe(true)
    expect(byId('expiration')?.valid).toBe(true)
    expect(byId('registered_issuer')?.valid).toBe(true)
    expect(byId('registered_issuer')?.matchingIssuers).toEqual(MATCHING_ISSUERS)
  })

  it('marks an expired credential as not verified', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult([
        check('proof.signature', { status: 'success', message: 'ok' }),
        check('validity.expiration', {
          status: 'failure',
          problems: [EXPIRED_PROBLEM]
        }),
        ISSUER_OK
      ])
    )

    const payload = await verifyCredential(CREDENTIAL)
    const byId = logById(payload)

    expect(byId('expiration')?.valid).toBe(false)
    expect(byId('expiration')?.error?.message).toContain('expired')
    expect(payload.verified).toBe(false)
  })

  it.each([
    ['expired', EXPIRED_PROBLEM],
    ['not-yet-valid', NOT_YET_VALID_PROBLEM]
  ])(
    'maps an %s signature verdict onto a passing signature row and a failing expiry row',
    async (_label, problem) => {
      coreVerifyMock.mockResolvedValue(
        coreResult([fatalSignatureFailure(problem), ISSUER_OK])
      )

      const payload = await verifyCredential(CREDENTIAL)
      const byId = logById(payload)

      expect(byId('valid_signature')).toEqual({
        id: 'valid_signature',
        valid: true
      })
      expect(byId('expiration')?.valid).toBe(false)
      expect(byId('expiration')?.error?.message).toBe(problem.detail)
      expect(payload.verified).toBe(false)
    }
  )

  it('reaches the "expired but authentic" checklist summary', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult([fatalSignatureFailure(EXPIRED_PROBLEM), ISSUER_OK])
    )

    const payload = await verifyCredential(CREDENTIAL)
    const checklist = verifyResultToChecklist({
      raw: payload as never,
      credential: CREDENTIAL,
      t
    })

    expect(checklist.signature.valid).toBe(true)
    expect(isExpiredOnly(checklist)).toBe(true)
  })

  it('writes one expiry row when the signature verdict and the expiration suite both report', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult([
        fatalSignatureFailure(EXPIRED_PROBLEM),
        check('validity.expiration', {
          status: 'failure',
          problems: [EXPIRED_PROBLEM]
        })
      ])
    )

    const payload = await verifyCredential(CREDENTIAL)
    expect(
      logOf(payload).filter(entry => entry.id === 'expiration')
    ).toHaveLength(1)
  })

  it('keeps a tampered credential as a failing signature row', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult([
        fatalSignatureFailure({
          type: ProblemTypes.INVALID_SIGNATURE,
          title: 'Invalid Signature',
          detail: 'Invalid signature.'
        })
      ])
    )

    const payload = await verifyCredential(CREDENTIAL)
    const byId = logById(payload)

    expect(byId('valid_signature')?.valid).toBe(false)
    expect(byId('valid_signature')?.error?.message).toBe('Invalid signature.')
    expect(byId('expiration')).toBeUndefined()
    expect(payload.verified).toBe(false)
  })

  it('omits the expiration row when the check is skipped', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult([
        check('proof.signature', { status: 'success', message: 'ok' }),
        check('validity.expiration', {
          status: 'skipped',
          reason: 'no expiry'
        }),
        ISSUER_OK
      ])
    )

    const payload = await verifyCredential(CREDENTIAL)
    expect(logById(payload)('expiration')).toBeUndefined()
  })

  it('drops a status_list_not_found revocation row instead of failing', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult([
        check('proof.signature', { status: 'success', message: 'ok' }),
        check('status.bitstring', {
          status: 'failure',
          problems: [
            {
              type: ProblemTypes.STATUS_LIST_NOT_FOUND,
              title: 'Status List Not Found',
              detail: 'Could not fetch the status list.'
            }
          ]
        }),
        ISSUER_OK
      ])
    )

    const payload = await verifyCredential(CREDENTIAL)
    expect(logById(payload)('revocation_status')).toBeUndefined()
    expect(payload.hasStatusError).toBeUndefined()
    // signature + issuer still pass, so overall is verified.
    expect(payload.verified).toBe(true)
  })

  it('keeps a genuine revocation as a failing, status-error row', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult([
        check('proof.signature', { status: 'success', message: 'ok' }),
        check('status.bitstring', {
          status: 'failure',
          problems: [
            {
              type: ProblemTypes.CREDENTIAL_REVOKED,
              title: 'Credential Revoked or Suspended',
              detail: 'The credential has been revoked.'
            }
          ]
        }),
        ISSUER_OK
      ])
    )

    const payload = await verifyCredential(CREDENTIAL)
    expect(logById(payload)('revocation_status')?.valid).toBe(false)
    expect(payload.hasStatusError).toBe(true)
    expect(payload.verified).toBe(false)
  })

  it('marks an unregistered issuer as not verified', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult([
        check('proof.signature', { status: 'success', message: 'ok' }),
        check('trust.issuer-details', {
          status: 'success',
          message: 'none',
          payload: { matchingIssuers: [] }
        })
      ])
    )

    const payload = await verifyCredential(CREDENTIAL)
    const issuer = logById(payload)('registered_issuer')
    expect(issuer?.valid).toBe(false)
    expect(issuer?.matchingIssuers).toEqual([])
    expect(payload.verified).toBe(false)
  })

  it('returns a fatal result for a malformed credential', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult([
        {
          id: 'parsing.envelope',
          check: 'parsing.envelope',
          suite: 'parsing',
          fatal: true,
          outcome: {
            status: 'failure',
            problems: [
              {
                type: ProblemTypes.PARSING_ERROR,
                title: 'Credential Parsing Failed',
                detail: 'type: missing'
              }
            ]
          }
        }
      ])
    )

    const payload = await verifyCredential(CREDENTIAL)
    expect(payload.verified).toBe(false)
    const firstResult = payload.results?.[0] as {
      error?: { isFatal?: boolean }
    }
    expect(firstResult.error?.isFatal).toBe(true)
  })

  it('returns a fatal result when the verifier throws', async () => {
    coreVerifyMock.mockRejectedValue(new Error('boom'))
    const payload = await verifyCredential(CREDENTIAL)
    expect(payload.verified).toBe(false)
    const firstResult = payload.results?.[0] as {
      error?: { isFatal?: boolean }
    }
    expect(firstResult.error?.isFatal).toBe(true)
  })
})
