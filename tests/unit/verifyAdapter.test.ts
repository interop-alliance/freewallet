import { describe, expect, it, vi, beforeEach } from 'vitest'
import { addSink, captureSink } from '@interop/logger'
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
  issuer: 'did:key:zABC',
  validUntil: '2099-01-01T00:00:00Z'
} as never

const CREDENTIAL_WITHOUT_EXPIRY = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:key:zABC'
} as never

const SIGNATURE = 'cryptographic.proof.signature'
const STATUS = 'cryptographic.status.bitstring'
const VALIDITY_PERIOD = 'cryptographic.proof.validity-period'
const ISSUER_DETAILS = 'trust.issuer-details'

/**
 * A `results[]` row as verifier-core stamps it: the phase-qualified id,
 * with the suite the segment after the phase.
 */
function check(checkId: string, outcome: CheckOutcome): CheckResult {
  const segments = checkId.split('.')
  return {
    id: checkId,
    suite: segments[segments.length - 2],
    outcome
  }
}

function coreResult(
  results: CheckResult[],
  credential: unknown = CREDENTIAL
): CredentialVerificationResult {
  return {
    verified: !results.some(r => r.fatal && r.outcome.status === 'failure'),
    verifiableCredential: credential as never,
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
 * A fatal failure of the check `checkId` carrying one problem.
 */
function fatalFailure(checkId: string, problem: ProblemDetail): CheckResult {
  return {
    ...check(checkId, { status: 'failure', problems: [problem] }),
    fatal: true
  }
}

const SIGNATURE_OK = check(SIGNATURE, { status: 'success', message: 'ok' })
const STATUS_OK = check(STATUS, { status: 'success', message: 'ok' })
const VALIDITY_PERIOD_OK = check(VALIDITY_PERIOD, {
  status: 'success',
  message: 'ok'
})

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

const ISSUER_OK = check(ISSUER_DETAILS, {
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
      coreResult([SIGNATURE_OK, STATUS_OK, VALIDITY_PERIOD_OK, ISSUER_OK])
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

  it.each([
    ['expired', EXPIRED_PROBLEM],
    ['not-yet-valid', NOT_YET_VALID_PROBLEM]
  ])(
    'maps an %s credential onto a passing signature row and a failing expiry row',
    async (_label, problem) => {
      coreVerifyMock.mockResolvedValue(
        coreResult([
          SIGNATURE_OK,
          fatalFailure(VALIDITY_PERIOD, problem),
          STATUS_OK,
          ISSUER_OK
        ])
      )

      const payload = await verifyCredential(CREDENTIAL)
      const byId = logById(payload)

      expect(byId('valid_signature')).toEqual({
        id: 'valid_signature',
        valid: true
      })
      expect(byId('expiration')?.valid).toBe(false)
      expect(byId('expiration')?.error?.message).toBe(problem.detail)
      // The validity check does not halt, so the later suites still report.
      expect(byId('revocation_status')?.valid).toBe(true)
      expect(byId('registered_issuer')?.valid).toBe(true)
      expect(payload.verified).toBe(false)
    }
  )

  it('writes a failing expiry row for a not-yet-valid credential stating no end date', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult(
        [SIGNATURE_OK, fatalFailure(VALIDITY_PERIOD, NOT_YET_VALID_PROBLEM)],
        CREDENTIAL_WITHOUT_EXPIRY
      )
    )

    const payload = await verifyCredential(CREDENTIAL_WITHOUT_EXPIRY)
    expect(logById(payload)('expiration')?.valid).toBe(false)
  })

  it('reaches the "expired but authentic" checklist summary', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult([
        SIGNATURE_OK,
        fatalFailure(VALIDITY_PERIOD, EXPIRED_PROBLEM),
        ISSUER_OK
      ])
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

  it('logs the proofs no suite could check and maps no row for them', async () => {
    const unsupported = {
      type: ProblemTypes.PROOF_UNSUPPORTED,
      title: 'Proof Unsupported',
      detail:
        'Proof 2 of 2 (DataIntegrityProof, bbs-2023): no registered suite supports this cryptosuite.'
    }
    coreVerifyMock.mockResolvedValue(
      coreResult([
        SIGNATURE_OK,
        check('cryptographic.proof.unsupported-proofs', {
          status: 'failure',
          problems: [unsupported]
        }),
        VALIDITY_PERIOD_OK,
        ISSUER_OK
      ])
    )
    const capture = captureSink()
    const stopCapture = addSink(capture.sink)

    try {
      const payload = await verifyCredential(CREDENTIAL)

      expect(payload.verified).toBe(true)
      expect(logOf(payload).map(entry => entry.id)).toEqual([
        'valid_signature',
        'expiration',
        'registered_issuer'
      ])
      expect(capture.events).toContainEqual(
        expect.objectContaining({
          ns: 'fw:verify',
          msg: 'Some proofs in the credential could not be checked',
          data: expect.objectContaining({ proofs: [unsupported.detail] })
        })
      )
    } finally {
      stopCapture()
    }
  })

  it('keeps a tampered credential as a failing signature row', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult([
        fatalFailure(SIGNATURE, {
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

  it('omits the expiration row when the credential states no end date', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult(
        [SIGNATURE_OK, VALIDITY_PERIOD_OK, ISSUER_OK],
        CREDENTIAL_WITHOUT_EXPIRY
      )
    )

    const payload = await verifyCredential(CREDENTIAL_WITHOUT_EXPIRY)
    expect(logById(payload)('expiration')).toBeUndefined()
    expect(payload.verified).toBe(true)
  })

  it('omits the expiration row when the validity check is skipped', async () => {
    coreVerifyMock.mockResolvedValue(
      coreResult([
        SIGNATURE_OK,
        check(VALIDITY_PERIOD, {
          status: 'skipped',
          reason: 'validUntil is not a date'
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
        SIGNATURE_OK,
        check(STATUS, {
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
        SIGNATURE_OK,
        check(STATUS, {
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
        SIGNATURE_OK,
        check(ISSUER_DETAILS, {
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
        fatalFailure('cryptographic.parsing.envelope', {
          type: ProblemTypes.PARSING_ERROR,
          title: 'Credential Parsing Failed',
          detail: 'type: missing'
        })
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
