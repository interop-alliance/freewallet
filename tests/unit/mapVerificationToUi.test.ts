import { describe, expect, it } from 'vitest'
import { verifyResultToChecklist } from '@/lib/viewMappers/mapVerificationToUi'
import {
  getVerificationAggregateStatus,
  isExpiredOnly,
  isFullyVerified
} from '@/lib/viewMappers/verificationMessages'
import type { IVerifiableCredential } from '@interop/data-integrity-core'

const BASE_VC = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:key:zABC'
} as IVerifiableCredential

function payload(
  log: Array<{ id: string; valid?: boolean; error?: { message?: string } }>
) {
  return {
    verified: log.every(entry => entry.valid !== false),
    log,
    results: [{ verified: true, log }]
  }
}

describe('verifyResultToChecklist', () => {
  it('maps a fully valid credential to five positive steps', () => {
    const result = verifyResultToChecklist(
      payload([
        { id: 'valid_signature', valid: true },
        { id: 'registered_issuer', valid: true },
        { id: 'revocation_status', valid: true },
        { id: 'expiration', valid: true }
      ]),
      BASE_VC
    )

    expect(result.supportedFormat.valid).toBe(true)
    expect(result.supportedFormat.status).toBe('positive')
    expect(result.signature.message).toBe('has a valid signature')
    expect(result.issuer.message).toBe('has been issued by a known issuer')
    expect(result.revocation.message).toBe('has not been revoked')
    expect(result.expiration.message).toBe('has not expired')
    expect(isFullyVerified(result)).toBe(true)
    expect(result.expiry).toBe(result.expiration)
    expect(result.status).toBe(result.revocation)
  })

  it('marks an unknown issuer as a warning, not a hard failure', () => {
    const result = verifyResultToChecklist(
      payload([
        { id: 'valid_signature', valid: true },
        {
          id: 'registered_issuer',
          valid: false,
          error: {
            message: 'Could not find issuer in registry with given DID.'
          }
        }
      ]),
      BASE_VC
    )

    expect(result.issuer.valid).toBe(false)
    expect(result.issuer.status).toBe('warning')
    expect(result.signature.valid).toBe(true)
    expect(getVerificationAggregateStatus(result)).toBe('warning')
    expect(isFullyVerified(result)).toBe(false)
  })

  it('marks expiration failure as a warning when other checks pass', () => {
    const result = verifyResultToChecklist(
      payload([
        { id: 'valid_signature', valid: true },
        { id: 'registered_issuer', valid: true },
        { id: 'expiration', valid: false }
      ]),
      BASE_VC
    )

    expect(result.expiration.valid).toBe(false)
    expect(result.expiration.status).toBe('warning')
    expect(getVerificationAggregateStatus(result)).toBe('warning')
    expect(isExpiredOnly(result)).toBe(true)
  })

  it('marks revocation failure as a hard failure', () => {
    const result = verifyResultToChecklist(
      payload([
        { id: 'valid_signature', valid: true },
        { id: 'registered_issuer', valid: true },
        { id: 'revocation_status', valid: false }
      ]),
      {
        ...BASE_VC,
        credentialStatus: { id: 'status:1' }
      } as IVerifiableCredential
    )

    expect(result.revocation.valid).toBe(false)
    expect(result.revocation.status).toBe('negative')
    expect(getVerificationAggregateStatus(result)).toBe('not_verified')
  })

  it('reports unsupported credential types as a hard failure', () => {
    const result = verifyResultToChecklist(
      payload([{ id: 'valid_signature', valid: true }]),
      { ...BASE_VC, type: ['CustomCredential'] } as IVerifiableCredential
    )

    expect(result.supportedFormat.valid).toBe(false)
    expect(result.supportedFormat.status).toBe('negative')
    expect(getVerificationAggregateStatus(result)).toBe('not_verified')
  })

  it('shows no expiration date when the credential has none', () => {
    const result = verifyResultToChecklist(
      payload([{ id: 'valid_signature', valid: true }]),
      BASE_VC
    )

    expect(result.expiration.valid).toBe(true)
    expect(result.expiration.message).toBe('has no expiration date set')
  })

  it('defaults revocation to valid when no credentialStatus is present', () => {
    const result = verifyResultToChecklist(
      payload([{ id: 'valid_signature', valid: true }]),
      BASE_VC
    )

    expect(result.revocation.valid).toBe(true)
    expect(result.revocation.message).toBe('has not been revoked')
  })
})
