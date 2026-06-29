import { describe, expect, it, vi, beforeEach } from 'vitest'
import type {
  VerificationContext,
  VerificationSubject
} from '@interop/verifier-core'

const lookupDid = vi.fn()

vi.mock('@/lib/registryManager', () => ({
  registryManager: { lookupDid: (...args: unknown[]) => lookupDid(...args) }
}))

const { issuerDetailsSuite } =
  await import('@/lib/verifierSuites/issuerDetailsSuite')

const issuerDetailsCheck = issuerDetailsSuite.checks[0]

const EMPTY_CONTEXT = {} as VerificationContext

function subjectWith(credential: Record<string, unknown>): VerificationSubject {
  return { verifiableCredential: credential }
}

describe('issuerDetailsSuite', () => {
  beforeEach(() => {
    lookupDid.mockReset()
  })

  it('returns matchingIssuers on the payload for a registered issuer', async () => {
    const matchingIssuers = [
      {
        registry: {
          federation_entity: { organization_name: 'DCC Pilot Registry' }
        },
        issuer: {
          federation_entity: {
            organization_name: 'Example University',
            homepage_uri: 'https://example.edu'
          }
        }
      }
    ]
    lookupDid.mockResolvedValue({
      matchingIssuers,
      uncheckedRegistries: []
    })

    const outcome = await issuerDetailsCheck.execute(
      subjectWith({ issuer: 'did:key:zABC' }),
      EMPTY_CONTEXT
    )

    expect(lookupDid).toHaveBeenCalledWith('did:key:zABC')
    expect(outcome.status).toBe('success')
    if (outcome.status === 'success') {
      expect(outcome.payload).toEqual({ matchingIssuers })
    }
  })

  it('handles the object form of issuer (issuer.id)', async () => {
    lookupDid.mockResolvedValue({
      matchingIssuers: [],
      uncheckedRegistries: []
    })

    await issuerDetailsCheck.execute(
      subjectWith({ issuer: { id: 'did:key:zDEF' } }),
      EMPTY_CONTEXT
    )

    expect(lookupDid).toHaveBeenCalledWith('did:key:zDEF')
  })

  it('succeeds with empty matchingIssuers for an unregistered issuer', async () => {
    lookupDid.mockResolvedValue({
      matchingIssuers: [],
      uncheckedRegistries: []
    })

    const outcome = await issuerDetailsCheck.execute(
      subjectWith({ issuer: 'did:key:zXYZ' }),
      EMPTY_CONTEXT
    )

    expect(outcome.status).toBe('success')
    if (outcome.status === 'success') {
      expect(outcome.payload).toEqual({ matchingIssuers: [] })
    }
  })

  it('skips when the credential has no issuer DID', async () => {
    const outcome = await issuerDetailsCheck.execute(
      subjectWith({ id: 'urn:example:1' }),
      EMPTY_CONTEXT
    )
    expect(outcome.status).toBe('skipped')
    expect(lookupDid).not.toHaveBeenCalled()
  })
})
