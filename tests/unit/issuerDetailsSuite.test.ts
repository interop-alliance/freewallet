import { describe, expect, it, vi, beforeEach } from 'vitest'
import type {
  EntityIdentityRegistry,
  VerificationContext,
  VerificationSubject
} from '@interop/verifier-core'

const lookupIssuersFor = vi.fn()

vi.mock('@/lib/registryManager', () => ({
  getCachedRegistryClient: () => ({ lookupIssuersFor })
}))

const { issuerDetailsSuite } =
  await import('@/lib/verifierSuites/issuerDetailsSuite')

const issuerDetailsCheck = issuerDetailsSuite.checks[0]

const REGISTRIES: EntityIdentityRegistry[] = [
  {
    type: 'dcc-legacy',
    name: 'DCC Pilot Registry',
    url: 'https://example.com/registry.json'
  }
]

function contextWith(
  registries: EntityIdentityRegistry[] | undefined
): VerificationContext {
  return { registries } as unknown as VerificationContext
}

function subjectWith(credential: Record<string, unknown>): VerificationSubject {
  return { verifiableCredential: credential }
}

describe('issuerDetailsSuite', () => {
  beforeEach(() => {
    lookupIssuersFor.mockReset()
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
    lookupIssuersFor.mockResolvedValue({
      matchingIssuers,
      uncheckedRegistries: []
    })

    const outcome = await issuerDetailsCheck.execute(
      subjectWith({ issuer: 'did:key:zABC' }),
      contextWith(REGISTRIES)
    )

    expect(lookupIssuersFor).toHaveBeenCalledWith('did:key:zABC')
    expect(outcome.status).toBe('success')
    if (outcome.status === 'success') {
      expect(outcome.payload).toEqual({ matchingIssuers })
    }
  })

  it('handles the object form of issuer (issuer.id)', async () => {
    lookupIssuersFor.mockResolvedValue({
      matchingIssuers: [],
      uncheckedRegistries: []
    })

    await issuerDetailsCheck.execute(
      subjectWith({ issuer: { id: 'did:key:zDEF' } }),
      contextWith(REGISTRIES)
    )

    expect(lookupIssuersFor).toHaveBeenCalledWith('did:key:zDEF')
  })

  it('succeeds with empty matchingIssuers for an unregistered issuer', async () => {
    lookupIssuersFor.mockResolvedValue({
      matchingIssuers: [],
      uncheckedRegistries: []
    })

    const outcome = await issuerDetailsCheck.execute(
      subjectWith({ issuer: 'did:key:zXYZ' }),
      contextWith(REGISTRIES)
    )

    expect(outcome.status).toBe('success')
    if (outcome.status === 'success') {
      expect(outcome.payload).toEqual({ matchingIssuers: [] })
    }
  })

  it('skips when no registries are configured', async () => {
    const outcome = await issuerDetailsCheck.execute(
      subjectWith({ issuer: 'did:key:zXYZ' }),
      contextWith(undefined)
    )
    expect(outcome.status).toBe('skipped')
    expect(lookupIssuersFor).not.toHaveBeenCalled()
  })

  it('skips when the credential has no issuer DID', async () => {
    const outcome = await issuerDetailsCheck.execute(
      subjectWith({ id: 'urn:example:1' }),
      contextWith(REGISTRIES)
    )
    expect(outcome.status).toBe('skipped')
    expect(lookupIssuersFor).not.toHaveBeenCalled()
  })
})
