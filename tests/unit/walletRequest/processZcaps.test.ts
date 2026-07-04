// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import * as vc from '@interop/vc'
import { securityLoader } from '@interop/security-document-loader'
import type { Session } from '@/types/auth'
import type { ICapabilityQueryDetail, IZcap } from '@/lib/walletRequest'
import {
  resolveInvocationTarget,
  resolveGrant,
  processZcaps,
  processRequest,
  presentationSuiteFor
} from '@/lib/walletRequest'

const documentLoader = securityLoader({ fetchRemoteContexts: true }).build()

const SPACE_URL = 'https://was.example.com/space/L8qcqABC'
const RP_DID = 'did:key:z6MkrRPexampleRelyingParty'
const CHALLENGE = '99612b24-63d9-11ea-b99f-4f66f3e4f81a'

const collectionDetail: ICapabilityQueryDetail = {
  referenceId: 'example-app-data',
  reason: 'Example App stores your documents in your wallet storage.',
  allowedAction: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'],
  controller: RP_DID,
  invocationTarget: { type: 'urn:was:collection', name: 'example-app-data' }
}

const spaceDetail: ICapabilityQueryDetail = {
  referenceId: 'space-read',
  allowedAction: ['GET', 'HEAD', 'PUT'],
  controller: RP_DID,
  invocationTarget: { type: 'urn:was:space' }
}

const foreignDetail: ICapabilityQueryDetail = {
  controller: RP_DID,
  invocationTarget: 'https://someone-else.example/space/OTHER/data'
}

/**
 * A full-tier session whose `keyAgent` really signs (for the round-trip VP
 * test), but whose `zcapClient.delegate` and `storage.ensureCollection` are
 * stubbed -- delegation and provisioning hit the WAS server in production.
 */
let session: Session
let delegated: Array<Record<string, unknown>>
let ensureCalls: string[]

beforeAll(async () => {
  const keyAgent = await CapabilityAgent.fromSecret({
    secret: 'correct horse battery staple',
    handle: 'test',
    keyName: 'test-key'
  })
  delegated = []
  ensureCalls = []

  const zcapClient = {
    async delegate({
      invocationTarget,
      controller,
      allowedActions,
      expires
    }: {
      invocationTarget: string
      controller: string
      allowedActions: string[]
      expires: Date | string
    }) {
      const zcap = {
        '@context': [
          'https://w3id.org/zcap/v1',
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        id: `urn:zcap:delegated:${encodeURIComponent(invocationTarget)}`,
        parentCapability: `urn:zcap:root:${encodeURIComponent(SPACE_URL)}`,
        invocationTarget,
        controller,
        allowedAction: allowedActions,
        expires: expires instanceof Date ? expires.toISOString() : expires,
        proof: {
          type: 'Ed25519Signature2020',
          proofPurpose: 'capabilityDelegation',
          capabilityChain: [`urn:zcap:root:${encodeURIComponent(SPACE_URL)}`],
          verificationMethod: `${keyAgent.id}#key`,
          proofValue: 'zFakeDelegationProof'
        }
      }
      delegated.push(zcap)
      return zcap
    }
  }

  const storage = {
    hasRemoteStorage: true,
    spaceUrl: SPACE_URL,
    async ensureCollection({ id }: { id: string }) {
      ensureCalls.push(id)
    }
  }

  session = {
    user: { id: keyAgent.id },
    profile: { keyAgent, zcapClient },
    storage,
    tier: 'full'
  } as unknown as Session
})

describe('resolveInvocationTarget', () => {
  it('accepts a plain URL under the Space, verbatim', () => {
    const target = resolveInvocationTarget({
      descriptor: `${SPACE_URL}/example-app-data/doc1`,
      spaceUrl: SPACE_URL
    })
    expect(target).toMatchObject({
      satisfiable: true,
      invocationTarget: `${SPACE_URL}/example-app-data/doc1`,
      wholeSpace: false,
      needsProvisioning: false
    })
  })

  it('treats an exact Space URL string as a whole-Space grant', () => {
    const target = resolveInvocationTarget({
      descriptor: SPACE_URL,
      spaceUrl: SPACE_URL
    })
    expect(target).toMatchObject({ satisfiable: true, wholeSpace: true })
  })

  it('refuses a foreign URL', () => {
    expect(
      resolveInvocationTarget({
        descriptor: 'https://someone-else.example/space/OTHER',
        spaceUrl: SPACE_URL
      }).satisfiable
    ).toBe(false)
  })

  it('resolves a named RP collection and flags provisioning', () => {
    const target = resolveInvocationTarget({
      descriptor: { type: 'urn:was:collection', name: 'example-app-data' },
      spaceUrl: SPACE_URL
    })
    expect(target).toMatchObject({
      satisfiable: true,
      invocationTarget: `${SPACE_URL}/example-app-data`,
      needsProvisioning: true,
      collectionId: 'example-app-data',
      encrypted: false
    })
  })

  it('grants an existing standard collection without provisioning', () => {
    const target = resolveInvocationTarget({
      descriptor: { type: 'urn:was:collection', name: 'public-credentials' },
      spaceUrl: SPACE_URL
    })
    expect(target).toMatchObject({
      needsProvisioning: false,
      encrypted: false
    })
  })

  it('flags an encrypted standard collection', () => {
    const target = resolveInvocationTarget({
      descriptor: { type: 'urn:was:collection', name: 'private-credentials' },
      spaceUrl: SPACE_URL
    })
    expect(target).toMatchObject({
      needsProvisioning: false,
      encrypted: true
    })
  })

  it('rejects an invalid collection name', () => {
    expect(
      resolveInvocationTarget({
        descriptor: { type: 'urn:was:collection', name: 'Bad_Name!' },
        spaceUrl: SPACE_URL
      }).satisfiable
    ).toBe(false)
  })

  it('resolves the whole Space', () => {
    expect(
      resolveInvocationTarget({
        descriptor: { type: 'urn:was:space' },
        spaceUrl: SPACE_URL
      })
    ).toMatchObject({
      satisfiable: true,
      invocationTarget: SPACE_URL,
      wholeSpace: true
    })
  })

  it('refuses an unknown descriptor type', () => {
    expect(
      resolveInvocationTarget({
        descriptor: { type: 'urn:was:unknown' },
        spaceUrl: SPACE_URL
      }).satisfiable
    ).toBe(false)
  })
})

describe('resolveGrant action handling', () => {
  it('defaults an absent allowedAction to read-only', () => {
    const grant = resolveGrant({
      descriptor: {
        controller: RP_DID,
        invocationTarget: { type: 'urn:was:collection', name: 'app-data' }
      },
      spaceUrl: SPACE_URL
    })
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
  })

  it('strips whole-Space grants to read-only', () => {
    const grant = resolveGrant({ descriptor: spaceDetail, spaceUrl: SPACE_URL })
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
  })

  it('passes through explicit collection actions', () => {
    const grant = resolveGrant({
      descriptor: collectionDetail,
      spaceUrl: SPACE_URL
    })
    expect(grant.allowedActions).toEqual([
      'GET',
      'HEAD',
      'PUT',
      'POST',
      'DELETE'
    ])
  })
})

describe('processZcaps', () => {
  it('delegates satisfiable grants, provisions, and skips foreign targets', async () => {
    delegated.length = 0
    ensureCalls.length = 0
    const before = Date.now()
    const zcaps = await processZcaps({
      zcapRequests: [collectionDetail, spaceDetail, foreignDetail],
      session,
      ttlMs: 720 * 60 * 60 * 1000
    })

    expect(zcaps).toHaveLength(2)
    // Only the un-provisioned RP collection is created.
    expect(ensureCalls).toEqual(['example-app-data'])

    const collectionZcap = zcaps[0] as unknown as {
      invocationTarget: string
      controller: string
      allowedAction: string[]
      expires: string
    }
    expect(collectionZcap.invocationTarget).toBe(
      `${SPACE_URL}/example-app-data`
    )
    expect(collectionZcap.controller).toBe(RP_DID)
    expect(collectionZcap.allowedAction).toEqual([
      'GET',
      'HEAD',
      'PUT',
      'POST',
      'DELETE'
    ])

    const spaceZcap = zcaps[1] as unknown as {
      invocationTarget: string
      allowedAction: string[]
    }
    expect(spaceZcap.invocationTarget).toBe(SPACE_URL)
    expect(spaceZcap.allowedAction).toEqual(['GET', 'HEAD'])

    // Expiry ~30 days out (from the passed ttl).
    const expiresMs = new Date(collectionZcap.expires).getTime()
    const expected = before + 720 * 60 * 60 * 1000
    expect(Math.abs(expiresMs - expected)).toBeLessThan(60 * 1000)
  })

  it('throws when the session has no remote storage', async () => {
    const guest = {
      ...session,
      storage: { hasRemoteStorage: false }
    } as unknown as Session
    await expect(
      processZcaps({ zcapRequests: [collectionDetail], session: guest })
    ).rejects.toThrow(/remote storage/)
  })
})

describe('processRequest with zcaps', () => {
  it('signs a VP over challenge/domain that embeds the grants and verifies', async () => {
    const { verifiablePresentation } = await processRequest({
      request: {
        query: [
          { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] },
          {
            type: 'AuthorizationCapabilityQuery',
            capabilityQuery: [collectionDetail, spaceDetail]
          }
        ],
        challenge: CHALLENGE,
        domain: 'verifier.example'
      },
      session,
      credentialRequestOrigin: 'https://verifier.example'
    })

    const vp = verifiablePresentation as unknown as {
      zcap?: IZcap[]
      proof?: { proofPurpose?: string }
    }
    expect(vp.zcap).toHaveLength(2)
    expect(vp.proof?.proofPurpose).toBe('authentication')

    const { suite } = presentationSuiteFor({
      signer: session.profile.keyAgent!.getSigner()
    })
    const result = await vc.verify({
      presentation: verifiablePresentation as never,
      challenge: CHALLENGE,
      domain: 'verifier.example',
      suite,
      documentLoader
    })
    expect(result.verified).toBe(true)
  })

  it('returns an unsigned VP carrying the grants for a zcap-only request', async () => {
    const { verifiablePresentation } = await processRequest({
      request: {
        query: [
          {
            type: 'ZcapQuery',
            capabilityQuery: collectionDetail
          }
        ]
      },
      session,
      credentialRequestOrigin: 'https://verifier.example'
    })
    const vp = verifiablePresentation as unknown as {
      zcap?: IZcap[]
      proof?: unknown
    }
    expect(vp.proof).toBeUndefined()
    expect(vp.zcap).toHaveLength(1)
  })

  it('enforces domain binding before delegating on a zcap request', async () => {
    await expect(
      processRequest({
        request: {
          query: [
            {
              type: 'AuthorizationCapabilityQuery',
              capabilityQuery: [collectionDetail]
            }
          ],
          domain: 'attacker.example'
        },
        session,
        credentialRequestOrigin: 'https://verifier.example'
      })
    ).rejects.toThrow(/does not match request origin/)
  })
})
