// @vitest-environment node
import { describe, it, expect, beforeAll, beforeEach } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import * as vc from '@interop/vc'
import { securityLoader } from '@interop/security-document-loader'
import type { Session } from '@/types/auth'
import type { ICapabilityQueryDetail, IZcap } from '@/lib/walletRequest'
import { x25519RecipientFromDidKey } from '@interop/was-client/edv'
import {
  existingCollectionsFrom,
  resolveInvocationTarget,
  resolveGrant,
  resolveGrants,
  processZcaps,
  processRequest,
  presentationSuiteFor
} from '@/lib/walletRequest'

const documentLoader = securityLoader({ fetchRemoteContexts: true }).build()

const SPACE_URL = 'https://was.example.com/space/L8qcqABC'
const RP_DID = 'did:key:z6MkrRPexampleRelyingParty'
const CHALLENGE = '99612b24-63d9-11ea-b99f-4f66f3e4f81a'

// The existing-collections snapshot resolution consults; the empty default is
// a Space where every named collection is new. `collectionListing` backs the
// session stub's `listCollectionPublicStates`, so processZcaps tests can stage
// existing collections per test.
const NO_COLLECTIONS = existingCollectionsFrom([])
let collectionListing: Array<{ id: string; isPublic?: boolean }> = []

const collectionDetail: ICapabilityQueryDetail = {
  referenceId: 'example-app-data',
  reason: 'Example App stores your documents in your wallet storage.',
  allowedAction: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'],
  controller: RP_DID,
  invocationTarget: {
    type: 'https://w3id.org/byoe#private-collection',
    name: 'example-app-data'
  }
}

const spaceDetail: ICapabilityQueryDetail = {
  referenceId: 'space-read',
  allowedAction: ['GET', 'HEAD', 'PUT'],
  controller: RP_DID,
  invocationTarget: { type: 'https://w3id.org/byoe#space' }
}

// A write request on a standard wallet collection (via descriptor object).
const standardCollectionDetail: ICapabilityQueryDetail = {
  referenceId: 'private-write',
  allowedAction: ['GET', 'HEAD', 'PUT', 'DELETE'],
  controller: RP_DID,
  invocationTarget: {
    type: 'https://w3id.org/byoe#private-collection',
    name: 'private-credentials'
  }
}

// A write request on a standard wallet collection, expressed as a plain URL.
const standardCollectionUrlDetail: ICapabilityQueryDetail = {
  referenceId: 'private-write-url',
  allowedAction: ['GET', 'HEAD', 'PUT', 'DELETE'],
  controller: RP_DID,
  invocationTarget: `${SPACE_URL}/private-credentials`
}

// A write request on a resource *inside* a standard collection (plain URL).
const standardResourceUrlDetail: ICapabilityQueryDetail = {
  referenceId: 'private-resource-write-url',
  allowedAction: ['GET', 'HEAD', 'PUT', 'DELETE'],
  controller: RP_DID,
  invocationTarget: `${SPACE_URL}/private-credentials/some-resource`
}

// A write request on the `id` collection (the published DID document).
const idCollectionDetail: ICapabilityQueryDetail = {
  referenceId: 'id-write',
  allowedAction: ['GET', 'HEAD', 'PUT', 'DELETE'],
  controller: RP_DID,
  invocationTarget: {
    type: 'https://w3id.org/byoe#private-collection',
    name: 'id'
  }
}

// A write request on the `key-map` collection (the private key-id map).
const keyMapCollectionDetail: ICapabilityQueryDetail = {
  referenceId: 'key-map-write',
  allowedAction: ['GET', 'HEAD', 'PUT', 'DELETE'],
  controller: RP_DID,
  invocationTarget: {
    type: 'https://w3id.org/byoe#private-collection',
    name: 'key-map'
  }
}

// A write request on the `unlock-methods` collection (the account's registry
// of unlock methods).
const unlockMethodsCollectionDetail: ICapabilityQueryDetail = {
  referenceId: 'unlock-methods-write',
  allowedAction: ['GET', 'HEAD', 'PUT', 'DELETE'],
  controller: RP_DID,
  invocationTarget: {
    type: 'https://w3id.org/byoe#private-collection',
    name: 'unlock-methods'
  }
}

// The same write request, spelled as a plain URL under the Space.
const unlockMethodsCollectionUrlDetail: ICapabilityQueryDetail = {
  referenceId: 'unlock-methods-write-url',
  allowedAction: ['GET', 'HEAD', 'PUT', 'DELETE'],
  controller: RP_DID,
  invocationTarget: `${SPACE_URL}/unlock-methods`
}

// A write request on the DID document resource itself (plain URL).
const didDocumentUrlDetail: ICapabilityQueryDetail = {
  referenceId: 'did-doc-write-url',
  allowedAction: ['PUT'],
  controller: RP_DID,
  invocationTarget: `${SPACE_URL}/id/did.json`
}

// A public-collection request: plaintext + collection-level PublicCanRead.
const publicCollectionDetail: ICapabilityQueryDetail = {
  referenceId: 'example-app-public',
  reason: 'Example App publishes your posts for anyone to read.',
  allowedAction: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'],
  controller: RP_DID,
  invocationTarget: {
    type: 'https://w3id.org/byoe#public-collection',
    name: 'example-app-public'
  }
}

const foreignDetail: ICapabilityQueryDetail = {
  controller: RP_DID,
  invocationTarget: 'https://someone-else.example/space/OTHER/data'
}

// A share request: read AND decrypt an encrypted standard collection. Its
// controller is a real did:key (filled in `beforeAll`), because the recipient
// key is derived from it.
const shareDetail: ICapabilityQueryDetail = {
  referenceId: 'shared-credentials',
  controller: '',
  invocationTarget: {
    type: 'https://w3id.org/byoe#shared-wallet-collection',
    name: 'private-credentials'
  }
}

/**
 * A session whose `keyAgent` really signs (for the round-trip VP
 * test), but whose `zcapClient.delegate` and `storage.ensureCollection` are
 * stubbed -- delegation and provisioning hit the WAS server in production.
 */
let session: Session
let delegated: Array<Record<string, unknown>>
let ensureCalls: Array<{ id: string; isPublic?: boolean }>
let provisionCalls: Array<{ collectionId: string; recipientId: string }>
let shareCalls: Array<{
  collectionId: string
  recipientId: string
  controller: string
  expires?: Date
  app?: { name: string; origin: string }
}>
// A real did:key, so the share flow can derive an X25519 twin from it.
let granteeDid: string

beforeAll(async () => {
  const keyAgent = await CapabilityAgent.fromSecret({
    secret: 'correct horse battery staple',
    handle: 'test',
    keyName: 'test-key'
  })
  const grantee = await CapabilityAgent.fromSecret({
    secret: 'a grantee secret',
    handle: 'test',
    keyName: 'test-key'
  })
  granteeDid = grantee.id
  shareDetail.controller = granteeDid
  delegated = []
  ensureCalls = []
  provisionCalls = []
  shareCalls = []

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
    async listCollectionPublicStates() {
      return collectionListing
    },
    async ensureCollection({
      id,
      isPublic
    }: {
      id: string
      isPublic?: boolean
    }) {
      ensureCalls.push({ id, isPublic })
    },
    async provisionAppCollection({
      collectionId,
      appRecipient
    }: {
      collectionId: string
      appRecipient: { id: string }
    }) {
      provisionCalls.push({ collectionId, recipientId: appRecipient.id })
      return { scheme: 'edv' }
    },
    async shareCollection({
      collectionId,
      recipient,
      controller,
      expires,
      app
    }: {
      collectionId: string
      recipient: { id: string }
      controller: string
      expires?: Date
      app?: { name: string; origin: string }
    }) {
      shareCalls.push({
        collectionId,
        recipientId: recipient.id,
        controller,
        expires,
        app
      })
      const zcap = {
        id: `urn:zcap:delegated:share:${collectionId}`,
        invocationTarget: `${SPACE_URL}/${collectionId}`,
        controller,
        allowedAction: ['GET', 'HEAD'],
        expires: expires?.toISOString()
      }
      delegated.push(zcap)
      return { descriptor: { scheme: 'edv' }, zcap }
    }
  }

  session = {
    user: { id: keyAgent.id },
    profile: { keyAgent, zcapClient },
    storage
  } as unknown as Session
})

beforeEach(() => {
  // Default: a Space with no listed collections; tests that need existing
  // collections stage their own listing.
  collectionListing = []
})

describe('resolveInvocationTarget', () => {
  it('accepts a plain URL under the Space, verbatim', () => {
    const target = resolveInvocationTarget({
      descriptor: `${SPACE_URL}/example-app-data/doc1`,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(target).toMatchObject({
      satisfiable: true,
      invocationTarget: `${SPACE_URL}/example-app-data/doc1`,
      wholeSpace: false,
      needsProvisioning: false,
      targetClass: 'collection'
    })
  })

  it('treats an exact Space URL string as a whole-Space grant', () => {
    const target = resolveInvocationTarget({
      descriptor: SPACE_URL,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(target).toMatchObject({
      satisfiable: true,
      wholeSpace: true,
      targetClass: 'space'
    })
    expect(target.collectionId).toBeUndefined()
  })

  it('treats the Space URL with a trailing slash as a whole-Space grant', () => {
    const target = resolveInvocationTarget({
      descriptor: `${SPACE_URL}/`,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    // The trailing slash is normalized off the delegated target.
    expect(target).toMatchObject({
      satisfiable: true,
      invocationTarget: SPACE_URL,
      wholeSpace: true,
      targetClass: 'space'
    })
    expect(target.collectionId).toBeUndefined()
  })

  it('refuses a foreign URL', () => {
    const target = resolveInvocationTarget({
      descriptor: 'https://someone-else.example/space/OTHER',
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(target.satisfiable).toBe(false)
    expect(target.targetClass).toBeUndefined()
  })

  // These previously classified as an RP `collection` (the string started with
  // `${SPACE_URL}/` and the segment was read off it verbatim), so a query or a
  // fragment smuggled past the prefix check earned the full write ceiling on a
  // target the server would route somewhere else entirely.
  it('refuses a plain-URL target carrying a query or a fragment', () => {
    for (const descriptor of [
      `${SPACE_URL}/private-credentials?x=1`,
      `${SPACE_URL}/private-credentials#frag`,
      `${SPACE_URL}/example-app-data/doc1?x=1`,
      `${SPACE_URL}?x=1`,
      `${SPACE_URL}#frag`
    ]) {
      const target = resolveInvocationTarget({
        descriptor,
        spaceUrl: SPACE_URL,
        collections: NO_COLLECTIONS
      })
      expect(target.satisfiable).toBe(false)
      expect(target.targetClass).toBeUndefined()
    }
  })

  it('refuses a path that escapes the Space through dot segments', () => {
    for (const descriptor of [
      `${SPACE_URL}/../other-space/private`,
      `${SPACE_URL}/example-app-data/../../other-space/private`,
      `${SPACE_URL}/..`
    ]) {
      const target = resolveInvocationTarget({
        descriptor,
        spaceUrl: SPACE_URL,
        collections: NO_COLLECTIONS
      })
      expect(target.satisfiable).toBe(false)
      expect(target.targetClass).toBeUndefined()
    }
  })

  it('refuses a first path segment that is not a valid collection id', () => {
    for (const segment of [
      'Upper-Case',
      '-leading-hyphen',
      'has%20space',
      'x'.repeat(65)
    ]) {
      const target = resolveInvocationTarget({
        descriptor: `${SPACE_URL}/${segment}/doc1`,
        spaceUrl: SPACE_URL,
        collections: NO_COLLECTIONS
      })
      expect(target.satisfiable).toBe(false)
      expect(target.targetClass).toBeUndefined()
    }
  })

  it('refuses a differing origin on an otherwise identical path', () => {
    const space = new URL(SPACE_URL)
    for (const origin of [
      `http://${space.host}`,
      `https://${space.hostname}:8443`,
      'https://was.example.com.evil'
    ]) {
      const target = resolveInvocationTarget({
        descriptor: `${origin}${space.pathname}/example-app-data`,
        spaceUrl: SPACE_URL,
        collections: NO_COLLECTIONS
      })
      expect(target.satisfiable).toBe(false)
      expect(target.targetClass).toBeUndefined()
    }
  })

  it('normalizes a trailing slash off a collection URL', () => {
    const withSlash = resolveInvocationTarget({
      descriptor: `${SPACE_URL}/example-app-data/`,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    const without = resolveInvocationTarget({
      descriptor: `${SPACE_URL}/example-app-data`,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(withSlash).toMatchObject({
      satisfiable: true,
      invocationTarget: `${SPACE_URL}/example-app-data`,
      collectionId: 'example-app-data',
      targetClass: 'collection'
    })
    expect(withSlash.invocationTarget).toBe(without.invocationTarget)
  })

  it('classifies a deep resource URL under a protected collection', () => {
    const url = `${SPACE_URL}/private-credentials/sub/path/resource-1`
    expect(
      resolveInvocationTarget({
        descriptor: url,
        spaceUrl: SPACE_URL,
        collections: NO_COLLECTIONS
      })
    ).toMatchObject({
      satisfiable: true,
      invocationTarget: url,
      wholeSpace: false,
      collectionId: 'private-credentials',
      encrypted: true,
      targetClass: 'protected-collection'
    })
  })

  it('resolves a named RP collection and flags provisioning', () => {
    const target = resolveInvocationTarget({
      descriptor: {
        type: 'https://w3id.org/byoe#private-collection',
        name: 'example-app-data'
      },
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(target).toMatchObject({
      satisfiable: true,
      invocationTarget: `${SPACE_URL}/example-app-data`,
      needsProvisioning: true,
      collectionId: 'example-app-data',
      encrypted: false,
      targetClass: 'collection'
    })
  })

  it('grants an existing standard collection without provisioning', () => {
    const target = resolveInvocationTarget({
      descriptor: {
        type: 'https://w3id.org/byoe#private-collection',
        name: 'public-credentials'
      },
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(target).toMatchObject({
      needsProvisioning: false,
      encrypted: false,
      targetClass: 'protected-collection'
    })
  })

  it('flags an encrypted standard collection', () => {
    const target = resolveInvocationTarget({
      descriptor: {
        type: 'https://w3id.org/byoe#private-collection',
        name: 'private-credentials'
      },
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(target).toMatchObject({
      needsProvisioning: false,
      encrypted: true,
      targetClass: 'protected-collection'
    })
  })

  it('treats the system collections as protected and present', () => {
    for (const name of ['id', 'key-map', 'unlock-methods']) {
      expect(
        resolveInvocationTarget({
          descriptor: {
            type: 'https://w3id.org/byoe#private-collection',
            name
          },
          spaceUrl: SPACE_URL,
          collections: NO_COLLECTIONS
        })
      ).toMatchObject({
        satisfiable: true,
        needsProvisioning: false,
        encrypted: false,
        targetClass: 'protected-collection'
      })
    }
  })

  it('rejects an invalid collection name', () => {
    expect(
      resolveInvocationTarget({
        descriptor: {
          type: 'https://w3id.org/byoe#private-collection',
          name: 'Bad_Name!'
        },
        spaceUrl: SPACE_URL,
        collections: NO_COLLECTIONS
      }).satisfiable
    ).toBe(false)
  })

  it('resolves the whole Space', () => {
    expect(
      resolveInvocationTarget({
        descriptor: { type: 'https://w3id.org/byoe#space' },
        spaceUrl: SPACE_URL,
        collections: NO_COLLECTIONS
      })
    ).toMatchObject({
      satisfiable: true,
      invocationTarget: SPACE_URL,
      wholeSpace: true,
      targetClass: 'space'
    })
  })

  it('refuses an unknown descriptor type', () => {
    const target = resolveInvocationTarget({
      descriptor: { type: 'https://w3id.org/byoe#unknown' },
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(target.satisfiable).toBe(false)
    expect(target.targetClass).toBeUndefined()
  })

  it('resolves a public collection: plaintext, provisioned, isPublic', () => {
    const target = resolveInvocationTarget({
      descriptor: {
        type: 'https://w3id.org/byoe#public-collection',
        name: 'example-app-public'
      },
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(target).toMatchObject({
      satisfiable: true,
      invocationTarget: `${SPACE_URL}/example-app-public`,
      needsProvisioning: true,
      collectionId: 'example-app-public',
      encrypted: false,
      isPublic: true,
      targetClass: 'public-collection'
    })
  })

  it('never flags a non-public descriptor isPublic', () => {
    for (const descriptor of [
      {
        type: 'https://w3id.org/byoe#private-collection',
        name: 'example-app-data'
      },
      { type: 'https://w3id.org/byoe#space' }
    ]) {
      expect(
        resolveInvocationTarget({
          descriptor,
          spaceUrl: SPACE_URL,
          collections: NO_COLLECTIONS
        }).isPublic
      ).toBe(false)
    }
    expect(
      resolveInvocationTarget({
        descriptor: `${SPACE_URL}/example-app-data`,
        spaceUrl: SPACE_URL,
        collections: NO_COLLECTIONS
      }).isPublic
    ).toBe(false)
  })

  it('refuses a public grant on protected wallet collections', () => {
    for (const name of [
      'private-credentials',
      'public-credentials',
      'wallet-activity',
      'id',
      'key-map',
      'unlock-methods'
    ]) {
      expect(
        resolveInvocationTarget({
          descriptor: { type: 'https://w3id.org/byoe#public-collection', name },
          spaceUrl: SPACE_URL,
          collections: NO_COLLECTIONS
        }).satisfiable
      ).toBe(false)
    }
  })

  it('resolves a share of an encrypted standard collection', () => {
    const target = resolveInvocationTarget({
      descriptor: {
        type: 'https://w3id.org/byoe#shared-wallet-collection',
        name: 'private-credentials'
      },
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(target).toMatchObject({
      satisfiable: true,
      invocationTarget: `${SPACE_URL}/private-credentials`,
      needsProvisioning: false,
      collectionId: 'private-credentials',
      encrypted: true,
      isPublic: false,
      isShare: true,
      targetClass: 'share'
    })
  })

  it('resolves a share of every encrypted standard collection', () => {
    // The rule is "any standard collection with an encryption descriptor", so the
    // contacts collections are shareable on the same terms as credentials.
    for (const name of ['wallet-activity', 'contacts', 'contacts-history']) {
      expect(
        resolveInvocationTarget({
          descriptor: {
            type: 'https://w3id.org/byoe#shared-wallet-collection',
            name
          },
          spaceUrl: SPACE_URL,
          collections: NO_COLLECTIONS
        })
      ).toMatchObject({ satisfiable: true, isShare: true, encrypted: true })
    }
  })

  it('refuses a share of anything but an encrypted standard collection', () => {
    // Plaintext standard collection, the `id` / `key-map` collections, an RP
    // collection, a made-up name, a missing name -- none has an epoch roster.
    for (const name of [
      'public-credentials',
      'id',
      'key-map',
      'unlock-methods',
      'example-app-data',
      'not-a-collection',
      undefined
    ]) {
      expect(
        resolveInvocationTarget({
          descriptor: {
            type: 'https://w3id.org/byoe#shared-wallet-collection',
            name
          },
          spaceUrl: SPACE_URL,
          collections: NO_COLLECTIONS
        }).satisfiable
      ).toBe(false)
    }
  })

  it('never flags an ordinary descriptor isShare', () => {
    for (const descriptor of [
      {
        type: 'https://w3id.org/byoe#private-collection',
        name: 'private-credentials'
      },
      {
        type: 'https://w3id.org/byoe#public-collection',
        name: 'example-app-public'
      },
      { type: 'https://w3id.org/byoe#space' }
    ]) {
      expect(
        resolveInvocationTarget({
          descriptor,
          spaceUrl: SPACE_URL,
          collections: NO_COLLECTIONS
        }).isShare
      ).toBe(false)
    }
    expect(
      resolveInvocationTarget({
        descriptor: `${SPACE_URL}/private-credentials`,
        spaceUrl: SPACE_URL,
        collections: NO_COLLECTIONS
      }).isShare
    ).toBe(false)
  })

  it('rejects an invalid public-collection name', () => {
    expect(
      resolveInvocationTarget({
        descriptor: {
          type: 'https://w3id.org/byoe#public-collection',
          name: 'Bad_Name!'
        },
        spaceUrl: SPACE_URL,
        collections: NO_COLLECTIONS
      }).satisfiable
    ).toBe(false)
    expect(
      resolveInvocationTarget({
        descriptor: { type: 'https://w3id.org/byoe#public-collection' },
        spaceUrl: SPACE_URL,
        collections: NO_COLLECTIONS
      }).satisfiable
    ).toBe(false)
  })
})

describe('existing-collection state (create-only public collections)', () => {
  // A Space that already holds one private RP collection (which stands in for
  // any existing non-public collection, an encrypted App Connect one
  // included -- only the public state matters) and one public collection.
  const EXISTING = existingCollectionsFrom([
    { id: 'example-app-data', isPublic: false },
    { id: 'example-app-public', isPublic: true }
  ])

  it('refuses a public grant that would convert an existing collection', () => {
    // A second app naming another app's existing (possibly encrypted)
    // collection in a public-collection entry must not be able to flip it
    // world-readable after one consent approval.
    const target = resolveInvocationTarget({
      descriptor: {
        type: 'https://w3id.org/byoe#public-collection',
        name: 'example-app-data'
      },
      spaceUrl: SPACE_URL,
      collections: EXISTING
    })
    expect(target.satisfiable).toBe(false)
    expect(target.targetClass).toBeUndefined()
  })

  it('keeps the re-grant on an already-public collection satisfiable', () => {
    const target = resolveInvocationTarget({
      descriptor: {
        type: 'https://w3id.org/byoe#public-collection',
        name: 'example-app-public'
      },
      spaceUrl: SPACE_URL,
      collections: EXISTING
    })
    // Satisfiable, but with nothing to provision: the policy is never
    // re-applied to an existing collection.
    expect(target).toMatchObject({
      satisfiable: true,
      needsProvisioning: false,
      collectionId: 'example-app-public',
      isPublic: true,
      targetClass: 'public-collection'
    })
  })

  it('caps a string target naming a public collection add-only', () => {
    for (const invocationTarget of [
      `${SPACE_URL}/example-app-public`,
      `${SPACE_URL}/example-app-public/some-resource`
    ]) {
      const grant = resolveGrant({
        descriptor: {
          controller: RP_DID,
          allowedAction: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
          invocationTarget
        },
        spaceUrl: SPACE_URL,
        collections: EXISTING
      })
      expect(grant.target.targetClass).toBe('public-collection')
      expect(grant.target.isPublic).toBe(true)
      expect(grant.allowedActions).toEqual(['GET', 'HEAD', 'POST'])
    }
  })

  it('caps a plain collection descriptor naming a public collection too', () => {
    // Ceiling parity holds for every spelling of the target, so asking via
    // `#collection` cannot recover the full RP-collection vocabulary either.
    const grant = resolveGrant({
      descriptor: {
        controller: RP_DID,
        allowedAction: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
        invocationTarget: {
          type: 'https://w3id.org/byoe#private-collection',
          name: 'example-app-public'
        }
      },
      spaceUrl: SPACE_URL,
      collections: EXISTING
    })
    expect(grant.target.targetClass).toBe('public-collection')
    expect(grant.target.isPublic).toBe(true)
    // Nothing to provision either: the `#collection` spelling of an existing
    // public collection is the idempotent public re-grant, so the public
    // policy is never re-applied and no recipient roster is ever set up on a
    // world-readable collection.
    expect(grant.target.needsProvisioning).toBe(false)
    expect(grant.allowedActions).toEqual(['GET', 'HEAD', 'POST'])
  })

  it('keeps the full ceiling on an existing private RP collection', () => {
    const grant = resolveGrant({
      descriptor: {
        controller: RP_DID,
        allowedAction: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
        invocationTarget: `${SPACE_URL}/example-app-data`
      },
      spaceUrl: SPACE_URL,
      collections: EXISTING
    })
    expect(grant.target.targetClass).toBe('collection')
    expect(grant.allowedActions).toEqual([
      'GET',
      'HEAD',
      'POST',
      'PUT',
      'DELETE'
    ])
  })
})

describe('resolveGrant action handling', () => {
  it('defaults an absent allowedAction to read-only', () => {
    const grant = resolveGrant({
      descriptor: {
        controller: RP_DID,
        invocationTarget: {
          type: 'https://w3id.org/byoe#private-collection',
          name: 'app-data'
        }
      },
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
  })

  it('strips whole-Space grants to read-only', () => {
    const grant = resolveGrant({
      descriptor: spaceDetail,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
  })

  it('passes through explicit RP-collection actions and flags write', () => {
    const grant = resolveGrant({
      descriptor: collectionDetail,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    // Emitted in ceiling order, not in the order the request asked in.
    expect(grant.allowedActions).toEqual([
      'GET',
      'HEAD',
      'POST',
      'PUT',
      'DELETE'
    ])
    expect(grant.write).toBe(true)
  })

  it('caps a standard-collection write to read-only (descriptor form)', () => {
    const grant = resolveGrant({
      descriptor: standardCollectionDetail,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
    expect(grant.write).toBe(false)
  })

  it('caps a standard-collection write to read-only (string URL form)', () => {
    const grant = resolveGrant({
      descriptor: standardCollectionUrlDetail,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.collectionId).toBe('private-credentials')
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
    expect(grant.write).toBe(false)
  })

  it('caps a write to a resource inside a standard collection (string URL)', () => {
    const grant = resolveGrant({
      descriptor: standardResourceUrlDetail,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.collectionId).toBe('private-credentials')
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
    expect(grant.write).toBe(false)
  })

  it('caps an id-collection write to read-only (descriptor form)', () => {
    const grant = resolveGrant({
      descriptor: idCollectionDetail,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.collectionId).toBe('id')
    // Provisioned at login, like the standard collections.
    expect(grant.target.needsProvisioning).toBe(false)
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
    expect(grant.write).toBe(false)
  })

  it('caps a key-map-collection write to read-only (descriptor form)', () => {
    const grant = resolveGrant({
      descriptor: keyMapCollectionDetail,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.collectionId).toBe('key-map')
    // Provisioned at login, like the standard and `id` collections.
    expect(grant.target.needsProvisioning).toBe(false)
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
    expect(grant.write).toBe(false)
  })

  it('caps an unlock-methods-collection write to read-only (descriptor form)', () => {
    const grant = resolveGrant({
      descriptor: unlockMethodsCollectionDetail,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.collectionId).toBe('unlock-methods')
    // A system collection, provisioned by the wallet itself.
    expect(grant.target.needsProvisioning).toBe(false)
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
    expect(grant.write).toBe(false)
  })

  it('caps an unlock-methods-collection write to read-only (string URL)', () => {
    const grant = resolveGrant({
      descriptor: unlockMethodsCollectionUrlDetail,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.collectionId).toBe('unlock-methods')
    expect(grant.target.needsProvisioning).toBe(false)
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
    expect(grant.write).toBe(false)
  })

  it('refuses a PUT-only grant on the DID document resource', () => {
    // The descriptor asks for PUT alone on the protected `id` collection, so
    // nothing survives that class's read-only ceiling. This used to silently
    // downgrade to a read-only grant; now the grant is refused outright, since
    // an empty `allowedAction` array means "every action" in the zcap model.
    const grant = resolveGrant({
      descriptor: didDocumentUrlDetail,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.satisfiable).toBe(false)
    expect(grant.allowedActions).toEqual([])
    expect(grant.write).toBe(false)
  })

  it('marks a read-only grant as not a write', () => {
    const grant = resolveGrant({
      descriptor: spaceDetail,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.write).toBe(false)
  })

  it('caps a public RP collection to add-only', () => {
    // A write to a plaintext world-readable target is not data management but
    // publication under the user's identity, and irreversible in practice: an
    // RP may add to what it published, never rewrite or retract it.
    const grant = resolveGrant({
      descriptor: publicCollectionDetail,
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.isPublic).toBe(true)
    expect(grant.allowedActions).toEqual(['GET', 'HEAD', 'POST'])
    expect(grant.write).toBe(true)
  })
})

describe('resolveGrant action vocabulary', () => {
  /**
   * A capability query on an RP collection (the only class whose ceiling is the
   * full vocabulary, so normalization is what the assertion is measuring).
   *
   * @param allowedAction {ICapabilityQueryDetail['allowedAction']}
   * @returns {ICapabilityQueryDetail}
   */
  function rpQuery(
    allowedAction: ICapabilityQueryDetail['allowedAction']
  ): ICapabilityQueryDetail {
    return {
      controller: RP_DID,
      allowedAction,
      invocationTarget: {
        type: 'https://w3id.org/byoe#private-collection',
        name: 'example-app-data'
      }
    }
  }

  it('accepts a single (non-array) action string', () => {
    const grant = resolveGrant({
      descriptor: rpQuery('PUT'),
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.allowedActions).toEqual(['PUT'])
    expect(grant.write).toBe(true)
  })

  it('uppercases, trims, dedupes, and drops non-vocabulary tokens', () => {
    const grant = resolveGrant({
      descriptor: rpQuery([
        'get',
        ' Put ',
        'GET',
        'FROBNICATE',
        'PATCH',
        'OPTIONS',
        42 as unknown as string,
        null as unknown as string,
        { action: 'DELETE' },
        ['POST'] as unknown as string
      ]),
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.allowedActions).toEqual(['GET', 'PUT'])
    expect(grant.write).toBe(true)
  })

  it('makes an all-dropped action set unsatisfiable, never empty-allowed', () => {
    // An empty `allowedAction` array means "every action" in the zcap model, so
    // a request that asks only for tokens outside the vocabulary is refused.
    const grant = resolveGrant({
      descriptor: rpQuery(['FROBNICATE', 'PATCH']),
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.satisfiable).toBe(false)
    expect(grant.target.invocationTarget).toBeUndefined()
    expect(grant.allowedActions).toEqual([])
    expect(grant.write).toBe(false)
  })

  it('makes an all-above-ceiling action set unsatisfiable', () => {
    const grant = resolveGrant({
      descriptor: {
        controller: RP_DID,
        allowedAction: ['PUT', 'DELETE'],
        invocationTarget: { type: 'https://w3id.org/byoe#space' }
      },
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.satisfiable).toBe(false)
    expect(grant.allowedActions).toEqual([])
  })

  it('makes an empty action array unsatisfiable rather than grant-all', () => {
    const grant = resolveGrant({
      descriptor: rpQuery([]),
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.satisfiable).toBe(false)
    expect(grant.allowedActions).toEqual([])
  })

  it('never yields an empty allowedActions on a satisfiable grant', () => {
    const grants = resolveGrants({
      zcapRequests: [
        collectionDetail,
        spaceDetail,
        publicCollectionDetail,
        standardCollectionDetail,
        didDocumentUrlDetail,
        foreignDetail,
        rpQuery(['PATCH']),
        rpQuery([])
      ],
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    for (const grant of grants) {
      if (grant.target.satisfiable) {
        expect(grant.allowedActions.length).toBeGreaterThan(0)
      } else {
        expect(grant.allowedActions).toEqual([])
      }
    }
  })
})

describe('processZcaps', () => {
  const READ_TTL_MS = 720 * 60 * 60 * 1000
  const WRITE_TTL_MS = 168 * 60 * 60 * 1000

  it('delegates satisfiable grants, provisions, and skips foreign targets', async () => {
    delegated.length = 0
    ensureCalls.length = 0
    const before = Date.now()
    const zcaps = await processZcaps({
      zcapRequests: [collectionDetail, spaceDetail, foreignDetail],
      session,
      ttlMs: READ_TTL_MS,
      writeTtlMs: WRITE_TTL_MS
    })

    expect(zcaps).toHaveLength(2)
    // Only the un-provisioned RP collection is created (and not made public).
    expect(ensureCalls).toEqual([{ id: 'example-app-data', isPublic: false }])

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
    // Emitted in ceiling order, not in the order the request asked in.
    expect(collectionZcap.allowedAction).toEqual([
      'GET',
      'HEAD',
      'POST',
      'PUT',
      'DELETE'
    ])

    const spaceZcap = zcaps[1] as unknown as {
      invocationTarget: string
      allowedAction: string[]
    }
    expect(spaceZcap.invocationTarget).toBe(SPACE_URL)
    expect(spaceZcap.allowedAction).toEqual(['GET', 'HEAD'])

    // The RP collection grant is a write, so it uses the shorter write TTL.
    const expiresMs = new Date(collectionZcap.expires).getTime()
    const expected = before + WRITE_TTL_MS
    expect(Math.abs(expiresMs - expected)).toBeLessThan(60 * 1000)
  })

  it('App Connect: provisions a private collection multi-recipient, a public one plaintext', async () => {
    delegated.length = 0
    ensureCalls.length = 0
    provisionCalls.length = 0
    await processZcaps({
      zcapRequests: [
        // A real did:key controller: the app's recipient key is the X25519
        // twin of the DID the wallet is delegating to, exactly as for a share.
        { ...collectionDetail, controller: granteeDid },
        publicCollectionDetail
      ],
      session,
      appProvisioning: true
    })

    // The private collection routed through provisionAppCollection (with the
    // identity-KAK recipient kid); the public one stayed plaintext via
    // ensureCollection.
    expect(provisionCalls).toHaveLength(1)
    expect(provisionCalls[0].collectionId).toBe('example-app-data')
    expect(provisionCalls[0].recipientId).toBe(
      x25519RecipientFromDidKey({ did: granteeDid }).id
    )
    expect(ensureCalls).toEqual([{ id: 'example-app-public', isPublic: true }])
  })

  it('App Connect: refuses to provision for an underivable controller', async () => {
    provisionCalls.length = 0
    // Right prefix, undecodable body: there is no X25519 twin to admit the app
    // with, so the collection is never created half-encrypted.
    await expect(
      processZcaps({
        zcapRequests: [{ ...collectionDetail, controller: 'did:key:z6MkZZZZ' }],
        session,
        appProvisioning: true
      })
    ).rejects.toThrow()
    expect(provisionCalls).toHaveLength(0)
  })

  it('without appProvisioning, a private collection provisions plaintext', async () => {
    delegated.length = 0
    ensureCalls.length = 0
    provisionCalls.length = 0
    await processZcaps({
      zcapRequests: [collectionDetail],
      session
    })
    expect(provisionCalls).toHaveLength(0)
    expect(ensureCalls).toEqual([{ id: 'example-app-data', isPublic: false }])
  })

  it('caps a standard-collection write to read-only when delegating', async () => {
    delegated.length = 0
    ensureCalls.length = 0
    const zcaps = await processZcaps({
      zcapRequests: [standardCollectionDetail, standardResourceUrlDetail],
      session
    })
    // Standard collections are never provisioned.
    expect(ensureCalls).toEqual([])
    expect(zcaps).toHaveLength(2)
    for (const zcap of zcaps) {
      expect(
        (zcap as unknown as { allowedAction: string[] }).allowedAction
      ).toEqual(['GET', 'HEAD'])
    }
  })

  it('gives write grants the shorter TTL and read grants the longer one', async () => {
    delegated.length = 0
    ensureCalls.length = 0
    const before = Date.now()
    const zcaps = await processZcaps({
      // Write (RP collection) then read-only (standard collection).
      zcapRequests: [collectionDetail, standardCollectionDetail],
      session,
      ttlMs: READ_TTL_MS,
      writeTtlMs: WRITE_TTL_MS
    })

    const writeExpires = new Date(
      (zcaps[0] as unknown as { expires: string }).expires
    ).getTime()
    const readExpires = new Date(
      (zcaps[1] as unknown as { expires: string }).expires
    ).getTime()
    expect(Math.abs(writeExpires - (before + WRITE_TTL_MS))).toBeLessThan(
      60 * 1000
    )
    expect(Math.abs(readExpires - (before + READ_TTL_MS))).toBeLessThan(
      60 * 1000
    )
    // The write grant expires strictly sooner than the read-only grant.
    expect(writeExpires).toBeLessThan(readExpires)
  })

  it('provisions a public collection as public and delegates an add-only zcap', async () => {
    delegated.length = 0
    ensureCalls.length = 0
    const before = Date.now()
    const zcaps = await processZcaps({
      zcapRequests: [publicCollectionDetail],
      session,
      ttlMs: READ_TTL_MS,
      writeTtlMs: WRITE_TTL_MS
    })

    expect(ensureCalls).toEqual([{ id: 'example-app-public', isPublic: true }])
    expect(zcaps).toHaveLength(1)
    const zcap = zcaps[0] as unknown as {
      invocationTarget: string
      allowedAction: string[]
      expires: string
    }
    expect(zcap.invocationTarget).toBe(`${SPACE_URL}/example-app-public`)
    // Public covers only unauthenticated reads; writes stay capability-only,
    // and are capped to add-only, with the ordinary write TTL. A write to a
    // plaintext world-readable target is publication under the user's identity
    // and irreversible in practice, so PUT and DELETE are dropped.
    expect(zcap.allowedAction).toEqual(['GET', 'HEAD', 'POST'])
    const expiresMs = new Date(zcap.expires).getTime()
    expect(Math.abs(expiresMs - (before + WRITE_TTL_MS))).toBeLessThan(
      60 * 1000
    )
  })

  it('skips a public grant on a protected collection entirely', async () => {
    delegated.length = 0
    ensureCalls.length = 0
    const zcaps = await processZcaps({
      zcapRequests: [
        {
          referenceId: 'protected-public',
          allowedAction: ['GET', 'HEAD'],
          controller: RP_DID,
          invocationTarget: {
            type: 'https://w3id.org/byoe#public-collection',
            name: 'private-credentials'
          }
        }
      ],
      session
    })
    expect(zcaps).toHaveLength(0)
    expect(ensureCalls).toEqual([])
  })

  it('skips a public grant that would convert an existing collection', async () => {
    // The listed collection stands in for another app's existing encrypted
    // collection: only its non-public state matters. Nothing is delegated and
    // nothing is provisioned, so the PublicCanRead policy is never applied.
    collectionListing = [{ id: 'example-app-data', isPublic: false }]
    delegated.length = 0
    ensureCalls.length = 0
    provisionCalls.length = 0
    const zcaps = await processZcaps({
      zcapRequests: [
        {
          referenceId: 'convert-attempt',
          allowedAction: ['GET', 'HEAD', 'POST'],
          controller: RP_DID,
          invocationTarget: {
            type: 'https://w3id.org/byoe#public-collection',
            name: 'example-app-data'
          }
        }
      ],
      session,
      appProvisioning: true
    })
    expect(zcaps).toHaveLength(0)
    expect(ensureCalls).toEqual([])
    expect(provisionCalls).toEqual([])
  })

  it('re-grants an already-public collection without re-provisioning', async () => {
    collectionListing = [{ id: 'example-app-public', isPublic: true }]
    delegated.length = 0
    ensureCalls.length = 0
    const zcaps = await processZcaps({
      zcapRequests: [publicCollectionDetail],
      session
    })
    // The delegation lands (idempotent re-grant), but the existing collection
    // is neither reconfigured nor has its policy re-set.
    expect(zcaps).toHaveLength(1)
    expect(ensureCalls).toEqual([])
    expect(
      (zcaps[0] as unknown as { allowedAction: string[] }).allowedAction
    ).toEqual(['GET', 'HEAD', 'POST'])
  })

  it('caps a string-target grant on an existing public collection add-only', async () => {
    collectionListing = [{ id: 'example-app-public', isPublic: true }]
    delegated.length = 0
    ensureCalls.length = 0
    const zcaps = await processZcaps({
      zcapRequests: [
        {
          referenceId: 'public-by-url',
          allowedAction: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
          controller: RP_DID,
          invocationTarget: `${SPACE_URL}/example-app-public`
        }
      ],
      session
    })
    expect(zcaps).toHaveLength(1)
    expect(
      (zcaps[0] as unknown as { allowedAction: string[] }).allowedAction
    ).toEqual(['GET', 'HEAD', 'POST'])
  })

  it('never re-provisions a #collection grant naming an existing public collection', async () => {
    collectionListing = [{ id: 'example-app-public', isPublic: true }]
    delegated.length = 0
    ensureCalls.length = 0
    provisionCalls.length = 0
    const zcaps = await processZcaps({
      zcapRequests: [
        {
          referenceId: 'collection-spelling',
          allowedAction: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
          controller: granteeDid,
          invocationTarget: {
            type: 'https://w3id.org/byoe#private-collection',
            name: 'example-app-public'
          }
        }
      ],
      session,
      appProvisioning: true
    })
    // The `#collection` spelling of an existing public collection is the
    // idempotent public re-grant: add-only, nothing provisioned -- so the
    // public policy is not re-applied, and on App Connect no recipient
    // roster is set up on a world-readable plaintext collection.
    expect(zcaps).toHaveLength(1)
    expect(ensureCalls).toEqual([])
    expect(provisionCalls).toEqual([])
    expect(
      (zcaps[0] as unknown as { allowedAction: string[] }).allowedAction
    ).toEqual(['GET', 'HEAD', 'POST'])
  })

  it('refuses a same-request public grant on a just-provisioned private collection', async () => {
    // One request, two descriptors naming the same collection: the first
    // provisions it private (on App Connect: encrypted, multi-recipient), the
    // second asks for it public. The snapshot records the in-request
    // provisioning, so the create-only rule sees an existing non-public
    // collection and refuses -- one consent approval must not flip the
    // just-created encrypted collection world-readable.
    delegated.length = 0
    ensureCalls.length = 0
    provisionCalls.length = 0
    const zcaps = await processZcaps({
      zcapRequests: [
        { ...collectionDetail, controller: granteeDid },
        {
          referenceId: 'convert-within-request',
          allowedAction: ['GET', 'HEAD', 'POST'],
          controller: granteeDid,
          invocationTarget: {
            type: 'https://w3id.org/byoe#public-collection',
            name: 'example-app-data'
          }
        }
      ],
      session,
      appProvisioning: true
    })
    expect(zcaps).toHaveLength(1)
    expect(provisionCalls).toHaveLength(1)
    expect(provisionCalls[0].collectionId).toBe('example-app-data')
    // The public grant was skipped outright: setPublic never runs.
    expect(ensureCalls).toEqual([])
  })

  it('caps a same-request string target on a just-provisioned public collection', async () => {
    // The mirror order: the first descriptor provisions a public collection,
    // the second reaches the same collection as a plain URL asking for the
    // full vocabulary. The live snapshot classes it public-collection, so
    // PUT/DELETE are dropped rather than granted on a world-readable target.
    delegated.length = 0
    ensureCalls.length = 0
    const zcaps = await processZcaps({
      zcapRequests: [
        publicCollectionDetail,
        {
          referenceId: 'public-by-url-within-request',
          allowedAction: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
          controller: RP_DID,
          invocationTarget: `${SPACE_URL}/example-app-public`
        }
      ],
      session
    })
    expect(zcaps).toHaveLength(2)
    expect(ensureCalls).toEqual([{ id: 'example-app-public', isPublic: true }])
    expect(
      (zcaps[1] as unknown as { allowedAction: string[] }).allowedAction
    ).toEqual(['GET', 'HEAD', 'POST'])
  })

  it('routes a share grant to shareCollection, not the delegation loop', async () => {
    delegated.length = 0
    shareCalls.length = 0
    const before = Date.now()
    const SHARE_TTL_MS = 8760 * 60 * 60 * 1000
    const zcaps = await processZcaps({
      zcapRequests: [shareDetail],
      session,
      shareTtlMs: SHARE_TTL_MS
    })

    // One call, both axes: the recipient key derived from the controller DID.
    expect(shareCalls).toHaveLength(1)
    expect(shareCalls[0].collectionId).toBe('private-credentials')
    expect(shareCalls[0].controller).toBe(granteeDid)
    expect(shareCalls[0].recipientId).toBe(
      x25519RecipientFromDidKey({ did: granteeDid }).id
    )
    expect(
      Math.abs(shareCalls[0].expires!.getTime() - (before + SHARE_TTL_MS))
    ).toBeLessThan(60 * 1000)

    // The pull zcap comes back for the response VP's `zcap` array.
    expect(zcaps).toHaveLength(1)
    expect(
      (zcaps[0] as unknown as { allowedAction: string[] }).allowedAction
    ).toEqual(['GET', 'HEAD'])
  })

  it('records the app name and origin on an App Connect share', async () => {
    shareCalls.length = 0
    await processZcaps({
      zcapRequests: [shareDetail],
      session,
      app: { name: 'Text Editor', origin: 'https://app.example' }
    })
    expect(shareCalls[0].app).toEqual({
      name: 'Text Editor',
      origin: 'https://app.example'
    })
  })

  it('refuses to share with a controller that has no Ed25519 did:key', async () => {
    shareCalls.length = 0
    const descriptor = { ...shareDetail, controller: 'did:web:app.example' }
    // Unsatisfiable at resolution time, so consent shows "cannot fulfill" and
    // delegation skips it rather than deriving a key from a DID it cannot.
    expect(
      resolveGrant({
        descriptor,
        spaceUrl: SPACE_URL,
        collections: NO_COLLECTIONS
      }).target
    ).toEqual(expect.objectContaining({ satisfiable: false }))
    const zcaps = await processZcaps({ zcapRequests: [descriptor], session })
    expect(zcaps).toHaveLength(0)
    expect(shareCalls).toHaveLength(0)
  })

  it('refuses a share whose did:key only looks well formed', async () => {
    shareCalls.length = 0
    // Right prefix, undecodable body: caught at resolution (so consent shows
    // "cannot fulfill") rather than throwing part-way through the response.
    const descriptor = { ...shareDetail, controller: 'did:key:z6MkZZZZ' }
    expect(
      resolveGrant({
        descriptor,
        spaceUrl: SPACE_URL,
        collections: NO_COLLECTIONS
      }).target
    ).toEqual(expect.objectContaining({ satisfiable: false }))
    const zcaps = await processZcaps({ zcapRequests: [descriptor], session })
    expect(zcaps).toHaveLength(0)
    expect(shareCalls).toHaveLength(0)
  })

  it('a share stays read-only even if the request asks for writes', async () => {
    shareCalls.length = 0
    const grant = resolveGrant({
      descriptor: {
        ...shareDetail,
        allowedAction: ['GET', 'HEAD', 'PUT', 'DELETE']
      },
      spaceUrl: SPACE_URL,
      collections: NO_COLLECTIONS
    })
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
    expect(grant.write).toBe(false)
  })

  it('skips a share of a collection with no epoch roster entirely', async () => {
    delegated.length = 0
    shareCalls.length = 0
    const zcaps = await processZcaps({
      zcapRequests: [
        {
          ...shareDetail,
          invocationTarget: {
            type: 'https://w3id.org/byoe#shared-wallet-collection',
            name: 'public-credentials'
          }
        }
      ],
      session
    })
    expect(zcaps).toHaveLength(0)
    expect(shareCalls).toHaveLength(0)
    expect(delegated).toHaveLength(0)
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
