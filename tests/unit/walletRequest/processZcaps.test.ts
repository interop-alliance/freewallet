// @vitest-environment node
import { describe, it, expect, beforeAll, beforeEach } from 'vitest'
import { CapabilityAgent } from '@interop/capability-agent'
import * as vc from '@interop/vc'
import { securityLoader } from '@interop/security-document-loader'
import type { Session } from '@/types/auth'
import type { ICapabilityQueryDetail, IZcap } from '@/lib/walletRequest'
import { x25519RecipientFromDidKey } from '@interop/was-client/edv'
import {
  APP_CONNECTIONS_COLLECTION,
  KEY_MAP_COLLECTION,
  UNLOCK_METHODS_COLLECTION
} from '@interop/wallet-core/space'
import {
  existingCollectionsFrom,
  isSatisfiable,
  resolveInvocationTarget,
  resolveGrant,
  resolveGrants,
  processZcaps,
  processRequest,
  presentationSuiteFor
} from '@/lib/walletRequest'

const documentLoader = securityLoader({ fetchRemoteContexts: true }).build()

// The Space resolution is handed, structurally, plus the URL that pair forms
// (what every expected target below is written against).
const SPACE = { serverUrl: 'https://was.example.com/', spaceId: 'L8qcqABC' }
const SPACE_URL = 'https://was.example.com/space/L8qcqABC/'
// A real Ed25519 did:key (the did:key spec's example): a provisioned private
// collection escrows the grantee's X25519 twin, so the controller must derive.
const RP_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const CHALLENGE = '99612b24-63d9-11ea-b99f-4f66f3e4f81a'

// The existing-collections snapshot resolution consults; the empty default is
// a Space where every named collection is new. `collectionListing` backs the
// session stub's `listCollectionPublicStates`, so processZcaps tests can stage
// existing collections per test.
const NO_COLLECTIONS = existingCollectionsFrom([])
// A Space holding the collections the string-target tests name. A string
// target never provisions, so it only resolves onto a collection that exists.
const STANDING_COLLECTIONS = existingCollectionsFrom(
  [
    'example-app-data',
    'private-credentials',
    'public-credentials',
    'id',
    KEY_MAP_COLLECTION.id,
    UNLOCK_METHODS_COLLECTION.id
  ].map(id => ({ id }))
)
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

// A reserved-type whole-Space request: always unsatisfiable.
const spaceDetail: ICapabilityQueryDetail = {
  referenceId: 'space-read',
  allowedAction: ['GET', 'HEAD', 'PUT'],
  controller: RP_DID,
  invocationTarget: { type: 'https://w3id.org/byoe#space' }
}

// A read of a standard wallet collection, by descriptor: satisfiable on every
// request path, since it provisions nothing.
const standardReadDetail: ICapabilityQueryDetail = {
  referenceId: 'public-credentials-read',
  allowedAction: ['GET', 'HEAD'],
  controller: RP_DID,
  invocationTarget: {
    type: 'https://w3id.org/byoe#private-collection',
    name: 'public-credentials'
  }
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
  invocationTarget: `${SPACE_URL}private-credentials`
}

// A write request on a resource *inside* a standard collection (plain URL).
const standardResourceUrlDetail: ICapabilityQueryDetail = {
  referenceId: 'private-resource-write-url',
  allowedAction: ['GET', 'HEAD', 'PUT', 'DELETE'],
  controller: RP_DID,
  invocationTarget: `${SPACE_URL}private-credentials/some-resource`
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
    name: KEY_MAP_COLLECTION.id
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
    name: UNLOCK_METHODS_COLLECTION.id
  }
}

// The same write request, spelled as a plain URL under the Space.
const unlockMethodsCollectionUrlDetail: ICapabilityQueryDetail = {
  referenceId: 'unlock-methods-write-url',
  allowedAction: ['GET', 'HEAD', 'PUT', 'DELETE'],
  controller: RP_DID,
  invocationTarget: `${SPACE_URL}${UNLOCK_METHODS_COLLECTION.id}`
}

// A write request on the DID document resource itself (plain URL).
const didDocumentUrlDetail: ICapabilityQueryDetail = {
  referenceId: 'did-doc-write-url',
  allowedAction: ['PUT'],
  controller: RP_DID,
  invocationTarget: `${SPACE_URL}id/did.json`
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
let provisionCalls: Array<{
  collectionId: string
  recipientId: string
  generator?: string
}>
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
      capability,
      invocationTarget,
      controller,
      allowedActions,
      expires
    }: {
      capability?: string | Record<string, unknown>
      invocationTarget: string
      controller: string
      allowedActions: string[]
      expires: Date | string
    }) {
      // The parent the caller actually delegated from: the Space root URI for
      // a remembered session, the generation delegation object for a transient
      // one. Recording it is what lets a test see which chain a grant hangs
      // from.
      const parent =
        typeof capability === 'string'
          ? capability
          : ((capability?.id as string | undefined) ??
            `urn:zcap:root:${encodeURIComponent(SPACE_URL)}`)
      const zcap = {
        '@context': [
          'https://w3id.org/zcap/v1',
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        id: `urn:zcap:delegated:${encodeURIComponent(invocationTarget)}`,
        parentCapability: parent,
        invocationTarget,
        controller,
        allowedAction: allowedActions,
        expires: expires instanceof Date ? expires.toISOString() : expires,
        proof: {
          type: 'Ed25519Signature2020',
          proofPurpose: 'capabilityDelegation',
          capabilityChain: [parent],
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
    spaceLocation: SPACE,
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
    async provisionEncryptedCollection({
      collectionId,
      recipient,
      generator
    }: {
      collectionId: string
      recipient: { id: string }
      generator?: string
    }) {
      provisionCalls.push({
        collectionId,
        recipientId: recipient.id,
        ...(generator && { generator })
      })
      return { scheme: 'edv' }
    },
    async delegateShareGrant({
      collectionId,
      controller,
      expires
    }: {
      collectionId: string
      controller: string
      expires?: Date
    }) {
      const zcap = {
        id: `urn:zcap:delegated:share:${collectionId}`,
        invocationTarget: `${SPACE_URL}${collectionId}`,
        controller,
        allowedAction: ['GET', 'HEAD'],
        expires: expires?.toISOString()
      }
      delegated.push(zcap)
      return zcap
    },
    async shareCollection({
      collectionId,
      recipient,
      zcap,
      app
    }: {
      collectionId: string
      recipient: { id: string }
      zcap: { controller: string; expires?: string }
      app?: { name: string; origin: string }
    }) {
      shareCalls.push({
        collectionId,
        recipientId: recipient.id,
        controller: zcap.controller,
        expires: zcap.expires ? new Date(zcap.expires) : undefined,
        app
      })
      return { descriptor: { scheme: 'edv' } }
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
  it('accepts a plain URL under an existing collection, verbatim', () => {
    const target = resolveInvocationTarget({
      descriptor: `${SPACE_URL}example-app-data/doc1`,
      space: SPACE,
      collections: STANDING_COLLECTIONS,
      requester: {}
    })
    // A string target never provisions.
    expect(target).toMatchObject({
      invocationTarget: `${SPACE_URL}example-app-data/doc1`,
      collectionId: 'example-app-data',
      needsProvisioning: false,
      targetClass: 'collection'
    })
  })

  it('refuses a plain URL under a collection that does not exist', () => {
    for (const descriptor of [
      `${SPACE_URL}example-app-data/`,
      `${SPACE_URL}example-app-data/doc1`
    ]) {
      const target = resolveInvocationTarget({
        descriptor,
        space: SPACE,
        collections: NO_COLLECTIONS,
        requester: {}
      })
      expect(target.targetClass).toBeUndefined()
      expect(target.invocationTarget).toBeUndefined()
    }
  })

  it('refuses the Space URL string, with or without a trailing slash', () => {
    for (const descriptor of [SPACE_URL, SPACE_URL.slice(0, -1)]) {
      const target = resolveInvocationTarget({
        descriptor,
        space: SPACE,
        collections: STANDING_COLLECTIONS,
        requester: {}
      })
      expect(target.targetClass).toBeUndefined()
      expect(target.invocationTarget).toBeUndefined()
    }
  })

  it('refuses a foreign URL', () => {
    const target = resolveInvocationTarget({
      descriptor: 'https://someone-else.example/space/OTHER',
      space: SPACE,
      collections: NO_COLLECTIONS,
      requester: {}
    })
    expect(target.targetClass).toBeUndefined()
    expect(target.targetClass).toBeUndefined()
  })

  // These previously classified as an RP `collection` (the string started with
  // `${SPACE_URL}` and the segment was read off it verbatim), so a query or a
  // fragment smuggled past the prefix check earned the full write ceiling on a
  // target the server would route somewhere else entirely.
  it('refuses a plain-URL target carrying a query or a fragment', () => {
    for (const descriptor of [
      `${SPACE_URL}private-credentials?x=1`,
      `${SPACE_URL}private-credentials#frag`,
      `${SPACE_URL}example-app-data/doc1?x=1`,
      `${SPACE_URL}?x=1`,
      `${SPACE_URL}#frag`
    ]) {
      const target = resolveInvocationTarget({
        descriptor,
        space: SPACE,
        collections: NO_COLLECTIONS,
        requester: {}
      })
      expect(target.targetClass).toBeUndefined()
      expect(target.targetClass).toBeUndefined()
    }
  })

  it('refuses a path that escapes the Space through dot segments', () => {
    for (const descriptor of [
      `${SPACE_URL}../other-space/private`,
      `${SPACE_URL}example-app-data/../../other-space/private`,
      `${SPACE_URL}..`
    ]) {
      const target = resolveInvocationTarget({
        descriptor,
        space: SPACE,
        collections: NO_COLLECTIONS,
        requester: {}
      })
      expect(target.targetClass).toBeUndefined()
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
        descriptor: `${SPACE_URL}${segment}/doc1`,
        space: SPACE,
        collections: NO_COLLECTIONS,
        requester: {}
      })
      expect(target.targetClass).toBeUndefined()
      expect(target.targetClass).toBeUndefined()
    }
  })

  it('refuses a reserved path segment as a collection name', () => {
    // `meta`, `query` and the rest of the Reserved Path Segment Registry pass
    // the collection naming rule while addressing a server facet. Resolution
    // refuses them as unsatisfiable rather than letting the path builder's
    // `ValidationError` escape into the caller's login handler, and `meta` in
    // particular is the Space Metadata object, which carries the controller.
    for (const name of ['meta', 'policy', 'query', 'quotas', 'linkset']) {
      for (const descriptor of [
        { type: 'https://w3id.org/byoe#private-collection', name },
        { type: 'https://w3id.org/byoe#public-collection', name },
        `${SPACE_URL}${name}/doc1` as string | { type: string; name: string }
      ]) {
        const target = resolveInvocationTarget({
          descriptor,
          space: SPACE,
          collections: NO_COLLECTIONS,
          requester: {}
        })
        expect(target.targetClass).toBeUndefined()
        expect(target.invocationTarget).toBeUndefined()
      }
    }
  })

  it('refuses a reserved name through resolveGrants without throwing', () => {
    const grants = resolveGrants({
      zcapRequests: [
        {
          referenceId: 'reserved',
          allowedAction: ['GET'],
          controller: RP_DID,
          invocationTarget: {
            type: 'https://w3id.org/byoe#private-collection',
            name: 'query'
          }
        }
      ],
      space: SPACE,
      collections: NO_COLLECTIONS
    })
    expect(grants).toHaveLength(1)
    expect(isSatisfiable(grants[0]!.target)).toBe(false)
    expect(grants[0]!.allowedActions).toEqual([])
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
        space: SPACE,
        collections: NO_COLLECTIONS,
        requester: {}
      })
      expect(target.targetClass).toBeUndefined()
      expect(target.targetClass).toBeUndefined()
    }
  })

  it('keeps a sub-path deployment prefix in a collection grant target', () => {
    const subPathSpace = 'https://host.example/was/space/L8qcqABC/'
    expect(
      resolveInvocationTarget({
        descriptor: {
          type: 'https://w3id.org/byoe#private-collection',
          name: 'example-app-data'
        },
        space: { serverUrl: 'https://host.example/was/', spaceId: 'L8qcqABC' },
        collections: NO_COLLECTIONS,
        requester: {}
      })
    ).toMatchObject({
      invocationTarget: `${subPathSpace}example-app-data/`,
      collectionId: 'example-app-data'
    })
  })

  it('normalizes a collection URL onto the canonical container form', () => {
    const withSlash = resolveInvocationTarget({
      descriptor: `${SPACE_URL}example-app-data/`,
      space: SPACE,
      collections: STANDING_COLLECTIONS,
      requester: {}
    })
    const without = resolveInvocationTarget({
      descriptor: `${SPACE_URL}example-app-data`,
      space: SPACE,
      collections: STANDING_COLLECTIONS,
      requester: {}
    })
    expect(withSlash).toMatchObject({
      invocationTarget: `${SPACE_URL}example-app-data/`,
      collectionId: 'example-app-data',
      targetClass: 'collection'
    })
    expect(withSlash.invocationTarget).toBe(without.invocationTarget)
  })

  it('classifies a resource URL under a protected collection', () => {
    const url = `${SPACE_URL}private-credentials/resource-1`
    expect(
      resolveInvocationTarget({
        descriptor: url,
        space: SPACE,
        collections: STANDING_COLLECTIONS,
        requester: {}
      })
    ).toMatchObject({
      invocationTarget: url,
      collectionId: 'private-credentials',
      encrypted: true,
      targetClass: 'protected-collection'
    })
  })

  it('refuses a URL that names no Space, Collection, or Resource', () => {
    // was-client's grammar classifies these as sub-endpoints rather than as
    // handles: a reserved segment at Collection or Resource depth, and any
    // path deeper than a Resource. None is a target this module grants.
    for (const target of [
      `${SPACE_URL}example-app-data/policy`,
      `${SPACE_URL}example-app-data/doc1/meta`,
      `${SPACE_URL}private-credentials/sub/path/resource-1`
    ]) {
      const resolved = resolveInvocationTarget({
        descriptor: target,
        space: SPACE,
        collections: NO_COLLECTIONS,
        requester: {}
      })
      expect(resolved.targetClass).toBeUndefined()
      expect(resolved.invocationTarget).toBeUndefined()
    }
  })

  it('resolves a named RP collection and flags provisioning', () => {
    const target = resolveInvocationTarget({
      descriptor: {
        type: 'https://w3id.org/byoe#private-collection',
        name: 'example-app-data'
      },
      space: SPACE,
      collections: NO_COLLECTIONS,
      requester: {}
    })
    expect(target).toMatchObject({
      invocationTarget: `${SPACE_URL}example-app-data/`,
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
      space: SPACE,
      collections: NO_COLLECTIONS,
      requester: {}
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
      space: SPACE,
      collections: NO_COLLECTIONS,
      requester: {}
    })
    expect(target).toMatchObject({
      needsProvisioning: false,
      encrypted: true,
      targetClass: 'protected-collection'
    })
  })

  it('treats the id system collection as protected and present', () => {
    expect(
      resolveInvocationTarget({
        descriptor: {
          type: 'https://w3id.org/byoe#private-collection',
          name: 'id'
        },
        space: SPACE,
        collections: NO_COLLECTIONS,
        requester: {}
      })
    ).toMatchObject({
      needsProvisioning: false,
      encrypted: false,
      targetClass: 'protected-collection'
    })
  })

  it('refuses key-map and unlock-methods under every descriptor type and as URLs', () => {
    const descriptors: Array<string | { type: string; name: string }> = []
    for (const name of [KEY_MAP_COLLECTION.id, UNLOCK_METHODS_COLLECTION.id]) {
      for (const type of [
        'https://w3id.org/byoe#private-collection',
        'https://w3id.org/byoe#public-collection',
        'https://w3id.org/byoe#shared-wallet-collection'
      ]) {
        descriptors.push({ type, name })
      }
      descriptors.push(
        `${SPACE_URL}${name}`,
        `${SPACE_URL}${name}/`,
        `${SPACE_URL}${name}/some-resource`
      )
    }
    for (const descriptor of descriptors) {
      const target = resolveInvocationTarget({
        descriptor,
        space: SPACE,
        collections: STANDING_COLLECTIONS,
        requester: {}
      })
      expect(target.targetClass, JSON.stringify(descriptor)).toBeUndefined()
    }
  })

  it('rejects an invalid collection name', () => {
    expect(
      resolveInvocationTarget({
        descriptor: {
          type: 'https://w3id.org/byoe#private-collection',
          name: 'Bad_Name!'
        },
        space: SPACE,
        collections: NO_COLLECTIONS,
        requester: {}
      }).targetClass
    ).toBeUndefined()
  })

  it('refuses the reserved whole-Space descriptor type', () => {
    const target = resolveInvocationTarget({
      descriptor: { type: 'https://w3id.org/byoe#space' },
      space: SPACE,
      collections: STANDING_COLLECTIONS,
      requester: {}
    })
    expect(target.targetClass).toBeUndefined()
    expect(target.invocationTarget).toBeUndefined()
  })

  it('refuses an unknown descriptor type', () => {
    const target = resolveInvocationTarget({
      descriptor: { type: 'https://w3id.org/byoe#unknown' },
      space: SPACE,
      collections: NO_COLLECTIONS,
      requester: {}
    })
    expect(target.targetClass).toBeUndefined()
    expect(target.targetClass).toBeUndefined()
  })

  it('resolves a public collection: plaintext, provisioned, isPublic', () => {
    const target = resolveInvocationTarget({
      descriptor: {
        type: 'https://w3id.org/byoe#public-collection',
        name: 'example-app-public'
      },
      space: SPACE,
      collections: NO_COLLECTIONS,
      requester: {}
    })
    expect(target).toMatchObject({
      invocationTarget: `${SPACE_URL}example-app-public/`,
      needsProvisioning: true,
      collectionId: 'example-app-public',
      encrypted: false,
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
          space: SPACE,
          collections: NO_COLLECTIONS,
          requester: {}
        }).targetClass
      ).not.toBe('public-collection')
    }
    expect(
      resolveInvocationTarget({
        descriptor: `${SPACE_URL}example-app-data`,
        space: SPACE,
        collections: NO_COLLECTIONS,
        requester: {}
      }).targetClass
    ).not.toBe('public-collection')
  })

  it('refuses a public grant on protected wallet collections', () => {
    for (const name of [
      'private-credentials',
      'public-credentials',
      'wallet-activity',
      'id',
      KEY_MAP_COLLECTION.id,
      UNLOCK_METHODS_COLLECTION.id
    ]) {
      expect(
        resolveInvocationTarget({
          descriptor: { type: 'https://w3id.org/byoe#public-collection', name },
          space: SPACE,
          collections: NO_COLLECTIONS,
          requester: {}
        }).targetClass
      ).toBeUndefined()
    }
  })

  it('resolves a share of an encrypted standard collection', () => {
    const target = resolveInvocationTarget({
      descriptor: {
        type: 'https://w3id.org/byoe#shared-wallet-collection',
        name: 'private-credentials'
      },
      space: SPACE,
      collections: NO_COLLECTIONS,
      requester: {}
    })
    expect(target).toMatchObject({
      invocationTarget: `${SPACE_URL}private-credentials/`,
      needsProvisioning: false,
      collectionId: 'private-credentials',
      encrypted: true,
      targetClass: 'share'
    })
  })

  it('resolves a share of every shareable standard collection', () => {
    // The rule is the roster's `shareable` flag, so the contacts collections
    // are shareable on the same terms as credentials.
    for (const name of ['wallet-activity', 'contacts', 'contacts-history']) {
      expect(
        resolveInvocationTarget({
          descriptor: {
            type: 'https://w3id.org/byoe#shared-wallet-collection',
            name
          },
          space: SPACE,
          collections: NO_COLLECTIONS,
          requester: {}
        })
      ).toMatchObject({ targetClass: 'share', encrypted: true })
    }
  })

  it('refuses a share of anything but a shareable standard collection', () => {
    // Plaintext standard collection, the `id` / `key-map` collections, an RP
    // collection, a made-up name, a missing name -- none has an epoch roster.
    // `app-connections` does have one and is refused all the same: its rows
    // are the connected apps' private seeds.
    for (const name of [
      'public-credentials',
      APP_CONNECTIONS_COLLECTION,
      'id',
      KEY_MAP_COLLECTION.id,
      UNLOCK_METHODS_COLLECTION.id,
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
          space: SPACE,
          collections: NO_COLLECTIONS,
          requester: {}
        }).targetClass
      ).toBeUndefined()
    }
  })

  it('refuses every descriptor spelling that names app-connections', () => {
    // The collection holds one app-key credential per connected app, each
    // carrying that app's private seed, so a grant naming it is unsatisfiable
    // rather than merely read-only -- whichever spelling it arrives in, and
    // whether it names the collection or a resource inside it.
    for (const descriptor of [
      `${SPACE_URL}${APP_CONNECTIONS_COLLECTION}`,
      `${SPACE_URL}${APP_CONNECTIONS_COLLECTION}/some-resource`,
      {
        type: 'https://w3id.org/byoe#private-collection',
        name: APP_CONNECTIONS_COLLECTION
      },
      {
        type: 'https://w3id.org/byoe#public-collection',
        name: APP_CONNECTIONS_COLLECTION
      },
      {
        type: 'https://w3id.org/byoe#shared-wallet-collection',
        name: APP_CONNECTIONS_COLLECTION
      }
    ]) {
      const target = resolveInvocationTarget({
        descriptor,
        space: SPACE,
        // Listed, so a string target is refused for what it names.
        collections: existingCollectionsFrom([
          { id: APP_CONNECTIONS_COLLECTION }
        ]),
        requester: {}
      })
      expect(target.targetClass).toBeUndefined()
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
          space: SPACE,
          collections: NO_COLLECTIONS,
          requester: {}
        }).targetClass
      ).not.toBe('share')
    }
    expect(
      resolveInvocationTarget({
        descriptor: `${SPACE_URL}private-credentials`,
        space: SPACE,
        collections: NO_COLLECTIONS,
        requester: {}
      }).targetClass
    ).not.toBe('share')
  })

  it('rejects an invalid public-collection name', () => {
    expect(
      resolveInvocationTarget({
        descriptor: {
          type: 'https://w3id.org/byoe#public-collection',
          name: 'Bad_Name!'
        },
        space: SPACE,
        collections: NO_COLLECTIONS,
        requester: {}
      }).targetClass
    ).toBeUndefined()
    expect(
      resolveInvocationTarget({
        descriptor: { type: 'https://w3id.org/byoe#public-collection' },
        space: SPACE,
        collections: NO_COLLECTIONS,
        requester: {}
      }).targetClass
    ).toBeUndefined()
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
      space: SPACE,
      collections: EXISTING,
      requester: {}
    })
    expect(target.targetClass).toBeUndefined()
    expect(target.targetClass).toBeUndefined()
  })

  it('keeps the re-grant on an already-public collection satisfiable', () => {
    const target = resolveInvocationTarget({
      descriptor: {
        type: 'https://w3id.org/byoe#public-collection',
        name: 'example-app-public'
      },
      space: SPACE,
      collections: EXISTING,
      requester: {}
    })
    // Satisfiable, but with nothing to provision: the policy is never
    // re-applied to an existing collection.
    expect(target).toMatchObject({
      needsProvisioning: false,
      collectionId: 'example-app-public',
      targetClass: 'public-collection'
    })
  })

  it('classes a string target naming a public collection public-collection', () => {
    for (const invocationTarget of [
      `${SPACE_URL}example-app-public`,
      `${SPACE_URL}example-app-public/some-resource`
    ]) {
      const grant = resolveGrant({
        descriptor: {
          controller: RP_DID,
          allowedAction: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
          invocationTarget
        },
        space: SPACE,
        collections: EXISTING
      })
      expect(grant.target.targetClass).toBe('public-collection')
      expect(grant.target.targetClass).toBe('public-collection')
      expect(grant.allowedActions).toEqual([
        'GET',
        'HEAD',
        'POST',
        'PUT',
        'DELETE'
      ])
    }
  })

  it('classes a plain collection descriptor naming a public collection too', () => {
    // Class parity holds for every spelling of the target, so asking via
    // `#collection` cannot dodge the isPublic flag or the provisioning skip.
    const grant = resolveGrant({
      descriptor: {
        controller: RP_DID,
        allowedAction: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
        invocationTarget: {
          type: 'https://w3id.org/byoe#private-collection',
          name: 'example-app-public'
        }
      },
      space: SPACE,
      collections: EXISTING
    })
    expect(grant.target.targetClass).toBe('public-collection')
    expect(grant.target.targetClass).toBe('public-collection')
    // Nothing to provision either: the `#collection` spelling of an existing
    // public collection is the idempotent public re-grant, so the public
    // policy is never re-applied and no recipient roster is ever set up on a
    // world-readable collection.
    expect(grant.target.needsProvisioning).toBe(false)
    expect(grant.allowedActions).toEqual([
      'GET',
      'HEAD',
      'POST',
      'PUT',
      'DELETE'
    ])
  })

  it('keeps the full ceiling on an existing private RP collection', () => {
    const grant = resolveGrant({
      descriptor: {
        controller: RP_DID,
        allowedAction: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
        invocationTarget: `${SPACE_URL}example-app-data`
      },
      space: SPACE,
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
      space: SPACE,
      collections: NO_COLLECTIONS
    })
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
  })

  it('refuses a whole-Space grant, whatever it asks for', () => {
    const grant = resolveGrant({
      descriptor: spaceDetail,
      space: SPACE,
      collections: STANDING_COLLECTIONS
    })
    expect(grant.target.targetClass).toBeUndefined()
    expect(grant.allowedActions).toEqual([])
  })

  it('passes through explicit RP-collection actions and flags write', () => {
    const grant = resolveGrant({
      descriptor: collectionDetail,
      space: SPACE,
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
      space: SPACE,
      collections: NO_COLLECTIONS
    })
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
    expect(grant.write).toBe(false)
  })

  it('caps a standard-collection write to read-only (string URL form)', () => {
    const grant = resolveGrant({
      descriptor: standardCollectionUrlDetail,
      space: SPACE,
      collections: STANDING_COLLECTIONS
    })
    expect(grant.target.collectionId).toBe('private-credentials')
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
    expect(grant.write).toBe(false)
  })

  it('caps a write to a resource inside a standard collection (string URL)', () => {
    const grant = resolveGrant({
      descriptor: standardResourceUrlDetail,
      space: SPACE,
      collections: STANDING_COLLECTIONS
    })
    expect(grant.target.collectionId).toBe('private-credentials')
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
    expect(grant.write).toBe(false)
  })

  it('caps an id-collection write to read-only (descriptor form)', () => {
    const grant = resolveGrant({
      descriptor: idCollectionDetail,
      space: SPACE,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.collectionId).toBe('id')
    // Provisioned at login, like the standard collections.
    expect(grant.target.needsProvisioning).toBe(false)
    expect(grant.allowedActions).toEqual(['GET', 'HEAD'])
    expect(grant.write).toBe(false)
  })

  it('refuses key-map and unlock-methods grants outright', () => {
    for (const descriptor of [
      keyMapCollectionDetail,
      unlockMethodsCollectionDetail,
      unlockMethodsCollectionUrlDetail
    ]) {
      const grant = resolveGrant({
        descriptor,
        space: SPACE,
        collections: STANDING_COLLECTIONS
      })
      expect(grant.target.targetClass, descriptor.referenceId).toBeUndefined()
      expect(grant.allowedActions).toEqual([])
    }
  })

  it('refuses a PUT-only grant on the DID document resource', () => {
    // The descriptor asks for PUT alone on the protected `id` collection, so
    // nothing survives that class's read-only ceiling. This used to silently
    // downgrade to a read-only grant; now the grant is refused outright, since
    // an empty `allowedAction` array means "every action" in the zcap model.
    const grant = resolveGrant({
      descriptor: didDocumentUrlDetail,
      space: SPACE,
      collections: STANDING_COLLECTIONS
    })
    expect(grant.target.targetClass).toBeUndefined()
    expect(grant.allowedActions).toEqual([])
    expect(grant.write).toBe(false)
  })

  it('marks a read-only grant as not a write', () => {
    const grant = resolveGrant({
      descriptor: standardReadDetail,
      space: SPACE,
      collections: NO_COLLECTIONS
    })
    expect(grant.write).toBe(false)
  })

  it('grants a public RP collection the full vocabulary', () => {
    // Published content is still the RP's own data, and un-publishing is as
    // much data management as publishing: PUT and DELETE survive, the same as
    // on a private RP collection (the App Connect registry ceiling).
    const grant = resolveGrant({
      descriptor: publicCollectionDetail,
      space: SPACE,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.targetClass).toBe('public-collection')
    expect(grant.allowedActions).toEqual([
      'GET',
      'HEAD',
      'POST',
      'PUT',
      'DELETE'
    ])
    expect(grant.write).toBe(true)
  })
})

describe('resolveGrant action vocabulary', () => {
  /**
   * A capability query on an RP collection (a class whose ceiling is the
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
      space: SPACE,
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
      space: SPACE,
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
      space: SPACE,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.targetClass).toBeUndefined()
    expect(grant.target.invocationTarget).toBeUndefined()
    expect(grant.allowedActions).toEqual([])
    expect(grant.write).toBe(false)
  })

  it('makes an all-above-ceiling action set unsatisfiable', () => {
    const grant = resolveGrant({
      descriptor: {
        controller: RP_DID,
        allowedAction: ['PUT', 'DELETE'],
        invocationTarget: {
          type: 'https://w3id.org/byoe#private-collection',
          name: 'public-credentials'
        }
      },
      space: SPACE,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.targetClass).toBeUndefined()
    expect(grant.allowedActions).toEqual([])
  })

  it('makes an empty action array unsatisfiable rather than grant-all', () => {
    const grant = resolveGrant({
      descriptor: rpQuery([]),
      space: SPACE,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.targetClass).toBeUndefined()
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
      space: SPACE,
      collections: NO_COLLECTIONS
    })
    for (const grant of grants) {
      if (isSatisfiable(grant.target)) {
        expect(grant.allowedActions.length).toBeGreaterThan(0)
      } else {
        expect(grant.allowedActions).toEqual([])
      }
    }
  })
})

describe('whole-Space targets', () => {
  it('refuses the reserved #space descriptor type', () => {
    const grant = resolveGrant({
      descriptor: spaceDetail,
      space: SPACE,
      collections: STANDING_COLLECTIONS
    })
    expect(isSatisfiable(grant.target)).toBe(false)
    expect(grant.allowedActions).toEqual([])
  })

  it('refuses the bare Space URL form the same way', () => {
    const grant = resolveGrant({
      descriptor: {
        controller: RP_DID,
        allowedAction: ['GET'],
        invocationTarget: SPACE_URL
      },
      space: SPACE,
      collections: STANDING_COLLECTIONS
    })
    expect(isSatisfiable(grant.target)).toBe(false)
    expect(grant.allowedActions).toEqual([])
  })

  it('keeps the generic refusal for a foreign target', () => {
    const grant = resolveGrant({
      descriptor: foreignDetail,
      space: SPACE,
      collections: NO_COLLECTIONS
    })
    expect(grant.target.targetClass).toBeUndefined()
  })
})

describe('processZcaps', () => {
  const READ_TTL_MS = 720 * 60 * 60 * 1000
  const WRITE_TTL_MS = 168 * 60 * 60 * 1000

  it('delegates satisfiable grants, provisions, and skips unsatisfiable ones', async () => {
    delegated.length = 0
    ensureCalls.length = 0
    provisionCalls.length = 0
    const before = Date.now()
    const zcaps = await processZcaps({
      zcapRequests: [
        collectionDetail,
        standardReadDetail,
        spaceDetail,
        foreignDetail
      ],
      session,
      ttlMs: READ_TTL_MS,
      writeTtlMs: WRITE_TTL_MS
    })

    expect(zcaps).toHaveLength(2)
    // Only the un-provisioned RP collection is created, encrypted, with the
    // grantee escrowed beside the user.
    expect(ensureCalls).toEqual([])
    expect(provisionCalls).toEqual([
      {
        collectionId: 'example-app-data',
        recipientId: x25519RecipientFromDidKey({ did: RP_DID }).id
      }
    ])

    const collectionZcap = zcaps[0] as unknown as {
      invocationTarget: string
      controller: string
      allowedAction: string[]
      expires: string
    }
    expect(collectionZcap.invocationTarget).toBe(
      `${SPACE_URL}example-app-data/`
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

    // The whole-Space and foreign rows are skipped.
    const readZcap = zcaps[1] as unknown as {
      invocationTarget: string
      allowedAction: string[]
    }
    expect(readZcap.invocationTarget).toBe(`${SPACE_URL}public-credentials/`)
    expect(readZcap.allowedAction).toEqual(['GET', 'HEAD'])

    // The RP collection grant is a write, so it uses the shorter write TTL.
    const expiresMs = new Date(collectionZcap.expires).getTime()
    const expected = before + WRITE_TTL_MS
    expect(Math.abs(expiresMs - expected)).toBeLessThan(60 * 1000)
  })

  it('under a generation delegation, chains every row to it', async () => {
    delegated.length = 0
    ensureCalls.length = 0
    const now = Date.now()
    // A healthy parent: outside its renewal window, so the blocking renewal
    // stage does not fire and the mint runs against this one.
    const generationDelegation = {
      id: 'urn:zcap:delegated:generation',
      invocationTarget: `${SPACE_URL}`,
      expires: new Date(now + 300 * 24 * 60 * 60 * 1000).toISOString()
    } as unknown as IZcap
    const transient = {
      ...session,
      profile: {
        ...session.profile,
        invocationCapability: generationDelegation
      }
    } as unknown as Session

    const zcaps = await processZcaps({
      zcapRequests: [
        collectionDetail,
        standardReadDetail,
        spaceDetail,
        foreignDetail
      ],
      session: transient,
      ttlMs: READ_TTL_MS,
      writeTtlMs: WRITE_TTL_MS
    })

    // The whole-Space and foreign rows are refused.
    expect(zcaps).toHaveLength(2)
    const [collectionZcap, readZcap] = zcaps as unknown as {
      invocationTarget: string
      parentCapability: string
      allowedAction: string[]
      expires: string
    }[]
    expect(collectionZcap.invocationTarget).toBe(
      `${SPACE_URL}example-app-data/`
    )
    expect(readZcap.invocationTarget).toBe(`${SPACE_URL}public-credentials/`)
    expect(readZcap.allowedAction).toEqual(['GET', 'HEAD'])
    // Chained under the generation delegation rather than the Space root, so
    // the annex key that signs it is one the annex document lists.
    for (const zcap of [collectionZcap, readZcap]) {
      expect(zcap.parentCapability).toBe(generationDelegation.id)
      // And clamped: a child never outlives its parent.
      expect(Date.parse(zcap.expires)).toBeLessThanOrEqual(
        Date.parse(
          (generationDelegation as unknown as { expires: string }).expires
        )
      )
    }
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
      app: { name: 'Example App', origin: 'https://app.example' }
    })

    // The private collection routed through provisionEncryptedCollection (with
    // the identity-KAK recipient kid and the app's attribution); the public one
    // stayed plaintext via ensureCollection.
    expect(provisionCalls).toHaveLength(1)
    expect(provisionCalls[0].collectionId).toBe('example-app-data')
    expect(provisionCalls[0].recipientId).toBe(
      x25519RecipientFromDidKey({ did: granteeDid }).id
    )
    expect(provisionCalls[0].generator).toBe(granteeDid)
    expect(ensureCalls).toEqual([{ id: 'example-app-public', isPublic: true }])
  })

  it('awaits beforeProvision with every signed grant before any collection is provisioned', async () => {
    delegated.length = 0
    ensureCalls.length = 0
    provisionCalls.length = 0
    const order: string[] = []
    let hookZcaps: IZcap[] = []
    const zcaps = await processZcaps({
      zcapRequests: [
        { ...collectionDetail, controller: granteeDid },
        standardReadDetail,
        publicCollectionDetail
      ],
      session,
      beforeProvision: async signed => {
        // Every delegation is already signed; nothing is provisioned yet.
        order.push(
          `hook:${signed.length}:${provisionCalls.length}:${ensureCalls.length}`
        )
        hookZcaps = [...signed]
      }
    })
    expect(order).toEqual(['hook:3:0:0'])
    expect(provisionCalls).toHaveLength(1)
    expect(ensureCalls).toEqual([{ id: 'example-app-public', isPublic: true }])
    // The hook saw the same signed grants the call returns, each carrying
    // what revocation reads back: the parent and the controller.
    expect(hookZcaps).toEqual(zcaps)
    for (const zcap of hookZcaps) {
      expect(zcap).toHaveProperty('parentCapability')
    }
    expect((hookZcaps[0] as { controller: string }).controller).toBe(granteeDid)
  })

  it('provisions nothing when beforeProvision throws', async () => {
    delegated.length = 0
    ensureCalls.length = 0
    provisionCalls.length = 0
    await expect(
      processZcaps({
        zcapRequests: [
          { ...collectionDetail, controller: granteeDid },
          publicCollectionDetail
        ],
        session,
        beforeProvision: async () => {
          throw new Error('history write failed')
        }
      })
    ).rejects.toThrow('history write failed')
    expect(provisionCalls).toHaveLength(0)
    expect(ensureCalls).toHaveLength(0)
  })

  it('does not call beforeProvision when no grant provisions', async () => {
    provisionCalls.length = 0
    let called = false
    const zcaps = await processZcaps({
      zcapRequests: [standardReadDetail],
      session,
      beforeProvision: async () => {
        called = true
      }
    })
    expect(zcaps).toHaveLength(1)
    expect(called).toBe(false)
  })

  it('admits a grantee to an existing private collection only after beforeProvision', async () => {
    provisionCalls.length = 0
    collectionListing = [{ id: 'example-app-data' }]
    const order: string[] = []
    await processZcaps({
      zcapRequests: [{ ...collectionDetail, controller: granteeDid }],
      session,
      beforeProvision: async () => {
        order.push(`hook:${provisionCalls.length}`)
      }
    })
    expect(order).toEqual(['hook:0'])
    expect(provisionCalls.map(call => call.collectionId)).toEqual([
      'example-app-data'
    ])
  })

  it('refuses a private-collection grant to an underivable controller at resolution', async () => {
    provisionCalls.length = 0
    ensureCalls.length = 0
    // Right prefix, undecodable body: there is no X25519 twin to escrow, so
    // the grant previews as "cannot fulfill" and the collection is never
    // created, rather than throwing part-way through the response.
    const descriptor = { ...collectionDetail, controller: 'did:key:z6MkZZZZ' }
    expect(
      resolveGrant({
        descriptor,
        space: SPACE,
        collections: NO_COLLECTIONS
      }).target.targetClass
    ).toBeUndefined()
    const zcaps = await processZcaps({
      zcapRequests: [descriptor],
      session
    })
    expect(zcaps).toHaveLength(0)
    expect(provisionCalls).toHaveLength(0)
    expect(ensureCalls).toHaveLength(0)
  })

  it('refuses a private-collection grant to a non-did:key controller', () => {
    expect(
      resolveGrant({
        descriptor: {
          ...collectionDetail,
          controller: 'did:web:agent.example'
        },
        space: SPACE,
        collections: NO_COLLECTIONS
      }).target.targetClass
    ).toBeUndefined()
  })

  it('still grants a public collection to a non-did:key controller', () => {
    expect(
      resolveGrant({
        descriptor: {
          ...publicCollectionDetail,
          controller: 'did:web:agent.example'
        },
        space: SPACE,
        collections: NO_COLLECTIONS
      }).target.targetClass
    ).toBe('public-collection')
  })

  it('an interaction-URL agent grant provisions encrypted and unattributed', async () => {
    delegated.length = 0
    ensureCalls.length = 0
    provisionCalls.length = 0
    await processZcaps({
      zcapRequests: [{ ...collectionDetail, controller: granteeDid }],
      session
    })
    expect(ensureCalls).toEqual([])
    expect(provisionCalls).toEqual([
      {
        collectionId: 'example-app-data',
        recipientId: x25519RecipientFromDidKey({ did: granteeDid }).id
      }
    ])
  })

  it('caps a standard-collection write to read-only when delegating', async () => {
    // The string target resolves only onto a collection the Space lists.
    collectionListing = [{ id: 'private-credentials' }]
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

  it('provisions a public collection as public and delegates the full vocabulary', async () => {
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
    expect(zcap.invocationTarget).toBe(`${SPACE_URL}example-app-public/`)
    // Public covers only unauthenticated reads; writes stay capability-only,
    // with the ordinary write TTL and the full vocabulary (in ceiling order):
    // published content is still the RP's own data, so PUT and DELETE survive.
    expect(zcap.allowedAction).toEqual(['GET', 'HEAD', 'POST', 'PUT', 'DELETE'])
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
      session
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
    ).toEqual(['GET', 'HEAD', 'POST', 'PUT', 'DELETE'])
  })

  it('grants a string target on an existing public collection the full vocabulary', async () => {
    collectionListing = [{ id: 'example-app-public', isPublic: true }]
    delegated.length = 0
    ensureCalls.length = 0
    const zcaps = await processZcaps({
      zcapRequests: [
        {
          referenceId: 'public-by-url',
          allowedAction: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
          controller: RP_DID,
          invocationTarget: `${SPACE_URL}example-app-public`
        }
      ],
      session
    })
    expect(zcaps).toHaveLength(1)
    expect(
      (zcaps[0] as unknown as { allowedAction: string[] }).allowedAction
    ).toEqual(['GET', 'HEAD', 'POST', 'PUT', 'DELETE'])
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
      session
    })
    // The `#collection` spelling of an existing public collection is the
    // idempotent public re-grant: nothing provisioned -- so the
    // public policy is not re-applied, and no recipient
    // roster is set up on a world-readable plaintext collection.
    expect(zcaps).toHaveLength(1)
    expect(ensureCalls).toEqual([])
    expect(provisionCalls).toEqual([])
    expect(
      (zcaps[0] as unknown as { allowedAction: string[] }).allowedAction
    ).toEqual(['GET', 'HEAD', 'POST', 'PUT', 'DELETE'])
  })

  it('refuses a same-request public grant on a just-provisioned private collection', async () => {
    // One request, two descriptors naming the same collection: the first
    // provisions it private (encrypted, multi-recipient), the
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
      session
    })
    expect(zcaps).toHaveLength(1)
    expect(provisionCalls).toHaveLength(1)
    expect(provisionCalls[0].collectionId).toBe('example-app-data')
    // The public grant was skipped outright: setPublic never runs.
    expect(ensureCalls).toEqual([])
  })

  it('refuses a same-request string target on a just-provisioned public collection', async () => {
    // The mirror order: the first descriptor provisions a public collection,
    // the second reaches the same collection as a plain URL asking for the
    // full vocabulary. A string target sees only the collections that stood
    // before the request, as the consent preview did, so the second grant is
    // skipped and the first is not re-provisioned.
    delegated.length = 0
    ensureCalls.length = 0
    const zcaps = await processZcaps({
      zcapRequests: [
        publicCollectionDetail,
        {
          referenceId: 'public-by-url-within-request',
          allowedAction: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
          controller: RP_DID,
          invocationTarget: `${SPACE_URL}example-app-public`
        }
      ],
      session
    })
    expect(zcaps).toHaveLength(1)
    expect(ensureCalls).toEqual([{ id: 'example-app-public', isPublic: true }])
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

  it('escrows a share only after beforeProvision records its signed zcap', async () => {
    shareCalls.length = 0
    let sharesAtHook = -1
    let signedAtHook: unknown[] = []
    const zcaps = await processZcaps({
      zcapRequests: [shareDetail],
      session,
      beforeProvision: async signed => {
        sharesAtHook = shareCalls.length
        signedAtHook = signed
      }
    })
    expect(sharesAtHook).toBe(0)
    expect(signedAtHook).toEqual(zcaps)
    expect(shareCalls).toHaveLength(1)
  })

  it('escrows no share when beforeProvision throws', async () => {
    shareCalls.length = 0
    await expect(
      processZcaps({
        zcapRequests: [shareDetail],
        session,
        beforeProvision: async () => {
          throw new Error('history write failed')
        }
      })
    ).rejects.toThrow('history write failed')
    expect(shareCalls).toHaveLength(0)
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
        space: SPACE,
        collections: NO_COLLECTIONS
      }).target.targetClass
    ).toBeUndefined()
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
        space: SPACE,
        collections: NO_COLLECTIONS
      }).target.targetClass
    ).toBeUndefined()
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
      space: SPACE,
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
            capabilityQuery: [collectionDetail, standardReadDetail]
          }
        ],
        challenge: CHALLENGE,
        domain: 'verifier.example'
      },
      session,
      credentialRequestOrigin: 'https://verifier.example',
      delegateStandaloneZcaps: true
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
      credentialRequestOrigin: 'https://verifier.example',
      delegateStandaloneZcaps: true
    })
    const vp = verifiablePresentation as unknown as {
      zcap?: IZcap[]
      proof?: unknown
    }
    expect(vp.proof).toBeUndefined()
    expect(vp.zcap).toHaveLength(1)
  })

  it('delegates no standalone grant without the opt-in', async () => {
    const response = await processRequest({
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
    expect(response).toEqual({})
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
        credentialRequestOrigin: 'https://verifier.example',
        delegateStandaloneZcaps: true
      })
    ).rejects.toThrow(/does not match request origin/)
  })
})
