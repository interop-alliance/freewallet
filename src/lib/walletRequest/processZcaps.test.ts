// @vitest-environment node
import { describe, it, expect } from 'vitest'
import {
  APP_CONNECTIONS_COLLECTION,
  KEY_MAP_COLLECTION,
  UNLOCK_METHODS_COLLECTION
} from '@interop/wallet-core/space'
import { x25519RecipientFromDidKey } from '@interop/was-client/edv'
import {
  existingCollectionsFrom,
  isSatisfiable,
  resolveGrant,
  resolveInvocationTarget
} from './processZcaps'
import type { ICapabilityQueryDetail } from './types'

const SPACE = { serverUrl: 'https://was.example/', spaceId: 'abc' }
const DESCRIPTOR: ICapabilityQueryDetail = {
  referenceId: 'docs',
  allowedAction: ['GET'],
  invocationTarget: {
    type: 'https://w3id.org/byoe#private-collection',
    name: 'docs'
  },
  controller: 'did:key:z6MkkxrCpdyM52QkhCaGrGRMdps26M8JQ8TmapYHPwc7n8MJ'
}

describe('resolveGrant recipient presence', () => {
  it('resolves satisfiable with a controller present', () => {
    const { target } = resolveGrant({
      descriptor: DESCRIPTOR,
      space: SPACE,
      collections: existingCollectionsFrom([])
    })
    expect(isSatisfiable(target)).toBe(true)
  })

  it('refuses a descriptor that names no controller as unsatisfiable', () => {
    // The wire type requires a `controller`, but an actual request body can
    // omit it; a grant with no recipient must render "cannot fulfill" rather
    // than a recipient-less consent row that delegates to nobody.
    const { controller: _controller, ...omitted } = DESCRIPTOR
    const { target } = resolveGrant({
      descriptor: omitted as ICapabilityQueryDetail,
      space: SPACE,
      collections: existingCollectionsFrom([])
    })
    expect(target.targetClass).toBeUndefined()
  })

  it('allows an empty controller for the App Connect consent preview', () => {
    // On first run the app-key DID does not exist yet; the preview resolves
    // with an empty controller and the approved path fills the real subject
    // DID before resolving again (without the opt-out).
    const { target } = resolveGrant({
      descriptor: { ...DESCRIPTOR, controller: '' },
      space: SPACE,
      collections: existingCollectionsFrom([]),
      allowMissingController: true
    })
    expect(isSatisfiable(target)).toBe(true)
  })
})

describe('resolveGrant provisioning', () => {
  it('provisions a new and an existing private collection', () => {
    for (const collections of [
      existingCollectionsFrom([]),
      existingCollectionsFrom([{ id: 'docs' }])
    ]) {
      const { target } = resolveGrant({
        descriptor: DESCRIPTOR,
        space: SPACE,
        collections
      })
      expect(isSatisfiable(target)).toBe(true)
      expect(target.needsProvisioning).toBe(true)
    }
  })
})

describe('resolveInvocationTarget string targets', () => {
  const requester = { controller: DESCRIPTOR.controller }
  const collectionUrl = `${SPACE.serverUrl}space/${SPACE.spaceId}/notes/`
  const resourceUrl = `${SPACE.serverUrl}space/${SPACE.spaceId}/notes/n1`

  it('refuses a collection that does not exist, and a Resource inside one', () => {
    for (const descriptor of [collectionUrl, resourceUrl]) {
      const target = resolveInvocationTarget({
        descriptor,
        space: SPACE,
        collections: existingCollectionsFrom([]),
        requester
      })
      expect(isSatisfiable(target)).toBe(false)
    }
  })

  it('grants an existing collection, and a Resource inside one, without provisioning', () => {
    const collections = existingCollectionsFrom([{ id: 'notes' }])
    const collection = resolveInvocationTarget({
      descriptor: collectionUrl,
      space: SPACE,
      collections,
      requester
    })
    expect(collection.targetClass).toBe('collection')
    expect(collection.collectionId).toBe('notes')
    expect(collection.needsProvisioning).toBe(false)
    const resource = resolveInvocationTarget({
      descriptor: resourceUrl,
      space: SPACE,
      collections,
      requester
    })
    expect(resource.invocationTarget).toBe(resourceUrl)
    expect(resource.collectionId).toBe('notes')
    expect(resource.needsProvisioning).toBe(false)
  })

  it('does not flag a standard or an already-public collection', () => {
    const standard = resolveInvocationTarget({
      descriptor: `${SPACE.serverUrl}space/${SPACE.spaceId}/private-credentials/`,
      space: SPACE,
      collections: existingCollectionsFrom([{ id: 'private-credentials' }]),
      requester
    })
    expect(standard.targetClass).toBe('protected-collection')
    expect(standard.needsProvisioning).toBe(false)
    const publicOne = resolveInvocationTarget({
      descriptor: collectionUrl,
      space: SPACE,
      collections: existingCollectionsFrom([{ id: 'notes', isPublic: true }]),
      requester
    })
    expect(publicOne.targetClass).toBe('public-collection')
    expect(publicOne.needsProvisioning).toBe(false)
  })

  it('grants an existing collection by string target, write actions included', () => {
    const { target, allowedActions } = resolveGrant({
      descriptor: {
        ...DESCRIPTOR,
        invocationTarget: collectionUrl,
        allowedAction: ['GET', 'PUT']
      },
      space: SPACE,
      collections: existingCollectionsFrom([{ id: 'notes' }])
    })
    expect(isSatisfiable(target)).toBe(true)
    expect(allowedActions).toEqual(['GET', 'PUT'])
  })

  it('flags an existing encrypted collection as ciphertext to the grantee', () => {
    // A string target admits the grantee to no key roster, so an encrypted
    // app collection reads as ciphertext. The flag comes from the
    // collection's own metadata, which the attribution pass reads.
    const encrypted = resolveInvocationTarget({
      descriptor: collectionUrl,
      space: SPACE,
      collections: existingCollectionsFrom([{ id: 'notes', encrypted: true }]),
      requester
    })
    expect(encrypted.encrypted).toBe(true)
    const plaintext = resolveInvocationTarget({
      descriptor: collectionUrl,
      space: SPACE,
      collections: existingCollectionsFrom([{ id: 'notes', encrypted: false }]),
      requester
    })
    expect(plaintext.encrypted).toBe(false)
    // The descriptor form joins the grantee to the roster, so it decrypts.
    const joined = resolveInvocationTarget({
      descriptor: {
        type: 'https://w3id.org/byoe#private-collection',
        name: 'notes'
      },
      space: SPACE,
      collections: existingCollectionsFrom([{ id: 'notes', encrypted: true }]),
      requester
    })
    expect(joined.needsProvisioning).toBe(true)
    expect(joined.encrypted).toBe(false)
  })

  it('drops the ciphertext note for a grantee the current key epoch lists', () => {
    const granteeKid = x25519RecipientFromDidKey({
      did: DESCRIPTOR.controller
    }).id!
    const listed = resolveInvocationTarget({
      descriptor: collectionUrl,
      space: SPACE,
      collections: existingCollectionsFrom([
        { id: 'notes', encrypted: true, recipientIds: new Set([granteeKid]) }
      ]),
      requester
    })
    expect(listed.encrypted).toBe(false)
    expect(listed.outsideKeyEpoch).toBe(false)
    const unlisted = resolveInvocationTarget({
      descriptor: collectionUrl,
      space: SPACE,
      collections: existingCollectionsFrom([
        { id: 'notes', encrypted: true, recipientIds: new Set(['#other']) }
      ]),
      requester
    })
    expect(unlisted.encrypted).toBe(true)
    expect(unlisted.outsideKeyEpoch).toBe(true)
    // An epoch left unread reaches no verdict, whatever `encrypted` says.
    const unread = resolveInvocationTarget({
      descriptor: collectionUrl,
      space: SPACE,
      collections: existingCollectionsFrom([{ id: 'notes', encrypted: true }]),
      requester
    })
    expect(unread.encrypted).toBe(true)
    expect(unread.outsideKeyEpoch).toBe(false)
    // A standard encrypted collection a share already escrowed the grantee
    // into reads the same way.
    const standard = resolveInvocationTarget({
      descriptor: `${SPACE.serverUrl}space/${SPACE.spaceId}/private-credentials/`,
      space: SPACE,
      collections: existingCollectionsFrom([
        { id: 'private-credentials', recipientIds: new Set([granteeKid]) }
      ]),
      requester
    })
    expect(standard.encrypted).toBe(false)
  })

  it('reaches no key-epoch verdict on a controller that derives no recipient', () => {
    // A did:key the recipient derivation cannot handle (a P-256 key here) was
    // never escrowed, so the collection reads as ciphertext to it. But a
    // read epoch cannot be said to exclude an id that does not exist, so
    // the interaction-URL page's refusal does not fire: its copy would send
    // the developer to a descriptor form the same controller cannot satisfy.
    const p256 = {
      controller: 'did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169'
    }
    const target = resolveInvocationTarget({
      descriptor: collectionUrl,
      space: SPACE,
      collections: existingCollectionsFrom([
        { id: 'notes', encrypted: true, recipientIds: new Set(['#other']) }
      ]),
      requester: p256
    })
    expect(target.encrypted).toBe(true)
    expect(target.outsideKeyEpoch).toBe(false)
  })

  it('refuses the Space itself, with or without a trailing slash', () => {
    for (const descriptor of [
      `${SPACE.serverUrl}space/${SPACE.spaceId}`,
      `${SPACE.serverUrl}space/${SPACE.spaceId}/`
    ]) {
      const target = resolveInvocationTarget({
        descriptor,
        space: SPACE,
        collections: existingCollectionsFrom([{ id: 'notes' }]),
        requester
      })
      expect(isSatisfiable(target)).toBe(false)
    }
  })
})

describe('whole-Space targets', () => {
  it('refuses the reserved #space descriptor type', () => {
    const { target } = resolveGrant({
      descriptor: {
        ...DESCRIPTOR,
        invocationTarget: { type: 'https://w3id.org/byoe#space' }
      },
      space: SPACE,
      collections: existingCollectionsFrom([])
    })
    expect(isSatisfiable(target)).toBe(false)
    expect(target.invocationTarget).toBeUndefined()
  })
})

describe('never-grantable system collections', () => {
  const NEVER = [
    KEY_MAP_COLLECTION.id,
    UNLOCK_METHODS_COLLECTION.id,
    APP_CONNECTIONS_COLLECTION
  ]
  // Present in the snapshot, so a string target is refused for what it names
  // rather than for naming a missing collection.
  const collections = existingCollectionsFrom(NEVER.map(id => ({ id })))
  const DESCRIPTOR_TYPES = [
    'https://w3id.org/byoe#private-collection',
    'https://w3id.org/byoe#public-collection',
    'https://w3id.org/byoe#shared-wallet-collection'
  ]

  it('refuses every descriptor type naming them', () => {
    for (const name of NEVER) {
      for (const type of DESCRIPTOR_TYPES) {
        const { target } = resolveGrant({
          descriptor: { ...DESCRIPTOR, invocationTarget: { type, name } },
          space: SPACE,
          collections
        })
        expect(isSatisfiable(target), `${type} ${name}`).toBe(false)
      }
    }
  })

  it('refuses a string target at them or at a Resource inside them', () => {
    for (const name of NEVER) {
      for (const url of [
        `${SPACE.serverUrl}space/${SPACE.spaceId}/${name}`,
        `${SPACE.serverUrl}space/${SPACE.spaceId}/${name}/`,
        `${SPACE.serverUrl}space/${SPACE.spaceId}/${name}/user-key.jsonl`
      ]) {
        const { target } = resolveGrant({
          descriptor: { ...DESCRIPTOR, invocationTarget: url },
          space: SPACE,
          collections
        })
        expect(isSatisfiable(target), url).toBe(false)
      }
    }
  })

  it('still grants a read of the id collection', () => {
    const { target, allowedActions } = resolveGrant({
      descriptor: {
        ...DESCRIPTOR,
        invocationTarget: `${SPACE.serverUrl}space/${SPACE.spaceId}/id/did.jsonl`
      },
      space: SPACE,
      collections: existingCollectionsFrom([{ id: 'id' }])
    })
    expect(target.targetClass).toBe('protected-collection')
    expect(allowedActions).toEqual(['GET'])
  })
})

describe('resolveInvocationTarget existing-collection reading', () => {
  const APP_DID = 'did:key:z6Mkw7S2TH3X6APb2znNczrq1qFmt53rGELjkpRRYBKR6ucp'
  const APP_ORIGIN = 'https://app.example'
  const APP_URL = 'https://app.example/editor'
  const OTHER_DID = 'did:key:z6Mkp56zji5TMZdkHSgjRC33UhTw3Kgu5S9pP5kXeiTcGHRq'
  const DOCS = {
    type: 'https://w3id.org/byoe#private-collection',
    name: 'docs'
  }
  // The attribution as the resolver sees it: the `generator` object off the
  // collection, plus the creating app as the wallet's own records know it.
  // This one carries no `generator.url` or `generator.name`, so the join
  // answers both.
  const createdByApp = existingCollectionsFrom([
    {
      id: 'docs',
      attribution: {
        generator: { id: APP_DID, origin: APP_ORIGIN },
        creatorApp: { name: 'Editor', appUrl: APP_URL }
      }
    }
  ])

  /**
   * A collection stamped with the full `generator` object, and optionally a
   * joined record of the creator.
   *
   * @param options {object}
   * @param options.url {string}   the stamped `generator.url`
   * @param [options.name] {string}   the stamped `generator.name`
   * @param [options.creatorApp] {{ name: string, appUrl: string }}
   * @returns {ReturnType<typeof existingCollectionsFrom>}
   */
  function stampedWithUrl({
    url,
    name,
    creatorApp
  }: {
    url: string
    name?: string
    creatorApp?: { name: string; appUrl: string }
  }) {
    return existingCollectionsFrom([
      {
        id: 'docs',
        attribution: {
          generator: {
            id: APP_DID,
            origin: APP_ORIGIN,
            url,
            ...(name && { name })
          },
          creatorApp
        }
      }
    ])
  }

  it('reports nothing for a collection that does not exist yet', () => {
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: existingCollectionsFrom([]),
      requester: { controller: APP_DID }
    })
    expect(target.existing).toBeUndefined()
    expect(target.needsProvisioning).toBe(true)
  })

  it('reports nothing for a collection whose attribution is unread', () => {
    // The first pass resolves over the lean listing alone; the row shows no
    // note until the second pass has read the collection's metadata.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: existingCollectionsFrom([{ id: 'docs' }]),
      requester: { controller: OTHER_DID }
    })
    expect(target.existing).toBeUndefined()
    expect(target.needsProvisioning).toBe(true)
  })

  it("reads the requester's own collection as this-app", () => {
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: createdByApp,
      requester: { controller: APP_DID }
    })
    expect(target.existing).toEqual({
      creator: 'this-app',
      generator: { id: APP_DID, origin: APP_ORIGIN }
    })
  })

  it('reads a stamped generator.url equal to the requester appUrl as this-application', () => {
    // The app reconnects under a new did:key and the wallet holds no record
    // of the creator at all: the collection's own `generator.url` vouches.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: stampedWithUrl({ url: APP_URL }),
      requester: { controller: OTHER_DID, appUrl: APP_URL }
    })
    expect(target.existing?.creator).toBe('this-application')
  })

  it('reads a stamped generator.url on the same origin but another path as other', () => {
    // The stamped URL decides ahead of the join: even a joined record naming
    // the requester's app URL does not override it.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: stampedWithUrl({
        url: 'https://app.example/notes',
        creatorApp: { name: 'Notes', appUrl: APP_URL }
      }),
      requester: { controller: OTHER_DID, appUrl: APP_URL }
    })
    expect(target.existing?.creator).toBe('other')
  })

  it('names the creator by generator.name ahead of the join', () => {
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: stampedWithUrl({
        url: APP_URL,
        name: 'Stamped Editor',
        creatorApp: { name: 'Editor', appUrl: APP_URL }
      }),
      requester: { controller: OTHER_DID }
    })
    expect(target.existing?.creatorName).toBe('Stamped Editor')
  })

  it('names the creator through the join when generator.name is absent', () => {
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: stampedWithUrl({
        url: APP_URL,
        creatorApp: { name: 'Editor', appUrl: APP_URL }
      }),
      requester: { controller: OTHER_DID }
    })
    expect(target.existing?.creatorName).toBe('Editor')
  })

  it('falls back to the joined app URL on a collection with no generator.url', () => {
    // The site was disconnected (its app key deleted) and reconnects: a new
    // did:key, the same attested origin, the same canonical app URL.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: createdByApp,
      requester: { controller: OTHER_DID, appUrl: APP_URL }
    })
    expect(target.existing?.creator).toBe('this-application')
  })

  it("reads a different app on the same origin's collection as other", () => {
    // Two apps hosted at different paths of one origin are two apps: the
    // wallet tells them apart by appUrl, and so does the reading.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: createdByApp,
      requester: {
        controller: OTHER_DID,
        appUrl: 'https://app.example/notes'
      }
    })
    expect(target.existing?.creator).toBe('other')
  })

  it("reads other when the creator's app URL is unknown to an App Connect requester", () => {
    // The wallet holds no record naming the creator (no app key, no Login
    // activity), so an origin match alone does not vouch for the same app.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: existingCollectionsFrom([
        {
          id: 'docs',
          attribution: { generator: { id: APP_DID, origin: APP_ORIGIN } }
        }
      ]),
      requester: { controller: OTHER_DID, appUrl: APP_URL }
    })
    expect(target.existing?.creator).toBe('other')
  })

  it('reads other for a requester with no app URL', () => {
    // An interaction-URL agent carries no app URL, so it is never the
    // collection's creating application.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: createdByApp,
      requester: { controller: OTHER_DID }
    })
    expect(target.existing?.creator).toBe('other')
  })

  it("reads another application's collection as other, and still admits the requester", () => {
    // The decided collision policy: the second application is admitted into
    // the collection's every key epoch, exactly as a reconnect is, and the
    // consent row states the creator before approval. The reading is what
    // keeps that admission from being silent.
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: createdByApp,
      requester: { controller: OTHER_DID }
    })
    expect(target.existing).toEqual({
      creator: 'other',
      generator: { id: APP_DID, origin: APP_ORIGIN },
      creatorName: 'Editor'
    })
    expect(isSatisfiable(target)).toBe(true)
    expect(target.needsProvisioning).toBe(true)
  })

  it('reads other on a first-run preview, where no requester DID exists yet', () => {
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: createdByApp,
      requester: { controller: '' }
    })
    expect(target.existing?.creator).toBe('other')
  })

  it('reads a collection with no attribution as unattributed', () => {
    const target = resolveInvocationTarget({
      descriptor: DOCS,
      space: SPACE,
      collections: existingCollectionsFrom([{ id: 'docs', attribution: {} }]),
      requester: { controller: OTHER_DID }
    })
    expect(target.existing).toEqual({ creator: 'unattributed' })
  })

  it('reports nothing for a public or a protected collection', () => {
    const collections = existingCollectionsFrom([
      {
        id: 'docs',
        isPublic: true,
        attribution: { generator: { id: APP_DID } }
      },
      {
        id: 'private-credentials',
        attribution: { generator: { id: APP_DID } }
      }
    ])
    const requester = { controller: OTHER_DID }
    expect(
      resolveInvocationTarget({
        descriptor: DOCS,
        space: SPACE,
        collections,
        requester
      }).existing
    ).toBeUndefined()
    expect(
      resolveInvocationTarget({
        descriptor: { ...DOCS, name: 'private-credentials' },
        space: SPACE,
        collections,
        requester
      }).existing
    ).toBeUndefined()
  })

  it('reads the same collection named as a plain URL the same way', () => {
    const target = resolveInvocationTarget({
      descriptor: `${SPACE.serverUrl}space/${SPACE.spaceId}/docs/`,
      space: SPACE,
      collections: createdByApp,
      requester: { controller: OTHER_DID }
    })
    expect(target.existing?.creator).toBe('other')
  })

  it('carries the reading through resolveGrant with the descriptor controller', () => {
    const { target } = resolveGrant({
      descriptor: { ...DESCRIPTOR, controller: OTHER_DID },
      space: SPACE,
      collections: createdByApp
    })
    expect(target.existing?.creator).toBe('other')
  })

  it('carries the app URL through resolveGrant', () => {
    const { target } = resolveGrant({
      descriptor: { ...DESCRIPTOR, controller: OTHER_DID },
      space: SPACE,
      collections: createdByApp,
      appUrl: APP_URL
    })
    expect(target.existing?.creator).toBe('this-application')
  })
})
