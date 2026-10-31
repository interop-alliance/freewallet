// @vitest-environment node
import { describe, it, expect, vi } from 'vitest'
import { x25519RecipientFromDidKey } from '@interop/pws-client/edv'
import type { ConnectionsListing } from '@interop/wallet-core/connections'
import type { Session } from '@/types/auth'
import { attributeExistingCollections } from './attributeExistingCollections'
import { existingCollectionsFrom, resolveGrants } from './processZcaps'

const SPACE_URL = 'https://was.example/space/abc/'
const GRANTEE = 'did:key:z6MkqojacRDqmQgDi4ESKKhGDqnZx4C6cChAbQZXvnUFX7D7'
const GRANTEE_KID = x25519RecipientFromDidKey({ did: GRANTEE }).id!

/**
 * The consent inputs for one string target naming an existing collection.
 *
 * @param collectionId {string}
 * @returns {Parameters<typeof resolveGrants>[0]}
 */
function stringTargetResolution(
  collectionId: string
): Parameters<typeof resolveGrants>[0] {
  return {
    zcapRequests: [
      {
        referenceId: collectionId,
        allowedAction: ['GET'],
        invocationTarget: `${SPACE_URL}${collectionId}/`,
        controller: GRANTEE
      }
    ],
    spaceUrl: SPACE_URL,
    collections: existingCollectionsFrom([{ id: collectionId }])
  }
}

/**
 * A storage double answering the attribution pass's reads.
 *
 * @param options {object}
 * @param options.encrypted {boolean}   what the metadata read reports
 * @param options.recipientIds {string[]}   the current key epoch's readers
 * @returns {object}
 */
function storageDouble({
  encrypted,
  recipientIds
}: {
  encrypted: boolean
  recipientIds: string[]
}) {
  const listing: ConnectionsListing = {
    entries: [],
    unreadable: [],
    unparseable: []
  }
  return {
    readConnectionsListing: vi.fn(async () => ({
      listing,
      spaceUrl: `${SPACE_URL}`
    })),
    collectionAttribution: vi.fn(async () => ({ encrypted })),
    listCollectionShares: vi.fn(async () =>
      recipientIds.map(recipientId => ({ recipientId }))
    )
  }
}

describe('attributeExistingCollections key-epoch read', () => {
  it('drops the ciphertext note when the current key epoch lists the grantee', async () => {
    const resolution = stringTargetResolution('notes')
    const storage = storageDouble({
      encrypted: true,
      recipientIds: [GRANTEE_KID]
    })
    const attributed = await attributeExistingCollections({
      resolution,
      grants: resolveGrants(resolution),
      storage: storage as unknown as Session['storage']
    })
    expect(attributed?.[0]!.target.encrypted).toBe(false)
    // The roster alone, handed no directory entries: a withheld directory
    // must not change what the roster says.
    expect(storage.listCollectionShares).toHaveBeenCalledWith({
      collectionId: 'notes'
    })
    expect(storage.readConnectionsListing).not.toHaveBeenCalled()
  })

  it('keeps the ciphertext note when the grantee is not listed', async () => {
    const resolution = stringTargetResolution('notes')
    const storage = storageDouble({
      encrypted: true,
      recipientIds: ['did:key:z6MkOther#other']
    })
    const attributed = await attributeExistingCollections({
      resolution,
      grants: resolveGrants(resolution),
      storage: storage as unknown as Session['storage']
    })
    expect(attributed?.[0]!.target.encrypted).toBe(true)
    expect(attributed?.[0]!.target.outsideKeyEpoch).toBe(true)
  })

  it('reaches no verdict on the key epoch when the roster read fails', async () => {
    const resolution = stringTargetResolution('notes')
    const storage = {
      ...storageDouble({ encrypted: true, recipientIds: [] }),
      listCollectionShares: vi.fn(async () => {
        throw new Error('roster unreachable')
      })
    }
    const attributed = await attributeExistingCollections({
      resolution,
      grants: resolveGrants(resolution),
      storage: storage as unknown as Session['storage']
    })
    // The ciphertext note stays, but an unread epoch says nothing about
    // whether the grantee is absent from it.
    expect(attributed?.[0]!.target.encrypted).toBe(true)
    expect(attributed?.[0]!.target.outsideKeyEpoch).toBe(false)
  })

  it('reads no key epoch for a plaintext collection', async () => {
    const resolution = stringTargetResolution('notes')
    const storage = storageDouble({ encrypted: false, recipientIds: [] })
    const attributed = await attributeExistingCollections({
      resolution,
      grants: resolveGrants(resolution),
      storage: storage as unknown as Session['storage']
    })
    expect(attributed?.[0]!.target.encrypted).toBe(false)
    expect(storage.listCollectionShares).not.toHaveBeenCalled()
  })

  it('reads a standard collection key epoch without a metadata read', async () => {
    const resolution = stringTargetResolution('private-credentials')
    const storage = storageDouble({
      encrypted: true,
      recipientIds: [GRANTEE_KID]
    })
    const [first] = resolveGrants(resolution)
    expect(first!.target.encrypted).toBe(true)
    // The first pass reads no epoch, so it reaches no verdict yet.
    expect(first!.target.outsideKeyEpoch).toBe(false)
    const attributed = await attributeExistingCollections({
      resolution,
      grants: [first!],
      storage: storage as unknown as Session['storage']
    })
    expect(attributed?.[0]!.target.encrypted).toBe(false)
    expect(storage.collectionAttribution).not.toHaveBeenCalled()
  })
})

describe("attributeExistingCollections on an agent's stamp", () => {
  const AGENT = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

  /**
   * The consent inputs for one private-collection descriptor naming the
   * existing collection `notes`.
   *
   * @param controller {string}   the requesting grantee
   * @returns {Parameters<typeof resolveGrants>[0]}
   */
  function privateTargetResolution(
    controller: string
  ): Parameters<typeof resolveGrants>[0] {
    return {
      zcapRequests: [
        {
          referenceId: 'notes',
          allowedAction: ['GET'],
          invocationTarget: {
            type: 'https://w3id.org/byoe#private-collection',
            name: 'notes'
          },
          controller
        }
      ],
      spaceUrl: SPACE_URL,
      collections: existingCollectionsFrom([{ id: 'notes' }])
    }
  }

  /**
   * A storage double whose metadata read reports an agent's stamp.
   *
   * @param generator {object}   the stamped `generator`
   * @returns {object}
   */
  function stampedStorage(generator: { id: string; name?: string }) {
    return {
      ...storageDouble({ encrypted: true, recipientIds: [] }),
      collectionAttribution: vi.fn(async () => ({ encrypted: true, generator }))
    }
  }

  it('names the agent by its stamped name, with no directory read', async () => {
    const resolution = privateTargetResolution(GRANTEE)
    const storage = stampedStorage({ id: AGENT, name: 'Backup Agent' })
    const attributed = await attributeExistingCollections({
      resolution,
      grants: resolveGrants(resolution),
      storage: storage as unknown as Session['storage']
    })
    expect(attributed?.[0]!.target.existing).toMatchObject({
      creator: 'other',
      creatorName: 'Backup Agent'
    })
    expect(storage.readConnectionsListing).not.toHaveBeenCalled()
  })

  it("reads the agent's own collection as this-app", async () => {
    const resolution = privateTargetResolution(AGENT)
    const storage = stampedStorage({ id: AGENT, name: 'Backup Agent' })
    const attributed = await attributeExistingCollections({
      resolution,
      grants: resolveGrants(resolution),
      storage: storage as unknown as Session['storage']
    })
    expect(attributed?.[0]!.target.existing?.creator).toBe('this-app')
  })
})

describe("attributeExistingCollections on an app's stamp", () => {
  const APP = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
  const APP_ORIGIN = 'https://notes.example'

  /**
   * The consent inputs for one private-collection descriptor naming the
   * existing collection `notes`, from a requester other than its creator.
   *
   * @returns {Parameters<typeof resolveGrants>[0]}
   */
  function privateTargetResolution(): Parameters<typeof resolveGrants>[0] {
    return {
      zcapRequests: [
        {
          referenceId: 'notes',
          allowedAction: ['GET'],
          invocationTarget: {
            type: 'https://w3id.org/byoe#private-collection',
            name: 'notes'
          },
          controller: GRANTEE
        }
      ],
      spaceUrl: SPACE_URL,
      collections: existingCollectionsFrom([{ id: 'notes' }]),
      appUrl: 'https://other.example/'
    }
  }

  /**
   * A storage double whose metadata read reports an app's stamp, and whose
   * directory holds that app's entry.
   *
   * @param options {object}
   * @param [options.directoryFails] {boolean}
   * @returns {object}
   */
  function stampedStorage({
    directoryFails = false
  }: { directoryFails?: boolean } = {}) {
    const entry = {
      version: 1,
      kind: 'app',
      id: APP,
      name: 'Notes',
      origin: APP_ORIGIN,
      url: `${APP_ORIGIN}/app`,
      firstSeen: '2026-07-01T00:00:00.000Z',
      lastSeen: '2026-07-01T00:00:00.000Z',
      retired: '2026-08-01T00:00:00.000Z',
      grants: [],
      writers: []
    }
    return {
      ...storageDouble({ encrypted: true, recipientIds: [] }),
      collectionAttribution: vi.fn(async () => ({
        encrypted: true,
        generator: { id: APP, origin: APP_ORIGIN }
      })),
      readConnectionsListing: vi.fn(async () => {
        if (directoryFails) {
          throw new Error('directory refused')
        }
        return {
          listing: {
            entries: [{ resourceId: 'r-notes', entry, body: entry }],
            unreadable: [],
            unparseable: []
          },
          spaceUrl: `${SPACE_URL}`
        }
      })
    }
  }

  it('names the creator from its directory entry, read once', async () => {
    const resolution = privateTargetResolution()
    const storage = stampedStorage()
    const attributed = await attributeExistingCollections({
      resolution,
      grants: resolveGrants(resolution),
      storage: storage as unknown as Session['storage']
    })
    expect(attributed?.[0]!.target.existing).toMatchObject({
      creator: 'other',
      creatorName: 'Notes'
    })
    expect(storage.readConnectionsListing).toHaveBeenCalledTimes(1)
  })

  it('leaves the creator unresolved when the directory read fails', async () => {
    const resolution = privateTargetResolution()
    const storage = stampedStorage({ directoryFails: true })
    const attributed = await attributeExistingCollections({
      resolution,
      grants: resolveGrants(resolution),
      storage: storage as unknown as Session['storage']
    })
    expect(attributed?.[0]!.target.existing?.creator).toBe('other')
    expect(attributed?.[0]!.target.existing?.creatorName).not.toBe('Notes')
  })
})
