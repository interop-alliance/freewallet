// @vitest-environment node
import { describe, it, expect, vi } from 'vitest'
import { x25519RecipientFromDidKey } from '@interop/was-client/edv'
import type { Session } from '@/types/auth'
import { attributeExistingCollections } from './attributeExistingCollections'
import { existingCollectionsFrom, resolveGrants } from './processZcaps'

const SPACE = { serverUrl: 'https://was.example/', spaceId: 'abc' }
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
        invocationTarget: `${SPACE.serverUrl}space/${SPACE.spaceId}/${collectionId}/`,
        controller: GRANTEE
      }
    ],
    space: SPACE,
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
  return {
    listAppKeys: vi.fn(async () => ({ appKeys: [], skipped: {} })),
    listHistoryItems: vi.fn(async () => ({ entries: [], unreadable: 0 })),
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
    expect(storage.listCollectionShares).toHaveBeenCalledWith({
      collectionId: 'notes',
      items: { entries: [], unreadable: 0 }
    })
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
      space: SPACE,
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

  it('names the agent by its stamped name, with no records lookup', async () => {
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
    expect(storage.listAppKeys).not.toHaveBeenCalled()
    expect(storage.listHistoryItems).not.toHaveBeenCalled()
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
