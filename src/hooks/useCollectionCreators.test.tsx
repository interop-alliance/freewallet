/**
 * The three surfaces that name a collection's creator -- the consent row's
 * existing-collection reading, the Storage page's collection listing, and the
 * collection contents page's "Created by" line -- read one resolver
 * (`lookupCollectionCreators`) over the `connections` directory. A creator
 * the user since disconnected keeps its retired entry, which still names it
 * on all three. The contents page reads the directory once on its own, and
 * reads nothing when its caller hands a listing in.
 */
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { attributeCollectionsToApps } from '@/lib/collectionAttribution'
import type { CollectionCreator } from '@/lib/connectedApps'
import type { StorageCollection } from '@/lib/storage'
import { attributeExistingCollections } from '@/lib/walletRequest/attributeExistingCollections'
import {
  existingCollectionsFrom,
  resolveGrants
} from '@/lib/walletRequest/processZcaps'
import type { Session } from '@/types/auth'
import { readConnections } from '@interop/wallet-core/connections'
import {
  APP_DID,
  SPACE_URL,
  fixtureDirectory,
  grantZcap,
  listedConnections,
  recordConsent,
  retireParty,
  type FixtureDirectory
} from '../../tests/unit/connectionFixtures'
import { HMAC_KEY } from '../../tests/unit/memoryConnections'
import { useCollectionCreators } from './useCollectionCreators'
import { useStorageListings } from './useStorageListings'

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean
}

const CREATOR_DID = APP_DID
const CREATOR_ORIGIN = 'https://notes.example'
const CREATOR_URL = 'https://notes.example/app'
const NOTES: StorageCollection = {
  id: 'notes',
  url: `${SPACE_URL}notes/`,
  generator: { id: CREATOR_DID, origin: CREATOR_ORIGIN }
}

/**
 * A storage double over an in-memory `connections` directory, whose `notes`
 * collection carries the creator's stamp.
 *
 * @param directory {FixtureDirectory}
 * @returns {object}
 */
function storageDouble(directory: FixtureDirectory) {
  return {
    hasRemoteStorage: true,
    spaceUrl: SPACE_URL,
    connectionsDirectory: vi.fn(async () => ({
      store: directory.store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL
    })),
    readConnectionsListing: vi.fn(async () => ({
      listing: (await readConnections({
        store: directory.store,
        hmacKey: HMAC_KEY
      }))!,
      spaceUrl: SPACE_URL
    })),
    listCollectionShares: vi.fn(async () => []),
    collectionAttribution: vi.fn(async () => ({
      generator: { id: CREATOR_DID, origin: CREATOR_ORIGIN }
    }))
  }
}

/**
 * Renders a probe component around a hook, without a testing library, and
 * lets its loads settle.
 */
async function renderHook<T>(hook: () => T): Promise<{
  result: () => T
  unmount: () => Promise<void>
}> {
  const container = document.createElement('div')
  const root: Root = createRoot(container)
  let latest: T | undefined
  function Probe() {
    latest = hook()
    return null
  }
  await act(async () => {
    root.render(<Probe />)
  })
  // The directory read, then the creators lookup behind it.
  for (let tick = 0; tick < 4; tick++) {
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 0))
    })
  }
  return {
    result: () => latest as T,
    unmount: () =>
      act(async () => {
        root.unmount()
      })
  }
}

describe('a disconnected creator across the attribution surfaces', () => {
  let directory: FixtureDirectory

  beforeEach(async () => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true
    directory = fixtureDirectory()
    await recordConsent({
      directory,
      did: CREATOR_DID,
      kind: 'app',
      grants: [grantZcap({ id: 'urn:zcap:notes', controller: CREATOR_DID })],
      appKey: 'r-notes-key',
      name: 'Notes',
      origin: CREATOR_ORIGIN,
      url: CREATOR_URL
    })
    // The disconnect retired the entry, keeping its names.
    await retireParty({
      directory,
      did: CREATOR_DID,
      zcapIds: ['urn:zcap:notes']
    })
    directory.get.mockClear()
    directory.list.mockClear()
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('is named by its retired entry on every surface', async () => {
    const storage = storageDouble(directory)
    const session = { storage } as unknown as Session

    // The consent row.
    const resolution = {
      zcapRequests: [
        {
          referenceId: 'notes',
          allowedAction: ['GET'],
          invocationTarget: {
            type: 'https://w3id.org/byoe#private-collection',
            name: 'notes'
          },
          controller: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
        }
      ],
      spaceUrl: SPACE_URL,
      collections: existingCollectionsFrom([{ id: 'notes' }]),
      appUrl: 'https://other.example/'
    }
    const attributed = await attributeExistingCollections({
      resolution,
      grants: resolveGrants(resolution),
      storage: session.storage
    })
    const consentName = attributed?.[0].target.existing?.creatorName

    // The Storage page's collection listing.
    const listing = await renderHook(() =>
      useStorageListings({ session, collections: [NOTES] })
    )
    const listingName = attributeCollectionsToApps({
      collections: [NOTES],
      creators: listing.result().creators
    }).get('notes')?.name
    await listing.unmount()

    // The collection contents page's "Created by" line.
    const contents = await renderHook(() =>
      useCollectionCreators({ session, generators: [NOTES.generator] })
    )
    const contentsCreator: CollectionCreator | undefined = contents
      .result()
      .get(CREATOR_DID)
    await contents.unmount()

    expect(consentName).toBe('Notes')
    expect(listingName).toBe('Notes')
    // A retired app has no Applications row, so no detail link.
    expect(contentsCreator).toEqual({ name: 'Notes', appUrl: CREATOR_URL })
    // Each surface read the listing, and none GET a derived id.
    expect(directory.get).not.toHaveBeenCalled()
  })

  it('reads nothing when the caller hands its listing in', async () => {
    const storage = storageDouble(directory)
    const session = { storage } as unknown as Session
    const connections = await listedConnections(directory)
    directory.list.mockClear()

    const contents = await renderHook(() =>
      useCollectionCreators({
        session,
        generators: [NOTES.generator],
        directory: { connections, spaceUrl: SPACE_URL }
      })
    )

    expect(contents.result().get(CREATOR_DID)?.name).toBe('Notes')
    expect(storage.connectionsDirectory).not.toHaveBeenCalled()
    expect(directory.list).not.toHaveBeenCalled()
    await contents.unmount()
  })

  it('stays off without remote storage', async () => {
    const storage = { ...storageDouble(directory), hasRemoteStorage: false }
    const session = { storage } as unknown as Session

    const contents = await renderHook(() =>
      useCollectionCreators({ session, generators: [NOTES.generator] })
    )

    expect(contents.result().size).toBe(0)
    expect(directory.list).not.toHaveBeenCalled()
    await contents.unmount()
  })
})
