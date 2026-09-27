/**
 * The three surfaces that name a collection's creator -- the consent row's
 * existing-collection reading, the Storage page's collection listing, and the
 * collection contents page's "Created by" line -- read one resolver
 * (`lookupCollectionCreators`). A creator whose app key a disconnect deleted
 * is named by its recorded Login on all three.
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
import { useCollectionCreators } from './useCollectionCreators'
import { useStorageListings } from './useStorageListings'

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean
}

const CREATOR_DID = 'did:key:zNotesApp'
const CREATOR_ORIGIN = 'https://notes.example'
const CREATOR_URL = 'https://notes.example/app'
const NOTES: StorageCollection = {
  id: 'notes',
  url: 'https://was.example/space/s/notes/',
  generator: CREATOR_DID,
  generatorOrigin: CREATOR_ORIGIN
}

/**
 * A storage double for an account whose `notes` collection was created by an
 * app since disconnected: `app-connections` is empty, and the only record
 * naming the app is the App Connect Login that delegated grants to its DID.
 */
function storageDouble() {
  return {
    hasRemoteStorage: true,
    listAppKeys: vi.fn(async () => ({
      appKeys: [],
      skipped: {
        unknownEpoch: 0,
        noEpochKey: 0,
        undecryptable: 0,
        integrity: 0
      }
    })),
    listHistoryItems: vi.fn(async () => [
      {
        id: 'login-1',
        doc: {
          type: ['Login'],
          created: '2026-07-01T00:00:00Z',
          object: {
            origin: CREATOR_ORIGIN,
            appConnect: { name: 'Notes', appUrl: CREATOR_URL },
            zcaps: [
              {
                id: 'urn:zcap:notes',
                target: NOTES.url,
                allowedActions: ['GET'],
                zcap: { id: 'urn:zcap:notes', controller: CREATOR_DID }
              }
            ]
          }
        }
      }
    ]),
    listCollectionShares: vi.fn(async () => []),
    collectionAttribution: vi.fn(async () => ({
      generator: CREATOR_DID,
      generatorOrigin: CREATOR_ORIGIN
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
  // The history read, then the creators lookup behind it.
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
  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('is named by its recorded Login on every surface', async () => {
    const storage = storageDouble()
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
          controller: 'did:key:z6MkqEPctyQs9MofPZCw2XdeFi2dTMoMqHKhfoWsfitrnprw'
        }
      ],
      space: { serverUrl: 'https://was.example/', spaceId: 's' },
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
      useCollectionCreators({
        storage: session.storage,
        generators: [CREATOR_DID]
      })
    )
    const contentsCreator: CollectionCreator | undefined = contents
      .result()
      .get(CREATOR_DID)
    await contents.unmount()

    expect(consentName).toBe('Notes')
    expect(listingName).toBe('Notes')
    expect(contentsCreator).toEqual({ name: 'Notes', appUrl: CREATOR_URL })
  })
})
