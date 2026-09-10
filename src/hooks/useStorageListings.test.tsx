import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { SHAREABLE_COLLECTIONS } from '@/session/shares'
import type { StorageCollection } from '@/lib/storage'
import type { Session } from '@/types/auth'
import { useStorageListings } from './useStorageListings'

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean
}

/**
 * A storage double recording every read the two listings make. Both the
 * shares listing and the connected-apps listing join over the activity
 * history, and the hook is meant to read it once for both.
 */
function storageDouble() {
  return {
    hasRemoteStorage: true,
    listHistoryItems: vi.fn(async () => []),
    listCollectionShares: vi.fn(async () => []),
    listAppKeys: vi.fn(async () => ({ appKeys: [] }))
  }
}

/**
 * Renders a probe component around the hook, without a testing library.
 */
async function mount({
  session,
  collections
}: {
  session: Session
  collections: StorageCollection[]
}): Promise<{ unmount: () => Promise<void> }> {
  const container = document.createElement('div')
  const root: Root = createRoot(container)
  function Probe() {
    useStorageListings({ session, collections })
    return null
  }
  await act(async () => {
    root.render(<Probe />)
  })
  // The listings run off the history read's settled state, one render later.
  await act(async () => {
    await Promise.resolve()
  })
  return {
    unmount: () =>
      act(async () => {
        root.unmount()
      })
  }
}

describe('useStorageListings', () => {
  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('reads the activity history once for both listings', async () => {
    const storage = storageDouble()
    const session = { storage } as unknown as Session
    const probe = await mount({
      session,
      collections: [
        {
          id: 'app-notes',
          url: 'https://was.example/spaces/s/collections/app-notes',
          generator: 'did:key:z6MkApp'
        } as StorageCollection
      ]
    })
    expect(storage.listHistoryItems).toHaveBeenCalledTimes(1)
    // Both listings ran off that one read.
    expect(storage.listCollectionShares).toHaveBeenCalledTimes(
      SHAREABLE_COLLECTIONS.length
    )
    expect(storage.listAppKeys).toHaveBeenCalledTimes(1)
    await probe.unmount()
  })

  it('leaves the apps listing off when no collection names a generator', async () => {
    const storage = storageDouble()
    const session = { storage } as unknown as Session
    const probe = await mount({
      session,
      collections: [
        {
          id: 'private-credentials',
          url: 'https://was.example/spaces/s/collections/private-credentials'
        }
      ]
    })
    expect(storage.listHistoryItems).toHaveBeenCalledTimes(1)
    expect(storage.listCollectionShares).toHaveBeenCalledTimes(
      SHAREABLE_COLLECTIONS.length
    )
    expect(storage.listAppKeys).not.toHaveBeenCalled()
    await probe.unmount()
  })
})
