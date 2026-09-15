/**
 * The metadata pass-throughs the storage browser's metadata card rides
 * (`fetchResourceMeta` / `fetchCollectionMeta`): both address the remote store
 * by URL, and both refuse without one.
 *
 * @vitest-environment node
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import { browserLocalSessionPersistence } from '@/session/persistence'
import type { User } from '@/types/auth'
import { BrowserStore } from './browserStore'
import { StorageManager } from './storageManager'
import type { WASRemoteStore } from './wasRemoteStore'

const openStores: BrowserStore[] = []
let userCounter = 0

afterEach(async () => {
  while (openStores.length > 0) {
    await openStores.pop()?.close()
  }
})

/**
 * A StorageManager over a fresh memory-RxDB BrowserStore, optionally with a
 * structural fake remote store attached.
 *
 * @param [remoteStore] {WASRemoteStore}
 * @returns {Promise<StorageManager>}
 */
async function makeStorage(
  remoteStore?: WASRemoteStore
): Promise<StorageManager> {
  userCounter += 1
  const user: User = {
    id: `did:key:z6MkMetaPassThrough${userCounter}`,
    email: 'test@example.com'
  }
  const { localStore } = await BrowserStore.initClient({
    user,
    storage: getRxStorageMemory(),
    ciphers: {}
  })
  await localStore.ensureUserCollections({ user })
  openStores.push(localStore)
  return new StorageManager({
    localStore,
    ...(remoteStore && { remoteStore }),
    ciphers: {},
    descriptors: {},
    persistence: browserLocalSessionPersistence()
  })
}

describe('StorageManager metadata reads', () => {
  it('passes a resource metadata read to the remote store', async () => {
    const fake = {
      fetchResourceMeta: vi.fn(async () => ({
        contentType: 'application/json',
        size: 12
      }))
    }
    const storage = await makeStorage(fake as unknown as WASRemoteStore)

    const meta = await storage.fetchResourceMeta({
      url: 'https://was.example/space/s/notes/n1'
    })

    expect(fake.fetchResourceMeta).toHaveBeenCalledWith({
      url: 'https://was.example/space/s/notes/n1'
    })
    expect(meta).toEqual({ contentType: 'application/json', size: 12 })
  })

  it('passes a collection metadata read through, null included', async () => {
    const fake = { fetchCollectionMeta: vi.fn(async () => null) }
    const storage = await makeStorage(fake as unknown as WASRemoteStore)

    const meta = await storage.fetchCollectionMeta({
      url: 'https://was.example/space/s/notes/'
    })

    expect(fake.fetchCollectionMeta).toHaveBeenCalledTimes(1)
    expect(meta).toBeNull()
  })

  it('refuses a metadata read without a remote store', async () => {
    const storage = await makeStorage()
    await expect(
      storage.fetchResourceMeta({ url: 'https://was.example/space/s/notes/n1' })
    ).rejects.toThrow()
  })
})
