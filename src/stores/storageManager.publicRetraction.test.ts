/**
 * Unit tests for the remote-aware retraction of a credential's world-readable
 * public copy (`StorageManager.retractPublicCopy`, the step
 * `deleteCredential` runs first) and for the union listing the login-time
 * app-key sweep's orphan pass reads (`listPublicCredentials`).
 *
 * The point of the remote probe is that the local `public-credentials` replica
 * cannot prove the ABSENCE of a remote copy: a freshly enrolled browser, or one
 * whose replication sits in retry backoff, has not pulled it yet. So with
 * `consultRemote` (the unattended app-key sweep's setting) the remote
 * collection is consulted, and a probe that cannot be answered refuses the
 * delete rather than deleting on the local replica's say-so. Without the
 * option (the interactive delete), or without a remote store at all, the path
 * is local-only, exactly as before.
 *
 * The manager runs over a real BrowserStore on memory RxDB, with a structural
 * fake `WASRemoteStore` behind the synced-resource surface.
 *
 * @vitest-environment node
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import type { Json } from '@/lib/sync'
import { browserLocalSessionPersistence } from '@/session/persistence'
import type { User } from '@/types/auth'
import { BrowserStore } from './browserStore'
import { PublicCopyRetractionError, StorageManager } from './storageManager'
import type { WASRemoteStore } from './wasRemoteStore'

const openStores: BrowserStore[] = []
let userCounter = 0

afterEach(async () => {
  while (openStores.length > 0) {
    await openStores.pop()?.close()
  }
})

/**
 * A minimal credential body; `public-credentials` stores it in plaintext.
 *
 * @param name {string}
 * @returns {IVerifiableCredential}
 */
function makeCredential(name: string): IVerifiableCredential {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    issuer: 'did:key:z6MkTestIssuer',
    credentialSubject: { name }
  } as unknown as IVerifiableCredential
}

/**
 * A structural fake `WASRemoteStore` over an in-memory `public-credentials`
 * map, recording the calls the retraction makes.
 *
 * @param options {object}
 * @param [options.resources] {Record<string, Json>}   the remote rows, by cid
 * @returns {object}
 */
function makeFakeRemote({
  resources = {}
}: {
  resources?: Record<string, Json>
} = {}) {
  const rows = new Map<string, Json>(Object.entries(resources))
  const fake = {
    spaceId: 's-space',
    listSyncedResources: vi.fn(async () =>
      [...rows.keys()].map(id => ({
        id,
        url: `https://was.example/space/s-space/public-credentials/${id}`
      }))
    ),
    getSyncedResource: vi.fn(async ({ resourceId }: { resourceId: string }) =>
      rows.get(resourceId)
    ),
    deleteSyncedResource: vi.fn(
      async ({ resourceId }: { resourceId: string }) => {
        rows.delete(resourceId)
      }
    )
  }
  return { fake, rows }
}

/**
 * A StorageManager over a fresh memory-RxDB BrowserStore, optionally with the
 * fake remote store attached (a plaintext-only session: no ciphers needed,
 * since `public-credentials` is plaintext).
 *
 * @param [remoteStore] {WASRemoteStore}
 * @returns {Promise<StorageManager>}
 */
async function makeStorage(
  remoteStore?: WASRemoteStore
): Promise<StorageManager> {
  userCounter += 1
  const user: User = {
    id: `did:key:z6MkPublicRetraction${userCounter}`,
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

describe('StorageManager.retractPublicCopy', () => {
  it('deletes a remote public copy the local replica has not pulled', async () => {
    const { fake, rows } = makeFakeRemote({
      resources: { 'cid-1': makeCredential('Alice') as unknown as Json }
    })
    const storage = await makeStorage(fake as unknown as WASRemoteStore)

    await storage.retractPublicCopy({ cid: 'cid-1', consultRemote: true })

    expect(fake.deleteSyncedResource).toHaveBeenCalledWith({
      logicalKey: 'publicCredentials',
      resourceId: 'cid-1'
    })
    expect(rows.has('cid-1')).toBe(false)
  })

  it('refuses the delete when the remote probe throws', async () => {
    const { fake } = makeFakeRemote()
    fake.getSyncedResource.mockImplementationOnce(async () => {
      throw new Error('offline')
    })
    const storage = await makeStorage(fake as unknown as WASRemoteStore)

    await expect(
      storage.retractPublicCopy({ cid: 'cid-1', consultRemote: true })
    ).rejects.toThrow(PublicCopyRetractionError)
    expect(fake.deleteSyncedResource).not.toHaveBeenCalled()
  })

  it('leaves a credential delete refused when the probe throws', async () => {
    const { fake } = makeFakeRemote()
    fake.getSyncedResource.mockImplementation(async () => {
      throw new Error('offline')
    })
    const storage = await makeStorage(fake as unknown as WASRemoteStore)
    const user: User = { id: 'did:key:z6MkTestUser', email: 'x@example.com' }
    const credential = makeCredential('Bob')
    await storage.addCredential({ credential, user })
    const [{ cid }] = await storage.listCredentials()

    await expect(
      storage.deleteCredential({ cid, consultRemote: true })
    ).rejects.toThrow(PublicCopyRetractionError)
    expect((await storage.listCredentials()).map(row => row.cid)).toEqual([cid])
  })

  it('decides on the local replica alone without consultRemote', async () => {
    const { fake } = makeFakeRemote({
      resources: { 'cid-1': makeCredential('Alice') as unknown as Json }
    })
    fake.getSyncedResource.mockImplementation(async () => {
      throw new Error('offline')
    })
    const storage = await makeStorage(fake as unknown as WASRemoteStore)
    const credential = makeCredential('Dave')
    await storage.addCredential({
      credential,
      user: { id: 'did:key:z6MkTestUser', email: 'x@example.com' }
    })
    const [{ cid }] = await storage.listCredentials()

    await storage.deleteCredential({ cid })

    expect(await storage.listCredentials()).toEqual([])
    expect(fake.getSyncedResource).not.toHaveBeenCalled()
    expect(fake.deleteSyncedResource).not.toHaveBeenCalled()
  })

  it('stays local-only with no remote store configured', async () => {
    const storage = await makeStorage()
    const credential = makeCredential('Carol')
    await storage.addCredential({
      credential,
      user: { id: 'did:key:z6MkTestUser', email: 'x@example.com' }
    })
    const [{ cid }] = await storage.listCredentials()

    await storage.deleteCredential({ cid })

    expect(await storage.listCredentials()).toEqual([])
  })
})

describe('StorageManager.listPublicCredentials', () => {
  it('unions the local rows with the remote collection, skipping known cids', async () => {
    const remoteOnly = makeCredential('Remote')
    const { fake } = makeFakeRemote({
      resources: {
        'cid-remote': remoteOnly as unknown as Json,
        'cid-private': makeCredential('HasPrivateRow') as unknown as Json
      }
    })
    const storage = await makeStorage(fake as unknown as WASRemoteStore)

    const listed = await storage.listPublicCredentials({
      skipCids: new Set(['cid-private'])
    })

    expect(listed.map(({ cid }) => cid)).toEqual(['cid-remote'])
    // The skipped cid's body is never fetched: its private row's delete
    // retracts it.
    expect(fake.getSyncedResource).toHaveBeenCalledTimes(1)
    expect(fake.getSyncedResource).toHaveBeenCalledWith({
      logicalKey: 'publicCredentials',
      resourceId: 'cid-remote'
    })
  })

  it('throws when the remote listing fails', async () => {
    const { fake } = makeFakeRemote()
    fake.listSyncedResources.mockImplementationOnce(async () => {
      throw new Error('collection unreachable')
    })
    const storage = await makeStorage(fake as unknown as WASRemoteStore)

    await expect(storage.listPublicCredentials()).rejects.toThrow(
      'collection unreachable'
    )
  })
})
