/**
 * Unit tests for the retraction of a credential's world-readable public copy,
 * the step `StorageManager.deleteCredential` runs first. The decision is the
 * local replica's: a configured remote store is not consulted, so an offline
 * delete of a credential with no local public copy keeps working.
 *
 * The manager runs over a real BrowserStore on memory RxDB, with a structural
 * fake `PWSRemoteStore` behind the synced-resource surface.
 *
 * @vitest-environment node
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import { browserLocalSessionPersistence } from '@/session/persistence'
import type { User } from '@/types/auth'
import { BrowserStore } from './browserStore'
import { StorageManager } from './storageManager'
import { generateVaultKeys } from '@/stores/testing/vaultKeys'
import type { PWSRemoteStore } from './pwsRemoteStore'

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
 * A structural fake `PWSRemoteStore` recording any synced-resource call the
 * retraction makes to it. None is expected.
 *
 * @returns {object}
 */
function makeFakeRemote() {
  return {
    spaceId: 's-space',
    getSyncedResource: vi.fn(),
    deleteSyncedResource: vi.fn()
  }
}

/**
 * A StorageManager over a fresh memory-RxDB BrowserStore, optionally with the
 * fake remote store attached (a plaintext-only session: no ciphers needed,
 * since `public-credentials` is plaintext).
 *
 * @param [remoteStore] {PWSRemoteStore}
 * @returns {Promise<StorageManager>}
 */
async function makeStorage(
  remoteStore?: PWSRemoteStore
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
    vaultKeys: await generateVaultKeys(),
    descriptors: {},
    persistence: browserLocalSessionPersistence()
  })
}

describe('StorageManager.deleteCredential public-copy retraction', () => {
  it('decides on the local replica alone with a remote configured', async () => {
    const fake = makeFakeRemote()
    const storage = await makeStorage(fake as unknown as PWSRemoteStore)
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
