/**
 * Unit tests for the local-first storage layer: BrowserStore as the always-on
 * active replica (RxDB memory storage) and the StorageManager facade routing
 * credential / public-link / history operations to it unconditionally.
 *
 * @vitest-environment node
 */
import { afterEach, describe, expect, it } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import type { User } from '@/types/auth'
import { cidFrom } from '@/lib/cidFrom'
import type { Json } from '@/lib/sync'
import { BrowserStore } from './browserStore'
import type { DocCipher } from './edvDocCipher'
import { StorageManager } from './storageManager'
import type { WASRemoteStore } from './wasRemoteStore'

/**
 * A minimal well-formed VC body; the storage layer treats it as opaque JSON.
 */
function makeCredential(name: string): IVerifiableCredential {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    issuer: 'did:key:z6MkTestIssuer',
    credentialSubject: { name }
  } as unknown as IVerifiableCredential
}

let userCounter = 0
const openStores: BrowserStore[] = []

let fakeCipherCounter = 0

/**
 * A reversible fake DocCipher: the "envelope" carries the JSON plaintext as
 * its `jwe.ciphertext`, and every encrypt mints a fresh id -- mimicking the
 * real codec's nondeterministic JWE (same plaintext, new id/ciphertext each
 * time), which is what the dedupe paths must handle.
 */
function makeFakeCipher(): DocCipher {
  return {
    async encrypt({ data }: { data: Json }) {
      fakeCipherCounter += 1
      const id = `z6FakeEnvelope${fakeCipherCounter}`
      return {
        id,
        envelope: {
          id,
          sequence: 0,
          jwe: { ciphertext: JSON.stringify(data) }
        } as Json
      }
    },
    async decrypt({ envelope }: { envelope: Json }) {
      const { ciphertext } = (envelope as { jwe: { ciphertext: string } }).jwe
      return JSON.parse(ciphertext) as Json
    }
  }
}

/**
 * Opens a fresh BrowserStore on memory storage for a unique synthetic user,
 * optionally with per-collection document ciphers.
 */
async function initLocalStore({
  ciphers
}: { ciphers?: Record<string, DocCipher> } = {}): Promise<{
  localStore: BrowserStore
  user: User
}> {
  userCounter += 1
  const user: User = {
    id: `did:key:z6MkTestUser${userCounter}`,
    email: 'test@example.com'
  }
  const { localStore } = await BrowserStore.initClient({
    user,
    storage: getRxStorageMemory(),
    ciphers
  })
  await localStore.ensureUserCollections({ user })
  openStores.push(localStore)
  return { localStore, user }
}

/**
 * The standard cipher set for an encrypted-store test: both encrypted
 * collections get the fake cipher.
 */
function encryptedCiphers(): Record<string, DocCipher> {
  return {
    privateCredentials: makeFakeCipher(),
    walletActivity: makeFakeCipher()
  }
}

afterEach(async () => {
  for (const store of openStores) {
    await store.wipeStorage()
  }
  openStores.length = 0
})

describe('BrowserStore (local active replica)', () => {
  it('round-trips a credential through the private-credentials collection', async () => {
    const { localStore } = await initLocalStore()
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })

    await localStore.addCredential({ cid, credential })

    const listed = await localStore.listCredentials()
    expect(listed).toHaveLength(1)
    expect(listed[0].cid).toBe(cid)
    expect(listed[0].vc).toEqual(credential)

    const loaded = await localStore.loadCredential({ cid })
    expect(loaded).toEqual(credential)
  })

  it('is idempotent on duplicate adds (insert-if-not-exists)', async () => {
    const { localStore } = await initLocalStore()
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })

    await localStore.addCredential({ cid, credential })
    await localStore.addCredential({ cid, credential })

    expect(await localStore.listCredentials()).toHaveLength(1)
  })

  it('deletes a credential and reports a miss as undefined', async () => {
    const { localStore } = await initLocalStore()
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    await localStore.addCredential({ cid, credential })

    await localStore.deleteCredential({ cid })

    expect(await localStore.listCredentials()).toHaveLength(0)
    expect(await localStore.loadCredential({ cid })).toBeUndefined()
    // Deleting an already-absent credential is a no-op, not an error.
    await localStore.deleteCredential({ cid })
  })

  it('stamps local rows with the synced-doc envelope (updatedAt, placeholder version)', async () => {
    const { localStore } = await initLocalStore()
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    await localStore.addCredential({ cid, credential })

    const doc = await localStore
      .rxCollection('privateCredentials')
      .findOne(cid)
      .exec()
    expect(doc).not.toBeNull()
    const row = doc!.toMutableJSON()
    expect(row.version).toBe(0)
    expect(Date.parse(row.updatedAt)).not.toBeNaN()
  })

  it('supports the share / unshare / re-share cycle on public-credentials', async () => {
    const { localStore } = await initLocalStore()
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })

    expect(await localStore.hasPublicCredential({ cid })).toBe(false)

    await localStore.addPublicCredential({ cid, credential })
    expect(await localStore.hasPublicCredential({ cid })).toBe(true)

    await localStore.removePublicCredential({ cid })
    expect(await localStore.hasPublicCredential({ cid })).toBe(false)

    // Re-share revives the soft-deleted row (insert over a tombstone).
    await localStore.addPublicCredential({ cid, credential })
    expect(await localStore.hasPublicCredential({ cid })).toBe(true)
  })

  it('lists history items oldest first', async () => {
    const { localStore } = await initLocalStore()
    await localStore.addHistoryItem({
      resourceId: 'first',
      activity: { summary: 'one' }
    })
    await localStore.addHistoryItem({
      resourceId: 'second',
      activity: { summary: 'two' }
    })

    const items = await localStore.listHistoryItems()
    expect(items.map(({ doc }) => doc.summary)).toEqual(['one', 'two'])
    expect(items.map(({ id }) => id)).toEqual(['first', 'second'])
  })

  it('throws a clear error when collections are not initialized', async () => {
    const { localStore } = await BrowserStore.initClient({
      user: { id: 'did:key:z6MkUninitialized' },
      storage: getRxStorageMemory()
    })
    expect(() => localStore.rxCollection('privateCredentials')).toThrow(
      /not initialized/
    )
  })
})

describe('BrowserStore (encrypted collections)', () => {
  it('stores credentials as envelopes and round-trips them through decrypt', async () => {
    const { localStore } = await initLocalStore({ ciphers: encryptedCiphers() })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })

    await localStore.addCredential({ cid, credential })

    // The stored row is an envelope keyed by the cipher-minted id, not the cid.
    const rows = await localStore
      .rxCollection('privateCredentials')
      .find()
      .exec()
    expect(rows).toHaveLength(1)
    const row = rows[0].toMutableJSON()
    expect(row.id).not.toBe(cid)
    expect((row.data as { jwe?: unknown }).jwe).toBeDefined()

    // The read paths decrypt and key by content cid.
    const listed = await localStore.listCredentials()
    expect(listed).toEqual([{ cid, vc: credential }])
    expect(await localStore.loadCredential({ cid })).toEqual(credential)
  })

  it('dedupes re-adds by content cid despite nondeterministic ids', async () => {
    const { localStore } = await initLocalStore({ ciphers: encryptedCiphers() })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })

    await localStore.addCredential({ cid, credential })
    await localStore.addCredential({ cid, credential })

    const rows = await localStore
      .rxCollection('privateCredentials')
      .find()
      .exec()
    expect(rows).toHaveLength(1)
    expect(await localStore.listCredentials()).toHaveLength(1)
  })

  it('collapses duplicate envelope rows on list and deletes them all by cid', async () => {
    const ciphers = encryptedCiphers()
    const { localStore } = await initLocalStore({ ciphers })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })

    // Seed two rows carrying the same credential under different ids -- the
    // shape a legacy random-id envelope replicated from remote takes next to
    // a re-keyed local copy.
    const collection = localStore.rxCollection('privateCredentials')
    for (let copy = 0; copy < 2; copy++) {
      const { id, envelope } = await ciphers.privateCredentials.encrypt({
        data: credential as unknown as Json
      })
      await collection.insert({
        id,
        updatedAt: new Date().toISOString(),
        version: 0,
        data: envelope
      })
    }

    expect(await collection.find().exec()).toHaveLength(2)
    expect(await localStore.listCredentials()).toHaveLength(1)

    await localStore.deleteCredential({ cid })
    expect(await collection.find().exec()).toHaveLength(0)
    expect(await localStore.listCredentials()).toHaveLength(0)
  })

  it('stores history as envelopes, preserving activity ids and order', async () => {
    const { localStore } = await initLocalStore({ ciphers: encryptedCiphers() })
    await localStore.addHistoryItem({
      resourceId: 'first',
      activity: { id: 'first', summary: 'one' }
    })
    await localStore.addHistoryItem({
      resourceId: 'second',
      activity: { id: 'second', summary: 'two' }
    })

    const rows = await localStore.rxCollection('walletActivity').find().exec()
    for (const row of rows) {
      expect((row.toMutableJSON().data as { jwe?: unknown }).jwe).toBeDefined()
    }

    const items = await localStore.listHistoryItems()
    expect(items.map(({ doc }) => doc.summary)).toEqual(['one', 'two'])
    expect(items.map(({ id }) => id)).toEqual(['first', 'second'])
  })

  it('reads legacy plaintext rows through the tolerant read paths', async () => {
    const { localStore } = await initLocalStore({ ciphers: encryptedCiphers() })
    // A plaintext activity row pulled from a pre-encryption-marker remote
    // collection: server revision >= 1, plaintext data.
    await localStore.rxCollection('walletActivity').insert({
      id: 'legacy-activity',
      updatedAt: new Date().toISOString(),
      version: 3,
      data: { id: 'legacy-activity', summary: 'legacy' } as Json
    })

    const items = await localStore.listHistoryItems()
    expect(items).toEqual([
      {
        id: 'legacy-activity',
        doc: { id: 'legacy-activity', summary: 'legacy' }
      }
    ])
  })

  describe('migrateLocalPlaintextDocs', () => {
    it('re-keys never-synced plaintext rows into envelopes, preserving updatedAt', async () => {
      const { localStore } = await initLocalStore({
        ciphers: encryptedCiphers()
      })
      const credential = makeCredential('Alice')
      const cid = await cidFrom({ doc: credential })
      const originalUpdatedAt = '2026-01-02T03:04:05.000Z'
      await localStore.rxCollection('privateCredentials').insert({
        id: cid,
        updatedAt: originalUpdatedAt,
        version: 0,
        data: credential as unknown as Json
      })

      await localStore.migrateLocalPlaintextDocs()

      const rows = await localStore
        .rxCollection('privateCredentials')
        .find()
        .exec()
      expect(rows).toHaveLength(1)
      const row = rows[0].toMutableJSON()
      expect(row.id).not.toBe(cid)
      expect(row.updatedAt).toBe(originalUpdatedAt)
      expect((row.data as { jwe?: unknown }).jwe).toBeDefined()

      // The credential survives the re-key intact.
      expect(await localStore.loadCredential({ cid })).toEqual(credential)
    })

    it('leaves already-synced rows (server revision) untouched', async () => {
      const { localStore } = await initLocalStore({
        ciphers: encryptedCiphers()
      })
      await localStore.rxCollection('walletActivity').insert({
        id: 'legacy-activity',
        updatedAt: new Date().toISOString(),
        version: 2,
        data: { id: 'legacy-activity', summary: 'legacy' } as Json
      })

      await localStore.migrateLocalPlaintextDocs()

      const rows = await localStore.rxCollection('walletActivity').find().exec()
      expect(rows).toHaveLength(1)
      const row = rows[0].toMutableJSON()
      expect(row.id).toBe('legacy-activity')
      expect((row.data as { jwe?: unknown }).jwe).toBeUndefined()
    })

    it('is a no-op on an already-migrated store', async () => {
      const { localStore } = await initLocalStore({
        ciphers: encryptedCiphers()
      })
      const credential = makeCredential('Alice')
      const cid = await cidFrom({ doc: credential })
      await localStore.addCredential({ cid, credential })

      await localStore.migrateLocalPlaintextDocs()
      await localStore.migrateLocalPlaintextDocs()

      const rows = await localStore
        .rxCollection('privateCredentials')
        .find()
        .exec()
      expect(rows).toHaveLength(1)
      expect(await localStore.listCredentials()).toHaveLength(1)
    })
  })
})

describe('StorageManager (local-first facade)', () => {
  /**
   * Builds a StorageManager over a fresh local store, optionally with a fake
   * remote store (sharing only needs `publicCredentialUrl`).
   */
  async function initManager({ withRemote = false } = {}) {
    const { localStore, user } = await initLocalStore()
    const remoteStore = withRemote
      ? ({
          publicCredentialUrl: (cid: string) =>
            `https://was.example/space/s/public-credentials/${cid}`
        } as unknown as WASRemoteStore)
      : undefined
    return { storage: new StorageManager({ localStore, remoteStore }), user }
  }

  it('adds and lists credentials locally, keyed by content cid', async () => {
    const { storage } = await initManager()
    const credential = makeCredential('Alice')

    await storage.addCredential({ credential })

    const listed = await storage.listCredentials()
    expect(listed).toHaveLength(1)
    expect(listed[0].cid).toBe(await cidFrom({ doc: credential }))
    expect(listed[0].vc).toEqual(credential)
  })

  it('writes history locally with no remote store (guest / offline path)', async () => {
    const { storage, user } = await initManager()

    await storage.addHistoryNewAccount({ user })
    await storage.addHistorySpaceCreated({ user })
    await storage.addHistoryCredentialCreated({ cid: 'abc', user })

    const items = await storage.listHistoryItems()
    expect(items).toHaveLength(3)
    expect(items[0].doc.summary).toMatch(/Sign Up/)
    // The no-remote branch records the local collections, not a remote Space.
    expect(items[1].doc.summary).toMatch(/local storage/)
    expect(items[2].doc.summary).toBe('Credential created: abc')
  })

  it('disables sharing without a remote replica', async () => {
    const { storage } = await initManager()
    expect(storage.canShare).toBe(false)
    expect(storage.publicLinkUrl({ cid: 'abc' })).toBeUndefined()
    await expect(
      storage.createPublicLink({ credential: makeCredential('Alice') })
    ).rejects.toThrow(/remote storage/)
  })

  it('shares via the local public-credentials collection when remote is configured', async () => {
    const { storage } = await initManager({ withRemote: true })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })

    expect(storage.canShare).toBe(true)
    const url = await storage.createPublicLink({ credential })
    expect(url).toBe(`https://was.example/space/s/public-credentials/${cid}`)
    expect(await storage.isShared({ cid })).toBe(true)

    await storage.removePublicLink({ cid })
    expect(await storage.isShared({ cid })).toBe(false)
  })

  it('deletes a credential locally', async () => {
    const { storage } = await initManager()
    const credential = makeCredential('Alice')
    await storage.addCredential({ credential })
    const cid = await cidFrom({ doc: credential })

    await storage.deleteCredential({ cid })

    expect(await storage.loadCredential({ cid })).toBeUndefined()
    expect(await storage.listCredentials()).toHaveLength(0)
  })
})
