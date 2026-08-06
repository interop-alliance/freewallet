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
import { cidFrom } from '@interop/was-client/sync'
import type { Json } from '@/lib/sync'
import { BrowserStore } from './browserStore'
import { UnknownEpochError, type DocCipher } from '@interop/was-client/edv'
import { PublicCopyRetractionError, StorageManager } from './storageManager'
import { RemoteDirectStore } from './remoteDirectStore'
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
 * A fake DocCipher whose every encrypt surfaces a fixed `epoch` id (mimicking a
 * multi-recipient cipher writing under the descriptor's `currentEpoch`), so a test
 * can assert the remote-direct write stamped it as `WAS-Key-Epoch`.
 */
function makeFakeEpochCipher(epoch: string): DocCipher {
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
        } as Json,
        epoch
      }
    },
    async decrypt({ envelope }: { envelope: Json }) {
      const { ciphertext } = (envelope as { jwe: { ciphertext: string } }).jwe
      return JSON.parse(ciphertext) as Json
    }
  }
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

  it('is idempotent across a batch with no prior list, and reports inserted-ness', async () => {
    const { localStore } = await initLocalStore({ ciphers: encryptedCiphers() })
    // A batch of three distinct credentials with two repeats interleaved,
    // stored with no intervening list call -- the cid index (not a per-insert
    // decrypt-scan) must still no-op every repeat.
    const [alice, bob, carol] = ['Alice', 'Bob', 'Carol'].map(makeCredential)
    const order = [alice, bob, alice, carol, bob, carol]
    const inserted: boolean[] = []
    for (const credential of order) {
      const cid = await cidFrom({ doc: credential })
      inserted.push(await localStore.addCredential({ cid, credential }))
    }

    // Only the first sighting of each cid inserts.
    expect(inserted).toEqual([true, true, false, true, false, false])
    expect(
      await localStore.rxCollection('privateCredentials').find().exec()
    ).toHaveLength(3)
    expect(await localStore.listCredentials()).toHaveLength(3)
  })

  it('re-inserts after a delete (cid index is maintained on removal)', async () => {
    const { localStore } = await initLocalStore({ ciphers: encryptedCiphers() })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })

    expect(await localStore.addCredential({ cid, credential })).toBe(true)
    await localStore.deleteCredential({ cid })
    // After the delete the index no longer holds the cid, so a re-add is a
    // genuine insert, not a false dedupe.
    expect(await localStore.addCredential({ cid, credential })).toBe(true)
    expect(await localStore.listCredentials()).toEqual([
      { cid, vc: credential }
    ])
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
    // A plaintext activity row pulled from a pre-encryption-descriptor remote
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

  /**
   * Inserts a poisoned envelope row directly: it looks like an EDV envelope
   * (its `jwe` is an object, so `isEncryptedEnvelope` accepts it) but its
   * ciphertext is not valid JSON, so the fake cipher's `decrypt` throws --
   * standing in for a row corrupted, replicated verbatim from another
   * identity, or written under a mismatched KAK.
   */
  async function insertUndecryptableRow(
    localStore: BrowserStore,
    logicalKey: string,
    rowId: string
  ) {
    await localStore.rxCollection(logicalKey).insert({
      id: rowId,
      updatedAt: new Date().toISOString(),
      version: 0,
      data: { id: rowId, sequence: 0, jwe: { ciphertext: 'not-json{' } } as Json
    })
  }

  describe('undecryptable rows (per-row fail-soft)', () => {
    it('skips a poisoned credential row, still listing the good ones', async () => {
      const { localStore } = await initLocalStore({
        ciphers: encryptedCiphers()
      })
      const credential = makeCredential('Alice')
      const cid = await cidFrom({ doc: credential })
      await localStore.addCredential({ cid, credential })
      await insertUndecryptableRow(localStore, 'privateCredentials', 'z6Poison')

      const listed = await localStore.listCredentials()

      expect(listed).toEqual([{ cid, vc: credential }])
      expect(localStore.undecryptableCredentials).toBe(1)
      // The good credential still loads and the poisoned row does not throw.
      expect(await localStore.loadCredential({ cid })).toEqual(credential)
    })

    it('still deletes a good credential despite a poisoned sibling row', async () => {
      const { localStore } = await initLocalStore({
        ciphers: encryptedCiphers()
      })
      const credential = makeCredential('Alice')
      const cid = await cidFrom({ doc: credential })
      await localStore.addCredential({ cid, credential })
      await insertUndecryptableRow(localStore, 'privateCredentials', 'z6Poison')

      await localStore.deleteCredential({ cid })

      expect(await localStore.listCredentials()).toHaveLength(0)
      // The poisoned row survives (it carries no recoverable cid).
      expect(
        await localStore.rxCollection('privateCredentials').find().exec()
      ).toHaveLength(1)
    })

    it('purges undecryptable credential rows on request', async () => {
      const { localStore } = await initLocalStore({
        ciphers: encryptedCiphers()
      })
      const credential = makeCredential('Alice')
      const cid = await cidFrom({ doc: credential })
      await localStore.addCredential({ cid, credential })
      await insertUndecryptableRow(localStore, 'privateCredentials', 'z6Poison')
      await localStore.listCredentials()
      expect(localStore.undecryptableCredentials).toBe(1)

      const removed = await localStore.purgeUndecryptableCredentials()

      expect(removed).toBe(1)
      expect(localStore.undecryptableCredentials).toBe(0)
      // The good credential is untouched; only the poisoned row is gone.
      expect(await localStore.listCredentials()).toEqual([
        { cid, vc: credential }
      ])
      expect(
        await localStore.rxCollection('privateCredentials').find().exec()
      ).toHaveLength(1)
    })

    it('removes a credential by row id without decrypting it', async () => {
      const { localStore } = await initLocalStore({
        ciphers: encryptedCiphers()
      })
      await insertUndecryptableRow(localStore, 'privateCredentials', 'z6Poison')

      await localStore.deleteCredentialByRowId({ rowId: 'z6Poison' })

      expect(
        await localStore.rxCollection('privateCredentials').find().exec()
      ).toHaveLength(0)
    })

    it('skips a poisoned history row, still listing the good ones', async () => {
      const { localStore } = await initLocalStore({
        ciphers: encryptedCiphers()
      })
      await localStore.addHistoryItem({
        resourceId: 'first',
        activity: { id: 'first', summary: 'one' }
      })
      await insertUndecryptableRow(localStore, 'walletActivity', 'z6Poison')

      const items = await localStore.listHistoryItems()

      expect(items.map(({ doc }) => doc.summary)).toEqual(['one'])
      expect(localStore.undecryptableHistory).toBe(1)
    })
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

/**
 * A fake cipher that stamps a fixed `epoch` on every encrypt result, mimicking
 * a multi-recipient cipher writing under a current key epoch.
 */
function makeEpochCipher(epoch: string): DocCipher {
  return {
    async encrypt({ data }: { data: Json }) {
      fakeCipherCounter += 1
      const id = `z6EpochEnvelope${fakeCipherCounter}`
      return {
        id,
        envelope: {
          id,
          sequence: 0,
          jwe: { ciphertext: JSON.stringify(data) }
        } as Json,
        epoch
      }
    },
    async decrypt({ envelope }: { envelope: Json }) {
      const { ciphertext } = (envelope as { jwe: { ciphertext: string } }).jwe
      return JSON.parse(ciphertext) as Json
    }
  }
}

/**
 * A fake cipher whose `decrypt` always throws `UnknownEpochError` -- standing
 * in for a row stamped with a key epoch this cipher's cached descriptor has never
 * seen (a rekey emits no change-feed entry). `encrypt` still produces a normal
 * fake envelope, so a caller can seed rows with it.
 */
function makeUnknownEpochCipher(): DocCipher {
  return {
    async encrypt({ data }: { data: Json }) {
      fakeCipherCounter += 1
      const id = `z6UnknownEnvelope${fakeCipherCounter}`
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
      const kids =
        (
          envelope as { jwe?: { recipients?: { header?: { kid?: string } }[] } }
        )?.jwe?.recipients?.map(recipient => recipient.header?.kid ?? '') ?? []
      throw new UnknownEpochError({ collectionId: 'private-credentials', kids })
    }
  }
}

describe('BrowserStore (key epochs)', () => {
  it('stores the epoch the cipher stamped on the row', async () => {
    const { localStore } = await initLocalStore({
      ciphers: {
        privateCredentials: makeEpochCipher('did:key:z6EpochOne'),
        walletActivity: makeEpochCipher('did:key:z6EpochOne')
      }
    })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })

    await localStore.addCredential({ cid, credential })

    const rows = await localStore
      .rxCollection('privateCredentials')
      .find()
      .exec()
    expect(rows).toHaveLength(1)
    expect(rows[0].toMutableJSON().epoch).toBe('did:key:z6EpochOne')

    // A history write carries its epoch too.
    await localStore.addHistoryItem({
      resourceId: 'act-1',
      activity: { id: 'act-1', summary: 'one' }
    })
    const activityRows = await localStore
      .rxCollection('walletActivity')
      .find()
      .exec()
    expect(activityRows[0].toMutableJSON().epoch).toBe('did:key:z6EpochOne')
  })

  it('counts an unknown-epoch row separately from undecryptable and skips it', async () => {
    const { localStore } = await initLocalStore({
      ciphers: {
        privateCredentials: makeUnknownEpochCipher(),
        walletActivity: makeUnknownEpochCipher()
      }
    })
    const credential = makeCredential('Alice')
    await localStore.rxCollection('privateCredentials').insert({
      id: 'z6Unknown',
      updatedAt: new Date().toISOString(),
      version: 0,
      data: {
        id: 'z6Unknown',
        sequence: 0,
        jwe: { ciphertext: JSON.stringify(credential) }
      } as Json
    })

    const listed = await localStore.listCredentials()

    // The row is skipped, counted as unknown-epoch (fresh data behind a stale
    // descriptor), and NOT as undecryptable garbage.
    expect(listed).toHaveLength(0)
    expect(localStore.unknownEpochCredentials).toBe(1)
    expect(localStore.undecryptableCredentials).toBe(0)
    // It is not purged either (purge only clears true undecryptables).
    expect(await localStore.purgeUndecryptableCredentials()).toBe(0)
    expect(
      await localStore.rxCollection('privateCredentials').find().exec()
    ).toHaveLength(1)
  })

  it('setCiphers swaps the injected cipher for a subsequent read', async () => {
    // Start with a cipher that cannot route the row's epoch.
    const { localStore } = await initLocalStore({
      ciphers: {
        privateCredentials: makeUnknownEpochCipher(),
        walletActivity: makeUnknownEpochCipher()
      }
    })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    await localStore.rxCollection('privateCredentials').insert({
      id: 'z6Swap',
      updatedAt: new Date().toISOString(),
      version: 0,
      data: {
        id: 'z6Swap',
        sequence: 0,
        jwe: { ciphertext: JSON.stringify(credential) }
      } as Json
    })

    // Under the stale cipher the row is invisible (unknown epoch).
    expect(await localStore.listCredentials()).toHaveLength(0)
    expect(localStore.unknownEpochCredentials).toBe(1)

    // Swap in a cipher that decrypts it; the same row now reads.
    localStore.setCiphers({
      privateCredentials: makeFakeCipher(),
      walletActivity: makeFakeCipher()
    })
    const listed = await localStore.listCredentials()
    expect(listed).toEqual([{ cid, vc: credential }])
    expect(localStore.unknownEpochCredentials).toBe(0)
  })
})

describe('BrowserStore (contacts encryption)', () => {
  it('stamps the key epoch on contact and revision writes (add + update)', async () => {
    const { localStore } = await initLocalStore({
      ciphers: {
        contacts: makeEpochCipher('did:key:z6EpochOne'),
        contactsHistory: makeEpochCipher('did:key:z6EpochOne')
      }
    })

    const stored = await localStore.addContact({
      contact: { givenName: 'Bob' } as never,
      deviceId: 'device-1'
    })
    const contactRow = (await localStore
      .rxCollection('contacts')
      .findOne(stored.id)
      .exec())!.toMutableJSON()
    // Previously the contact writers dropped the epoch; it is now stamped.
    expect(contactRow.epoch).toBe('did:key:z6EpochOne')
    expect((contactRow.data as { jwe?: unknown }).jwe).toBeDefined()

    // An in-place edit re-stamps the epoch (the row keeps its stable id).
    await localStore.updateContact({
      id: stored.id,
      contact: { givenName: 'Bobby' } as never,
      deviceId: 'device-1'
    })
    const updatedRow = (await localStore
      .rxCollection('contacts')
      .findOne(stored.id)
      .exec())!.toMutableJSON()
    expect(updatedRow.epoch).toBe('did:key:z6EpochOne')
    expect((await localStore.loadContact({ id: stored.id }))!.contact).toEqual({
      givenName: 'Bobby'
    })

    await localStore.addContactRevision({
      revision: {
        contactId: stored.contactId,
        action: 'create',
        snapshot: { givenName: 'Bob' }
      } as never
    })
    const revisionRow = (
      await localStore.rxCollection('contactsHistory').find().exec()
    )[0].toMutableJSON()
    expect(revisionRow.epoch).toBe('did:key:z6EpochOne')
    const revisions = await localStore.listContactRevisions({
      contactId: stored.contactId
    })
    expect(revisions).toHaveLength(1)
  })

  it('tolerates an unknown-epoch contact row rather than throwing', async () => {
    const { localStore } = await initLocalStore({
      ciphers: {
        contacts: makeUnknownEpochCipher(),
        contactsHistory: makeUnknownEpochCipher()
      }
    })
    await localStore.rxCollection('contacts').insert({
      id: 'z6UnknownContact',
      updatedAt: new Date().toISOString(),
      version: 0,
      data: {
        id: 'z6UnknownContact',
        sequence: 0,
        jwe: { ciphertext: JSON.stringify({ contactId: 'c1' }) }
      } as Json
    })

    // The unified read skeleton skips the unroutable row (it is not garbage),
    // so the list read succeeds with the row simply omitted.
    expect(await localStore.listContacts()).toHaveLength(0)
  })
})

describe('migratePublicCredentialCids', () => {
  it('re-keys a row stored under the pre-fix cid, preserving updatedAt', async () => {
    const { localStore } = await initLocalStore()
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    const wrongCid = 'z6PreFixWrongCid'
    const originalUpdatedAt = '2026-01-02T03:04:05.000Z'
    // Seed a public row under a wrong id, as the pre-fix formula would have.
    await localStore.rxCollection('publicCredentials').insert({
      id: wrongCid,
      updatedAt: originalUpdatedAt,
      version: 0,
      data: credential as unknown as Json
    })

    await localStore.migratePublicCredentialCids()

    // The row now lives under the correct cid; the old id is soft-deleted.
    expect(await localStore.hasPublicCredential({ cid })).toBe(true)
    expect(await localStore.hasPublicCredential({ cid: wrongCid })).toBe(false)
    const doc = await localStore
      .rxCollection('publicCredentials')
      .findOne(cid)
      .exec()
    expect(doc).not.toBeNull()
    const row = doc!.toMutableJSON()
    expect(row.updatedAt).toBe(originalUpdatedAt)
    expect(row.data).toEqual(credential)
  })

  it('re-keys a pulled row (any version), not just never-synced rows', async () => {
    const { localStore } = await initLocalStore()
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    await localStore.rxCollection('publicCredentials').insert({
      id: 'z6PreFixWrongCid',
      updatedAt: new Date().toISOString(),
      version: 4,
      data: credential as unknown as Json
    })

    await localStore.migratePublicCredentialCids()

    expect(await localStore.hasPublicCredential({ cid })).toBe(true)
    expect(
      await localStore.hasPublicCredential({ cid: 'z6PreFixWrongCid' })
    ).toBe(false)
  })

  it('leaves a correctly-keyed row untouched (no churn)', async () => {
    const { localStore } = await initLocalStore()
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    await localStore.addPublicCredential({ cid, credential })
    const before = (await localStore
      .rxCollection('publicCredentials')
      .findOne(cid)
      .exec())!.toMutableJSON()

    await localStore.migratePublicCredentialCids()

    const rows = await localStore
      .rxCollection('publicCredentials')
      .find()
      .exec()
    expect(rows).toHaveLength(1)
    expect(rows[0].toMutableJSON()).toEqual(before)
  })

  it('is a no-op on a second run', async () => {
    const { localStore } = await initLocalStore()
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    await localStore.rxCollection('publicCredentials').insert({
      id: 'z6PreFixWrongCid',
      updatedAt: new Date().toISOString(),
      version: 0,
      data: credential as unknown as Json
    })

    await localStore.migratePublicCredentialCids()
    await localStore.migratePublicCredentialCids()

    expect(await localStore.hasPublicCredential({ cid })).toBe(true)
    // Only the re-keyed row remains live (the wrong-id row is tombstoned).
    const rows = await localStore
      .rxCollection('publicCredentials')
      .find()
      .exec()
    expect(rows).toHaveLength(1)
    expect(rows[0].toMutableJSON().id).toBe(cid)
  })

  it('short-circuits on a later login via the per-dbPrefix marker', async () => {
    // Install a minimal localStorage (absent in the node test env) so the gate
    // is exercised, then restore it after.
    const backing = new Map<string, string>()
    const fakeLocalStorage = {
      getItem: (key: string) => backing.get(key) ?? null,
      setItem: (key: string, value: string) => backing.set(key, value)
    }
    const globalObject = globalThis as { localStorage?: unknown }
    const previous = globalObject.localStorage
    globalObject.localStorage = fakeLocalStorage
    try {
      const { localStore } = await initLocalStore()
      // First run sets the marker.
      await localStore.migratePublicCredentialCids()

      // A mis-keyed row inserted after the marker is set is NOT re-keyed: the
      // gate short-circuits the scan, exactly like migrateLocalPlaintextDocs.
      const credential = makeCredential('Alice')
      const cid = await cidFrom({ doc: credential })
      await localStore.rxCollection('publicCredentials').insert({
        id: 'z6PreFixWrongCid',
        updatedAt: new Date().toISOString(),
        version: 0,
        data: credential as unknown as Json
      })

      await localStore.migratePublicCredentialCids()

      expect(await localStore.hasPublicCredential({ cid })).toBe(false)
      expect(
        await localStore.hasPublicCredential({ cid: 'z6PreFixWrongCid' })
      ).toBe(true)
    } finally {
      if (previous === undefined) {
        delete globalObject.localStorage
      } else {
        globalObject.localStorage = previous
      }
    }
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
    const { storage, user } = await initManager()
    const credential = makeCredential('Alice')

    await storage.addCredential({ credential, user })

    const listed = await storage.listCredentials()
    expect(listed).toHaveLength(1)
    expect(listed[0].cid).toBe(await cidFrom({ doc: credential }))
    expect(listed[0].vc).toEqual(credential)
  })

  it('writes history locally with no remote store (guest / offline path)', async () => {
    const { storage, user } = await initManager()

    await storage.addHistoryNewAccount({ user })
    await storage.addHistorySpaceCreated({ user })
    await storage.addHistoryCredentialCreated({
      cid: 'abc',
      title: 'Test Credential',
      user
    })

    const items = await storage.listHistoryItems()
    expect(items).toHaveLength(3)
    expect(items[0].doc.summary).toMatch(/Sign Up/)
    // The no-remote branch records the local collections, not a remote Space.
    expect(items[1].doc.summary).toMatch(/local storage/)
    expect(items[2].doc.summary).toBe('Credential created: Test Credential')
    expect(items[2].doc.object).toEqual({
      cid: 'abc',
      title: 'Test Credential'
    })
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
    const { storage, user } = await initManager()
    const credential = makeCredential('Alice')
    await storage.addCredential({ credential, user })
    const cid = await cidFrom({ doc: credential })

    await storage.deleteCredential({ cid })

    expect(await storage.loadCredential({ cid })).toBeUndefined()
    expect(await storage.listCredentials()).toHaveLength(0)
  })

  it('retracts the public copy before deleting the credential', async () => {
    const { localStore, user } = await initLocalStore()
    const remoteStore = {
      publicCredentialUrl: (cid: string) =>
        `https://was.example/space/s/public-credentials/${cid}`
    } as unknown as WASRemoteStore
    const storage = new StorageManager({ localStore, remoteStore })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    await storage.addCredential({ credential, user })
    await storage.createPublicLink({ credential })

    const calls: string[] = []
    const removePublicCredential =
      localStore.removePublicCredential.bind(localStore)
    const deleteCredential = localStore.deleteCredential.bind(localStore)
    localStore.removePublicCredential = async options => {
      calls.push('removePublicCredential')
      return await removePublicCredential(options)
    }
    localStore.deleteCredential = async options => {
      calls.push('deleteCredential')
      return await deleteCredential(options)
    }

    await storage.deleteCredential({ cid })

    expect(calls).toEqual(['removePublicCredential', 'deleteCredential'])
    expect(await storage.isShared({ cid })).toBe(false)
    expect(await storage.listCredentials()).toHaveLength(0)
  })

  it('refuses the delete when a live public copy cannot be retracted', async () => {
    const { localStore, user } = await initLocalStore()
    const remoteStore = {
      publicCredentialUrl: (cid: string) =>
        `https://was.example/space/s/public-credentials/${cid}`
    } as unknown as WASRemoteStore
    const storage = new StorageManager({ localStore, remoteStore })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    await storage.addCredential({ credential, user })
    await storage.createPublicLink({ credential })

    localStore.removePublicCredential = async () => {
      throw new Error('offline')
    }

    await expect(storage.deleteCredential({ cid })).rejects.toThrow(
      PublicCopyRetractionError
    )
    // The private credential is still there: no world-readable orphan.
    expect(await storage.loadCredential({ cid })).toEqual(credential)
  })

  it('keeps the public copy when the user deliberately chose to', async () => {
    const { localStore, user } = await initLocalStore()
    const remoteStore = {
      publicCredentialUrl: (cid: string) =>
        `https://was.example/space/s/public-credentials/${cid}`
    } as unknown as WASRemoteStore
    const storage = new StorageManager({ localStore, remoteStore })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    await storage.addCredential({ credential, user })
    await storage.createPublicLink({ credential })

    await storage.deleteCredential({ cid, keepPublicCopy: true })

    expect(await storage.loadCredential({ cid })).toBeUndefined()
    expect(await storage.isShared({ cid })).toBe(true)
  })

  it('deletes a credential with no public copy offline', async () => {
    // No remote store at all: the retraction step finds nothing to retract and
    // the delete goes through.
    const { storage, user } = await initManager()
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    await storage.addCredential({ credential, user })

    await storage.deleteCredential({ cid })

    expect(await storage.loadCredential({ cid })).toBeUndefined()
  })

  it('surfaces and purges undecryptable credentials through the facade', async () => {
    const ciphers = encryptedCiphers()
    const { localStore, user } = await initLocalStore({ ciphers })
    const storage = new StorageManager({ localStore, ciphers })
    const credential = makeCredential('Alice')
    await storage.addCredential({ credential, user })
    await localStore.rxCollection('privateCredentials').insert({
      id: 'z6Poison',
      updatedAt: new Date().toISOString(),
      version: 0,
      data: {
        id: 'z6Poison',
        sequence: 0,
        jwe: { ciphertext: 'not-json{' }
      } as Json
    })

    const listed = await storage.listCredentials()
    expect(listed).toHaveLength(1)
    expect(storage.undecryptableCredentials).toBe(1)

    expect(await storage.purgeUndecryptableCredentials()).toBe(1)
    expect(storage.undecryptableCredentials).toBe(0)
  })

  it('records credential-created history only on an actual insert', async () => {
    const { storage, user } = await initManager()
    const credential = makeCredential('Alice')

    // First add inserts and logs; the re-add dedupes and must not log again.
    await storage.addCredential({ credential, user })
    await storage.addCredential({ credential, user })

    const items = await storage.listHistoryItems()
    expect(items).toHaveLength(1)
    expect(items[0].doc.summary).toMatch(/Credential created/)
  })
})

/**
 * An in-memory stand-in for the remote WAS standard collections: one map of
 * resource-id to raw stored body per logical collection, exposing the same
 * `listSyncedResources` / `getSyncedResource` / `putSyncedResource` /
 * `deleteSyncedResource` surface the remote-direct backend calls.
 * `putSyncedResource` honors the create-if-absent contract (a second write to
 * an existing id reports `created: false`) and records any `WAS-Key-Epoch`
 * stamp under `epochs`, so a test can assert a remote-direct write carried it.
 */
function makeFakeRemoteStore(): {
  remoteStore: WASRemoteStore
  collections: Map<string, Map<string, Json>>
  epochs: Map<string, Map<string, string | undefined>>
} {
  const collections = new Map<string, Map<string, Json>>()
  const epochs = new Map<string, Map<string, string | undefined>>()
  const collectionFor = (logicalKey: string): Map<string, Json> => {
    let collection = collections.get(logicalKey)
    if (!collection) {
      collection = new Map<string, Json>()
      collections.set(logicalKey, collection)
    }
    return collection
  }
  const epochsFor = (logicalKey: string): Map<string, string | undefined> => {
    let map = epochs.get(logicalKey)
    if (!map) {
      map = new Map<string, string | undefined>()
      epochs.set(logicalKey, map)
    }
    return map
  }
  const remoteStore = {
    async listSyncedResources({ logicalKey }: { logicalKey: string }) {
      return [...collectionFor(logicalKey).keys()].map(id => ({
        id,
        url: `/space/s/${logicalKey}/${id}`
      }))
    },
    async getSyncedResource({
      logicalKey,
      resourceId
    }: {
      logicalKey: string
      resourceId: string
    }) {
      return collectionFor(logicalKey).get(resourceId)
    },
    async putSyncedResource({
      logicalKey,
      resourceId,
      body,
      epoch
    }: {
      logicalKey: string
      resourceId: string
      body: Json
      epoch?: string
    }) {
      const collection = collectionFor(logicalKey)
      if (collection.has(resourceId)) {
        return { created: false }
      }
      collection.set(resourceId, body)
      epochsFor(logicalKey).set(resourceId, epoch)
      return { created: true }
    },
    async deleteSyncedResource({
      logicalKey,
      resourceId
    }: {
      logicalKey: string
      resourceId: string
    }) {
      collectionFor(logicalKey).delete(resourceId)
      epochsFor(logicalKey).delete(resourceId)
    }
  } as unknown as WASRemoteStore
  return { remoteStore, collections, epochs }
}

describe('StorageManager (remote-direct popup mode)', () => {
  it('routes credential add/list/load to the remote store, deduping by cid', async () => {
    const ciphers = encryptedCiphers()
    const { localStore, user } = await initLocalStore({ ciphers })
    const { remoteStore, collections } = makeFakeRemoteStore()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      remoteDirect: true
    })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })

    await storage.addCredential({ credential, user })
    // A re-add dedupes against the remote contents (no second envelope row).
    await storage.addCredential({ credential, user })

    expect(collections.get('privateCredentials')!.size).toBe(1)
    expect(await storage.listCredentials()).toEqual([{ cid, vc: credential }])
    expect(await storage.loadCredential({ cid })).toEqual(credential)
    // Nothing was written to the local (partitioned) store.
    expect(await localStore.listCredentials()).toHaveLength(0)
  })

  it('records credential-created history remotely only on an actual insert', async () => {
    const ciphers = encryptedCiphers()
    const { localStore, user } = await initLocalStore({ ciphers })
    const { remoteStore, collections } = makeFakeRemoteStore()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      remoteDirect: true
    })
    const credential = makeCredential('Alice')

    await storage.addCredential({ credential, user })
    await storage.addCredential({ credential, user })

    // One credential, one history entry -- the deduped re-add logs nothing.
    expect(collections.get('privateCredentials')!.size).toBe(1)
    expect(collections.get('walletActivity')!.size).toBe(1)
  })

  it('falls back to the local store when no remote store is configured', async () => {
    const ciphers = encryptedCiphers()
    const { localStore, user } = await initLocalStore({ ciphers })
    // remoteDirect requested but no remote store: effective mode is off.
    const storage = new StorageManager({
      localStore,
      ciphers,
      remoteDirect: true
    })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })

    await storage.addCredential({ credential, user })

    expect(await storage.listCredentials()).toEqual([{ cid, vc: credential }])
    // The write landed in the local store, not any remote surface.
    expect(await localStore.listCredentials()).toHaveLength(1)
  })

  it('stamps the WAS-Key-Epoch on the remote-direct credential and history writes', async () => {
    const ciphers = {
      privateCredentials: makeFakeEpochCipher('epoch-cred'),
      walletActivity: makeFakeEpochCipher('epoch-hist')
    }
    const { localStore, user } = await initLocalStore({ ciphers })
    const { remoteStore, collections, epochs } = makeFakeRemoteStore()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      remoteDirect: true
    })

    await storage.addCredential({ credential: makeCredential('Alice'), user })

    // The single written resource in each collection carries its cipher's epoch.
    const [credRow] = [...collections.get('privateCredentials')!.keys()]
    expect(epochs.get('privateCredentials')!.get(credRow)).toBe('epoch-cred')
    const [histRow] = [...collections.get('walletActivity')!.keys()]
    expect(epochs.get('walletActivity')!.get(histRow)).toBe('epoch-hist')
  })

  it('routes deleteCredential to the remote backend (not the empty local store)', async () => {
    const ciphers = encryptedCiphers()
    const { localStore, user } = await initLocalStore({ ciphers })
    const { remoteStore, collections } = makeFakeRemoteStore()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      remoteDirect: true
    })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })

    await storage.addCredential({ credential, user })
    expect(collections.get('privateCredentials')!.size).toBe(1)

    await storage.deleteCredential({ cid })

    // The remote row is gone; nothing ever touched the local partitioned store.
    expect(collections.get('privateCredentials')!.size).toBe(0)
    expect(await storage.listCredentials()).toHaveLength(0)
  })
})

describe('RemoteDirectStore', () => {
  it('counts an unknown-epoch row separately and re-reads it after a cipher swap', async () => {
    const { remoteStore, collections } = makeFakeRemoteStore()
    // Seed one envelope resource in the remote private-credentials collection.
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    const good = makeFakeCipher()
    const { id, envelope } = await good.encrypt({
      data: credential as unknown as Json
    })
    collections.set('privateCredentials', new Map([[id, envelope]]))

    // A cipher that cannot route the envelope's epoch (a stale descriptor).
    const stale: DocCipher = {
      async encrypt() {
        throw new Error('unused')
      },
      async decrypt() {
        throw new UnknownEpochError({
          collectionId: 'private-credentials',
          kids: ['z6MkUnknownEpochKey']
        })
      }
    }
    const store = new RemoteDirectStore({
      remoteStore,
      ciphers: { privateCredentials: stale, walletActivity: makeFakeCipher() }
    })

    // The unknown-epoch row is skipped (not undecryptable) and counted apart.
    expect(await store.listCredentials()).toHaveLength(0)
    expect(store.unknownEpochCredentials).toBe(1)
    expect(store.undecryptableCredentials).toBe(0)

    // A descriptor refresh swaps in a cipher that can decrypt it; the row re-reads.
    store.setCiphers({
      privateCredentials: good,
      walletActivity: makeFakeCipher()
    })
    expect(await store.listCredentials()).toEqual([{ cid, vc: credential }])
    expect(store.unknownEpochCredentials).toBe(0)
  })

  it('dedupes adds against the session cache without re-listing per item', async () => {
    const { remoteStore } = makeFakeRemoteStore()
    let lists = 0
    const spied = {
      ...remoteStore,
      async listSyncedResources(options: { logicalKey: string }) {
        lists += 1
        return remoteStore.listSyncedResources(options)
      }
    } as unknown as WASRemoteStore
    const store = new RemoteDirectStore({
      remoteStore: spied,
      ciphers: {
        privateCredentials: makeFakeCipher(),
        walletActivity: makeFakeCipher()
      }
    })

    const first = makeCredential('Alice')
    const second = makeCredential('Bob')
    expect(
      await store.addCredential({
        cid: await cidFrom({ doc: first }),
        credential: first
      })
    ).toBe(true)
    expect(
      await store.addCredential({
        cid: await cidFrom({ doc: second }),
        credential: second
      })
    ).toBe(true)
    // The re-add dedupes against the incrementally maintained cache.
    expect(
      await store.addCredential({
        cid: await cidFrom({ doc: first }),
        credential: first
      })
    ).toBe(false)

    // The collection was scanned once (the first add), not once per item.
    expect(lists).toBe(1)
  })

  it('rejects contact operations rather than hitting the partitioned store', async () => {
    const { remoteStore } = makeFakeRemoteStore()
    const store = new RemoteDirectStore({
      remoteStore,
      ciphers: {
        privateCredentials: makeFakeCipher(),
        walletActivity: makeFakeCipher()
      }
    })
    await expect(store.listContacts()).rejects.toThrow(/not available/)
  })
})
