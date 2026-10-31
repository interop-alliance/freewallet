// @vitest-environment node
/**
 * Unit tests for the local adapter of the `connections` directory
 * (`localConnectionsStore` in `src/stores/connectionsStore.ts`), the store a
 * guest or no-WAS session keeps its directory in: every body sealed as an
 * EDV envelope at its derived id and opened under the id it was read at,
 * conditional writes under the RxDB revision as the ETag, a create race
 * surfacing as `PreconditionFailedError`, and the directory logic in
 * `@interop/wallet-core/connections` running over it unchanged.
 */
import { afterEach, describe, expect, it } from 'vitest'
import {
  createRxDatabase,
  type RxCollection,
  type RxDatabase
} from 'rxdb/plugins/core'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import { syncedDocSchema, type SyncedDoc } from '@interop/pws-sync'
import {
  createEdvDocCipher,
  isEncryptedEnvelope,
  ownerRecipient,
  type EdvDocCipher
} from '@interop/pws-client/edv'
import {
  connectionResourceId,
  readConnections,
  recordGrants,
  retireConnection
} from '@interop/wallet-core/connections'
import { ensureIndexedFirstEpoch } from '@interop/wallet-core/keys'
import { errorNameOf } from '@interop/wallet-core/menders'
import { memoryDescriptorStores } from '../../tests/unit/fakeDescriptorStores'
import { localConnectionsStore } from './connectionsStore'
import { generateVaultKeys } from './testing/vaultKeys'

const HMAC_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1)
const AGENT = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const OTHER = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'

let databaseCounter = 0
const open: RxDatabase[] = []

/**
 * A fresh RxDB `connections` collection on memory storage.
 *
 * @returns {Promise<RxCollection<SyncedDoc>>}
 */
async function directoryCollection(): Promise<RxCollection<SyncedDoc>> {
  databaseCounter += 1
  const db = await createRxDatabase({
    name: `connections-test-${databaseCounter}`,
    storage: getRxStorageMemory(),
    multiInstance: false
  })
  open.push(db)
  const { connections } = await db.addCollections({
    connections: { schema: syncedDocSchema() }
  })
  return connections as unknown as RxCollection<SyncedDoc>
}

afterEach(async () => {
  await Promise.all(open.splice(0).map(db => db.close()))
})

/**
 * The directory's EDV cipher over a fresh epoch[0] wrapped to a fresh vault
 * key, as the local mint installs it.
 *
 * @returns {Promise<EdvDocCipher>}
 */
async function directoryCipher(): Promise<EdvDocCipher> {
  const owner = await generateVaultKeys()
  const { descriptor } = await ensureIndexedFirstEpoch({
    store: memoryDescriptorStores().storeFor('connections'),
    recipients: [ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })]
  })
  return createEdvDocCipher({
    ...owner,
    collectionId: 'connections',
    idDerivation: 'random',
    encryption: descriptor
  })
}

/**
 * The local adapter over a fresh collection and cipher, plus the collection
 * so a test can read the stored envelopes.
 *
 * @returns {Promise<object>}   `{ store, collection }`
 */
async function localDirectory(): Promise<{
  store: ReturnType<typeof localConnectionsStore>
  collection: RxCollection<SyncedDoc>
}> {
  const collection = await directoryCollection()
  const store = localConnectionsStore({
    collection,
    cipher: await directoryCipher()
  })
  return { store, collection }
}

/**
 * A resource id the directory logic would derive, for a party DID.
 *
 * @param did {string}
 * @returns {Promise<string>}
 */
async function idOf(did: string): Promise<string> {
  return connectionResourceId({ hmacKey: HMAC_KEY, did })
}

/**
 * What a promise rejected with, by error name.
 *
 * @param promise {Promise<unknown>}
 * @returns {Promise<string | undefined>}
 */
async function rejectionName(
  promise: Promise<unknown>
): Promise<string | undefined> {
  return promise.then(
    () => undefined,
    (err: unknown) => errorNameOf(err)
  )
}

describe('localConnectionsStore', () => {
  it('stores an EDV envelope at the derived id and opens it there', async () => {
    const { store, collection } = await localDirectory()
    const resourceId = await idOf(AGENT)
    const { etag } = await store.put({
      resourceId,
      body: { version: 1, id: AGENT },
      ifNoneMatch: true
    })
    const stored = await collection.findOne(resourceId).exec()
    expect(isEncryptedEnvelope(stored?.toMutableJSON().data)).toBe(true)
    expect(JSON.stringify(stored?.toMutableJSON().data)).not.toContain(AGENT)
    await expect(store.get({ resourceId })).resolves.toEqual({
      body: { version: 1, id: AGENT },
      etag
    })
  })

  it('refuses an envelope moved to another id: get throws, list reports it', async () => {
    const { store, collection } = await localDirectory()
    const resourceId = await idOf(AGENT)
    await store.put({ resourceId, body: { n: 1 }, ifNoneMatch: true })
    const envelope = (await collection
      .findOne(resourceId)
      .exec())!.toMutableJSON().data
    const elsewhere = await idOf(OTHER)
    await collection.insert({
      id: elsewhere,
      updatedAt: new Date().toISOString(),
      data: envelope
    })
    expect(await rejectionName(store.get({ resourceId: elsewhere }))).toBe(
      'IntegrityError'
    )
    const listed = await store.list()
    const moved = listed?.find(item => item.resourceId === elsewhere)
    expect(moved?.body).toBeUndefined()
    expect(errorNameOf(moved?.readError)).toBe('IntegrityError')
    expect(listed?.find(item => item.resourceId === resourceId)?.body).toEqual({
      n: 1
    })
  })

  it('creates under ifNoneMatch once, and refuses the second create', async () => {
    const { store } = await localDirectory()
    const resourceId = await idOf(AGENT)
    const { etag } = await store.put({
      resourceId,
      body: { version: 1 },
      ifNoneMatch: true
    })
    expect(etag).toEqual(expect.any(String))
    expect(
      await rejectionName(
        store.put({ resourceId, body: { version: 1 }, ifNoneMatch: true })
      )
    ).toBe('PreconditionFailedError')
    await expect(store.get({ resourceId })).resolves.toEqual({
      body: { version: 1 },
      etag
    })
  })

  it('writes under a current ifMatch and refuses a stale one', async () => {
    const { store } = await localDirectory()
    const resourceId = await idOf(AGENT)
    const first = await store.put({
      resourceId,
      body: { n: 1 },
      ifNoneMatch: true
    })
    const second = await store.put({
      resourceId,
      body: { n: 2 },
      ifMatch: first.etag
    })
    expect(second.etag).not.toBe(first.etag)
    await expect(store.get({ resourceId })).resolves.toEqual({
      body: { n: 2 },
      etag: second.etag
    })
    expect(
      await rejectionName(
        store.put({ resourceId, body: { n: 3 }, ifMatch: first.etag })
      )
    ).toBe('PreconditionFailedError')
    expect(
      await rejectionName(
        store.put({
          resourceId: await idOf(OTHER),
          body: { n: 1 },
          ifMatch: 'x'
        })
      )
    ).toBe('PreconditionFailedError')
  })

  it('lists every entry with its ETag, and an absent get is undefined', async () => {
    const { store } = await localDirectory()
    const resourceId = await idOf(AGENT)
    const { etag } = await store.put({
      resourceId,
      body: { n: 1 },
      ifNoneMatch: true
    })
    await expect(store.list()).resolves.toEqual([
      { resourceId, etag, body: { n: 1 } }
    ])
    await expect(store.get({ resourceId: await idOf(OTHER) })).resolves.toBe(
      undefined
    )
  })

  it('runs the directory logic unchanged: record, list, retire', async () => {
    const { store } = await localDirectory()
    // A session with no Space passes no container URL and records no grant.
    await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      did: AGENT,
      kind: 'app',
      grants: [],
      name: 'Notes',
      appKey: 'z1AppKey'
    })
    await retireConnection({
      store,
      hmacKey: HMAC_KEY,
      did: AGENT,
      handledZcapIds: [],
      spaceUrl: 'https://was.example/space/local/'
    })
    const listing = await readConnections({ store, hmacKey: HMAC_KEY })
    expect(listing?.entries).toHaveLength(1)
    const [{ entry }] = listing!.entries
    expect(entry).toMatchObject({ kind: 'app', id: AGENT, name: 'Notes' })
    expect(entry.retired).toEqual(expect.any(String))
    expect(entry.appKey).toBeUndefined()
  })
})
