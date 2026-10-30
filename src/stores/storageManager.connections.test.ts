// @vitest-environment node
/**
 * Unit tests for the `connections` directory's store seam on
 * `StorageManager` (`connectionsDirectory`): the session's one directory
 * store, resolved to wallet-core's WAS adapter on a session with a remote
 * Space and to the local adapter on a guest or no-WAS session.
 *
 * - The binding refuses a `connections` collection whose current epoch lists
 *   a kid outside the account's user key generations, one whose Collection
 *   Metadata object carries a `generator`, and one whose descriptor declares
 *   no blinded-index key. Only a stranded descriptor, which the user key
 *   cascade converges, joins the stranded report; a missing blinded-index
 *   key, a foreign recipient, and a `generator` stamp do not. A structural
 *   refusal is decided once per descriptor; an absent Collection Metadata
 *   object is read again at the next directory operation.
 * - The directory's cipher follows a user key cascade: the next entry write
 *   seals under the new epoch, and a second session adopting the rotated key
 *   reads the entries sealed under it.
 * - A transient session writes and reads the directory under its generation
 *   delegation.
 * - `decryptCollectionResource` opens a directory entry after a rotation.
 * - A guest or no-WAS session keeps its directory locally, its ids derived
 *   under the locally minted blinded-index key.
 *
 * The remote side is a real `WASRemoteStore` over a real `WasClient`, served
 * by the in-memory WAS server, with real EDV ciphers over generated keys.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { ZcapClient } from '@interop/ezcap'
import type {
  CollectionEncryption,
  CollectionGenerator,
  IZcap
} from '@interop/was-client'
import {
  addRecipient,
  createEdvDocCipher,
  ensureFirstEpoch,
  ownerRecipient,
  removeRecipient,
  replaceRecipient,
  resolveHmacKey
} from '@interop/was-client/edv'
import { ensureIndexedFirstEpoch } from '@interop/wallet-core/keys'
import {
  connectionResourceId,
  readConnections,
  recordGrants
} from '@interop/wallet-core/connections'
import type { Json } from '@interop/was-sync'
import { classifyDecryptFailure } from '@/lib/decryptFailure'
import {
  browserLocalSessionPersistence,
  inMemorySessionPersistence,
  transientSessionStores
} from '@/session/persistence'
import type { ControllerProfile, User } from '@/types/auth'
import { TEST_SERVICE_DESCRIPTION } from '../../tests/shared/wasServiceFixture'
import {
  descriptorLogsFrom,
  memoryDescriptorStores,
  type MemoryDescriptorStores
} from '../../tests/unit/fakeDescriptorStores'
import {
  MEMORY_SERVER_URL,
  memoryWasServer
} from '../../tests/unit/memoryWasServer'
import { StorageManager } from './storageManager'
import { generateVaultKeys } from './testing/vaultKeys'
import { WASRemoteStore } from './wasRemoteStore'

const SPACE_ID = 's-space'
const AGENT = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const OTHER_AGENT = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'

type VaultKeys = Awaited<ReturnType<typeof generateVaultKeys>>

/**
 * Installs the directory's epoch[0] and blinded-index key, wrapped to
 * `owner`, in the in-memory descriptor logs.
 *
 * @param options {object}
 * @param options.stores {MemoryDescriptorStores}
 * @param options.owner {VaultKeys}
 * @param [options.blindedIndex] {boolean}   default true
 * @returns {Promise<CollectionEncryption>}
 */
async function installDirectory({
  stores,
  owner,
  blindedIndex = true
}: {
  stores: MemoryDescriptorStores
  owner: VaultKeys
  blindedIndex?: boolean
}): Promise<CollectionEncryption> {
  const recipients = [
    ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })
  ]
  const store = stores.storeFor('connections')
  const { descriptor } = blindedIndex
    ? await ensureIndexedFirstEpoch({ store, recipients })
    : await ensureFirstEpoch({ store, recipients })
  return descriptor
}

/**
 * A remote session's storage manager over the in-memory WAS server: the
 * descriptors read through the in-memory logs, the requests through a real
 * `WASRemoteStore` bound to `capability` when one is given.
 *
 * @param options {object}
 * @param options.owner {VaultKeys}   the session's vault keys
 * @param options.stores {MemoryDescriptorStores}
 * @param options.server {object}   the in-memory WAS server
 * @param [options.capability] {IZcap}   the generation delegation of a
 *   transient session
 * @param [options.generator] {CollectionGenerator}   the directory's
 *   attribution stamp, as its Collection Metadata object serves it
 * @param [options.generationKids] {string[]}   the account's user key
 *   generations
 * @returns {StorageManager}
 */
function remoteSession({
  owner,
  stores,
  server,
  capability,
  generator,
  generationKids = []
}: {
  owner: VaultKeys
  stores: MemoryDescriptorStores
  server: ReturnType<typeof memoryWasServer>
  capability?: IZcap
  generator?: CollectionGenerator
  generationKids?: string[]
}): StorageManager {
  const remoteStore = new WASRemoteStore({
    serviceDescription: TEST_SERVICE_DESCRIPTION,
    pinStore: memoryResourceLogPinStore(),
    baseServerUrl: MEMORY_SERVER_URL,
    zcapClient: {} as ZcapClient,
    spaceId: SPACE_ID,
    controller: 'did:key:z6MkTestController',
    ...(capability ? { capability } : {})
  })
  remoteStore.was = server.client({ maxBlobBytes: 1 << 20, chunkSize: 1 << 18 })
  vi.spyOn(remoteStore, 'collectionMetadata').mockImplementation(
    async ({ collectionId }) => ({
      encryption: stores.descriptorOf(collectionId),
      ...(generator ? { generator } : {})
    })
  )
  const descriptor = stores.descriptorOf('connections')
  return new StorageManager({
    remoteStore,
    persistence: inMemorySessionPersistence({
      stores: transientSessionStores(),
      clientAnnex: {
        clientAnnexDid: 'did:webvh:example:annex',
        invocationCapability: (capability ?? {}) as IZcap
      }
    }),
    descriptorLogs: descriptorLogsFrom(stores),
    vaultKeys: owner,
    descriptors: descriptor ? { connections: descriptor } : {},
    userKeyGenerationKids: async () => generationKids
  })
}

/**
 * Rotates the directory from one user key to the next, as a client
 * revocation's collection fan-out does.
 *
 * @param options {object}
 * @param options.stores {MemoryDescriptorStores}
 * @param options.from {VaultKeys}
 * @param options.to {VaultKeys}
 * @returns {Promise<CollectionEncryption>}
 */
async function rotateDirectory({
  stores,
  from,
  to
}: {
  stores: MemoryDescriptorStores
  from: VaultKeys
  to: VaultKeys
}): Promise<CollectionEncryption> {
  return replaceRecipient({
    store: stores.storeFor('connections'),
    retire: from.keyAgreementKey.id!,
    recipient: ownerRecipient({ keyAgreementKey: to.keyAgreementKey }),
    owner: { keyAgreementKey: from.keyAgreementKey },
    pull: async () => {},
    resolveRecipientKey: async () => null
  })
}

/**
 * The stored envelope at a directory resource id, as the server holds it.
 *
 * @param options {object}
 * @param options.server {object}
 * @param options.resourceId {string}
 * @returns {Json}
 */
function storedEnvelope({
  server,
  resourceId
}: {
  server: ReturnType<typeof memoryWasServer>
  resourceId: string
}): Json {
  const found = server
    .documentsOf({ spaceId: SPACE_ID, collectionId: 'connections' })
    .find(doc => doc.id === resourceId)
  expect(found).toBeDefined()
  return found!.data as Json
}

describe('the directory binding', () => {
  it('opens a directory the user key alone reads', async () => {
    const owner = await generateVaultKeys()
    const stores = memoryDescriptorStores()
    await installDirectory({ stores, owner })
    const storage = remoteSession({ owner, stores, server: memoryWasServer() })

    const { store, hmacKey, spaceUrl } = await storage.connectionsDirectory()
    expect(spaceUrl).toBe(`${MEMORY_SERVER_URL}space/${SPACE_ID}/`)
    await recordGrants({
      store,
      hmacKey,
      spaceUrl: spaceUrl!,
      did: AGENT,
      kind: 'agent',
      grants: []
    })
    const listing = await readConnections({ store, hmacKey })
    expect(listing?.entries.map(({ entry }) => entry.id)).toEqual([AGENT])
    expect(storage.strandedCollectionIds).not.toContain('connections')
  })

  it("refuses one whose current epoch lists a kid outside the account's user key generations", async () => {
    const owner = await generateVaultKeys()
    const requester = await generateVaultKeys({
      controller: 'did:key:z6MkRequester'
    })
    const stores = memoryDescriptorStores()
    // Provisioned before the directory existed, for a requester that is an
    // epoch recipient beside the user key.
    await ensureIndexedFirstEpoch({
      store: stores.storeFor('connections'),
      recipients: [
        ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
        ownerRecipient({ keyAgreementKey: requester.keyAgreementKey })
      ]
    })
    const storage = remoteSession({ owner, stores, server: memoryWasServer() })

    await expect(storage.connectionsDirectory()).rejects.toThrow(
      'foreign-recipient'
    )
    // No cascade converges a foreign recipient, so it is not reported
    // stranded.
    expect(storage.strandedCollectionIds).not.toContain('connections')
    // The verdict stands for the descriptor: a second call refuses too.
    await expect(storage.connectionsDirectory()).rejects.toThrow(
      'foreign-recipient'
    )
  })

  it("admits an earlier user key generation the account's roster still names", async () => {
    const owner = await generateVaultKeys()
    const earlier = await generateVaultKeys({ controller: 'did:key:z6MkOld' })
    const stores = memoryDescriptorStores()
    await ensureIndexedFirstEpoch({
      store: stores.storeFor('connections'),
      recipients: [
        ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
        ownerRecipient({ keyAgreementKey: earlier.keyAgreementKey })
      ]
    })
    const storage = remoteSession({
      owner,
      stores,
      server: memoryWasServer(),
      generationKids: [earlier.keyAgreementKey.id!]
    })

    await expect(storage.connectionsDirectory()).resolves.toMatchObject({
      spaceUrl: expect.any(String)
    })
  })

  it('refuses one whose Collection Metadata object carries a generator', async () => {
    const owner = await generateVaultKeys()
    const stores = memoryDescriptorStores()
    await installDirectory({ stores, owner })
    const storage = remoteSession({
      owner,
      stores,
      server: memoryWasServer(),
      generator: { id: 'did:key:z6MkApp', origin: 'https://app.example' }
    })

    await expect(storage.connectionsDirectory()).rejects.toThrow('generator')
    expect(storage.strandedCollectionIds).not.toContain('connections')
  })

  it('keeps a generator refusal out of the stranded report across a descriptor refresh', async () => {
    // The stranded report triggers the user key cascade, which cannot remove
    // a `generator` stamp. Were the refusal reported, the refresh's cipher
    // rebuild would drop it again and the encounter would grade the
    // directory converged while every directory operation still refuses.
    const owner = await generateVaultKeys()
    const stores = memoryDescriptorStores()
    await installDirectory({ stores, owner })
    const storage = remoteSession({
      owner,
      stores,
      server: memoryWasServer(),
      generator: { id: 'did:key:z6MkApp', origin: 'https://app.example' }
    })
    const onStranded = vi.fn()
    storage.setOnStranded(onStranded)

    await expect(storage.connectionsDirectory()).rejects.toThrow('generator')
    await storage.refreshEncryptedDescriptors()
    await Promise.resolve()

    expect(onStranded).not.toHaveBeenCalled()
    expect(storage.strandedCollectionIds).not.toContain('connections')
    await expect(storage.connectionsDirectory()).rejects.toThrow('generator')
  })

  it('refuses one whose descriptor declares no blinded-index key', async () => {
    const owner = await generateVaultKeys()
    const stores = memoryDescriptorStores()
    await installDirectory({ stores, owner, blindedIndex: false })
    const storage = remoteSession({ owner, stores, server: memoryWasServer() })
    const onStranded = vi.fn()
    storage.setOnStranded(onStranded)

    await expect(storage.connectionsDirectory()).rejects.toThrow(
      'no-blinded-index-key'
    )
    // The key is installed at provisioning or never, so no cascade supplies
    // one: a cipher rebuild does not report the directory stranded.
    await storage.refreshEncryptedDescriptors()
    await Promise.resolve()
    expect(onStranded).not.toHaveBeenCalled()
    expect(storage.strandedCollectionIds).not.toContain('connections')
    await expect(storage.connectionsDirectory()).rejects.toThrow(
      'no-blinded-index-key'
    )
  })

  it('reports a directory no key epoch of which names the vault KAK as stranded', async () => {
    // The positive case of the negatives above: a directory sealed only to
    // a user key this session does not hold is what the cascade converges.
    const owner = await generateVaultKeys()
    const retired = await generateVaultKeys({ controller: 'did:key:z6MkOld' })
    const stores = memoryDescriptorStores()
    await installDirectory({ stores, owner: retired })
    const storage = remoteSession({ owner, stores, server: memoryWasServer() })
    const onStranded = vi.fn()
    storage.setOnStranded(onStranded)

    await expect(storage.connectionsDirectory()).rejects.toThrow('stranded')
    await storage.refreshEncryptedDescriptors()
    await Promise.resolve()
    expect(onStranded).toHaveBeenCalled()
    expect(storage.strandedCollectionIds).toContain('connections')
  })

  it('refuses an account with no directory, without reporting it stranded', async () => {
    const owner = await generateVaultKeys()
    const storage = remoteSession({
      owner,
      stores: memoryDescriptorStores(),
      server: memoryWasServer()
    })

    await expect(storage.connectionsDirectory()).rejects.toThrow('absent')
    expect(storage.strandedCollectionIds).not.toContain('connections')
  })

  it('reads the metadata again after an absent verdict, and opens the directory once it is present', async () => {
    // WAS masks an unauthorized read as a 404, so one missing Collection
    // Metadata object may be transient and is not kept for the descriptor.
    const owner = await generateVaultKeys()
    const stores = memoryDescriptorStores()
    await installDirectory({ stores, owner })
    const storage = remoteSession({ owner, stores, server: memoryWasServer() })
    const metadata = vi.mocked(storage.remoteStore!.collectionMetadata)
    metadata.mockResolvedValueOnce(undefined)

    await expect(storage.connectionsDirectory()).rejects.toThrow('absent')
    await expect(storage.connectionsDirectory()).resolves.toMatchObject({
      spaceUrl: expect.any(String)
    })
    const directoryReads = metadata.mock.calls.filter(
      ([{ collectionId }]) => collectionId === 'connections'
    )
    expect(directoryReads).toHaveLength(2)
  })

  it('reads the metadata once for a structural refusal', async () => {
    const owner = await generateVaultKeys()
    const stores = memoryDescriptorStores()
    await installDirectory({ stores, owner })
    const storage = remoteSession({
      owner,
      stores,
      server: memoryWasServer(),
      generator: { id: 'did:key:z6MkApp', origin: 'https://app.example' }
    })
    const metadata = vi.mocked(storage.remoteStore!.collectionMetadata)

    await expect(storage.connectionsDirectory()).rejects.toThrow('generator')
    await expect(storage.connectionsDirectory()).rejects.toThrow('generator')
    const directoryReads = metadata.mock.calls.filter(
      ([{ collectionId }]) => collectionId === 'connections'
    )
    expect(directoryReads).toHaveLength(1)
  })
})

describe('the descriptor acquisition', () => {
  it('acquires the connections descriptor beside the synced ones', async () => {
    const owner = await generateVaultKeys()
    const stores = memoryDescriptorStores()
    await installDirectory({ stores, owner })
    const asked = vi.spyOn(stores.source, 'collectionEncryption')
    const storage = remoteSession({ owner, stores, server: memoryWasServer() })

    await storage.refreshEncryptedDescriptors()

    const acquired = asked.mock.calls.map(([{ collectionId }]) => collectionId)
    expect(acquired).toContain('connections')
    expect(acquired).toContain('private-credentials')
  })
})

describe('the directory cipher across a user key cascade', () => {
  it('seals the next entry write under the new epoch, and a second session reads it', async () => {
    const before = await generateVaultKeys({ controller: 'did:key:z6MkV1' })
    const after = await generateVaultKeys({ controller: 'did:key:z6MkV2' })
    const stores = memoryDescriptorStores()
    const oldDescriptor = await installDirectory({ stores, owner: before })
    const server = memoryWasServer()
    const driver = remoteSession({ owner: before, stores, server })
    // A second client's session, open across the cascade.
    const follower = remoteSession({ owner: before, stores, server })

    const first = await driver.connectionsDirectory()
    await recordGrants({
      ...first,
      spaceUrl: first.spaceUrl!,
      did: AGENT,
      kind: 'agent',
      grants: []
    })

    // The cascade's fan-out re-keys the directory, then the session that
    // drove it adopts the rotated key.
    await rotateDirectory({ stores, from: before, to: after })
    await driver.adoptRotatedVaultKeys(after)

    const next = await driver.connectionsDirectory()
    // The blinded-index key never rotates, so every id stays where it was.
    expect(
      await connectionResourceId({ hmacKey: next.hmacKey, did: AGENT })
    ).toBe(await connectionResourceId({ hmacKey: first.hmacKey, did: AGENT }))
    await recordGrants({
      ...next,
      spaceUrl: next.spaceUrl!,
      did: OTHER_AGENT,
      kind: 'agent',
      grants: []
    })

    // The retired epoch does not open the new entry.
    const resourceId = await connectionResourceId({
      hmacKey: next.hmacKey,
      did: OTHER_AGENT
    })
    const oldCipher = await createEdvDocCipher({
      ...before,
      collectionId: 'connections',
      idDerivation: 'random',
      encryption: oldDescriptor
    })
    const failure = await oldCipher
      .decrypt({
        id: resourceId,
        envelope: storedEnvelope({ server, resourceId })
      })
      .then(
        () => undefined,
        (err: unknown) => err
      )
    expect(classifyDecryptFailure(failure)).toBe('unknown-epoch')

    // The follower adopts the rotated key as its follower adoption does, and
    // reads both entries, the one sealed under the new epoch included.
    await follower.adoptRotatedVaultKeys(after)
    const followed = await follower.connectionsDirectory()
    const listing = await readConnections(followed)
    expect(listing?.unreadable).toEqual([])
    expect(listing?.entries.map(({ entry }) => entry.id).sort()).toEqual(
      [AGENT, OTHER_AGENT].sort()
    )
  })

  it('refreshes once and reads an entry another client sealed under a newer epoch', async () => {
    const owner = await generateVaultKeys()
    const stores = memoryDescriptorStores()
    await installDirectory({ stores, owner })
    const server = memoryWasServer()
    const writer = remoteSession({ owner, stores, server })
    const reader = remoteSession({ owner, stores, server })
    // The reader built its cipher before the epoch moved.
    await reader.connectionsDirectory()

    // Another client moves the epoch on the same user key (a reader added
    // and removed again), then writes under the new epoch.
    const reader2 = await generateVaultKeys({ controller: 'did:key:z6MkR' })
    await addRecipient({
      store: stores.storeFor('connections'),
      recipient: ownerRecipient({ keyAgreementKey: reader2.keyAgreementKey }),
      owner: { keyAgreementKey: owner.keyAgreementKey }
    })
    const rotated = await removeRecipient({
      store: stores.storeFor('connections'),
      recipientId: reader2.keyAgreementKey.id!,
      pull: async () => {},
      resolveRecipientKey: async kid =>
        kid === owner.keyAgreementKey.id
          ? ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })
          : null
    })
    expect(rotated.epochs?.length).toBe(2)
    await writer.refreshEncryptedDescriptors()
    const written = await writer.connectionsDirectory()
    await recordGrants({
      ...written,
      spaceUrl: written.spaceUrl!,
      did: AGENT,
      kind: 'agent',
      grants: []
    })

    const listing = await readConnections(await reader.connectionsDirectory())
    expect(listing?.unreadable).toEqual([])
    expect(listing?.entries.map(({ entry }) => entry.id)).toEqual([AGENT])
  })
})

describe('the storage browser', () => {
  it('opens a directory entry after a rotation', async () => {
    const before = await generateVaultKeys({ controller: 'did:key:z6MkV1' })
    const after = await generateVaultKeys({ controller: 'did:key:z6MkV2' })
    const stores = memoryDescriptorStores()
    await installDirectory({ stores, owner: before })
    const server = memoryWasServer()
    const storage = remoteSession({ owner: before, stores, server })
    await rotateDirectory({ stores, from: before, to: after })
    await storage.adoptRotatedVaultKeys(after)

    const directory = await storage.connectionsDirectory()
    await recordGrants({
      ...directory,
      spaceUrl: directory.spaceUrl!,
      did: AGENT,
      kind: 'agent',
      grants: [],
      name: 'Backup Agent'
    })
    const resourceId = await connectionResourceId({
      hmacKey: directory.hmacKey,
      did: AGENT
    })

    // Through the roster path, not the app-collection one: the decrypted
    // entry, rather than the raw envelope.
    await expect(
      storage.decryptCollectionResource({
        collectionId: 'connections',
        resourceId,
        data: storedEnvelope({ server, resourceId })
      })
    ).resolves.toMatchObject({ kind: 'agent', id: AGENT, name: 'Backup Agent' })
  })
})

describe('a transient session', () => {
  it('writes and reads the directory under its generation delegation', async () => {
    const owner = await generateVaultKeys()
    const stores = memoryDescriptorStores()
    await installDirectory({ stores, owner })
    const server = memoryWasServer()
    const capability = {
      id: 'urn:zcap:generation-delegation',
      controller: 'did:webvh:example:annex',
      invocationTarget: `${MEMORY_SERVER_URL}space/${SPACE_ID}/`
    } as unknown as IZcap
    const storage = remoteSession({ owner, stores, server, capability })

    const directory = await storage.connectionsDirectory()
    await recordGrants({
      ...directory,
      spaceUrl: directory.spaceUrl!,
      did: AGENT,
      kind: 'agent',
      grants: []
    })
    const listing = await readConnections(directory)
    expect(listing?.entries.map(({ entry }) => entry.id)).toEqual([AGENT])

    // Every directory request (the re-read, the create, the feed) rode the
    // generation delegation.
    const directoryRequests = server.requests.filter(request =>
      new URL(request.url!).pathname.startsWith(
        `/space/${SPACE_ID}/connections`
      )
    )
    expect(directoryRequests.length).toBeGreaterThanOrEqual(3)
    for (const request of directoryRequests) {
      expect(request.capability).toBe(capability)
    }
  })
})

describe('a guest or no-WAS session', () => {
  beforeEach(() => {
    // `BrowserStore.userExists` probes the browser's database list; a local
    // session never branches on the answer, so an empty listing is enough.
    Object.defineProperty(globalThis, 'indexedDB', {
      configurable: true,
      value: { databases: async () => [] }
    })
  })
  afterEach(() => {
    Reflect.deleteProperty(globalThis, 'indexedDB')
  })

  it('keeps its directory locally, its ids derived under the locally minted blinded-index key', async () => {
    const owner = await generateVaultKeys()
    const user: User = { id: 'did:key:z6MkLocalDirectoryUser' }
    const persistence = browserLocalSessionPersistence({ persistCaches: false })
    const { storage } = await StorageManager.initStorageClients({
      user,
      session: {
        profile: {
          ...owner,
          keyAgent: { id: 'did:key:z6MkLocalAgent' }
        } as unknown as ControllerProfile,
        persistence
      },
      isGuest: true,
      storage: getRxStorageMemory()
    })
    await storage.ensureUserCollections({ user })

    const directory = await storage.connectionsDirectory()
    // No remote Space, so no container URL: such a session delegates nothing.
    expect(directory.spaceUrl).toBeUndefined()
    await recordGrants({
      ...directory,
      did: AGENT,
      kind: 'app',
      grants: [],
      appKey: 'z1AppKeyResourceId'
    })

    const listing = await readConnections(directory)
    expect(listing?.entries).toHaveLength(1)
    expect(listing?.entries[0]?.entry).toMatchObject({
      kind: 'app',
      id: AGENT,
      appKey: 'z1AppKeyResourceId',
      grants: []
    })
    // The id is keyed by the blinded-index key the local mint installed on
    // the directory's descriptor, which the vault KAK unwraps. The expected
    // key is resolved here from the minted descriptor, apart from the key
    // the session handed out.
    expect(storage.strandedCollectionIds).not.toContain('connections')
    const descriptor = await persistence
      .descriptorCache({ scope: `local:${user.id}` })
      .readDescriptor({ collectionId: 'connections' })
    const mintedKey = await resolveHmacKey({
      encryption: descriptor!,
      keyAgreementKey: owner.keyAgreementKey,
      required: true
    })
    expect(listing?.entries[0]?.resourceId).toBe(
      await connectionResourceId({ hmacKey: mintedKey!, did: AGENT })
    )
  })

  it('mints every local encrypted collection with a blinded-index key', async () => {
    const owner = await generateVaultKeys()
    const user: User = { id: 'did:key:z6MkLocalMintUser' }
    const persistence = browserLocalSessionPersistence({ persistCaches: false })
    await StorageManager.initStorageClients({
      user,
      session: {
        profile: {
          ...owner,
          keyAgent: { id: 'did:key:z6MkLocalAgent' }
        } as unknown as ControllerProfile,
        persistence
      },
      isGuest: true,
      storage: getRxStorageMemory()
    })
    const cache = persistence.descriptorCache({ scope: `local:${user.id}` })
    for (const collectionId of [
      'private-credentials',
      'wallet-activity',
      'contacts',
      'contacts-history',
      'app-keys',
      'connections'
    ]) {
      const descriptor = await cache.readDescriptor({ collectionId })
      expect(descriptor?.epochs?.length, collectionId).toBe(1)
      await expect(
        resolveHmacKey({
          encryption: descriptor!,
          keyAgreementKey: owner.keyAgreementKey,
          required: true
        }),
        collectionId
      ).resolves.not.toBeNull()
    }
  })
})
