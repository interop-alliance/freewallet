/**
 * Unit tests for StorageManager's multi-recipient collection sharing surface:
 * `shareCollection` / `unshareCollection` / `listCollectionShares`, plus the
 * transparent unknown-epoch descriptor refresh on `listCredentials`.
 *
 * Every encrypted collection's descriptor is log-governed, so the descriptor
 * state lives in the in-memory descriptor stores (`memoryDescriptorStores`,
 * one per collection, with real create-if-absent and compare-and-swap
 * semantics) that stand in for each collection's governing log -- the real
 * `initRecipients` / `addRecipient` / `removeRecipient` exercise their real
 * write path against them, and `StorageManager` reaches them through the
 * injected `descriptorLogs` seam. The remote WAS store is a structural fake
 * around that: a `revoke` recorder on the Space handle, the raw synced-resource
 * bodies, the stored `/meta` values, and a `collectionEncryption` served from
 * the same stores (as the server derives a Collection Description's
 * `encryption` member from the governing log). The local store is a real
 * BrowserStore on memory RxDB, and the ciphers are real EDV codecs over
 * freshly generated X25519 keys, so an epoch written under one descriptor
 * really fails to decrypt under a stale one.
 *
 * @vitest-environment node
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import {
  AlreadyRevokedError,
  ValidationError,
  type CollectionEncryption,
  type IZcap,
  type ResourceMetadataCustom,
  type Space
} from '@interop/was-client'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import {
  addRecipient,
  createEdvEncryption,
  ensureFirstEpoch,
  initRecipients,
  removeRecipient,
  resolveHmacKey,
  x25519RecipientFromDidKey,
  type RecipientPublicKey
} from '@interop/was-client/edv'
import {
  descriptorLogsFrom,
  memoryDescriptorStores,
  type MemoryDescriptorStores
} from '../../tests/unit/fakeDescriptorStores'
import { mintRecordEncryption } from '@/session/recordEnvelope'
import {
  browserLocalSessionPersistence,
  inMemorySessionPersistence,
  transientSessionStores,
  type SessionPersistence
} from '@/session/persistence'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import type { ControllerProfile, User } from '@/types/auth'
import { cidFrom } from '@interop/was-client/sync'
import type { Json } from '@interop/was-sync'
import { BrowserStore } from './browserStore'
import {
  createEdvDocCipher,
  ownerRecipient,
  type DocCipher
} from '@interop/was-client/edv'
import { revokeAgentAccess, type AccountSignerCheck } from '@/lib/connectedApps'
import { StorageManager } from './storageManager'
import {
  accountSignerCheck,
  ENROLLED_SIGNER,
  GONE_SIGNER,
  LADDER_SIGNER,
  recordedGrant,
  SIGNER_FIXTURE
} from '@interop/wallet-core/testing'
import { EXTERNAL_REQUEST_ORIGIN } from '@/lib/walletRequest/externalRequest'
import type { WASRemoteStore } from './wasRemoteStore'
import type { StorageCollection } from '@/lib/storage'

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

/**
 * A generated X25519 key pair plus the single-key resolver the session profile
 * supplies alongside it.
 */
async function generateKey(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}> {
  const key = await X25519KeyAgreementKey2020.generate({
    controller: 'did:key:z6MkTestController'
  })
  const keyResolver: IKeyResolver = async () => ({
    id: key.id!,
    type: key.type,
    publicKeyMultibase: key.publicKeyMultibase
  })
  return { keyAgreementKey: key as IKeyAgreementKey, keyResolver }
}

/**
 * An App Connect app's identity: a seed-derived Ed25519 `did:key` subject, the
 * epoch-recipient key App Connect provisioning derives from it, and the
 * matching private key-agreement key, so a test can both write the roster
 * entry the way production does and try to read with it afterwards.
 */
async function generateAppIdentity(): Promise<{
  did: `did:${string}`
  recipient: RecipientPublicKey
  keyAgreementKey: IKeyAgreementKey
}> {
  const key = await Ed25519VerificationKey.generate()
  const did: `did:${string}` = `did:key:${key.fingerprint()}`
  const keyAgreementKey = X25519KeyAgreementKey2020.fromEd25519({
    controller: did,
    publicKeyMultibase: key.publicKeyMultibase,
    privateKeyMultibase: key.privateKeyMultibase
  })
  return {
    did,
    recipient: x25519RecipientFromDidKey({ did }),
    keyAgreementKey: keyAgreementKey as IKeyAgreementKey
  }
}

/**
 * A structural fake of WASRemoteStore over the in-memory descriptor stores and
 * a revoke-recording Space handle. `collectionEncryption` is served from those
 * same stores -- the server derives a Collection Description's `encryption`
 * member from the collection's governing log -- so a recipient op through a
 * store is visible to a later descriptor read.
 */
function makeFakeRemote({
  stores,
  revoke
}: {
  stores: MemoryDescriptorStores
  /**
   * Stands in for the Space handle's `revoke` once the POST is recorded, so
   * a test can make the server refuse it.
   */
  revoke?: (zcap: unknown) => Promise<void>
}): {
  remoteStore: WASRemoteStore
  revoked: unknown[]
  /**
   * The collection ids `ensureGovernedCollection` was asked for, in order.
   */
  governed: string[]
  seedResource(options: {
    logicalKey: string
    resourceId: string
    body: Json
  }): void
  setCollectionMeta(options: {
    collectionId: string
    meta: { custom?: unknown } | undefined
  }): void
  /**
   * The Space's collection listing, as `listCollections` serves it -- the app
   * attribution (`generator`) the revocation's candidate derivation reads.
   */
  setCollections(items: StorageCollection[]): void
  /**
   * Stands a collection with no `encryption` descriptor, holding the given
   * resource ids, as a plaintext collection the Space already carries.
   */
  standPlaintextCollection(options: {
    collectionId: string
    resourceIds: string[]
  }): void
} {
  const spaceId = 's-space'
  const storageServerUrl = 'https://was.example'
  // The canonical container form, which the path builders emit.
  const spaceUrl = 'https://was.example/space/s-space/'
  const revoked: unknown[] = []
  const governed: string[] = []
  // The stored `/meta` value per collection, as `collectionMeta` serves it.
  const metas = new Map<string, { custom?: unknown }>()
  // The Space's collection listing; empty unless a test seeds one.
  let collections: StorageCollection[] = []
  // Standing plaintext collections and their resource ids.
  const plaintext = new Map<string, string[]>()
  // The raw synced-resource bodies keyed by logical collection key -- what the
  // remote-direct backend reads/writes over `listSyncedDocuments` etc.
  const logicalToId: Record<string, string> = {
    privateCredentials: 'private-credentials',
    walletActivity: 'wallet-activity',
    publicCredentials: 'public-credentials'
  }
  const resources = new Map<string, Map<string, Json>>()
  const resourcesFor = (logicalKey: string): Map<string, Json> => {
    const id = logicalToId[logicalKey] ?? logicalKey
    let map = resources.get(id)
    if (!map) {
      map = new Map<string, Json>()
      resources.set(id, map)
    }
    return map
  }
  const space = {
    async revoke(zcap: unknown) {
      revoked.push(zcap)
      await revoke?.(zcap)
    }
  } as unknown as Space
  const remoteStore = {
    spaceId,
    spaceUrl,
    storageServerUrl,
    collectionTargetUrl: (collectionId: string) =>
      `${spaceUrl}${collectionId}/`,
    async collectionEncryption({ collectionId }: { collectionId: string }) {
      return stores.descriptorOf(collectionId)
    },
    async listCollections() {
      return collections
    },
    async listCollectionPublicStates() {
      return collections.map(({ id, isPublic }) => ({
        id,
        isPublic: !!isPublic
      }))
    },
    async collectionMeta({ collectionId }: { collectionId: string }) {
      // The real store reports "nothing stored" as undefined; a collection a
      // test never seeded metadata for has no index schema to install.
      return metas.get(collectionId)
    },
    async collectionMetadata({ collectionId }: { collectionId: string }) {
      if (plaintext.has(collectionId)) {
        return {}
      }
      const encryption = stores.descriptorOf(collectionId)
      return encryption ? { encryption } : undefined
    },
    collectionHandle({ collectionId }: { collectionId: string }) {
      return {
        async list() {
          return {
            items: (plaintext.get(collectionId) ?? []).map(id => ({ id }))
          }
        }
      }
    },
    async ensureGovernedCollection({ id }: { id: string }) {
      // A bare create: the descriptor is the governing log's business, so
      // this only records that the collection was ensured to exist.
      governed.push(id)
    },
    spaceHandle() {
      return space
    },
    async listSyncedDocuments({ logicalKey }: { logicalKey: string }) {
      return [...resourcesFor(logicalKey)].map(([id, data]) => ({ id, data }))
    },
    async getSyncedResource({
      logicalKey,
      resourceId
    }: {
      logicalKey: string
      resourceId: string
    }) {
      return resourcesFor(logicalKey).get(resourceId)
    },
    async putSyncedResource({
      logicalKey,
      resourceId,
      body
    }: {
      logicalKey: string
      resourceId: string
      body: Json
    }) {
      const map = resourcesFor(logicalKey)
      if (map.has(resourceId)) {
        return { created: false }
      }
      map.set(resourceId, body)
      return { created: true }
    },
    async deleteSyncedResource({
      logicalKey,
      resourceId
    }: {
      logicalKey: string
      resourceId: string
    }) {
      resourcesFor(logicalKey).delete(resourceId)
    }
  } as unknown as WASRemoteStore
  const seedResource = ({
    logicalKey,
    resourceId,
    body
  }: {
    logicalKey: string
    resourceId: string
    body: Json
  }) => {
    resourcesFor(logicalKey).set(resourceId, body)
  }
  const setCollectionMeta = ({
    collectionId,
    meta
  }: {
    collectionId: string
    meta: { custom?: unknown } | undefined
  }) => {
    if (meta === undefined) {
      metas.delete(collectionId)
      return
    }
    metas.set(collectionId, meta)
  }
  const setCollections = (items: StorageCollection[]) => {
    collections = items
  }
  const standPlaintextCollection = ({
    collectionId,
    resourceIds
  }: {
    collectionId: string
    resourceIds: string[]
  }) => {
    plaintext.set(collectionId, resourceIds)
  }
  return {
    remoteStore,
    revoked,
    governed,
    seedResource,
    setCollectionMeta,
    setCollections,
    standPlaintextCollection
  }
}

/**
 * Builds the encrypted-collection ciphers over the owner's keys and the given
 * per-collection descriptors (keyed by WAS collection id), mirroring what
 * StorageManager builds internally. Every encrypted collection carries a
 * key-epoch roster from birth, so a collection the test supplies no
 * descriptor for gets a local one-epoch descriptor wrapped to the owner --
 * standing in for what provisioning would have installed.
 */
async function buildCiphers(
  owner: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver },
  descriptors: Record<string, CollectionEncryption>
): Promise<Record<string, DocCipher>> {
  const specs: Array<[string, string]> = [
    ['privateCredentials', 'private-credentials'],
    ['walletActivity', 'wallet-activity']
  ]
  const entries = await Promise.all(
    specs.map(async ([key, id]) => [
      key,
      await createEdvDocCipher({
        keyAgreementKey: owner.keyAgreementKey,
        keyResolver: owner.keyResolver,
        collectionId: id,
        encryption:
          descriptors[id] ??
          (await mintRecordEncryption({
            keyAgreementKey: owner.keyAgreementKey
          }))
      })
    ])
  )
  return Object.fromEntries(entries)
}

/**
 * A one-attribute index schema, as `collection.declareIndex()` would have
 * persisted it into the collection's stored metadata.
 */
const INDEX_SCHEMA = {
  revision: 1,
  indexes: [{ attribute: 'content.issuer', addedIn: 1 }]
}

/**
 * Mints the collection's stored `/meta` value the way a Collection-handle
 * `declareIndex` would: the schema encrypted into a metadata envelope by the
 * same EDV codec, AEAD-bound to the collection id, under the collection's own
 * descriptor and keys. What `WASRemoteStore.collectionMeta` would hand back.
 *
 * @param options {object}
 * @param options.collectionId {string}
 * @param options.encryption {CollectionEncryption}
 * @param options.keys {object}   the owner's key material
 * @param [options.schema] {object}   defaults to {@link INDEX_SCHEMA}
 * @returns {Promise<{ custom: unknown }>}
 */
async function mintCollectionMeta({
  collectionId,
  encryption,
  keys,
  schema = INDEX_SCHEMA
}: {
  collectionId: string
  encryption: CollectionEncryption
  keys: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  schema?: typeof INDEX_SCHEMA
}): Promise<{ custom: unknown }> {
  const provider = createEdvEncryption({ resolveKeys: async () => keys })
  const codec = await provider.codecFor({
    spaceId: 'local',
    collectionId,
    scheme: 'edv',
    encryption
  })
  if (!codec) {
    throw new Error(`No codec for collection "${collectionId}".`)
  }
  const { custom } = await codec.encodeMeta({
    // The same cast was-client's own declareIndex applies: the index schema
    // rides inside `custom` beyond the declared `name` / `tags` members.
    custom: { indexSchema: schema } as ResourceMetadataCustom,
    // The collection's own stored metadata, so the envelope is AEAD-bound to
    // the collection rather than to a resource id.
    slot: { kind: 'collection' }
  })
  return { custom }
}

/**
 * The blinded index entries of a stored EDV envelope.
 *
 * @param envelope {unknown}
 * @returns {Array<Record<string, unknown>>}
 */
function indexedOf(envelope: unknown): Array<Record<string, unknown>> {
  return (
    (envelope as { indexed?: Array<Record<string, unknown>> }).indexed ?? []
  )
}

/**
 * The EDV envelopes stored in the local `private-credentials` replica.
 *
 * @param localStore {BrowserStore}
 * @returns {Promise<unknown[]>}
 */
async function storedCredentialEnvelopes(
  localStore: BrowserStore
): Promise<unknown[]> {
  const docs = await localStore.rxCollection('privateCredentials').find().exec()
  return docs.map(doc => (doc.toJSON() as { data: unknown }).data)
}

/**
 * Installs epoch[0] (the owner as recipient zero) as the governing-log genesis
 * of each standard encrypted collection, as the shared provisioning two-step
 * would have -- `shareCollection` now assumes every encrypted collection
 * already carries its epochs and always `addRecipient`s. Returns the
 * descriptors (keyed by WAS collection id) to build the ciphers and seed the
 * StorageManager with, so a mid-test cipher rebuild keeps every collection
 * readable. `blindedIndex` mints each collection's blinded-index HMAC key
 * alongside epoch[0], as wallet provisioning does.
 */
async function provisionGovernedCollections(
  owner: { keyAgreementKey: IKeyAgreementKey },
  stores: MemoryDescriptorStores,
  { blindedIndex = false }: { blindedIndex?: boolean } = {}
): Promise<Record<string, CollectionEncryption>> {
  const descriptors: Record<string, CollectionEncryption> = {}
  for (const id of ['private-credentials', 'wallet-activity']) {
    const { descriptor } = await ensureFirstEpoch({
      store: stores.storeFor(id),
      recipients: [ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })],
      blindedIndex
    })
    descriptors[id] = descriptor
  }
  return descriptors
}

/**
 * A stub zcapClient whose `delegate` records its arguments and returns a
 * distinct stub zcap document per call.
 */
function makeFakeZcapClient(): {
  zcapClient: ControllerProfile['zcapClient']
  calls: Array<Record<string, unknown>>
} {
  const calls: Array<Record<string, unknown>> = []
  const zcapClient = {
    async delegate(options: Record<string, unknown>) {
      calls.push(options)
      const expires = options.expires
      return {
        id: `urn:zcap:delegated:${calls.length}`,
        invocationTarget: options.invocationTarget,
        controller: options.controller,
        allowedAction: options.allowedActions,
        expires: expires instanceof Date ? expires.toISOString() : expires
      }
    }
  } as unknown as ControllerProfile['zcapClient']
  return { zcapClient, calls }
}

let userCounter = 0
const openStores: BrowserStore[] = []

async function initLocalStore(
  ciphers: Record<string, DocCipher>
): Promise<{ localStore: BrowserStore; user: User }> {
  userCounter += 1
  const user: User = {
    id: `did:key:z6MkShareUser${userCounter}`,
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
 * An owner profile: the vault keys, a stub delegation signer, and a truthy
 * `keyAgent` (the root key the share/unshare guards require for delegation).
 */
function makeProfile(
  owner: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver },
  zcapClient: ControllerProfile['zcapClient']
): ControllerProfile {
  return {
    keyAgreementKey: owner.keyAgreementKey,
    keyResolver: owner.keyResolver,
    zcapClient,
    keyAgent: { id: 'did:key:z6MkOwnerAgent' },
    persistence: browserLocalSessionPersistence()
  } as unknown as ControllerProfile
}

/**
 * The JWE-recipient kids of a descriptor's current epoch roster.
 */
function currentEpochKids(descriptor: CollectionEncryption): string[] {
  const epoch = descriptor.epochs?.find(
    entry => entry.id === descriptor.currentEpoch
  )
  return (epoch?.recipients ?? []).map(recipient => recipient.header.kid)
}

/**
 * The JWE-recipient kids of a descriptor's blinded-index HMAC key wrap set.
 */
function hmacKids(descriptor: CollectionEncryption): string[] {
  return (descriptor.hmac?.recipients ?? []).map(
    recipient => recipient.header.kid
  )
}

/**
 * Resolves a blinding key with the given key-agreement key, returning the
 * refusal instead of throwing so a test can assert on its `name` (errors cross
 * a package boundary here, so they are matched by name, never `instanceof`).
 */
async function resolveHmacOutcome({
  descriptor,
  keyAgreementKey
}: {
  descriptor: CollectionEncryption
  keyAgreementKey: IKeyAgreementKey
}): Promise<{ id?: string; errorName?: string }> {
  try {
    const key = await resolveHmacKey({
      encryption: descriptor,
      keyAgreementKey,
      // A current recipient's view: an entry this key cannot unwrap is a
      // refusal rather than a silently unindexed cipher.
      required: true
    })
    return { id: key?.id }
  } catch (err) {
    return { errorName: (err as Error).name }
  }
}

/**
 * An in-memory persistence strategy, whose descriptor cache a test can read
 * back in the node environment (the browser-local tier's rides localStorage).
 */
function transientPersistence(): ReturnType<typeof inMemorySessionPersistence> {
  return inMemorySessionPersistence({
    stores: transientSessionStores(),
    clientAnnex: {
      clientAnnexDid: 'did:webvh:example:annex',
      invocationCapability: {} as IZcap
    }
  })
}

afterEach(async () => {
  for (const store of openStores) {
    await store.wipeStorage()
  }
  openStores.length = 0
})

/**
 * Shares a collection the way the request path does: signs the pull zcap
 * with `delegateShareGrant`, then escrows and records it with
 * `shareCollection`.
 *
 * @param storage {StorageManager}
 * @param options {object}   `shareCollection`'s options, with the grantee
 *   `controller` in place of the signed `zcap`
 * @returns {Promise<object>}   the new descriptor and the signed zcap
 */
async function shareWith(
  storage: StorageManager,
  {
    controller,
    ...options
  }: Omit<Parameters<StorageManager['shareCollection']>[0], 'zcap'> & {
    controller: string
  }
) {
  const zcap = await storage.delegateShareGrant({
    profile: options.profile,
    collectionId: options.collectionId,
    controller
  })
  const { descriptor } = await storage.shareCollection({ ...options, zcap })
  return { descriptor, zcap }
}

describe('StorageManager.shareCollection', () => {
  it('refuses a zcap that is not read-only on the shared collection, escrowing nothing', async () => {
    const owner = await generateKey()
    const reader = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const { zcapClient } = makeFakeZcapClient()
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    const profile = makeProfile(owner, zcapClient)
    const zcap = await storage.delegateShareGrant({
      profile,
      collectionId: 'private-credentials',
      controller: 'did:key:z6MkReader'
    })
    const before = stores.descriptorOf('private-credentials')
    const share = (overrides: Record<string, unknown>) =>
      storage.shareCollection({
        profile,
        user,
        collectionId: 'private-credentials',
        recipient: ownerRecipient({ keyAgreementKey: reader.keyAgreementKey }),
        zcap: { ...zcap, ...overrides }
      })

    await expect(share({ allowedAction: ['GET', 'PUT'] })).rejects.toThrow(
      'read-only zcap'
    )
    await expect(share({ allowedAction: undefined })).rejects.toThrow(
      'read-only zcap'
    )
    await expect(
      share({ invocationTarget: `${zcap.invocationTarget}other/` })
    ).rejects.toThrow('read-only zcap')
    expect(stores.descriptorOf('private-credentials')).toEqual(before)
    expect(
      (await storage.listHistoryItems()).some(({ doc }) =>
        doc.type?.includes('CollectionShare')
      )
    ).toBe(false)
  })

  it('first share escrows the reader into the provisioned epoch and delegates a GET/HEAD zcap', async () => {
    const owner = await generateKey()
    const reader = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const { zcapClient, calls } = makeFakeZcapClient()
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    const { descriptor } = await shareWith(storage, {
      profile: makeProfile(owner, zcapClient),
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: reader.keyAgreementKey }),
      controller: 'did:key:z6MkReader'
    })

    // Read axis: still the one provisioned epoch, and both the owner
    // (recipient zero) and the new reader are on its roster. The returned
    // descriptor is the one the governing log now holds -- the escrow is one
    // signed append, not a local edit.
    expect(stores.descriptorOf('private-credentials')).toEqual(descriptor)
    expect(stores.writes).toContain('private-credentials')
    expect(descriptor.epochs).toHaveLength(1)
    expect(descriptor.currentEpoch).toBeDefined()
    expect(currentEpochKids(descriptor)).toEqual(
      expect.arrayContaining([
        owner.keyAgreementKey.id,
        reader.keyAgreementKey.id
      ])
    )

    // Pull axis: exactly one read-only delegation on the collection URL.
    expect(calls).toHaveLength(1)
    expect(calls[0].allowedActions).toEqual(['GET', 'HEAD'])
    expect(calls[0].controller).toBe('did:key:z6MkReader')
    expect(calls[0].invocationTarget).toBe(
      'https://was.example/space/s-space/private-credentials/'
    )

    // The share was recorded (with the delegated zcap for later revocation).
    const history = await storage.listHistoryItems()
    const shareEntry = history.find(({ doc }) =>
      doc.type?.includes('CollectionShare')
    )
    expect(shareEntry).toBeDefined()
    expect(
      (shareEntry!.doc.object as { zcap?: { id?: string } }).zcap?.id
    ).toBe('urn:zcap:delegated:1')
  })

  it('a second share adds a reader without rotating the epoch', async () => {
    const owner = await generateKey()
    const readerA = await generateKey()
    const readerB = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const { zcapClient } = makeFakeZcapClient()
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    const profile = makeProfile(owner, zcapClient)

    const { descriptor: descriptor1 } = await shareWith(storage, {
      profile,
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: readerA.keyAgreementKey }),
      controller: 'did:key:z6MkReaderA'
    })
    const { descriptor: descriptor2 } = await shareWith(storage, {
      profile,
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: readerB.keyAgreementKey }),
      controller: 'did:key:z6MkReaderB'
    })

    // Adds are cheap: the current epoch is unchanged, but the roster grew.
    expect(descriptor2.currentEpoch).toBe(descriptor1.currentEpoch)
    expect(descriptor2.epochs).toHaveLength(1)
    expect(currentEpochKids(descriptor2)).toEqual(
      expect.arrayContaining([
        owner.keyAgreementKey.id,
        readerA.keyAgreementKey.id,
        readerB.keyAgreementKey.id
      ])
    )
  })
})

describe('StorageManager.unshareCollection', () => {
  it('rotates the epoch and revokes the recorded zcap(s)', async () => {
    const owner = await generateKey()
    const reader = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore, revoked } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const { zcapClient } = makeFakeZcapClient()
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    const profile = makeProfile(owner, zcapClient)

    const { descriptor: shared } = await shareWith(storage, {
      profile,
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: reader.keyAgreementKey }),
      controller: 'did:key:z6MkReader'
    })

    const rotated = await storage.unshareCollection({
      profile,
      user,
      collectionId: 'private-credentials',
      recipientId: reader.keyAgreementKey.id!
    })

    // Read axis: the epoch rotated and the removed reader is off the new
    // roster, as the governing log now holds it.
    expect(stores.descriptorOf('private-credentials')).toEqual(rotated)
    expect(rotated.currentEpoch).not.toBe(shared.currentEpoch)
    expect(currentEpochKids(rotated)).toEqual([owner.keyAgreementKey.id])
    expect(currentEpochKids(rotated)).not.toContain(reader.keyAgreementKey.id)

    // Pull axis: the recorded delegated zcap was handed to the revoke recorder.
    expect(revoked).toEqual([
      expect.objectContaining({ id: 'urn:zcap:delegated:1' })
    ])

    // The unshare was recorded (no zcap on it).
    const history = await storage.listHistoryItems()
    expect(
      history.some(({ doc }) => doc.type?.includes('CollectionUnshare'))
    ).toBe(true)
  })

  it('adopts the rotation but records no unshare when the server refuses a live grant', async () => {
    const owner = await generateKey()
    const reader = await generateKey()
    const stores = memoryDescriptorStores()
    // A refusal the verified document cannot explain: the grant may still be
    // live, so it is no revocation.
    let refuse = true
    const { remoteStore, revoked } = makeFakeRemote({
      stores,
      revoke: async () => {
        if (refuse) {
          throw new ValidationError('chain does not verify', { status: 400 })
        }
      }
    })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const { zcapClient } = makeFakeZcapClient()
    // The in-memory tier, so the adopted descriptor is readable back here.
    const persistence = transientPersistence()
    const storage = new StorageManager({
      persistence,
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    const profile = makeProfile(owner, zcapClient)
    await shareWith(storage, {
      profile,
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: reader.keyAgreementKey }),
      controller: 'did:key:z6MkReader'
    })
    const unshared = async () =>
      (await storage.listHistoryItems()).some(({ doc }) =>
        doc.type?.includes('CollectionUnshare')
      )

    await expect(
      storage.unshareCollection({
        profile,
        user,
        collectionId: 'private-credentials',
        recipientId: reader.keyAgreementKey.id!
      })
    ).rejects.toMatchObject({ name: 'ValidationError' })

    // The rotation landed and this session adopted it.
    const rotated = stores.descriptorOf('private-credentials')!
    expect(currentEpochKids(rotated)).toEqual([owner.keyAgreementKey.id])
    const cached = await persistence
      .descriptorCache({ scope: remoteStore.spaceId })
      .readDescriptor({ collectionId: 'private-credentials' })
    expect(cached?.currentEpoch).toBe(rotated.currentEpoch)
    // No unshare is recorded, so the share stays revocable: the panel still
    // lists the reader, though the current epoch no longer does.
    expect(await unshared()).toBe(false)
    const listed = async () =>
      (
        await storage.listCollectionShares({
          collectionId: 'private-credentials'
        })
      ).map(share => share.recipientId)
    expect(await listed()).toEqual([reader.keyAgreementKey.id])

    // A retry re-runs the pull without minting another epoch.
    refuse = false
    const retried = await storage.unshareCollection({
      profile,
      user,
      collectionId: 'private-credentials',
      recipientId: reader.keyAgreementKey.id!
    })
    expect(retried.epochs).toHaveLength(rotated.epochs!.length)
    expect(revoked).toHaveLength(2)
    expect(await unshared()).toBe(true)
    // The recorded unshare supersedes the share, so the reader is gone.
    expect(await listed()).toEqual([])
  })

  it('records the unshare when the server answers AlreadyRevokedError', async () => {
    const owner = await generateKey()
    const reader = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({
      stores,
      revoke: async () => {
        throw new AlreadyRevokedError('already revoked', { status: 400 })
      }
    })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const { zcapClient } = makeFakeZcapClient()
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    const profile = makeProfile(owner, zcapClient)
    await shareWith(storage, {
      profile,
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: reader.keyAgreementKey }),
      controller: 'did:key:z6MkReader'
    })

    await storage.unshareCollection({
      profile,
      user,
      collectionId: 'private-credentials',
      recipientId: reader.keyAgreementKey.id!
    })

    const history = await storage.listHistoryItems()
    expect(
      history.some(({ doc }) => doc.type?.includes('CollectionUnshare'))
    ).toBe(true)
  })

  it('escrows the grantee into the blinding-key wrap set and drops it on unshare', async () => {
    const owner = await generateKey()
    const reader = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores, {
      blindedIndex: true
    })
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const { zcapClient } = makeFakeZcapClient()
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    const profile = makeProfile(owner, zcapClient)

    const { descriptor: shared } = await shareWith(storage, {
      profile,
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: reader.keyAgreementKey }),
      controller: 'did:key:z6MkReader'
    })

    // The share covers the blinded index too: the grantee unwraps the key.
    expect(hmacKids(shared)).toContain(reader.keyAgreementKey.id)
    expect(
      await resolveHmacOutcome({
        descriptor: shared,
        keyAgreementKey: reader.keyAgreementKey
      })
    ).toEqual({ id: shared.hmac?.id })

    const rotated = await storage.unshareCollection({
      profile,
      user,
      collectionId: 'private-credentials',
      recipientId: reader.keyAgreementKey.id!
    })

    // Removal drops the wrap entry only: the epoch rotated, the key did not.
    expect(rotated.hmac?.id).toBe(shared.hmac?.id)
    expect(hmacKids(rotated)).not.toContain(reader.keyAgreementKey.id)
    expect(hmacKids(rotated)).toContain(owner.keyAgreementKey.id)
  })

  it('lists current shares from the descriptor roster minus the owner', async () => {
    const owner = await generateKey()
    const reader = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const { zcapClient } = makeFakeZcapClient()
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    await shareWith(storage, {
      profile: makeProfile(owner, zcapClient),
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: reader.keyAgreementKey }),
      controller: 'did:key:z6MkReader'
    })

    const shares = await storage.listCollectionShares({
      collectionId: 'private-credentials'
    })
    expect(shares).toHaveLength(1)
    expect(shares[0].recipientId).toBe(reader.keyAgreementKey.id)
    expect(shares[0].controller).toBe('did:key:z6MkReader')
  })

  it('carries a connected app name and origin through to the listing', async () => {
    const owner = await generateKey()
    const reader = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const { zcapClient } = makeFakeZcapClient()
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    const { zcap } = await shareWith(storage, {
      profile: makeProfile(owner, zcapClient),
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: reader.keyAgreementKey }),
      controller: 'did:key:z6MkReader',
      app: { name: 'Text Editor', origin: 'https://app.example' }
    })

    // The pull zcap comes back to the caller (it goes in the response VP).
    expect(zcap.id).toBe('urn:zcap:delegated:1')

    const shares = await storage.listCollectionShares({
      collectionId: 'private-credentials'
    })
    expect(shares[0]).toMatchObject({
      appName: 'Text Editor',
      appOrigin: 'https://app.example'
    })
  })
})

describe('StorageManager.revokeAppGrants', () => {
  const APP_ORIGIN = 'https://app.example'
  const APP_SUBJECT = SIGNER_FIXTURE.appDid

  /**
   * A `StorageManager` over a revoke-recording remote, for the tests that
   * exercise the revocation policy alone.
   */
  async function revokeStorage(
    revoke: (zcap: unknown) => Promise<void>,
    signerCheck: () => Promise<AccountSignerCheck | undefined> = async () =>
      undefined
  ) {
    const owner = await generateKey()
    const stores = memoryDescriptorStores()
    const remoteStore = makeRevokeRemote(revoke)
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors,
      signerCheck
    })
    return { storage, user }
  }

  const { annexDid: ANNEX_DID, oldAnnexDid: OLD_ANNEX_DID } = SIGNER_FIXTURE
  const SIGNER_CHECK = accountSignerCheck()

  /**
   * A remote store whose `spaceHandle().revoke` is the supplied recorder.
   * Revocation touches no descriptor, so this store carries the Space handle
   * and its identifiers alone.
   */
  function makeRevokeRemote(
    revoke: (zcap: unknown) => Promise<void>
  ): WASRemoteStore {
    const space = { revoke } as unknown as Space
    return {
      spaceId: 's-space',
      spaceUrl: 'https://was.example/space/s-space/',
      spaceHandle() {
        return space
      }
    } as unknown as WASRemoteStore
  }

  async function seedLogin(
    storage: StorageManager,
    user: User,
    grants: Array<{
      id: string
      target: string
      allowedActions: string[]
      expires: string
      zcap?: IZcap
    }>
  ) {
    await storage.addHistoryLogin({
      user,
      origin: APP_ORIGIN,
      grants,
      appConnect: { name: 'Example App', firstRun: true }
    })
  }

  it('revokes the active grant and skips expired and legacy entries', async () => {
    const owner = await generateKey()
    const revoked: unknown[] = []
    const stores = memoryDescriptorStores()
    const remoteStore = makeRevokeRemote(async zcap => {
      revoked.push(zcap)
    })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    const future = new Date(Date.now() + 1_000_000).toISOString()
    const past = new Date(Date.now() - 1_000_000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-active',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET', 'HEAD'],
        expires: future,
        zcap: recordedGrant({ id: 'z-active', expires: future })
      },
      {
        id: 'g-expired',
        target: 'https://was.example/space/x/wallet-activity',
        allowedActions: ['GET'],
        expires: past,
        zcap: recordedGrant({ id: 'z-expired', expires: past })
      },
      {
        id: 'g-legacy',
        target: 'https://was.example/space/x/public-credentials',
        allowedActions: ['GET'],
        expires: future
      }
    ])

    const outcome = await storage.revokeAppGrants({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    expect(outcome).toEqual({ revoked: 1, withdrawn: 1, skipped: 2 })
    expect(revoked).toHaveLength(1)
    expect((revoked[0] as { id: string }).id).toBe('z-active')
  })

  it('skips grants delegated to a different controller', async () => {
    const owner = await generateKey()
    const revoked: unknown[] = []
    const stores = memoryDescriptorStores()
    const remoteStore = makeRevokeRemote(async zcap => {
      revoked.push(zcap)
    })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    const future = new Date(Date.now() + 1_000_000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-other',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: recordedGrant({
          id: 'z-other',
          controller: 'did:key:z6MkSomeoneElse',
          expires: future
        })
      }
    ])

    const outcome = await storage.revokeAppGrants({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    expect(outcome).toEqual({ revoked: 0, withdrawn: 0, skipped: 1 })
    expect(revoked).toHaveLength(0)
  })

  it("counts the server's AlreadyRevokedError as revoked", async () => {
    const owner = await generateKey()
    const stores = memoryDescriptorStores()
    const remoteStore = makeRevokeRemote(async () => {
      throw new AlreadyRevokedError('already revoked')
    })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    const future = new Date(Date.now() + 1_000_000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-active',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: recordedGrant({ id: 'z-active', expires: future })
      }
    ])

    const outcome = await storage.revokeAppGrants({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    // The capability is dead on the server: an earlier attempt that landed
    // it and then failed elsewhere recorded nothing, so this run counts it
    // as revoked. This run's POST did not land it, so it is not withdrawn.
    expect(outcome).toEqual({ revoked: 1, withdrawn: 0, skipped: 0 })
  })

  it.each([
    ['a 400', 400],
    ['a 415', 415]
  ])(
    'throws a plain ValidationError (%s) after the other POSTs settle',
    async (_label, status) => {
      const revoked: string[] = []
      const { storage, user } = await revokeStorage(async zcap => {
        const { id } = zcap as { id: string }
        if (id === 'z-refused') {
          throw new ValidationError('chain does not verify', { status })
        }
        // The refused POST rejects first; the sibling must still land.
        await new Promise(resolve => setTimeout(resolve, 5))
        revoked.push(id)
      })
      const future = new Date(Date.now() + 1_000_000).toISOString()

      await seedLogin(storage, user, [
        {
          id: 'g-refused',
          target: 'https://was.example/space/x/private-credentials',
          allowedActions: ['GET'],
          expires: future,
          zcap: recordedGrant({ id: 'z-refused', expires: future })
        },
        {
          id: 'g-live',
          target: 'https://was.example/space/x/public-credentials',
          allowedActions: ['GET'],
          expires: future,
          zcap: recordedGrant({ id: 'z-live', expires: future })
        }
      ])

      await expect(
        storage.revokeAppGrants({ origin: APP_ORIGIN, subjectDid: APP_SUBJECT })
      ).rejects.toMatchObject({ name: 'ValidationError', status })
      expect(revoked).toEqual(['z-live'])
    }
  )

  it('lists the grants the server confirmed revoked in revokedIds', async () => {
    const { storage, user } = await revokeStorage(async zcap => {
      if ((zcap as { id: string }).id === 'z-done') {
        throw new AlreadyRevokedError('already revoked', { status: 400 })
      }
    })
    const future = new Date(Date.now() + 1_000_000).toISOString()
    await storage.addHistoryLogin({
      user,
      origin: EXTERNAL_REQUEST_ORIGIN,
      grants: [
        {
          id: 'g-done',
          target: 'https://was.example/space/x/private-credentials',
          allowedActions: ['GET'],
          expires: future,
          zcap: recordedGrant({ id: 'z-done', expires: future })
        },
        {
          id: 'g-live',
          target: 'https://was.example/space/x/public-credentials',
          allowedActions: ['GET'],
          expires: future,
          zcap: recordedGrant({ id: 'z-live', expires: future })
        }
      ]
    })

    const outcome = await storage.revokeAgentGrants({
      controller: APP_SUBJECT
    })

    expect(outcome).toEqual({
      revoked: 2,
      withdrawn: 1,
      skipped: 0,
      revokedIds: ['z-done', 'z-live']
    })
  })

  it('counts a grant the rotation already revoked without a second POST', async () => {
    const posted: string[] = []
    const { storage, user } = await revokeStorage(async zcap => {
      posted.push((zcap as { id: string }).id)
    })
    const future = new Date(Date.now() + 1_000_000).toISOString()
    await seedLogin(storage, user, [
      {
        id: 'g-rotated',
        target: 'https://was.example/space/s-space/app-docs',
        allowedActions: ['GET'],
        expires: future,
        zcap: recordedGrant({ id: 'z-rotated', expires: future })
      },
      {
        id: 'g-live',
        target: 'https://was.example/space/s-space/public-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: recordedGrant({ id: 'z-live', expires: future })
      }
    ])

    const outcome = await storage.revokeAppGrants({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT,
      revokedByRotation: ['z-rotated']
    })

    expect(outcome).toEqual({ revoked: 2, withdrawn: 1, skipped: 0 })
    expect(posted).toEqual(['z-live'])
  })

  it('posts every unexpired grant, logging once, when the signer-check read throws', async () => {
    const posted: string[] = []
    const reads: number[] = []
    const { storage, user } = await revokeStorage(
      async zcap => {
        posted.push((zcap as { id: string }).id)
      },
      async () => {
        reads.push(1)
        throw new Error('log unreachable')
      }
    )
    const future = new Date(Date.now() + 1_000_000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-one',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: recordedGrant({ id: 'z-one', expires: future })
      },
      {
        id: 'g-two',
        target: 'https://was.example/space/x/public-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: recordedGrant({ id: 'z-two', expires: future })
      }
    ])
    const capture = captureSink()
    const removeSink = addSink(capture.sink)

    try {
      const outcome = await storage.revokeAppGrants({
        origin: APP_ORIGIN,
        subjectDid: APP_SUBJECT
      })

      expect(outcome).toEqual({ revoked: 2, withdrawn: 2, skipped: 0 })
      expect(posted.sort()).toEqual(['z-one', 'z-two'])
      expect(reads).toHaveLength(1)
      expect(
        capture.events.filter(
          event =>
            event.level === 'warn' &&
            event.msg.includes('Could not read the account key set')
        )
      ).toHaveLength(1)
    } finally {
      removeSink()
    }
  })

  it('skips a grant expired beyond the skew margin without a POST', async () => {
    const revoked: unknown[] = []
    const { storage, user } = await revokeStorage(
      async zcap => {
        revoked.push(zcap)
      },
      async () => SIGNER_CHECK
    )
    const past = new Date(Date.now() - 60 * 60 * 1000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-expired',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET'],
        expires: past,
        zcap: recordedGrant({ id: 'z-expired', expires: past })
      }
    ])

    const outcome = await storage.revokeAppGrants({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    expect(outcome).toEqual({ revoked: 0, withdrawn: 0, skipped: 1 })
    expect(revoked).toHaveLength(0)
  })

  it('reads the refusal of an annex-signed grant under a swapped generation as dead', async () => {
    const posted: string[] = []
    const { storage, user } = await revokeStorage(
      async zcap => {
        const { id } = zcap as { id: string }
        posted.push(id)
        if (id === 'z-swapped') {
          throw new ValidationError('chain does not verify', { status: 400 })
        }
      },
      async () => SIGNER_CHECK
    )
    const future = new Date(Date.now() + 1_000_000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-swapped',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: recordedGrant({
          id: 'z-swapped',
          expires: future,
          signerKeyId: `${OLD_ANNEX_DID}#z6MkVisit`,
          parent: { controller: OLD_ANNEX_DID, signerKeyId: LADDER_SIGNER }
        })
      },
      {
        id: 'g-current',
        target: 'https://was.example/space/x/public-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: recordedGrant({
          id: 'z-current',
          expires: future,
          signerKeyId: `${ANNEX_DID}#z6MkVisit`,
          parent: { controller: ANNEX_DID, signerKeyId: LADDER_SIGNER }
        })
      }
    ])

    const outcome = await storage.revokeAppGrants({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    // Both are POSTed: the document a login read is a snapshot. The
    // swapped one's refusal reads as a dead chain and counts as skipped.
    expect(outcome).toEqual({ revoked: 1, withdrawn: 1, skipped: 1 })
    expect(posted.sort()).toEqual(['z-current', 'z-swapped'])
  })

  it('reads the refusal of a grant whose generation delegation was signed by a struck key as dead', async () => {
    const posted: string[] = []
    const { storage, user } = await revokeStorage(
      async zcap => {
        posted.push((zcap as { id: string }).id)
        throw new ValidationError('chain does not verify', { status: 400 })
      },
      async () => SIGNER_CHECK
    )
    const future = new Date(Date.now() + 1_000_000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-rotted',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: recordedGrant({
          id: 'z-rotted',
          expires: future,
          signerKeyId: `${ANNEX_DID}#z6MkVisit`,
          // The pointer still names this generation; the delegation was
          // re-minted within it and its old signer struck.
          parent: {
            controller: ANNEX_DID,
            signerKeyId: GONE_SIGNER
          }
        })
      }
    ])

    const outcome = await storage.revokeAppGrants({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    expect(outcome).toEqual({ revoked: 0, withdrawn: 0, skipped: 1 })
    expect(posted).toEqual(['z-rotted'])
  })

  it('reads the refusal of an orphaned account-signed grant as dead', async () => {
    const posted: string[] = []
    const { storage, user } = await revokeStorage(
      async zcap => {
        const { id } = zcap as { id: string }
        posted.push(id)
        if (id === 'z-orphaned') {
          throw new ValidationError('chain does not verify', { status: 400 })
        }
      },
      async () => SIGNER_CHECK
    )
    const future = new Date(Date.now() + 1_000_000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-orphaned',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: recordedGrant({
          id: 'z-orphaned',
          expires: future,
          signerKeyId: GONE_SIGNER
        })
      },
      {
        id: 'g-enrolled',
        target: 'https://was.example/space/x/public-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: recordedGrant({
          id: 'z-enrolled',
          expires: future,
          signerKeyId: ENROLLED_SIGNER
        })
      }
    ])

    const outcome = await storage.revokeAppGrants({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    expect(outcome).toEqual({ revoked: 1, withdrawn: 1, skipped: 1 })
    expect(posted.sort()).toEqual(['z-enrolled', 'z-orphaned'])
  })

  it('throws the refusal of an orphaned-looking grant when no signer check is supplied', async () => {
    const { storage, user } = await revokeStorage(async () => {
      throw new ValidationError('chain does not verify', { status: 400 })
    })
    const future = new Date(Date.now() + 1_000_000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-orphaned',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: recordedGrant({
          id: 'z-orphaned',
          expires: future,
          signerKeyId: GONE_SIGNER
        })
      }
    ])

    // Nothing local can say why the server refused, so the refusal is
    // the caller's to retry.
    await expect(
      storage.revokeAppGrants({ origin: APP_ORIGIN, subjectDid: APP_SUBJECT })
    ).rejects.toMatchObject({ name: 'ValidationError' })
  })

  it('propagates any other revoke failure', async () => {
    const owner = await generateKey()
    const stores = memoryDescriptorStores()
    const remoteStore = makeRevokeRemote(async () => {
      throw new Error('server unreachable')
    })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    const future = new Date(Date.now() + 1_000_000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-active',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: recordedGrant({ id: 'z-active', expires: future })
      }
    ])

    await expect(
      storage.revokeAppGrants({ origin: APP_ORIGIN, subjectDid: APP_SUBJECT })
    ).rejects.toThrow('server unreachable')
  })

  it('is a no-op when no remote store is configured', async () => {
    const owner = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })

    const outcome = await storage.revokeAppGrants({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    expect(outcome).toEqual({ revoked: 0, withdrawn: 0, skipped: 0 })
  })
})

describe('StorageManager.provisionEncryptedCollection', () => {
  it('first provision mints an epoch with the owner and the app recipient', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore, governed } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    const descriptor = await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient: ownerRecipient({ keyAgreementKey: app.keyAgreementKey })
    })

    expect(descriptor.epochs).toHaveLength(1)
    expect(currentEpochKids(descriptor)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, app.keyAgreementKey.id])
    )
    // Epoch[0] is the collection's governing-log genesis, and the collection
    // itself was ensured to exist as a bare create.
    expect(stores.descriptorOf('app-docs')).toEqual(descriptor)
    expect(governed).toEqual(['app-docs'])
  })

  it('refuses a standing plaintext collection that holds resources', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore, governed, standPlaintextCollection } = makeFakeRemote({
      stores
    })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    standPlaintextCollection({
      collectionId: 'agent-notes',
      resourceIds: ['note-1']
    })

    await expect(
      storage.provisionEncryptedCollection({
        collectionId: 'agent-notes',
        recipient: ownerRecipient({ keyAgreementKey: app.keyAgreementKey })
      })
    ).rejects.toThrow(/already holds unencrypted resources/)
    // Nothing was written: no ensure, and no governing log was created.
    expect(governed).toEqual([])
    expect(stores.descriptorOf('agent-notes')).toBeUndefined()
  })

  it('finishes a torn provision over an empty collection with no descriptor', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore, standPlaintextCollection } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    standPlaintextCollection({ collectionId: 'agent-notes', resourceIds: [] })

    const descriptor = await storage.provisionEncryptedCollection({
      collectionId: 'agent-notes',
      recipient: ownerRecipient({ keyAgreementKey: app.keyAgreementKey })
    })

    expect(currentEpochKids(descriptor)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, app.keyAgreementKey.id])
    )
  })

  it('a reconnect after revoke re-adds the app without a second epoch', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    const recipient = ownerRecipient({
      keyAgreementKey: app.keyAgreementKey
    })

    const descriptor1 = await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient
    })
    // A revoke rotates the app off (owner alone on a fresh epoch).
    await removeRecipient({
      store: stores.storeFor('app-docs'),
      space: remoteStore.spaceHandle(),
      recipientId: app.keyAgreementKey.id!,
      revoke: []
    })
    // Reconnect: the app is escrowed back in (add, not a rotation, so the
    // roster grows but the current epoch is the post-revoke one).
    const descriptor2 = await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient
    })

    expect(descriptor1.currentEpoch).toBeDefined()
    expect(currentEpochKids(descriptor2)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, app.keyAgreementKey.id])
    )
  })

  it('is a no-op when the app is already a recipient of the current epoch', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    const recipient = ownerRecipient({
      keyAgreementKey: app.keyAgreementKey
    })

    const descriptor1 = await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient
    })
    const descriptor2 = await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient
    })

    // No rotation, no new epoch: the descriptor is unchanged.
    expect(descriptor2.currentEpoch).toBe(descriptor1.currentEpoch)
    expect(stores.descriptorOf('app-docs')?.epochs).toHaveLength(1)
    // The second provision appended nothing to the governing log: the first
    // wrote epoch[0] and then escrowed the app in, and that is all.
    expect(stores.writes.filter(id => id === 'app-docs')).toHaveLength(2)
  })

  it('installs a blinded-index HMAC key wrapped to the owner and the app', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    const descriptor = await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient: ownerRecipient({ keyAgreementKey: app.keyAgreementKey })
    })

    expect(descriptor.hmac?.id).toMatch(/^urn:uuid:/)
    expect(descriptor.hmac?.type).toBe('Sha256HmacKey2019')
    // The key is minted with epoch[0] (owner) and escrowed to the app by the
    // same `addRecipient` that put it on the epoch roster.
    expect(hmacKids(descriptor)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, app.keyAgreementKey.id])
    )
  })

  it('lets the app unwrap the blinding key from the descriptor and its own key alone', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient: ownerRecipient({ keyAgreementKey: app.keyAgreementKey })
    })

    // What an App Connect grantee holds: the descriptor served on the
    // Collection Description (derived from the governing log) and its own
    // key-agreement key -- no other material.
    const fetched = await remoteStore.collectionEncryption({
      collectionId: 'app-docs'
    })
    const outcome = await resolveHmacOutcome({
      descriptor: fetched!,
      keyAgreementKey: app.keyAgreementKey
    })
    expect(outcome.errorName).toBeUndefined()
    expect(outcome.id).toMatch(/^urn:uuid:/)
    expect(outcome.id).toBe(fetched!.hmac?.id)
  })

  it('adopts a pre-blind-index epoch roster without installing an HMAC key', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    // A collection provisioned before blind-index support: epoch[0], no `hmac`.
    const { descriptor: legacy } = await ensureFirstEpoch({
      store: stores.storeFor('app-docs'),
      recipients: [ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })]
    })
    expect(legacy.hmac).toBeUndefined()

    const descriptor = await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient: ownerRecipient({ keyAgreementKey: app.keyAgreementKey })
    })

    // The roster is adopted as it stands: the app is escrowed in, and the
    // collection stays unindexable rather than the ask being refused.
    expect(descriptor.hmac).toBeUndefined()
    expect(descriptor.currentEpoch).toBe(legacy.currentEpoch)
    expect(currentEpochKids(descriptor)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, app.keyAgreementKey.id])
    )
  })
})

describe('StorageManager.revokeAppCollectionRecipients', () => {
  const APP_ORIGIN = 'https://app.example'

  it('rotates the app off each app-provisioned collection and revokes its grant', async () => {
    const owner = await generateKey()
    const app = await generateAppIdentity()
    const stores = memoryDescriptorStores()
    const { remoteStore, revoked } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient: app.recipient
    })

    const future = new Date(Date.now() + 1_000_000).toISOString()
    const target = 'https://was.example/space/s-space/app-docs'
    await storage.addHistoryLogin({
      user,
      origin: APP_ORIGIN,
      grants: [
        {
          id: 'g-app-docs',
          target,
          allowedActions: ['GET', 'HEAD'],
          expires: future,
          zcap: recordedGrant({
            id: 'z-app-docs',
            invocationTarget: target,
            expires: future,
            controller: app.did
          })
        }
      ],
      appConnect: { name: 'Example App', firstRun: true }
    })

    const outcome = await storage.revokeAppCollectionRecipients({
      origin: APP_ORIGIN,
      subjectDid: app.did
    })

    expect(outcome).toEqual({
      collections: 1,
      rotated: 1,
      failed: 0,
      revokedIds: ['z-app-docs']
    })
    // Read axis: the app is off the new current epoch; the owner remains.
    const descriptor = await remoteStore.collectionEncryption({
      collectionId: 'app-docs'
    })
    expect(currentEpochKids(descriptor!)).toEqual([owner.keyAgreementKey.id])
    // Pull axis: the recorded grant was revoked.
    expect((revoked as Array<{ id: string }>).map(zcap => zcap.id)).toContain(
      'z-app-docs'
    )
  })

  it('rotates an app-provisioned collection whose every grant expired', async () => {
    const owner = await generateKey()
    const app = await generateAppIdentity()
    const stores = memoryDescriptorStores()
    const { remoteStore, revoked, setCollections } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient: app.recipient
    })
    // The collection carries the app's attribution, as provisioning stamps it.
    setCollections([
      {
        id: 'app-docs',
        url: 'https://was.example/space/s-space/app-docs/',
        generator: { id: app.did }
      }
    ])

    // Every recorded grant is long past its own expiry, so the grant scan
    // yields nothing to revoke.
    const past = new Date(Date.now() - 1_000_000).toISOString()
    const target = 'https://was.example/space/s-space/app-docs'
    await storage.addHistoryLogin({
      user,
      origin: APP_ORIGIN,
      grants: [
        {
          id: 'g-app-docs',
          target,
          allowedActions: ['GET', 'HEAD'],
          expires: past,
          zcap: recordedGrant({
            id: 'z-app-docs',
            invocationTarget: target,
            expires: past,
            controller: app.did
          })
        }
      ],
      appConnect: { name: 'Example App', firstRun: true }
    })

    const outcome = await storage.revokeAppCollectionRecipients({
      origin: APP_ORIGIN,
      subjectDid: app.did
    })

    expect(outcome).toEqual({
      collections: 1,
      rotated: 1,
      failed: 0,
      revokedIds: []
    })
    const descriptor = await remoteStore.collectionEncryption({
      collectionId: 'app-docs'
    })
    expect(currentEpochKids(descriptor!)).toEqual([owner.keyAgreementKey.id])
    // Nothing to revoke: the grant had already expired.
    expect(revoked).toEqual([])
  })

  it('skips a generator-attributed collection the app no longer reads', async () => {
    const owner = await generateKey()
    const app = await generateAppIdentity()
    const other = await generateAppIdentity()
    const stores = memoryDescriptorStores()
    const { remoteStore, setCollections } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    // The app provisioned the collection and was rotated off it already, so
    // only the attribution still names it; another app reads it today.
    await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient: other.recipient
    })
    setCollections([
      {
        id: 'app-docs',
        url: 'https://was.example/space/s-space/app-docs/',
        generator: { id: app.did }
      }
    ])
    const before = await remoteStore.collectionEncryption({
      collectionId: 'app-docs'
    })
    const epochsBefore = before!.epochs!.length

    const outcome = await storage.revokeAppCollectionRecipients({
      origin: APP_ORIGIN,
      subjectDid: app.did
    })

    expect(outcome).toEqual({
      collections: 1,
      rotated: 0,
      failed: 0,
      revokedIds: []
    })
    const after = await remoteStore.collectionEncryption({
      collectionId: 'app-docs'
    })
    // Nothing rotated: no epoch was added and the reading app kept its entry.
    expect(after!.epochs).toHaveLength(epochsBefore)
    expect(currentEpochKids(after!)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, other.recipient.id])
    )
  })

  it('leaves a collection the listing reports public out of the candidates', async () => {
    const owner = await generateKey()
    const app = await generateAppIdentity()
    const stores = memoryDescriptorStores()
    const { remoteStore, setCollections } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    // A public collection the app provisioned: attributed to it, and
    // carrying no key-epoch roster.
    setCollections([
      {
        id: 'app-public',
        url: 'https://was.example/space/s-space/app-public/',
        generator: { id: app.did },
        isPublic: true
      }
    ])
    const collectionEncryption = vi.spyOn(stores.source, 'collectionEncryption')

    const outcome = await storage.revokeAppCollectionRecipients({
      origin: APP_ORIGIN,
      subjectDid: app.did
    })

    expect(outcome).toEqual({
      collections: 0,
      rotated: 0,
      failed: 0,
      revokedIds: []
    })
    expect(collectionEncryption).not.toHaveBeenCalled()
  })

  it('counts a collection listing it could not read as a failure', async () => {
    const owner = await generateKey()
    const app = await generateAppIdentity()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    vi.spyOn(remoteStore, 'listCollections').mockRejectedValue(
      new Error('offline')
    )

    const outcome = await storage.revokeAppCollectionRecipients({
      origin: APP_ORIGIN,
      subjectDid: app.did
    })

    // The caller cannot tell a rotated app from one still holding a recipient
    // entry, so the disconnect must not report itself done.
    expect(outcome).toEqual({
      collections: 0,
      rotated: 0,
      failed: 1,
      revokedIds: []
    })
  })

  it('leaves a co-admitted app its recipient entry', async () => {
    const owner = await generateKey()
    const app = await generateAppIdentity()
    const other = await generateAppIdentity()
    const stores = memoryDescriptorStores()
    const { remoteStore, revoked } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient: app.recipient
    })
    await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient: other.recipient
    })
    const before = await remoteStore.collectionEncryption({
      collectionId: 'app-docs'
    })
    expect(currentEpochKids(before!)).toHaveLength(3)
    const epochsBefore = before!.epochs!.length

    const future = new Date(Date.now() + 1_000_000).toISOString()
    const target = 'https://was.example/space/s-space/app-docs'
    await storage.addHistoryLogin({
      user,
      origin: APP_ORIGIN,
      grants: [
        {
          id: 'g-app-docs',
          target,
          allowedActions: ['GET', 'HEAD'],
          expires: future,
          zcap: recordedGrant({
            id: 'z-app-docs',
            invocationTarget: target,
            expires: future,
            controller: app.did
          })
        }
      ],
      appConnect: { name: 'Example App', firstRun: true }
    })

    const outcome = await storage.revokeAppCollectionRecipients({
      origin: APP_ORIGIN,
      subjectDid: app.did
    })

    expect(outcome).toEqual({
      collections: 1,
      rotated: 1,
      failed: 0,
      revokedIds: ['z-app-docs']
    })
    const after = await remoteStore.collectionEncryption({
      collectionId: 'app-docs'
    })
    // One fresh epoch, and the app that was not disconnected reads on.
    expect(after!.epochs).toHaveLength(epochsBefore + 1)
    expect(currentEpochKids(after!)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, other.recipient.id])
    )
    expect(currentEpochKids(after!)).not.toContain(app.recipient.id)
    expect((revoked as Array<{ id: string }>).map(zcap => zcap.id)).toEqual([
      'z-app-docs'
    ])
  })

  it('drops the app from the blinding-key wrap set without rotating the key', async () => {
    const owner = await generateKey()
    const app = await generateAppIdentity()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    const provisioned = await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient: app.recipient
    })
    const hmacId = provisioned.hmac?.id

    const future = new Date(Date.now() + 1_000_000).toISOString()
    const target = 'https://was.example/space/s-space/app-docs'
    await storage.addHistoryLogin({
      user,
      origin: APP_ORIGIN,
      grants: [
        {
          id: 'g-app-docs',
          target,
          allowedActions: ['GET', 'HEAD'],
          expires: future,
          zcap: recordedGrant({
            id: 'z-app-docs',
            invocationTarget: target,
            expires: future,
            controller: app.did
          })
        }
      ],
      appConnect: { name: 'Example App', firstRun: true }
    })

    await storage.revokeAppCollectionRecipients({
      origin: APP_ORIGIN,
      subjectDid: app.did
    })

    const descriptor = await remoteStore.collectionEncryption({
      collectionId: 'app-docs'
    })
    // The key never rotates -- blinded tokens must compare across the
    // collection's whole history -- so only the app's wrap entry goes.
    expect(descriptor!.hmac?.id).toBe(hmacId)
    expect(hmacKids(descriptor!)).not.toContain(app.recipient.id)
    expect(
      await resolveHmacOutcome({
        descriptor: descriptor!,
        keyAgreementKey: app.keyAgreementKey
      })
    ).toEqual({ errorName: 'EncryptionError' })
    // The owner still resolves the same key.
    expect(
      await resolveHmacOutcome({
        descriptor: descriptor!,
        keyAgreementKey: owner.keyAgreementKey
      })
    ).toEqual({ id: hmacId })
  })

  it.each([
    [
      'a collection target',
      'https://was.example/space/s-space/app-docs/',
      { collections: 1, rotated: 1, failed: 0, revokedIds: ['z-app-docs'] },
      ['z-app-docs']
    ],
    [
      'a reserved sub-endpoint target',
      'https://was.example/space/s-space/app-docs/meta',
      { collections: 0, rotated: 0, failed: 0, revokedIds: [] },
      []
    ],
    [
      'a protected collection target',
      'https://was.example/space/s-space/private-credentials',
      { collections: 0, rotated: 0, failed: 0, revokedIds: [] },
      []
    ]
  ])(
    'recovers the collection id from %s recorded in history',
    async (_label, target, expected, expectedRevoked) => {
      const owner = await generateKey()
      const app = await generateAppIdentity()
      const stores = memoryDescriptorStores()
      const { remoteStore, revoked } = makeFakeRemote({ stores })
      const descriptors = await provisionGovernedCollections(owner, stores)
      const ciphers = await buildCiphers(owner, descriptors)
      const { localStore, user } = await initLocalStore(ciphers)
      const storage = new StorageManager({
        persistence: browserLocalSessionPersistence(),
        localStore,
        remoteStore,
        descriptorLogs: descriptorLogsFrom(stores),
        ciphers,
        vaultKeys: owner,
        descriptors
      })

      await storage.provisionEncryptedCollection({
        collectionId: 'app-docs',
        recipient: app.recipient
      })

      const future = new Date(Date.now() + 1_000_000).toISOString()
      await storage.addHistoryLogin({
        user,
        origin: APP_ORIGIN,
        grants: [
          {
            id: 'g-app-docs',
            target,
            allowedActions: ['GET', 'HEAD'],
            expires: future,
            zcap: recordedGrant({
              id: 'z-app-docs',
              invocationTarget: target,
              expires: future,
              controller: app.did
            })
          }
        ],
        appConnect: { name: 'Example App', firstRun: true }
      })

      const outcome = await storage.revokeAppCollectionRecipients({
        origin: APP_ORIGIN,
        subjectDid: app.did
      })

      // Only an app Collection target names a collection to rotate; a
      // reserved sub-endpoint beneath one, or a standard/protected
      // collection, does not.
      expect(outcome).toEqual(expected)
      expect((revoked as Array<{ id: string }>).map(zcap => zcap.id)).toEqual(
        expectedRevoked
      )
    }
  )
})

describe('StorageManager.revokeAgentCollectionRecipients', () => {
  /**
   * A storage manager over a fake remote, holding one private collection
   * provisioned for `agent`, with the grant recorded on an agent Login.
   *
   * @param agent {Awaited<ReturnType<typeof generateAppIdentity>>}
   * @returns {Promise<object>}
   */
  async function agentGrantStorage(
    agent: Awaited<ReturnType<typeof generateAppIdentity>>,
    {
      revoke,
      signerCheck,
      signerKeyId,
      persistence = browserLocalSessionPersistence()
    }: {
      revoke?: (zcap: unknown) => Promise<void>
      signerCheck?: () => Promise<AccountSignerCheck | undefined>
      signerKeyId?: string
      persistence?: SessionPersistence
    } = {}
  ) {
    const owner = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore, revoked, setCollections } = makeFakeRemote({
      stores,
      revoke
    })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence,
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors,
      signerCheck
    })
    await storage.provisionEncryptedCollection({
      collectionId: 'agent-notes',
      recipient: agent.recipient
    })
    const future = new Date(Date.now() + 1_000_000).toISOString()
    const target = 'https://was.example/space/s-space/agent-notes'
    await storage.addHistoryLogin({
      user,
      origin: EXTERNAL_REQUEST_ORIGIN,
      grants: [
        {
          id: 'g-agent-notes',
          target,
          allowedActions: ['GET', 'HEAD', 'PUT'],
          expires: future,
          zcap: recordedGrant({
            id: 'z-agent-notes',
            invocationTarget: target,
            expires: future,
            controller: agent.did,
            ...(signerKeyId && { signerKeyId })
          })
        }
      ]
    })
    return {
      owner,
      stores,
      storage,
      remoteStore,
      revoked,
      persistence,
      user,
      setCollections
    }
  }

  it('rotates the agent off each granted collection and revokes its grant', async () => {
    const agent = await generateAppIdentity()
    const { owner, storage, remoteStore, revoked } =
      await agentGrantStorage(agent)

    const outcome = await storage.revokeAgentCollectionRecipients({
      controller: agent.did
    })

    expect(outcome).toEqual({
      collections: 1,
      rotated: 1,
      failed: 0,
      revokedIds: ['z-agent-notes']
    })
    // Read axis: the agent is off the new current epoch; the owner remains.
    const descriptor = await remoteStore.collectionEncryption({
      collectionId: 'agent-notes'
    })
    expect(currentEpochKids(descriptor!)).toEqual([owner.keyAgreementKey.id])
    // Pull axis: the recorded grant was revoked with the rotation.
    expect((revoked as Array<{ id: string }>).map(zcap => zcap.id)).toContain(
      'z-agent-notes'
    )
  })

  it('hands the rotated grants to the grant stage, which does not POST them again', async () => {
    const agent = await generateAppIdentity()
    const { storage, revoked } = await agentGrantStorage(agent)

    const rotation = await storage.revokeAgentCollectionRecipients({
      controller: agent.did
    })
    const outcome = await storage.revokeAgentGrants({
      controller: agent.did,
      revokedByRotation: rotation.revokedIds
    })

    // The rotation's pull axis revoked the grant; the grant stage counts it
    // as revoked and names it, so the recorded Revoke lists it.
    expect(outcome).toEqual({
      revoked: 1,
      withdrawn: 0,
      skipped: 0,
      revokedIds: ['z-agent-notes']
    })
    const posted = (revoked as Array<{ id: string }>).map(zcap => zcap.id)
    expect(posted.filter(id => id === 'z-agent-notes')).toHaveLength(1)
  })

  it('leaves an app login for the same DID to the app path', async () => {
    const agent = await generateAppIdentity()
    const { storage } = await agentGrantStorage(agent)

    // The app predicate matches an App Connect Login alone, so the agent's
    // interaction-URL grant is no candidate there.
    const outcome = await storage.revokeAppCollectionRecipients({
      origin: EXTERNAL_REQUEST_ORIGIN,
      subjectDid: agent.did,
      collections: []
    })

    expect(outcome).toEqual({
      collections: 0,
      rotated: 0,
      failed: 0,
      revokedIds: []
    })
  })

  it('is a no-op for a controller no recipient key derives from', async () => {
    const agent = await generateAppIdentity()
    const { storage } = await agentGrantStorage(agent)

    const outcome = await storage.revokeAgentCollectionRecipients({
      controller: 'did:web:agent.example'
    })

    expect(outcome).toEqual({
      collections: 0,
      rotated: 0,
      failed: 0,
      revokedIds: []
    })
  })

  it('reads the collections whose current epoch lists the agent, as rotation does', async () => {
    const agent = await generateAppIdentity()
    const { storage } = await agentGrantStorage(agent)
    const targets = [
      'https://was.example/space/s-space/agent-notes',
      // Protected: the agent holds no roster entry there to rotate.
      'https://was.example/space/s-space/private-credentials',
      // Another Space's collection.
      'https://was.example/space/elsewhere/agent-notes'
    ]

    expect(
      await storage.granteeRosterCollections({
        grantees: [{ controller: agent.did, targets }]
      })
    ).toEqual([
      { controller: agent.did, collectionIds: ['agent-notes'], failed: 0 }
    ])

    // Once rotated off, the same targets list the agent nowhere.
    await storage.revokeAgentCollectionRecipients({ controller: agent.did })
    expect(
      await storage.granteeRosterCollections({
        grantees: [{ controller: agent.did, targets }]
      })
    ).toEqual([{ controller: agent.did, collectionIds: [], failed: 0 }])
  })

  it('reads each targeted collection once across grantees', async () => {
    const agent = await generateAppIdentity()
    const other = await generateAppIdentity()
    const { owner, stores, remoteStore } = await agentGrantStorage(agent)
    const collectionEncryption = vi.fn((options: { collectionId: string }) =>
      stores.source.collectionEncryption(options)
    )
    const reader = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      remoteStore,
      vaultKeys: owner,
      descriptorLogs: {
        source: { collectionEncryption },
        storeFor: async collectionId => stores.storeFor(collectionId)
      }
    })
    const target = 'https://was.example/space/s-space/agent-notes'

    const outcomes = await reader.granteeRosterCollections({
      grantees: [
        { controller: agent.did, targets: [target] },
        { controller: other.did, targets: [target] }
      ]
    })

    expect(outcomes).toEqual([
      { controller: agent.did, collectionIds: ['agent-notes'], failed: 0 },
      { controller: other.did, collectionIds: [], failed: 0 }
    ])
    expect(collectionEncryption).toHaveBeenCalledTimes(1)
  })

  it('reports an unreadable key epoch against every grantee targeting it', async () => {
    const agent = await generateAppIdentity()
    const other = await generateAppIdentity()
    const { owner, stores, remoteStore } = await agentGrantStorage(agent)
    const reader = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      remoteStore,
      vaultKeys: owner,
      descriptorLogs: {
        source: {
          collectionEncryption: async () => {
            throw new Error('offline')
          }
        },
        storeFor: async collectionId => stores.storeFor(collectionId)
      }
    })
    const target = 'https://was.example/space/s-space/agent-notes'

    expect(
      await reader.granteeRosterCollections({
        grantees: [
          { controller: agent.did, targets: [target] },
          { controller: other.did, targets: [target] }
        ]
      })
    ).toEqual([
      { controller: agent.did, collectionIds: [], failed: 1 },
      { controller: other.did, collectionIds: [], failed: 1 }
    ])
  })

  it('counts the rotation, and names nothing, when the server refuses the pull', async () => {
    // was-client's default pull reads every ValidationError as already
    // revoked. A refusal the signer check cannot explain may be a live grant,
    // so it is left to the grant stage. The rotation itself landed, so the
    // collection counts as rotated.
    const agent = await generateAppIdentity()
    const { owner, storage, remoteStore, persistence } =
      await agentGrantStorage(agent, {
        revoke: async () => {
          throw new ValidationError('chain does not verify', { status: 400 })
        },
        // The in-memory tier, so the adopted descriptor is readable back.
        persistence: transientPersistence()
      })

    const outcome = await storage.revokeAgentCollectionRecipients({
      controller: agent.did
    })

    expect(outcome).toEqual({
      collections: 1,
      rotated: 1,
      failed: 0,
      revokedIds: []
    })
    // The rotation itself is durable before the pull runs.
    const descriptor = await remoteStore.collectionEncryption({
      collectionId: 'agent-notes'
    })
    expect(currentEpochKids(descriptor!)).toEqual([owner.keyAgreementKey.id])
    // ...and this session adopted it, though the pull failed: the cached
    // descriptor no longer lists the agent.
    const cached = await persistence
      .descriptorCache({ scope: remoteStore.spaceId })
      .readDescriptor({ collectionId: 'agent-notes' })
    expect(cached?.currentEpoch).toBe(descriptor!.currentEpoch)
    expect(currentEpochKids(cached!)).toEqual([owner.keyAgreementKey.id])
    // The grant stage POSTs it again and throws the same refusal.
    await expect(
      storage.revokeAgentGrants({
        controller: agent.did,
        revokedByRotation: outcome.revokedIds
      })
    ).rejects.toMatchObject({ name: 'ValidationError' })
  })

  it('records the Revoke when the grant stage revokes what a failed pull missed', async () => {
    // The pull POST fails once; the grant stage's re-POST lands. No
    // authority remains, so the revocation completes.
    const agent = await generateAppIdentity()
    let attempts = 0
    const { storage, user } = await agentGrantStorage(agent, {
      revoke: async () => {
        attempts += 1
        if (attempts === 1) {
          throw new Error('network down')
        }
      }
    })

    const outcome = await revokeAgentAccess({
      storage,
      user,
      agent: {
        controller: agent.did,
        origin: EXTERNAL_REQUEST_ORIGIN,
        grants: []
      }
    })

    expect(outcome).toMatchObject({ revoked: 1, rotated: 1 })
    expect(attempts).toBe(2)
    const items = await storage.listHistoryItems()
    expect(items.some(({ doc }) => doc.type?.includes('Revoke'))).toBe(true)
  })

  it('names a pull the server answers AlreadyRevokedError', async () => {
    const agent = await generateAppIdentity()
    const { storage } = await agentGrantStorage(agent, {
      revoke: async () => {
        throw new AlreadyRevokedError('already revoked', { status: 400 })
      }
    })

    expect(
      await storage.revokeAgentCollectionRecipients({ controller: agent.did })
    ).toEqual({
      collections: 1,
      rotated: 1,
      failed: 0,
      revokedIds: ['z-agent-notes']
    })
  })

  it('does not name a pull refused for a signer the document no longer lists', async () => {
    const agent = await generateAppIdentity()
    const { storage } = await agentGrantStorage(agent, {
      revoke: async () => {
        throw new ValidationError('chain does not verify', { status: 400 })
      },
      signerCheck: async () => accountSignerCheck(),
      signerKeyId: GONE_SIGNER
    })

    const rotation = await storage.revokeAgentCollectionRecipients({
      controller: agent.did
    })

    // The grant is dead already, so the rotation lands but revokes nothing.
    expect(rotation).toEqual({
      collections: 1,
      rotated: 1,
      failed: 0,
      revokedIds: []
    })
    expect(
      await storage.revokeAgentGrants({
        controller: agent.did,
        revokedByRotation: rotation.revokedIds
      })
    ).toEqual({ revoked: 0, withdrawn: 0, skipped: 1, revokedIds: [] })
  })

  it('reads no key epoch for a grant target the listing reports public', async () => {
    const agent = await generateAppIdentity()
    const { stores, storage, setCollections, user } =
      await agentGrantStorage(agent)
    setCollections([
      {
        id: 'agent-notes',
        url: 'https://was.example/space/s-space/agent-notes/'
      },
      {
        id: 'agent-public',
        url: 'https://was.example/space/s-space/agent-public/',
        isPublic: true
      }
    ])
    const collectionEncryption = vi.spyOn(stores.source, 'collectionEncryption')
    const publicTarget = 'https://was.example/space/s-space/agent-public'
    const future = new Date(Date.now() + 1_000_000).toISOString()
    await storage.addHistoryLogin({
      user,
      origin: EXTERNAL_REQUEST_ORIGIN,
      grants: [
        {
          id: 'g-agent-public',
          target: publicTarget,
          allowedActions: ['GET', 'HEAD', 'PUT'],
          expires: future,
          zcap: recordedGrant({
            id: 'z-agent-public',
            invocationTarget: publicTarget,
            expires: future,
            controller: agent.did
          })
        }
      ]
    })

    expect(
      await storage.granteeRosterCollections({
        grantees: [
          {
            controller: agent.did,
            targets: [
              'https://was.example/space/s-space/agent-notes',
              publicTarget
            ]
          }
        ]
      })
    ).toEqual([
      { controller: agent.did, collectionIds: ['agent-notes'], failed: 0 }
    ])
    // The revocation skips the public collection as well, and rotates the
    // private one.
    const outcome = await storage.revokeAgentCollectionRecipients({
      controller: agent.did
    })
    expect(outcome).toEqual({
      collections: 1,
      rotated: 1,
      failed: 0,
      revokedIds: ['z-agent-notes']
    })
    const readIds = collectionEncryption.mock.calls.map(
      ([options]) => options.collectionId
    )
    expect(readIds).toContain('agent-notes')
    expect(readIds).not.toContain('agent-public')
  })

  it('counts a listing it could not read as a failure, and still rotates', async () => {
    const agent = await generateAppIdentity()
    const { storage, remoteStore } = await agentGrantStorage(agent)
    vi.spyOn(remoteStore, 'listCollectionPublicStates').mockRejectedValue(
      new Error('offline')
    )

    // Without the listing a public target cannot be told apart, so the
    // revocation cannot say the agent is off every roster. The private
    // collection is rotated all the same.
    expect(
      await storage.revokeAgentCollectionRecipients({ controller: agent.did })
    ).toEqual({
      collections: 1,
      rotated: 1,
      failed: 1,
      revokedIds: ['z-agent-notes']
    })
  })

  it('records no Revoke when the listing cannot be read', async () => {
    const agent = await generateAppIdentity()
    const { storage, remoteStore, user } = await agentGrantStorage(agent)
    vi.spyOn(remoteStore, 'listCollectionPublicStates').mockRejectedValue(
      new Error('offline')
    )

    await expect(
      revokeAgentAccess({
        storage,
        user,
        agent: {
          controller: agent.did,
          origin: EXTERNAL_REQUEST_ORIGIN,
          grants: []
        }
      })
    ).rejects.toThrow(/Could not rotate every collection/)
    const items = await storage.listHistoryItems()
    expect(items.some(({ doc }) => doc.type?.includes('Revoke'))).toBe(false)
  })

  it('throws for an app subject no recipient key derives from', async () => {
    const agent = await generateAppIdentity()
    const { storage } = await agentGrantStorage(agent)

    // An app-key subject is always a did:key: anything else is a malformed
    // caller, which must not read as a rotation that found nothing to do.
    await expect(
      storage.revokeAppCollectionRecipients({
        origin: 'https://app.example',
        subjectDid: 'did:web:app.example',
        collections: []
      })
    ).rejects.toThrow()
  })
})

describe('StorageManager.decryptCollectionResource (app collection)', () => {
  it('decrypts an app-collection envelope with the vault KAK', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    const descriptor = await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient: ownerRecipient({ keyAgreementKey: app.keyAgreementKey })
    })

    // A document written under the current epoch (the owner is recipient zero,
    // so a cipher built from the descriptor over the owner's keys can write it).
    const ownerCipher = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'app-docs',
      encryption: descriptor
    })
    const doc = { title: 'App note', body: 'hello' }
    const { id, envelope } = await ownerCipher.encrypt({
      data: doc as unknown as Json
    })

    const decrypted = await storage.decryptCollectionResource({
      collectionId: 'app-docs',
      resourceId: id,
      data: envelope
    })
    expect(decrypted).toEqual(doc)
  })

  it('returns undefined for an app collection with no epoch roster', async () => {
    const owner = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })

    // A well-formed EDV envelope shape, but the collection was never provisioned
    // multi-recipient, so the wallet has nothing to decrypt it with.
    const envelope = {
      id: 'z-fake',
      sequence: 0,
      jwe: { recipients: [{ header: { kid: 'did:key:zStranger#zStranger' } }] }
    } as unknown as Json

    const decrypted = await storage.decryptCollectionResource({
      collectionId: 'never-provisioned',
      resourceId: 'z-fake',
      data: envelope
    })
    expect(decrypted).toBeUndefined()
  })
})

describe('StorageManager unknown-epoch refresh', () => {
  it('re-reads the descriptor and returns a credential written under a newer epoch', async () => {
    const owner = await generateKey()
    const extra = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })

    // The governing log starts on epoch 1 (owner + a soon-removed reader).
    const collectionStore = stores.storeFor('private-credentials')
    const descriptor1 = await initRecipients({
      store: collectionStore,
      recipients: [
        ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
        ownerRecipient({ keyAgreementKey: extra.keyAgreementKey })
      ]
    })

    // StorageManager (and the local store) build ciphers from the STALE
    // descriptor 1.
    const ciphers = await buildCiphers(owner, {
      'private-credentials': descriptor1
    })
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors: { 'private-credentials': descriptor1 }
    })

    // A rekey rotates the collection to epoch 2 (emitting no change feed
    // entry): removing the extra reader leaves the owner alone on the new
    // epoch.
    const descriptor2 = await removeRecipient({
      store: collectionStore,
      space: remoteStore.spaceHandle(),
      recipientId: extra.keyAgreementKey.id!,
      revoke: []
    })
    expect(descriptor2.currentEpoch).not.toBe(descriptor1.currentEpoch)

    // A credential is written locally under epoch 2 (as replication would land
    // it), which the stale epoch-1 cipher cannot route.
    const epoch2Cipher = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials',
      encryption: descriptor2
    })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    const { id, envelope, epoch } = await epoch2Cipher.encrypt({
      data: credential as unknown as Json
    })
    expect(epoch).toBe(descriptor2.currentEpoch)
    await localStore.rxCollection('privateCredentials').insert({
      id,
      updatedAt: new Date().toISOString(),
      version: 0,
      epoch,
      data: envelope
    })

    // listCredentials transparently refreshes the descriptor from the governing log,
    // rebuilds the cipher, and returns the credential.
    const listed = await storage.listCredentials()
    expect(listed).toEqual([{ cid, vc: credential }])
  })

  it('transient session: the refresh still runs, with zero localStorage residue', async () => {
    const owner = await generateKey()
    const extra = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })

    const collectionStore = stores.storeFor('private-credentials')
    const descriptor1 = await initRecipients({
      store: collectionStore,
      recipients: [
        ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
        ownerRecipient({ keyAgreementKey: extra.keyAgreementKey })
      ]
    })

    const ciphers = await buildCiphers(owner, {
      'private-credentials': descriptor1
    })
    const { localStore } = await initLocalStore(ciphers)
    const persistence = inMemorySessionPersistence({
      stores: transientSessionStores(),
      clientAnnex: {
        clientAnnexDid: 'did:webvh:example:annex',
        invocationCapability: {} as IZcap
      }
    })
    // The login-time acquisition seeds the strategy's in-memory cache pair.
    await persistence
      .descriptorCache({ scope: remoteStore.spaceId })
      .writeDescriptor({
        collectionId: 'private-credentials',
        descriptor: descriptor1
      })
    const storage = new StorageManager({
      persistence,
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors: { 'private-credentials': descriptor1 }
    })

    const descriptor2 = await removeRecipient({
      store: collectionStore,
      space: remoteStore.spaceHandle(),
      recipientId: extra.keyAgreementKey.id!,
      revoke: []
    })
    const epoch2Cipher = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials',
      encryption: descriptor2
    })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    const { id, envelope, epoch } = await epoch2Cipher.encrypt({
      data: credential as unknown as Json
    })
    await localStore.rxCollection('privateCredentials').insert({
      id,
      updatedAt: new Date().toISOString(),
      version: 0,
      epoch,
      data: envelope
    })

    // The unknown-epoch read drives the same one-time refresh as the
    // browser-local variant -- into the strategy's in-memory cache, not
    // localStorage.
    const listed = await storage.listCredentials()
    expect(listed).toEqual([{ cid, vc: credential }])
    const cached = await persistence
      .descriptorCache({ scope: remoteStore.spaceId })
      .readDescriptor({ collectionId: 'private-credentials' })
    expect(cached?.currentEpoch).toBe(descriptor2.currentEpoch)
    // This file runs in the node environment; guard the residue check for a
    // jsdom run, where a localStorage cache write would have landed here.
    if (typeof localStorage !== 'undefined') {
      expect(
        localStorage.getItem(
          `freewallet:collection-encryption:${remoteStore.spaceId}:private-credentials`
        )
      ).toBeNull()
    }
  })

  it('remote-direct: refreshes the descriptor and returns a fresh-epoch credential', async () => {
    const owner = await generateKey()
    const extra = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore, seedResource } = makeFakeRemote({ stores })

    const collectionStore = stores.storeFor('private-credentials')
    const descriptor1 = await initRecipients({
      store: collectionStore,
      recipients: [
        ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
        ownerRecipient({ keyAgreementKey: extra.keyAgreementKey })
      ]
    })

    // The remote-direct popup backend builds ciphers from the STALE descriptor 1.
    const ciphers = await buildCiphers(owner, {
      'private-credentials': descriptor1
    })
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      remoteDirect: true,
      vaultKeys: owner,
      descriptors: { 'private-credentials': descriptor1 }
    })

    // A rekey rotates the collection to epoch 2 (owner alone).
    const descriptor2 = await removeRecipient({
      store: collectionStore,
      space: remoteStore.spaceHandle(),
      recipientId: extra.keyAgreementKey.id!,
      revoke: []
    })

    // A credential lands in the remote collection under epoch 2, which the
    // stale epoch-1 cipher cannot route.
    const epoch2Cipher = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials',
      encryption: descriptor2
    })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    const { id, envelope } = await epoch2Cipher.encrypt({
      data: credential as unknown as Json
    })
    seedResource({
      logicalKey: 'privateCredentials',
      resourceId: id,
      body: envelope
    })

    // The remote-direct listCredentials refreshes the descriptor, rebuilds the
    // backend's cipher via setCiphers, and re-reads -- returning the fresh row.
    const listed = await storage.listCredentials()
    expect(listed).toEqual([{ cid, vc: credential }])
  })

  it('refetches the collection metadata, so later writes carry index entries', async () => {
    const owner = await generateKey()
    const extra = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore, setCollectionMeta } = makeFakeRemote({ stores })

    // A blinded-index collection on epoch 1, with a second reader to remove.
    const descriptors = await provisionGovernedCollections(owner, stores, {
      blindedIndex: true
    })
    const collectionStore = stores.storeFor('private-credentials')
    const descriptor1 = await addRecipient({
      store: collectionStore,
      recipient: ownerRecipient({ keyAgreementKey: extra.keyAgreementKey }),
      owner: { keyAgreementKey: owner.keyAgreementKey }
    })
    descriptors['private-credentials'] = descriptor1

    // The session's ciphers are built from the epoch-1 descriptor, and no
    // collection metadata existed yet -- so writes carry no index entries.
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    await storage.addCredential({ credential: makeCredential('Alice'), user })
    const beforeEnvelopes = await storedCredentialEnvelopes(localStore)
    expect(beforeEnvelopes).toHaveLength(1)
    expect(indexedOf(beforeEnvelopes[0])).toEqual([])

    // Another client rotates the collection to epoch 2 and declares an index,
    // so the server now serves both a newer descriptor and a stored metadata
    // envelope.
    const descriptor2 = await removeRecipient({
      store: collectionStore,
      space: remoteStore.spaceHandle(),
      recipientId: extra.keyAgreementKey.id!,
      revoke: []
    })
    setCollectionMeta({
      collectionId: 'private-credentials',
      meta: await mintCollectionMeta({
        collectionId: 'private-credentials',
        encryption: descriptor2,
        keys: owner
      })
    })

    // A credential lands locally under epoch 2 (as replication would),
    // unreadable by the stale epoch-1 cipher.
    const epoch2Cipher = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials',
      encryption: descriptor2
    })
    const credential = makeCredential('Bob')
    const cid = await cidFrom({ doc: credential })
    const { id, envelope, epoch } = await epoch2Cipher.encrypt({
      data: credential as unknown as Json
    })
    await localStore.rxCollection('privateCredentials').insert({
      id,
      updatedAt: new Date().toISOString(),
      version: 0,
      epoch,
      data: envelope
    })

    // The unknown-epoch read refreshes the descriptor AND the metadata, so the
    // rebuilt cipher writes blinded index entries from here on.
    const listed = await storage.listCredentials()
    expect(listed.map(entry => entry.cid)).toContain(cid)

    await storage.addCredential({ credential: makeCredential('Carol'), user })
    const afterEnvelopes = await storedCredentialEnvelopes(localStore)
    expect(afterEnvelopes).toHaveLength(3)
    expect(
      afterEnvelopes.filter(stored => indexedOf(stored).length > 0)
    ).toHaveLength(1)
  })
})

describe('StorageManager blinded index writes', () => {
  /**
   * A StorageManager over blinded-index-provisioned governing logs, with its
   * ciphers built from the same descriptors (no metadata applied yet).
   *
   * @returns {Promise<object>}   the manager, its local store, the owner keys,
   *   the descriptors, and the remote fake's metadata setter
   */
  async function makeIndexableManager(): Promise<{
    storage: StorageManager
    localStore: BrowserStore
    user: User
    owner: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
    descriptors: Record<string, CollectionEncryption>
    setCollectionMeta: ReturnType<typeof makeFakeRemote>['setCollectionMeta']
  }> {
    const owner = await generateKey()
    const stores = memoryDescriptorStores()
    const { remoteStore, setCollectionMeta } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores, {
      blindedIndex: true
    })
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    return { storage, localStore, user, owner, descriptors, setCollectionMeta }
  }

  it('writes no index entries for a collection with no stored metadata', async () => {
    const { storage, localStore, user } = await makeIndexableManager()

    // The remote fake serves no metadata, so the rebuilt ciphers have no
    // schema to install -- the pre-index behavior.
    await storage.refreshEncryptedDescriptors()
    await storage.addCredential({ credential: makeCredential('Alice'), user })

    const envelopes = await storedCredentialEnvelopes(localStore)
    expect(envelopes).toHaveLength(1)
    expect(indexedOf(envelopes[0])).toEqual([])
  })

  it('writes blinded index entries once the collection metadata declares a schema', async () => {
    const { storage, localStore, user, owner, descriptors, setCollectionMeta } =
      await makeIndexableManager()
    setCollectionMeta({
      collectionId: 'private-credentials',
      meta: await mintCollectionMeta({
        collectionId: 'private-credentials',
        encryption: descriptors['private-credentials']!,
        keys: owner
      })
    })

    await storage.refreshEncryptedDescriptors()
    await storage.addCredential({ credential: makeCredential('Alice'), user })

    const envelopes = await storedCredentialEnvelopes(localStore)
    expect(envelopes).toHaveLength(1)
    const indexed = indexedOf(envelopes[0])
    expect(indexed).toHaveLength(1)
    expect((indexed[0] as { hmac: { id: string } }).hmac.id).toBe(
      descriptors['private-credentials']!.hmac!.id
    )
    // Blinded: neither the attribute name nor the issuer value is in the clear.
    expect(JSON.stringify(indexed)).not.toContain('issuer')
    expect(JSON.stringify(indexed)).not.toContain('z6MkTestIssuer')
    // The credential still round-trips through the same cipher.
    const listed = await storage.listCredentials()
    expect(listed).toHaveLength(1)
  })

  it('degrades to a schema-less cipher when the metadata cannot be decoded', async () => {
    const { storage, localStore, user, setCollectionMeta } =
      await makeIndexableManager()
    // Garbage in place of the metadata envelope: indexing is auxiliary, so the
    // write must still succeed, just without index entries.
    setCollectionMeta({
      collectionId: 'private-credentials',
      meta: { custom: { not: 'an envelope' } }
    })
    const capture = captureSink()
    const removeSink = addSink(capture.sink)

    try {
      await storage.refreshEncryptedDescriptors()
      await storage.addCredential({ credential: makeCredential('Alice'), user })

      const envelopes = await storedCredentialEnvelopes(localStore)
      expect(envelopes).toHaveLength(1)
      expect(indexedOf(envelopes[0])).toEqual([])
      expect(
        capture.events.some(
          event =>
            event.level === 'warn' &&
            event.msg.includes('Could not install the index schema')
        )
      ).toBe(true)
    } finally {
      removeSink()
    }
  })
})

describe('StorageManager.addHistoryWalletLogin', () => {
  it('records the local sign-in with the actor and no relying party', async () => {
    const owner = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore, user } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })

    await storage.addHistoryWalletLogin({ user })

    const history = await storage.listHistoryItems()
    const loginEntry = history.find(({ doc }) => doc.type?.includes('Login'))
    expect(loginEntry).toBeDefined()
    expect(loginEntry!.doc.summary).toBe('Logged in to wallet.')
    expect(loginEntry!.doc.actor).toEqual({ email: user.email })
    expect(loginEntry!.doc.object).toBeUndefined()
  })
})
