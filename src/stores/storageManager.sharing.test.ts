/**
 * Unit tests for StorageManager's multi-recipient collection sharing and
 * revocation surface: `shareCollection` / `unshareCollection` /
 * `listCollectionShares`, the grant stage (`revokeConnectionGrants`) and the
 * recipient rotation (`revokeCollectionRecipients`) a party revocation runs,
 * the admitted-recipient resolver every rotation wraps the fresh epoch
 * through, the server-side app-key delete (`deleteAppKeyResource`), plus the
 * transparent unknown-epoch descriptor refresh on `listCredentials` and on
 * the contacts point reads (`loadContact`, `updateContact`).
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
 * The `connections` directory is the grant index the revocations, the
 * unshare, and the share listing read. Here it stands on an in-memory store
 * (`memoryConnectionsStore`) that the storage manager's `connectionsDirectory`
 * hands back, under wallet-core's real reader and upsert logic. Its binding to
 * the `connections` collection is covered in
 * `storageManager.connections.test.ts`. No history row decides a revocation or
 * an admission here.
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
} from '@interop/pws-client'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import {
  addRecipient,
  createEdvEncryption,
  ensureFirstEpoch,
  initRecipients,
  removeRecipient,
  resolveHmacKey,
  unwrapEpochSecret,
  x25519RecipientFromDidKey,
  type RecipientPublicKey
} from '@interop/pws-client/edv'
import {
  connectionGrants,
  connectionResourceId,
  findConnection,
  recordGrants,
  recordReceivedGrants,
  setConnectionLabel,
  type ConnectionEntry,
  type ConnectionGrant,
  type ConnectionKind,
  type GrantKind
} from '@interop/wallet-core/connections'
import { mintAppKeyCredential } from '@interop/wallet-request'
import type { ContactData, ContactHeadPayload } from '@interop/social-core'
import {
  descriptorLogsFrom,
  memoryDescriptorStores,
  type MemoryDescriptorStores
} from '../../tests/unit/fakeDescriptorStores'
import {
  HMAC_KEY,
  memoryConnectionsStore
} from '../../tests/unit/memoryConnections'
import { mintRecordEncryption } from '@/session/recordEnvelope'
import {
  browserLocalSessionPersistence,
  inMemorySessionPersistence,
  transientSessionStores,
  type SessionPersistence
} from '@/session/persistence'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import type { ControllerProfile, User } from '@/types/auth'
import { cidFrom } from '@interop/pws-client/sync'
import type { Json } from '@interop/pws-sync'
import { BrowserStore } from './browserStore'
import {
  createEdvDocCipher,
  ownerRecipient,
  type DocCipher
} from '@interop/pws-client/edv'
import {
  revokeAgentAccess,
  revokeAppAuthority,
  type AccountSignerCheck
} from '@/lib/connectedApps'
import { StorageManager } from './storageManager'
import { generateVaultKeys } from '@/stores/testing/vaultKeys'
import {
  accountSignerCheck,
  ENROLLED_SIGNER,
  GONE_SIGNER,
  LADDER_SIGNER,
  recordedGrant,
  SIGNER_FIXTURE
} from '@interop/wallet-core/testing'
import { mintUserKey, userKeyVaultKeys } from '@interop/wallet-core/keys'
import { EXTERNAL_REQUEST_ORIGIN } from '@/lib/walletRequest/externalRequest'
import type { WASRemoteStore } from './wasRemoteStore'
import type { StorageCollection } from '@/lib/storage'
import type { StoredContact } from '@/types/contact'

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
 * A `resolveRecipientKey` vouching for the given keys alone, standing in for
 * the admitted-recipient resolver another client rotates with.
 *
 * @param keys {Array<{ keyAgreementKey: IKeyAgreementKey }>}
 * @returns {Function}
 */
function vouchFor(
  ...keys: Array<{ keyAgreementKey: IKeyAgreementKey }>
): (kid: string) => Promise<RecipientPublicKey | null> {
  const recipients = keys.map(({ keyAgreementKey }) =>
    ownerRecipient({ keyAgreementKey })
  )
  return async kid => recipients.find(recipient => recipient.id === kid) ?? null
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
  const baseServerUrl = 'https://was.example'
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
    baseServerUrl,
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
 * standing in for what provisioning would have installed. `appKeys`
 * adds the `app-keys` cipher, for a test that stores app keys.
 */
async function buildCiphers(
  owner: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver },
  descriptors: Record<string, CollectionEncryption>,
  { appKeys = false }: { appKeys?: boolean } = {}
): Promise<Record<string, DocCipher>> {
  const specs: Array<[string, string]> = [
    ['privateCredentials', 'private-credentials'],
    ['walletActivity', 'wallet-activity'],
    ...(appKeys ? [['appKeys', 'app-keys'] as [string, string]] : [])
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
    spaceUrl: 'http://localhost/space/local/',
    collectionId,
    scheme: 'edv',
    encryption
  })
  if (!codec) {
    throw new Error(`No codec for collection "${collectionId}".`)
  }
  const { custom } = await codec.encodeMeta({
    // The same cast pws-client's own declareIndex applies: the index schema
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

/**
 * Installs an empty in-memory `localStorage` for one test, so a residue check
 * runs in the node environment too. The `afterEach` below removes it.
 *
 * @returns {{ keys: () => string[] }}
 */
function stubLocalStorage(): { keys: () => string[] } {
  const map = new Map<string, string>()
  vi.stubGlobal('localStorage', {
    get length() {
      return map.size
    },
    key: (index: number) => [...map.keys()][index] ?? null,
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, value: string) => void map.set(key, value),
    removeItem: (key: string) => void map.delete(key),
    clear: () => map.clear()
  })
  return { keys: () => [...map.keys()] }
}

afterEach(async () => {
  vi.unstubAllGlobals()
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

/**
 * This Space's container URL, as the fake remote serves it. Every grant a
 * directory reader keeps targets beneath it.
 */
const SPACE_URL = 'https://was.example/space/s-space/'

/**
 * An app's or an agent's identity, as {@link generateAppIdentity} mints it.
 */
type PartyIdentity = Awaited<ReturnType<typeof generateAppIdentity>>

/**
 * The in-memory directory store a test inspects and plants rows in.
 */
type MemoryDirectory = ReturnType<typeof memoryConnectionsStore>

/**
 * Stands the session's `connections` directory on an in-memory store: the
 * storage manager's `connectionsDirectory` hands back that store, the fixed
 * blinded-index key, and this Space's container URL. Two storage managers
 * over one account share a directory by passing the same `memory`.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param [options.memory] {MemoryDirectory}   an existing store to share
 * @returns {MemoryDirectory}
 */
function standDirectory({
  storage,
  memory = memoryConnectionsStore()
}: {
  storage: StorageManager
  memory?: MemoryDirectory
}): MemoryDirectory {
  vi.spyOn(storage, 'connectionsDirectory').mockResolvedValue({
    store: memory.store,
    hmacKey: HMAC_KEY,
    spaceUrl: SPACE_URL
  })
  return memory
}

/**
 * A recorded capability on one collection of this Space.
 *
 * @param options {object}
 * @param options.id {string}
 * @param options.controller {string}   the grantee DID
 * @param [options.collectionId] {string}   default `private-credentials`
 * @param [options.target] {string}   an explicit invocation target, in place
 *   of the collection's
 * @param [options.expires] {string}   default a little past now
 * @param [options.signerKeyId] {string}
 * @param [options.parent] {object}   the generation delegation it chains
 *   under
 * @returns {IZcap}
 */
function collectionGrant({
  id,
  controller,
  collectionId = 'private-credentials',
  target = `${SPACE_URL}${collectionId}`,
  expires = new Date(Date.now() + 1_000_000).toISOString(),
  signerKeyId,
  parent
}: {
  id: string
  controller: string
  collectionId?: string
  target?: string
  expires?: string
  signerKeyId?: string
  parent?: { controller: string; signerKeyId?: string }
}): IZcap {
  return recordedGrant({
    id,
    controller,
    invocationTarget: target,
    expires,
    ...(signerKeyId && { signerKeyId }),
    ...(parent && { parent })
  })
}

/**
 * A directory entry's body, built past the upsert helpers: what a test plants
 * at a resource id, or reads grants off in memory.
 *
 * @param options {object}
 * @param options.did {string}   the entry's `id`
 * @param [options.kind] {ConnectionKind}   default `app`
 * @param [options.zcaps] {object[]}   the grants' capabilities
 * @param [options.grantKind] {GrantKind}   default `grant`
 * @param [options.version] {number}   default 1
 * @param [options.retired] {string}
 * @param [options.appKey] {string}
 * @returns {ConnectionEntry}
 */
function entryBody({
  did,
  kind = 'app',
  zcaps = [],
  grantKind = 'grant',
  version = 1,
  retired,
  appKey
}: {
  did: string
  kind?: ConnectionKind
  zcaps?: object[]
  grantKind?: GrantKind
  version?: number
  retired?: string
  appKey?: string
}): ConnectionEntry {
  const stamp = '2026-09-01T00:00:00.000Z'
  return {
    version,
    kind,
    id: did,
    firstSeen: stamp,
    lastSeen: stamp,
    ...(retired !== undefined && { retired }),
    ...(appKey !== undefined && { appKey }),
    grants: zcaps.map(zcap => ({
      zcap: zcap as ConnectionEntry['grants'][number]['zcap'],
      grantKind,
      grantedAt: stamp
    })),
    grantsReceived: [],
    outbox: [],
    writers: [],
    replicas: []
  }
}

/**
 * A party's grants as wallet-core's reader checks keep them, read off an
 * entry built in memory: the grant stage's input, which reads no directory.
 *
 * @param options {object}
 * @param options.did {string}   the party's DID
 * @param options.zcaps {object[]}
 * @returns {ConnectionGrant[]}
 */
function grantsOf({
  did,
  zcaps
}: {
  did: string
  zcaps: object[]
}): ConnectionGrant[] {
  return connectionGrants({
    entry: entryBody({ did, zcaps }),
    spaceUrl: SPACE_URL
  })
}

/**
 * Plants a stored body in the in-memory directory at a resource id, past the
 * upsert helpers, as a host or a newer build could leave one. The resource id
 * defaults to the one the body's own `id` derives to.
 *
 * @param options {object}
 * @param options.memory {MemoryDirectory}
 * @param options.body {object}
 * @param [options.resourceId] {string}
 * @returns {Promise<string>}   the resource id planted at
 */
async function plantEntry({
  memory,
  body,
  resourceId
}: {
  memory: MemoryDirectory
  body: object
  resourceId?: string
}): Promise<string> {
  const at =
    resourceId ??
    (await connectionResourceId({
      hmacKey: HMAC_KEY,
      did: (body as { id: string }).id
    }))
  memory.rows.set(at, { body, etag: `planted-${at}` })
  return at
}

/**
 * Records a consent on a party's directory entry, as the request path does
 * once the grants are delegated.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.did {string}   the party's DID, every grant's controller
 * @param options.zcaps {object[]}   the delegated capabilities
 * @param [options.kind] {ConnectionKind}   default `app`
 * @param [options.grantKind] {GrantKind}   default `grant`
 * @param [options.name] {string}
 * @param [options.origin] {string}
 * @param [options.now] {Date}
 * @returns {Promise<void>}
 */
async function recordPartyGrants({
  storage,
  did,
  zcaps,
  kind = 'app',
  grantKind = 'grant',
  name,
  origin,
  now
}: {
  storage: StorageManager
  did: string
  zcaps: object[]
  kind?: ConnectionKind
  grantKind?: GrantKind
  name?: string
  origin?: string
  now?: Date
}): Promise<void> {
  const { store, hmacKey, spaceUrl } = await storage.connectionsDirectory()
  await recordGrants({
    store,
    hmacKey,
    spaceUrl,
    did,
    kind,
    grants: zcaps.map(zcap => ({ zcap, grantKind })),
    ...(name !== undefined && { name }),
    ...(origin !== undefined && { origin }),
    ...(now !== undefined && { now })
  })
}

/**
 * A party's grants as a revocation reads them: off its entry in one directory
 * listing, through wallet-core's reader checks, with the listing itself.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.did {string}
 * @returns {Promise<object>}   `{ directory, entry, grants }`
 */
async function readParty({
  storage,
  did
}: {
  storage: StorageManager
  did: string
}): Promise<{
  directory: Awaited<ReturnType<StorageManager['readConnectionsListing']>>
  entry?: ConnectionEntry
  grants: ConnectionGrant[]
}> {
  const directory = await storage.readConnectionsListing()
  const entry = findConnection({ listing: directory.listing, did })?.entry
  return {
    directory,
    ...(entry !== undefined && { entry }),
    grants: entry ? connectionGrants({ entry, spaceUrl: SPACE_URL }) : []
  }
}

/**
 * Runs a party revocation's rotation stage the way the session layer does:
 * the party's grants and the admissions both come from one directory read.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.did {string}
 * @param [options.collections] {StorageCollection[]}
 * @returns {Promise<object>}   the rotation outcome and the grants it read
 */
async function rotateParty({
  storage,
  did,
  collections
}: {
  storage: StorageManager
  did: string
  collections?: StorageCollection[]
}): Promise<{
  rotation: Awaited<ReturnType<StorageManager['revokeCollectionRecipients']>>
  grants: ConnectionGrant[]
}> {
  const { directory, grants } = await readParty({ storage, did })
  const rotation = await storage.revokeCollectionRecipients({
    did,
    grants,
    directory,
    ...(collections && { collections })
  })
  return { rotation, grants }
}

/**
 * A remote session over the fake remote, its standard encrypted collections
 * provisioned to the owner, and its directory stood on an in-memory store.
 *
 * @param [options] {object}
 * @param [options.revoke] {Function}   the Space handle's refusal, if any
 * @param [options.signerCheck] {Function}
 * @param [options.persistence] {SessionPersistence}
 * @param [options.blindedIndex] {boolean}
 * @param [options.appKeys] {boolean}   builds the app-key cipher
 * @returns {Promise<object>}
 */
async function directorySession({
  revoke,
  signerCheck,
  persistence = browserLocalSessionPersistence(),
  blindedIndex = false,
  appKeys = false
}: {
  revoke?: (zcap: unknown) => Promise<void>
  signerCheck?: () => Promise<AccountSignerCheck | undefined>
  persistence?: SessionPersistence
  blindedIndex?: boolean
  appKeys?: boolean
} = {}) {
  const owner = await generateVaultKeys()
  const stores = memoryDescriptorStores()
  const remote = makeFakeRemote({ stores, revoke })
  const descriptors = await provisionGovernedCollections(owner, stores, {
    blindedIndex
  })
  const ciphers = await buildCiphers(owner, descriptors, { appKeys })
  const { localStore, user } = await initLocalStore(ciphers)
  const storage = new StorageManager({
    persistence,
    localStore,
    remoteStore: remote.remoteStore,
    descriptorLogs: descriptorLogsFrom(stores),
    ciphers,
    vaultKeys: owner,
    descriptors,
    ...(signerCheck && { signerCheck })
  })
  const memory = standDirectory({ storage })
  return {
    ...remote,
    owner,
    stores,
    ciphers,
    localStore,
    user,
    storage,
    memory,
    persistence
  }
}

/**
 * The ids of the capabilities the fake remote was asked to revoke, in order.
 *
 * @param revoked {unknown[]}
 * @returns {string[]}
 */
function revokedIdsOf(revoked: unknown[]): string[] {
  return (revoked as Array<{ id: string }>).map(zcap => zcap.id)
}

/**
 * Shares a collection with a party the way the request path does: signs and
 * escrows the share (`shareWith`), then records the share grant on the
 * party's directory entry.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.profile {ControllerProfile}
 * @param options.user {User}
 * @param options.reader {PartyIdentity}
 * @param [options.collectionId] {string}   default `private-credentials`
 * @param [options.name] {string}   the party's self-declared name
 * @param [options.origin] {string}   the app's attested origin
 * @returns {Promise<object>}   the new descriptor and the signed zcap
 */
async function shareWithParty({
  storage,
  profile,
  user,
  reader,
  collectionId = 'private-credentials',
  name,
  origin
}: {
  storage: StorageManager
  profile: ControllerProfile
  user: User
  reader: PartyIdentity
  collectionId?: string
  name?: string
  origin?: string
}) {
  const shared = await shareWith(storage, {
    profile,
    user,
    collectionId,
    recipient: reader.recipient,
    controller: reader.did,
    ...(name !== undefined && origin !== undefined && { app: { name, origin } })
  })
  await recordPartyGrants({
    storage,
    did: reader.did,
    zcaps: [shared.zcap],
    grantKind: 'share',
    name,
    origin
  })
  return shared
}

describe('StorageManager.shareCollection', () => {
  it('refuses a zcap that is not read-only on the shared collection, escrowing nothing', async () => {
    const owner = await generateVaultKeys()
    const reader = await generateVaultKeys()
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
      (await storage.listHistoryItems()).entries.some(({ doc }) =>
        doc.type?.includes('CollectionShare')
      )
    ).toBe(false)
  })

  it('first share escrows the reader into the provisioned epoch and delegates a GET/HEAD zcap', async () => {
    const owner = await generateVaultKeys()
    const reader = await generateVaultKeys()
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
    const { entries: history } = await storage.listHistoryItems()
    const shareEntry = history.find(({ doc }) =>
      doc.type?.includes('CollectionShare')
    )
    expect(shareEntry).toBeDefined()
    expect(
      (shareEntry!.doc.object as { zcap?: { id?: string } }).zcap?.id
    ).toBe('urn:zcap:delegated:1')
  })

  it('a second share adds a reader without rotating the epoch', async () => {
    const owner = await generateVaultKeys()
    const readerA = await generateVaultKeys()
    const readerB = await generateVaultKeys()
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

/**
 * The `descriptorLogs` seam over `stores`, with a failing escrow append on
 * one collection. Under `lands`, the append is written and then its response
 * is lost (the call throws). Under `fails`, it throws with nothing written.
 * `failRereads` makes every descriptor read through the source throw once
 * the append has failed, so the re-read after it fails too.
 *
 * @param options {object}
 * @param options.stores {MemoryDescriptorStores}
 * @param options.collectionId {string}
 * @param options.mode {string}   `lands` or `fails`
 * @param [options.failRereads] {boolean}
 * @returns {object}   the seam, and the error the append threw
 */
function lossyEscrowLogs({
  stores,
  collectionId,
  mode,
  failRereads = false
}: {
  stores: MemoryDescriptorStores
  collectionId: string
  mode: 'lands' | 'fails'
  failRereads?: boolean
}): {
  descriptorLogs: ReturnType<typeof descriptorLogsFrom>
  appendError: Error
} {
  const appendError = new Error('escrow append response lost')
  let appendFailed = false
  return {
    appendError,
    descriptorLogs: {
      source: {
        async collectionEncryption(options) {
          if (failRereads && appendFailed) {
            throw new Error('descriptor re-read failed')
          }
          return stores.source.collectionEncryption(options)
        }
      },
      storeFor: async id => {
        const store = stores.storeFor(id)
        if (id !== collectionId) {
          return store
        }
        return {
          ...store,
          async replace(next, options) {
            if (mode === 'lands') {
              await store.replace(next, options)
            }
            appendFailed = true
            throw appendError
          }
        }
      }
    }
  }
}

describe('an escrow whose append response was lost', () => {
  /**
   * A storage manager over provisioned collections, its escrow appends on
   * `collectionId` failing as {@link lossyEscrowLogs} describes.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param options.mode {string}   `lands` or `fails`
   * @param [options.failRereads] {boolean}
   * @returns {Promise<object>}
   */
  async function setup({
    collectionId,
    mode,
    failRereads
  }: {
    collectionId: string
    mode: 'lands' | 'fails'
    failRereads?: boolean
  }) {
    const owner = await generateVaultKeys()
    const reader = await generateVaultKeys()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore, user } = await initLocalStore(ciphers)
    const { zcapClient } = makeFakeZcapClient()
    const { descriptorLogs, appendError } = lossyEscrowLogs({
      stores,
      collectionId,
      mode,
      failRereads
    })
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs,
      ciphers,
      vaultKeys: owner,
      descriptors
    })
    const profile = makeProfile(owner, zcapClient)
    const recipient = ownerRecipient({
      keyAgreementKey: reader.keyAgreementKey
    })
    return { storage, profile, user, recipient, appendError, stores }
  }

  /**
   * Shares `private-credentials` with the reader, counting the escrow
   * reports.
   *
   * @param options {object}
   * @param options.mode {string}   `lands` or `fails`
   * @param [options.failRereads] {boolean}
   * @returns {Promise<object>}   what the call threw, the expected error,
   *   and the report count
   */
  async function share({
    mode,
    failRereads
  }: {
    mode: 'lands' | 'fails'
    failRereads?: boolean
  }) {
    const { storage, profile, user, recipient, appendError } = await setup({
      collectionId: 'private-credentials',
      mode,
      failRereads
    })
    const zcap = await storage.delegateShareGrant({
      profile,
      collectionId: 'private-credentials',
      controller: 'did:key:z6MkReader'
    })
    const onEscrowLanded = vi.fn()
    const thrown = await storage
      .shareCollection({
        profile,
        user,
        collectionId: 'private-credentials',
        recipient,
        zcap,
        onEscrowLanded
      })
      .catch((err: unknown) => err)
    return { thrown, appendError, onEscrowLanded }
  }

  it('reports a share escrow that landed, then throws the original error', async () => {
    const { thrown, appendError, onEscrowLanded } = await share({
      mode: 'lands'
    })
    expect(thrown).toBe(appendError)
    expect(onEscrowLanded).toHaveBeenCalledTimes(1)
  })

  it('does not report a share escrow that did not land', async () => {
    const { thrown, appendError, onEscrowLanded } = await share({
      mode: 'fails'
    })
    expect(thrown).toBe(appendError)
    expect(onEscrowLanded).not.toHaveBeenCalled()
  })

  it('logs a failed re-read and throws the original error, reporting nothing', async () => {
    const captured = captureSink()
    const removeSink = addSink(captured.sink)
    try {
      const { thrown, appendError, onEscrowLanded } = await share({
        mode: 'lands',
        failRereads: true
      })
      expect(thrown).toBe(appendError)
      expect(onEscrowLanded).not.toHaveBeenCalled()
      expect(
        captured.events.some(
          event =>
            event.level === 'warn' &&
            event.msg.includes('Could not re-read the key epoch')
        )
      ).toBe(true)
    } finally {
      removeSink()
    }
  })

  it('reports a first-epoch escrow that landed, then throws the original error', async () => {
    const { storage, recipient, appendError, stores } = await setup({
      collectionId: 'app-docs',
      mode: 'lands'
    })
    const onEscrowLanded = vi.fn()
    const thrown = await storage
      .provisionEncryptedCollection({
        collectionId: 'app-docs',
        recipient,
        onEscrowLanded
      })
      .catch((err: unknown) => err)
    expect(thrown).toBe(appendError)
    expect(onEscrowLanded).toHaveBeenCalledTimes(1)
    expect(currentEpochKids(stores.descriptorOf('app-docs')!)).toContain(
      recipient.id
    )
  })

  it('does not report a first-epoch escrow that did not land', async () => {
    const { storage, recipient, appendError } = await setup({
      collectionId: 'app-docs',
      mode: 'fails'
    })
    const onEscrowLanded = vi.fn()
    const thrown = await storage
      .provisionEncryptedCollection({
        collectionId: 'app-docs',
        recipient,
        onEscrowLanded
      })
      .catch((err: unknown) => err)
    expect(thrown).toBe(appendError)
    expect(onEscrowLanded).not.toHaveBeenCalled()
  })
})

describe('StorageManager.unshareCollection', () => {
  /**
   * A remote session sharing nothing yet, with the owner profile a share and
   * an unshare run under, and a share and an unshare of `private-credentials`
   * bound to it.
   *
   * @param [options] {object}   {@link directorySession}'s options
   * @returns {Promise<object>}
   */
  async function shareSession(
    options: Parameters<typeof directorySession>[0] = {}
  ) {
    const session = await directorySession(options)
    const { zcapClient } = makeFakeZcapClient()
    const profile = makeProfile(session.owner, zcapClient)
    const share = async (
      reader: PartyIdentity,
      named: { name?: string; origin?: string } = {}
    ) =>
      await shareWithParty({
        storage: session.storage,
        profile,
        user: session.user,
        reader,
        ...named
      })
    const unshare = async (reader: PartyIdentity) =>
      await session.storage.unshareCollection({
        profile,
        user: session.user,
        collectionId: 'private-credentials',
        recipientId: reader.recipient.id
      })
    const unshareRecorded = async () =>
      (await session.storage.listHistoryItems()).entries.some(({ doc }) =>
        doc.type?.includes('CollectionUnshare')
      )
    const listed = async () =>
      await session.storage.listCollectionShares({
        collectionId: 'private-credentials',
        connections: (
          await session.storage.readConnectionsListing()
        ).listing.entries.map(({ entry }) => entry)
      })
    return { ...session, profile, share, unshare, unshareRecorded, listed }
  }

  it('rotates the epoch, revokes the share grant, and removes it from the entry', async () => {
    const reader = await generateAppIdentity()
    const { owner, stores, storage, revoked, share, unshare, unshareRecorded } =
      await shareSession()
    const { descriptor: shared } = await share(reader)

    const rotated = await unshare(reader)

    // Read axis: the epoch rotated and the removed reader is off the new
    // roster, as the governing log now holds it.
    expect(stores.descriptorOf('private-credentials')).toEqual(rotated)
    expect(rotated.currentEpoch).not.toBe(shared.currentEpoch)
    expect(currentEpochKids(rotated)).toEqual([owner.keyAgreementKey.id])

    // Pull axis: the share grant the entry records was handed to the revoke
    // recorder.
    expect(revokedIdsOf(revoked)).toEqual(['urn:zcap:delegated:1'])

    // The share grant left the entry, which stays live: the party may hold
    // other grants.
    const { entry } = await readParty({ storage, did: reader.did })
    expect(entry?.grants).toEqual([])
    expect(entry?.retired).toBeUndefined()

    // The unshare was recorded as the audit trail.
    expect(await unshareRecorded()).toBe(true)
  })

  it('disconnecting an app takes it off the wallet collection it holds a share of', async () => {
    const app = await generateAppIdentity()
    const { owner, stores, storage, revoked, share } = await shareSession()
    const { descriptor: shared, zcap } = await share(app, {
      name: 'Notes',
      origin: 'https://notes.example'
    })
    expect(currentEpochKids(shared)).toContain(app.recipient.id)

    const { rotated, outcome } = await revokeAppAuthority({
      storage,
      subjectDid: app.did
    })

    // Read axis: the protected collection rotated, and the app is off its
    // new current epoch.
    expect(rotated).toBe(1)
    const descriptor = stores.descriptorOf('private-credentials')!
    expect(descriptor.currentEpoch).not.toBe(shared.currentEpoch)
    expect(currentEpochKids(descriptor)).toEqual([owner.keyAgreementKey.id])
    // Pull axis: the share grant was revoked once, by the rotation.
    expect(revokedIdsOf(revoked)).toEqual([zcap.id])
    expect(outcome.revoked + outcome.withdrawn).toBeGreaterThan(0)
  })

  it('keeps a torn unshare listed, and a retry POSTs and removes the share grant', async () => {
    const reader = await generateAppIdentity()
    // A refusal the verified document cannot explain: the grant may still be
    // live, so it is no revocation, and the unshare tears after its rotation.
    let refuse = true
    // The in-memory tier, so the adopted descriptor is readable back here.
    const persistence = transientPersistence()
    const {
      owner,
      stores,
      storage,
      remoteStore,
      revoked,
      share,
      unshare,
      unshareRecorded,
      listed
    } = await shareSession({
      persistence,
      revoke: async () => {
        if (refuse) {
          throw new ValidationError('chain does not verify', { status: 400 })
        }
      }
    })
    await share(reader)

    await expect(unshare(reader)).rejects.toMatchObject({
      name: 'ValidationError'
    })

    // The rotation landed and this session adopted it.
    const rotated = stores.descriptorOf('private-credentials')!
    expect(currentEpochKids(rotated)).toEqual([owner.keyAgreementKey.id])
    const cached = await persistence
      .descriptorCache({ scope: remoteStore.spaceId })
      .readDescriptor({ collectionId: 'private-credentials' })
    expect(cached?.currentEpoch).toBe(rotated.currentEpoch)
    // The entry still carries the unexpired share grant, so the panel still
    // lists the reader, though the current epoch no longer does.
    expect(await unshareRecorded()).toBe(false)
    expect(
      (await readParty({ storage, did: reader.did })).grants.map(
        grant => grant.zcapId
      )
    ).toEqual(['urn:zcap:delegated:1'])
    expect(await listed()).toEqual([
      expect.objectContaining({
        recipientId: reader.recipient.id,
        controller: reader.did
      })
    ])

    // A retry re-runs the pull without minting another epoch.
    refuse = false
    const retried = await unshare(reader)
    expect(retried.epochs).toHaveLength(rotated.epochs!.length)
    expect(revokedIdsOf(revoked)).toEqual([
      'urn:zcap:delegated:1',
      'urn:zcap:delegated:1'
    ])
    // The share grant left the entry, so the reader is gone from the panel.
    expect((await readParty({ storage, did: reader.did })).grants).toEqual([])
    expect(await unshareRecorded()).toBe(true)
    expect(await listed()).toEqual([])
  })

  it('marks each unshare stage once its write lands, a torn run stopping after the rotation', async () => {
    const reader = await generateAppIdentity()
    let refuse = true
    const { storage, profile, user, share } = await shareSession({
      revoke: async () => {
        if (refuse) {
          throw new ValidationError('chain does not verify', { status: 400 })
        }
      }
    })
    await share(reader)
    const unshareMarking = async (stages: string[]) =>
      await storage.unshareCollection({
        profile,
        user,
        collectionId: 'private-credentials',
        recipientId: reader.recipient.id,
        onStage: stage => {
          stages.push(stage)
        }
      })

    const torn: string[] = []
    await expect(unshareMarking(torn)).rejects.toMatchObject({
      name: 'ValidationError'
    })
    expect(torn).toEqual(['rotate-recipients'])

    refuse = false
    const retried: string[] = []
    await unshareMarking(retried)
    expect(retried).toEqual([
      'rotate-recipients',
      'revoke-grants',
      'remove-grants',
      'record-activity'
    ])
  })

  it('records the unshare when the server answers AlreadyRevokedError', async () => {
    const reader = await generateAppIdentity()
    const { storage, share, unshare, unshareRecorded } = await shareSession({
      revoke: async () => {
        throw new AlreadyRevokedError('already revoked', { status: 400 })
      }
    })
    await share(reader)

    await unshare(reader)

    expect(await unshareRecorded()).toBe(true)
    expect((await readParty({ storage, did: reader.did })).grants).toEqual([])
  })

  it('unshares a reader whose share no history row records', async () => {
    // The share's history row was never written, or was lost. The entry's
    // share grant is the record the unshare revokes.
    const reader = await generateAppIdentity()
    const { owner, stores, storage, revoked, unshare } = await shareSession()
    await addRecipient({
      store: stores.storeFor('private-credentials'),
      recipient: reader.recipient,
      owner: { keyAgreementKey: owner.keyAgreementKey }
    })
    await recordPartyGrants({
      storage,
      did: reader.did,
      zcaps: [
        collectionGrant({
          id: 'z-share',
          controller: reader.did,
          target: `${SPACE_URL}private-credentials/`
        })
      ],
      grantKind: 'share'
    })
    expect(
      (await storage.listHistoryItems()).entries.filter(({ doc }) =>
        doc.type?.includes('CollectionShare')
      )
    ).toEqual([])

    const rotated = await unshare(reader)

    expect(currentEpochKids(rotated)).toEqual([owner.keyAgreementKey.id])
    expect(revokedIdsOf(revoked)).toEqual(['z-share'])
    expect((await readParty({ storage, did: reader.did })).grants).toEqual([])
  })

  it('admits the other share reader of a protected collection to the fresh epoch', async () => {
    // `private-credentials` is protected, and a share reader there is
    // admitted all the same: unsharing one reader keeps the other.
    const first = await generateAppIdentity()
    const second = await generateAppIdentity()
    const { owner, revoked, share, unshare } = await shareSession()
    await share(first)
    await share(second)

    const rotated = await unshare(first)

    expect(currentEpochKids(rotated)).toHaveLength(2)
    expect(currentEpochKids(rotated)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, second.recipient.id])
    )
    expect(revokedIdsOf(revoked)).toEqual(['urn:zcap:delegated:1'])
  })

  it('escrows the grantee into the blinding-key wrap set and drops it on unshare', async () => {
    const reader = await generateAppIdentity()
    const { owner, share, unshare } = await shareSession({
      blindedIndex: true
    })

    const { descriptor: shared } = await share(reader)

    // The share covers the blinded index too: the grantee unwraps the key.
    expect(hmacKids(shared)).toContain(reader.recipient.id)
    expect(
      await resolveHmacOutcome({
        descriptor: shared,
        keyAgreementKey: reader.keyAgreementKey
      })
    ).toEqual({ id: shared.hmac?.id })

    const rotated = await unshare(reader)

    // Removal drops the wrap entry only: the epoch rotated, the key did not.
    expect(rotated.hmac?.id).toBe(shared.hmac?.id)
    expect(hmacKids(rotated)).not.toContain(reader.recipient.id)
    expect(hmacKids(rotated)).toContain(owner.keyAgreementKey.id)
  })

  describe('the fresh epoch after a rotation', () => {
    it('wraps no reader an earlier unshare removed, even when the roster lists it again', async () => {
      const first = await generateAppIdentity()
      const second = await generateAppIdentity()
      const { owner, stores, share, unshare } = await shareSession()
      await share(first)
      await share(second)
      await unshare(first)
      // The unshared reader reappears on the current epoch, as anyone able
      // to write the descriptor could make it.
      await addRecipient({
        store: stores.storeFor('private-credentials'),
        recipient: first.recipient,
        owner: { keyAgreementKey: owner.keyAgreementKey }
      })
      expect(
        currentEpochKids(stores.descriptorOf('private-credentials')!)
      ).toContain(first.recipient.id)

      const rotated = await unshare(second)

      expect(currentEpochKids(rotated)).toEqual([owner.keyAgreementKey.id])
    })

    it('keeps a reader re-shared after its unshare', async () => {
      const first = await generateAppIdentity()
      const second = await generateAppIdentity()
      const { owner, share, unshare } = await shareSession()
      await share(first)
      await unshare(first)
      await share(first)
      await share(second)

      const rotated = await unshare(second)

      expect(currentEpochKids(rotated)).toHaveLength(2)
      expect(currentEpochKids(rotated)).toEqual(
        expect.arrayContaining([owner.keyAgreementKey.id, first.recipient.id])
      )
    })
  })

  it('lists current shares from the descriptor roster minus the owner', async () => {
    const reader = await generateAppIdentity()
    const { storage, share, listed } = await shareSession()
    await share(reader)

    // The roster alone, unnamed, when no directory entries are handed in.
    expect(
      await storage.listCollectionShares({
        collectionId: 'private-credentials'
      })
    ).toEqual([{ recipientId: reader.recipient.id }])
    // Named by the entry whose DID derives the reader's kid.
    const shares = await listed()
    expect(shares).toHaveLength(1)
    expect(shares[0]).toMatchObject({
      recipientId: reader.recipient.id,
      controller: reader.did
    })
  })

  it('carries the entry name, origin, and latest share expiry through to the listing', async () => {
    const reader = await generateAppIdentity()
    const { storage, share, listed } = await shareSession()

    const { zcap } = await share(reader, {
      name: 'Text Editor',
      origin: 'https://app.example'
    })

    // The pull zcap comes back to the caller (it goes in the response VP).
    expect(zcap.id).toBe('urn:zcap:delegated:1')
    expect((await listed())[0]).toMatchObject({
      appName: 'Text Editor',
      appOrigin: 'https://app.example',
      expires: zcap.expires
    })

    // A later share grant on the same collection carries the expiry, and the
    // user's own label wins over the app's name.
    const later = new Date(Date.now() + 5_000_000).toISOString()
    await recordPartyGrants({
      storage,
      did: reader.did,
      zcaps: [
        collectionGrant({
          id: 'z-later-share',
          controller: reader.did,
          target: `${SPACE_URL}private-credentials/`,
          expires: later
        })
      ],
      grantKind: 'share',
      now: new Date(Date.now() + 60_000)
    })
    const { store, hmacKey } = await storage.connectionsDirectory()
    await setConnectionLabel({
      store,
      hmacKey,
      did: reader.did,
      kind: 'app',
      label: 'My Editor'
    })
    expect((await listed())[0]).toMatchObject({
      appName: 'My Editor',
      appOrigin: 'https://app.example',
      expires: later
    })
  })
})

describe('StorageManager.revokeConnectionGrants', () => {
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
    const owner = await generateVaultKeys()
    const stores = memoryDescriptorStores()
    const remoteStore = makeRevokeRemote(revoke)
    const descriptors = await provisionGovernedCollections(owner, stores)
    const ciphers = await buildCiphers(owner, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    return new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      vaultKeys: owner,
      descriptors,
      signerCheck
    })
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
      spaceUrl: SPACE_URL,
      spaceHandle() {
        return space
      }
    } as unknown as WASRemoteStore
  }

  /**
   * The app's grants over the given capabilities, as its entry records them.
   *
   * @param zcaps {IZcap[]}
   * @returns {ConnectionGrant[]}
   */
  function appGrants(...zcaps: IZcap[]): ConnectionGrant[] {
    return grantsOf({ did: APP_SUBJECT, zcaps })
  }

  /**
   * One of the app's grants on `private-credentials`.
   *
   * @param options {object}   {@link collectionGrant}'s options, less the
   *   controller
   * @returns {IZcap}
   */
  function appGrant(
    options: Omit<Parameters<typeof collectionGrant>[0], 'controller'>
  ): IZcap {
    return collectionGrant({ controller: APP_SUBJECT, ...options })
  }

  it('revokes the live grant and skips an expired one without a POST', async () => {
    const revoked: unknown[] = []
    const storage = await revokeStorage(async zcap => {
      revoked.push(zcap)
    })
    const past = new Date(Date.now() - 1_000_000).toISOString()

    const outcome = await storage.revokeConnectionGrants({
      grants: appGrants(
        appGrant({ id: 'z-active' }),
        appGrant({
          id: 'z-expired',
          collectionId: 'wallet-activity',
          expires: past
        })
      )
    })

    expect(outcome).toEqual({
      revoked: 1,
      withdrawn: 1,
      skipped: 1,
      revokedIds: ['z-active']
    })
    expect(revokedIdsOf(revoked)).toEqual(['z-active'])
  })

  it('revokes no grant an entry holds for a different controller', async () => {
    const revoked: unknown[] = []
    const storage = await revokeStorage(async zcap => {
      revoked.push(zcap)
    })

    // Another controller's grant is another grantee's, so the reader checks
    // drop it before the grant stage sees it.
    const grants = appGrants(
      collectionGrant({ id: 'z-other', controller: 'did:key:z6MkSomeoneElse' })
    )
    expect(grants).toEqual([])
    expect(await storage.revokeConnectionGrants({ grants })).toEqual({
      revoked: 0,
      withdrawn: 0,
      skipped: 0,
      revokedIds: []
    })
    expect(revoked).toHaveLength(0)
  })

  it("counts the server's AlreadyRevokedError as revoked", async () => {
    const storage = await revokeStorage(async () => {
      throw new AlreadyRevokedError('already revoked')
    })

    const outcome = await storage.revokeConnectionGrants({
      grants: appGrants(appGrant({ id: 'z-active' }))
    })

    // The capability is dead on the server: an earlier attempt that landed
    // it and then failed elsewhere recorded nothing, so this run counts it
    // as revoked. This run's POST did not land it, so it is not withdrawn.
    expect(outcome).toEqual({
      revoked: 1,
      withdrawn: 0,
      skipped: 0,
      revokedIds: ['z-active']
    })
  })

  it.each([
    ['a 400', 400],
    ['a 415', 415]
  ])(
    'throws a plain ValidationError (%s) after the other POSTs settle',
    async (_label, status) => {
      const revoked: string[] = []
      const storage = await revokeStorage(async zcap => {
        const { id } = zcap as { id: string }
        if (id === 'z-refused') {
          throw new ValidationError('chain does not verify', { status })
        }
        // The refused POST rejects first; the sibling must still land.
        await new Promise(resolve => setTimeout(resolve, 5))
        revoked.push(id)
      })

      await expect(
        storage.revokeConnectionGrants({
          grants: appGrants(
            appGrant({ id: 'z-refused' }),
            appGrant({ id: 'z-live', collectionId: 'public-credentials' })
          )
        })
      ).rejects.toMatchObject({ name: 'ValidationError', status })
      expect(revoked).toEqual(['z-live'])
    }
  )

  it('lists the grants the server confirmed revoked in revokedIds', async () => {
    const storage = await revokeStorage(async zcap => {
      if ((zcap as { id: string }).id === 'z-done') {
        throw new AlreadyRevokedError('already revoked', { status: 400 })
      }
    })

    const outcome = await storage.revokeConnectionGrants({
      grants: appGrants(
        appGrant({ id: 'z-done' }),
        appGrant({ id: 'z-live', collectionId: 'public-credentials' })
      )
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
    const storage = await revokeStorage(async zcap => {
      posted.push((zcap as { id: string }).id)
    })

    const outcome = await storage.revokeConnectionGrants({
      grants: appGrants(
        appGrant({ id: 'z-rotated', collectionId: 'app-docs' }),
        appGrant({ id: 'z-live', collectionId: 'public-credentials' })
      ),
      revokedByRotation: ['z-rotated']
    })

    expect(outcome).toEqual({
      revoked: 2,
      withdrawn: 1,
      skipped: 0,
      revokedIds: ['z-rotated', 'z-live']
    })
    expect(posted).toEqual(['z-live'])
  })

  it('posts every unexpired grant, logging once, when the signer-check read throws', async () => {
    const posted: string[] = []
    const reads: number[] = []
    const storage = await revokeStorage(
      async zcap => {
        posted.push((zcap as { id: string }).id)
      },
      async () => {
        reads.push(1)
        throw new Error('log unreachable')
      }
    )
    const capture = captureSink()
    const removeSink = addSink(capture.sink)

    try {
      const outcome = await storage.revokeConnectionGrants({
        grants: appGrants(
          appGrant({ id: 'z-one' }),
          appGrant({ id: 'z-two', collectionId: 'public-credentials' })
        )
      })

      expect(outcome).toMatchObject({ revoked: 2, withdrawn: 2, skipped: 0 })
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
    const storage = await revokeStorage(
      async zcap => {
        revoked.push(zcap)
      },
      async () => SIGNER_CHECK
    )
    const past = new Date(Date.now() - 60 * 60 * 1000).toISOString()

    const outcome = await storage.revokeConnectionGrants({
      grants: appGrants(appGrant({ id: 'z-expired', expires: past }))
    })

    expect(outcome).toEqual({
      revoked: 0,
      withdrawn: 0,
      skipped: 1,
      revokedIds: []
    })
    expect(revoked).toHaveLength(0)
  })

  it('reads the refusal of an annex-signed grant under a swapped generation as dead', async () => {
    const posted: string[] = []
    const storage = await revokeStorage(
      async zcap => {
        const { id } = zcap as { id: string }
        posted.push(id)
        if (id === 'z-swapped') {
          throw new ValidationError('chain does not verify', { status: 400 })
        }
      },
      async () => SIGNER_CHECK
    )

    const outcome = await storage.revokeConnectionGrants({
      grants: appGrants(
        appGrant({
          id: 'z-swapped',
          signerKeyId: `${OLD_ANNEX_DID}#z6MkVisit`,
          parent: { controller: OLD_ANNEX_DID, signerKeyId: LADDER_SIGNER }
        }),
        appGrant({
          id: 'z-current',
          collectionId: 'public-credentials',
          signerKeyId: `${ANNEX_DID}#z6MkVisit`,
          parent: { controller: ANNEX_DID, signerKeyId: LADDER_SIGNER }
        })
      )
    })

    // Both are POSTed: the document a login read is a snapshot. The
    // swapped one's refusal reads as a dead chain and counts as skipped.
    expect(outcome).toEqual({
      revoked: 1,
      withdrawn: 1,
      skipped: 1,
      revokedIds: ['z-current']
    })
    expect(posted.sort()).toEqual(['z-current', 'z-swapped'])
  })

  it('reads the refusal of a grant whose generation delegation was signed by a struck key as dead', async () => {
    const posted: string[] = []
    const storage = await revokeStorage(
      async zcap => {
        posted.push((zcap as { id: string }).id)
        throw new ValidationError('chain does not verify', { status: 400 })
      },
      async () => SIGNER_CHECK
    )

    const outcome = await storage.revokeConnectionGrants({
      grants: appGrants(
        appGrant({
          id: 'z-rotted',
          signerKeyId: `${ANNEX_DID}#z6MkVisit`,
          // The pointer still names this generation; the delegation was
          // re-minted within it and its old signer struck.
          parent: { controller: ANNEX_DID, signerKeyId: GONE_SIGNER }
        })
      )
    })

    expect(outcome).toEqual({
      revoked: 0,
      withdrawn: 0,
      skipped: 1,
      revokedIds: []
    })
    expect(posted).toEqual(['z-rotted'])
  })

  it('reads the refusal of an orphaned account-signed grant as dead', async () => {
    const posted: string[] = []
    const storage = await revokeStorage(
      async zcap => {
        const { id } = zcap as { id: string }
        posted.push(id)
        if (id === 'z-orphaned') {
          throw new ValidationError('chain does not verify', { status: 400 })
        }
      },
      async () => SIGNER_CHECK
    )

    const outcome = await storage.revokeConnectionGrants({
      grants: appGrants(
        appGrant({ id: 'z-orphaned', signerKeyId: GONE_SIGNER }),
        appGrant({
          id: 'z-enrolled',
          collectionId: 'public-credentials',
          signerKeyId: ENROLLED_SIGNER
        })
      )
    })

    expect(outcome).toEqual({
      revoked: 1,
      withdrawn: 1,
      skipped: 1,
      revokedIds: ['z-enrolled']
    })
    expect(posted.sort()).toEqual(['z-enrolled', 'z-orphaned'])
  })

  it('throws the refusal of an orphaned-looking grant when no signer check is supplied', async () => {
    const storage = await revokeStorage(async () => {
      throw new ValidationError('chain does not verify', { status: 400 })
    })

    // Nothing local can say why the server refused, so the refusal is
    // the caller's to retry.
    await expect(
      storage.revokeConnectionGrants({
        grants: appGrants(
          appGrant({ id: 'z-orphaned', signerKeyId: GONE_SIGNER })
        )
      })
    ).rejects.toMatchObject({ name: 'ValidationError' })
  })

  it('propagates any other revoke failure', async () => {
    const storage = await revokeStorage(async () => {
      throw new Error('server unreachable')
    })

    await expect(
      storage.revokeConnectionGrants({
        grants: appGrants(appGrant({ id: 'z-active' }))
      })
    ).rejects.toThrow('server unreachable')
  })

  it('is a no-op when no remote store is configured', async () => {
    const owner = await generateVaultKeys()
    const ciphers = await buildCiphers(owner, {})
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      persistence: browserLocalSessionPersistence(),
      localStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })

    const outcome = await storage.revokeConnectionGrants({
      grants: appGrants(appGrant({ id: 'z-active' }))
    })

    expect(outcome).toEqual({
      revoked: 0,
      withdrawn: 0,
      skipped: 0,
      revokedIds: []
    })
  })
})

describe('StorageManager.provisionEncryptedCollection', () => {
  it('first provision mints an epoch with the owner and the app recipient', async () => {
    const owner = await generateVaultKeys()
    const app = await generateVaultKeys()
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
    const owner = await generateVaultKeys()
    const app = await generateVaultKeys()
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
    const owner = await generateVaultKeys()
    const app = await generateVaultKeys()
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
    const owner = await generateVaultKeys()
    const app = await generateVaultKeys()
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
      revoke: [],
      resolveRecipientKey: vouchFor(owner)
    })
    const revokedDescriptor = stores.descriptorOf('app-docs')!
    expect(revokedDescriptor.currentEpoch).not.toEqual(descriptor1.currentEpoch)
    expect(currentEpochKids(revokedDescriptor)).toEqual([
      owner.keyAgreementKey.id
    ])
    // Reconnect: the app is escrowed back in (add, not a rotation, so the
    // roster grows but the current epoch is the post-revoke one).
    const descriptor2 = await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient
    })

    expect(descriptor2.currentEpoch).toEqual(revokedDescriptor.currentEpoch)
    expect(descriptor2.epochs).toHaveLength(revokedDescriptor.epochs!.length)
    expect(currentEpochKids(descriptor2)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, app.keyAgreementKey.id])
    )
  })

  it('is a no-op when the app is already a recipient of the current epoch', async () => {
    const owner = await generateVaultKeys()
    const app = await generateVaultKeys()
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
    const owner = await generateVaultKeys()
    const app = await generateVaultKeys()
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
    const owner = await generateVaultKeys()
    const app = await generateVaultKeys()
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
    const owner = await generateVaultKeys()
    const app = await generateVaultKeys()
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

describe('StorageManager.revokeCollectionRecipients (an app)', () => {
  /**
   * A remote session holding `app-docs`, provisioned for each grantee in
   * turn, with each grantee's live grant on it recorded on its entry.
   *
   * @param options {object}
   * @param options.grantees {PartyIdentity[]}
   * @param [options.record] {PartyIdentity[]}   the grantees whose grant is
   *   recorded; default every one
   * @returns {Promise<object>}
   */
  async function appDocsSession({
    grantees,
    record = grantees
  }: {
    grantees: PartyIdentity[]
    record?: PartyIdentity[]
  }) {
    const session = await directorySession()
    for (const grantee of grantees) {
      await session.storage.provisionEncryptedCollection({
        collectionId: 'app-docs',
        recipient: grantee.recipient
      })
    }
    for (const grantee of record) {
      await recordPartyGrants({
        storage: session.storage,
        did: grantee.did,
        zcaps: [
          collectionGrant({
            id: `z-docs-${grantee.did.slice(-6)}`,
            collectionId: 'app-docs',
            controller: grantee.did
          })
        ]
      })
    }
    const appDocs = async () =>
      (await session.remoteStore.collectionEncryption({
        collectionId: 'app-docs'
      }))!
    return { ...session, appDocs }
  }

  it('rotates the app off each collection its grants target and revokes its grant', async () => {
    const app = await generateAppIdentity()
    const { owner, storage, revoked, appDocs } = await appDocsSession({
      grantees: [app]
    })
    const grantId = `z-docs-${app.did.slice(-6)}`

    const { rotation } = await rotateParty({ storage, did: app.did })

    expect(rotation).toEqual({
      collections: 1,
      rotated: 1,
      failed: 0,
      revokedIds: [grantId]
    })
    // Read axis: the app is off the new current epoch; the owner remains.
    expect(currentEpochKids(await appDocs())).toEqual([
      owner.keyAgreementKey.id
    ])
    // Pull axis: the recorded grant was revoked.
    expect(revokedIdsOf(revoked)).toEqual([grantId])
  })

  it('rotates an app-provisioned collection whose every grant expired', async () => {
    const app = await generateAppIdentity()
    const { owner, storage, revoked, setCollections, appDocs } =
      await appDocsSession({ grantees: [app], record: [] })
    // The collection carries the app's attribution, as provisioning stamps it.
    setCollections([
      {
        id: 'app-docs',
        url: `${SPACE_URL}app-docs/`,
        generator: { id: app.did }
      }
    ])
    // Every recorded grant is long past its own expiry, so there is nothing
    // to revoke.
    await recordPartyGrants({
      storage,
      did: app.did,
      zcaps: [
        collectionGrant({
          id: 'z-app-docs',
          collectionId: 'app-docs',
          controller: app.did,
          expires: new Date(Date.now() - 1_000_000).toISOString()
        })
      ]
    })

    const { rotation } = await rotateParty({ storage, did: app.did })

    expect(rotation).toEqual({
      collections: 1,
      rotated: 1,
      failed: 0,
      revokedIds: []
    })
    expect(currentEpochKids(await appDocs())).toEqual([
      owner.keyAgreementKey.id
    ])
    expect(revoked).toEqual([])
  })

  it('skips a generator-attributed collection the app no longer reads', async () => {
    const app = await generateAppIdentity()
    const other = await generateAppIdentity()
    // The app provisioned the collection and was rotated off it already, so
    // only the attribution still names it; another app reads it today.
    const { owner, storage, setCollections, appDocs } = await appDocsSession({
      grantees: [other],
      record: []
    })
    setCollections([
      {
        id: 'app-docs',
        url: `${SPACE_URL}app-docs/`,
        generator: { id: app.did }
      }
    ])
    const epochsBefore = (await appDocs()).epochs!.length

    const { rotation } = await rotateParty({ storage, did: app.did })

    expect(rotation).toEqual({
      collections: 1,
      rotated: 0,
      failed: 0,
      revokedIds: []
    })
    // Nothing rotated: no epoch was added and the reading app kept its entry.
    const after = await appDocs()
    expect(after.epochs).toHaveLength(epochsBefore)
    expect(currentEpochKids(after)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, other.recipient.id])
    )
  })

  it('leaves a collection the listing reports public out of the candidates', async () => {
    const app = await generateAppIdentity()
    const { stores, storage, setCollections } = await directorySession()
    // A public collection the app provisioned: attributed to it, and
    // carrying no key-epoch roster.
    setCollections([
      {
        id: 'app-public',
        url: `${SPACE_URL}app-public/`,
        generator: { id: app.did },
        isPublic: true
      }
    ])
    const collectionEncryption = vi.spyOn(stores.source, 'collectionEncryption')

    const { rotation } = await rotateParty({ storage, did: app.did })

    expect(rotation).toEqual({
      collections: 0,
      rotated: 0,
      failed: 0,
      revokedIds: []
    })
    expect(collectionEncryption).not.toHaveBeenCalled()
  })

  it('counts a collection listing it could not read as a failure', async () => {
    const app = await generateAppIdentity()
    const { storage, remoteStore } = await directorySession()
    vi.spyOn(remoteStore, 'listCollections').mockRejectedValue(
      new Error('offline')
    )

    const { rotation } = await rotateParty({ storage, did: app.did })

    // The caller cannot tell a rotated app from one still holding a recipient
    // entry, so the disconnect must not report itself done.
    expect(rotation).toEqual({
      collections: 0,
      rotated: 0,
      failed: 1,
      revokedIds: []
    })
  })

  it('leaves a co-admitted app its recipient entry', async () => {
    const app = await generateAppIdentity()
    const other = await generateAppIdentity()
    // The co-admitted app's own grant on its entry is what vouches for its
    // roster entry when the rotation re-wraps the fresh epoch.
    const { owner, storage, revoked, appDocs } = await appDocsSession({
      grantees: [app, other]
    })
    const before = await appDocs()
    expect(currentEpochKids(before)).toHaveLength(3)

    const { rotation } = await rotateParty({ storage, did: app.did })

    expect(rotation).toMatchObject({ collections: 1, rotated: 1, failed: 0 })
    const after = await appDocs()
    // One fresh epoch, and the app that was not disconnected reads on.
    expect(after.epochs).toHaveLength(before.epochs!.length + 1)
    expect(currentEpochKids(after)).toHaveLength(2)
    expect(currentEpochKids(after)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, other.recipient.id])
    )
    expect(revokedIdsOf(revoked)).toEqual([`z-docs-${app.did.slice(-6)}`])
  })

  it('wraps the fresh epoch to no roster entry the wallet did not admit', async () => {
    const app = await generateAppIdentity()
    const other = await generateAppIdentity()
    // A well-formed did:key entry no directory entry names, as anyone able
    // to write the descriptor could inject.
    const junk = await generateAppIdentity()
    const { owner, stores, storage, appDocs } = await appDocsSession({
      grantees: [app, other]
    })
    await addRecipient({
      store: stores.storeFor('app-docs'),
      recipient: junk.recipient,
      owner: { keyAgreementKey: owner.keyAgreementKey }
    })
    const before = await appDocs()
    expect(currentEpochKids(before)).toContain(junk.recipient.id)

    const { rotation } = await rotateParty({ storage, did: app.did })

    expect(rotation).toMatchObject({ collections: 1, rotated: 1, failed: 0 })
    const after = await appDocs()
    expect(after.epochs).toHaveLength(before.epochs!.length + 1)
    expect(currentEpochKids(after)).toHaveLength(2)
    expect(currentEpochKids(after)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, other.recipient.id])
    )
  })

  it('keeps an earlier user key generation a torn user key rotation left on the roster', async () => {
    // A user key rotation that tore before this collection's re-epoch: the
    // session runs on the current user key, and the collection's current
    // epoch still names the previous generation.
    const previous = userKeyVaultKeys({ userKey: await mintUserKey() })
    const current = userKeyVaultKeys({ userKey: await mintUserKey() })
    const app = await generateAppIdentity()
    const other = await generateAppIdentity()
    const stores = memoryDescriptorStores()
    const { remoteStore } = makeFakeRemote({ stores })
    const descriptors = await provisionGovernedCollections(previous, stores)
    const ciphers = await buildCiphers(previous, descriptors)
    const { localStore } = await initLocalStore(ciphers)
    const parts = {
      persistence: browserLocalSessionPersistence(),
      localStore,
      remoteStore,
      descriptorLogs: descriptorLogsFrom(stores),
      ciphers,
      descriptors
    }
    const before = new StorageManager({ ...parts, vaultKeys: previous })
    const memory = standDirectory({ storage: before })
    for (const grantee of [app, other]) {
      await before.provisionEncryptedCollection({
        collectionId: 'app-docs',
        recipient: grantee.recipient
      })
      await recordPartyGrants({
        storage: before,
        did: grantee.did,
        zcaps: [
          collectionGrant({
            id: `z-docs-${grantee.did.slice(-6)}`,
            collectionId: 'app-docs',
            controller: grantee.did
          })
        ]
      })
    }
    const storage = new StorageManager({
      ...parts,
      vaultKeys: current,
      userKeyGenerationKids: async () => [
        previous.keyAgreementKey.id!,
        current.keyAgreementKey.id!
      ]
    })
    standDirectory({ storage, memory })

    const { rotation } = await rotateParty({ storage, did: app.did })

    expect(rotation).toMatchObject({ collections: 1, rotated: 1, failed: 0 })
    const after = (await remoteStore.collectionEncryption({
      collectionId: 'app-docs'
    }))!
    expect(currentEpochKids(after)).toHaveLength(2)
    expect(currentEpochKids(after)).toEqual(
      expect.arrayContaining([previous.keyAgreementKey.id, other.recipient.id])
    )
    // The account still unwraps the fresh epoch through that generation.
    const entry = after
      .epochs!.find(epoch => epoch.id === after.currentEpoch)!
      .recipients.find(
        recipient => recipient.header.kid === previous.keyAgreementKey.id
      )!
    expect(
      await unwrapEpochSecret({
        entry,
        keyAgreementKey: previous.keyAgreementKey
      })
    ).toBeInstanceOf(Uint8Array)
  })

  it('drops the app from the blinding-key wrap set without rotating the key', async () => {
    const app = await generateAppIdentity()
    const { owner, storage, appDocs } = await appDocsSession({
      grantees: [app]
    })
    const hmacId = (await appDocs()).hmac?.id

    await rotateParty({ storage, did: app.did })

    const descriptor = await appDocs()
    // The key never rotates -- blinded tokens must compare across the
    // collection's whole history -- so only the app's wrap entry goes.
    expect(descriptor.hmac?.id).toBe(hmacId)
    expect(hmacKids(descriptor)).not.toContain(app.recipient.id)
    expect(
      await resolveHmacOutcome({
        descriptor,
        keyAgreementKey: app.keyAgreementKey
      })
    ).toEqual({ errorName: 'EncryptionError' })
    // The owner still resolves the same key.
    expect(
      await resolveHmacOutcome({
        descriptor,
        keyAgreementKey: owner.keyAgreementKey
      })
    ).toEqual({ id: hmacId })
  })

  it.each([
    [
      'a collection target',
      `${SPACE_URL}app-docs/`,
      { collections: 1, rotated: 1, failed: 0, revokedIds: ['z-app-docs'] },
      ['z-app-docs']
    ],
    [
      'a reserved sub-endpoint target',
      `${SPACE_URL}app-docs/meta`,
      { collections: 0, rotated: 0, failed: 0, revokedIds: [] },
      []
    ],
    [
      // A candidate, since a share reader sits on a protected collection's
      // roster; the app holds no recipient entry there, so nothing rotates.
      'a protected collection target',
      `${SPACE_URL}private-credentials`,
      { collections: 1, rotated: 0, failed: 0, revokedIds: [] },
      []
    ]
  ])(
    'recovers the collection id from %s recorded on the entry',
    async (_label, target, expected, expectedRevoked) => {
      const app = await generateAppIdentity()
      const { storage, revoked } = await appDocsSession({
        grantees: [app],
        record: []
      })
      await recordPartyGrants({
        storage,
        did: app.did,
        zcaps: [
          collectionGrant({ id: 'z-app-docs', controller: app.did, target })
        ]
      })

      const { rotation } = await rotateParty({ storage, did: app.did })

      expect(rotation).toEqual(expected)
      expect(revokedIdsOf(revoked)).toEqual(expectedRevoked)
    }
  )

  it('is a no-op for a DID no recipient key derives from', async () => {
    const { storage } = await directorySession()
    const did = 'did:web:app.example'
    // A recorded grant and a collection stamped with the DID as its
    // generator: either would name a candidate collection, so only the
    // missing recipient key leaves the result empty.
    await recordPartyGrants({
      storage,
      did,
      zcaps: [
        collectionGrant({
          id: 'z-web-docs',
          collectionId: 'app-docs',
          controller: did
        })
      ]
    })

    const { rotation, grants } = await rotateParty({
      storage,
      did,
      collections: [
        {
          id: 'app-docs',
          url: `${SPACE_URL}app-docs/`,
          isPublic: false,
          generator: { id: did }
        }
      ]
    })

    expect(grants).toHaveLength(1)
    expect(rotation).toEqual({
      collections: 0,
      rotated: 0,
      failed: 0,
      revokedIds: []
    })
  })
})

describe('StorageManager.revokeCollectionRecipients (an agent)', () => {
  /**
   * A remote session holding one private collection provisioned for `agent`,
   * with the agent's grant on it recorded on its `kind: 'agent'` entry.
   *
   * @param agent {PartyIdentity}
   * @param [options] {object}
   * @param [options.revoke] {Function}
   * @param [options.signerCheck] {Function}
   * @param [options.signerKeyId] {string}   the grant's signer
   * @param [options.persistence] {SessionPersistence}
   * @returns {Promise<object>}
   */
  async function agentGrantStorage(
    agent: PartyIdentity,
    {
      revoke,
      signerCheck,
      signerKeyId,
      persistence
    }: {
      revoke?: (zcap: unknown) => Promise<void>
      signerCheck?: () => Promise<AccountSignerCheck | undefined>
      signerKeyId?: string
      persistence?: SessionPersistence
    } = {}
  ) {
    const session = await directorySession({
      revoke,
      signerCheck,
      ...(persistence && { persistence })
    })
    await session.storage.provisionEncryptedCollection({
      collectionId: 'agent-notes',
      recipient: agent.recipient
    })
    await recordPartyGrants({
      storage: session.storage,
      did: agent.did,
      kind: 'agent',
      zcaps: [
        collectionGrant({
          id: 'z-agent-notes',
          collectionId: 'agent-notes',
          controller: agent.did,
          ...(signerKeyId && { signerKeyId })
        })
      ]
    })
    return session
  }

  /**
   * The agent's grant stage, as the session layer runs it after the
   * rotation.
   *
   * @param options {object}
   * @param options.storage {StorageManager}
   * @param options.did {string}
   * @param [options.revokedByRotation] {string[]}
   * @returns {Promise<object>}
   */
  async function revokeGrants({
    storage,
    did,
    revokedByRotation
  }: {
    storage: StorageManager
    did: string
    revokedByRotation?: string[]
  }) {
    const { grants } = await readParty({ storage, did })
    return await storage.revokeConnectionGrants({
      grants,
      ...(revokedByRotation && { revokedByRotation })
    })
  }

  it('rotates the agent off each granted collection and revokes its grant', async () => {
    const agent = await generateAppIdentity()
    const { owner, storage, remoteStore, revoked } =
      await agentGrantStorage(agent)

    const { rotation } = await rotateParty({ storage, did: agent.did })

    expect(rotation).toEqual({
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
    expect(revokedIdsOf(revoked)).toEqual(['z-agent-notes'])
  })

  it('rotates an agent-provisioned collection its entry holds no grant on, through the generator stamp alone', async () => {
    const agent = await generateAppIdentity()
    const { owner, storage, remoteStore, revoked, setCollections, localStore } =
      await directorySession()
    await storage.provisionEncryptedCollection({
      collectionId: 'agent-notes',
      recipient: agent.recipient
    })
    // The entry records the agent and no grant on the collection: the
    // consent's grant was lost, and no Login or Grant activity row exists
    // either. The collection carries the agent's stamp, as the
    // interaction-URL path stamps it: `id` and the self-attested `name`,
    // with no `origin` or `url`.
    await recordPartyGrants({
      storage,
      did: agent.did,
      kind: 'agent',
      zcaps: []
    })
    setCollections([
      {
        id: 'agent-notes',
        url: `${SPACE_URL}agent-notes/`,
        generator: { id: agent.did, name: 'Notes agent' }
      }
    ])
    expect((await localStore.listHistoryItems()).entries).toEqual([])

    const { rotation } = await rotateParty({ storage, did: agent.did })

    expect(rotation).toEqual({
      collections: 1,
      rotated: 1,
      failed: 0,
      revokedIds: []
    })
    const descriptor = await remoteStore.collectionEncryption({
      collectionId: 'agent-notes'
    })
    expect(currentEpochKids(descriptor!)).toEqual([owner.keyAgreementKey.id])
    expect(revoked).toEqual([])
  })

  it('skips a plaintext inbox or audience target, which resolves no descriptor', async () => {
    const agent = await generateAppIdentity()
    const { storage } = await agentGrantStorage(agent)
    await recordPartyGrants({
      storage,
      did: agent.did,
      kind: 'agent',
      zcaps: [
        collectionGrant({
          id: 'z-agent-inbox',
          collectionId: 'inbox',
          controller: agent.did
        }),
        collectionGrant({
          id: 'z-agent-news',
          collectionId: 'news',
          controller: agent.did
        })
      ]
    })

    const { rotation } = await rotateParty({ storage, did: agent.did })

    // `inbox` and the audience reach the epoch read, find no key epochs, and
    // are skipped: neither counts as a rotation failure.
    expect(rotation).toMatchObject({
      collections: 3,
      rotated: 1,
      failed: 0
    })
    expect(
      await storage.granteeRosterCollections({
        grantees: [
          {
            controller: agent.did,
            targets: [`${SPACE_URL}inbox`, `${SPACE_URL}news`]
          }
        ]
      })
    ).toEqual([{ controller: agent.did, collectionIds: [], failed: 0 }])
  })

  it('revokes an agent holding plaintext audience and inbox grants: every grant POSTed, its channel and outbox emptied, the entry retired', async () => {
    const agent = await generateAppIdentity()
    const pairwise = await generateAppIdentity()
    const { storage, user, revoked } = await agentGrantStorage(agent)
    const inboxGrant = collectionGrant({
      id: 'z-agent-inbox',
      collectionId: 'inbox',
      controller: agent.did
    })
    const newsGrant = collectionGrant({
      id: 'z-agent-news',
      collectionId: 'news',
      controller: agent.did
    })
    const { store, hmacKey, spaceUrl } = await storage.connectionsDirectory()
    await recordGrants({
      store,
      hmacKey,
      spaceUrl,
      did: agent.did,
      kind: 'agent',
      grants: [inboxGrant, newsGrant].map(zcap => ({
        zcap,
        grantKind: 'grant' as const
      })),
      // A pending envelope, as a renewal or a restore leaves one.
      message: {
        type: 'Grant',
        actor: pairwise.did,
        object: { zcaps: [inboxGrant, newsGrant] }
      }
    })
    await recordReceivedGrants({
      store,
      hmacKey,
      did: agent.did,
      pairwiseDid: pairwise.did,
      spaceUrl: spaceUrl!,
      grants: [
        {
          zcap: {
            id: 'z-channel',
            controller: pairwise.did,
            parentCapability: 'urn:zcap:root:agent',
            invocationTarget: 'https://agent.example/space/a/inbox/',
            allowedAction: ['POST'],
            expires: new Date(Date.now() + 1_000_000).toISOString(),
            proof: {
              type: 'Ed25519Signature2020',
              proofPurpose: 'capabilityDelegation',
              verificationMethod: 'did:webvh:agent#z6MkAgent',
              capabilityChain: ['urn:zcap:root:agent']
            }
          },
          grantKind: 'inbox'
        }
      ],
      channelMaxLifetimeMs: 365 * 24 * 60 * 60 * 1000
    })
    const before = await readParty({ storage, did: agent.did })
    expect(before.entry?.grantsReceived).toHaveLength(1)
    expect(before.entry?.outbox).toHaveLength(1)

    const outcome = await revokeAgentAccess({
      storage,
      user,
      agent: {
        resourceId: '',
        controller: agent.did,
        origin: EXTERNAL_REQUEST_ORIGIN,
        grants: []
      }
    })

    // The rotation re-keys the one encrypted collection; `inbox` and the
    // audience resolve no descriptor and count no failure.
    expect(outcome).toMatchObject({ rotated: 1 })
    expect(revokedIdsOf(revoked).sort()).toEqual([
      'z-agent-inbox',
      'z-agent-news',
      'z-agent-notes'
    ])
    const { entry } = await readParty({ storage, did: agent.did })
    expect(entry?.retired).toBeDefined()
    expect(entry?.grants).toEqual([])
    expect(entry?.grantsReceived).toEqual([])
    expect(entry?.outbox).toEqual([])
  })

  it('hands the rotated grants to the grant stage, which does not POST them again', async () => {
    const agent = await generateAppIdentity()
    const { storage, revoked } = await agentGrantStorage(agent)

    const { rotation } = await rotateParty({ storage, did: agent.did })
    const outcome = await revokeGrants({
      storage,
      did: agent.did,
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
    expect(revokedIdsOf(revoked)).toEqual(['z-agent-notes'])
  })

  it("revokes none of another agent's grants", async () => {
    const agent = await generateAppIdentity()
    const other = await generateAppIdentity()
    const { storage, revoked } = await agentGrantStorage(agent)
    await recordPartyGrants({
      storage,
      did: other.did,
      kind: 'agent',
      zcaps: [
        collectionGrant({
          id: 'z-other-notes',
          collectionId: 'other-notes',
          controller: other.did
        })
      ]
    })

    expect(await revokeGrants({ storage, did: agent.did })).toEqual({
      revoked: 1,
      withdrawn: 1,
      skipped: 0,
      revokedIds: ['z-agent-notes']
    })
    expect(revokedIdsOf(revoked)).toEqual(['z-agent-notes'])
  })

  it('is a no-op for a controller no recipient key derives from', async () => {
    const agent = await generateAppIdentity()
    const { storage } = await agentGrantStorage(agent)
    const did = 'did:web:agent.example'
    // A recorded grant on the agent's collection would name it a candidate,
    // so only the missing recipient key leaves the result empty.
    await recordPartyGrants({
      storage,
      did,
      kind: 'agent',
      zcaps: [
        collectionGrant({
          id: 'z-web-notes',
          collectionId: 'agent-notes',
          controller: did
        })
      ]
    })

    const { rotation, grants } = await rotateParty({ storage, did })

    expect(grants).toHaveLength(1)
    expect(rotation).toEqual({
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
      `${SPACE_URL}agent-notes`,
      // Protected: the agent holds no roster entry there to rotate.
      `${SPACE_URL}private-credentials`,
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
    await rotateParty({ storage, did: agent.did })
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
    const target = `${SPACE_URL}agent-notes`

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
    const target = `${SPACE_URL}agent-notes`

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
    // pws-client's default pull reads every ValidationError as already
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

    const { rotation } = await rotateParty({ storage, did: agent.did })

    expect(rotation).toEqual({
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
      revokeGrants({
        storage,
        did: agent.did,
        revokedByRotation: rotation.revokedIds
      })
    ).rejects.toMatchObject({ name: 'ValidationError' })
  })

  it('retires the entry and records the Revoke when the grant stage revokes what a failed pull missed', async () => {
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
        resourceId: '',
        controller: agent.did,
        origin: EXTERNAL_REQUEST_ORIGIN,
        grants: []
      }
    })

    expect(outcome).toMatchObject({ revoked: 1, rotated: 1 })
    expect(attempts).toBe(2)
    const { entry } = await readParty({ storage, did: agent.did })
    expect(entry?.retired).toBeDefined()
    expect(entry?.grants).toEqual([])
    const { entries: items } = await storage.listHistoryItems()
    expect(items.some(({ doc }) => doc.type?.includes('Revoke'))).toBe(true)
  })

  it('names a pull the server answers AlreadyRevokedError', async () => {
    const agent = await generateAppIdentity()
    const { storage } = await agentGrantStorage(agent, {
      revoke: async () => {
        throw new AlreadyRevokedError('already revoked', { status: 400 })
      }
    })

    expect((await rotateParty({ storage, did: agent.did })).rotation).toEqual({
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

    const { rotation } = await rotateParty({ storage, did: agent.did })

    // The grant is dead already, so the rotation lands but revokes nothing.
    expect(rotation).toEqual({
      collections: 1,
      rotated: 1,
      failed: 0,
      revokedIds: []
    })
    expect(
      await revokeGrants({
        storage,
        did: agent.did,
        revokedByRotation: rotation.revokedIds
      })
    ).toEqual({ revoked: 0, withdrawn: 0, skipped: 1, revokedIds: [] })
  })

  it('reads no key epoch for a grant target the listing reports public', async () => {
    const agent = await generateAppIdentity()
    const { stores, storage, setCollections } = await agentGrantStorage(agent)
    setCollections([
      { id: 'agent-notes', url: `${SPACE_URL}agent-notes/` },
      {
        id: 'agent-public',
        url: `${SPACE_URL}agent-public/`,
        isPublic: true
      }
    ])
    const collectionEncryption = vi.spyOn(stores.source, 'collectionEncryption')
    const publicTarget = `${SPACE_URL}agent-public`
    await recordPartyGrants({
      storage,
      did: agent.did,
      kind: 'agent',
      zcaps: [
        collectionGrant({
          id: 'z-agent-public',
          controller: agent.did,
          target: publicTarget
        })
      ]
    })

    expect(
      await storage.granteeRosterCollections({
        grantees: [
          {
            controller: agent.did,
            targets: [`${SPACE_URL}agent-notes`, publicTarget]
          }
        ]
      })
    ).toEqual([
      { controller: agent.did, collectionIds: ['agent-notes'], failed: 0 }
    ])
    // The revocation skips the public collection as well, and rotates the
    // private one.
    expect((await rotateParty({ storage, did: agent.did })).rotation).toEqual({
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

  it('rotates a collection its generator stamp names, with no grant recording it', async () => {
    const agent = await generateAppIdentity()
    const { owner, storage, remoteStore, setCollections } =
      await agentGrantStorage(agent)
    // A second collection provisioned for the agent, with no grant on its
    // entry: only its `generator` stamp names the agent.
    await storage.provisionEncryptedCollection({
      collectionId: 'agent-drafts',
      recipient: agent.recipient
    })
    setCollections([
      { id: 'agent-notes', url: `${SPACE_URL}agent-notes/` },
      {
        id: 'agent-drafts',
        url: `${SPACE_URL}agent-drafts/`,
        generator: { id: agent.did }
      }
    ])

    expect((await rotateParty({ storage, did: agent.did })).rotation).toEqual({
      collections: 2,
      rotated: 2,
      failed: 0,
      revokedIds: ['z-agent-notes']
    })
    const descriptor = await remoteStore.collectionEncryption({
      collectionId: 'agent-drafts'
    })
    expect(currentEpochKids(descriptor!)).toEqual([owner.keyAgreementKey.id])
  })

  it('counts a listing it could not read as a failure, and still rotates', async () => {
    const agent = await generateAppIdentity()
    const { storage, remoteStore } = await agentGrantStorage(agent)
    vi.spyOn(remoteStore, 'listCollections').mockRejectedValue(
      new Error('offline')
    )

    // Without the listing a public target cannot be told apart, so the
    // revocation cannot say the agent is off every roster. The private
    // collection is rotated all the same.
    expect((await rotateParty({ storage, did: agent.did })).rotation).toEqual({
      collections: 1,
      rotated: 1,
      failed: 1,
      revokedIds: ['z-agent-notes']
    })
  })

  it('leaves the entry live and records no Revoke when the listing cannot be read', async () => {
    const agent = await generateAppIdentity()
    const { storage, remoteStore, user } = await agentGrantStorage(agent)
    vi.spyOn(remoteStore, 'listCollections').mockRejectedValue(
      new Error('offline')
    )

    await expect(
      revokeAgentAccess({
        storage,
        user,
        agent: {
          resourceId: '',
          controller: agent.did,
          origin: EXTERNAL_REQUEST_ORIGIN,
          grants: []
        }
      })
    ).rejects.toThrow(/Could not rotate every collection/)
    const { entry } = await readParty({ storage, did: agent.did })
    expect(entry?.retired).toBeUndefined()
    const { entries: items } = await storage.listHistoryItems()
    expect(items.some(({ doc }) => doc.type?.includes('Revoke'))).toBe(false)
  })
})

describe('the admitted-recipient resolver over the connections directory', () => {
  /**
   * A remote session holding `app-docs` for the app being revoked and a
   * co-admitted reader, each with its live grant there recorded on its entry.
   * The app's grants are read before a test touches the directory.
   *
   * @returns {Promise<object>}
   */
  async function coAdmittedSession() {
    const session = await directorySession()
    const app = await generateAppIdentity()
    const other = await generateAppIdentity()
    const stranger = await generateAppIdentity()
    for (const grantee of [app, other]) {
      await session.storage.provisionEncryptedCollection({
        collectionId: 'app-docs',
        recipient: grantee.recipient
      })
      await recordPartyGrants({
        storage: session.storage,
        did: grantee.did,
        zcaps: [
          collectionGrant({
            id: `z-docs-${grantee === app ? 'app' : 'other'}`,
            collectionId: 'app-docs',
            controller: grantee.did
          })
        ]
      })
    }
    const { grants } = await readParty({
      storage: session.storage,
      did: app.did
    })
    const appDocs = async () =>
      (await session.remoteStore.collectionEncryption({
        collectionId: 'app-docs'
      }))!
    return { ...session, app, other, stranger, grants, appDocs }
  }

  /**
   * Asserts a rotation failed closed: one failure, nothing rotated, no new
   * epoch on `app-docs`, and no revocation POSTed.
   *
   * @param options {object}
   * @param options.rotation {object}   the rotation outcome
   * @param options.before {CollectionEncryption}   `app-docs` before it ran
   * @param options.after {CollectionEncryption}   `app-docs` after it ran
   * @param options.revoked {unknown[]}   the fake remote's revoke recorder
   */
  function expectFailedClosed({
    rotation,
    before,
    after,
    revoked
  }: {
    rotation: Awaited<ReturnType<StorageManager['revokeCollectionRecipients']>>
    before: CollectionEncryption
    after: CollectionEncryption
    revoked: unknown[]
  }): void {
    expect(rotation).toEqual({
      collections: 1,
      rotated: 0,
      failed: 1,
      revokedIds: []
    })
    expect(after).toEqual(before)
    expect(after.epochs).toHaveLength(before.epochs!.length)
    expect(revoked).toEqual([])
  }

  it.each<
    [
      string,
      (options: {
        memory: MemoryDirectory
        stranger: PartyIdentity
      }) => Promise<void>
    ]
  >([
    [
      'a listing the store cannot read',
      async ({ memory }) => {
        vi.spyOn(memory.store, 'list').mockResolvedValue(null)
      }
    ],
    [
      'an entry it cannot decrypt',
      async ({ memory }) => {
        const list = memory.store.list
        vi.spyOn(memory.store, 'list').mockImplementation(async () => [
          ...((await list()) ?? []),
          {
            resourceId: 'zUndecryptable',
            readError: new Error('unknown epoch')
          }
        ])
      }
    ],
    [
      'an unparseable body at its own id',
      async ({ memory, stranger }) => {
        await plantEntry({
          memory,
          body: { version: 1, kind: 'app', id: stranger.did, grants: 'none' }
        })
      }
    ],
    [
      'an entry from a newer build at its own id',
      async ({ memory, stranger }) => {
        await plantEntry({
          memory,
          body: entryBody({ did: stranger.did, version: 2 })
        })
      }
    ]
  ])('fails closed, wrapping nothing, on %s', async (_label, corrupt) => {
    const { storage, memory, stranger, app, grants, revoked, appDocs } =
      await coAdmittedSession()
    await corrupt({ memory, stranger })
    const before = await appDocs()

    // No directory handed in, so the rotation reads it, as a caller that
    // read the party's grants elsewhere would have it do.
    const rotation = await storage.revokeCollectionRecipients({
      did: app.did,
      grants
    })

    expectFailedClosed({ rotation, before, after: await appDocs(), revoked })
  })

  it('fails closed, wrapping nothing, on an absent directory', async () => {
    const { storage, app, grants, revoked, appDocs } = await coAdmittedSession()
    // The real directory binding: this account holds no `connections`
    // descriptor, so every directory read is refused.
    vi.mocked(storage.connectionsDirectory).mockRestore()
    await expect(storage.connectionsDirectory()).rejects.toThrow('absent')
    const before = await appDocs()

    const rotation = await storage.revokeCollectionRecipients({
      did: app.did,
      grants
    })

    expectFailedClosed({ rotation, before, after: await appDocs(), revoked })
  })

  it('ignores a body at an id its own members do not derive, and rotates', async () => {
    const { owner, stores, storage, memory, stranger, app, grants, appDocs } =
      await coAdmittedSession()
    // A stranger on the roster, and a well-formed entry granting it the
    // collection, misplaced at an id its own DID does not derive to.
    await addRecipient({
      store: stores.storeFor('app-docs'),
      recipient: stranger.recipient,
      owner: { keyAgreementKey: owner.keyAgreementKey }
    })
    await plantEntry({
      memory,
      resourceId: 'zMisplacedEntry',
      body: entryBody({
        did: stranger.did,
        zcaps: [
          collectionGrant({
            id: 'z-stranger',
            collectionId: 'app-docs',
            controller: stranger.did
          })
        ]
      })
    })

    const rotation = await storage.revokeCollectionRecipients({
      did: app.did,
      grants
    })

    expect(rotation).toEqual({
      collections: 1,
      rotated: 1,
      failed: 0,
      revokedIds: ['z-docs-app']
    })
    expect(currentEpochKids(await appDocs())).toHaveLength(2)
  })

  it('wraps no retired party, and wraps a live party whose grant expired', async () => {
    const { owner, stores, storage, memory, app, grants, appDocs } =
      await coAdmittedSession()
    const retired = await generateAppIdentity()
    const lapsed = await generateAppIdentity()
    for (const grantee of [retired, lapsed]) {
      await addRecipient({
        store: stores.storeFor('app-docs'),
        recipient: grantee.recipient,
        owner: { keyAgreementKey: owner.keyAgreementKey }
      })
    }
    // A retired entry still carrying its grant: the retirement alone keeps
    // it out of the fresh epoch.
    await plantEntry({
      memory,
      body: entryBody({
        did: retired.did,
        retired: '2026-09-02T00:00:00.000Z',
        zcaps: [
          collectionGrant({
            id: 'z-retired',
            collectionId: 'app-docs',
            controller: retired.did
          })
        ]
      })
    })
    // A live entry whose only grant expired: its recipient entry outlives
    // the grant, so it is still admitted.
    await recordPartyGrants({
      storage,
      did: lapsed.did,
      kind: 'agent',
      zcaps: [
        collectionGrant({
          id: 'z-lapsed',
          collectionId: 'app-docs',
          controller: lapsed.did,
          expires: new Date(Date.now() - 1_000_000).toISOString()
        })
      ]
    })

    const rotation = await storage.revokeCollectionRecipients({
      did: app.did,
      grants
    })

    expect(rotation).toMatchObject({ rotated: 1, failed: 0 })
    const kids = currentEpochKids(await appDocs())
    expect(kids).toContain(lapsed.recipient.id)
    expect(kids).not.toContain(retired.recipient.id)
    expect(kids).not.toContain(app.recipient.id)
    expect(kids).toHaveLength(3)
  })
})

describe('a revocation with no history row', () => {
  it('rotates an app and an agent off every collection and POSTs every grant', async () => {
    const app = await generateAppIdentity()
    const agent = await generateAppIdentity()
    const { owner, storage, revoked, setCollections, remoteStore } =
      await directorySession()
    // `app-docs` the app created; the agent was admitted to it by its grant.
    // `team-notes` carries no generator stamp, and the agent reads it by its
    // grant alone.
    for (const [collectionId, grantees] of [
      ['app-docs', [app, agent]],
      ['team-notes', [agent]]
    ] as const) {
      for (const grantee of grantees) {
        await storage.provisionEncryptedCollection({
          collectionId,
          recipient: grantee.recipient
        })
      }
    }
    setCollections([
      {
        id: 'app-docs',
        url: `${SPACE_URL}app-docs/`,
        generator: { id: app.did }
      },
      { id: 'team-notes', url: `${SPACE_URL}team-notes/` }
    ])
    await recordPartyGrants({
      storage,
      did: app.did,
      zcaps: [
        collectionGrant({
          id: 'z-app-docs',
          collectionId: 'app-docs',
          controller: app.did
        })
      ]
    })
    await recordPartyGrants({
      storage,
      did: agent.did,
      kind: 'agent',
      zcaps: [
        collectionGrant({
          id: 'z-agent-docs',
          collectionId: 'app-docs',
          controller: agent.did
        }),
        collectionGrant({
          id: 'z-agent-team',
          collectionId: 'team-notes',
          controller: agent.did
        })
      ]
    })
    // Not one Grant, CollectionShare, or Login row exists.
    expect((await storage.listHistoryItems()).entries).toEqual([])

    for (const party of [app, agent]) {
      const { rotation, grants } = await rotateParty({
        storage,
        did: party.did
      })
      expect(rotation.failed).toBe(0)
      await storage.revokeConnectionGrants({
        grants,
        revokedByRotation: rotation.revokedIds
      })
    }

    for (const collectionId of ['app-docs', 'team-notes']) {
      const descriptor = await remoteStore.collectionEncryption({
        collectionId
      })
      expect(currentEpochKids(descriptor!), collectionId).toEqual([
        owner.keyAgreementKey.id
      ])
    }
    expect(revokedIdsOf(revoked).sort()).toEqual([
      'z-agent-docs',
      'z-agent-team',
      'z-app-docs'
    ])
  })
})

describe('a planted directory entry', () => {
  it("steers no revocation at another party's grants or app key", async () => {
    const victim = await mintAppKeyCredential({
      app: { name: 'Victim', appUrl: 'https://victim.example/app' },
      origin: 'https://victim.example'
    })
    const victimDid = (victim.credential.credentialSubject as { id: string }).id
    const planted = await generateAppIdentity()
    const {
      owner,
      storage,
      memory,
      ciphers,
      seedResource,
      remoteStore,
      revoked
    } = await directorySession({ appKeys: true })
    await storage.provisionEncryptedCollection({
      collectionId: 'app-docs',
      recipient: x25519RecipientFromDidKey({ did: victimDid })
    })
    const { id: victimKeyId, envelope } = await ciphers.appKeys.encrypt({
      data: victim.credential as unknown as Json
    })
    seedResource({
      logicalKey: 'appKeys',
      resourceId: victimKeyId,
      body: envelope
    })
    // An entry at the planted party's id, carrying the victim's grant and
    // naming the victim's app key.
    const body = entryBody({
      did: planted.did,
      appKey: victimKeyId,
      zcaps: [
        collectionGrant({
          id: 'z-victim',
          collectionId: 'app-docs',
          controller: victimDid
        })
      ]
    })
    await plantEntry({ memory, body })

    // The reader checks drop a grant delegated to another party.
    const { entry, grants } = await readParty({ storage, did: planted.did })
    expect(entry?.appKey).toBe(victimKeyId)
    expect(grants).toEqual([])
    const { outcome, rotated } = await revokeAppAuthority({
      storage,
      subjectDid: planted.did
    })
    expect(outcome).toMatchObject({ revoked: 0, withdrawn: 0 })
    expect(rotated).toBe(0)
    expect(revoked).toEqual([])
    const descriptor = await remoteStore.collectionEncryption({
      collectionId: 'app-docs'
    })
    expect(currentEpochKids(descriptor!)).toEqual(
      expect.arrayContaining([
        owner.keyAgreementKey.id,
        x25519RecipientFromDidKey({ did: victimDid }).id
      ])
    )

    // The app key does not bind the planted DID, so it is left on the server.
    expect(
      await storage.deleteAppKeyResource({
        appKey: victimKeyId,
        did: planted.did
      })
    ).toBe('foreign')
    expect(
      (await remoteStore.listSyncedDocuments({ logicalKey: 'appKeys' })).map(
        ({ id }) => id
      )
    ).toEqual([victimKeyId])
  })
})

describe('StorageManager.deleteAppKeyResource (remote)', () => {
  it('deletes every server copy of the key before the replica holds it', async () => {
    // A remembered session before its pull: the local replica holds no copy,
    // and the server holds the key twice under two ids.
    const { storage, ciphers, seedResource, remoteStore, localStore } =
      await directorySession({ appKeys: true })
    const editor = await mintAppKeyCredential({
      app: { name: 'Editor', appUrl: 'https://app.example/editor' },
      origin: 'https://app.example'
    })
    const reader = await mintAppKeyCredential({
      app: { name: 'Reader', appUrl: 'https://app.example/reader' },
      origin: 'https://app.example'
    })
    const editorDid = (editor.credential.credentialSubject as { id: string }).id
    const seeded: Record<string, string> = {}
    for (const [label, credential] of [
      ['editor-1', editor.credential],
      ['editor-2', editor.credential],
      ['reader', reader.credential]
    ] as const) {
      const { id, envelope } = await ciphers.appKeys.encrypt({
        data: credential as unknown as Json
      })
      seedResource({
        logicalKey: 'appKeys',
        resourceId: id,
        body: envelope
      })
      seeded[label] = id
    }
    expect(await localStore.rxCollection('appKeys').find().exec()).toHaveLength(
      0
    )
    const held = async () =>
      (await remoteStore.listSyncedDocuments({ logicalKey: 'appKeys' })).map(
        ({ id }) => id
      )

    expect(
      await storage.deleteAppKeyResource({
        appKey: seeded['editor-1'],
        did: editorDid
      })
    ).toBe('deleted')

    // Both copies of the key are gone from the server; the other app's stays.
    expect(await held()).toEqual([seeded.reader])
    // A dangling reference reads as already deleted.
    expect(
      await storage.deleteAppKeyResource({
        appKey: seeded['editor-1'],
        did: editorDid
      })
    ).toBe('absent')
    expect(await held()).toEqual([seeded.reader])
  })

  it('deletes the named copy last, so a retry after a torn delete finds the rest', async () => {
    const { storage, ciphers, seedResource, remoteStore } =
      await directorySession({ appKeys: true })
    const editor = await mintAppKeyCredential({
      app: { name: 'Editor', appUrl: 'https://app.example/editor' },
      origin: 'https://app.example'
    })
    const editorDid = (editor.credential.credentialSubject as { id: string }).id
    const ids: string[] = []
    for (let copy = 0; copy < 2; copy++) {
      const { id, envelope } = await ciphers.appKeys.encrypt({
        data: editor.credential as unknown as Json
      })
      seedResource({
        logicalKey: 'appKeys',
        resourceId: id,
        body: envelope
      })
      ids.push(id)
    }
    const [named, other] = ids
    const deleteSynced = remoteStore.deleteSyncedResource.bind(remoteStore)
    const deleted: string[] = []
    const spy = vi
      .spyOn(remoteStore, 'deleteSyncedResource')
      .mockImplementation(async options => {
        deleted.push(options.resourceId)
        if (options.resourceId === named) {
          throw new Error('connection dropped')
        }
        await deleteSynced(options)
      })

    await expect(
      storage.deleteAppKeyResource({ appKey: named, did: editorDid })
    ).rejects.toThrow('connection dropped')
    // The other copy went first; the named one is still there.
    expect(deleted).toEqual([other, named])

    spy.mockRestore()
    expect(
      await storage.deleteAppKeyResource({ appKey: named, did: editorDid })
    ).toBe('deleted')
    expect(
      await remoteStore.listSyncedDocuments({ logicalKey: 'appKeys' })
    ).toEqual([])
  })
})

describe('StorageManager.decryptCollectionResource (app collection)', () => {
  it('decrypts an app-collection envelope with the vault KAK', async () => {
    const owner = await generateVaultKeys()
    const app = await generateVaultKeys()
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
    const owner = await generateVaultKeys()
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
    const owner = await generateVaultKeys()
    const extra = await generateVaultKeys()
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
      revoke: [],
      resolveRecipientKey: vouchFor(owner)
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
      epoch,
      data: envelope
    })

    // listCredentials transparently refreshes the descriptor from the governing log,
    // rebuilds the cipher, and returns the credential.
    const listed = await storage.listCredentials()
    expect(listed).toEqual([{ cid, vc: credential }])
  })

  it('transient session: the refresh still runs, with zero localStorage residue', async () => {
    // Production reads the global at call time, so a cache write that leaked
    // past the in-memory strategy would land in this stub.
    const residue = stubLocalStorage()
    const owner = await generateVaultKeys()
    const extra = await generateVaultKeys()
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
      revoke: [],
      resolveRecipientKey: vouchFor(owner)
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
    // No localStorage key at all, the descriptor cache's included.
    expect(
      localStorage.getItem(
        `freewallet:collection-encryption:${remoteStore.spaceId}:private-credentials`
      )
    ).toBeNull()
    expect(residue.keys()).toEqual([])
  })

  it('remote-direct: refreshes the descriptor and returns a fresh-epoch credential', async () => {
    const owner = await generateVaultKeys()
    const extra = await generateVaultKeys()
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
      revoke: [],
      resolveRecipientKey: vouchFor(owner)
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
    // backend's cipher via setCiphers, and re-reads -- returning the fresh
    // credential.
    const listed = await storage.listCredentials()
    expect(listed).toEqual([{ cid, vc: credential }])
  })

  it('refetches the collection metadata, so later writes carry index entries', async () => {
    const owner = await generateVaultKeys()
    const extra = await generateVaultKeys()
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
      revoke: [],
      resolveRecipientKey: vouchFor(owner)
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

/**
 * A local-replica session holding one contact, with plain (not
 * self-refreshing) contacts ciphers built on a two-reader epoch, beside a
 * stand-in for another client that rotates the `contacts` epoch and whose
 * rewrite of the head lands in the local replica, as replication would land
 * it. The session's cipher stays on the stale descriptor, so the next point
 * read meets an unknown epoch.
 *
 * @returns {Promise<object>}
 */
async function localContactsRotation(): Promise<{
  storage: StorageManager
  localStore: BrowserStore
  stored: StoredContact
  rotateAndRewrite(contact: ContactData): Promise<string>
}> {
  const owner = await generateVaultKeys()
  const extra = await generateVaultKeys()
  const stores = memoryDescriptorStores()
  const { remoteStore } = makeFakeRemote({ stores })
  const contactsStore = stores.storeFor('contacts')
  const descriptor1 = await initRecipients({
    store: contactsStore,
    recipients: [
      ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
      ownerRecipient({ keyAgreementKey: extra.keyAgreementKey })
    ]
  })
  const { descriptor: historyDescriptor } = await ensureFirstEpoch({
    store: stores.storeFor('contacts-history'),
    recipients: [ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })]
  })
  const contactsCipher = (encryption: CollectionEncryption) =>
    createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'contacts',
      idDerivation: 'random',
      encryption
    })
  const ciphers = {
    ...(await buildCiphers(owner, {})),
    contacts: await contactsCipher(descriptor1),
    contactsHistory: await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'contacts-history',
      encryption: historyDescriptor
    })
  }
  const { localStore } = await initLocalStore(ciphers)
  const storage = new StorageManager({
    persistence: browserLocalSessionPersistence(),
    localStore,
    remoteStore,
    descriptorLogs: descriptorLogsFrom(stores),
    ciphers,
    vaultKeys: owner,
    descriptors: {
      contacts: descriptor1,
      'contacts-history': historyDescriptor
    }
  })
  const stored = await storage.addContact({
    contact: { displayName: 'Ada' } as ContactData
  })

  const rotateAndRewrite = async (contact: ContactData): Promise<string> => {
    const descriptor2 = await removeRecipient({
      store: contactsStore,
      space: remoteStore.spaceHandle(),
      recipientId: extra.keyAgreementKey.id!,
      revoke: [],
      resolveRecipientKey: vouchFor(owner)
    })
    const doc = await localStore
      .rxCollection('contacts')
      .findOne(stored.id)
      .exec()
    const head: ContactHeadPayload = {
      contactId: stored.contactId,
      updatedAt: new Date().toISOString(),
      writerId: 'other-client-writer',
      contact
    }
    const epoch2Cipher = await contactsCipher(descriptor2)
    const { envelope, epoch } = await epoch2Cipher.encryptUpdate!({
      id: stored.id,
      data: head as unknown as Json,
      current: doc!.toMutableJSON().data as Json
    })
    await doc!.incrementalPatch({
      updatedAt: new Date().toISOString(),
      epoch,
      data: envelope
    })
    return descriptor2.currentEpoch!
  }
  return { storage, localStore, stored, rotateAndRewrite }
}

describe('StorageManager unknown-epoch refresh (contacts point reads)', () => {
  it('re-runs an edit once under the fresh epoch when a rotation lands between the read and the edit', async () => {
    const { storage, localStore, stored, rotateAndRewrite } =
      await localContactsRotation()
    // The read the edit is built on.
    expect((await storage.loadContact({ id: stored.id }))?.contact).toEqual({
      displayName: 'Ada'
    })

    const freshEpoch = await rotateAndRewrite({
      displayName: 'Ada L.'
    } as ContactData)
    const updated = await storage.updateContact({
      id: stored.id,
      contact: { displayName: 'Ada Lovelace' } as ContactData
    })
    expect(updated.contactId).toBe(stored.contactId)

    // The edit landed under the fresh epoch, and recorded one revision.
    const doc = await localStore
      .rxCollection('contacts')
      .findOne(stored.id)
      .exec()
    expect(doc!.toMutableJSON().epoch).toBe(freshEpoch)
    expect((await storage.loadContact({ id: stored.id }))?.contact).toEqual({
      displayName: 'Ada Lovelace'
    })
    const revisions = await storage.listContactRevisions({
      contactId: stored.contactId
    })
    expect(revisions.map(({ action }) => action).sort()).toEqual([
      'create',
      'update'
    ])
  })

  it('loads a head sealed under a rotated epoch instead of resolving undefined', async () => {
    const { storage, stored, rotateAndRewrite } = await localContactsRotation()
    await rotateAndRewrite({ displayName: 'Ada L.' } as ContactData)
    expect(await storage.loadContact({ id: stored.id })).toEqual(
      expect.objectContaining({
        id: stored.id,
        contactId: stored.contactId,
        contact: { displayName: 'Ada L.' }
      })
    )
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
    const owner = await generateVaultKeys()
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
    const owner = await generateVaultKeys()
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

    const { entries: history } = await storage.listHistoryItems()
    const loginEntry = history.find(({ doc }) => doc.type?.includes('Login'))
    expect(loginEntry).toBeDefined()
    expect(loginEntry!.doc.summary).toBe('Logged in to wallet.')
    expect(loginEntry!.doc.actor).toEqual({ email: user.email })
    expect(loginEntry!.doc.object).toBeUndefined()
  })
})
