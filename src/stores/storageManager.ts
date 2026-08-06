/**
 * Storage layer for the wallet. StorageManager is the single facade used by
 * all pages. The local BrowserStore (RxDB/IndexedDB) is always the ACTIVE
 * replica: every credential, public-link, and history read/write targets it
 * unconditionally, online or offline, guest or not. When VITE_WAS_SERVER_URL
 * is set (and the session is not a guest), a WASRemoteStore is also attached --
 * not as a primary store, but as a remote replica: the sync controller
 * replicates the local collections to it in the background, and the storage
 * browser / export / import / quota pages read through it directly.
 *
 * Every synced-collection read/write goes through one `SyncedCollectionStore`
 * backend chosen ONCE at construction (`src/stores/remoteDirectStore.ts`): the
 * local `BrowserStore` in the normal case, or a `RemoteDirectStore` for the
 * CHAPI popup. A popup runs in a third-party partitioned iframe: its local
 * BrowserStore binds a partitioned IndexedDB no sync controller drives, so a
 * credential stored there would be stranded and a credential list would always
 * come back empty. The remote-direct backend therefore reads and writes the
 * standard synced collections straight over the remote WAS collections,
 * reproducing verbatim what background replication would have pushed (the raw
 * EDV envelope under its content-derived id, `Key-Epoch` stamped) so the
 * main app pulls popup writes cleanly. Both backends share the session's
 * per-collection ciphers, so the envelope/id/epoch logic lives once. The
 * remote-direct backend is selected only when a remote store is configured; a
 * guest / no-WAS session always uses the local BrowserStore.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver,
  IVerifiableCredential,
  IZcap
} from '@interop/data-integrity-core'
import { generateZcapUri } from '@interop/ezcap'
import type { ContactData, ContactRevisionPayload } from '@interop/social-core'
import type { RxCollection } from 'rxdb/plugins/core'
import {
  ValidationError,
  type CollectionEncryption,
  type IDelegatedZcap
} from '@interop/was-client'
import {
  addRecipient,
  ensureFirstEpoch,
  removeRecipient,
  type RecipientPublicKey
} from '@interop/was-client/edv'
import type { ControllerProfile, User } from '@/types/auth'
import { cidFrom } from '@interop/was-client/sync'
import {
  ENABLE_DID_WEBVH,
  RP_ZCAP_TTL_MS,
  SYSTEM_COLLECTIONS,
  WALLET_STANDARD_COLLECTIONS,
  WAS_SERVER_URL
} from '@/app.config'
import {
  assertMintedAppKey,
  assertStorableAppKey
} from '@interop/wallet-core/request'
import { getOrCreateWriterId } from '@/lib/writerId'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { didWebFromSpace, ensureDidWeb } from '@/lib/didWeb'
import {
  clientSigningKeyMultibase,
  didKeyZcapClient,
  ensureDidWebvh,
  isWebvhDid,
  webvhCapabilityAgent,
  webvhZcapClient,
  type DidWebKeyMapV2
} from '@interop/wallet-core/webvh'
import { promoteKeystoreController, rebindKeystoreAgent } from '@/lib/kms'
import { ensureUserKeyRoster } from '@interop/wallet-core/keys'
import { accountRosterStore } from '@/session/rosterStore'
import { mintRecordEncryption } from '@interop/wallet-core/keyring'
import {
  acquireDescriptor,
  acquireDescriptors,
  DescriptorRefreshPolicy,
  type EncryptionDescriptorCache
} from '@interop/wallet-core/descriptors'
import { savePinFromDescriptor } from '@/lib/sessionKey'
import { invalidateVerifiedLog } from '@/session/verifiedLog'
import { SHAREABLE_COLLECTIONS as ENCRYPTED_STANDARD_COLLECTIONS } from '@/session/shares'
import {
  createEdvDocCipher,
  isEncryptedEnvelope,
  ownerRecipient,
  type DocCipher
} from '@interop/was-client/edv'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import type { Json, SyncedDoc } from '@/lib/sync'
import type { SpaceQuotaReport } from '@/types/storageQuota'
import type { FetchedCollectionResource } from '@/lib/storageResource'
import type { StoredCredential } from '@/types/credential'
import type { StoredContact } from '@/types/contact'
import { BrowserStore } from '@/stores/browserStore'
import { WASRemoteStore } from '@/stores/wasRemoteStore'
import {
  RemoteDirectStore,
  type SyncedCollectionStore
} from '@/stores/remoteDirectStore'
import { UnknownEpochError } from '@interop/was-client/edv'
import { uuidv7 } from 'uuidv7'
import {
  ACTIVITY_TYPE,
  addHistoryNewAccount as buildHistoryNewAccount,
  addHistorySpaceCreated as buildHistorySpaceCreated,
  addHistoryCredentialCreated as buildHistoryCredentialCreated,
  addHistoryCredentialDeleted as buildHistoryCredentialDeleted,
  addHistoryCredentialShared as buildHistoryCredentialShared,
  addHistoryCredentialUnshared as buildHistoryCredentialUnshared,
  addHistoryLogin as buildHistoryLogin,
  addHistoryAppRevoke as buildHistoryAppRevoke,
  addHistoryClientRevoked as buildHistoryClientRevoked,
  type WalletActivity
} from '@interop/wallet-core/space'

// The `wallet-activity` wire shape now lives in `@interop/wallet-core/space`
// (shared with Freewallet mobile). Re-exported here so existing importers keep
// resolving it from `@/stores/storageManager`.
export type { WalletActivity }

export type ImportSpaceSummary = {
  collectionsCreated: number
  collectionsSkipped: number
  resourcesCreated: number
  resourcesSkipped: number
}

/**
 * The recipient kids of a descriptor's CURRENT key epoch, minus the owner's
 * own key-agreement key when one is given (the owner is recipient zero of
 * every epoch, so dropping it leaves exactly the other readers). Empty when the
 * descriptor carries no epochs, or none matching `currentEpoch`.
 *
 * @param options {object}
 * @param [options.descriptor] {CollectionEncryption | null}
 * @param [options.ownerKid] {string}   the owner's key-agreement key id
 * @returns {string[]}
 */
function currentEpochRecipientKids({
  descriptor,
  ownerKid
}: {
  descriptor?: CollectionEncryption | null
  ownerKid?: string
}): string[] {
  const epoch = descriptor?.epochs?.find(
    entry => entry.id === descriptor.currentEpoch
  )
  return (epoch?.recipients ?? [])
    .map(entry => entry.header.kid)
    .filter(kid => kid !== ownerKid)
}

/**
 * Decrypts one EDV envelope into the `{ value, unknownEpoch }` shape the
 * epoch-refresh readers bucket on: an `UnknownEpochError` (a rekey the cached
 * descriptor has not caught up to) becomes the refresh signal, and any other
 * failure is logged and degrades to `undefined`, so the caller can fall back
 * to the raw envelope.
 *
 * @param options {object}
 * @param options.cipher {DocCipher}
 * @param options.envelope {Json}
 * @param options.source {string}   how the failure names the collection, e.g.
 *   `collection "private-credentials"`
 * @returns {Promise<{ value: Json | undefined, unknownEpoch: boolean }>}
 */
async function decryptEnvelope({
  cipher,
  envelope,
  source
}: {
  cipher: DocCipher
  envelope: Json
  source: string
}): Promise<{ value: Json | undefined; unknownEpoch: boolean }> {
  try {
    return { value: await cipher.decrypt({ envelope }), unknownEpoch: false }
  } catch (err) {
    if (err instanceof UnknownEpochError) {
      return { value: undefined, unknownEpoch: true }
    }
    console.warn(`Could not decrypt resource envelope from ${source}:`, err)
    return { value: undefined, unknownEpoch: false }
  }
}

// The WAS collection ids of the encrypted standard collections -- the set
// whose descriptors are acquired at session start and refreshed on an
// unknown-epoch read.
const ENCRYPTED_COLLECTION_IDS = ENCRYPTED_STANDARD_COLLECTIONS.map(
  ({ id }) => id
)

/**
 * The localStorage-backed `EncryptionDescriptorCache` for one account's Space: a collection's
 * last-seen encryption descriptor under
 * `freewallet:collection-encryption:<spaceId>:<collectionId>`, scoped by Space
 * so two accounts on one browser never collide. The cache is the offline
 * fallback: when a descriptor fetch fails, a previously-shared collection must
 * keep encrypting under its current epoch. Reads treat a corrupt entry (or a
 * non-browser environment) as absent; writes no-op without localStorage.
 *
 * @param options {object}
 * @param options.spaceId {string}
 * @returns {EncryptionDescriptorCache}
 */
function localStorageDescriptorCache({
  spaceId
}: {
  spaceId: string
}): EncryptionDescriptorCache {
  const cacheKey = (collectionId: string): string =>
    `freewallet:collection-encryption:${spaceId}:${collectionId}`
  return {
    async readDescriptor({ collectionId }) {
      if (typeof localStorage === 'undefined') {
        return undefined
      }
      const raw = localStorage.getItem(cacheKey(collectionId))
      if (!raw) {
        return undefined
      }
      try {
        return JSON.parse(raw) as CollectionEncryption
      } catch {
        return undefined
      }
    },
    async writeDescriptor({ collectionId, descriptor }) {
      if (typeof localStorage === 'undefined') {
        return
      }
      localStorage.setItem(cacheKey(collectionId), JSON.stringify(descriptor))
    }
  }
}

/**
 * Descriptors for a session with no remote store (a guest, or no WAS server
 * configured). Every encrypted collection still carries a key-epoch roster
 * from birth, so each collection gets a local one-epoch descriptor wrapped to
 * the session's vault KAK alone -- minted on first use and persisted in the
 * same localStorage cache a remote Space's descriptors use, scoped by the
 * user's DID in place of a Space id, so a returning local login rebuilds the
 * same epoch and keeps decrypting its own rows. A guest's identity is random
 * per session and its data dies with it, so a guest's descriptors are minted
 * fresh and never persisted.
 *
 * @param options {object}
 * @param options.userId {string}   the session user's DID (the cache scope)
 * @param options.keyAgreementKey {IKeyAgreementKey}   the vault KAK epoch[0]
 *   wraps to
 * @param options.persist {boolean}   false for a guest (mint-only)
 * @returns {Promise<Record<string, CollectionEncryption>>}   keyed by
 *   collection id
 */
async function localOnlyDescriptors({
  userId,
  keyAgreementKey,
  persist
}: {
  userId: string
  keyAgreementKey: IKeyAgreementKey
  persist: boolean
}): Promise<Record<string, CollectionEncryption>> {
  const cache = persist
    ? localStorageDescriptorCache({ spaceId: `local:${userId}` })
    : undefined
  const entries = await Promise.all(
    ENCRYPTED_COLLECTION_IDS.map(async collectionId => {
      const cached = await cache?.readDescriptor({ collectionId })
      if (cached?.epochs?.length) {
        return [collectionId, cached] as const
      }
      const minted = await mintRecordEncryption({ keyAgreementKey })
      await cache?.writeDescriptor({ collectionId, descriptor: minted })
      return [collectionId, minted] as const
    })
  )
  return Object.fromEntries(entries)
}

/**
 * Logs a swallowed descriptor-fetch failure (the cached-fallback branch of
 * `acquireDescriptors`).
 *
 * @param err {unknown}
 * @param info {object}
 * @param info.collectionId {string}
 */
function warnDescriptorFetchError(
  err: unknown,
  { collectionId }: { collectionId: string }
): void {
  console.warn(
    `Could not fetch the encryption descriptor for collection "${collectionId}"; ` +
      'falling back to the cached copy.',
    err
  )
}

/**
 * Thrown when a credential's live public copy could not be retracted, so the
 * delete of the private credential was refused rather than left to strand a
 * world-readable orphan. See {@link StorageManager.deleteCredential}.
 */
export class PublicCopyRetractionError extends Error {
  cid: string

  constructor({ cid, cause }: { cid: string; cause?: unknown }) {
    super(
      `Could not retract the public copy of credential "${cid}"; ` +
        'the credential was not deleted.',
      { cause }
    )
    this.name = 'PublicCopyRetractionError'
    this.cid = cid
  }
}

/**
 * Manages storage operations for the wallet and a logged-in user profile:
 * routes all wallet reads/writes to the local active replica and exposes the
 * optional remote WAS backend for replication and remote-only features.
 */
export class StorageManager {
  #localStore: BrowserStore
  #remoteStore?: WASRemoteStore // Only set if VITE_WAS_SERVER_URL env var is present
  // The backend every synced-collection read/write routes through, chosen once
  // at construction: the local active replica, or the remote-direct popup
  // backend. Never re-forked per operation.
  #store: SyncedCollectionStore
  // Whether the remote-direct backend is the one selected (drives the read
  // readiness contract: its reads need no local provisioning).
  #remoteDirect: boolean
  // The per-collection document ciphers, kept here for the storage browser's own
  // decrypt at the WAS seam (`decryptCollectionResource`) and rebuilt on a
  // descriptor refresh.
  #ciphers?: Record<string, DocCipher>
  // The provisioning promise from `ensureUserCollections` (fired at session
  // creation), awaited by the read-readiness contract in non-remote-direct mode.
  #provisioning?: Promise<void>
  // The vault key material, kept so ciphers can be rebuilt after a descriptor
  // refresh (an unknown-epoch read) without re-plumbing the profile.
  #vaultKeys?: {
    keyAgreementKey: IKeyAgreementKey
    keyResolver: IKeyResolver
  }
  // The last-known per-collection encryption descriptors, keyed by WAS collection
  // id, that the current ciphers were built from.
  #descriptors: Record<string, CollectionEncryption>
  // The durable (localStorage) descriptor cache for this account's Space -- the
  // offline fallback descriptor acquisition falls back to. Only set with a remote
  // store (a guest / no-WAS session has no descriptors to cache).
  #descriptorCache?: EncryptionDescriptorCache
  // The once-per-collection-per-session unknown-epoch refresh guard, shared by
  // the standard and the app-provisioned encrypted collections, so a genuinely
  // foreign envelope cannot drive a refresh loop. Its `reset` re-arms a
  // collection whenever a share / unshare / recipient rotation installs a
  // fresh descriptor.
  #refreshPolicy = new DescriptorRefreshPolicy({
    refresh: async ({ collectionId }) => {
      if (ENCRYPTED_COLLECTION_IDS.includes(collectionId)) {
        await this.#refreshDescriptors()
      } else {
        // An app-provisioned collection: drop the cached descriptor and cipher so
        // the re-read rebuilds them from a fresh Description fetch.
        delete this.#appDescriptors[collectionId]
        delete this.#appCiphers[collectionId]
      }
    }
  })
  // Lazily-built per-collection ciphers for App Connect app-provisioned
  // (non-standard) encrypted collections, keyed by WAS collection id. The
  // wallet decrypts these as an ordinary recipient with its vault KAK (recipient
  // zero), driven by the collection's fetched descriptor; built on first
  // decrypt-read from the storage browser, invalidated when a rekey lands.
  #appCiphers: Record<string, DocCipher> = {}
  // The descriptors the `#appCiphers` entries were built from, keyed by WAS
  // collection id -- the offline/lazy source for an app collection's cipher.
  #appDescriptors: Record<string, CollectionEncryption> = {}

  constructor({
    localStore,
    remoteStore,
    ciphers,
    remoteDirect = false,
    vaultKeys,
    descriptors
  }: {
    localStore: BrowserStore
    remoteStore?: WASRemoteStore
    ciphers?: Record<string, DocCipher>
    remoteDirect?: boolean
    vaultKeys?: {
      keyAgreementKey: IKeyAgreementKey
      keyResolver: IKeyResolver
    }
    descriptors?: Record<string, CollectionEncryption>
  }) {
    this.#localStore = localStore
    this.#remoteStore = remoteStore
    this.#ciphers = ciphers
    this.#vaultKeys = vaultKeys
    this.#descriptors = descriptors ?? {}
    this.#descriptorCache = remoteStore
      ? localStorageDescriptorCache({ spaceId: remoteStore.spaceId })
      : undefined
    // Remote-direct routing is only meaningful when a remote store is configured
    // (a guest / no-WAS session always uses the local BrowserStore).
    this.#remoteDirect = remoteDirect && !!remoteStore
    this.#store = this.#remoteDirect
      ? new RemoteDirectStore({
          remoteStore: remoteStore!,
          ciphers: ciphers ?? {}
        })
      : localStore
  }

  /**
   * Resolves when the active storage backend can serve reads: the local active
   * replica's collections being open (part of the provisioning `storageReady`
   * runs), or nothing at all in the popup's remote-direct mode (reads hit the
   * remote collections directly and need no local provisioning). Full
   * provisioning -- the remote Space and did:web -- runs in the background as
   * `session.storageReady`; a caller awaits that separately where a grant needs
   * the Space to exist.
   *
   * @returns {Promise<void>}
   */
  async ready(): Promise<void> {
    if (this.#remoteDirect) {
      return
    }
    await this.#provisioning
  }

  /**
   * The remote backend, or a throw naming what needed it. The one place a
   * remote-only operation states its precondition; the operations that
   * degrade to an empty result without a remote keep their own `if` instead.
   *
   * @param action {string}   what the caller was doing, as the message opens
   *   ("Sharing a collection requires remote storage.")
   * @returns {WASRemoteStore}
   */
  #requireRemote(action: string): WASRemoteStore {
    if (!this.#remoteStore) {
      throw new Error(`${action} requires remote storage.`)
    }
    return this.#remoteStore
  }

  /**
   * Whether a remote WAS backend is configured for this session. Pages use this
   * instead of reaching into the backend directly.
   */
  get hasRemoteStorage(): boolean {
    return !!this.#remoteStore
  }

  /**
   * The remote Space id, or undefined when there is no remote backend.
   */
  get spaceId(): string | undefined {
    return this.#remoteStore?.spaceId
  }

  /**
   * The remote WAS client, or undefined when there is no remote backend. Used by
   * the sync controller to drive background replication against remote Collection
   * replicas (it signs with the same session key).
   */
  get wasClient(): WASRemoteStore['was'] | undefined {
    return this.#remoteStore?.was
  }

  /**
   * The remote Space URL, or undefined when there is no remote backend.
   */
  get spaceUrl(): string | undefined {
    return this.#remoteStore?.spaceUrl
  }

  /**
   * The world-readable URL the user's published did:web document resolves to,
   * or undefined when there is no remote backend. (Whether a document has
   * actually been published is a separate `profile.didWeb` check.)
   */
  get publishedDidUrl(): string | undefined {
    return this.#remoteStore?.didDocumentUrl()
  }

  /**
   * The remote WAS store, or undefined when there is no remote backend. Exposed
   * for the did:webvh rotation ceremony (`rotateWebvhUpdateKey`), which reads
   * and rewrites the `id` collection's `did.jsonl` / `did.json` and the
   * `key-map` collection's `keys.json` directly through it.
   */
  get remoteStore(): WASRemoteStore | undefined {
    return this.#remoteStore
  }

  /**
   * The live local RxDB collection backing one of the wallet's standard
   * logical collections. The sync controller uses this as the local end of
   * replication.
   *
   * @param logicalKey {string} e.g. 'publicCredentials'.
   * @returns {RxCollection<SyncedDoc>}
   */
  localCollection(logicalKey: string): RxCollection<SyncedDoc> {
    return this.#localStore.rxCollection(logicalKey)
  }

  /**
   * Builds the per-collection document ciphers for the encrypted standard
   * collections from a session's key material (the vault KAK and its resolver).
   * When a collection has a multi-recipient encryption descriptor (its `descriptors`
   * entry, keyed by WAS collection id), the cipher is built epoch-aware from
   * it; without one it is the single-key path, unchanged.
   *
   * @param options {object}
   * @param options.keyAgreementKey {IKeyAgreementKey}
   * @param options.keyResolver {IKeyResolver}
   * @param [options.descriptors] {Record<string, CollectionEncryption>}   per-
   *   collection encryption descriptors, keyed by WAS collection id
   * @returns {Promise<Record<string, DocCipher>>}
   */
  static async #buildCiphers({
    keyAgreementKey,
    keyResolver,
    descriptors
  }: {
    keyAgreementKey: IKeyAgreementKey
    keyResolver: IKeyResolver
    descriptors?: Record<string, CollectionEncryption>
  }) {
    const cipherEntries = await Promise.all(
      ENCRYPTED_STANDARD_COLLECTIONS.map(async ({ key, id, idDerivation }) => {
        const encryption = descriptors?.[id]
        // Every encrypted collection carries its key epochs from
        // provisioning, so a missing (or epoch-less) descriptor -- an
        // unprovisioned or torn collection, or an offline session with
        // nothing cached -- gets a fail-closed cipher rather than none: an
        // absent cipher would fall through to the store's cipher-less
        // plaintext path, silently storing (and pushing) plaintext into an
        // encrypted collection, and an epoch-less descriptor would make the
        // whole rebuild throw, taking the healthy collections down with it.
        const cipher = encryption?.epochs?.length
          ? await createEdvDocCipher({
              keyAgreementKey,
              keyResolver,
              collectionId: id,
              // The collection spec's id mint ('random' for the mutable
              // contacts head, 'content' for the content-addressed
              // collections), so a minted id follows the spec and can key
              // the row.
              idDerivation,
              encryption
            })
          : StorageManager.#refusingCipher({ collectionId: id })
        return [key, cipher]
      })
    )
    return Object.fromEntries(cipherEntries)
  }

  /**
   * A {@link DocCipher} that refuses every operation: the stand-in for an
   * encrypted collection whose descriptor could not be acquired. The refusal
   * clears when a descriptor refresh rebuilds the ciphers.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @returns {DocCipher}
   */
  static #refusingCipher({
    collectionId
  }: {
    collectionId: string
  }): DocCipher {
    const refuse = (): never => {
      throw new Error(
        `Collection "${collectionId}" has no encryption descriptor available ` +
          '(fetched or cached). Every encrypted collection carries its key ' +
          'epochs from provisioning; refusing to read or write without them.'
      )
    }
    return {
      encrypt: async () => refuse(),
      encryptUpdate: async () => refuse(),
      decrypt: async () => refuse()
    }
  }

  /**
   * Rebuilds the per-collection ciphers from the current descriptors and the held
   * vault keys, then swaps them into the local store (and this facade). No-op
   * without vault keys.
   *
   * @returns {Promise<void>}
   */
  async #rebuildCiphers(): Promise<void> {
    if (!this.#vaultKeys) {
      return
    }
    const ciphers = await StorageManager.#buildCiphers({
      keyAgreementKey: this.#vaultKeys.keyAgreementKey,
      keyResolver: this.#vaultKeys.keyResolver,
      descriptors: this.#descriptors
    })
    this.#ciphers = ciphers
    // Swap into the active backend (the local store in the normal case, the
    // remote-direct backend in the popup); both honor `setCiphers` for the
    // descriptor-refresh path.
    this.#store.setCiphers(ciphers)
  }

  /**
   * Refreshes every encrypted collection's descriptor from the remote store, caches
   * them, and rebuilds + swaps the ciphers. Called when a local read reports
   * unknown-epoch rows -- a rekey emits no change-feed entry, so the local
   * cipher may be built from a stale descriptor. No-op without a remote store or
   * vault keys.
   *
   * @returns {Promise<void>}
   */
  async #refreshDescriptors(): Promise<void> {
    if (!this.#remoteStore || !this.#vaultKeys || !this.#descriptorCache) {
      return
    }
    this.#descriptors = await acquireDescriptors({
      source: this.#remoteStore,
      cache: this.#descriptorCache,
      collectionIds: ENCRYPTED_COLLECTION_IDS,
      onFetchError: warnDescriptorFetchError
    })
    await this.#rebuildCiphers()
  }

  /**
   * Adopts a rotated user key's vault keys into the live session's storage -- the
   * tail of the revocation cascade: once the roster and the collections have
   * moved to a fresh user key, the session that drove the rotation (it minted the
   * key, so it holds it) swaps its vault key material, refetches the rotated
   * descriptors, and rebuilds the ciphers, so it keeps reading and writing
   * without a re-login. The app-collection cipher caches are dropped too (they
   * were built from the old vault KAK) and rebuild lazily on next decrypt.
   *
   * @param options {object}
   * @param options.keyAgreementKey {IKeyAgreementKey}   the fresh user key's KAK
   * @param options.keyResolver {IKeyResolver}
   * @returns {Promise<void>}
   */
  async adoptRotatedVaultKeys({
    keyAgreementKey,
    keyResolver
  }: {
    keyAgreementKey: IKeyAgreementKey
    keyResolver: IKeyResolver
  }): Promise<void> {
    this.#vaultKeys = { keyAgreementKey, keyResolver }
    await this.refreshEncryptedDescriptors()
  }

  /**
   * Refetches every encrypted collection's descriptor and rebuilds + swaps
   * the ciphers under the vault keys already held -- the tail of the
   * cascade-completion sweep, which can move a collection's current epoch
   * (completing a cascade another client crashed partway through) AFTER this
   * session's ciphers were built at login: without the refresh, every later
   * write would stay sealed under the retired epoch the revoked party can
   * still decrypt. The app-collection cipher caches are dropped too and
   * rebuild lazily on next decrypt.
   *
   * @returns {Promise<void>}
   */
  async refreshEncryptedDescriptors(): Promise<void> {
    this.#appCiphers = {}
    this.#appDescriptors = {}
    if (this.#remoteStore && this.#descriptorCache) {
      await this.#refreshDescriptors()
    } else {
      await this.#rebuildCiphers()
    }
    this.#refreshPolicy.reset()
  }

  /**
   * Runs a read that reports whether it skipped unknown-epoch rows; on the first
   * such report for a collection this session, refreshes the descriptor (rebuilding
   * + swapping the ciphers) and re-reads once, via the shared
   * `DescriptorRefreshPolicy`. The single seam behind `listCredentials`,
   * `listHistoryItems`, and `decryptCollectionResource`, so a fresh-epoch
   * resource is never silently dropped after a rekey by another client -- for
   * either backend, since the remote-direct backend surfaces the same counts.
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id
   * @param options.read {() => Promise<{ value: T; unknownEpoch: boolean }>}
   * @returns {Promise<T>}
   */
  async #readWithEpochRefresh<T>({
    collectionId,
    read
  }: {
    collectionId: string
    read: () => Promise<{ value: T; unknownEpoch: boolean }>
  }): Promise<T> {
    // A refresh needs a remote store and the vault keys; without them, serve
    // the single read as-is (and leave the policy's guard unspent).
    if (!this.#remoteStore || !this.#vaultKeys) {
      return (await read()).value
    }
    return this.#refreshPolicy.readWithRefresh({ collectionId, read })
  }

  static async initStorageClients({
    user,
    profile,
    isGuest = false,
    remoteDirect = false
  }: {
    user: User
    profile: ControllerProfile
    isGuest?: boolean
    // Route credential + history operations straight to the remote WAS
    // collections (the CHAPI popup path, whose local IndexedDB is partitioned).
    remoteDirect?: boolean
  }) {
    // Guest sessions never touch the remote WAS server -- they get no remote
    // replica. This keeps guest mode usable as a fallback even when the
    // configured WAS server is unreachable.
    const storageServerUrl = isGuest ? undefined : WAS_SERVER_URL
    console.log('Initializing storage clients:', { storageServerUrl })

    const { keyAgreementKey, keyResolver } = profile
    if (!keyAgreementKey || !keyResolver) {
      throw new Error('A full session profile requires the key material.')
    }

    // Build the remote store first (when configured), so its encryption descriptors
    // can be fetched before the ciphers are built: a shared collection encrypts
    // under its current key epoch, discovered from the Collection Description.
    let remoteStore
    if (storageServerUrl) {
      ;({ remoteStore } = await WASRemoteStore.initClient({
        storageServerUrl,
        user,
        profile
      }))
    }
    // Fetch the current encryption descriptor for each encrypted standard
    // collection best-effort (concurrently -- login is not gated on a serial
    // chain of describes), caching each success and falling back to the cached
    // copy on a fetch failure. A collection whose descriptor cannot be
    // acquired gets a fail-closed refusing cipher below. With no remote store
    // (guest / no-WAS) the descriptors are minted locally instead -- every
    // encrypted collection carries its key epochs from birth, server or not.
    const descriptors = remoteStore
      ? await acquireDescriptors({
          source: remoteStore,
          cache: localStorageDescriptorCache({ spaceId: remoteStore.spaceId }),
          collectionIds: ENCRYPTED_COLLECTION_IDS,
          onFetchError: warnDescriptorFetchError
        })
      : await localOnlyDescriptors({
          userId: user.id,
          keyAgreementKey,
          persist: !isGuest
        })

    // One document cipher per encrypted collection, built from the session's
    // passphrase-derived key material (guests included -- their random secret
    // encrypts just as well; it is merely unrecoverable after logout, like the
    // rest of a guest session) plus any multi-recipient descriptor. The local store
    // holds EDV envelopes for these collections and replication ships them
    // verbatim.
    const ciphers = await StorageManager.#buildCiphers({
      keyAgreementKey,
      keyResolver,
      descriptors
    })

    // The local store is always the active replica.
    const { localStore } = await BrowserStore.initClient({ user, ciphers })
    let userExists = await localStore.userExists()
    if (remoteStore) {
      // A returning user may be on a fresh browser (no local db yet) but have
      // an existing remote Space.
      userExists = userExists || (await remoteStore.userExists())
    }
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      remoteDirect,
      vaultKeys: { keyAgreementKey, keyResolver },
      descriptors
    })
    return { storage, userExists }
  }

  /**
   * Stores a credential and, when a row was actually inserted (a re-add of a
   * stored credential is a no-op), records its Create history entry. Routes to
   * the active backend (the local active replica, or the remote-direct popup
   * backend).
   *
   * This is the single door every credential coming from outside the wallet
   * goes through (the CHAPI store popup, the URL / QR / manual-paste import,
   * and the credentials half of a space import), so it is where a credential
   * presenting as an app key is refused outright, whether or not it binds to
   * its own seed: app keys are wallet-minted, never imported, and the mint
   * path has its own door ({@link addMintedAppKey}). The background sync pull
   * (`src/lib/sync/`) writes pulled rows into the local replica without
   * passing through here, deliberately: it replicates the account's own
   * remote collections, which only the account's enrolled wallet clients can
   * write (`private-credentials` is a protected collection -- RP and share
   * grants on it are read-only), and each of those clients enforces this same
   * refusal at its own door; the pulled bodies are also EDV envelopes the
   * sync layer could not inspect. The match-time seed binding in
   * `@interop/wallet-core/request` remains the backstop for anything that
   * slips past.
   *
   * @param options {object}
   * @param options.credential {IVerifiableCredential}
   * @param options.user {User}   recorded as the history entry's actor
   * @returns {Promise<void>}
   */
  async addCredential({
    credential,
    user
  }: {
    credential: IVerifiableCredential
    user: User
  }) {
    assertStorableAppKey(credential)
    await this.#putCredential({ credential, user })
  }

  /**
   * The mint path's own store door: saves an app-key credential the wallet
   * itself just minted (`processAppConnect`), which {@link addCredential}
   * would refuse -- external ingest never stores a marker credential, so the
   * one legitimate producer gets its own entry point instead of a bypass flag
   * on the shared one. Still asserts the mint invariants (`assertMintedAppKey`
   * in `@interop/wallet-core/request`: marker present, subject DID derived
   * from the carried seed) so this door cannot be misused to store a foreign
   * app key either.
   *
   * @param options {object}
   * @param options.credential {IVerifiableCredential}
   * @param options.user {User}   recorded as the history entry's actor
   * @returns {Promise<void>}
   */
  async addMintedAppKey({
    credential,
    user
  }: {
    credential: IVerifiableCredential
    user: User
  }) {
    await assertMintedAppKey(credential)
    await this.#putCredential({ credential, user })
  }

  /**
   * The shared store step behind {@link addCredential} and
   * {@link addMintedAppKey}: content-cid derivation, the idempotent insert,
   * and the best-effort Create history entry.
   *
   * @param options {object}
   * @param options.credential {IVerifiableCredential}
   * @param options.user {User}
   * @returns {Promise<void>}
   */
  async #putCredential({
    credential,
    user
  }: {
    credential: IVerifiableCredential
    user: User
  }) {
    // The credential's content cid is its page-facing identity (idempotence,
    // routes, history); the backend encrypts the VC into an EDV envelope keyed
    // by a content-derived envelope-hash id.
    const cid = await cidFrom({ doc: credential })
    const inserted = await this.#store.addCredential({ cid, credential })
    if (inserted) {
      // Best-effort: the credential is already durably stored, and losing a
      // log line beats reporting the whole store as failed (in remote-direct
      // mode the history entry is its own remote write and can fail alone).
      try {
        await this.addHistoryCredentialCreated({
          cid,
          title: credentialTitle(credential),
          user
        })
      } catch (err) {
        console.warn('Could not record the credential-created activity:', err)
      }
    }
  }

  async listCredentials(): Promise<Array<StoredCredential>> {
    // Unknown-epoch rows mean the cipher may be built from a stale descriptor (a
    // rekey emits no change-feed entry); the shared helper refreshes the descriptor
    // once and re-reads, uniformly for both backends.
    return this.#readWithEpochRefresh({
      collectionId: 'private-credentials',
      read: async () => ({
        value: await this.#store.listCredentials(),
        unknownEpoch: this.#store.unknownEpochCredentials > 0
      })
    })
  }

  async loadCredential({
    cid
  }: {
    cid: string
  }): Promise<IVerifiableCredential | undefined> {
    return await this.#store.loadCredential({ cid })
  }

  /**
   * Deletes a credential, retracting its world-readable public copy FIRST when
   * it has one. The order is load-bearing: once the private credential is gone
   * there is no wallet-side handle left to retract the public copy with, so
   * deleting it first can strand a world-readable orphan of a credential the
   * user believes is deleted.
   *
   * Retraction of a live public copy is therefore BLOCKING, not best-effort:
   * if the credential has a public copy that cannot be retracted (offline
   * while a remote store is configured, say), the delete is refused with a
   * {@link PublicCopyRetractionError} and the private credential is left in
   * place, so the user can retry once the retraction can land. A credential
   * with no public copy deletes normally, offline included.
   *
   * `keepPublicCopy` is the user's deliberate "keep the public link" choice
   * from the delete dialog: a retention the user was asked about and chose, as
   * distinct from the accidental orphan above. It skips the retraction (and
   * therefore the refusal) entirely.
   *
   * @param options {object}
   * @param options.cid {string}
   * @param [options.keepPublicCopy] {boolean}
   * @returns {Promise<void>}
   */
  async deleteCredential({
    cid,
    keepPublicCopy = false
  }: {
    cid: string
    keepPublicCopy?: boolean
  }): Promise<void> {
    if (!keepPublicCopy) {
      await this.#retractPublicCopy({ cid })
    }
    await this.#store.deleteCredential({ cid })
  }

  /**
   * Removes a credential's public copy, if it has one, ahead of deleting the
   * credential itself. A failure to determine whether a public copy exists is
   * treated exactly like a failed retraction -- an unknown public copy is
   * indistinguishable from an unretracted one -- so both refuse the delete.
   *
   * @param options {object}
   * @param options.cid {string}
   * @returns {Promise<void>}
   */
  async #retractPublicCopy({ cid }: { cid: string }): Promise<void> {
    try {
      if (!(await this.#store.hasPublicCredential({ cid }))) {
        return
      }
      await this.#store.removePublicCredential({ cid })
    } catch (err) {
      throw new PublicCopyRetractionError({ cid, cause: err })
    }
  }

  /**
   * The count of local `private-credentials` rows the most recent
   * {@link listCredentials} read had to skip because their envelope would not
   * decrypt under the current vault KAK (corrupted, or written under a
   * mismatched KAK). Surfaced so the dashboard can warn the user without one
   * bad row bricking the list.
   *
   * @returns {number}
   */
  get undecryptableCredentials(): number {
    return this.#store.undecryptableCredentials
  }

  /**
   * Removes the local `private-credentials` rows that could not be decrypted,
   * so the user can clear rows that can never be shown. Returns the number of
   * rows removed.
   *
   * @returns {Promise<number>}
   */
  async purgeUndecryptableCredentials(): Promise<number> {
    return await this.#store.purgeUndecryptableCredentials()
  }

  async wipeStorage() {
    // Remote first: if the remote wipe fails, the error surfaces while the
    // local data (and session) are still intact.
    if (this.#remoteStore) {
      await this.#remoteStore.wipeStorage()
    }
    await this.#localStore.wipeStorage()
  }

  /**
   * Closes the local database without removing data. Called on logout.
   *
   * @returns {Promise<void>}
   */
  async close() {
    await this.#localStore.close()
  }

  async getSpaceQuotas(): Promise<SpaceQuotaReport | null> {
    if (!this.#remoteStore) {
      return null
    }
    return await this.#remoteStore.getSpaceQuotas()
  }

  async exportSpace(): Promise<ReadableStream<Uint8Array>> {
    return await this.#requireRemote('Exporting a Space').exportSpace()
  }

  async importSpace({
    tarFile
  }: {
    tarFile: File
  }): Promise<ImportSpaceSummary> {
    return await this.#requireRemote('Importing a Space').importSpace({
      tarFile
    })
  }

  async listCollections(): Promise<Array<StorageCollection>> {
    if (!this.#remoteStore) {
      return []
    }
    return await this.#remoteStore.listCollections()
  }

  /**
   * Lean collection listing for grant resolution (the ids and their public
   * state, no per-collection description reads). Empty without a remote
   * store, like {@link listCollections}.
   *
   * @returns {Promise<Array<{ id: string, isPublic: boolean }>>}
   */
  async listCollectionPublicStates(): Promise<
    Array<{ id: string; isPublic: boolean }>
  > {
    if (!this.#remoteStore) {
      return []
    }
    return await this.#remoteStore.listCollectionPublicStates()
  }

  async listCollectionResources({
    collectionUrl
  }: {
    collectionUrl: string
  }): Promise<Array<StorageResource>> {
    if (!this.#remoteStore) {
      return []
    }
    return await this.#remoteStore.listCollectionResources({ collectionUrl })
  }

  async fetchCollectionResource(
    resource: StorageResource
  ): Promise<FetchedCollectionResource> {
    return await this.#requireRemote(
      'Fetching a storage resource'
    ).fetchCollectionResource(resource)
  }

  /**
   * Best-effort decryption of a fetched storage-browser resource body: when
   * the body is an EDV envelope from one of the encrypted standard
   * collections and this session holds that collection's cipher (unlocked
   * vault), returns the decrypted document. Returns undefined otherwise --
   * plaintext bodies, non-standard collections, a locked vault, or an
   * envelope that fails to decrypt (logged, not thrown), letting callers fall
   * back to showing the raw envelope. An `UnknownEpochError` (a rekey on
   * another client the cached descriptor has not caught up to) drives the same
   * one-time descriptor refresh + retry `listCredentials` / `listHistoryItems` use,
   * so a freshly-rekeyed resource is not rendered as raw JWE until re-login.
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id (e.g.
   *   `private-credentials`)
   * @param options.data {Json}   the fetched JSON resource body
   * @returns {Promise<Json | undefined>}
   */
  async decryptCollectionResource({
    collectionId,
    data
  }: {
    collectionId: string
    data: Json
  }): Promise<Json | undefined> {
    if (!isEncryptedEnvelope(data)) {
      return undefined
    }
    const entry = WALLET_STANDARD_COLLECTIONS.find(
      collection => collection.id === collectionId && collection.encryption
    )
    if (!entry) {
      // A non-standard collection: an App Connect app-provisioned collection the
      // wallet decrypts as an ordinary recipient (vault KAK = recipient zero),
      // descriptor-driven from the fetched Collection Description.
      return this.#decryptAppCollectionResource({ collectionId, data })
    }
    return this.#readWithEpochRefresh({
      collectionId,
      read: async () => {
        // Re-fetch the cipher inside the read: a descriptor refresh rebuilds it.
        const cipher = this.#ciphers?.[entry.key]
        if (!cipher) {
          return { value: undefined, unknownEpoch: false }
        }
        return await decryptEnvelope({
          cipher,
          envelope: data,
          source: `collection "${collectionId}"`
        })
      }
    })
  }

  /**
   * Best-effort decrypt of an EDV envelope from a non-standard (App Connect
   * app-provisioned) encrypted collection, using the session's vault KAK as an
   * ordinary recipient (recipient zero). Lazily fetches the collection's
   * `encryption` descriptor, builds and caches a per-collection `DocCipher` from it
   * (only when the descriptor carries epochs -- a wallet with only its vault KAK can
   * decrypt an app collection only once it is provisioned multi-recipient with
   * the vault KAK as a recipient), and decrypts. On an `UnknownEpochError` (a
   * rekey the cached descriptor has not caught up to) it re-fetches the descriptor,
   * rebuilds the cipher, and retries once per session for that collection.
   * Returns undefined on any failure (no vault keys / no remote store / no epoch
   * descriptor / a decrypt error), letting the caller show the raw envelope.
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id
   * @param options.data {Json}   the fetched EDV envelope
   * @returns {Promise<Json | undefined>}
   */
  async #decryptAppCollectionResource({
    collectionId,
    data
  }: {
    collectionId: string
    data: Json
  }): Promise<Json | undefined> {
    const remote = this.#remoteStore
    if (!remote || !this.#vaultKeys) {
      return undefined
    }
    const { keyAgreementKey, keyResolver } = this.#vaultKeys

    // The shared refresh policy guards the retry to once per collection per
    // session; its refresh drops the cached app descriptor and cipher, so the
    // re-read below rebuilds them from a fresh Description fetch.
    return this.#refreshPolicy.readWithRefresh({
      collectionId,
      read: async (): Promise<{
        value: Json | undefined
        unknownEpoch: boolean
      }> => {
        let cipher = this.#appCiphers[collectionId]
        if (!cipher) {
          let descriptor: CollectionEncryption | undefined =
            this.#appDescriptors[collectionId]
          if (!descriptor) {
            try {
              descriptor = await remote.collectionEncryption({ collectionId })
            } catch (err) {
              console.warn(
                `Could not fetch the encryption descriptor for app collection ` +
                  `"${collectionId}":`,
                err
              )
            }
          }
          if (!descriptor?.epochs || descriptor.epochs.length === 0) {
            // No multi-recipient roster: the vault KAK is not (yet) a
            // recipient, so there is nothing this session can decrypt.
            return { value: undefined, unknownEpoch: false }
          }
          this.#appDescriptors[collectionId] = descriptor
          cipher = await createEdvDocCipher({
            keyAgreementKey,
            keyResolver,
            collectionId,
            encryption: descriptor
          })
          this.#appCiphers[collectionId] = cipher
        }
        return await decryptEnvelope({
          cipher,
          envelope: data,
          source: `app collection "${collectionId}"`
        })
      }
    })
  }

  async deleteCollectionResource(resource: StorageResource): Promise<void> {
    await this.#requireRemote(
      'Deleting a storage resource'
    ).deleteCollectionResource({
      relativeUrl: resource.url
    })
  }

  /**
   * Provisions an arbitrary plaintext collection on the remote WAS Space, for
   * a relying party's delegated capability. No local counterpart -- RP
   * collections are the RP's data, reached only over its zcap. Requires a
   * remote backend. With `isPublic`, the collection also gets a
   * collection-level world-readable (PublicCanRead) policy.
   *
   * @param options {object}
   * @param options.id {string}
   * @param [options.name] {string}
   * @param [options.isPublic] {boolean}
   * @returns {Promise<void>}
   */
  async ensureCollection({
    id,
    name,
    isPublic
  }: {
    id: string
    name?: string
    isPublic?: boolean
  }): Promise<void> {
    await this.#requireRemote('Provisioning a collection').ensureCollection({
      id,
      name,
      isPublic
    })
  }

  async deleteCollection({ id }: { id: string }): Promise<void> {
    await this.#requireRemote('Deleting a collection').deleteCollection({ id })
  }

  /**
   * Provisions an App Connect app-provisioned PRIVATE collection as a
   * multi-recipient EDV collection: the user's vault KAK is always recipient
   * zero (policy -- the user is a recipient of every encrypted collection in
   * their own Space) alongside the app's identity key-agreement key. The
   * collection is ensured to exist and declared `'edv'` without clobbering an
   * existing descriptor, then `ensureFirstEpoch` installs epoch[0] wrapped to
   * the owner alone -- create-if-absent, adopting a roster an earlier
   * provision landed, so every app collection carries its key epochs from
   * birth (the first-epoch mint runs only here, at provisioning). The app is
   * then always escrowed in by `addRecipient` (into every epoch -- adds are
   * cheap) unless the current epoch already wraps to it (reconnect with no
   * intervening revoke: a no-op).
   *
   * The app never needs the vault KAK and the wallet never needs the app seed
   * at all (the recipient is derived from the app's controller DID, and the
   * roster kid is in the descriptor), so this is the only step that pairs the two
   * recipients. Requires the vault key material and a remote store (an App
   * Connect popup always has both).
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id to provision
   * @param options.appRecipient {RecipientPublicKey}   the app's identity
   *   public key-agreement key, the X25519 twin of its controller `did:key`
   *   (its `id` is the recipient `kid`)
   * @returns {Promise<CollectionEncryption>}   the current descriptor
   */
  async provisionAppCollection({
    collectionId,
    appRecipient
  }: {
    collectionId: string
    appRecipient: RecipientPublicKey
  }): Promise<CollectionEncryption> {
    const remote = this.#requireRemote('Provisioning an app collection')
    if (!this.#vaultKeys) {
      throw new Error(
        'Provisioning an app collection requires the vault key material.'
      )
    }
    const { keyAgreementKey } = this.#vaultKeys
    const collection = remote.collectionHandle({ collectionId })
    // Ensure the collection exists and is declared encrypted without dropping
    // an existing epoch roster, then install epoch[0] (owner as recipient
    // zero) create-if-absent -- an existing roster is adopted, never
    // overwritten.
    await remote.ensureEncryptedCollection({ id: collectionId })
    const { descriptor: current } = await ensureFirstEpoch({
      collection,
      recipients: [ownerRecipient({ keyAgreementKey })]
    })

    if (
      currentEpochRecipientKids({ descriptor: current }).includes(
        appRecipient.id
      )
    ) {
      // The app already reads the current epoch: nothing to do.
      return current
    }
    // First connect, or reconnect after a revoke rotated the epoch off the
    // app: escrow the app into every epoch (adds are cheap -- no rotation).
    const descriptor = await addRecipient({
      collection,
      recipient: appRecipient,
      owner: { keyAgreementKey }
    })

    // Update the descriptor cache and the in-memory app-collection state, then drop
    // any stale app cipher so the wallet's own next read rebuilds under the new
    // descriptor (mirrors shareCollection's tail).
    await this.#descriptorCache?.writeDescriptor({ collectionId, descriptor })
    this.#appDescriptors[collectionId] = descriptor
    delete this.#appCiphers[collectionId]
    this.#refreshPolicy.reset({ collectionId })
    return descriptor
  }

  /**
   * Fires collection provisioning and records its promise for the read-readiness
   * contract (`ready()`), returning the same promise so a caller can await full
   * provisioning where a grant needs the remote Space to exist.
   *
   * @param options {object}
   * @param options.user {User}
   * @param [options.profile] {ControllerProfile}
   * @param [options.idb] {IDBFactory}   an explicit IndexedDB factory for the
   *   session-key caches (the pin stores), where the default first-party
   *   database is not the right home
   * @returns {Promise<void>}
   */
  ensureUserCollections({
    user,
    profile,
    idb
  }: {
    user: User
    profile?: ControllerProfile
    idb?: IDBFactory
  }): Promise<void> {
    this.#provisioning = this.#provisionUserCollections({ user, profile, idb })
    return this.#provisioning
  }

  /**
   * Promotes the account's Space (and keystore) controller to the published
   * did:webvh -- the last step of promotion by ordering: the Space was
   * created under this client's did:key, the log went into the
   * world-readable `id` collection, and this PUTs the Space Description
   * naming the did:webvh, authorized by the stored controller. Idempotent
   * across every state:
   *
   * - Fresh signup (store bound to the did:key): promote, then swap the
   *   session's signing -- `profile.zcapClient` and the remote store rebind
   *   to the `<did:webvh>#<multibase>` keyId, since under the current-key-set
   *   rule the did:key-signed form stops verifying the moment the promotion
   *   lands.
   * - Pointer-promoted login (store already bound to the did:webvh): confirm
   *   with one describe and return.
   * - Torn signup (pointer names the did:webvh but the promotion PUT never
   *   landed): the describe fails, and the promotion is retried signed by
   *   the stored did:key controller, then the store rebinds back to the
   *   session's did:webvh client.
   *
   * The keystore half runs after the Space half, non-fatally (KMS outages
   * must not fail provisioning): the keystore config's controller becomes
   * the did:webvh and the session's KeystoreAgent rebinds to invoke under
   * it.
   *
   * @param options {object}
   * @param options.profile {ControllerProfile}
   * @returns {Promise<void>}
   */
  async ensurePromotedController({
    profile
  }: {
    profile: ControllerProfile
  }): Promise<void> {
    const remote = this.#remoteStore
    const did = profile.didWebvh?.did
    const { keyAgent } = profile
    if (!remote || !keyAgent || !isWebvhDid(did)) {
      return
    }

    if (remote.controller === did) {
      // Already bound to the promoted controller (the pointer path): one
      // describe confirms the server agrees; a null answer (was-client maps
      // 404 -- the shape unauthorized reads take -- to null) means the
      // promotion PUT never landed, and the promotion is retried signed by
      // the stored did:key controller. A THROWN describe (a 5xx, a network
      // flake) is not evidence either way: re-PUTting with the demoted key
      // on a hiccup would be wrong, and this is the one provisioning step
      // awaited un-guarded -- so a transport failure warns and skips like
      // the neighbouring steps, and the next login re-checks.
      let description: { controller?: string } | null
      try {
        description = (await remote.spaceHandle().describe()) as {
          controller?: string
        } | null
      } catch (err) {
        console.warn('Could not confirm the promoted Space controller:', err)
        return
      }
      if (description?.controller === did) {
        this.#promoteKeystore({ profile, did })
        return
      }
      remote.rebindController({
        zcapClient: didKeyZcapClient({ keyAgent }),
        controller: keyAgent.id
      })
      try {
        await remote.promoteSpaceController({ controller: did })
      } finally {
        remote.rebindController({
          zcapClient: profile.zcapClient,
          controller: did
        })
      }
      this.#promoteKeystore({ profile, did })
      return
    }

    // Fresh promotion: the PUT is authorized by the stored did:key
    // controller the store is still bound to; the swap follows.
    await remote.promoteSpaceController({ controller: did })
    const zcapClient = webvhZcapClient({ keyAgent, did })
    profile.zcapClient = zcapClient
    remote.rebindController({ zcapClient, controller: did })
    this.#promoteKeystore({ profile, did })
  }

  /**
   * The keystore half of controller promotion, non-fatal by design (no
   * wallet feature hard-depends on the keystore): promotes the keystore
   * config's controller to the did:webvh -- retrying once with the did:key
   * identity when the bound agent's invocation is refused (a keystore not
   * yet promoted, invoked as the did:webvh) -- and rebinds the session's
   * KeystoreAgent to invoke under the promoted identity.
   *
   * Fired without await from the Space promotion path: the keystore's
   * promotion has no ordering dependency on anything that follows, and a
   * KMS hiccup only surfaces as the same warn a failed keystore
   * provisioning does.
   *
   * @param options {object}
   * @param options.profile {ControllerProfile}
   * @param options.did {string}   the account's did:webvh DID
   * @returns {void}
   */
  #promoteKeystore({
    profile,
    did
  }: {
    profile: ControllerProfile
    did: string
  }): void {
    const { keystoreAgent, keyAgent } = profile
    if (!keystoreAgent || !keyAgent) {
      return
    }
    void (async () => {
      try {
        await promoteKeystoreController({ keystoreAgent, controller: did })
      } catch {
        // The bound identity could not read/update the config -- a keystore
        // still under the did:key invoked as the did:webvh. Retry as the
        // did:key.
        const didKeyBound = rebindKeystoreAgent({
          keystoreAgent,
          capabilityAgent: keyAgent
        })
        await promoteKeystoreController({
          keystoreAgent: didKeyBound,
          controller: did
        })
      }
      profile.keystoreAgent = rebindKeystoreAgent({
        keystoreAgent,
        capabilityAgent: webvhCapabilityAgent({ keyAgent, did })
      })
    })().catch(err => {
      console.warn('Keystore controller promotion failed:', err)
    })
  }

  async #provisionUserCollections({
    user,
    profile,
    idb
  }: {
    user: User
    profile?: ControllerProfile
    idb?: IDBFactory
  }) {
    await this.#localStore.ensureUserCollections({ user })
    // Re-key any plaintext rows a pre-encryption version of the app left in
    // the (now encrypted) local collections. Runs before login completes --
    // and so before background replication starts -- because the remote
    // collections reject plaintext pushes once their encryption descriptor is set.
    await this.#localStore.migrateLocalPlaintextDocs()
    // Re-key any `public-credentials` rows left under the pre-fix CID formula.
    // Runs regardless of vault state -- public rows are plaintext -- and before
    // replication so the tombstone and the re-keyed row reach the remote
    // collection.
    await this.#localStore.migratePublicCredentialCids()
    if (this.#remoteStore) {
      // A pointer-promoted session signs with the did:webvh keyId from the
      // start; confirm the server agrees before any signed upsert runs, and
      // heal a signup that tore between the pointer backfill and the
      // promotion PUT (the requests below would otherwise all be refused).
      // Warn-and-continue like the neighbouring steps: an unpromoted
      // controller degrades the signed requests below, but a promotion
      // hiccup must not fail the whole login (the next login re-heals).
      if (profile && isWebvhDid(profile.accountPointer?.did)) {
        try {
          await this.ensurePromotedController({ profile })
        } catch (err) {
          console.warn('Space controller promotion failed:', err)
        }
      }
      await this.#remoteStore.ensureUserCollections({ user })
      // The provisioning two-step's EDV-bearing second half: install key
      // epoch[0] on every encrypted roster collection, wrapped to the
      // account's user key -- create-if-absent, adopting whatever an earlier
      // provisioner landed. Runs before login completes (and so before
      // replication starts), keeping the descriptor-before-first-content-push
      // invariant. Warn-and-continue like the neighbouring steps: without
      // epochs the affected collections' ciphers refuse fail-closed (nothing
      // leaks plaintext), and the idempotent ensure resumes on the next
      // login.
      if (profile?.userKey) {
        try {
          await this.#remoteStore.ensureSpaceEpochs({
            userKey: profile.userKey
          })
          // A fresh signup built this session's ciphers before the Space
          // existed, so every encrypted collection's descriptor was
          // unavailable and its cipher refuses. Now that epoch[0] is
          // installed, refresh the descriptors and rebuild the ciphers --
          // only when a descriptor is still missing its epochs, so an
          // ordinary login (descriptors fetched at session init) adds no
          // requests.
          if (
            ENCRYPTED_COLLECTION_IDS.some(
              collectionId => !this.#descriptors[collectionId]?.epochs?.length
            )
          ) {
            await this.refreshEncryptedDescriptors()
          }
        } catch (err) {
          console.warn('Collection key-epoch provisioning failed:', err)
        }
      }
      // Provision and publish the user's did:web DID (only when a keystore
      // agent is present). Runs here, after the Space and `id` collection
      // exist. Non-fatal like keystore provisioning: a KMS/WAS hiccup must not
      // fail login; the settings page surfaces the unprovisioned state, and
      // the idempotent flow resumes on the next login.
      if (profile?.keystoreAgent) {
        try {
          const did = didWebFromSpace({
            wasServerUrl: this.#remoteStore.storageServerUrl,
            spaceId: this.#remoteStore.spaceId
          })
          const keys = await ensureDidWeb({
            keystoreAgent: profile.keystoreAgent,
            remoteStore: this.#remoteStore,
            did
          })
          profile.didWeb = { did, keys }

          // Provision and publish the did:webvh log alongside did:web, in
          // its own try so a webvh hiccup never rolls back the did:web
          // provisioning. Gated on the opt-out flag, and on this client
          // holding its update-key seeds and identity keys (the document
          // carries a verification method per enrolled client, and the log
          // can only be extended with the client-held update key).
          // `ensureDidWeb` returned the parsed keys.json (with any webvh
          // block), threaded in so steady state stays one keys.json read
          // total.
          if (
            ENABLE_DID_WEBVH &&
            profile.clientWebvhKeys &&
            profile.keyAgent &&
            profile.clientKeyAgreementKey
          ) {
            try {
              const { publicKeyMultibase: keyAgreementKeyMultibase } =
                profile.clientKeyAgreementKey as unknown as {
                  publicKeyMultibase?: string
                }
              if (!keyAgreementKeyMultibase) {
                throw new Error(
                  'The client key-agreement key has no public multibase.'
                )
              }
              const { did: webvhDid } = await ensureDidWebvh({
                idStore: this.#remoteStore.webvhIdStore(),
                wasServerUrl: this.#remoteStore.storageServerUrl,
                spaceId: this.#remoteStore.spaceId,
                didWebKeys: keys as DidWebKeyMapV2,
                clientKeys: {
                  signingKeyMultibase: clientSigningKeyMultibase({
                    keyAgent: profile.keyAgent
                  }),
                  keyAgreementKeyMultibase
                },
                updateKeys: profile.clientWebvhKeys
              })
              if (webvhDid) {
                profile.didWebvh = { did: webvhDid }
              }
              // Provisioning publishes (or extends) the log, so any memo of
              // an earlier verification is dropped.
              invalidateVerifiedLog({ profile })
            } catch (err) {
              console.warn('did:webvh provisioning failed:', err)
            }
          }
        } catch (err) {
          console.warn('did:web provisioning failed:', err)
        }
      }
      // Ensure the user key wrap-set roster (the `key-map/user-key.jsonl`
      // resource log) exists, create-if-absent through the log-governed
      // descriptor-store seam: an absent roster is initialized with the
      // account's user key as its first epoch, wrapped to this client's own
      // key-agreement key, and the created epoch is pinned as the latest
      // seen. Runs after DID provisioning, not before: the roster log's
      // entry proofs anchor in the account's did:webvh document, so the
      // genesis append needs the published log to verify against. An
      // existing roster is left untouched (the login-time read verifies
      // it). Non-fatal like DID provisioning: the idempotent ensure resumes
      // on the next login.
      const rosterDid = profile?.didWebvh?.did ?? profile?.accountPointer?.did
      if (
        profile?.userKey &&
        profile.clientKeyAgreementKey &&
        profile.keyAgent &&
        isWebvhDid(rosterDid)
      ) {
        try {
          const descriptor = await ensureUserKeyRoster({
            store: accountRosterStore({
              zcapClient: profile.zcapClient,
              keyAgent: profile.keyAgent,
              pointer: {
                did: rosterDid,
                spaceId: this.#remoteStore.spaceId,
                host: this.#remoteStore.storageServerUrl
              },
              idb
            }),
            userKey: profile.userKey,
            clientKeyAgreementKey: profile.clientKeyAgreementKey
          })
          // Pin only an epoch this session already holds the key for: the
          // ensure serves an existing roster back without the continuity and
          // unwrap checks of the full login-time read, so a served epoch id
          // alone is not evidence. The session's own user key is -- it came
          // from the checked login-time read or the local client-key record
          // -- and the save itself is monotonic, so a rolled-back descriptor
          // can never drag the pin backward.
          if (descriptor.currentEpoch === profile.userKey.id) {
            await savePinFromDescriptor({
              spaceId: this.#remoteStore.spaceId,
              epochId: descriptor.currentEpoch,
              descriptor,
              idb
            })
          }
        } catch (err) {
          console.warn('user key roster provisioning failed:', err)
        }
      }
    }
  }

  /**
   * Mints the activity id and writes the built activity to the local
   * `wallet-activity` collection -- the shared body of every `addHistory*`
   * method below.
   *
   * A locally-minted, time-monotonic `uuidv7` is injected as the activity id
   * (rather than the builder's random default) so it doubles as the record's
   * resource id: on the guest / offline path that id is the RxDB primary key,
   * and its monotonicity keeps history ordering stable when two writes share
   * an `updatedAt` millisecond.
   *
   * @param build {function}   builds the activity from the minted id
   * @returns {Promise<void>}
   */
  async #recordActivity(build: (id: string) => WalletActivity): Promise<void> {
    const resourceId = uuidv7()
    await this.#store.addHistoryItem({
      resourceId,
      activity: build(resourceId)
    })
  }

  /**
   * Records (in the `wallet-activity` collection) the Create activity for
   * the bootstrap did:key DID.
   */
  async addHistoryNewAccount({ user }: { user: User }) {
    await this.#recordActivity(id => buildHistoryNewAccount({ user, id }))
  }

  /**
   * Records (in the `wallet-activity` collection) the Create activity for
   * the storage collections created (and, when a remote replica is
   * configured, the remote Space).
   */
  async addHistorySpaceCreated({ user }: { user: User }) {
    const remote = this.#remoteStore
    const object = remote
      ? [
          { type: ['Space'], id: remote.spaceUrl },
          ...WALLET_STANDARD_COLLECTIONS.map(({ key }) => ({
            type: ['Collection'],
            id: remote.collectionUrl(key)
          }))
        ]
      : WALLET_STANDARD_COLLECTIONS.map(({ id }) => ({
          type: ['Collection'],
          id
        }))
    await this.#recordActivity(id =>
      buildHistorySpaceCreated({
        actor: user.id,
        object,
        remote: !!remote,
        id
      })
    )
  }

  /**
   * Records (in the `wallet-activity` collection) a credential activity,
   * stamping the shared-package summary/object with the credential's
   * display title so the History page can render a title link without
   * re-deriving it from the (possibly already-deleted) credential.
   *
   * @param options {object}
   * @param options.cid {string} - CID of the credential (used as history object id).
   * @param options.title {string} - Display title of the credential at the time of the event.
   * @param options.user {User} - Session user object (used to record history object actor).
   * @param options.verb {string} - Past-tense verb for the summary line (e.g. "created").
   * @param options.buildActivity {function} - The `@interop/wallet-core` builder for this event.
   * @returns {Promise<void>}
   */
  async #recordCredentialActivity({
    cid,
    title,
    user,
    verb,
    buildActivity
  }: {
    cid: string
    title: string
    user: User
    verb: string
    buildActivity: (options: {
      cid: string
      user: User
      id: string
    }) => WalletActivity
  }) {
    const resourceId = uuidv7()
    const activity = buildActivity({ cid, user, id: resourceId })
    activity.summary = `Credential ${verb}: ${title}`
    activity.object = { cid, title }
    await this.#addHistoryItem({ resourceId, activity })
  }

  /**
   * Records (in the `wallet-activity` collection) a credential activity,
   * stamping the shared-package summary/object with the credential's
   * display title so the History page can render a title link without
   * re-deriving it from the (possibly already-deleted) credential.
   *
   * @param options {object}
   * @param options.cid {string} - CID of the credential (used as history object id).
   * @param options.title {string} - Display title of the credential at the time of the event.
   * @param options.user {User} - Session user object (used to record history object actor).
   * @param options.verb {string} - Past-tense verb for the summary line (e.g. "created").
   * @param options.buildActivity {function} - The `@interop/wallet-core` builder for this event.
   * @returns {Promise<void>}
   */
  async #recordCredentialActivity({
    cid,
    title,
    user,
    verb,
    buildActivity
  }: {
    cid: string
    title: string
    user: User
    verb: string
    buildActivity: (options: {
      cid: string
      user: User
      id: string
    }) => WalletActivity
  }) {
    const resourceId = uuidv7()
    const activity = buildActivity({ cid, user, id: resourceId })
    activity.summary = `Credential ${verb}: ${title}`
    activity.object = { cid, title }
    await this.#addHistoryItem({ resourceId, activity })
  }

  /**
   * Records (in the `wallet-activity` collection) the Create activity for
   * a credential.
   *
   * @param cid {string} - CID of the credential (used as history object id).
   * @param title {string} - Display title of the credential.
   * @param user {User} - Session user object (used to record history object actor).
   * @returns {Promise<void>}
   */
  async addHistoryCredentialCreated({
    cid,
    title,
    user
  }: {
    cid: string
    title: string
    user: User
  }) {
    await this.#recordCredentialActivity({
      cid,
      title,
      user,
      verb: 'created',
      buildActivity: buildHistoryCredentialCreated
    })
  }

  /**
   * Records (in the `wallet-activity` collection) the Delete activity for
   * a credential.
   *
   * @param cid {string} - CID of the credential (used as history object id).
   * @param title {string} - Display title of the credential (captured before deletion).
   * @param user {User} - Session user object (used to record history object actor).
   * @returns {Promise<void>}
   */
  async addHistoryCredentialDeleted({
    cid,
    title,
    user
  }: {
    cid: string
    title: string
    user: User
  }) {
    await this.#recordCredentialActivity({
      cid,
      title,
      user,
      verb: 'deleted',
      buildActivity: buildHistoryCredentialDeleted
    })
  }

  /**
   * Records (in the `wallet-activity` collection) the Share activity for a credential.
   *
   * @param cid {string} - CID of the credential (used as history object id).
   * @param title {string} - Display title of the credential.
   * @param user {User} - Session user object (used to record history object actor).
   * @returns {Promise<void>}
   */
  async addHistoryCredentialShared({
    cid,
    title,
    user
  }: {
    cid: string
    title: string
    user: User
  }) {
    await this.#recordCredentialActivity({
      cid,
      title,
      user,
      verb: 'shared',
      buildActivity: buildHistoryCredentialShared
    })
  }

  /**
   * Records (in the `wallet-activity` collection) the Unshare activity for a credential.
   *
   * @param cid {string} - CID of the credential (used as history object id).
   * @param title {string} - Display title of the credential.
   * @param user {User} - Session user object (used to record history object actor).
   * @returns {Promise<void>}
   */
  async addHistoryCredentialUnshared({
    cid,
    title,
    user
  }: {
    cid: string
    title: string
    user: User
  }) {
    await this.#recordCredentialActivity({
      cid,
      title,
      user,
      verb: 'unshared',
      buildActivity: buildHistoryCredentialUnshared
    })
  }

  /**
   * Records (in the `wallet-activity` collection) a Login activity: the user
   * logged in to a relying party via "Login with Wallet", granting the listed
   * capabilities. The recorded zcap ids are the hook for a revocation UI: the
   * WAS server now exposes a Space-scoped revocation endpoint, so a grant can
   * be retired before its expiry.
   *
   * @param options {object}
   * @param options.user {User}
   * @param options.origin {string}   the relying party's origin
   * @param options.grants {Array<{ id: string; target: string;
   *   allowedActions: string[]; expires: string; zcap?: IZcap }>}   each grant
   *   carries its display summary plus, when available, the full delegated
   *   capability document (`zcap`) kept verbatim so it can be revoked later
   * @param [options.appConnect] {{ name: string; firstRun: boolean;
   *   appUrl?: string }}   set for an App Connect login: the app's display
   *   name, whether the app key was minted on this connect (first run) or
   *   matched (returning), and the validated request's `appUrl` -- what tells
   *   two apps sharing an origin apart
   * @returns {Promise<void>}
   */
  async addHistoryLogin({
    user,
    origin,
    grants,
    appConnect
  }: {
    user: User
    origin: string
    grants: Array<{
      id: string
      target: string
      allowedActions: string[]
      expires: string
      zcap?: IZcap
    }>
    appConnect?: { name: string; firstRun: boolean; appUrl?: string }
  }) {
    await this.#recordActivity(id =>
      buildHistoryLogin({ user, origin, grants, appConnect, id })
    )
  }

  /**
   * Records (in the `wallet-activity` collection) a Revoke activity: the user
   * revoked a connected app's access, retiring its app-key credential and its
   * storage grants. The recorded origin and app name are the audit trail for
   * the Applications settings section; the deletion of the app-key credential
   * itself is a separate credential activity.
   *
   * @param options {object}
   * @param options.user {User}
   * @param options.origin {string}   the connected app's origin
   * @param options.name {string}   the connected app's display name
   * @param [options.cid] {string}   the retired app-key credential's cid
   * @param [options.revoked] {number}   how many storage grants were revoked
   * @param [options.skipped] {number}   how many grants needed no revocation
   *   (legacy summary-only records, already-expired, or already-revoked)
   * @returns {Promise<void>}
   */
  async addHistoryAppRevoke({
    user,
    origin,
    name,
    cid,
    revoked,
    skipped
  }: {
    user: User
    origin: string
    name: string
    cid?: string
    revoked?: number
    skipped?: number
  }) {
    await this.#recordActivity(id =>
      buildHistoryAppRevoke({ user, origin, name, cid, revoked, skipped, id })
    )
  }

  /**
   * Records (in the `wallet-activity` collection) a ClientRevoke activity: an
   * enrolled wallet client was disconnected -- the revocation cascade's audit
   * record.
   *
   * @param options {object}
   * @param options.user {User}
   * @param options.signingKeyMultibase {string}   the revoked client's signing
   *   key multibase
   * @param [options.label] {string}
   * @param [options.rotated] {number}   collections that took a fresh epoch
   * @param [options.failed] {number}   collections the cascade could not
   *   rotate (the completion sweep's remainder)
   * @returns {Promise<void>}
   */
  async addHistoryClientRevoked({
    user,
    signingKeyMultibase,
    label,
    rotated,
    failed
  }: {
    user: User
    signingKeyMultibase: string
    label?: string
    rotated?: number
    failed?: number
  }) {
    await this.#recordActivity(id =>
      buildHistoryClientRevoked({
        user,
        signingKeyMultibase,
        label,
        rotated,
        failed,
        id
      })
    )
  }

  /**
   * Revokes the storage grants a connected app received through App Connect.
   * Scans the `Login` activities for App Connect records matching the app's
   * `origin`, collects the full delegated capabilities recorded on them that
   * were delegated to the app's `subjectDid`, and revokes each one via the
   * Space's root capability (the Space controller can revoke anything it
   * delegated). The app never receives decryption key material, so unlike a
   * collection un-share this rotates no epoch and touches no recipient roster.
   *
   * Best-effort per capability: an already-revoked, expired, or foreign zcap
   * makes the server throw `ValidationError`, which is swallowed (counted as
   * skipped) so revoking twice is a no-op; any other failure (e.g. the server
   * unreachable) propagates so the caller can retry rather than silently drop
   * the credential. Legacy records that stored only a display summary (no full
   * zcap) are nothing to revoke -- expiry is their backstop -- and count as
   * skipped. A no-op returning zero counts when no remote store is configured.
   *
   * @param options {object}
   * @param options.origin {string}   the connected app's origin
   * @param options.subjectDid {string}   the app-key credential's subject DID,
   *   the controller the grants were delegated to
   * @param [options.items] {Array<{ id: string; doc: WalletActivity }>}   a
   *   pre-fetched history scan, when the caller already holds one
   * @returns {Promise<{ revoked: number; skipped: number }>}
   */
  async revokeAppGrants({
    origin,
    subjectDid,
    items
  }: {
    origin: string
    subjectDid: string
    items?: Array<{ id: string; doc: WalletActivity }>
  }): Promise<{ revoked: number; skipped: number }> {
    const remote = this.#remoteStore
    if (!remote) {
      return { revoked: 0, skipped: 0 }
    }
    // Scan the history once and pass it through, so the grant lookup does not
    // re-await and re-scan it. A caller that already holds the history (the
    // revoke orchestration, which drives several of these) passes it in.
    const { zcaps, skipped: nonRevocable } = this.#recordedAppGrantZcaps({
      origin,
      subjectDid,
      items: items ?? (await this.listHistoryItems())
    })
    const space = remote.spaceHandle()
    let revoked = 0
    let skipped = nonRevocable
    for (const zcap of zcaps) {
      try {
        await space.revoke(zcap)
        revoked += 1
      } catch (err) {
        if (err instanceof ValidationError) {
          // Already revoked, expired, or foreign -- treat as a no-op.
          skipped += 1
          continue
        }
        throw err
      }
    }
    return { revoked, skipped }
  }

  /**
   * The WAS collection id a grant zcap targets, when its `invocationTarget` is a
   * collection (or a resource within one) directly under the given Space URL --
   * the first path segment after `${spaceUrl}/`. Returns undefined for a
   * whole-Space target or a foreign URL.
   *
   * @param options {object}
   * @param options.invocationTarget {string}
   * @param options.spaceUrl {string}
   * @returns {string | undefined}
   */
  static #collectionIdFromTarget({
    invocationTarget,
    spaceUrl
  }: {
    invocationTarget: string
    spaceUrl: string
  }): string | undefined {
    if (!invocationTarget.startsWith(`${spaceUrl}/`)) {
      return undefined
    }
    const segment = invocationTarget.slice(spaceUrl.length + 1).split('/')[0]
    return segment || undefined
  }

  /**
   * Whether a collection id names a protected wallet collection -- a standard
   * collection, or one of the account's system collections
   * (`SYSTEM_COLLECTIONS`: `id`, `key-map`, `unlock-methods`). Never an
   * app-provisioned one, so it is excluded from recipient-removal on
   * revocation.
   *
   * @param collectionId {string}
   * @returns {boolean}
   */
  static #isProtectedCollection(collectionId: string): boolean {
    return (
      SYSTEM_COLLECTIONS.some(entry => entry.id === collectionId) ||
      WALLET_STANDARD_COLLECTIONS.some(entry => entry.id === collectionId)
    )
  }

  /**
   * The key-rotation half of revoking a connected app's access: for each
   * app-provisioned encrypted collection the app was granted, removes every
   * non-owner recipient entry from the current epoch via was-client's
   * `removeRecipient` (which rotates the epoch FIRST, then revokes the passed
   * pull-axis zcaps -- indivisible), so a revoked app cannot decrypt future
   * writes. The owner (the vault KAK) stays recipient zero; for these
   * collections every non-owner entry is the app's, and removal needs no seed
   * (the roster kid is in the descriptor), so it works even for an orphaned state.
   *
   * The candidate collections come from the recorded grant zcaps'
   * `invocationTarget`s (standard / protected collections and whole-Space grants
   * excluded); only those whose current-epoch roster still carries a non-owner
   * entry are rotated. Best-effort per collection: a failure is logged and the
   * rest proceed, so one stuck collection does not strand the whole revocation.
   * A no-op (zero counts) without a remote store or vault keys. The honest
   * ceiling stands: ciphertext the app already fetched stays readable to it.
   *
   * @param options {object}
   * @param options.origin {string}   the connected app's origin
   * @param options.subjectDid {string}   the app-key credential's subject DID
   * @param [options.items] {Array<{ id: string; doc: WalletActivity }>}   a
   *   pre-fetched history scan, when the caller already holds one
   * @returns {Promise<{ collections: number; rotated: number; failed: number }>}
   */
  async revokeAppCollectionRecipients({
    origin,
    subjectDid,
    items
  }: {
    origin: string
    subjectDid: string
    items?: Array<{ id: string; doc: WalletActivity }>
  }): Promise<{ collections: number; rotated: number; failed: number }> {
    const remote = this.#remoteStore
    if (!remote || !this.#vaultKeys) {
      return { collections: 0, rotated: 0, failed: 0 }
    }
    const ownerKid = this.#vaultKeys.keyAgreementKey.id
    const spaceUrl = remote.spaceUrl
    const { zcaps } = this.#recordedAppGrantZcaps({
      origin,
      subjectDid,
      items: items ?? (await this.listHistoryItems())
    })

    // Group the pull-axis zcaps by the app-provisioned collection they target,
    // dropping whole-Space and protected-collection grants.
    const byCollection = new Map<string, IDelegatedZcap[]>()
    for (const zcap of zcaps) {
      const collectionId = StorageManager.#collectionIdFromTarget({
        invocationTarget: zcap.invocationTarget,
        spaceUrl
      })
      if (
        !collectionId ||
        StorageManager.#isProtectedCollection(collectionId)
      ) {
        continue
      }
      const existing = byCollection.get(collectionId)
      if (existing) {
        existing.push(zcap)
      } else {
        byCollection.set(collectionId, [zcap])
      }
    }

    let rotated = 0
    let failed = 0
    for (const [collectionId, revoke] of byCollection) {
      try {
        const descriptor = await remote.collectionEncryption({ collectionId })
        if (!descriptor?.epochs?.length || !descriptor.currentEpoch) {
          continue
        }
        const nonOwner = currentEpochRecipientKids({ descriptor, ownerKid })
        if (nonOwner.length === 0) {
          continue
        }
        for (const recipientId of nonOwner) {
          const newDescriptor = await removeRecipient({
            collection: remote.collectionHandle({ collectionId }),
            space: remote.spaceHandle(),
            recipientId,
            revoke
          })
          await this.#descriptorCache?.writeDescriptor({
            collectionId,
            descriptor: newDescriptor
          })
          this.#appDescriptors[collectionId] = newDescriptor
          delete this.#appCiphers[collectionId]
          this.#refreshPolicy.reset({ collectionId })
        }
        rotated += 1
      } catch (err) {
        console.warn(
          `Could not rotate the epoch for app collection "${collectionId}" ` +
            'during revocation:',
          err
        )
        failed += 1
      }
    }
    return { collections: byCollection.size, rotated, failed }
  }

  /**
   * The full delegated zcaps recorded for a connected app, scanned from the
   * App Connect `Login` history activities: those on a Login for `origin` whose
   * recorded `zcap` was delegated to `subjectDid` and has not already expired.
   * Deduplicated by capability id. `skipped` counts the entries that carry no
   * revocable capability (legacy summary-only records, a different controller,
   * or an already-expired grant).
   *
   * @param options {object}
   * @param options.origin {string}
   * @param options.subjectDid {string}
   * @param options.items {Array<{ id: string; doc: WalletActivity }>}   the
   *   pre-fetched history, so this need not re-scan it
   * @returns {{ zcaps: IDelegatedZcap[]; skipped: number }}
   */
  #recordedAppGrantZcaps({
    origin,
    subjectDid,
    items
  }: {
    origin: string
    subjectDid: string
    items: Array<{ id: string; doc: WalletActivity }>
  }): { zcaps: IDelegatedZcap[]; skipped: number } {
    const zcaps: IDelegatedZcap[] = []
    const seen = new Set<string>()
    const now = Date.now()
    let skipped = 0
    for (const { doc } of items) {
      if (!doc.type?.includes('Login')) {
        continue
      }
      const object = doc.object as
        { origin?: string; appConnect?: unknown; zcaps?: unknown } | undefined
      if (!object || object.origin !== origin || !object.appConnect) {
        continue
      }
      if (!Array.isArray(object.zcaps)) {
        continue
      }
      for (const entry of object.zcaps) {
        const record = (entry ?? {}) as { expires?: string; zcap?: IZcap }
        const zcap = record.zcap
        // A legacy summary-only entry has no revocable capability; expiry is
        // the backstop.
        if (!zcap || !('parentCapability' in zcap)) {
          skipped += 1
          continue
        }
        // Only revoke capabilities delegated to this app's key.
        const controllers = Array.isArray(zcap.controller)
          ? zcap.controller
          : [zcap.controller]
        if (!controllers.includes(subjectDid)) {
          skipped += 1
          continue
        }
        if (seen.has(zcap.id)) {
          continue
        }
        seen.add(zcap.id)
        const expiresAt = zcap.expires
          ? new Date(zcap.expires).getTime()
          : record.expires
            ? new Date(record.expires).getTime()
            : 0
        if (expiresAt && expiresAt <= now) {
          skipped += 1
          continue
        }
        zcaps.push(zcap)
      }
    }
    return { zcaps, skipped }
  }

  /**
   * Whether public links (sharing) are available this session. A public link
   * only means something as a world-readable URL on the remote WAS server, so
   * sharing requires a remote replica to be configured.
   */
  get canShare(): boolean {
    return !!this.#remoteStore
  }

  /**
   * The public URL a credential would resolve to once shared, or `undefined`
   * when there is no remote backend.
   */
  publicLinkUrl({ cid }: { cid: string }): string | undefined {
    return this.#remoteStore?.publicCredentialUrl(cid)
  }

  /**
   * Creates a world-readable public link for a credential and returns its URL.
   * The public copy is plaintext and content-addressed (keyed by the
   * credential's cid, a hash of its content). It is written to the local
   * `public-credentials` collection; background replication mirrors it to the
   * remote WAS Collection, where the returned URL resolves.
   *
   * @param credential {IVerifiableCredential}
   * @returns {Promise<string>}
   */
  async createPublicLink({
    credential
  }: {
    credential: IVerifiableCredential
  }): Promise<string> {
    const remote = this.#requireRemote('Creating a public link')
    const cid = await cidFrom({ doc: credential })
    await this.#store.addPublicCredential({ cid, credential })
    return remote.publicCredentialUrl(cid)
  }

  /**
   * Revokes a credential's public link by removing its copy from the local
   * `public-credentials` collection (replication pushes the delete to the
   * remote Collection).
   *
   * @param cid {string}
   * @returns {Promise<void>}
   */
  async removePublicLink({ cid }: { cid: string }): Promise<void> {
    await this.#store.removePublicCredential({ cid })
  }

  async isShared({ cid }: { cid: string }): Promise<boolean> {
    return await this.#store.hasPublicCredential({ cid })
  }

  /**
   * Lists the items in the `wallet-activity` history collection.
   */
  async listHistoryItems(): Promise<
    Array<{ id: string; doc: WalletActivity }>
  > {
    // Same stale-descriptor refresh as `listCredentials`, once per session.
    return this.#readWithEpochRefresh({
      collectionId: 'wallet-activity',
      read: async () => ({
        value: await this.#store.listHistoryItems(),
        unknownEpoch: this.#store.unknownEpochHistory > 0
      })
    })
  }

  /**
   * Shares one of the wallet's encrypted collections with another reader,
   * doing BOTH halves of a share as one procedure: the read axis (an epoch-key
   * recipient entry, so the reader can decrypt) and the pull axis (a read-only
   * Collection zcap delegated to the grantee, so the server serves it
   * ciphertext). Requires a passphrase session (the root key delegates and the
   * recipient operations rewrite the Collection Description) with an unlocked
   * vault and a remote store.
   *
   * The read axis is always `addRecipient`: every encrypted collection
   * carries its key epochs from provisioning (epoch[0] wrapped to the user
   * key; the first-epoch mint runs only there), so a share escrows the reader
   * into every existing epoch (no rotation -- adds are cheap) and an
   * epoch-less descriptor is refused fail-closed rather than seeded here (it
   * can only mean an unprovisioned or torn collection). The delegated zcap
   * (the full document, needed later for revocation) is recorded in a
   * `CollectionShare` history activity, and the refreshed descriptor is cached and
   * swapped into the local ciphers.
   *
   * @param options {object}
   * @param options.profile {ControllerProfile}   the passphrase session profile
   *   (root `zcapClient` + vault KAK)
   * @param options.user {User}   recorded as the share activity's actor
   * @param options.collectionId {string}   the WAS collection id to share
   * @param options.recipient {RecipientPublicKey}   the grantee's public
   *   key-agreement key (its `id` is the recipient `kid`)
   * @param options.controller {string}   the grantee's DID (the zcap controller)
   * @param [options.expires] {Date}   the pull zcap's expiry; defaults to the
   *   read-only grant TTL
   * @param [options.app] {{ name: string, origin: string }}   the connected app
   *   the share was granted to, when the grantee is one; recorded on the share
   *   activity so the settings panel can name it instead of showing a bare DID
   * @returns {Promise<{ descriptor: CollectionEncryption, zcap: IDelegatedZcap }>}
   *   the new descriptor and the delegated pull-axis capability (the caller embeds
   *   it in its response -- the grantee needs both axes)
   */
  async shareCollection({
    profile,
    user,
    collectionId,
    recipient,
    controller,
    expires,
    app
  }: {
    profile: ControllerProfile
    user: User
    collectionId: string
    recipient: RecipientPublicKey
    controller: string
    expires?: Date
    app?: { name: string; origin: string }
  }): Promise<{ descriptor: CollectionEncryption; zcap: IDelegatedZcap }> {
    const remote = this.#requireRemote('Sharing a collection')
    const { keyAgreementKey, keyResolver, zcapClient } = profile
    if (!keyAgreementKey || !keyResolver) {
      throw new Error('Sharing a collection requires the vault key material.')
    }
    if (!profile.keyAgent) {
      throw new Error('Sharing a collection requires a passphrase session.')
    }

    // Read axis: escrow the reader into the existing epochs (epoch[0] exists
    // from provisioning, wrapped to the owner -- recipient zero).
    const collection = remote.collectionHandle({ collectionId })
    const descriptor = await addRecipient({
      collection,
      recipient,
      owner: { keyAgreementKey }
    })

    // Pull axis: delegate a read-only (GET/HEAD) zcap on the collection URL to
    // the grantee, rooted at the Space root capability (targets outside the
    // Space are unsatisfiable by construction).
    const spaceUrl = remote.spaceUrl
    const spaceRootCapability = await generateZcapUri({ url: spaceUrl })
    const collectionUrl = `${spaceUrl}/${collectionId}`
    const expiresAt = expires ?? new Date(Date.now() + RP_ZCAP_TTL_MS)
    const zcap = (await zcapClient.delegate({
      capability: spaceRootCapability,
      invocationTarget: collectionUrl,
      controller,
      allowedActions: ['GET', 'HEAD'],
      expires: expiresAt
    })) as unknown as IDelegatedZcap

    // Record the share -- the full delegated zcap document is the revocation
    // hook `unshareCollection` reads back.
    await this.#recordActivity(id => ({
      id,
      type: [ACTIVITY_TYPE.CollectionShare],
      summary: `Shared collection "${collectionId}" with ${controller}.`,
      actor: { email: user.email },
      object: {
        collectionId,
        recipientId: recipient.id,
        controller,
        zcap,
        expires: expiresAt.toISOString(),
        ...(app && { appName: app.name, appOrigin: app.origin })
      },
      created: new Date().toISOString()
    }))

    // Update the descriptor cache and rebuild + swap the ciphers under it.
    await this.#adoptCollectionDescriptor({
      collectionId,
      descriptor,
      vaultKeys: { keyAgreementKey, keyResolver }
    })
    return { descriptor, zcap }
  }

  /**
   * Stops sharing one of the wallet's encrypted collections with a reader,
   * doing BOTH halves of an un-share indivisibly via was-client's
   * `removeRecipient`: it rotates the epoch to the remaining current-epoch
   * roster (the read axis; prospective) THEN revokes the recorded zcap(s) (the
   * pull axis; immediate). freewallet never exposes a rotate-only or
   * revoke-only path. Requires a passphrase session with a remote store.
   *
   * Every zcap recorded for this `(collectionId, recipientId)` is looked up
   * from the `CollectionShare` history activities and passed to `revoke`; an
   * empty set is acceptable (e.g. all grants already expired) -- the rotation
   * still happens. A `CollectionUnshare` activity is recorded (no zcap), and
   * the rotated descriptor is cached and swapped into the local ciphers.
   *
   * @param options {object}
   * @param options.profile {ControllerProfile}   the passphrase session profile
   * @param options.user {User}   recorded as the unshare activity's actor
   * @param options.collectionId {string}
   * @param options.recipientId {string}   the removed reader's key-agreement
   *   key id (`kid`)
   * @returns {Promise<CollectionEncryption>}   the new descriptor
   */
  async unshareCollection({
    profile,
    user,
    collectionId,
    recipientId
  }: {
    profile: ControllerProfile
    user: User
    collectionId: string
    recipientId: string
  }): Promise<CollectionEncryption> {
    const remote = this.#requireRemote('Unsharing a collection')
    const { keyAgreementKey, keyResolver } = profile
    if (!keyAgreementKey || !keyResolver) {
      throw new Error('Unsharing a collection requires the vault key material.')
    }
    if (!profile.keyAgent) {
      throw new Error('Unsharing a collection requires a passphrase session.')
    }

    // Gather every zcap recorded for this recipient, to revoke as the pull-axis
    // half of the removal. Scan the history once and pass it through.
    const items = await this.listHistoryItems()
    const revoke = this.#recordedShareZcaps({
      collectionId,
      recipientId,
      items
    })
    const descriptor = await removeRecipient({
      collection: remote.collectionHandle({ collectionId }),
      space: remote.spaceHandle(),
      recipientId,
      revoke
    })

    await this.#recordActivity(id => ({
      id,
      type: [ACTIVITY_TYPE.CollectionUnshare],
      summary: `Stopped sharing collection "${collectionId}".`,
      actor: { email: user.email },
      object: { collectionId, recipientId },
      created: new Date().toISOString()
    }))

    await this.#adoptCollectionDescriptor({
      collectionId,
      descriptor,
      vaultKeys: { keyAgreementKey, keyResolver }
    })
    return descriptor
  }

  /**
   * Adopts a freshly rotated collection descriptor into this session: cached,
   * swapped into the in-memory descriptor map, the refresh policy reset, and
   * the ciphers rebuilt under the given vault keys. The shared tail of
   * `shareCollection` and `unshareCollection`.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param options.descriptor {CollectionEncryption}
   * @param options.vaultKeys {object}
   * @param options.vaultKeys.keyAgreementKey {IKeyAgreementKey}
   * @param options.vaultKeys.keyResolver {IKeyResolver}
   * @returns {Promise<void>}
   */
  async #adoptCollectionDescriptor({
    collectionId,
    descriptor,
    vaultKeys
  }: {
    collectionId: string
    descriptor: CollectionEncryption
    vaultKeys: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  }): Promise<void> {
    await this.#descriptorCache?.writeDescriptor({ collectionId, descriptor })
    this.#descriptors = { ...this.#descriptors, [collectionId]: descriptor }
    this.#refreshPolicy.reset()
    this.#vaultKeys = vaultKeys
    await this.#rebuildCiphers()
  }

  /**
   * The delegated zcap documents recorded for a `(collectionId, recipientId)`
   * pair, scanned from the `CollectionShare` history activities -- the pull-axis
   * capabilities `unshareCollection` revokes.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param options.recipientId {string}
   * @param options.items {Array<{ id: string; doc: WalletActivity }>}   the
   *   pre-fetched history, so this need not re-scan it
   * @returns {IDelegatedZcap[]}
   */
  #recordedShareZcaps({
    collectionId,
    recipientId,
    items
  }: {
    collectionId: string
    recipientId: string
    items: Array<{ id: string; doc: WalletActivity }>
  }): IDelegatedZcap[] {
    const zcaps: IDelegatedZcap[] = []
    for (const { doc } of items) {
      if (!doc.type?.includes('CollectionShare')) {
        continue
      }
      const object = doc.object as
        | {
            collectionId?: string
            recipientId?: string
            zcap?: IDelegatedZcap
          }
        | undefined
      if (
        object?.collectionId === collectionId &&
        object?.recipientId === recipientId &&
        object?.zcap
      ) {
        zcaps.push(object.zcap)
      }
    }
    return zcaps
  }

  /**
   * Lists the readers a collection is currently shared with, derived from the
   * descriptor's `currentEpoch` roster minus the owner's own key (the cryptographic
   * truth), joined best-effort with the `CollectionShare` / `CollectionUnshare`
   * history for each reader's controller DID, grant expiry, and -- when the
   * reader is a connected app -- its name and origin. Backs the settings UI.
   * Returns an empty list for a collection with no epochs (never shared) or
   * when the descriptor cannot be resolved.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param [options.items] {Array<{ id: string; doc: WalletActivity }>}   a
   *   pre-fetched history scan, when the caller already holds one (the
   *   settings panel lists every shareable collection off one read)
   * @returns {Promise<Array<{ recipientId: string; controller?: string;
   *   expires?: string; appName?: string; appOrigin?: string }>>}
   */
  async listCollectionShares({
    collectionId,
    items
  }: {
    collectionId: string
    items?: Array<{ id: string; doc: WalletActivity }>
  }): Promise<
    Array<{
      recipientId: string
      controller?: string
      expires?: string
      appName?: string
      appOrigin?: string
    }>
  > {
    const remote = this.#remoteStore
    let descriptor: CollectionEncryption | undefined =
      this.#descriptors[collectionId]
    if (!descriptor && remote && this.#descriptorCache) {
      descriptor = await acquireDescriptor({
        source: remote,
        cache: this.#descriptorCache,
        collectionId
      })
    }
    if (!descriptor?.currentEpoch || !descriptor.epochs) {
      return []
    }
    // The owner's own key-agreement key is recipient zero on every epoch; drop
    // it so the list is only the other readers.
    const recipientIds = currentEpochRecipientKids({
      descriptor,
      ownerKid: this.#vaultKeys?.keyAgreementKey.id
    })
    if (recipientIds.length === 0) {
      return []
    }

    // Best-effort labels from history: the latest CollectionShare per recipient
    // for its controller / expiry.
    const labels = new Map<
      string,
      {
        controller?: string
        expires?: string
        appName?: string
        appOrigin?: string
      }
    >()
    for (const { doc } of items ?? (await this.listHistoryItems())) {
      if (!doc.type?.includes('CollectionShare')) {
        continue
      }
      const object = doc.object as
        | {
            collectionId?: string
            recipientId?: string
            controller?: string
            expires?: string
            appName?: string
            appOrigin?: string
          }
        | undefined
      if (object?.collectionId === collectionId && object?.recipientId) {
        labels.set(object.recipientId, {
          controller: object.controller,
          expires: object.expires,
          appName: object.appName,
          appOrigin: object.appOrigin
        })
      }
    }
    return recipientIds.map(recipientId => ({
      recipientId,
      ...labels.get(recipientId)
    }))
  }

  /**
   * Lists the stored contacts.
   *
   * @returns {Promise<Array<StoredContact>>}
   */
  async listContacts(): Promise<Array<StoredContact>> {
    return await this.#store.listContacts()
  }

  /**
   * @param options {object}
   * @param options.id {string}
   * @returns {Promise<StoredContact | undefined>}
   */
  async loadContact({
    id
  }: {
    id: string
  }): Promise<StoredContact | undefined> {
    return await this.#store.loadContact({ id })
  }

  /**
   * Adds a contact and appends its `create` revision to `contacts-history`
   * (best-effort: the contact is already durably stored either way).
   *
   * @param options {object}
   * @param options.contact {ContactData}
   * @returns {Promise<StoredContact>}
   */
  async addContact({
    contact
  }: {
    contact: ContactData
  }): Promise<StoredContact> {
    const writerId = getOrCreateWriterId()
    const stored = await this.#store.addContact({ contact, writerId })
    await this.#recordContactRevision({
      contactId: stored.contactId,
      action: 'create',
      snapshot: contact,
      writerId
    })
    return stored
  }

  /**
   * Rewrites a contact's row in place and appends its `update` revision.
   *
   * @param options {object}
   * @param options.id {string}
   * @param options.contact {ContactData}
   * @returns {Promise<StoredContact>}
   */
  async updateContact({
    id,
    contact
  }: {
    id: string
    contact: ContactData
  }): Promise<StoredContact> {
    const writerId = getOrCreateWriterId()
    const stored = await this.#store.updateContact({
      id,
      contact,
      writerId
    })
    await this.#recordContactRevision({
      contactId: stored.contactId,
      action: 'update',
      snapshot: contact,
      writerId
    })
    return stored
  }

  /**
   * Deletes a contact and appends a `delete` revision carrying its last known
   * snapshot (read before the row is removed).
   *
   * @param options {object}
   * @param options.id {string}
   * @returns {Promise<void>}
   */
  async deleteContact({ id }: { id: string }): Promise<void> {
    const existing = await this.#store.loadContact({ id })
    await this.#store.deleteContact({ id })
    if (existing) {
      await this.#recordContactRevision({
        contactId: existing.contactId,
        action: 'delete',
        snapshot: existing.contact,
        writerId: getOrCreateWriterId()
      })
    }
  }

  /**
   * Best-effort revision write shared by `addContact`/`updateContact`/
   * `deleteContact`: the contact mutation itself has already landed, so a
   * failure here (e.g. a transient encryption hiccup) is logged rather than
   * thrown -- losing one history line beats reporting the whole save/delete
   * as failed.
   *
   * @param options {object}
   * @param options.contactId {string}
   * @param options.action {ContactRevisionPayload['action']}
   * @param options.snapshot {ContactData}
   * @param options.writerId {string}
   * @returns {Promise<void>}
   */
  async #recordContactRevision({
    contactId,
    action,
    snapshot,
    writerId
  }: {
    contactId: string
    action: ContactRevisionPayload['action']
    snapshot: ContactData
    writerId: string
  }): Promise<void> {
    try {
      await this.#store.addContactRevision({
        revision: {
          contactId,
          action,
          timestamp: new Date().toISOString(),
          writerId,
          snapshot
        }
      })
    } catch (err) {
      console.warn(`Could not record the contact-${action} revision:`, err)
    }
  }

  /**
   * Lists a contact's revision history, most recent first. Keyed by the
   * LOGICAL contact id (`StoredContact.contactId`, the id inside the head
   * payload that every replica's revisions refer to), not the row id --
   * for mobile-authored contacts the two differ.
   *
   * @param options {object}
   * @param options.contactId {string}
   * @returns {Promise<Array<ContactRevisionPayload>>}
   */
  async listContactRevisions({
    contactId
  }: {
    contactId: string
  }): Promise<Array<ContactRevisionPayload>> {
    return await this.#store.listContactRevisions({ contactId })
  }
}
