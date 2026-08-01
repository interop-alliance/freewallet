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
 * EDV envelope under its content-derived id, `WAS-Key-Epoch` stamped) so the
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
  initRecipients,
  removeRecipient,
  type RecipientPublicKey
} from '@interop/was-client/edv'
import type { ControllerProfile, User } from '@/types/auth'
import { cidFrom } from '@interop/was-client/sync'
import {
  ENABLE_DID_WEBVH,
  ID_COLLECTION,
  KEY_MAP_COLLECTION,
  RP_ZCAP_TTL_MS,
  WALLET_STANDARD_COLLECTIONS,
  WAS_SERVER_URL
} from '@/app.config'
import { assertStorableAppKey } from '@/lib/appKey'
import { getOrCreateDeviceId } from '@/lib/deviceId'
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
import { ensurePukRoster } from '@interop/wallet-core/keys'
import { savePukEpochPin } from '@/lib/sessionKey'
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
 * The localStorage key under which a collection's last-seen encryption marker
 * is cached, scoped by Space so two accounts on one browser never collide. The
 * cache is the offline fallback: when a marker fetch fails, a
 * previously-shared collection must keep encrypting under its current epoch.
 *
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @returns {string}
 */
function markerCacheKey({
  spaceId,
  collectionId
}: {
  spaceId: string
  collectionId: string
}): string {
  return `freewallet:collection-encryption:${spaceId}:${collectionId}`
}

/**
 * Reads a cached collection encryption marker, or `undefined` when none is
 * cached (or in a non-browser environment). A corrupt cache entry is treated
 * as absent.
 *
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @returns {CollectionEncryption | undefined}
 */
function readCachedMarker({
  spaceId,
  collectionId
}: {
  spaceId: string
  collectionId: string
}): CollectionEncryption | undefined {
  if (typeof localStorage === 'undefined') {
    return undefined
  }
  const raw = localStorage.getItem(markerCacheKey({ spaceId, collectionId }))
  if (!raw) {
    return undefined
  }
  try {
    return JSON.parse(raw) as CollectionEncryption
  } catch {
    return undefined
  }
}

/**
 * Caches a collection encryption marker (no-op in a non-browser environment).
 *
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param options.marker {CollectionEncryption}
 * @returns {void}
 */
function writeCachedMarker({
  spaceId,
  collectionId,
  marker
}: {
  spaceId: string
  collectionId: string
  marker: CollectionEncryption
}): void {
  if (typeof localStorage === 'undefined') {
    return
  }
  localStorage.setItem(
    markerCacheKey({ spaceId, collectionId }),
    JSON.stringify(marker)
  )
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
  // marker refresh.
  #ciphers?: Record<string, DocCipher>
  // The provisioning promise from `ensureUserCollections` (fired at session
  // creation), awaited by the read-readiness contract in non-remote-direct mode.
  #provisioning?: Promise<void>
  // The vault key material, kept so ciphers can be rebuilt after a marker
  // refresh (an unknown-epoch read) without re-plumbing the profile.
  #vaultKeys?: {
    keyAgreementKey: IKeyAgreementKey
    keyResolver: IKeyResolver
  }
  // The last-known per-collection encryption markers, keyed by WAS collection
  // id, that the current ciphers were built from.
  #markers: Record<string, CollectionEncryption>
  // WAS collection ids whose marker has already been refreshed once this
  // session in response to an unknown-epoch read, so a genuinely foreign
  // envelope cannot drive a refresh loop. Cleared whenever a share / unshare
  // installs a fresh marker.
  #markerRefreshed = new Set<string>()
  // Lazily-built per-collection ciphers for App Connect app-provisioned
  // (non-standard) encrypted collections, keyed by WAS collection id. The
  // wallet decrypts these as an ordinary recipient with its vault KAK (recipient
  // zero), driven by the collection's fetched marker; built on first
  // decrypt-read from the storage browser, invalidated when a rekey lands.
  #appCiphers: Record<string, DocCipher> = {}
  // The markers the `#appCiphers` entries were built from, keyed by WAS
  // collection id -- the offline/lazy source for an app collection's cipher.
  #appMarkers: Record<string, CollectionEncryption> = {}

  constructor({
    localStore,
    remoteStore,
    ciphers,
    remoteDirect = false,
    vaultKeys,
    markers
  }: {
    localStore: BrowserStore
    remoteStore?: WASRemoteStore
    ciphers?: Record<string, DocCipher>
    remoteDirect?: boolean
    vaultKeys?: {
      keyAgreementKey: IKeyAgreementKey
      keyResolver: IKeyResolver
    }
    markers?: Record<string, CollectionEncryption>
  }) {
    this.#localStore = localStore
    this.#remoteStore = remoteStore
    this.#ciphers = ciphers
    this.#vaultKeys = vaultKeys
    this.#markers = markers ?? {}
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
   * When a collection has a multi-recipient encryption marker (its `markers`
   * entry, keyed by WAS collection id), the cipher is built epoch-aware from
   * it; without one it is the single-key path, unchanged.
   *
   * @param options {object}
   * @param options.keyAgreementKey {IKeyAgreementKey}
   * @param options.keyResolver {IKeyResolver}
   * @param [options.markers] {Record<string, CollectionEncryption>}   per-
   *   collection encryption markers, keyed by WAS collection id
   * @returns {Promise<Record<string, DocCipher>>}
   */
  static async #buildCiphers({
    keyAgreementKey,
    keyResolver,
    markers
  }: {
    keyAgreementKey: IKeyAgreementKey
    keyResolver: IKeyResolver
    markers?: Record<string, CollectionEncryption>
  }) {
    const cipherEntries = await Promise.all(
      WALLET_STANDARD_COLLECTIONS.filter(({ encryption }) => encryption).map(
        async ({ key, id }) => [
          key,
          await createEdvDocCipher({
            keyAgreementKey,
            keyResolver,
            collectionId: id,
            encryption: markers?.[id]
          })
        ]
      )
    )
    return Object.fromEntries(cipherEntries)
  }

  /**
   * Fetches the current encryption marker for each encrypted standard
   * collection best-effort, caching each success in localStorage and falling
   * back to the cached copy on a fetch failure (offline: a previously-shared
   * collection must keep encrypting under its current epoch). A successful
   * fetch that returns no marker (an unshared collection) leaves the entry
   * absent -- the single-key path. Returns the markers keyed by WAS collection
   * id; with no remote store it is empty (guest / no-WAS: single-key).
   *
   * @param options {object}
   * @param [options.remoteStore] {WASRemoteStore}
   * @returns {Promise<Record<string, CollectionEncryption>>}
   */
  static async #acquireMarkers({
    remoteStore
  }: {
    remoteStore?: WASRemoteStore
  }): Promise<Record<string, CollectionEncryption>> {
    const markers: Record<string, CollectionEncryption> = {}
    if (!remoteStore) {
      return markers
    }
    const { spaceId } = remoteStore
    // The per-collection marker fetches are independent signed round trips; run
    // them concurrently so login is not gated on a serial chain of describes.
    const resolved = await Promise.all(
      WALLET_STANDARD_COLLECTIONS.filter(({ encryption }) => encryption).map(
        async ({ id }): Promise<[string, CollectionEncryption] | null> => {
          try {
            const fetched = await remoteStore.collectionEncryption({
              collectionId: id
            })
            if (fetched) {
              writeCachedMarker({ spaceId, collectionId: id, marker: fetched })
              return [id, fetched]
            }
            return null
          } catch (err) {
            console.warn(
              `Could not fetch the encryption marker for collection "${id}"; ` +
                'falling back to the cached copy.',
              err
            )
            const cached = readCachedMarker({ spaceId, collectionId: id })
            return cached ? [id, cached] : null
          }
        }
      )
    )
    for (const entry of resolved) {
      if (entry) {
        markers[entry[0]] = entry[1]
      }
    }
    return markers
  }

  /**
   * Rebuilds the per-collection ciphers from the current markers and the held
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
      markers: this.#markers
    })
    this.#ciphers = ciphers
    // Swap into the active backend (the local store in the normal case, the
    // remote-direct backend in the popup); both honor `setCiphers` for the
    // marker-refresh path.
    this.#store.setCiphers(ciphers)
  }

  /**
   * Refreshes every encrypted collection's marker from the remote store, caches
   * them, and rebuilds + swaps the ciphers. Called when a local read reports
   * unknown-epoch rows -- a rekey emits no change-feed entry, so the local
   * cipher may be built from a stale marker. No-op without a remote store or
   * vault keys.
   *
   * @returns {Promise<void>}
   */
  async #refreshMarkers(): Promise<void> {
    if (!this.#remoteStore || !this.#vaultKeys) {
      return
    }
    this.#markers = await StorageManager.#acquireMarkers({
      remoteStore: this.#remoteStore
    })
    await this.#rebuildCiphers()
  }

  /**
   * Whether an unknown-epoch read should drive a one-time marker refresh for a
   * collection: a rekey emits no change-feed entry, so the cipher may be built
   * from a stale marker. Guarded so a genuinely foreign envelope cannot loop --
   * once per session per collection, and only with a remote store + vault keys.
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id
   * @param options.unknown {boolean}   whether the read reported unknown-epoch rows
   * @returns {boolean}
   */
  #shouldRefreshEpoch({
    collectionId,
    unknown
  }: {
    collectionId: string
    unknown: boolean
  }): boolean {
    return (
      unknown &&
      !!this.#remoteStore &&
      !!this.#vaultKeys &&
      !this.#markerRefreshed.has(collectionId)
    )
  }

  /**
   * Runs a read that reports whether it skipped unknown-epoch rows; on the first
   * such report for a collection this session, refreshes the marker (rebuilding
   * + swapping the ciphers) and re-reads once. The single seam behind
   * `listCredentials`, `listHistoryItems`, and `decryptCollectionResource`, so a
   * fresh-epoch resource is never silently dropped after a rekey on another
   * device -- for either backend, since the remote-direct backend surfaces the
   * same counts.
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
    const first = await read()
    if (
      this.#shouldRefreshEpoch({ collectionId, unknown: first.unknownEpoch })
    ) {
      this.#markerRefreshed.add(collectionId)
      await this.#refreshMarkers()
      return (await read()).value
    }
    return first.value
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

    // Build the remote store first (when configured), so its encryption markers
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
    const markers = await StorageManager.#acquireMarkers({ remoteStore })

    // One document cipher per encrypted collection, built from the session's
    // passphrase-derived key material (guests included -- their random secret
    // encrypts just as well; it is merely unrecoverable after logout, like the
    // rest of a guest session) plus any multi-recipient marker. The local store
    // holds EDV envelopes for these collections and replication ships them
    // verbatim.
    const ciphers = await StorageManager.#buildCiphers({
      keyAgreementKey,
      keyResolver,
      markers
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
      markers
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
   * presenting as an app key is screened: one that does not bind its subject
   * DID to the seed it carries is refused rather than stored and later
   * ignored. The wallet's own mint path stores through here too and passes,
   * since a freshly minted app key binds by construction.
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
    await assertStorableAppKey(credential)
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
        await this.addHistoryCredentialCreated({ cid, user })
      } catch (err) {
        console.warn('Could not record the credential-created activity:', err)
      }
    }
  }

  async listCredentials(): Promise<Array<StoredCredential>> {
    // Unknown-epoch rows mean the cipher may be built from a stale marker (a
    // rekey emits no change-feed entry); the shared helper refreshes the marker
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

  async deleteCredential({ cid }: { cid: string }) {
    await this.#store.deleteCredential({ cid })
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
    if (!this.#remoteStore) {
      throw new Error('Remote storage is not configured for this session.')
    }
    return await this.#remoteStore.exportSpace()
  }

  async importSpace({
    tarFile
  }: {
    tarFile: File
  }): Promise<ImportSpaceSummary> {
    if (!this.#remoteStore) {
      throw new Error('Remote storage is not configured for this session.')
    }
    return await this.#remoteStore.importSpace({ tarFile })
  }

  async listCollections(): Promise<Array<StorageCollection>> {
    if (!this.#remoteStore) {
      return []
    }
    return await this.#remoteStore.listCollections()
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
    if (!this.#remoteStore) {
      throw new Error('Remote storage is not configured for this session.')
    }
    return await this.#remoteStore.fetchCollectionResource(resource)
  }

  /**
   * Best-effort decryption of a fetched storage-browser resource body: when
   * the body is an EDV envelope from one of the encrypted standard
   * collections and this session holds that collection's cipher (unlocked
   * vault), returns the decrypted document. Returns undefined otherwise --
   * plaintext bodies, non-standard collections, a locked vault, or an
   * envelope that fails to decrypt (logged, not thrown), letting callers fall
   * back to showing the raw envelope. An `UnknownEpochError` (a rekey on
   * another device the cached marker has not caught up to) drives the same
   * one-time marker refresh + retry `listCredentials` / `listHistoryItems` use,
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
      // marker-driven from the fetched Collection Description.
      return this.#decryptAppCollectionResource({ collectionId, data })
    }
    return this.#readWithEpochRefresh({
      collectionId,
      read: async () => {
        // Re-fetch the cipher inside the read: a marker refresh rebuilds it.
        const cipher = this.#ciphers?.[entry.key]
        if (!cipher) {
          return { value: undefined, unknownEpoch: false }
        }
        try {
          return {
            value: await cipher.decrypt({ envelope: data }),
            unknownEpoch: false
          }
        } catch (err) {
          if (err instanceof UnknownEpochError) {
            return { value: undefined, unknownEpoch: true }
          }
          console.warn(
            `Could not decrypt resource envelope from collection ` +
              `"${collectionId}":`,
            err
          )
          return { value: undefined, unknownEpoch: false }
        }
      }
    })
  }

  /**
   * Best-effort decrypt of an EDV envelope from a non-standard (App Connect
   * app-provisioned) encrypted collection, using the session's vault KAK as an
   * ordinary recipient (recipient zero). Lazily fetches the collection's
   * `encryption` marker, builds and caches a per-collection `DocCipher` from it
   * (only when the marker carries epochs -- a wallet with only its vault KAK can
   * decrypt an app collection only once it is provisioned multi-recipient with
   * the vault KAK as a recipient), and decrypts. On an `UnknownEpochError` (a
   * rekey the cached marker has not caught up to) it re-fetches the marker,
   * rebuilds the cipher, and retries once per session for that collection.
   * Returns undefined on any failure (no vault keys / no remote store / no epoch
   * marker / a decrypt error), letting the caller show the raw envelope.
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

    const attempt = async (
      forceRefresh: boolean
    ): Promise<{ value: Json | undefined; unknownEpoch: boolean }> => {
      let cipher = this.#appCiphers[collectionId]
      if (!cipher || forceRefresh) {
        let marker = forceRefresh ? undefined : this.#appMarkers[collectionId]
        if (!marker) {
          try {
            marker = await remote.collectionEncryption({ collectionId })
          } catch (err) {
            console.warn(
              `Could not fetch the encryption marker for app collection ` +
                `"${collectionId}":`,
              err
            )
            marker = this.#appMarkers[collectionId]
          }
        }
        if (!marker?.epochs || marker.epochs.length === 0) {
          // No multi-recipient roster: the vault KAK is not (yet) a recipient,
          // so there is nothing this session can decrypt.
          return { value: undefined, unknownEpoch: false }
        }
        this.#appMarkers[collectionId] = marker
        cipher = await createEdvDocCipher({
          keyAgreementKey,
          keyResolver,
          collectionId,
          encryption: marker
        })
        this.#appCiphers[collectionId] = cipher
      }
      try {
        return {
          value: await cipher.decrypt({ envelope: data }),
          unknownEpoch: false
        }
      } catch (err) {
        if (err instanceof UnknownEpochError) {
          return { value: undefined, unknownEpoch: true }
        }
        console.warn(
          `Could not decrypt resource envelope from app collection ` +
            `"${collectionId}":`,
          err
        )
        return { value: undefined, unknownEpoch: false }
      }
    }

    const first = await attempt(false)
    if (first.unknownEpoch && !this.#markerRefreshed.has(collectionId)) {
      this.#markerRefreshed.add(collectionId)
      return (await attempt(true)).value
    }
    return first.value
  }

  async deleteCollectionResource(resource: StorageResource): Promise<void> {
    if (!this.#remoteStore) {
      throw new Error('Remote storage is not configured for this session.')
    }
    await this.#remoteStore.deleteCollectionResource({
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
    if (!this.#remoteStore) {
      throw new Error('Provisioning a collection requires remote storage.')
    }
    await this.#remoteStore.ensureCollection({ id, name, isPublic })
  }

  async deleteCollection({ id }: { id: string }): Promise<void> {
    if (!this.#remoteStore) {
      throw new Error('Deleting a collection requires remote storage.')
    }
    await this.#remoteStore.deleteCollection({ id })
  }

  /**
   * Provisions an App Connect app-provisioned PRIVATE collection as a
   * multi-recipient EDV collection: the user's vault KAK is always recipient
   * zero (policy -- the user is a recipient of every encrypted collection in
   * their own Space) alongside the app's identity key-agreement key. The
   * collection is ensured to exist and declared `'edv'` without clobbering an
   * existing marker, then the epoch roster is brought to the desired state:
   *
   * - no epochs yet -> `initRecipients` with `[owner, appRecipient]`;
   * - epochs exist but the app is absent (reconnect after revoke) ->
   *   `addRecipient` escrows the app into every epoch;
   * - epochs exist and the app is present -> no-op.
   *
   * The app never needs the vault KAK and the wallet never needs the app seed
   * at all (the recipient is derived from the app's controller DID, and the
   * roster kid is in the marker), so this is the only step that pairs the two
   * recipients. Requires the vault key material and a remote store (an App
   * Connect popup always has both).
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id to provision
   * @param options.appRecipient {RecipientPublicKey}   the app's identity
   *   public key-agreement key, the X25519 twin of its controller `did:key`
   *   (its `id` is the recipient `kid`)
   * @returns {Promise<CollectionEncryption>}   the current marker
   */
  async provisionAppCollection({
    collectionId,
    appRecipient
  }: {
    collectionId: string
    appRecipient: RecipientPublicKey
  }): Promise<CollectionEncryption> {
    const remote = this.#remoteStore
    if (!remote) {
      throw new Error('Provisioning an app collection requires remote storage.')
    }
    if (!this.#vaultKeys) {
      throw new Error(
        'Provisioning an app collection requires the vault key material.'
      )
    }
    const { keyAgreementKey } = this.#vaultKeys
    const collection = remote.collectionHandle({ collectionId })
    // Ensure the collection exists and is declared encrypted without dropping an
    // existing epoch roster; the returned marker (with any epochs) drives the
    // init-vs-add decision below.
    const current = await remote.ensureEncryptedCollection({ id: collectionId })

    let marker: CollectionEncryption
    if (!current?.epochs || current.epochs.length === 0) {
      // Lazy first provision: mint the first epoch with the owner as recipient
      // zero plus the app's identity key.
      marker = await initRecipients({
        collection,
        recipients: [ownerRecipient({ keyAgreementKey }), appRecipient]
      })
    } else {
      const epoch = current.epochs.find(
        entry => entry.id === current.currentEpoch
      )
      const present = !!epoch?.recipients.some(
        entry => entry.header.kid === appRecipient.id
      )
      if (present) {
        // The app already reads the current epoch: nothing to do.
        return current
      }
      // Reconnect after a revoke rotated the epoch off the app: escrow the app
      // back into every epoch (adds are cheap -- no rotation).
      marker = await addRecipient({
        collection,
        recipient: appRecipient,
        owner: { keyAgreementKey }
      })
    }

    // Update the marker cache and the in-memory app-collection state, then drop
    // any stale app cipher so the wallet's own next read rebuilds under the new
    // marker (mirrors shareCollection's tail).
    writeCachedMarker({ spaceId: remote.spaceId, collectionId, marker })
    this.#appMarkers[collectionId] = marker
    delete this.#appCiphers[collectionId]
    this.#markerRefreshed.delete(collectionId)
    return marker
  }

  /**
   * Fires collection provisioning and records its promise for the read-readiness
   * contract (`ready()`), returning the same promise so a caller can await full
   * provisioning where a grant needs the remote Space to exist.
   *
   * @param options {object}
   * @param options.user {User}
   * @param [options.profile] {ControllerProfile}
   * @returns {Promise<void>}
   */
  ensureUserCollections({
    user,
    profile
  }: {
    user: User
    profile?: ControllerProfile
  }): Promise<void> {
    this.#provisioning = this.#provisionUserCollections({ user, profile })
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
      // describe confirms the server agrees; a null answer (404-shaped for
      // unauthorized) means the promotion PUT never landed -- retry it
      // signed by the stored did:key controller, then rebind back.
      const description = (await remote
        .spaceHandle()
        .describe()
        .catch(() => null)) as { controller?: string } | null
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
    profile
  }: {
    user: User
    profile?: ControllerProfile
  }) {
    await this.#localStore.ensureUserCollections({ user })
    // Re-key any plaintext rows a pre-encryption version of the app left in
    // the (now encrypted) local collections. Runs before login completes --
    // and so before background replication starts -- because the remote
    // collections reject plaintext pushes once their encryption marker is set.
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
      if (profile && isWebvhDid(profile.accountPointer?.did)) {
        await this.ensurePromotedController({ profile })
      }
      await this.#remoteStore.ensureUserCollections({ user })
      // Ensure the PUK wrap-set roster (`key-map/puk.json`) exists,
      // create-if-absent through the marker-store seam: an absent roster is
      // initialized with the account's PUK as its first epoch, wrapped to
      // this client's own key-agreement key, and the created epoch is pinned
      // as the latest seen. An existing roster is left untouched (the
      // login-time read authenticates it). Non-fatal like DID provisioning:
      // the idempotent ensure resumes on the next login.
      if (profile?.puk && profile?.clientKeyAgreementKey) {
        try {
          const marker = await ensurePukRoster({
            store: this.#remoteStore.pukRosterStore(),
            puk: profile.puk,
            clientKeyAgreementKey: profile.clientKeyAgreementKey
          })
          if (marker.currentEpoch) {
            await savePukEpochPin({
              spaceId: this.#remoteStore.spaceId,
              epochId: marker.currentEpoch
            })
          }
        } catch (err) {
          console.warn('PUK roster provisioning failed:', err)
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
                idStore: this.#remoteStore,
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
            } catch (err) {
              console.warn('did:webvh provisioning failed:', err)
            }
          }
        } catch (err) {
          console.warn('did:web provisioning failed:', err)
        }
      }
    }
  }

  /**
   * Writes one activity to the local `wallet-activity` collection -- the
   * shared tail of every `addHistory*` method.
   *
   * @param options {object}
   * @param options.resourceId {string}
   * @param options.activity {WalletActivity}
   * @returns {Promise<void>}
   */
  async #addHistoryItem({
    resourceId,
    activity
  }: {
    resourceId: string
    activity: WalletActivity
  }): Promise<void> {
    await this.#store.addHistoryItem({ resourceId, activity })
  }

  /**
   * Records (in the `wallet-activity` collection) the Create activity for
   * the bootstrap did:key DID.
   */
  async addHistoryNewAccount({ user }: { user: User }) {
    // A locally-minted, time-monotonic `uuidv7` is injected as the activity id
    // (rather than the builder's random default) so it doubles as the record's
    // resource id: on the guest / offline path that id is the RxDB primary key,
    // and its monotonicity keeps history ordering stable when two writes share
    // an `updatedAt` millisecond. Every `addHistory*` wrapper below does the same.
    const resourceId = uuidv7()
    const activity = buildHistoryNewAccount({ user, id: resourceId })
    await this.#addHistoryItem({ resourceId, activity })
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
    const resourceId = uuidv7()
    const activity = buildHistorySpaceCreated({
      actor: user.id,
      object,
      remote: !!remote,
      id: resourceId
    })
    await this.#addHistoryItem({ resourceId, activity })
  }

  /**
   * Records (in the `wallet-activity` collection) the Create activity for
   * a credential.
   *
   * @param cid {string} - CID of the credential (used as history object id).
   * @param user {User} - Session user object (used to record history object actor).
   * @returns {Promise<void>}
   */
  async addHistoryCredentialCreated({
    cid,
    user
  }: {
    cid: string
    user: User
  }) {
    const resourceId = uuidv7()
    const activity = buildHistoryCredentialCreated({
      cid,
      user,
      id: resourceId
    })
    await this.#addHistoryItem({ resourceId, activity })
  }

  /**
   * Records (in the `wallet-activity` collection) the Delete activity for
   * a credential.
   *
   * @param cid {string} - CID of the credential (used as history object id).
   * @param user {User} - Session user object (used to record history object actor).
   * @returns {Promise<void>}
   */
  async addHistoryCredentialDeleted({
    cid,
    user
  }: {
    cid: string
    user: User
  }) {
    const resourceId = uuidv7()
    const activity = buildHistoryCredentialDeleted({
      cid,
      user,
      id: resourceId
    })
    await this.#addHistoryItem({ resourceId, activity })
  }

  /**
   * Records (in the `wallet-activity` collection) the Share activity for a credential.
   *
   * @param cid {string} - CID of the credential (used as history object id).
   * @param user {User} - Session user object (used to record history object actor).
   * @returns {Promise<void>}
   */
  async addHistoryCredentialShared({ cid, user }: { cid: string; user: User }) {
    const resourceId = uuidv7()
    const activity = buildHistoryCredentialShared({ cid, user, id: resourceId })
    await this.#addHistoryItem({ resourceId, activity })
  }

  /**
   * Records (in the `wallet-activity` collection) the Unshare activity for a credential.
   *
   * @param cid {string} - CID of the credential (used as history object id).
   * @param user {User} - Session user object (used to record history object actor).
   * @returns {Promise<void>}
   */
  async addHistoryCredentialUnshared({
    cid,
    user
  }: {
    cid: string
    user: User
  }) {
    const resourceId = uuidv7()
    const activity = buildHistoryCredentialUnshared({
      cid,
      user,
      id: resourceId
    })
    await this.#addHistoryItem({ resourceId, activity })
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
   * @param [options.appConnect] {{ name: string; firstRun: boolean }}   set
   *   for an App Connect login: the app's display name and whether the app
   *   key was minted on this connect (first run) or matched (returning)
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
    appConnect?: { name: string; firstRun: boolean }
  }) {
    const resourceId = uuidv7()
    const activity = buildHistoryLogin({
      user,
      origin,
      grants,
      appConnect,
      id: resourceId
    })
    await this.#addHistoryItem({ resourceId, activity })
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
    const resourceId = uuidv7()
    const activity = buildHistoryAppRevoke({
      user,
      origin,
      name,
      cid,
      revoked,
      skipped,
      id: resourceId
    })
    await this.#addHistoryItem({ resourceId, activity })
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
   * @returns {Promise<{ revoked: number; skipped: number }>}
   */
  async revokeAppGrants({
    origin,
    subjectDid
  }: {
    origin: string
    subjectDid: string
  }): Promise<{ revoked: number; skipped: number }> {
    const remote = this.#remoteStore
    if (!remote) {
      return { revoked: 0, skipped: 0 }
    }
    // Scan the history once and pass it through, so the grant lookup does not
    // re-await and re-scan it.
    const items = await this.listHistoryItems()
    const { zcaps, skipped: nonRevocable } = this.#recordedAppGrantZcaps({
      origin,
      subjectDid,
      items
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
   * Whether a collection id names a protected wallet collection (a standard
   * collection, `id`, or `key-map`) -- never an app-provisioned one, so it is
   * excluded from recipient-removal on revocation.
   *
   * @param collectionId {string}
   * @returns {boolean}
   */
  static #isProtectedCollection(collectionId: string): boolean {
    return (
      collectionId === ID_COLLECTION.id ||
      collectionId === KEY_MAP_COLLECTION.id ||
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
   * (the roster kid is in the marker), so it works even for an orphaned state.
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
   * @returns {Promise<{ collections: number; rotated: number; failed: number }>}
   */
  async revokeAppCollectionRecipients({
    origin,
    subjectDid
  }: {
    origin: string
    subjectDid: string
  }): Promise<{ collections: number; rotated: number; failed: number }> {
    const remote = this.#remoteStore
    if (!remote || !this.#vaultKeys) {
      return { collections: 0, rotated: 0, failed: 0 }
    }
    const ownerKid = this.#vaultKeys.keyAgreementKey.id
    const spaceUrl = remote.spaceUrl
    const items = await this.listHistoryItems()
    const { zcaps } = this.#recordedAppGrantZcaps({ origin, subjectDid, items })

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
        const marker = await remote.collectionEncryption({ collectionId })
        if (!marker?.epochs?.length || !marker.currentEpoch) {
          continue
        }
        const epoch = marker.epochs.find(
          entry => entry.id === marker.currentEpoch
        )
        if (!epoch) {
          continue
        }
        const nonOwner = epoch.recipients
          .map(entry => entry.header.kid)
          .filter(kid => kid !== ownerKid)
        if (nonOwner.length === 0) {
          continue
        }
        for (const recipientId of nonOwner) {
          const newMarker = await removeRecipient({
            collection: remote.collectionHandle({ collectionId }),
            space: remote.spaceHandle(),
            recipientId,
            revoke
          })
          writeCachedMarker({
            spaceId: remote.spaceId,
            collectionId,
            marker: newMarker
          })
          this.#appMarkers[collectionId] = newMarker
          delete this.#appCiphers[collectionId]
          this.#markerRefreshed.delete(collectionId)
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
    if (!this.#remoteStore) {
      throw new Error('Public links require remote storage.')
    }
    const cid = await cidFrom({ doc: credential })
    await this.#store.addPublicCredential({ cid, credential })
    return this.#remoteStore.publicCredentialUrl(cid)
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
    // Same stale-marker refresh as `listCredentials`, once per session.
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
   * On a collection with no epochs yet this is the lazy first-share migration:
   * `initRecipients` mints the first epoch with the owner as recipient zero
   * plus the new reader. On an already-shared collection `addRecipient` escrows
   * the reader into every epoch (no rotation -- adds are cheap). The delegated
   * zcap (the full document, needed later for revocation) is recorded in a
   * `CollectionShare` history activity, and the refreshed marker is cached and
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
   * @returns {Promise<{ marker: CollectionEncryption, zcap: IDelegatedZcap }>}
   *   the new marker and the delegated pull-axis capability (the caller embeds
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
  }): Promise<{ marker: CollectionEncryption; zcap: IDelegatedZcap }> {
    const remote = this.#remoteStore
    if (!remote) {
      throw new Error('Sharing a collection requires remote storage.')
    }
    const { keyAgreementKey, keyResolver, zcapClient } = profile
    if (!keyAgreementKey || !keyResolver) {
      throw new Error('Sharing a collection requires the vault key material.')
    }
    if (!profile.keyAgent) {
      throw new Error('Sharing a collection requires a passphrase session.')
    }

    // Read axis: mint the first epoch (lazy first-share) or escrow the reader
    // into the existing epochs. The owner must always be recipient zero.
    const collection = remote.collectionHandle({ collectionId })
    const current = await remote.collectionEncryption({ collectionId })
    let marker: CollectionEncryption
    if (!current?.epochs || current.epochs.length === 0) {
      marker = await initRecipients({
        collection,
        recipients: [ownerRecipient({ keyAgreementKey }), recipient]
      })
    } else {
      marker = await addRecipient({
        collection,
        recipient,
        owner: { keyAgreementKey }
      })
    }

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
    const resourceId = uuidv7()
    await this.#addHistoryItem({
      resourceId,
      activity: {
        id: resourceId,
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
      }
    })

    // Update the marker cache and rebuild + swap the ciphers under it.
    writeCachedMarker({ spaceId: remote.spaceId, collectionId, marker })
    this.#markers = { ...this.#markers, [collectionId]: marker }
    this.#markerRefreshed.clear()
    this.#vaultKeys = { keyAgreementKey, keyResolver }
    await this.#rebuildCiphers()
    return { marker, zcap }
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
   * the rotated marker is cached and swapped into the local ciphers.
   *
   * @param options {object}
   * @param options.profile {ControllerProfile}   the passphrase session profile
   * @param options.user {User}   recorded as the unshare activity's actor
   * @param options.collectionId {string}
   * @param options.recipientId {string}   the removed reader's key-agreement
   *   key id (`kid`)
   * @returns {Promise<CollectionEncryption>}   the new marker
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
    const remote = this.#remoteStore
    if (!remote) {
      throw new Error('Unsharing a collection requires remote storage.')
    }
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
    const marker = await removeRecipient({
      collection: remote.collectionHandle({ collectionId }),
      space: remote.spaceHandle(),
      recipientId,
      revoke
    })

    const resourceId = uuidv7()
    await this.#addHistoryItem({
      resourceId,
      activity: {
        id: resourceId,
        type: [ACTIVITY_TYPE.CollectionUnshare],
        summary: `Stopped sharing collection "${collectionId}".`,
        actor: { email: user.email },
        object: { collectionId, recipientId },
        created: new Date().toISOString()
      }
    })

    writeCachedMarker({ spaceId: remote.spaceId, collectionId, marker })
    this.#markers = { ...this.#markers, [collectionId]: marker }
    this.#markerRefreshed.clear()
    this.#vaultKeys = { keyAgreementKey, keyResolver }
    await this.#rebuildCiphers()
    return marker
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
   * marker's `currentEpoch` roster minus the owner's own key (the cryptographic
   * truth), joined best-effort with the `CollectionShare` / `CollectionUnshare`
   * history for each reader's controller DID, grant expiry, and -- when the
   * reader is a connected app -- its name and origin. Backs the settings UI.
   * Returns an empty list for a collection with no epochs (never shared) or
   * when the marker cannot be resolved.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @returns {Promise<Array<{ recipientId: string; controller?: string;
   *   expires?: string; appName?: string; appOrigin?: string }>>}
   */
  async listCollectionShares({
    collectionId
  }: {
    collectionId: string
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
    let marker: CollectionEncryption | undefined = this.#markers[collectionId]
    if (!marker && remote) {
      try {
        marker = await remote.collectionEncryption({ collectionId })
        if (marker) {
          writeCachedMarker({ spaceId: remote.spaceId, collectionId, marker })
        }
      } catch {
        marker = remote
          ? readCachedMarker({ spaceId: remote.spaceId, collectionId })
          : undefined
      }
    }
    if (!marker?.currentEpoch || !marker.epochs) {
      return []
    }
    const epoch = marker.epochs.find(entry => entry.id === marker!.currentEpoch)
    if (!epoch) {
      return []
    }
    // The owner's own key-agreement key is recipient zero on every epoch; drop
    // it so the list is only the other readers.
    const ownerKid = this.#vaultKeys?.keyAgreementKey.id
    const recipientIds = epoch.recipients
      .map(entry => entry.header.kid)
      .filter(kid => kid !== ownerKid)

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
    for (const { doc } of await this.listHistoryItems()) {
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
    const deviceId = getOrCreateDeviceId()
    const stored = await this.#store.addContact({ contact, deviceId })
    await this.#recordContactRevision({
      contactId: stored.contactId,
      action: 'create',
      snapshot: contact,
      deviceId
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
    const deviceId = getOrCreateDeviceId()
    const stored = await this.#store.updateContact({
      id,
      contact,
      deviceId
    })
    await this.#recordContactRevision({
      contactId: stored.contactId,
      action: 'update',
      snapshot: contact,
      deviceId
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
        deviceId: getOrCreateDeviceId()
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
   * @param options.deviceId {string}
   * @returns {Promise<void>}
   */
  async #recordContactRevision({
    contactId,
    action,
    snapshot,
    deviceId
  }: {
    contactId: string
    action: ContactRevisionPayload['action']
    snapshot: ContactData
    deviceId: string
  }): Promise<void> {
    try {
      await this.#store.addContactRevision({
        revision: {
          contactId,
          action,
          timestamp: new Date().toISOString(),
          deviceId,
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
