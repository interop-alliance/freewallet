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
import { cidFrom } from '@/lib/cidFrom'
import {
  ENABLE_DID_WEBVH,
  RP_ZCAP_TTL_MS,
  WALLET_STANDARD_COLLECTIONS,
  WAS_SERVER_URL
} from '@/app.config'
import { getOrCreateDeviceId } from '@/lib/deviceId'
import { didWebFromSpace, ensureDidWeb } from '@/lib/didWeb'
import { ensureDidWebvh, type DidWebKeyMapV2 } from '@/lib/didWebvh'
import {
  createEdvDocCipher,
  isEncryptedEnvelope,
  ownerRecipient,
  type DocCipher
} from '@/stores/edvDocCipher'
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
import { UnknownEpochError } from '@/stores/edvDocCipher'
import { uuidv7 } from 'uuidv7'

/**
 * A wallet-activity log entry stored in the `wallet-activity` collection.
 * Modelled on ActivityStreams: a typed action carrying a human-readable
 * summary and a creation timestamp. All fields are optional because the
 * payload originates from the storage server and isn't schema-validated here.
 */
export interface WalletActivity {
  id?: string
  type?: string[]
  summary?: string
  actor?: unknown
  object?: unknown
  created?: string
}

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
   * and rewrites the `id` collection's `did.jsonl` / `keys.json` / `did.json`
   * directly through it.
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
      return undefined
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
      await this.#remoteStore.ensureUserCollections({ user })
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

          // Provision and publish the did:webvh log alongside did:web (Phase
          // 2, decision 6), in its own try so a webvh hiccup never rolls back
          // the did:web provisioning. Gated on the opt-out flag. `ensureDidWeb`
          // returned the parsed keys.json (with any webvh block), threaded in
          // so steady state stays one keys.json read total.
          if (ENABLE_DID_WEBVH) {
            try {
              const {
                updateKey,
                stagedKey,
                did: webvhDid
              } = await ensureDidWebvh({
                keystoreAgent: profile.keystoreAgent,
                remoteStore: this.#remoteStore,
                wasServerUrl: this.#remoteStore.storageServerUrl,
                spaceId: this.#remoteStore.spaceId,
                didWebKeys: keys as DidWebKeyMapV2
              })
              if (webvhDid) {
                profile.didWebvh = { did: webvhDid, updateKey, stagedKey }
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
    const resourceId = uuidv7()
    await this.#addHistoryItem({
      resourceId,
      activity: {
        id: resourceId,
        type: ['Create'],
        summary: 'Account Sign Up. did:key DID generated.',
        actor: { email: user.email },
        object: user.id,
        created: new Date().toISOString()
      }
    })
  }

  /**
   * Records (in the `wallet-activity` collection) the Create activity for
   * the storage collections created (and, when a remote replica is
   * configured, the remote Space).
   */
  async addHistorySpaceCreated({ user }: { user: User }) {
    const resourceId = uuidv7()
    const remote = this.#remoteStore
    const objects = remote
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
    await this.#addHistoryItem({
      resourceId,
      activity: {
        id: resourceId,
        type: ['Create'],
        summary: remote
          ? 'Account space created on remote storage server, collections initialized.'
          : 'Wallet collections initialized in local storage.',
        actor: user.id,
        object: objects,
        created: new Date().toISOString()
      }
    })
  }

  /**
   * Records (in the `wallet-activity` collection) a single credential activity.
   * Backs the four `addHistoryCredential*` wrappers, which differ only in the
   * activity type and the summary verb.
   *
   * @param options {object}
   * @param options.cid {string} - CID of the credential (used as history object id).
   * @param options.user {User} - Session user object (used to record history object actor).
   * @param options.type {string} - the activity type, e.g. 'Create' | 'Delete'.
   * @param options.verb {string} - the summary verb, e.g. 'created' | 'deleted'.
   * @returns {Promise<void>}
   */
  async #addCredentialActivity({
    cid,
    user,
    type,
    verb
  }: {
    cid: string
    user: User
    type: string
    verb: string
  }) {
    const resourceId = uuidv7()
    await this.#addHistoryItem({
      resourceId,
      activity: {
        id: resourceId,
        type: [type],
        summary: `Credential ${verb}: ${cid}`,
        actor: { email: user.email },
        object: cid,
        created: new Date().toISOString()
      }
    })
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
    await this.#addCredentialActivity({
      cid,
      user,
      type: 'Create',
      verb: 'created'
    })
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
    await this.#addCredentialActivity({
      cid,
      user,
      type: 'Delete',
      verb: 'deleted'
    })
  }

  /**
   * Records (in the `wallet-activity` collection) the Share activity for a credential.
   *
   * @param cid {string} - CID of the credential (used as history object id).
   * @param user {User} - Session user object (used to record history object actor).
   * @returns {Promise<void>}
   */
  async addHistoryCredentialShared({ cid, user }: { cid: string; user: User }) {
    await this.#addCredentialActivity({
      cid,
      user,
      type: 'Share',
      verb: 'shared'
    })
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
    await this.#addCredentialActivity({
      cid,
      user,
      type: 'Unshare',
      verb: 'unshared'
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
    const summary = appConnect
      ? `Connected ${appConnect.name} (${origin}) to wallet` +
        `${appConnect.firstRun ? ', minting a new app key' : ''}.`
      : `Logged in to ${origin} with wallet.`
    await this.#addHistoryItem({
      resourceId,
      activity: {
        id: resourceId,
        type: ['Login'],
        summary,
        actor: { email: user.email },
        object: appConnect
          ? { origin, zcaps: grants, appConnect }
          : { origin, zcaps: grants },
        created: new Date().toISOString()
      }
    })
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
    const summary =
      typeof revoked === 'number'
        ? `Revoked ${name} (${origin}) app access: ${revoked} grant(s) ` +
          `revoked${skipped ? `, ${skipped} skipped` : ''}.`
        : `Revoked ${name} (${origin}) app access.`
    await this.#addHistoryItem({
      resourceId,
      activity: {
        id: resourceId,
        type: ['Revoke'],
        summary,
        actor: { email: user.email },
        object: { origin, appConnect: { name }, cid, revoked, skipped },
        created: new Date().toISOString()
      }
    })
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
   * @returns {Promise<CollectionEncryption>}   the new marker
   */
  async shareCollection({
    profile,
    user,
    collectionId,
    recipient,
    controller,
    expires
  }: {
    profile: ControllerProfile
    user: User
    collectionId: string
    recipient: RecipientPublicKey
    controller: string
    expires?: Date
  }): Promise<CollectionEncryption> {
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
        type: ['CollectionShare'],
        summary: `Shared collection "${collectionId}" with ${controller}.`,
        actor: { email: user.email },
        object: {
          collectionId,
          recipientId: recipient.id,
          controller,
          zcap,
          expires: expiresAt.toISOString()
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
    return marker
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
        type: ['CollectionUnshare'],
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
   * history for each reader's controller DID and grant expiry. Backs the
   * settings UI. Returns an empty list for a collection with no epochs (never
   * shared) or when the marker cannot be resolved.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @returns {Promise<Array<{ recipientId: string; controller?: string;
   *   expires?: string }>>}
   */
  async listCollectionShares({
    collectionId
  }: {
    collectionId: string
  }): Promise<
    Array<{ recipientId: string; controller?: string; expires?: string }>
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
    const labels = new Map<string, { controller?: string; expires?: string }>()
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
          }
        | undefined
      if (object?.collectionId === collectionId && object?.recipientId) {
        labels.set(object.recipientId, {
          controller: object.controller,
          expires: object.expires
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
