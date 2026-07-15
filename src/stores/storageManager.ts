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
 * The one deviation is remote-direct mode (`remoteDirect`), used by the CHAPI
 * popup. A popup runs in a third-party partitioned iframe: its local
 * BrowserStore binds a partitioned IndexedDB no sync controller drives, so a
 * credential stored there would be stranded and a credential list would always
 * come back empty. In remote-direct mode the credential and history operations
 * therefore route straight to the remote WAS collections (`WASRemoteStore`'s
 * `listSyncedResources` / `getSyncedResource` / `putSyncedResource`),
 * reproducing verbatim what background replication would have pushed so the
 * main app pulls it cleanly. It is effective only when a remote store is
 * configured; a guest / no-WAS session falls back to the local BrowserStore
 * behavior unchanged.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver,
  IVerifiableCredential,
  IZcap
} from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import type { RxCollection } from 'rxdb/plugins/core'
import type { ControllerProfile, User } from '@/types/auth'
import { cidFrom } from '@/lib/cidFrom'
import {
  ENABLE_DID_WEBVH,
  WALLET_STANDARD_COLLECTIONS,
  WAS_SERVER_URL
} from '@/app.config'
import { didWebFromSpace, ensureDidWeb } from '@/lib/didWeb'
import { ensureDidWebvh, type DidWebKeyMapV2 } from '@/lib/didWebvh'
import {
  createEdvDocCipher,
  isEncryptedEnvelope,
  type DocCipher
} from '@/stores/edvDocCipher'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import type { Json, SyncedDoc } from '@/lib/sync'
import type { SpaceQuotaReport } from '@/types/storageQuota'
import type { FetchedCollectionResource } from '@/lib/storageResource'
import type { StoredCredential } from '@/types/credential'
import { BrowserStore } from '@/stores/browserStore'
import {
  WASRemoteStore,
  type SessionCapabilities
} from '@/stores/wasRemoteStore'
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
 * Manages storage operations for the wallet and a logged-in user profile:
 * routes all wallet reads/writes to the local active replica and exposes the
 * optional remote WAS backend for replication and remote-only features.
 */
export class StorageManager {
  private _localStore: BrowserStore
  private _remoteStore?: WASRemoteStore // Only set if VITE_WAS_SERVER_URL env var is present
  private _vaultLocked: boolean
  // The per-collection document ciphers (same set handed to the local store),
  // kept here for remote-direct mode's own encrypt/decrypt at the WAS seam.
  private _ciphers?: Record<string, DocCipher>
  // Route credential + history operations straight to the remote WAS
  // collections instead of the local BrowserStore (the CHAPI popup path).
  private _remoteDirect: boolean

  constructor({
    localStore,
    remoteStore,
    vaultLocked = false,
    ciphers,
    remoteDirect = false
  }: {
    localStore: BrowserStore
    remoteStore?: WASRemoteStore
    vaultLocked?: boolean
    ciphers?: Record<string, DocCipher>
    remoteDirect?: boolean
  }) {
    this._localStore = localStore
    this._remoteStore = remoteStore
    this._vaultLocked = vaultLocked
    this._ciphers = ciphers
    this._remoteDirect = remoteDirect
  }

  /**
   * Whether remote-direct routing is actually in effect: the flag is only
   * meaningful when a remote store is configured (a guest / no-WAS session
   * always uses the local BrowserStore).
   */
  private get _effectiveRemoteDirect(): boolean {
    return this._remoteDirect && !!this._remoteStore
  }

  /**
   * Public view of {@link _effectiveRemoteDirect}, for callers that must know
   * where reads actually route (e.g. whether a read depends on the local
   * collections that `ensureUserCollections` initializes).
   */
  get remoteDirectActive(): boolean {
    return this._effectiveRemoteDirect
  }

  /**
   * Whether the encrypted collections are locked: true in a restored
   * (`delegated` tier) session whose vault KAK could not be recovered from
   * the session vault envelope (fail closed -- absent, expired, or unusable
   * envelopes all lock). Locked reads return nothing rather than raw
   * envelopes; locked writes throw rather than store plaintext into an
   * encrypted collection.
   */
  get vaultLocked(): boolean {
    return this._vaultLocked
  }

  private _requireUnlockedVault(): void {
    if (this._vaultLocked) {
      throw new Error(
        'The vault is locked in a restored session; log in with the ' +
          'passphrase to unlock it.'
      )
    }
  }

  /**
   * Whether a remote WAS backend is configured for this session. Pages use this
   * instead of reaching into the backend directly.
   */
  get hasRemoteStorage(): boolean {
    return !!this._remoteStore
  }

  /**
   * The remote Space id, or undefined when there is no remote backend.
   */
  get spaceId(): string | undefined {
    return this._remoteStore?.spaceId
  }

  /**
   * The remote WAS client, or undefined when there is no remote backend. Used by
   * the sync controller to drive background replication against remote Collection
   * replicas (it signs with the same session key).
   */
  get wasClient(): WASRemoteStore['was'] | undefined {
    return this._remoteStore?.was
  }

  /**
   * The remote Space URL, or undefined when there is no remote backend.
   */
  get spaceUrl(): string | undefined {
    return this._remoteStore?.spaceUrl
  }

  /**
   * The world-readable URL the user's published did:web document resolves to,
   * or undefined when there is no remote backend. (Whether a document has
   * actually been published is a separate `profile.didWeb` check.)
   */
  get publishedDidUrl(): string | undefined {
    return this._remoteStore?.didDocumentUrl()
  }

  /**
   * The remote WAS store, or undefined when there is no remote backend. Exposed
   * for the did:webvh rotation ceremony (`rotateWebvhUpdateKey`), which reads
   * and rewrites the `id` collection's `did.jsonl` / `keys.json` / `did.json`
   * directly through it.
   */
  get remoteStore(): WASRemoteStore | undefined {
    return this._remoteStore
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
    return this._localStore.rxCollection(logicalKey)
  }

  /**
   * The delegated session capability for writes to a WAS collection, or
   * `undefined` in the full tier (root invocations). The sync controller
   * attaches this to the sync port's requests.
   *
   * @param collectionId {string}   the WAS collection id (e.g. `wallet-activity`)
   * @returns {IZcap | undefined}
   */
  collectionCapability(collectionId: string): IZcap | undefined {
    return this._remoteStore?.sessionCapabilityFor({
      collectionId,
      write: true
    })
  }

  /**
   * Builds the per-collection document ciphers for the encrypted standard
   * collections from a session's key material (the vault KAK and its
   * resolver).
   */
  private static async _buildCiphers({
    keyAgreementKey,
    keyResolver
  }: {
    keyAgreementKey: IKeyAgreementKey
    keyResolver: IKeyResolver
  }) {
    const cipherEntries = await Promise.all(
      WALLET_STANDARD_COLLECTIONS.filter(({ encryption }) => encryption).map(
        async ({ key, id }) => [
          key,
          await createEdvDocCipher({
            keyAgreementKey,
            keyResolver,
            collectionId: id
          })
        ]
      )
    )
    return Object.fromEntries(cipherEntries)
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

    // One document cipher per encrypted collection, built from the session's
    // passphrase-derived key material (guests included -- their random secret
    // encrypts just as well; it is merely unrecoverable after logout, like the
    // rest of a guest session). The local store holds EDV envelopes for these
    // collections and replication ships them verbatim. (Restored delegated
    // sessions initialize via `initDelegatedStorageClients` instead.)
    const { keyAgreementKey, keyResolver } = profile
    if (!keyAgreementKey || !keyResolver) {
      throw new Error('A full session profile requires the key material.')
    }
    const ciphers = await StorageManager._buildCiphers({
      keyAgreementKey,
      keyResolver
    })

    // The local store is always the active replica.
    const { localStore } = await BrowserStore.initClient({ user, ciphers })
    let userExists = await localStore.userExists()

    let remoteStore
    if (storageServerUrl) {
      ;({ remoteStore } = await WASRemoteStore.initClient({
        storageServerUrl,
        user,
        profile
      }))
      // A returning user may be on a fresh browser (no local db yet) but have
      // an existing remote Space.
      userExists = userExists || (await remoteStore.userExists())
    }
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      remoteDirect
    })
    return { storage, userExists }
  }

  /**
   * Initializes storage for a restored (`delegated` tier) session: the remote
   * store invokes the persisted delegated capabilities instead of root
   * capabilities. When the session vault envelope yielded the vault KAK
   * (`vaultKeys`), the local store opens with the document ciphers and the
   * vault is unlocked exactly as in a full session; without it the local
   * store opens cipher-less and the vault stays locked -- encrypted
   * collections are unreadable and unwritable until re-login, while envelope
   * replication still works (it moves opaque stored bodies verbatim and never
   * needs keys).
   *
   * @param options {object}
   * @param options.user {User}
   * @param options.zcapClient {ZcapClient}   signs with the session key
   * @param options.spaceId {string}
   * @param options.sessionCapabilities {SessionCapabilities}
   * @param [options.vaultKeys] {object}   the vault KAK and its resolver,
   *   recovered from the session vault envelope (absent = locked vault)
   * @returns {Promise<{ storage: StorageManager }>}
   */
  static async initDelegatedStorageClients({
    user,
    zcapClient,
    spaceId,
    sessionCapabilities,
    vaultKeys
  }: {
    user: User
    zcapClient: ZcapClient
    spaceId: string
    sessionCapabilities: SessionCapabilities
    vaultKeys?: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  }) {
    if (!WAS_SERVER_URL) {
      throw new Error('A delegated session requires a remote WAS server.')
    }
    const ciphers = vaultKeys
      ? await StorageManager._buildCiphers(vaultKeys)
      : undefined
    const { localStore } = await BrowserStore.initClient({ user, ciphers })
    const remoteStore = new WASRemoteStore({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient,
      spaceId,
      controller: user.id,
      sessionCapabilities
    })
    const storage = new StorageManager({
      localStore,
      remoteStore,
      vaultLocked: !vaultKeys,
      ciphers
    })
    return { storage }
  }

  /**
   * Stores a credential and, when a row was actually inserted (a re-add of a
   * stored credential is a no-op), records its Create history entry. Routes to
   * the remote WAS `private-credentials` collection in effective remote-direct
   * mode (the CHAPI popup), otherwise to the local active replica.
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
    this._requireUnlockedVault()
    // The credential's content cid is its page-facing identity (idempotence,
    // routes, history); the store encrypts the VC into an EDV envelope keyed by
    // a content-derived envelope-hash id. Locally this envelope replicates to
    // the remote `private-credentials` collection; in remote-direct mode it is
    // written straight there.
    const cid = await cidFrom({ doc: credential })
    const inserted = this._effectiveRemoteDirect
      ? await this._addCredentialRemote({ cid, credential })
      : await this._localStore.addCredential({ cid, credential })
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
    if (this._vaultLocked) {
      return []
    }
    if (this._effectiveRemoteDirect) {
      const entries = await this._remoteCredentialEntries()
      const seen = new Set<string>()
      const credentials: StoredCredential[] = []
      for (const { cid, vc } of entries) {
        if (seen.has(cid)) {
          continue
        }
        seen.add(cid)
        credentials.push({ cid, vc })
      }
      return credentials
    }
    return await this._localStore.listCredentials()
  }

  async loadCredential({
    cid
  }: {
    cid: string
  }): Promise<IVerifiableCredential | undefined> {
    if (this._vaultLocked) {
      return undefined
    }
    if (this._effectiveRemoteDirect) {
      const entries = await this._remoteCredentialEntries()
      return entries.find(entry => entry.cid === cid)?.vc
    }
    return await this._localStore.loadCredential({ cid })
  }

  /**
   * Reads every resource of the remote `private-credentials` collection and
   * resolves each to its content cid + decrypted VC, mirroring
   * `BrowserStore._credentialEntries` (decrypt envelope rows, pass legacy
   * plaintext rows through keyed by their resource id). The per-resource GETs
   * run in parallel. Order is whatever the WAS listing returns (best-effort);
   * dedupe keys on the content cid, so ordering only affects which duplicate
   * copy wins, not correctness. Remote-direct mode only.
   *
   * @returns {Promise<Array<{ resourceId: string; cid: string;
   *   vc: IVerifiableCredential }>>}
   */
  private async _remoteCredentialEntries(): Promise<
    Array<{ resourceId: string; cid: string; vc: IVerifiableCredential }>
  > {
    const remote = this._remoteStore!
    const cipher = this._ciphers?.privateCredentials
    const resources = await remote.listSyncedResources({
      logicalKey: 'privateCredentials'
    })
    const bodies = await Promise.all(
      resources.map(({ id }) =>
        remote.getSyncedResource({
          logicalKey: 'privateCredentials',
          resourceId: id
        })
      )
    )
    const entries: Array<{
      resourceId: string
      cid: string
      vc: IVerifiableCredential
    }> = []
    for (let index = 0; index < resources.length; index++) {
      const data = bodies[index]
      if (data === undefined) {
        continue
      }
      const { id: resourceId } = resources[index]
      if (cipher && isEncryptedEnvelope(data)) {
        try {
          const vc = (await cipher.decrypt({
            envelope: data
          })) as unknown as IVerifiableCredential
          entries.push({ resourceId, cid: await cidFrom({ doc: vc }), vc })
        } catch (err) {
          // One undecryptable remote row must not brick the whole popup list
          // (mirrors the local store's tolerant read path).
          console.warn(
            `Skipping undecryptable remote private-credentials resource ` +
              `"${resourceId}":`,
            err
          )
        }
      } else {
        entries.push({
          resourceId,
          cid: resourceId,
          vc: data as unknown as IVerifiableCredential
        })
      }
    }
    return entries
  }

  /**
   * Adds a credential to the remote `private-credentials` collection: dedupe by
   * content cid against the remote contents, then encrypt into an EDV envelope
   * and PUT it under its content-derived envelope-hash id (`If-None-Match: *`).
   * Returns whether a row was actually written. Remote-direct mode only.
   *
   * @param options {object}
   * @param options.cid {string}
   * @param options.credential {IVerifiableCredential}
   * @returns {Promise<boolean>}
   */
  private async _addCredentialRemote({
    cid,
    credential
  }: {
    cid: string
    credential: IVerifiableCredential
  }): Promise<boolean> {
    const cipher = this._ciphers?.privateCredentials
    if (!cipher) {
      throw new Error(
        'Remote-direct credential storage requires the private-credentials ' +
          'cipher (an unlocked vault).'
      )
    }
    const entries = await this._remoteCredentialEntries()
    if (entries.some(entry => entry.cid === cid)) {
      return false
    }
    const { id, envelope } = await cipher.encrypt({
      data: credential as unknown as Json
    })
    const { created } = await this._remoteStore!.putSyncedResource({
      logicalKey: 'privateCredentials',
      resourceId: id,
      body: envelope
    })
    return created
  }

  async deleteCredential({ cid }: { cid: string }) {
    await this._localStore.deleteCredential({ cid })
  }

  /**
   * The count of local `private-credentials` rows the most recent
   * {@link listCredentials} read had to skip because their envelope would not
   * decrypt under the current vault KAK (corrupted, or written under a
   * mismatched KAK). Zero when the vault is locked (that read returns nothing).
   * Surfaced so the dashboard can warn the user without one bad row bricking
   * the list.
   *
   * @returns {number}
   */
  get undecryptableCredentials(): number {
    return this._localStore.undecryptableCredentials
  }

  /**
   * Removes the local `private-credentials` rows that could not be decrypted,
   * so the user can clear rows that can never be shown. Returns the number of
   * rows removed. No-op with the vault locked (nothing is undecryptable there;
   * locked rows are left intact).
   *
   * @returns {Promise<number>}
   */
  async purgeUndecryptableCredentials(): Promise<number> {
    if (this._vaultLocked) {
      return 0
    }
    return await this._localStore.purgeUndecryptableCredentials()
  }

  async wipeStorage() {
    // Remote first: if the remote wipe fails, the error surfaces while the
    // local data (and session) are still intact.
    if (this._remoteStore) {
      await this._remoteStore.wipeStorage()
    }
    await this._localStore.wipeStorage()
  }

  /**
   * Closes the local database without removing data. Called on logout.
   *
   * @returns {Promise<void>}
   */
  async close() {
    await this._localStore.close()
  }

  async getSpaceQuotas(): Promise<SpaceQuotaReport | null> {
    if (!this._remoteStore) {
      return null
    }
    return await this._remoteStore.getSpaceQuotas()
  }

  async exportSpace(): Promise<ReadableStream<Uint8Array>> {
    if (!this._remoteStore) {
      throw new Error('Remote storage is not configured for this session.')
    }
    return await this._remoteStore.exportSpace()
  }

  async importSpace({
    tarFile
  }: {
    tarFile: File
  }): Promise<ImportSpaceSummary> {
    if (!this._remoteStore) {
      throw new Error('Remote storage is not configured for this session.')
    }
    return await this._remoteStore.importSpace({ tarFile })
  }

  async listCollections(): Promise<Array<StorageCollection>> {
    if (!this._remoteStore) {
      return []
    }
    return await this._remoteStore.listCollections()
  }

  async listCollectionResources({
    collectionUrl
  }: {
    collectionUrl: string
  }): Promise<Array<StorageResource>> {
    if (!this._remoteStore) {
      return []
    }
    return await this._remoteStore.listCollectionResources({ collectionUrl })
  }

  async fetchCollectionResource(
    resource: StorageResource
  ): Promise<FetchedCollectionResource> {
    if (!this._remoteStore) {
      throw new Error('Remote storage is not configured for this session.')
    }
    return await this._remoteStore.fetchCollectionResource(resource)
  }

  /**
   * Best-effort decryption of a fetched storage-browser resource body: when
   * the body is an EDV envelope from one of the encrypted standard
   * collections and this session holds that collection's cipher (unlocked
   * vault), returns the decrypted document. Returns undefined otherwise --
   * plaintext bodies, non-standard collections, a locked vault, or an
   * envelope that fails to decrypt (logged, not thrown), letting callers fall
   * back to showing the raw envelope.
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
    const cipher = entry && this._ciphers?.[entry.key]
    if (!cipher) {
      return undefined
    }
    try {
      return await cipher.decrypt({ envelope: data })
    } catch (err) {
      console.warn(
        `Could not decrypt resource envelope from collection ` +
          `"${collectionId}":`,
        err
      )
      return undefined
    }
  }

  async deleteCollectionResource(resource: StorageResource): Promise<void> {
    if (!this._remoteStore) {
      throw new Error('Remote storage is not configured for this session.')
    }
    await this._remoteStore.deleteCollectionResource({
      relativeUrl: resource.url
    })
  }

  /**
   * Provisions an arbitrary plaintext collection on the remote WAS Space, for
   * a relying party's delegated capability. No local counterpart -- RP
   * collections are the RP's data, reached only over its zcap. Requires a
   * remote backend (full tier). With `isPublic`, the collection also gets a
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
    if (!this._remoteStore) {
      throw new Error('Provisioning a collection requires remote storage.')
    }
    await this._remoteStore.ensureCollection({ id, name, isPublic })
  }

  async deleteCollection({ id }: { id: string }): Promise<void> {
    if (!this._remoteStore) {
      throw new Error('Deleting a collection requires remote storage.')
    }
    await this._remoteStore.deleteCollection({ id })
  }

  async ensureUserCollections({
    user,
    profile
  }: {
    user: User
    profile?: ControllerProfile
  }) {
    await this._localStore.ensureUserCollections({ user })
    // Re-key any plaintext rows a pre-encryption version of the app left in
    // the (now encrypted) local collections. Runs before login completes --
    // and so before background replication starts -- because the remote
    // collections reject plaintext pushes once their encryption marker is set.
    await this._localStore.migrateLocalPlaintextDocs()
    // Re-key any `public-credentials` rows left under the pre-fix CID formula.
    // Runs regardless of vault state -- public rows are plaintext -- and before
    // replication so the tombstone and the re-keyed row reach the remote
    // collection.
    await this._localStore.migratePublicCredentialCids()
    if (this._remoteStore) {
      await this._remoteStore.ensureUserCollections({ user })
      // Provision and publish the user's did:web DID (full tier only -- a
      // delegated session holds no keystore agent and restores `didWeb` from
      // its record instead). Runs here, after the Space and `id` collection
      // exist. Non-fatal like keystore provisioning: a KMS/WAS hiccup must not
      // fail login; the settings page surfaces the unprovisioned state, and
      // the idempotent flow resumes on the next full login.
      if (profile?.keystoreAgent) {
        try {
          const did = didWebFromSpace({
            wasServerUrl: this._remoteStore.storageServerUrl,
            spaceId: this._remoteStore.spaceId
          })
          const keys = await ensureDidWeb({
            keystoreAgent: profile.keystoreAgent,
            remoteStore: this._remoteStore,
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
                remoteStore: this._remoteStore,
                wasServerUrl: this._remoteStore.storageServerUrl,
                spaceId: this._remoteStore.spaceId,
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
   * shared tail of every `addHistory*` method. With the vault locked (a
   * restored delegated session) the entry is skipped: the collection is
   * encrypted and there is no cipher, and losing a log line beats failing
   * the action that produced it.
   *
   * @param options {object}
   * @param options.resourceId {string}
   * @param options.activity {WalletActivity}
   * @returns {Promise<void>}
   */
  private async _addHistoryItem({
    resourceId,
    activity
  }: {
    resourceId: string
    activity: WalletActivity
  }) {
    if (this._vaultLocked) {
      console.warn('Vault locked; skipping wallet-activity entry.')
      return
    }
    if (this._effectiveRemoteDirect) {
      await this._addHistoryItemRemote({ activity })
      return
    }
    await this._localStore.addHistoryItem({ resourceId, activity })
  }

  /**
   * Writes one activity straight to the remote `wallet-activity` collection:
   * encrypt into an EDV envelope and PUT it under its content-derived
   * envelope-hash id. The caller's `resourceId` lives on only as the activity's
   * own `id` inside the encrypted document (mirroring the local store).
   * Remote-direct mode only.
   *
   * @param options {object}
   * @param options.activity {WalletActivity}
   * @returns {Promise<void>}
   */
  private async _addHistoryItemRemote({
    activity
  }: {
    activity: WalletActivity
  }) {
    const cipher = this._ciphers?.walletActivity
    if (!cipher) {
      throw new Error(
        'Remote-direct history storage requires the wallet-activity cipher ' +
          '(an unlocked vault).'
      )
    }
    const { id, envelope } = await cipher.encrypt({ data: activity as Json })
    await this._remoteStore!.putSyncedResource({
      logicalKey: 'walletActivity',
      resourceId: id,
      body: envelope
    })
  }

  /**
   * Records (in the `wallet-activity` collection) the Create activity for
   * the bootstrap did:key DID.
   */
  async addHistoryNewAccount({ user }: { user: User }) {
    const resourceId = uuidv7()
    await this._addHistoryItem({
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
    const remote = this._remoteStore
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
    await this._addHistoryItem({
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
  private async _addCredentialActivity({
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
    await this._addHistoryItem({
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
    await this._addCredentialActivity({
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
    await this._addCredentialActivity({
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
    await this._addCredentialActivity({
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
    await this._addCredentialActivity({
      cid,
      user,
      type: 'Unshare',
      verb: 'unshared'
    })
  }

  /**
   * Records (in the `wallet-activity` collection) a Login activity: the user
   * logged in to a relying party via "Login with Wallet", granting the listed
   * capabilities. The recorded zcap ids are the hook for a future revocation
   * UI (the WAS server has no Space-side revocation endpoint yet, so grants
   * are expiry-only for now).
   *
   * @param options {object}
   * @param options.user {User}
   * @param options.origin {string}   the relying party's origin
   * @param options.grants {Array<{ id: string; target: string;
   *   allowedActions: string[]; expires: string }>}
   * @returns {Promise<void>}
   */
  async addHistoryLogin({
    user,
    origin,
    grants
  }: {
    user: User
    origin: string
    grants: Array<{
      id: string
      target: string
      allowedActions: string[]
      expires: string
    }>
  }) {
    const resourceId = uuidv7()
    await this._addHistoryItem({
      resourceId,
      activity: {
        id: resourceId,
        type: ['Login'],
        summary: `Logged in to ${origin} with wallet.`,
        actor: { email: user.email },
        object: { origin, zcaps: grants },
        created: new Date().toISOString()
      }
    })
  }

  /**
   * Whether public links (sharing) are available this session. A public link
   * only means something as a world-readable URL on the remote WAS server, so
   * sharing requires a remote replica to be configured.
   */
  get canShare(): boolean {
    return !!this._remoteStore
  }

  /**
   * The public URL a credential would resolve to once shared, or `undefined`
   * when there is no remote backend.
   */
  publicLinkUrl({ cid }: { cid: string }): string | undefined {
    return this._remoteStore?.publicCredentialUrl(cid)
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
    if (!this._remoteStore) {
      throw new Error('Public links require remote storage.')
    }
    const cid = await cidFrom({ doc: credential })
    await this._localStore.addPublicCredential({ cid, credential })
    return this._remoteStore.publicCredentialUrl(cid)
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
    await this._localStore.removePublicCredential({ cid })
  }

  async isShared({ cid }: { cid: string }): Promise<boolean> {
    return await this._localStore.hasPublicCredential({ cid })
  }

  /**
   * Lists the items in the `wallet-activity` history collection.
   */
  async listHistoryItems(): Promise<
    Array<{ id: string; doc: WalletActivity }>
  > {
    if (this._vaultLocked) {
      return []
    }
    return await this._localStore.listHistoryItems()
  }
}
