/**
 * Storage layer for the wallet. StorageManager is the single facade used by
 * all pages. The local BrowserStore (RxDB/IndexedDB) is always the ACTIVE
 * replica: every credential, public-link, and history read/write targets it
 * unconditionally, online or offline, guest or not. When VITE_WAS_SERVER_URL
 * is set (and the session is not a guest), a WASRemoteStore is also attached --
 * not as a primary store, but as a remote replica: the sync controller
 * replicates the local collections to it in the background, and the storage
 * browser / export / import / quota pages read through it directly.
 */
import type { IVerifiableCredential, IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import type { RxCollection } from 'rxdb/plugins/core'
import type { ControllerProfile, User } from '@/types/auth'
import { cidFrom } from '@/lib/cidFrom'
import { WALLET_STANDARD_COLLECTIONS, WAS_SERVER_URL } from '@/app.config'
import { createEdvDocCipher } from '@/stores/edvDocCipher'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import type { SyncedDoc } from '@/lib/sync'
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

  constructor({
    localStore,
    remoteStore,
    vaultLocked = false
  }: {
    localStore: BrowserStore
    remoteStore?: WASRemoteStore
    vaultLocked?: boolean
  }) {
    this._localStore = localStore
    this._remoteStore = remoteStore
    this._vaultLocked = vaultLocked
  }

  /**
   * Whether the encrypted collections are locked: true in a restored
   * (`delegated` tier) session, where the passphrase-derived KAK is absent.
   * Locked reads return nothing rather than raw envelopes; locked writes
   * throw rather than store plaintext into an encrypted collection.
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

  static async initStorageClients({
    user,
    profile,
    isGuest = false
  }: {
    user: User
    profile: ControllerProfile
    isGuest?: boolean
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
    // sessions, which have no KAK, initialize via
    // `initDelegatedStorageClients` instead.)
    const { keyAgreementKey, keyResolver } = profile
    if (!keyAgreementKey || !keyResolver) {
      throw new Error('A full session profile requires the key material.')
    }
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
    const ciphers = Object.fromEntries(cipherEntries)

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
    const storage = new StorageManager({ localStore, remoteStore })
    return { storage, userExists }
  }

  /**
   * Initializes storage for a restored (`delegated` tier) session: the local
   * store opens without ciphers (the vault stays locked -- encrypted
   * collections are unreadable and unwritable until re-login) and the remote
   * store invokes the persisted delegated capabilities instead of root
   * capabilities. Envelope replication still works: it moves opaque stored
   * bodies verbatim and never needs keys.
   *
   * @param options {object}
   * @param options.user {User}
   * @param options.zcapClient {ZcapClient}   signs with the session key
   * @param options.spaceId {string}
   * @param options.sessionCapabilities {SessionCapabilities}
   * @returns {Promise<{ storage: StorageManager }>}
   */
  static async initDelegatedStorageClients({
    user,
    zcapClient,
    spaceId,
    sessionCapabilities
  }: {
    user: User
    zcapClient: ZcapClient
    spaceId: string
    sessionCapabilities: SessionCapabilities
  }) {
    if (!WAS_SERVER_URL) {
      throw new Error('A delegated session requires a remote WAS server.')
    }
    const { localStore } = await BrowserStore.initClient({ user })
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
      vaultLocked: true
    })
    return { storage }
  }

  async addCredential({ credential }: { credential: IVerifiableCredential }) {
    this._requireUnlockedVault()
    // The credential's content cid is its page-facing identity (idempotence,
    // routes, history); the local store encrypts the VC into an EDV envelope
    // keyed by a content-derived envelope-hash id, and replication mirrors
    // that envelope to the remote `private-credentials` collection.
    const cid = await cidFrom({ doc: credential })
    await this._localStore.addCredential({ cid, credential })
  }

  async listCredentials(): Promise<Array<StoredCredential>> {
    if (this._vaultLocked) {
      return []
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
    return await this._localStore.loadCredential({ cid })
  }

  async deleteCredential({ cid }: { cid: string }) {
    await this._localStore.deleteCredential({ cid })
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

  async deleteCollectionResource(resource: StorageResource): Promise<void> {
    if (!this._remoteStore) {
      throw new Error('Remote storage is not configured for this session.')
    }
    await this._remoteStore.deleteCollectionResource({
      relativeUrl: resource.url
    })
  }

  async ensureUserCollections({ user }: { user: User }) {
    await this._localStore.ensureUserCollections({ user })
    // Re-key any plaintext rows a pre-encryption version of the app left in
    // the (now encrypted) local collections. Runs before login completes --
    // and so before background replication starts -- because the remote
    // collections reject plaintext pushes once their encryption marker is set.
    await this._localStore.migrateLocalPlaintextDocs()
    if (this._remoteStore) {
      await this._remoteStore.ensureUserCollections({ user })
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
    await this._localStore.addHistoryItem({ resourceId, activity })
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
    await this._addHistoryItem({
      resourceId,
      activity: {
        id: resourceId,
        type: ['Create'],
        summary: 'Credential created: ' + cid,
        actor: { email: user.email },
        object: cid,
        created: new Date().toISOString()
      }
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
    const resourceId = uuidv7()
    await this._addHistoryItem({
      resourceId,
      activity: {
        id: resourceId,
        type: ['Delete'],
        summary: 'Credential deleted: ' + cid,
        actor: { email: user.email },
        object: cid,
        created: new Date().toISOString()
      }
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
    const resourceId = uuidv7()
    await this._addHistoryItem({
      resourceId,
      activity: {
        id: resourceId,
        type: ['Share'],
        summary: 'Credential shared: ' + cid,
        actor: { email: user.email },
        object: cid,
        created: new Date().toISOString()
      }
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
    const resourceId = uuidv7()
    await this._addHistoryItem({
      resourceId,
      activity: {
        id: resourceId,
        type: ['Unshare'],
        summary: 'Credential unshared: ' + cid,
        actor: { email: user.email },
        object: cid,
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
