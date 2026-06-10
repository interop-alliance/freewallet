/**
 * Storage layer for the wallet. StorageManager is the single facade used by
 * all pages; it delegates to BrowserStore (local RxDB/IndexedDB, credentials
 * only) or WASRemoteStore (remote WAS server via ZCap-signed HTTP, full
 * Space/Collection/Resource support) depending on whether VITE_WAS_SERVER_URL
 * is set. The two backends are mutually exclusive.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { ControllerProfile, User } from '@/types/auth'
import { cidFrom } from '@/lib/cidFrom'
import { WAS_SERVER_URL } from '@/app.config'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import type { FetchedCollectionResource } from '@/lib/storageResource'
import type { StoredCredential } from '@/types/credential'
import { BrowserStore } from '@/stores/browserStore'
import { WASRemoteStore } from '@/stores/wasRemoteStore'
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

/**
 * The shared contract implemented by both storage backends (BrowserStore and
 * WASRemoteStore). Optional members are only meaningful for the remote backend.
 */
export interface IWalletStore {
  userExists: () => Promise<boolean>
  addCredential: ({
    cid,
    credential
  }: {
    cid: string
    credential: IVerifiableCredential
  }) => Promise<void>
  listCredentials: () => Promise<Array<StoredCredential>>
  wipeStorage: () => Promise<void>
  listCollections?: () => Promise<Array<StorageCollection>>
  listCollectionResources?: ({
    collectionUrl
  }: {
    collectionUrl: string
  }) => Promise<Array<StorageResource>>
  exportSpace?: () => Promise<ReadableStream<Uint8Array>>
  importSpace?: ({ tarFile }: { tarFile: File }) => Promise<ImportSpaceSummary>
}

export type ImportSpaceSummary = {
  collectionsCreated: number
  collectionsSkipped: number
  resourcesCreated: number
  resourcesSkipped: number
}

/**
 * Manages local and remote storage operations for the wallet and a logged-in
 * user profile.
 */
export class StorageManager {
  private _localStore?: BrowserStore
  private _remoteStore?: WASRemoteStore // Only set if VITE_WAS_SERVER_URL env var is present
  public remoteOnly: boolean

  constructor({
    localStore,
    remoteStore,
    remoteOnly = false
  }: {
    localStore?: BrowserStore
    remoteStore?: WASRemoteStore
    remoteOnly: boolean
  }) {
    this._localStore = localStore
    this._remoteStore = remoteStore
    this.remoteOnly = remoteOnly
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
   * The remote Space URL, or undefined when there is no remote backend.
   */
  get spaceUrl(): string | undefined {
    return this._remoteStore?.spaceUrl
  }

  static async initStorageClients({
    user,
    profile
  }: {
    user: User
    profile: ControllerProfile
  }) {
    const storageServerUrl = WAS_SERVER_URL
    console.log('Initializing remote storage clients:', { storageServerUrl })
    const remoteOnly = !!storageServerUrl
    let remoteStore, localStore
    let userExists = false
    // For the moment, localStore and remoteStore are mutually exclusive

    if (!remoteOnly) {
      ;({ localStore } = await BrowserStore.initClient({ user }))
      userExists = await localStore.userExists()
    }

    if (storageServerUrl) {
      ;({ remoteStore } = await WASRemoteStore.initClient({
        storageServerUrl,
        user,
        profile
      }))
      userExists = await remoteStore.userExists()
    }
    const storage = new StorageManager({ localStore, remoteStore, remoteOnly })
    return { storage, userExists }
  }

  async addCredential({ credential }: { credential: IVerifiableCredential }) {
    const cid = await cidFrom({ doc: credential })
    if (!this.remoteOnly) {
      await this._localStore!.addCredential({ cid, credential })
    }
    if (this._remoteStore) {
      await this._remoteStore.addCredential({ cid, credential })
    }
  }

  async wipeStorage() {
    if (!this.remoteOnly) {
      await this._localStore!.wipeStorage()
    }
    if (this._remoteStore) {
      await this._remoteStore.wipeStorage()
    }
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
    if (!this.remoteOnly) {
      await this._localStore!.ensureUserCollections({ user })
    }
    if (this._remoteStore) {
      await this._remoteStore.ensureUserCollections({ user })
    }
  }

  /**
   * Records (in the `wallet-activity` collection) the Create activity for
   * the bootstrap did:key DID.
   */
  async addHistoryNewAccount({ user }: { user: User }) {
    // Skip recording history item for local storage for now
    if (!this._remoteStore) {
      return
    }
    const resourceId = uuidv7()
    await this._remoteStore.addCollectionResource({
      resourceId,
      collectionId: 'walletActivity',
      resourceBody: {
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
   * the space and various collections created.
   */
  async addHistorySpaceCreated({ user }: { user: User }) {
    if (!this._remoteStore) {
      return
    }
    const resourceId = uuidv7()
    await this._remoteStore.addCollectionResource({
      resourceId,
      collectionId: 'walletActivity',
      resourceBody: {
        id: resourceId,
        type: ['Create'],
        summary:
          'Account space created on remote storage server, collections initialized.',
        actor: user.id,
        object: [
          {
            type: ['Space'],
            id: this._remoteStore.spaceUrl
          },
          {
            type: ['Collection'],
            id: this._remoteStore.collectionUrl('privateCredentials')
          },
          {
            type: ['Collection'],
            id: this._remoteStore.collectionUrl('publicCredentials')
          },
          {
            type: ['Collection'],
            id: this._remoteStore.collectionUrl('walletActivity')
          }
        ],
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
    if (!this._remoteStore) {
      return
    }
    const resourceId = uuidv7()
    await this._remoteStore.addCollectionResource({
      resourceId,
      collectionId: 'walletActivity',
      resourceBody: {
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
    if (!this._remoteStore) {
      return
    }
    const resourceId = uuidv7()
    await this._remoteStore.addCollectionResource({
      resourceId,
      collectionId: 'walletActivity',
      resourceBody: {
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
    if (!this._remoteStore) {
      return
    }
    const resourceId = uuidv7()
    await this._remoteStore.addCollectionResource({
      resourceId,
      collectionId: 'walletActivity',
      resourceBody: {
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
    if (!this._remoteStore) {
      return
    }
    const resourceId = uuidv7()
    await this._remoteStore.addCollectionResource({
      resourceId,
      collectionId: 'walletActivity',
      resourceBody: {
        id: resourceId,
        type: ['Unshare'],
        summary: 'Credential unshared: ' + cid,
        actor: { email: user.email },
        object: cid,
        created: new Date().toISOString()
      }
    })
  }

  async listCredentials(): Promise<Array<StoredCredential>> {
    let vcs: Array<StoredCredential> = []
    if (!this.remoteOnly) {
      vcs = await this._localStore!.listCredentials()
    }
    if (this._remoteStore) {
      vcs = await this._remoteStore.listCredentials()
    }
    return vcs.map(vc => vc as StoredCredential)
  }

  async loadCredential({
    cid
  }: {
    cid: string
  }): Promise<IVerifiableCredential | undefined> {
    let vc: IVerifiableCredential | undefined
    if (!this.remoteOnly) {
      vc = await this._localStore!.loadCredential({ cid })
    }
    if (this._remoteStore) {
      vc = await this._remoteStore.loadCredential({ cid })
    }
    return vc
  }

  async deleteCredential({ cid }: { cid: string }) {
    if (!this.remoteOnly) {
      await this._localStore!.deleteCredential({ cid })
    }
    if (this._remoteStore) {
      await this._remoteStore.deleteCredential({ cid })
    }
  }

  /**
   * Whether public links (sharing) are available this session. Sharing relies
   * on the remote WAS server's access-control policies, so it's only possible
   * with a remote backend.
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
   *
   * @param cid {string}
   * @returns {Promise<string>}
   */
  async createPublicLink({ cid }: { cid: string }): Promise<string> {
    if (!this._remoteStore) {
      throw new Error('Public links require remote storage.')
    }
    const credential = await this._remoteStore.loadCredential({ cid })
    if (!credential) {
      throw new Error(`Credential "${cid}" not found.`)
    }
    return await this._remoteStore.createPublicLink({ cid, credential })
  }

  async removePublicLink({ cid }: { cid: string }): Promise<void> {
    if (!this._remoteStore) {
      throw new Error('Public links require remote storage.')
    }
    await this._remoteStore.removePublicLink({ cid })
  }

  async isShared({ cid }: { cid: string }): Promise<boolean> {
    if (!this._remoteStore) {
      return false
    }
    return await this._remoteStore.isShared({ cid })
  }

  /**
   * Lists the items in the `wallet-activity` history collection. Returns an
   * empty array when there is no remote backend.
   */
  async listHistoryItems(): Promise<
    Array<{ id: string; doc: WalletActivity }>
  > {
    if (!this._remoteStore) {
      return []
    }
    return await this._remoteStore.listHistoryItems()
  }
}
