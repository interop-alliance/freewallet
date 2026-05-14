import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import type { ZcapClient } from '@digitalcredentials/ezcap'
import { createRxDatabase, type RxDatabase } from 'rxdb/plugins/core'
import { getRxStorageDexie } from 'rxdb/plugins/storage-dexie'
import type { ControllerProfile, User } from '@/types/auth'
import { bufferToBase64Url, cidFrom, digestHash } from '@/lib/cidFrom'
import { WAS_SERVER_URL } from '@/app.config'
import type {
  StorageCollection,
  StorageCollectionList,
  StorageResource,
  StorageResourceList
} from '@/lib/storage'
import {
  type StoredCredential,
  StoredCredentialSchema
} from '@/types/credential'
import { uuidv7 } from 'uuidv7'

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
  wipeStorage: ({ profile }: { profile: ControllerProfile }) => Promise<void>
  listCollections?: () => Promise<Array<StorageCollection>>
  listCollectionResources?: ({
    collectionUrl
  }: {
    collectionUrl: string
  }) => Promise<Array<StorageResource>>
  exportSpace?: () => Promise<ReadableStream<Uint8Array>>
}

/**
 * Manages local and remote storage operations for the wallet and a logged-in
 * user profile.
 */
export class StorageManager {
  public localStore?: BrowserStore
  public remoteStore?: WASRemoteStore // Only set if VITE_WAS_SERVER_URL env var is present
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
    this.localStore = localStore
    this.remoteStore = remoteStore
    this.remoteOnly = remoteOnly
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
      await this.localStore!.addCredential({ cid, credential })
    }
    if (this.remoteStore) {
      await this.remoteStore.addCredential({ cid, credential })
    }
  }

  async wipeStorage({ profile }: { profile: ControllerProfile }) {
    if (!this.remoteOnly) {
      await this.localStore!.wipeStorage()
    }
    if (this.remoteStore) {
      await this.remoteStore.wipeStorage({ profile })
    }
  }

  async exportSpace(): Promise<ReadableStream<Uint8Array>> {
    if (!this.remoteStore) {
      throw new Error('Remote storage is not configured for this session.')
    }
    return await this.remoteStore.exportSpace()
  }

  async listCollections(): Promise<Array<StorageCollection>> {
    if (!this.remoteStore) {
      return []
    }
    return await this.remoteStore.listCollections()
  }

  async listCollectionResources({
    collectionUrl
  }: {
    collectionUrl: string
  }): Promise<Array<StorageResource>> {
    if (!this.remoteStore) {
      return []
    }
    return await this.remoteStore.listCollectionResources({ collectionUrl })
  }

  async ensureUserCollections({ user }: { user: User }) {
    if (!this.remoteOnly) {
      await this.localStore!.ensureUserCollections({ user })
    }
    if (this.remoteStore) {
      await this.remoteStore.ensureUserCollections({ user })
    }
  }

  /**
   * Records (in the `wallet-activity` collection) the Create activity for
   * the bootstrap did:key DID.
   */
  async addHistoryNewAccount({ user }: { user: User }) {
    // Skip recording history item for local storage for now
    if (!this.remoteStore) {
      return
    }
    const resourceId = uuidv7()
    await this.remoteStore.addCollectionResource({
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
    if (!this.remoteStore) {
      return
    }
    const resourceId = uuidv7()
    await this.remoteStore.addCollectionResource({
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
            id: this.remoteStore.spaceUrl
          },
          {
            type: ['Collection'],
            id: this.remoteStore.collections!.get('privateCredentials')!.url
          },
          {
            type: ['Collection'],
            id: this.remoteStore.collections!.get('publicCredentials')!.url
          },
          {
            type: ['Collection'],
            id: this.remoteStore.collections!.get('walletActivity')!.url
          }
        ],
        created: new Date().toISOString()
      }
    })
  }

  async listCredentials(): Promise<Array<StoredCredential>> {
    let vcs: Array<StoredCredential> = []
    if (!this.remoteOnly) {
      vcs = await this.localStore!.listCredentials()
    }
    if (this.remoteStore) {
      vcs = await this.remoteStore.listCredentials()
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
      vc = await this.localStore!.loadCredential({ cid })
    }
    if (this.remoteStore) {
      vc = await this.remoteStore.loadCredential({ cid })
    }
    return vc
  }

  async deleteCredential({ cid }: { cid: string }) {
    if (!this.remoteOnly) {
      await this.localStore!.deleteCredential({ cid })
    }
    if (this.remoteStore) {
      await this.remoteStore.deleteCredential({ cid })
    }
  }
}

export type ICollectionsSet = Map<string, { url: string }>

/**
 * @see https://digitalcredentials.github.io/wallet-attached-storage-spec/
 * @see https://github.com/interop-alliance/zcap-developer-guide
 */
export class WASRemoteStore implements IWalletStore {
  public storageServerUrl: string
  public zcapClient: ZcapClient
  public spaceId: string
  public controller: string

  public spaceUrl: string
  public collections?: ICollectionsSet

  constructor({
    storageServerUrl,
    zcapClient,
    spaceId,
    controller
  }: {
    storageServerUrl: string
    zcapClient: ZcapClient
    spaceId: string
    controller: string
  }) {
    this.storageServerUrl = storageServerUrl
    this.zcapClient = zcapClient
    this.spaceId = spaceId
    this.controller = controller
    this.spaceUrl = new URL(`/space/${spaceId}`, storageServerUrl).toString()
  }

  async userExists() {
    try {
      await this.zcapClient.request({
        url: this.spaceUrl,
        method: 'GET'
      })
    } catch (_: any) {
      return false
    }
    return true
  }

  async ensureUserCollections({ user }: { user: User }) {
    const { storageServerUrl, zcapClient } = this

    // Create Space for this user on remote storage server
    const spaceDescription = {
      name: 'Freewallet Space',
      controller: this.controller
    }
    const { spaceId } = this
    const spaceUrl = new URL(`/space/${spaceId}`, storageServerUrl).toString()
    try {
      await zcapClient.request({
        url: spaceUrl,
        method: 'PUT',
        json: spaceDescription
      })
    } catch (e: any) {
      console.error('Error creating space:', JSON.stringify(e.data, null, 2))
      throw new Error(
        `Error creating space for user "${user.id}" at "${spaceUrl}": ${JSON.stringify(e.data)}`
      )
    }

    // Space created, now create collections
    const { url: vcPrivateCollection } = await this.createCollection({
      spaceId,
      collectionId: 'private-credentials',
      name: 'Verifiable Credentials'
    })

    const { url: vcPublicCollection } = await this.createCollection({
      spaceId,
      collectionId: 'public-credentials',
      name: 'Publicly Shared Verifiable Credentials'
    })

    const { url: walletActivityLog } = await this.createCollection({
      spaceId,
      collectionId: 'wallet-activity',
      name: 'Wallet Activity Log'
    })

    this.collections = new Map([
      ['privateCredentials', { url: vcPrivateCollection }],
      ['publicCredentials', { url: vcPublicCollection }],
      ['walletActivity', { url: walletActivityLog }]
    ])
  }

  async createCollection({
    spaceId,
    collectionId,
    name
  }: {
    spaceId: string
    collectionId: string
    name: string
  }) {
    const { storageServerUrl, zcapClient } = this
    const collectionUrl = new URL(
      `/space/${spaceId}/${collectionId}`,
      storageServerUrl
    ).toString()
    const collectionDescription = {
      id: collectionId,
      name,
      type: ['Collection']
    }
    try {
      await zcapClient.request({
        url: collectionUrl,
        method: 'PUT',
        json: collectionDescription
      })
    } catch (e: any) {
      console.error(
        `Error creating collection "${collectionId}":`,
        JSON.stringify(e.data, null, 2)
      )
      throw new Error(
        `Error creating collection "${collectionId}" at "${collectionUrl}": ${JSON.stringify(e.data)}`
      )
    }
    const collectionBaseUrl = `${collectionUrl}/` // ensure trailing slash
    return { url: collectionBaseUrl }
  }

  static async initClient({
    storageServerUrl,
    user,
    profile
  }: {
    storageServerUrl: string
    user: User
    profile: ControllerProfile
  }) {
    const controller = profile.keyAgent.id || user.id
    const spaceId = bufferToBase64Url(await digestHash(controller))
    const remoteStore = new WASRemoteStore({
      storageServerUrl,
      zcapClient: profile.zcapClient,
      spaceId,
      controller
    })

    return { remoteStore }
  }

  async addCollectionResource({
    resourceId,
    collectionId,
    resourceBody
  }: {
    resourceId: string
    collectionId: string
    resourceBody: any
  }) {
    const collectionBaseUrl = this.collections!.get(collectionId)!.url
    const resourceUrl = new URL(resourceId, collectionBaseUrl).toString()
    try {
      await this.zcapClient.request({
        url: resourceUrl,
        method: 'PUT',
        json: resourceBody
      })
    } catch (e: any) {
      console.log('Attempted to add resource to:', resourceUrl)
      console.error('Error adding resource:', JSON.stringify(e.data, null, 2))
    }
  }

  async addCredential({
    cid,
    credential
  }: {
    cid: string
    credential: IVerifiableCredential
  }) {
    return await this.addCollectionResource({
      resourceId: cid,
      collectionId: 'privateCredentials',
      resourceBody: credential
    })
  }

  async listCollectionItems({ url }: { url: string }) {
    let response
    try {
      response = await this.zcapClient.request({
        url: new URL(url, this.storageServerUrl).toString(),
        method: 'GET'
      })
    } catch (err: any) {
      console.log('Attempted to list collection items from:', url)
      console.error(
        'Error listing collection items:',
        JSON.stringify(err.data, null, 2)
      )
    }
    // @ts-expect-error TODO add a type to the response
    const { data } = response!
    // data looks like:
    // { id, url, name, type, totalItems, items: [{ id, url, contentType }] }
    return await this.fetchAll({ rows: data.items })
  }

  async listCollectionResources({
    collectionUrl
  }: {
    collectionUrl: string
  }): Promise<Array<StorageResource>> {
    const collectionListUrl = collectionUrl.endsWith('/')
      ? collectionUrl
      : `${collectionUrl}/`
    const url = new URL(collectionListUrl, this.storageServerUrl).toString()
    let response
    try {
      response = await this.zcapClient.request({
        url,
        method: 'GET',
        headers: {
          accept: 'application/json'
        }
      })
    } catch (err: any) {
      console.log('Attempted to list collection resources from:', url)
      console.error(
        'Error listing collection resources:',
        JSON.stringify(err.data, null, 2)
      )
      throw new Error('Failed to list remote storage collection resources.')
    }

    const { data } = response as { data?: StorageResourceList }
    return data?.items ?? []
  }

  async listCollections(): Promise<Array<StorageCollection>> {
    const collectionsUrl = new URL(
      `/space/${this.spaceId}/collections/`,
      this.storageServerUrl
    ).toString()
    let response
    try {
      response = await this.zcapClient.request({
        url: collectionsUrl,
        method: 'GET',
        headers: {
          accept: 'application/json'
        }
      })
    } catch (err: any) {
      console.error(
        'Error listing collections:',
        JSON.stringify(err.data, null, 2)
      )
      throw new Error('Failed to list remote storage collections.')
    }

    const { data } = response as { data?: StorageCollectionList }
    return data?.items ?? []
  }

  async listHistoryItems(): Promise<Array<{ id: string; doc: any }>> {
    const walletActivityUrl = this.collections!.get('walletActivity')!.url
    return await this.listCollectionItems({ url: walletActivityUrl })
  }

  async listCredentials() {
    const vcCollectionBaseUrl = this.collections!.get('privateCredentials')!.url
    const docs = await this.listCollectionItems({ url: vcCollectionBaseUrl })
    return docs.map(({ id, doc }) => {
      return { cid: id, vc: doc }
    })
  }

  async loadCredential({ cid }: { cid: string }) {
    const vcCollectionBaseUrl = this.collections!.get('privateCredentials')!.url
    const vcUrl = new URL(cid, vcCollectionBaseUrl).toString()
    const doc: IVerifiableCredential | undefined = await this.fetchDocument({
      objectUrl: vcUrl
    })
    return doc
  }

  async deleteCredential({ cid }: { cid: string }) {
    const vcCollectionBaseUrl = this.collections!.get('privateCredentials')!.url
    const vcUrl = new URL(cid, vcCollectionBaseUrl).toString()
    try {
      await this.zcapClient.request({
        url: vcUrl,
        method: 'DELETE'
      })
    } catch (e: any) {
      console.log('Attempted to delete credential:', vcUrl)
      console.error(
        'Error deleting credential:',
        JSON.stringify(e.data, null, 2)
      )
    }
  }

  /**
   * Fetches all documents from the rows of a list collection result.
   */
  async fetchAll({
    rows
  }: {
    rows: any[]
  }): Promise<Array<{ id: string; doc: any }>> {
    return await Promise.all(
      rows.map(collectionRow => this.fetchRow({ collectionRow }))
    )
  }

  async fetchRow({ collectionRow }: { collectionRow: any }) {
    const { id, url: relativeUrl, contentType } = collectionRow
    const doc: any | undefined = await this.fetchDocument({
      relativeUrl,
      contentType
    })
    return { id, doc }
  }

  /**
   * Fetches a document from the remote storage server, returns undefined if
   * not found.
   */
  async fetchDocument({
    objectUrl,
    relativeUrl,
    contentType = 'application/json'
  }: {
    objectUrl?: string
    relativeUrl?: string
    contentType?: string
  }): Promise<any | undefined> {
    const { storageServerUrl } = this
    if (relativeUrl && !objectUrl) {
      objectUrl = new URL(relativeUrl, storageServerUrl).toString()
    }
    let headers
    if (contentType) {
      headers = { accept: contentType }
    }
    let result
    try {
      result = await this.zcapClient.request({
        url: objectUrl,
        method: 'GET',
        headers
      })
    } catch (e: any) {
      console.log('Attempted to fetch document:', objectUrl)
      console.error('Error fetching:', JSON.stringify(e.data, null, 2))
      return
    }
    // @ts-expect-error TODO add a type to the response
    return result!.data
  }

  async wipeStorage({ profile }: { profile: ControllerProfile }) {
    try {
      await profile.zcapClient.request({
        url: this.spaceUrl,
        method: 'DELETE'
      })
    } catch (e: any) {
      console.error('Error deleting space:', JSON.stringify(e.data, null, 2))
    }
    console.log('Remote space deleted.')
  }

  async exportSpace(): Promise<ReadableStream<Uint8Array>> {
    const exportUrl = new URL(
      `/space/${this.spaceId}/export`,
      this.storageServerUrl
    ).toString()

    let response
    try {
      // `parseBody: false` preserves the raw Response so we can stream bytes.
      response = await (this.zcapClient.request as any)({
        url: exportUrl,
        method: 'POST',
        parseBody: false,
        headers: { accept: 'application/x-tar' }
      })
    } catch (e: any) {
      console.error('Error exporting space:', JSON.stringify(e.data, null, 2))
      throw new Error('Failed to export remote space.')
    }

    if (!response || !(response instanceof Response) || !response.body) {
      throw new Error('Unexpected export response format from storage server.')
    }

    return response.body
  }
}

/**
 * Exploratory storage wrapper for Verifiable Credential
 * storage. Currently only storing VCs locally, using IndexDB (via Dexie.js),
 * will add replication next.
 */
export class BrowserStore implements IWalletStore {
  public dbPrefix: string
  public db?: RxDatabase
  public dbName?: string

  constructor({ dbPrefix }: { dbPrefix: string }) {
    this.dbPrefix = dbPrefix
  }

  async userExists() {
    const databases = await indexedDB.databases()
    return databases.some(db => db.name!.includes(this.dbPrefix))
  }

  /**
   * @see https://rxdb.info/rx-storage-dexie.html
   * @param user {User}
   */
  static async initClient({ user }: { user: User }) {
    // Local DBs will have a prefix of <hash of user.id>
    const dbPrefix = bufferToBase64Url(await digestHash(user.id))

    const localStore = new BrowserStore({ dbPrefix })
    return { localStore }
  }

  static async dbInstanceFor({ dbPrefix }: { dbPrefix: string }) {
    const dbName = `${dbPrefix}-credentials-db`
    let db
    /**
     * Add a global singleton workaround to fix the "duplicate database" error.
     */
    // @ts-expect-error Suppress implicit any
    if (globalThis.__rxdb_instance__) {
      // @ts-expect-error Suppress implicit any
      db = globalThis.__rxdb_instance__
    } else {
      db = await createRxDatabase({
        name: dbName,
        storage: getRxStorageDexie(),
        closeDuplicates: true
      })
    }
    // addCollections is an idempotent operation and will be called on Login also
    await db.addCollections({
      credentials: {
        schema: StoredCredentialSchema
      }
    })
    return { db, dbName }
  }

  async ensureUserCollections({ user }: { user: User }) {
    const { dbPrefix } = this
    const { db, dbName } = await BrowserStore.dbInstanceFor({ dbPrefix })
    console.log('Initialized user collections in', dbName, 'user:', user.id)
    this.db = db
    this.dbName = dbName
  }

  /**
   * Adds a VC to session storage. Note the `insertIfNotExists()` logic.
   * @see https://rxdb.info/rx-collection.html#insertifnotexists
   */
  async addCredential({
    cid,
    credential
  }: {
    cid: string
    credential: IVerifiableCredential
  }) {
    await this.db!.credentials.insertIfNotExists({
      cid,
      vc: { ...credential }
    })
  }

  async loadCredential({ cid }: { cid: string }) {
    const doc = await this.db!.credentials.findOne({ selector: { cid } }).exec()
    if (doc) {
      return doc.vc
    } else {
      return undefined
    }
  }

  async deleteCredential({ cid }: { cid: string }) {
    const doc = await this.db!.credentials.findOne({ selector: { cid } }).exec()
    if (doc) {
      await doc.remove()
    }
  }

  /**
   * Lists available VCs in session storage.
   * @see https://rxdb.info/rx-collection.html#find
   *
   * @returns {Array<{ cid, doc }>} List of JSON docs (that match VcBlobSchema)
   */
  async listCredentials() {
    return await this.db!.credentials.find().exec()
  }

  /**
   * @see https://rxdb.info/rx-database.html#remove
   */
  async wipeStorage() {
    // @ts-expect-error Suppress implicit any
    globalThis.__rxdb_instance__ = null
    await this.db!.remove()
    const databases = await indexedDB.databases()
    for (const db of databases) {
      if (db.name!.includes(this.dbName!)) {
        indexedDB.deleteDatabase(db.name!)
      }
    }
  }
}
