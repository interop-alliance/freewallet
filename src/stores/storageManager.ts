import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { createRxDatabase, type RxDatabase } from 'rxdb/plugins/core'
import { getRxStorageDexie } from 'rxdb/plugins/storage-dexie'
import type { ControllerProfile, User } from '@/types/auth'
import { bufferToBase64Url, cidFrom, digestHash } from '@/lib/cidFrom'
import { WAS_SERVER_URL } from '@/app.config'
import {
  type StoredCredential,
  StoredCredentialSchema
} from '@/types/credential'
import type { ZcapClient } from '@digitalcredentials/ezcap'

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

  async ensureUserCollections({ user }: { user: User }) {
    if (!this.remoteOnly) {
      await this.localStore!.ensureUserCollections({ user })
    }
    if (this.remoteStore) {
      await this.remoteStore.ensureUserCollections({ user })
    }
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

export interface ICollectionsSet {
  credentials: {
    url: string
  }
}

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
  public collections: ICollectionsSet

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
    this.collections = {
      credentials: { url: '' }
    }
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
    const spaceDescription = {
      name: 'Freewallet Space',
      controller: user.id
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
    }

    // Space created, now create collections
    const vcCollectionUrl = new URL(
      `/space/${spaceId}/private-credentials`,
      storageServerUrl
    ).toString()

    const collectionDescription = {
      id: 'private-credentials',
      name: 'Verifiable Credentials',
      type: ['Collection']
    }

    try {
      await zcapClient.request({
        url: vcCollectionUrl,
        method: 'PUT',
        json: collectionDescription
      })
    } catch (e: any) {
      console.error(
        'Error creating collection:',
        JSON.stringify(e.data, null, 2)
      )
    }
    const vcCollectionBaseUrl = `${vcCollectionUrl}/` // ensure trailing slash

    this.collections.credentials = {
      url: vcCollectionBaseUrl
    }
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
    const controller = user.id
    const spaceId = bufferToBase64Url(await digestHash(controller))
    const remoteStore = new WASRemoteStore({
      storageServerUrl,
      zcapClient: profile.zcapClient,
      spaceId,
      controller
    })

    return { remoteStore }
  }

  async addCredential({
    cid,
    credential
  }: {
    cid: string
    credential: IVerifiableCredential
  }) {
    const vcCollectionBaseUrl = this.collections.credentials.url
    const vcUrl = new URL(cid, vcCollectionBaseUrl).toString()
    try {
      await this.zcapClient.request({
        url: vcUrl,
        method: 'PUT',
        json: credential
      })
    } catch (e: any) {
      console.log('Attempted to add credential to:', vcUrl)
      console.error('Error adding credential:', JSON.stringify(e.data, null, 2))
    }
  }

  async listCredentials() {
    const vcCollectionBaseUrl = this.collections.credentials.url
    let response
    try {
      response = await this.zcapClient.request({
        url: vcCollectionBaseUrl,
        method: 'GET'
      })
    } catch (e: any) {
      console.log('Attempted to list credentials:', vcCollectionBaseUrl)
      console.error(
        'Error listing credentials:',
        JSON.stringify(e.data, null, 2)
      )
    }
    // @ts-expect-error TODO add a type to the response
    const { data } = response!
    console.log('Fetched credentials list:', data)
    // data looks like: { offset: 0, total_rows, rows: [{ id, url, contentType }] }

    return this.fetchAll({ rows: data.rows })
  }

  async loadCredential({ cid }: { cid: string }) {
    const vcCollectionBaseUrl = this.collections.credentials.url
    const vcUrl = new URL(cid, vcCollectionBaseUrl).toString()
    const doc: IVerifiableCredential | undefined = await this.fetchDocument({
      objectUrl: vcUrl
    })
    return doc
  }

  async deleteCredential({ cid }: { cid: string }) {
    const vcCollectionBaseUrl = this.collections.credentials.url
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

  async fetchAll({ rows }: { rows: any[] }) {
    const docs = await Promise.all(
      rows.map(collectionRow => this.fetchRow({ collectionRow }))
    )
    return docs.map(({ id, doc }) => {
      return { cid: id, vc: doc }
    })
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
      console.log('Attempted to add credential to:', objectUrl)
      console.error('Error adding credential:', JSON.stringify(e.data, null, 2))
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
     * Add a global singleton workaround, to fix the "duplicate database" error.
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
    console.log('Initialed user collections in', dbName, 'user:', user.id)
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
