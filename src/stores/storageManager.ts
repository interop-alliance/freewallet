import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { createRxDatabase, type RxDatabase } from 'rxdb/plugins/core'
import { getRxStorageDexie } from 'rxdb/plugins/storage-dexie'
import type { ControllerProfile, User } from '@/types/auth'
import { cidFrom } from '@/lib/cidFrom'
import { WAS_SERVER_URL } from '@/app.config'
import {
  type StoredCredential,
  StoredCredentialSchema
} from '@/types/credential'
import type { ZcapClient } from '@digitalcredentials/ezcap'

export interface IWalletStore {
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

  static async initStorage({
    user,
    profile
  }: {
    user: User
    profile: ControllerProfile
  }) {
    const storageServerUrl = WAS_SERVER_URL
    const remoteOnly = !!storageServerUrl
    let remoteStore, localStore

    if (!remoteOnly) {
      ;({ localStore } = await BrowserStore.initStore({ user }))
    }

    if (storageServerUrl) {
      ;({ remoteStore } = await WASRemoteStore.initStore({
        storageServerUrl,
        user,
        profile
      }))
    }
    const storage = new StorageManager({ localStore, remoteStore, remoteOnly })
    return { storage }
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
  public spaceUrl: string
  public zcapClient: ZcapClient
  public collections: ICollectionsSet

  constructor({
    storageServerUrl,
    spaceUrl,
    zcapClient
  }: {
    storageServerUrl: string
    spaceUrl: string
    zcapClient: ZcapClient
  }) {
    this.storageServerUrl = storageServerUrl
    this.spaceUrl = spaceUrl
    this.zcapClient = zcapClient
    this.collections = {
      credentials: { url: '' }
    }
  }

  static async initStore({
    storageServerUrl,
    user,
    profile
  }: {
    storageServerUrl: string
    user: User
    profile: ControllerProfile
  }) {
    const { zcapClient } = profile
    const spaceDescription = {
      name: 'Freewallet Space',
      controller: user.id
    }
    const spaceId = await cidFrom({ doc: spaceDescription })
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
    const remoteStore = new WASRemoteStore({
      storageServerUrl,
      spaceUrl,
      zcapClient
    })

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

    remoteStore.collections.credentials = {
      url: vcCollectionBaseUrl
    }

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
    const { data } = response!
    console.log('Fetched credentials list:', data)
    // data looks like: { offset: 0, total_rows, rows: [{ id, url, contentType }] }

    return this.fetchAll({ rows: data.rows })
  }

  async fetchAll({ rows }: { rows: any[] }) {
    const docs = await Promise.all(
      rows.map(collectionRow => this.fetchDocument({ collectionRow }))
    )
    return docs.map(({ id, doc }) => {
      return { cid: id, vc: doc }
    })
  }

  async fetchDocument({ collectionRow }: { collectionRow: any }) {
    const { storageServerUrl } = this
    const objectUrl = new URL(collectionRow.url, storageServerUrl).toString()
    let result
    try {
      result = await this.zcapClient.request({
        url: objectUrl,
        method: 'GET',
        headers: { accept: collectionRow.contentType }
      })
    } catch (e: any) {
      console.log('Attempted to add credential to:', vcUrl)
      console.error('Error adding credential:', JSON.stringify(e.data, null, 2))
    }
    return { id: collectionRow.id, doc: result!.data }
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
  public db
  public dbName
  constructor({ db, dbName }: { db: RxDatabase; dbName: string }) {
    this.db = db
    this.dbName = dbName
  }

  /**
   * @see https://rxdb.info/rx-storage-dexie.html
   * @param user {User}
   */
  static async initStore({ user }: { user: User }) {
    const { db, dbName } = await dbInstance({ user })
    // addCollections is an idempotent operation
    await db.addCollections({
      credentials: {
        schema: StoredCredentialSchema
      }
    })
    const localStore = new BrowserStore({ db, dbName })
    return { localStore }
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
    await this.db.credentials.insertIfNotExists({
      cid,
      vc: { ...credential }
    })
  }

  /**
   * Lists available VCs in session storage.
   * @see https://rxdb.info/rx-collection.html#find
   *
   * @returns {Array<{ cid, doc }>} List of JSON docs (that match VcBlobSchema)
   */
  async listCredentials() {
    return await this.db.credentials.find().exec()
  }

  /**
   * @see https://rxdb.info/rx-database.html#remove
   */
  async wipeStorage() {
    // @ts-expect-error Suppress implicit any
    globalThis.__rxdb_instance__ = null
    await this.db.remove()
    const databases = await indexedDB.databases()
    for (const db of databases) {
      if (db.name!.includes(this.dbName)) {
        indexedDB.deleteDatabase(db.name!)
      }
    }
  }
}

export function dbNameFor({ user }: { user: User }) {
  return `${user.id}-credentials-db`
}

export async function dbInstance({ user }: { user: User }) {
  const dbName = dbNameFor({ user })
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
      storage: getRxStorageDexie()
    })
  }
  return { db, dbName }
}
