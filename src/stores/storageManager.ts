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

export interface IStorageManager {
  addCredential: ({
    credential
  }: {
    credential: IVerifiableCredential
  }) => Promise<void>
  listCredentials: () => Promise<Array<StoredCredential>>
  wipeStorage: ({ profile }: { profile: ControllerProfile }) => Promise<void>
}

export class StorageManager implements IStorageManager {
  public localStore: BrowserStore
  public remoteStore?: WASRemoteStore

  constructor({
    localStore,
    remoteStore
  }: {
    localStore: BrowserStore
    remoteStore?: WASRemoteStore
  }) {
    this.localStore = localStore
    this.remoteStore = remoteStore
  }

  static async initStorage({
    user,
    profile
  }: {
    user: User
    profile: ControllerProfile
  }) {
    const serverUrl = WAS_SERVER_URL
    const { localStore } = await BrowserStore.initStore({ user })
    let remoteStore
    if (serverUrl) {
      ;({ remoteStore } = await WASRemoteStore.initStore({
        serverUrl,
        user,
        profile
      }))
    }
    const storage = new StorageManager({ localStore, remoteStore })
    return { storage }
  }

  async addCredential({ credential }: { credential: IVerifiableCredential }) {
    await this.localStore.addCredential({ credential })
  }
  async wipeStorage({ profile }: { profile: ControllerProfile }) {
    await this.localStore.wipeStorage()
    await this.remoteStore?.wipeStorage({ profile })
  }
  async listCredentials(): Promise<Array<StoredCredential>> {
    const vcs = await this.localStore.listCredentials()
    return vcs.map(vc => vc as StoredCredential)
  }
}

/**
 * @see https://digitalcredentials.github.io/wallet-attached-storage-spec/
 * @see https://github.com/interop-alliance/zcap-developer-guide
 */
export class WASRemoteStore implements IStorageManager {
  public spaceUrl: string

  constructor({ spaceUrl }: { spaceUrl: string }) {
    this.spaceUrl = spaceUrl
  }

  static async initStore({
    serverUrl,
    user,
    profile
  }: {
    serverUrl: string
    user: User
    profile: ControllerProfile
  }) {
    const body = {
      name: 'Freewallet Space',
      controller: user.id
    }
    const spaceId = await cidFrom({ doc: body })
    const spaceUrl = new URL(`/space/${spaceId}`, serverUrl).toString()
    try {
      await profile.zcapClient.request({
        url: spaceUrl,
        method: 'PUT',
        json: body
      })
    } catch (e: any) {
      console.error('Error creating space:', JSON.stringify(e.data, null, 2))
    }
    const remoteStore = new WASRemoteStore({ spaceUrl })
    return { remoteStore }
  }

  async addCredential({ credential }: { credential: IVerifiableCredential }) {
    console.log(credential)
  }

  async listCredentials() {
    return []
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
export class BrowserStore implements IStorageManager {
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
   *
   * @param credential {IVerifiableCredential}
   */
  async addCredential({ credential }: { credential: IVerifiableCredential }) {
    await this.db.credentials.insertIfNotExists({
      cid: await cidFrom({ doc: credential }),
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
