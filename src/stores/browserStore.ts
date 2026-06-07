/**
 * BrowserStore: local-only storage backend using RxDB over Dexie/IndexedDB.
 * Stores credentials only (no Spaces/Collections/Resources). Used by
 * StorageManager when VITE_WAS_SERVER_URL is not set.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { createRxDatabase, type RxDatabase } from 'rxdb/plugins/core'
import { getRxStorageDexie } from 'rxdb/plugins/storage-dexie'
import type { User } from '@/types/auth'
import { bufferToBase64Url, digestHash } from '@/lib/cidFrom'
import { StoredCredentialSchema } from '@/types/credential'
import type { IWalletStore } from '@/stores/storageManager'

declare global {
  /**
   * Global singleton used to work around RxDB's "duplicate database" error
   * across hot reloads / repeated logins. See `BrowserStore.dbInstanceFor`.
   */
  var __rxdb_instance__: RxDatabase | null | undefined
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
    if (globalThis.__rxdb_instance__) {
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
