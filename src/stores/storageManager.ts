import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { createRxDatabase, type RxDatabase } from 'rxdb/plugins/core'
import { getRxStorageDexie } from 'rxdb/plugins/storage-dexie'
import type { User } from '@/types/auth'
import { cidFrom } from '@/lib/cidFrom'

/**
 * Temporary schema for storing VCs as JSON blobs.
 */
export const VcBlobSchema = {
  version: 0,
  primaryKey: 'cid',
  type: 'object',
  properties: {
    cid: { type: 'string', maxLength: 128 },
    doc: { type: 'object', additionalProperties: true }
  },
  required: ['cid']
}

/**
 * Exploratory storage wrapper for Verifiable Credential
 * storage. Currently only storing VCs locally, using IndexDB (via Dexie.js),
 * will add replication next.
 */
export class StorageManager {
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
  static async initStorage({ user }: { user: User }) {
    const { db, dbName } = await dbInstance({ user })
    // addCollections is an idempotent operation
    await db.addCollections({
      credentials: {
        schema: VcBlobSchema
      }
    })
    const storage = new StorageManager({ db, dbName })
    return { storage }
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
      doc: { ...credential }
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
  async clearStorage() {
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
