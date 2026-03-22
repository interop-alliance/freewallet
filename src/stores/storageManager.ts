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
  primaryKey: 'id',
  type: 'object',
  properties: {
    id: { type: 'string', maxLength: 128 },
    data: { type: 'object', additionalProperties: true }
  },
  required: ['id']
}

/**
 * Exploratory storage wrapper for Verifiable Credential
 * storage. Currently only storing VCs locally, using IndexDB (via Dexie.js),
 * will add replication next.
 */
export class StorageManager {
  public db
  constructor({ db }: { db: RxDatabase }) {
    this.db = db
  }

  /**
   * @see https://rxdb.info/rx-storage-dexie.html
   * @param user {User}
   */
  static async initStorage({ user }: { user: User }) {
    const db = await createRxDatabase({
      name: `${user.id}-credentials-db`,
      storage: getRxStorageDexie()
    })
    await db.addCollections({
      credentials: {
        schema: VcBlobSchema
      }
    })
    const storage = new StorageManager({ db })
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
      id: await cidFrom({ doc: credential }),
      data: { ...credential }
    })
  }

  /**
   * Lists available VCs in session storage.
   * @see https://rxdb.info/rx-collection.html#find
   *
   * @returns {Array<{ id, data }>} List of JSON docs (that match VcBlobSchema)
   */
  async listCredentials() {
    return await this.db.credentials.find().exec()
  }
}
