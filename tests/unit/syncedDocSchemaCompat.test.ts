/**
 * The local replica's schema is browser-local stored state, not a code detail:
 * RxDB hashes a collection's declared schema and refuses to open an existing
 * replica whose stored hash differs at the same `version`. Freewallet's replica
 * predates the move of the schema into `@interop/was-sync`, so this pins that
 * the package's `syncedDocSchema()` is the shape this wallet already stored --
 * a remembered browser keeps its replica, with no forget-and-log-in-again.
 *
 * The legacy shape below is the literal freewallet declared before the move
 * (`src/lib/sync/syncedDocSchema.ts`). It stays inlined here: reading it from
 * the package would compare the package with itself.
 */
import { describe, expect, it } from 'vitest'
import { createRxDatabase, type RxJsonSchema } from 'rxdb/plugins/core'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import { syncedDocSchema, type SyncedDoc } from '@interop/was-sync'

const legacySyncedDocSchema = {
  version: 0,
  primaryKey: 'id',
  type: 'object',
  properties: {
    id: { type: 'string', maxLength: 256 },
    updatedAt: { type: 'string', maxLength: 64 },
    version: { type: 'number' },
    metaVersion: { type: 'number' },
    createdBy: { type: 'string', maxLength: 256 },
    epoch: { type: 'string', maxLength: 256 },
    data: { type: 'object', additionalProperties: true },
    custom: { type: 'object', additionalProperties: true }
  },
  required: ['id', 'updatedAt', 'version'],
  indexes: ['updatedAt']
} as unknown as RxJsonSchema<SyncedDoc>

describe('the synced-doc schema across the move into @interop/was-sync', () => {
  it('re-opens a replica created under the previous schema', async () => {
    // One storage instance across both opens, so the second open meets the
    // first's stored schema hash the way a returning browser does.
    const storage = getRxStorageMemory()
    const before = await createRxDatabase({
      name: 'schema-compat-db',
      storage,
      multiInstance: false
    })
    await before.addCollections({
      privateCredentials: { schema: legacySyncedDocSchema }
    })
    await before.close()

    const after = await createRxDatabase({
      name: 'schema-compat-db',
      storage,
      multiInstance: false
    })
    // A differing shape raises RxDB's DB6 here; opening cleanly is the claim.
    await after.addCollections({
      privateCredentials: {
        schema: syncedDocSchema() as unknown as RxJsonSchema<SyncedDoc>
      }
    })
    expect(after.collections.privateCredentials).toBeDefined()
    await after.close()
  })
})
