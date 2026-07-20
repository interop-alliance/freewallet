/**
 * The single generic RxDB JSON schema reused across every synced collection.
 * One shape (`{ id, updatedAt, version, metaVersion?, createdBy?, epoch?, data?,
 * custom? }`) carries both a content revision and an independently-versioned
 * metadata sub-resource; `_deleted` is added by RxDB via `deletedField`.
 * `data` / `custom` are opaque bodies (plaintext JSON, or an EDV envelope on an
 * encrypted collection), so they are typed as free-form objects. `createdBy` is
 * the server-managed creator DID carried down from the `changes` feed. `epoch`
 * is the opaque key-epoch id the resource's envelope was encrypted under (absent
 * = pre-epoch, encrypted directly to the vault key), also carried down the feed.
 *
 * Bumping this schema (adding `createdBy` at `version: 1`, `epoch` at
 * `version: 2`) requires the RxDB migration-schema plugin, so it is registered
 * here as an import side effect -- this module is the shared dependency of every
 * RxDB open in the app, so any consumer that reaches for the schema also gets
 * the plugin. `addRxPlugin` is idempotent, so registering once at module load is
 * safe.
 */
import {
  addRxPlugin,
  type MigrationStrategies,
  type RxJsonSchema
} from 'rxdb/plugins/core'
import { RxDBMigrationSchemaPlugin } from 'rxdb/plugins/migration-schema'
import type { SyncedDoc } from './types.js'

addRxPlugin(RxDBMigrationSchemaPlugin)

/**
 * Returns the synced-doc schema. `id` is the primary key (the WAS resourceId);
 * `updatedAt` is indexed because it is the change-feed sort field / checkpoint
 * component.
 *
 * @returns {RxJsonSchema<SyncedDoc>}
 */
export function syncedDocSchema(): RxJsonSchema<SyncedDoc> {
  return {
    version: 2,
    primaryKey: 'id',
    type: 'object',
    properties: {
      id: { type: 'string', maxLength: 256 },
      updatedAt: { type: 'string', maxLength: 64 },
      version: { type: 'number' },
      metaVersion: { type: 'number' },
      // The server-managed creator DID (a `did:key`), absent when unrecorded.
      createdBy: { type: 'string', maxLength: 256 },
      // The opaque key-epoch id the envelope was encrypted under, absent when
      // pre-epoch (encrypted directly to the vault key). Not indexed.
      epoch: { type: 'string', maxLength: 256 },
      // Opaque stored bodies -- content and metadata envelopes -- moved verbatim.
      data: { type: 'object', additionalProperties: true },
      custom: { type: 'object', additionalProperties: true }
    },
    required: ['id', 'updatedAt', 'version'],
    indexes: ['updatedAt']
  } as RxJsonSchema<SyncedDoc>
}

/**
 * The migration strategies for {@link syncedDocSchema}, passed to
 * `addCollections` alongside the schema. The `version: 0` to `version: 1` bump
 * only adds the optional `createdBy` field, and `version: 1` to `version: 2`
 * only adds the optional `epoch` field, so an existing document migrates
 * unchanged -- leaving the new field undefined ("not recorded" / "pre-epoch") is
 * correct.
 *
 * @returns {MigrationStrategies}
 */
export function syncedDocMigrationStrategies(): MigrationStrategies {
  return {
    1: (oldDoc: SyncedDoc) => oldDoc,
    2: (oldDoc: SyncedDoc) => oldDoc
  }
}
