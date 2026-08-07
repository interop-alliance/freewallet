/**
 * Public surface of the collection-agnostic WAS replication adapter. Framework-
 * and Freewallet-agnostic: consumers supply an RxDB collection and a
 * {@link WasSyncPort}; nothing here imports React or `@interop/was-client`.
 */
export { createWasReplication } from './wasReplication.js'
export {
  syncedDocSchema,
  syncedDocMigrationStrategies
} from './syncedDocSchema.js'
export {
  type Json,
  type SyncCheckpoint,
  type SyncedDoc,
  type WasSyncPort
} from './types.js'
