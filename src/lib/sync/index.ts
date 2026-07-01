/**
 * Public surface of the collection-agnostic WAS replication adapter. Framework-
 * and Freewallet-agnostic: consumers supply an RxDB collection and a
 * {@link WasSyncPort}; nothing here imports React or `@interop/was-client`.
 */
export { createWasReplication } from './wasReplication.js'
export { syncedDocSchema } from './syncedDocSchema.js'
export { createPullHandler, wireDocToRxDoc } from './changesQuery.js'
export { createPushHandler, formatEtag } from './pushWrites.js'
export {
  WasSyncConflictError,
  type Json,
  type SyncCheckpoint,
  type WireDoc,
  type SyncedDoc,
  type MasterState,
  type WasSyncPort
} from './types.js'
