/**
 * Shared types for the collection-agnostic WAS replication adapter.
 *
 * The adapter drives an RxDB `replicateRxCollection` state machine against a
 * remote WAS Collection's replication endpoints. The wire model
 * (`Json` / `SyncCheckpoint` / `MasterState`) and the 412/404 conflict signals
 * (`WasSyncConflictError` / `WasSyncNotFoundError`) now come from
 * `@interop/was-client/sync`, so the port implementation and this driver agree
 * on one set of types and one error hierarchy.
 *
 * `WireDoc`, `SyncedDoc`, and `WasSyncPort` stay defined here as the driver's
 * own, stricter internal contract: the driver maps the opaque wire body into a
 * typed RxDB document, so it types `data` / `custom` as {@link Json} rather than
 * the library `ChangeDocument`'s `unknown`. The library port is bridged onto
 * this stricter `WasSyncPort` at the one construction site (`SyncController`).
 *
 * The wire contract is the WAS spec's `changes` query profile plus its V2
 * encrypted-metadata profile: a synced document carries both a content revision
 * (`version` / `data`) and an independently-versioned metadata sub-resource
 * (`metaVersion` / `custom`). A metadata-only edit re-surfaces the resource with
 * a bumped `updatedAt` / `metaVersion` but unchanged `version` / `data`. The
 * sync layer moves both bodies opaquely: `data` is the stored content body
 * (plaintext JSON, or the EDV envelope on an encrypted collection) and `custom`
 * is the stored metadata body (an opaque envelope on an encrypted collection);
 * encrypt/decrypt stays a read/write-time concern above this layer.
 */
import type {
  Json,
  SyncCheckpoint,
  MasterState
} from '@interop/was-client/sync'

export type { Json, SyncCheckpoint, MasterState }
export {
  WasSyncConflictError,
  WasSyncNotFoundError
} from '@interop/was-client/sync'

/**
 * One document as it travels on the `changes` feed wire
 * (`POST /space/:s/:c/query`, profile `changes`). `id` is the WAS resourceId,
 * `version` is the content master revision (feeds the content push `If-Match`
 * ETag) and the user content body is nested under `data`; `metaVersion` is the
 * independent metadata revision (feeds the `/meta` push `If-Match` ETag) and the
 * user-writable metadata body is under `custom`. A tombstone carries
 * `_deleted: true` with no `data`. `metaVersion` / `custom` are present only
 * once metadata has been written for the resource.
 *
 * `createdBy` is the server-managed `did:key` DID of whoever created the
 * resource. It is read-only (the server ignores any `createdBy` a client sends),
 * absent when no creator was recorded, and rides the feed on tombstones too, so
 * a delete replicates with its attribution intact.
 *
 * `epoch` is the key-epoch id the resource's envelope was encrypted under. It is
 * absent for a pre-epoch resource (encrypted directly to the vault key) and is
 * opaque to the sync layer -- it rides the feed verbatim so a replicating reader
 * can pick the right epoch key without a `/meta` fetch per resource.
 */
export interface WireDoc {
  id: string
  _deleted: boolean
  updatedAt: string
  version: number
  metaVersion?: number
  createdBy?: string
  epoch?: string
  data?: Json
  custom?: Json
}

/**
 * The local RxDB document shape, shared across every synced collection. The
 * envelope fields are top-level (`id` primary key, `updatedAt` the checkpoint
 * sort field, `version` / `metaVersion` the server master revisions); the user
 * bodies stay nested (`data` for content, `custom` for metadata) to avoid field
 * collisions. `_deleted` is managed by RxDB via `deletedField` and so is not
 * part of this "clean" shape (handlers work with RxDB's `WithDeleted<SyncedDoc>`).
 * `createdBy` is the server-managed creator `did:key` DID carried down from the
 * feed (absent when the server recorded no creator); it is persisted on the
 * schema at `version: 1`. `epoch` is the key-epoch id the resource's envelope was
 * encrypted under (absent = pre-epoch, encrypted directly to the vault key);
 * opaque to the sync layer and persisted on the schema at `version: 2`.
 */
export interface SyncedDoc {
  id: string
  updatedAt: string
  version: number
  metaVersion?: number
  createdBy?: string
  epoch?: string
  data?: Json
  custom?: Json
}

/**
 * The injected WAS-access seam the driver depends on. `createWasSyncPort` from
 * `@interop/was-client/sync` implements a structurally compatible port (its
 * writes additionally return the server-acked `version`, which the driver
 * ignores); it is bridged onto this stricter interface at the one construction
 * site. Every method moves the stored body verbatim -- no codec, no key handling
 * -- so the same port works for plaintext and encrypted collections alike.
 *
 * `putContent` / `deleteContent` / `putMeta` MUST throw
 * {@link WasSyncConflictError} when the server rejects a conditional write with
 * `412 precondition-failed`, and let every other error propagate so RxDB's
 * retry/backoff handles it.
 */
export interface WasSyncPort {
  /**
   * Pulls one page of the `changes` feed. Omit `checkpoint` for the first page.
   * Returns the page's `documents` and its resume `checkpoint`, or
   * `checkpoint: null` for an empty (no-change) page.
   *
   * @param options {object}
   * @param [options.checkpoint] {SyncCheckpoint}   resume position
   * @param options.limit {number}                  requested batch size
   * @returns {Promise<{ documents: WireDoc[], checkpoint: SyncCheckpoint | null }>}
   */
  query(options: { checkpoint?: SyncCheckpoint; limit: number }): Promise<{
    documents: WireDoc[]
    checkpoint: SyncCheckpoint | null
  }>

  /**
   * Conditionally writes the content body verbatim (`PUT /:id`). Pass
   * `ifNoneMatch: true` for a create-if-absent, or `ifMatch` (a quoted ETag over
   * the content `version`) for an update-if-unchanged. `epoch` is the opaque
   * key-epoch id the body was encrypted under, stamped on the resource by the
   * server (absent leaves the resource with no epoch stamp).
   *
   * @param options {object}
   * @param options.id {string}
   * @param options.data {Json}
   * @param [options.ifMatch] {string}
   * @param [options.ifNoneMatch] {boolean}
   * @param [options.epoch] {string}
   * @returns {Promise<void>}
   */
  putContent(options: {
    id: string
    data: Json
    ifMatch?: string
    ifNoneMatch?: boolean
    epoch?: string
  }): Promise<void>

  /**
   * Conditionally deletes a resource (writes a tombstone; `DELETE /:id`). Pass
   * `ifMatch` (a quoted ETag over the content `version`) to delete only if
   * unchanged.
   *
   * @param options {object}
   * @param options.id {string}
   * @param [options.ifMatch] {string}
   * @returns {Promise<void>}
   */
  deleteContent(options: { id: string; ifMatch?: string }): Promise<void>

  /**
   * Conditionally writes the metadata body verbatim (`PUT /:id/meta`, body
   * `{ custom }`). Pass `ifNoneMatch: true` when the resource has no metadata
   * yet, or `ifMatch` (a quoted ETag over `metaVersion`) for an
   * update-if-unchanged. The resource must already exist (the server does not
   * create a resource from a `/meta` write).
   *
   * @param options {object}
   * @param options.id {string}
   * @param options.custom {Json}
   * @param [options.ifMatch] {string}
   * @param [options.ifNoneMatch] {boolean}
   * @returns {Promise<void>}
   */
  putMeta(options: {
    id: string
    custom: Json
    ifMatch?: string
    ifNoneMatch?: boolean
  }): Promise<void>

  /**
   * Re-reads a single resource's current master state (content + metadata) for
   * the 412 conflict assembler. Returns `null` when the resource is genuinely
   * absent (a delete/delete race).
   *
   * @param options {object}
   * @param options.id {string}
   * @returns {Promise<MasterState | null>}
   */
  get(options: { id: string }): Promise<MasterState | null>
}
