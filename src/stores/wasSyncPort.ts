/**
 * The Freewallet-side seam between the generic sync adapter (`src/lib/sync/`)
 * and `@interop/was-client`. Implements the `WasSyncPort` interface for one
 * remote WAS Collection using the raw, signed `was.request()` escape hatch.
 *
 * Using `request()` (rather than the `Resource` / `Collection` handles) is
 * deliberate: it moves the stored body VERBATIM, bypassing the encryption codec.
 * The `changes` feed already ships opaque stored bodies (plaintext for a
 * plaintext collection, the EDV envelope for an encrypted one), and the push
 * side must write those same bytes back unchanged -- running them through
 * `resource.put()` would re-encrypt an already-encrypted envelope. Encrypt /
 * decrypt stays a read/write-time concern at the StorageManager layer; this port
 * is collection-agnostic and never touches keys.
 *
 * Conditional writes ride the server's monotonic `version` (content) and
 * `metaVersion` (metadata) ETags, which the reference server enforces uniformly
 * for plaintext and encrypted resources alike -- so there is no plaintext-vs-
 * encrypted fork here.
 */
import type { WasClient } from '@interop/was-client'
// Deep import (bypassing the `@/lib/sync` barrel) so this eagerly loaded
// module does not drag the barrel's RxDB replication machinery into the
// entry chunk; the heavy adapter is loaded on demand by the SyncController.
import {
  WasSyncConflictError,
  type Json,
  type MasterState,
  type SyncCheckpoint,
  type WasSyncPort,
  type WireDoc
} from '@/lib/sync/types.js'

/**
 * The request header the server reads the content write's key-epoch id from,
 * stamping it onto the Resource's metadata (an absent header clears any prior
 * stamp). Matches `@interop/was-client`'s internal `writeHeaders` emitter; not
 * exported as a constant there, so it is spelled out here.
 */
const WAS_KEY_EPOCH_HEADER = 'WAS-Key-Epoch'

/**
 * Extracts an HTTP status from a raw ky/ezcap error. `was.request()` rejects on
 * any non-2xx with `err.status` set (see `@interop/http-client`'s error
 * normaliser); this reads it defensively from either location.
 *
 * @param err {unknown}
 * @returns {number | undefined}
 */
export function errorStatus(err: unknown): number | undefined {
  return (
    (err as { status?: number }).status ??
    (err as { response?: { status?: number } }).response?.status
  )
}

/**
 * Parses a quoted strong ETag (`"3"`) into its numeric revision, or `undefined`
 * when the header is absent (the resource has no such revision yet).
 *
 * @param etag {string | null}
 * @returns {number | undefined}
 */
function parseEtag(etag: string | null): number | undefined {
  if (!etag) {
    return undefined
  }
  const revision = Number(etag.replace(/"/g, ''))
  return Number.isFinite(revision) ? revision : undefined
}

/**
 * Builds a `WasSyncPort` bound to a single Space + Collection on the remote WAS
 * server, backed by the session's signed `WasClient`.
 *
 * @param options {object}
 * @param options.was {WasClient}       the session client (holds the signer)
 * @param options.spaceId {string}
 * @param options.collectionId {string}   the WAS collection id (e.g. `public-credentials`)
 * @returns {WasSyncPort}
 */
export function createWasSyncPort({
  was,
  spaceId,
  collectionId
}: {
  was: WasClient
  spaceId: string
  collectionId: string
}): WasSyncPort {
  const collectionPath = `/space/${spaceId}/${collectionId}`
  const resourcePath = (id: string) =>
    `${collectionPath}/${encodeURIComponent(id)}`

  // The pull path rides the client's `Collection.changes()` feed API. The handle
  // is bound to the same space + collection the raw write paths use, so
  // `changes()` produces the byte-identical signed `POST /space/:s/:c/query`
  // (profile `changes`) the raw request did -- a root invocation. Construction
  // is I/O-free (the codec/feature probes are lazy thunks) and `changes()` never
  // resolves the codec, so unlike `get()` it does not decrypt: it ships the
  // stored bodies (plaintext or EDV envelope) verbatim, which is what this
  // codec-bypassing port requires. Writes stay on the raw `request()` escape
  // hatch so they too move bodies verbatim.
  const changesCollection = was.space(spaceId).collection(collectionId)

  /**
   * Builds the conditional-write headers from the port's precondition options.
   */
  const writeHeaders = ({
    ifMatch,
    ifNoneMatch
  }: {
    ifMatch?: string
    ifNoneMatch?: boolean
  }): Record<string, string> | undefined => {
    const headers: Record<string, string> = {}
    if (ifMatch !== undefined) {
      headers['if-match'] = ifMatch
    }
    if (ifNoneMatch) {
      headers['if-none-match'] = '*'
    }
    return Object.keys(headers).length > 0 ? headers : undefined
  }

  /**
   * Runs a conditional write, mapping the server's `412 precondition-failed`
   * into the core's `WasSyncConflictError` and letting all else propagate.
   */
  const conditionalWrite = async (
    run: () => Promise<unknown>
  ): Promise<void> => {
    try {
      await run()
    } catch (err) {
      if (errorStatus(err) === 412) {
        throw new WasSyncConflictError()
      }
      throw err
    }
  }

  return {
    async query({ checkpoint, limit }) {
      // `changes()` omits `checkpoint` from the request body when it is
      // `undefined` (the first pull), matching the old raw request. Its wire
      // documents (storage-core's `ChangeDocument`) are the same shape as
      // `WireDoc`, only more loosely typed (`data: unknown`), and carry the
      // server-managed `createdBy` and the opaque `epoch` key-epoch id through
      // verbatim; the cast narrows the static type without touching the runtime
      // objects.
      const page = await changesCollection.changes({ checkpoint, limit })
      return {
        documents: page.documents as unknown as WireDoc[],
        checkpoint: page.checkpoint as SyncCheckpoint | null
      }
    },

    async putContent({ id, data, ifMatch, ifNoneMatch, epoch }) {
      const headers = writeHeaders({ ifMatch, ifNoneMatch }) ?? {}
      // Stamp the opaque key-epoch id the body was encrypted under; absent leaves
      // the resource without an epoch stamp (server clears any prior one).
      if (epoch !== undefined) {
        headers[WAS_KEY_EPOCH_HEADER] = epoch
      }
      await conditionalWrite(() =>
        was.request({
          path: resourcePath(id),
          method: 'PUT',
          json: data as object,
          headers: Object.keys(headers).length > 0 ? headers : undefined
        })
      )
    },

    async deleteContent({ id, ifMatch }) {
      await conditionalWrite(() =>
        was.request({
          path: resourcePath(id),
          method: 'DELETE',
          headers: writeHeaders({ ifMatch })
        })
      )
    },

    async putMeta({ id, custom, ifMatch, ifNoneMatch }) {
      await conditionalWrite(() =>
        was.request({
          path: `${resourcePath(id)}/meta`,
          method: 'PUT',
          json: { custom },
          headers: writeHeaders({ ifMatch, ifNoneMatch })
        })
      )
    },

    async get({ id }): Promise<MasterState | null> {
      // Content re-read: raw GET returns the stored body verbatim (no decrypt)
      // and the content `version` in the ETag. A 404 means the resource is gone
      // (or tombstoned) -- report absent so the core synthesizes a tombstone.
      let contentResponse
      try {
        contentResponse = await was.request({
          path: resourcePath(id),
          method: 'GET'
        })
      } catch (err) {
        if (errorStatus(err) === 404) {
          return null
        }
        throw err
      }

      const master: MasterState = {
        version: parseEtag(contentResponse.headers.get('etag')) ?? 0,
        // Filled from the `/meta` body's server-managed `updatedAt` below; the
        // change feed remains the authority on ordering, so this only feeds the
        // one-off conflict entry and is corrected on the next pull.
        updatedAt: '',
        deleted: false,
        data: contentResponse.data as Json
      }

      // Metadata re-read: the `/meta` body carries the server-managed
      // `updatedAt` plus the user-writable `custom` (opaque), and its own
      // `metaVersion` ETag (absent until metadata has been written).
      try {
        const metaResponse = await was.request({
          path: `${resourcePath(id)}/meta`,
          method: 'GET'
        })
        const metaBody = metaResponse.data as
          | {
              updatedAt?: string
              createdBy?: string
              epoch?: string
              custom?: Json
            }
          | undefined
        if (metaBody?.updatedAt) {
          master.updatedAt = metaBody.updatedAt
        }
        // The same server-managed creator DID the change feed carries; reading
        // it here keeps the conflict-assembler path at parity with a pull.
        if (metaBody?.createdBy !== undefined) {
          master.createdBy = metaBody.createdBy
        }
        // The opaque key-epoch id the resource was stamped with (a top-level
        // metadata field), likewise carried so the conflict entry matches a pull.
        if (metaBody?.epoch !== undefined) {
          master.epoch = metaBody.epoch
        }
        const metaVersion = parseEtag(metaResponse.headers.get('etag'))
        if (metaVersion !== undefined) {
          master.metaVersion = metaVersion
        }
        if (metaBody?.custom !== undefined) {
          master.custom = metaBody.custom
        }
      } catch (err) {
        // Metadata is optional; only a hard error (not 404) should propagate.
        if (errorStatus(err) !== 404) {
          throw err
        }
      }

      return master
    }
  }
}
