/**
 * An in-memory `connections` store with ETags, honoring `ifMatch` and
 * `ifNoneMatch` the way the PWS server does, for tests that drive the
 * directory logic in `@interop/wallet-core/connections` against a store the
 * test can inspect. Mirrors wallet-core's own test fixture, which its
 * package does not export.
 */
import type {
  ConnectionsStore,
  StoredConnection
} from '@interop/wallet-core/connections'

/**
 * A named error, the shape the directory logic matches on.
 *
 * @param name {string}
 * @returns {Error}
 */
function namedError(name: string): Error {
  const err = new Error(name)
  err.name = name
  return err
}

/**
 * A fixed 32-byte blinded-index key.
 */
export const HMAC_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1)

/**
 * Builds the store.
 *
 * @returns {object}   the store, its rows by resource id, and the list of
 *   writes it took
 */
export function memoryConnectionsStore(): {
  store: ConnectionsStore
  rows: Map<string, { body: unknown; etag: string }>
  writes: string[]
} {
  const rows = new Map<string, { body: unknown; etag: string }>()
  const writes: string[] = []
  let revision = 0
  const store: ConnectionsStore = {
    async list() {
      return [...rows].map(([resourceId, row]): StoredConnection => ({
        resourceId,
        etag: row.etag,
        body: structuredClone(row.body)
      }))
    },
    async get({ resourceId }) {
      const row = rows.get(resourceId)
      return row === undefined
        ? undefined
        : { body: structuredClone(row.body), etag: row.etag }
    },
    async put({ resourceId, body, ifMatch, ifNoneMatch }) {
      const row = rows.get(resourceId)
      if (ifNoneMatch && row !== undefined) {
        throw namedError('PreconditionFailedError')
      }
      if (ifMatch !== undefined && row?.etag !== ifMatch) {
        throw namedError('PreconditionFailedError')
      }
      writes.push(`put:${resourceId}`)
      const etag = `e${++revision}`
      rows.set(resourceId, { body: structuredClone(body), etag })
      return { etag }
    }
  }
  return { store, rows, writes }
}
