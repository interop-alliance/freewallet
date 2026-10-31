/**
 * The `connections` directory's store seam for a session: one
 * `ConnectionsStore` (the `@interop/wallet-core/connections` store
 * interface) per session, resolved to a concrete adapter at every call.
 *
 * - On a session with a remote Space the adapter is wallet-core's
 *   `pwsConnectionsStore`, built by the storage manager over the account
 *   Space's `connections` Collection handle and the directory's EDV cipher.
 *   The handle and the cipher are rebuilt from the descriptor the call
 *   resolves, so a user key cascade's descriptor refresh reaches the next
 *   call and no entry is sealed under an epoch the cascade retired.
 * - On a guest or a no-WAS session, which have no Space, the adapter is
 *   {@link localConnectionsStore}, over the BrowserStore's local
 *   `connections` collection and the same EDV cipher. That collection is
 *   never replicated, and the local copy is the only copy.
 *
 * Every write the directory logic makes is conditional, a read-modify-write
 * under `ifMatch` or a create under `ifNoneMatch`, and a lost race surfaces
 * as pws-client's `PreconditionFailedError`, which wallet-core matches by
 * name.
 */
import type { RxCollection, RxDocument } from 'rxdb/plugins/core'
import { PreconditionFailedError } from '@interop/pws-client'
import type { EdvDocCipher } from '@interop/pws-client/edv'
import type {
  ConnectionIdKey,
  ConnectionsStore,
  StoredConnection
} from '@interop/wallet-core/connections'
import type { Json, SyncedDoc } from '@interop/pws-sync'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:connections')

/**
 * What a directory caller works with: the session's store, the collection's
 * blinded-index key every resource id is derived under, and, on a session
 * with a remote Space, the Space's container URL the grant checks read.
 */
export interface ConnectionsDirectory {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  /**
   * This Space's container URL, with its trailing slash. Absent on a session
   * with no remote Space, which delegates nothing.
   */
  spaceUrl?: string
}

/**
 * A store that resolves its adapter at every call and delegates to it. The
 * resolution is where the directory binding is checked and the cipher and
 * handle are built from the current descriptor, so nothing is captured
 * across a descriptor refresh. A failed call is logged at debug and
 * rethrown: a lost race is routine, and a refusal is logged where it is
 * decided.
 *
 * @param options {object}
 * @param options.resolve {Function}   `() => Promise<ConnectionsStore>`
 * @returns {ConnectionsStore}
 */
export function resolvingConnectionsStore({
  resolve
}: {
  resolve: () => Promise<ConnectionsStore>
}): ConnectionsStore {
  /**
   * Runs one store operation on the resolved adapter.
   *
   * @param options {object}
   * @param options.operation {string}   how the log names the call
   * @param options.run {Function}   `(store) => Promise<T>`
   * @returns {Promise<T>}
   */
  async function delegate<T>({
    operation,
    run
  }: {
    operation: string
    run: (store: ConnectionsStore) => Promise<T>
  }): Promise<T> {
    try {
      return await run(await resolve())
    } catch (err) {
      log.debug('A connections directory call failed', { operation, err })
      throw err
    }
  }
  return {
    list: () => delegate({ operation: 'list', run: store => store.list() }),
    get: options =>
      delegate({ operation: 'get', run: store => store.get(options) }),
    put: options =>
      delegate({ operation: 'put', run: store => store.put(options) })
  }
}

/**
 * Whether an RxDB write failed on a revision conflict: another write to the
 * same document landed between this write's read and its write.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
function isRxConflict(err: unknown): boolean {
  return (err as { code?: unknown } | null)?.code === 'CONFLICT'
}

/**
 * The refusal a conditional local write raises when its precondition does
 * not hold, under the name the directory logic matches.
 *
 * @param options {object}
 * @param options.resourceId {string}
 * @param [options.cause] {unknown}
 * @returns {PreconditionFailedError}
 */
function preconditionFailed({
  resourceId,
  cause
}: {
  resourceId: string
  cause?: unknown
}): PreconditionFailedError {
  return new PreconditionFailedError(
    `The local connections entry "${resourceId}" changed since it was read.`,
    { status: 412, ...(cause !== undefined && { cause }) }
  )
}

/**
 * The directory adapter over the local `connections` RxDB collection of a
 * session with no remote Space. A body is sealed as an EDV envelope at the
 * resource id the directory logic derived, through the cipher's seal-at-id
 * path, and stored as the resource replica's `data`, as every other local
 * encrypted collection stores its envelopes. A read opens the envelope under
 * the id it was read at, so a body sealed for another id is refused. The
 * RxDB revision is the ETag: a write under `ifMatch` lands only while the
 * document still carries that revision, and a create under `ifNoneMatch`
 * lands only where no live document stands. Either refusal is
 * `PreconditionFailedError`.
 *
 * @param options {object}
 * @param options.collection {RxCollection<SyncedDoc>}   the BrowserStore's
 *   local `connections` collection
 * @param options.cipher {object}   the directory's EDV document cipher,
 *   built from its current descriptor; its `encrypt` (given an `id`) and
 *   `decrypt` are used
 * @returns {ConnectionsStore}
 */
export function localConnectionsStore({
  collection,
  cipher
}: {
  collection: RxCollection<SyncedDoc>
  cipher: Pick<EdvDocCipher, 'encrypt' | 'decrypt'>
}): ConnectionsStore {
  /**
   * One local document as the store seam states it: its opened body, and
   * its RxDB revision as the ETag a conditional write pins to.
   *
   * @param doc {RxDocument<SyncedDoc>}
   * @returns {Promise<{ body: unknown; etag: string }>}
   */
  async function openedBody(
    doc: RxDocument<SyncedDoc>
  ): Promise<{ body: unknown; etag: string }> {
    // A document with no stored body opens as nothing does: the cipher
    // refuses it, and the listing reports it unreadable.
    const body = await cipher.decrypt({
      id: doc.id,
      envelope: doc.toMutableJSON().data ?? null
    })
    return { body, etag: doc.revision }
  }

  return {
    async list() {
      const docs = await collection.find().exec()
      return Promise.all(
        docs.map(async (doc): Promise<StoredConnection> => {
          try {
            const { body, etag } = await openedBody(doc)
            return { resourceId: doc.id, etag, body }
          } catch (err) {
            return { resourceId: doc.id, etag: doc.revision, readError: err }
          }
        })
      )
    },
    async get({ resourceId }) {
      const doc = await collection.findOne(resourceId).exec()
      return doc ? openedBody(doc) : undefined
    },
    async put({ resourceId, body, ifMatch, ifNoneMatch }) {
      const existing = await collection.findOne(resourceId).exec()
      if (ifNoneMatch === true && existing) {
        throw preconditionFailed({ resourceId })
      }
      if (ifMatch !== undefined && existing?.revision !== ifMatch) {
        throw preconditionFailed({ resourceId })
      }
      const { envelope, epoch } = await cipher.encrypt({
        id: resourceId,
        data: body as Json
      })
      const updatedAt = new Date().toISOString()
      try {
        if (existing) {
          // `patch` writes against the revision `existing` was read at, so a
          // write that landed in between is a conflict rather than lost.
          const patched = await existing.patch({
            updatedAt,
            data: envelope,
            ...(epoch !== undefined && { epoch })
          })
          return { etag: patched.revision }
        }
        const inserted = await collection.insert({
          id: resourceId,
          updatedAt,
          data: envelope,
          ...(epoch !== undefined && { epoch })
        })
        return { etag: inserted.revision }
      } catch (err) {
        if (isRxConflict(err)) {
          throw preconditionFailed({ resourceId, cause: err })
        }
        throw err
      }
    }
  }
}
