/**
 * The RxDB binding for the mutable `contacts` collection's conflict rule.
 * Every other synced collection is immutable and content-addressed, so a
 * write-write conflict is impossible there and RxDB's default handler (always
 * keep the remote master) is never exercised. A contact head document is
 * genuinely overwritten in place under a stable row id, so two replicas CAN
 * race on the same row -- and the default handler would silently drop one
 * side's edit.
 *
 * The rule itself lives in `@interop/wallet-core/sync`, so both replicas
 * decide a race identically; the RxDB shape around it comes from
 * `@interop/was-sync`, so everything here is the decision closure. The
 * collection's document cipher is read at resolve time through `getCipher`,
 * never captured, so a later `setCiphers` swap (the epoch cascade's) is
 * honored. A resolver throw (an integrity refusal, or a `getCipher` that itself
 * fails) is reported by `makeConflictHandler` too, through was-sync's logging
 * seam (the same `sync` namespace), before it propagates.
 *
 * Each side's envelope is addressed with the contested row's own id, so a body
 * sealed for another resource is refused rather than compared. Both directions
 * fail the replication cycle: a misbound remote side and a misbound local side
 * are refused alike, no winner is returned, and the queued local edit stays
 * queued rather than being dropped. The refusal is logged here first, on the
 * `sync` namespace, naming the row and the side the binding check refused, and
 * is then rethrown unchanged.
 *
 * Equality is the whole-row `deepEqual`, not the package's `statesEqual`
 * (which compares the revision and body members alone): the feed echo of a
 * row this replica just pushed carries the server-managed `createdBy` and
 * `updatedAt`, and a handler that called the two states equal would let RxDB
 * skip writing them into the local row.
 */
import { makeConflictHandler, type ConflictHandler } from '@interop/was-sync'
import { resolveContactHeadConflict } from '@interop/wallet-core/sync'
import type { DocCipher } from '@interop/was-client/edv'
import { deepEqual } from 'rxdb/plugins/utils'
import { createLogger } from '@/lib/log'

// The driver's own namespace: the refusal reads beside was-sync's report of
// the failed cycle rather than under an app-side name of its own.
const log = createLogger('sync')

/**
 * @param options {object}
 * @param options.getCipher {() => DocCipher | undefined}   lazy accessor for
 *   the `contacts` document cipher (undefined for a plaintext store)
 * @returns {ConflictHandler}
 */
export function createContactsConflictHandler({
  getCipher
}: {
  getCipher: () => DocCipher | undefined
}): ConflictHandler {
  return makeConflictHandler({
    isEqual: deepEqual,
    async resolve({ realMasterState, newDocumentState }) {
      const cipher = getCipher()
      return await resolveContactHeadConflict({
        id: realMasterState.id,
        remote: realMasterState.data,
        local: newDocumentState.data,
        ...(cipher ? { cipher } : {}),
        remoteDeleted: Boolean(realMasterState._deleted),
        localDeleted: Boolean(newDocumentState._deleted),
        onIntegrityRefusal({ side, err }) {
          log.error('Contacts conflict side sealed for another resource', {
            id: realMasterState.id,
            side,
            err
          })
        }
      })
    }
  })
}
