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
 * honored. A resolver throw (an undecryptable side, say) is reported by
 * `makeConflictHandler` itself, through was-sync's logging seam (the `sync`
 * namespace), before it propagates.
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
        remote: realMasterState.data,
        local: newDocumentState.data,
        ...(cipher ? { cipher } : {}),
        remoteDeleted: Boolean(realMasterState._deleted),
        localDeleted: Boolean(newDocumentState._deleted)
      })
    }
  })
}
