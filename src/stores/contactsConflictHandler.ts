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
 * decide a race identically; everything here is the RxDB shape around it. The
 * collection's document cipher is read lazily through `getCipher`, so a later
 * `setCiphers` swap is honored.
 */
import type { RxConflictHandler } from 'rxdb/plugins/core'
import { deepEqual } from 'rxdb/plugins/utils'
import { resolveContactHeadConflict } from '@interop/wallet-core/sync'
import type { SyncedDoc } from '@/lib/sync'
import type { DocCipher } from '@interop/was-client/edv'

/**
 * @param options {object}
 * @param options.getCipher {() => DocCipher | undefined}   lazy accessor for
 *   the `contacts` document cipher (undefined for a plaintext store)
 * @returns {RxConflictHandler<SyncedDoc>}
 */
export function createContactsConflictHandler({
  getCipher
}: {
  getCipher: () => DocCipher | undefined
}): RxConflictHandler<SyncedDoc> {
  return {
    isEqual(a, b) {
      return deepEqual(a, b)
    },
    async resolve({ realMasterState, newDocumentState }) {
      const cipher = getCipher()
      const winner = await resolveContactHeadConflict({
        remote: realMasterState.data,
        local: newDocumentState.data,
        ...(cipher ? { cipher } : {}),
        remoteDeleted: Boolean(realMasterState._deleted),
        localDeleted: Boolean(newDocumentState._deleted)
      })
      return winner === 'local' ? newDocumentState : realMasterState
    }
  }
}
