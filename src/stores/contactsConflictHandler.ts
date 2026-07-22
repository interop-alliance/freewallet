/**
 * The RxDB conflict handler for the mutable `contacts` collection. Every other
 * synced collection is immutable and content-addressed, so a write-write
 * conflict is impossible there and RxDB's default handler (always keep the
 * remote master) is never exercised. A contact head document is genuinely
 * overwritten in place under a stable row id, so two replicas CAN race on the
 * same row -- and the default handler would silently drop one side's edit.
 *
 * The winner is decided by the last-write-wins rule both replicas share
 * (`remotePayloadWins` from `@interop/social-core`): the `updatedAt` /
 * `deviceId` pair sealed inside each head payload's encrypted envelope. The
 * handler decrypts both sides with the collection's document cipher, read
 * lazily through `getCipher` so a later `setCiphers` swap is honored.
 *
 * Fail-safe: whenever the LWW fields are unreachable -- a tombstone on either
 * side, a missing cipher, an envelope that will not decrypt, a malformed
 * payload -- the handler falls back to keeping the remote master, which is
 * exactly RxDB's default and therefore always converges.
 */
import {
  remotePayloadWins,
  type ContactHeadPayload
} from '@interop/social-core'
import type { RxConflictHandler } from 'rxdb/plugins/core'
import { deepEqual } from 'rxdb/plugins/utils'
import type { SyncedDoc } from '@/lib/sync'
import { isEncryptedEnvelope, type DocCipher } from '@interop/was-client/edv'

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
  /**
   * Recovers the head payload from a synced-doc row body: decrypts an
   * envelope, passes plaintext through, returns undefined when the payload
   * (and so its LWW fields) cannot be reached.
   *
   * @param data {SyncedDoc['data']}
   * @returns {Promise<ContactHeadPayload | undefined>}
   */
  async function headOf(
    data: SyncedDoc['data']
  ): Promise<ContactHeadPayload | undefined> {
    let head: unknown
    if (isEncryptedEnvelope(data)) {
      const cipher = getCipher()
      if (!cipher) {
        return undefined
      }
      try {
        head = await cipher.decrypt({ envelope: data! })
      } catch {
        return undefined
      }
    } else {
      head = data
    }
    const candidate = head as ContactHeadPayload | undefined
    return typeof candidate?.updatedAt === 'string' &&
      typeof candidate?.deviceId === 'string'
      ? candidate
      : undefined
  }

  return {
    isEqual(a, b) {
      return deepEqual(a, b)
    },
    async resolve({ realMasterState, newDocumentState }) {
      // A tombstone carries no fresher LWW stamp (delete does not rewrite the
      // head payload), so deletes resolve like the default handler: remote
      // master wins.
      if (!realMasterState._deleted && !newDocumentState._deleted) {
        const remoteHead = await headOf(realMasterState.data)
        const localHead = await headOf(newDocumentState.data)
        if (
          remoteHead &&
          localHead &&
          !remotePayloadWins(remoteHead, localHead)
        ) {
          return newDocumentState
        }
      }
      return realMasterState
    }
  }
}
