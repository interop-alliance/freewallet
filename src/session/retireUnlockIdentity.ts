/**
 * The retirement of one unlock identity: its unlock Space on the server
 * (best effort) and every browser-local record filed under it. The one
 * deleter behind an unlock method's removal, the old-identity half of a
 * passphrase change, and the dead-pointer prompt's accept. It lives apart
 * from `keyring.ts` so the dead-pointer module can call it without a
 * module cycle.
 */
import { deleteUnlockSpace } from '@interop/wallet-core/keyring'
import type { UnlockIdentity } from '@interop/wallet-core/keyring'
import { WAS_SERVER_URL } from '@/app.config'
import { deleteUnlockLocalState } from '@/lib/sessionKey'
import { createLogger } from '@/lib/log'
import { wasServiceDescription } from '@/lib/wasService'

const log = createLogger('fw:session:keyring')

/**
 * Retires one unlock identity: its unlock Space on the server (best effort)
 * and every local record filed under it (the keyring cache and the
 * client-key record). Shared by `deleteUnlockMethod`, the old-identity
 * half of `changePassphrase`, and `removeDeadPointerSignInData`.
 *
 * @param options {object}
 * @param options.unlock {UnlockIdentity}   the identity to retire
 * @param options.warning {string}   how a failed Space deletion is logged
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<boolean>}   whether the unlock Space was deleted
 */
export async function retireUnlockIdentity({
  unlock,
  warning,
  idb
}: {
  unlock: UnlockIdentity
  warning: string
  idb?: IDBFactory
}): Promise<boolean> {
  let unlockSpaceDeleted = true
  if (WAS_SERVER_URL) {
    try {
      await deleteUnlockSpace({
        serviceDescription: await wasServiceDescription(),
        storageServerUrl: WAS_SERVER_URL,
        zcapClient: unlock.zcapClient,
        spaceId: unlock.spaceId
      })
    } catch (err) {
      log.warn(warning, { err })
      unlockSpaceDeleted = false
    }
  }
  await deleteUnlockLocalState({ spaceId: unlock.spaceId, idb })
  return unlockSpaceDeleted
}
