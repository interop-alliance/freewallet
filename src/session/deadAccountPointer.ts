/**
 * The dead account pointer: an unlock record that decrypts cleanly but
 * points at an account whose log no longer exists. The record and its unlock
 * Space stand, naming an account that is gone -- an account deleted
 * server-side, migrated to another host, torn out from under this credential
 * by an account deletion that could not reach this credential's unlock
 * Space, or a credential unused for so long that the deletion's management
 * zcap for its Space had lapsed.
 *
 * The one signal is the account log answering 404 (wallet-core's
 * `AccountLogMissingError`). A network failure, a server fault, and a
 * continuity refusal are not deletion evidence: each rethrows unchanged, so
 * none of them can reach the deleter. On the signal, the login surface
 * receives `DeadAccountPointerError` carrying the removal closure, offers
 * "this account no longer exists; remove its sign-in data", and runs the
 * closure on accept. Declining leaves the record in place for a later
 * login to revisit.
 *
 * The removal is the credential's own retirement: its unlock Space is
 * deleted root-invoked under its own unlock identity, and the credential's
 * unlock-local state goes with it, so the browser holds no record for the
 * credential afterwards. It is the mender for invariant
 * `no-unlock-space-outlives-its-credential`, on the `login-routing`
 * trigger, and reports there.
 */
import {
  verifyAccountLog,
  type VerifiedAccountLog
} from '@interop/wallet-core/webvh'
import type { UnlockIdentity } from '@interop/wallet-core/keyring'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import type { PublishedWebvhLog } from '@interop/wallet-core/webvh'
import { mendReportAccumulator } from '@interop/wallet-core/menders'
import type { CeremonyId } from '@interop/wallet-core'
import { retireUnlockIdentity } from '@/session/retireUnlockIdentity'
import { isAccountLogMissing } from '@/session/verifiedLog'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:dead-pointer')

/**
 * The login refusal for an unlock record whose account log answers 404.
 * Carries what the surface needs to offer the way out: the unlock Space id
 * the record lives in, the account DID it named, and the removal closure.
 */
export class DeadAccountPointerError extends Error {
  readonly unlockSpaceId: string
  readonly accountDid: string
  /**
   * Removes this credential's sign-in data: its unlock Space (best effort,
   * reported in the result) and its unlock-local state (always).
   */
  readonly removeSignInData: () => Promise<{ unlockSpaceDeleted: boolean }>

  constructor({
    unlockSpaceId,
    accountDid,
    removeSignInData,
    cause
  }: {
    unlockSpaceId: string
    accountDid: string
    removeSignInData: () => Promise<{ unlockSpaceDeleted: boolean }>
    cause?: unknown
  }) {
    super(
      'The unlock record points at an account whose log no longer exists.',
      { ...(cause !== undefined ? { cause } : {}) }
    )
    this.name = 'DeadAccountPointerError'
    this.unlockSpaceId = unlockSpaceId
    this.accountDid = accountDid
    this.removeSignInData = removeSignInData
  }
}

/**
 * Removes a dead pointer's sign-in data: the credential's unlock Space,
 * root-invoked under its own unlock identity, and the credential's
 * unlock-local state. The one deleter the dead-pointer prompt runs, and the
 * converger the registry's `login-routing` site for invariant
 * `no-unlock-space-outlives-its-credential` names. A Space that could not
 * be deleted leaves the local state removed anyway and reports `partial`,
 * so the browser holds no record either way and the next login on the
 * credential finds nothing here.
 *
 * @param options {object}
 * @param options.unlock {UnlockIdentity}   the credential's unlock identity
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<{ unlockSpaceDeleted: boolean }>}
 */
export async function removeDeadPointerSignInData({
  unlock,
  idb
}: {
  unlock: UnlockIdentity
  idb?: IDBFactory
}): Promise<{ unlockSpaceDeleted: boolean }> {
  const mends = mendReportAccumulator<CeremonyId>({ logger: log })
  const unlockSpaceDeleted = await retireUnlockIdentity({
    unlock,
    warning: "Could not delete the dead pointer's unlock Space",
    idb
  })
  mends.report({
    invariant: 'no-unlock-space-outlives-its-credential',
    outcome: unlockSpaceDeleted ? 'clean' : 'partial',
    detail: { reason: 'dead-account-pointer' }
  })
  return { unlockSpaceDeleted }
}

/**
 * Builds the typed refusal for the dead-pointer signal, with the removal
 * closure bound to the credential's unlock identity. The caller has already
 * matched the signal (`isAccountLogMissing`), so a network failure, a
 * server fault, and a continuity refusal never reach here.
 *
 * @param options {object}
 * @param options.cause {unknown}   the account log's 404
 * @param options.unlock {UnlockIdentity}   the credential whose record
 *   pointed at the account
 * @param options.accountDid {string}   the account the record named
 * @param [options.idb] {IDBFactory}
 * @returns {DeadAccountPointerError}
 */
export function deadAccountPointerError({
  cause,
  unlock,
  accountDid,
  idb
}: {
  cause: unknown
  unlock: UnlockIdentity
  accountDid: string
  idb?: IDBFactory
}): DeadAccountPointerError {
  log.warn('The unlock record points at an account whose log is gone', {
    unlockSpaceId: unlock.spaceId
  })
  return new DeadAccountPointerError({
    unlockSpaceId: unlock.spaceId,
    accountDid,
    removeSignInData: () => removeDeadPointerSignInData({ unlock, idb }),
    cause
  })
}

/**
 * The first-contact account-log read of a login or a recovery spend:
 * wallet-core's `verifyAccountLog`, with the 404 refused as a dead pointer
 * when the credential's unlock identity is in hand. With none (a signup
 * entering the account it just established) the 404 rethrows as it did
 * before, since there is nothing to offer removing with.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.spaceId {string}
 * @param options.host {string}
 * @param [options.pinStore] {ResourceLogPinStore}
 * @param [options.published] {PublishedWebvhLog}
 * @param [options.unlock] {UnlockIdentity}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<VerifiedAccountLog>}
 */
export async function verifyPointedAccountLog({
  did,
  spaceId,
  host,
  pinStore,
  published,
  unlock,
  idb
}: {
  did: string
  spaceId: string
  host: string
  pinStore?: ResourceLogPinStore
  published?: PublishedWebvhLog
  unlock?: UnlockIdentity
  idb?: IDBFactory
}): Promise<VerifiedAccountLog> {
  try {
    return await verifyAccountLog({
      did,
      spaceId,
      host,
      ...(pinStore !== undefined ? { pinStore } : {}),
      ...(published !== undefined ? { published } : {})
    })
  } catch (err) {
    if (unlock === undefined || !isAccountLogMissing(err)) {
      throw err
    }
    throw deadAccountPointerError({ cause: err, unlock, accountDid: did, idb })
  }
}
