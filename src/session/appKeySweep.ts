/**
 * The login-time app-key sweep: removes app-key credentials stranded in the
 * `private-credentials` collection, where they were stored before they got
 * their own `app-connections` collection.
 *
 * They are deleted, never moved. An app key's value is the seed it carries, and
 * leaving one among the ordinary credentials keeps two doors open onto that
 * seed -- a world-readable public link, and a share of the credentials
 * collection. Copying the rows across would preserve each app's identity but
 * also preserve whatever a stale copy of the old row exposes, so the accepted
 * outcome is that an affected app reconnects through the ordinary App Connect
 * flow and is treated as a first run.
 *
 * The sweep is idempotent and cheap on a healthy account: one credential list,
 * a filter, and no writes when nothing matches.
 */
import {
  appKeyOrigin,
  appKeySeedBindsSubject,
  presentsAsAppKey
} from '@interop/wallet-core/request'
import { isSelfIssued } from '@/lib/vcShape'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { StorageManager } from '@/stores/storageManager'

/**
 * Whether a stored credential is an app key stranded in
 * `private-credentials`. Two rules, deliberately both: the marker type every
 * minted app key carries, and -- for the keys minted before the marker existed
 * -- the shape the old app-key match path accepted, a self-issued credential
 * (issuer == subject) claiming an origin AND carrying a seed that re-derives
 * its own subject DID.
 *
 * The seed binding is what keeps the legacy rule from being wider than the
 * class it sweeps: without it an ordinary self-issued credential that merely
 * happens to claim an `origin` would be deleted permanently, and no such
 * credential could ever have been handed to an application as an app key.
 *
 * @param credential {IVerifiableCredential}
 * @returns {Promise<boolean>}
 */
async function isStrandedAppKey(
  credential: IVerifiableCredential
): Promise<boolean> {
  if (presentsAsAppKey(credential)) {
    return true
  }
  if (!isSelfIssued(credential) || !appKeyOrigin(credential)) {
    return false
  }
  return appKeySeedBindsSubject(credential)
}

/**
 * Deletes every app key still sitting in `private-credentials`.
 *
 * A row whose delete fails (a public copy that cannot be retracted, a network
 * failure) is logged and skipped rather than aborting the sweep, so one bad
 * row cannot strand every later seed until some future login. The sweep is
 * idempotent, so the skipped rows are retried at the next one.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @returns {Promise<number>}   how many rows were deleted
 */
export async function sweepStrandedAppKeys({
  storage
}: {
  storage: StorageManager
}): Promise<number> {
  const credentials = await storage.listCredentials()
  const stranded: string[] = []
  for (const { cid, vc } of credentials) {
    if (await isStrandedAppKey(vc)) {
      stranded.push(cid)
    }
  }
  let deleted = 0
  for (const cid of stranded) {
    try {
      // Through the ordinary delete path, so a stranded key that was ever
      // published as a public link has that world-readable copy retracted
      // first -- the one case where the row's seed is already exposed.
      await storage.deleteCredential({ cid })
      deleted += 1
    } catch (err) {
      console.warn(`Could not delete the stranded app key "${cid}":`, err)
    }
  }
  return deleted
}
