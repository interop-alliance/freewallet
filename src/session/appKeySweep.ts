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
 * Deleting a stranded row also removes the app from the Applications page,
 * which lists connected apps out of the `app-connections` collection alone --
 * so the delete destroys the surface the user would revoke the app from. The
 * app's live authority is therefore retired BEFORE the row goes: the same two
 * calls, in the same order, that `revokeAppAccess` drives (rotate the app out
 * of its app-provisioned collections' key epochs and revoke those pull-axis
 * grants, then revoke the remaining recorded grants). Without that, an app's
 * delegated zcaps would stand until their TTL expired and it would stay a key
 * epoch recipient indefinitely, with nothing left to revoke it from.
 *
 * The sweep is idempotent and cheap on a healthy account: one credential list,
 * a filter, and no writes when nothing matches.
 */
import {
  appKeyOrigin,
  appKeySeedBindsSubject,
  presentsAsAppKey
} from '@interop/wallet-core/request'
import { isSelfIssued, subjectId } from '@/lib/vcShape'
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
 * Deletes every app key still sitting in `private-credentials`, retiring the
 * app's live authority first.
 *
 * Revoke before delete, for the reason `revokeAppAccess` states: the row is
 * the app's only listing on the Applications page, so once it is gone there is
 * nothing left to revoke the app from, and its grants would stand until they
 * expired. A row whose subject DID or origin is missing has no revocable
 * identity to look up and is deleted directly.
 *
 * A row whose revocation does not fully land is left in place: a rotation
 * reporting failures, or a grant revocation that throws, skips that row's
 * delete. The sweep is unattended, so an app that is only half rotated must
 * stay retryable at the next login rather than lose its revocation handle --
 * deliberately stricter than the interactive `revokeAppAccess`, where a user
 * sees the outcome. Delete failures (a public copy that cannot be retracted, a
 * network failure) are logged and skipped the same way, so one bad row cannot
 * strand every later seed until some future login. The sweep is idempotent, so
 * the skipped rows are retried at the next one.
 *
 * The activity history both revocation calls scan is fetched once, and only
 * when at least one row needs revoking.
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
  const stranded: Array<{
    cid: string
    origin?: string
    subjectDid?: string
  }> = []
  for (const { cid, vc } of credentials) {
    if (await isStrandedAppKey(vc)) {
      stranded.push({
        cid,
        origin: appKeyOrigin(vc),
        subjectDid: subjectId(vc)
      })
    }
  }

  let items: Awaited<ReturnType<StorageManager['listHistoryItems']>> | undefined
  let deleted = 0
  for (const { cid, origin, subjectDid } of stranded) {
    try {
      if (origin && subjectDid) {
        items ??= await storage.listHistoryItems()
        // Rotate the app out of its app-provisioned collections' key epochs
        // (revoking those collections' pull-axis grants indivisibly) before
        // anything else, then revoke the remaining recorded grants.
        const rotation = await storage.revokeAppCollectionRecipients({
          origin,
          subjectDid,
          items
        })
        if (rotation.failed > 0) {
          console.warn(
            `Could not rotate every collection off the stranded app key ` +
              `"${cid}"; leaving it in place to retry at the next login.`
          )
          continue
        }
        await storage.revokeAppGrants({ origin, subjectDid, items })
      }
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
