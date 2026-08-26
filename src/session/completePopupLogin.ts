/**
 * Shared passphrase-login sequence for the CHAPI popup pages
 * (`WalletGetPage`, `WalletStorePage`). Both popups run in a third-party
 * partitioned iframe, so both log in the same way: ask for the unpartitioned
 * IndexedDB handle inside the submit gesture, resolve the passphrase through
 * the keyring as a popup session, guard the account-not-found case, and map
 * any failure to the popup's error-message key. Only the post-login work
 * differs per page (credential selection vs credential offer), so that stays
 * in the pages.
 *
 * The popup does NOT choose its own durability. It runs the ordinary
 * post-KDF routing with the Storage Access handle threaded in, so the
 * browser's own ratchet state decides: a granted handle lets the record probe
 * see the first-party client-key record and a remembered browser proceeds as
 * that durable client, while a denied handle -- and every engine that offers
 * no unpartitioned-IndexedDB request at all, which is Safari's and Firefox's
 * steady state -- finds no record in the partitioned bucket and falls back to
 * the transient session, exactly as a non-remembered browser does. That is
 * `decisions/0009-popup-denied-storage-access-goes-transient.md`'s one
 * uniform fallback, and it arrives by construction rather than as a popup arm
 * of its own.
 *
 * What the popup flag still gates is only what the partitioning implies:
 * remote-direct storage in the durable arm (the partitioned replica no sync
 * controller drives), the localStorage caches suppressed where they are
 * genuinely caches, and the durable arm's popup refusals (no
 * self-enrollment, no pending resume). A transient popup session needs none
 * of them -- it is replica-less and in-memory by construction.
 *
 * A future passkey entry point for the popup can reuse `completePopupLogin`
 * unchanged once it, too, produces a session.
 */
import type { Session } from '@/types/auth'
import { loginWithPassphrase } from '@/session/initSession'
import { isStorageUnreachable } from '@/lib/storageErrors'
import { requestUnpartitionedIdb } from '@/lib/storageAccess'
import { TransientLoginUnavailableError } from '@/session/transientLogin'
import { transientRefusalKey } from '@/session/loginErrorKey'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:popup')

/**
 * Maps a popup login/storage failure to its message key -- the shared error
 * mapping both popups apply, whether the failure came from the login itself
 * or from a post-login storage read. A storage-unreachable error gets its own
 * guidance key; a transient-login refusal gets the shared per-reason copy
 * (the popup reaches those now that a record-less visit routes transient);
 * anything else is logged and reported as a generic login failure.
 *
 * @param err {unknown}
 * @returns {string}   an i18n key the page passes to `t()`
 */
export function mapPopupLoginError(err: unknown): string {
  if (isStorageUnreachable(err)) {
    return 'chapi.storageUnreachable'
  }
  if (err instanceof TransientLoginUnavailableError) {
    log.error('CHAPI transient login unavailable', {
      reason: err.reason,
      err
    })
    return transientRefusalKey(err.reason)
  }
  log.error('CHAPI login failed', { err })
  return 'chapi.loginFailed'
}

/**
 * Logs the popup user in with their passphrase. Returns the live session on
 * success or an `errorKey` (an i18n key) on any failure, so the calling page
 * never has to reproduce the login sequence or its error mapping.
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @returns {Promise<{ session: Session } | { errorKey: string }>}
 */
export async function completePopupLogin({
  passphrase
}: {
  passphrase: string
}): Promise<{ session: Session } | { errorKey: string }> {
  try {
    // The popup's own IndexedDB is third-party partitioned: ask for the
    // unpartitioned factory first (the Storage Access API handle extension,
    // still inside the submit gesture), so the keyring caches and this
    // client's key record resolve to their first-party home and a remembered
    // browser can log in from the popup as its durable client. Browsers
    // without the extension resolve undefined and the routing sees a
    // record-less browser -- the transient fallback, not a refusal.
    const idb = await requestUnpartitionedIdb()
    const { session, userExists } = await loginWithPassphrase({
      passphrase,
      popup: true,
      idb
    })
    if (!session && userExists) {
      // The account was located but this browser holds no client key set for
      // it and no transient session could be composed either. With a WAS
      // server that state is unreachable (a record-less popup routes
      // transient, whose own refusals arrive as
      // `TransientLoginUnavailableError` below); it is the no-WAS
      // deployment's plain pointer record -- distinct guidance from
      // "no account".
      return { errorKey: 'chapi.clientNotEnrolled' }
    }
    if (!session || !userExists) {
      return { errorKey: 'chapi.accountNotFound' }
    }
    return { session }
  } catch (err) {
    return { errorKey: mapPopupLoginError(err) }
  }
}
