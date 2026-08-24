/**
 * Shared passphrase-login sequence for the CHAPI popup pages
 * (`WalletGetPage`, `WalletStorePage`). Both popups run in a third-party
 * partitioned iframe, so both log in the same way: resolve the passphrase
 * through the keyring in remote-direct storage mode, guard the
 * account-not-found case, and map any failure to the popup's error-message
 * key. Only the post-login work differs per page (credential selection vs
 * credential offer), so that stays in the pages.
 *
 * A future passkey entry point for the popup can reuse `completePopupLogin`
 * unchanged once it, too, produces a session.
 */
import type { Session } from '@/types/auth'
import { loginWithPassphrase } from '@/session/initSession'
import { isStorageUnreachable } from '@/lib/storageErrors'
import { requestUnpartitionedIdb } from '@/lib/storageAccess'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:popup')

/**
 * Maps a popup login/storage failure to its `chapi.*` message key -- the
 * shared error mapping both popups apply, whether the failure came from the
 * login itself or from a post-login storage read. A storage-unreachable error
 * gets its own guidance key; anything else is logged and reported as a generic
 * login failure.
 *
 * @param err {unknown}
 * @returns {string}   an i18n key the page passes to `t()`
 */
export function mapPopupLoginError(err: unknown): string {
  if (isStorageUnreachable(err)) {
    return 'chapi.storageUnreachable'
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
    // client's key record resolve to their first-party home and an enrolled
    // client can log in from the popup. Browsers without the extension
    // resolve undefined and the login proceeds against the partitioned
    // bucket -- landing in the honest not-enrolled state.
    const idb = await requestUnpartitionedIdb()
    // The popup's local RxDB is partitioned either way and no sync
    // controller runs here, so route credential + history operations
    // straight to the remote WAS collections (remote-direct mode).
    const { session, userExists } = await loginWithPassphrase({
      passphrase,
      remoteDirectStorage: true,
      idb
    })
    if (!session && userExists) {
      // The account was located but this browser holds no client key set for
      // it (not enrolled) -- distinct guidance from "no account".
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
