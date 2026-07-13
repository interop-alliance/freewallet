/**
 * Shared passphrase-login sequence for the CHAPI popup pages
 * (`WalletGetPage`, `WalletStorePage`). Both popups run in a third-party
 * partitioned iframe, so both log in the same way: resolve the passphrase
 * through the keyring in remote-direct storage mode, guard the
 * account-not-found case, persist the delegated session through the
 * first-party Storage Access handle (so the next popup visit auto-recognizes
 * the user), and map any failure to the popup's error-message key. Only the
 * post-login work differs per page (credential selection vs credential
 * offer), so that stays in the pages.
 *
 * A future passkey entry point for the popup can reuse `completePopupLogin`
 * unchanged once it, too, produces a session.
 */
import type { Session } from '@/types/auth'
import { loginWithPassphrase } from '@/session/initSession'
import { persistDelegatedSession } from '@/session/delegatedSession'
import { isStorageUnreachable } from '@/lib/storageErrors'

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
  console.error('CHAPI login failed:', err)
  return 'chapi.loginFailed'
}

/**
 * Logs the popup user in with their passphrase and, on success, persists the
 * delegated session through the first-party handle. Returns the live session
 * on success or an `errorKey` (an i18n key) on any failure, so the calling
 * page never has to reproduce the login sequence or its error mapping.
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @param [options.firstPartyIdb] {IDBFactory | null}   the first-party
 *   IndexedDB factory from the Storage Access API flow; threaded into the
 *   keyring lookup and used to persist the delegated session (falls back to
 *   the global factory when absent, and the session is not persisted then)
 * @returns {Promise<{ session: Session } | { errorKey: string }>}
 */
export async function completePopupLogin({
  passphrase,
  firstPartyIdb
}: {
  passphrase: string
  firstPartyIdb?: IDBFactory | null
}): Promise<{ session: Session } | { errorKey: string }> {
  try {
    // Thread the first-party IndexedDB factory (from the Storage Access API
    // flow) into the keyring lookup so its cache read/write lands in
    // first-party storage rather than the popup's partitioned bucket; fall
    // back to the global factory when no handle is held. The popup's local
    // IndexedDB is third-party partitioned and no sync controller runs here,
    // so route credential + history operations straight to the remote WAS
    // collections (remote-direct mode).
    const { session, userExists } = await loginWithPassphrase({
      passphrase,
      idb: firstPartyIdb ?? undefined,
      remoteDirectStorage: true
    })
    if (!session || !userExists) {
      return { errorKey: 'chapi.accountNotFound' }
    }
    if (firstPartyIdb) {
      // Persist the delegated session through the first-party handle so the
      // main app (and the next popup visit) recognizes the user. Fire-and-
      // forget: a failure here only costs refresh-survival, never the login.
      void persistDelegatedSession({
        session,
        idb: firstPartyIdb
      }).catch((err: unknown) => {
        console.warn('Could not persist the delegated session:', err)
      })
    }
    return { session }
  } catch (err) {
    return { errorKey: mapPopupLoginError(err) }
  }
}
