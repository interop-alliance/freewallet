/**
 * The one post-login step sequence every page-level login site runs once a
 * `Session` exists: the login page's passphrase, passkey, and
 * enrollment-completion handlers, the external request page's in-place
 * login, and the recovery page's final login. It is the top-level sibling
 * of `completePopupLogin`, which covers the CHAPI popup pages instead.
 *
 * The steps, in order: wait for storage provisioning, adopt the session
 * into the auth store, record the Login activity, register the CHAPI
 * handler, show the could-not-remember warning when the roster read adopted
 * a rotated user key this browser could not persist, run the recovery
 * delegation health check (a nudge, fire-and-forget), and navigate. A caller
 * that stays on its own page passes no `navigate`.
 */
import type { TFunction } from 'i18next'
import type { Session } from '@/types/auth'
import { useAuthStore } from '@/stores/authStore'
import { registerWallet } from '@/lib/registerWallet'
import { checkRecoveryHealth } from '@/session/recovery'
import { recordWalletLogin } from '@/session/walletLoginActivity'
import { showToast } from '@/stores/toastStore'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:login')

/**
 * Runs the post-login steps for a page-level login site.
 *
 * Session creation fired `ensureUserCollections` as `session.storageReady`;
 * the sequence waits for the collections to be provisioned or opened before
 * adopting the session. The login-time registry passes run AFTER
 * navigation, serialized on `session.registryReady`, and nothing here waits
 * on them (FW-300).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.t {TFunction}   the page's translator, for the toasts
 * @param [options.navigate] {(to: string, opts: { replace: boolean }) => void}
 *   where to go once the session is live; omitted by a caller that stays on
 *   its page (the external request page, a resumed recovery spend that
 *   still owes its replacement-code display)
 * @returns {Promise<void>}
 */
export async function completeAppLogin({
  session,
  t,
  navigate
}: {
  session: Session
  t: TFunction
  navigate?: (to: string, opts: { replace: boolean }) => void
}): Promise<void> {
  await session.storageReady
  useAuthStore.getState().login(session)
  recordWalletLogin({ session })
  // The login page registers at mount too; the registration is run-once
  // (it queries the mediator's permission state first), so the second call
  // costs one non-prompting query. The other sites have no mount-time
  // registration and would otherwise never install the handler.
  void registerWallet()
  // The roster read adopted a rotated user key but could not write this
  // browser's copy of it (the client-key record): the session is fine, so
  // warn rather than fail the login.
  if (session.userKeyPersistFailed) {
    showToast({
      message: t('auth.login.rememberBrowserWarning'),
      severity: 'warning'
    })
  }
  // The login-time recovery health check: a recovery delegation signed by a
  // since-removed client rots silently and would brick recovery exactly
  // when it is needed, so nudge now rather than then.
  void checkRecoveryHealth({ session })
    .then(flags => {
      if (flags.length > 0) {
        showToast({
          message: t('auth.login.recoveryHealthWarning'),
          severity: 'warning'
        })
      }
    })
    .catch(err => log.warn('Recovery health check failed', { err }))
  navigate?.('/dashboard', { replace: true })
}
