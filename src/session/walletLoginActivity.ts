/**
 * Records a local sign-in in `wallet-activity` -- "Logged in to wallet.", the
 * same entry the mobile wallet writes at unlock (wallet-core's
 * `addHistoryWalletLogin`). Shared by every page that ends in a sign-in: the
 * login page's passphrase, passkey, and connect-this-browser handlers, and
 * the recovery page's tail.
 */
import type { Session } from '@/types/auth'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:activity')

/**
 * Fire-and-forget: the entry is an audit trail, so a failed write is logged
 * and never blocks or fails the login.
 *
 * @param options {object}
 * @param options.session {Session}
 */
export function recordWalletLogin({ session }: { session: Session }) {
  void session.storage
    .addHistoryWalletLogin({ user: session.user })
    .catch(err => log.warn('Could not record the wallet login', { err }))
}
