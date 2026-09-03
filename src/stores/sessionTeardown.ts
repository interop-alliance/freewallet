/**
 * The one teardown for a session that will not be entered again: background
 * replication stopped, then the local replica handle released. Shared by the
 * auth store's logout and account switch and by the setup store's discard of
 * an abandoned run's session, so the order (replication before the database)
 * lives in one place.
 */
import type { Session } from '@/types/auth'
import { syncController } from '@/stores/syncController'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:teardown')

/**
 * Tears a session down. Non-throwing: a teardown failure must not wedge the
 * logout, account switch, or discard that asked for it, and both halves are
 * already logged.
 *
 * @param session {Session | null}   the session to release, or `null` to stop
 *   replication alone
 * @returns {Promise<void>}
 */
export async function discardSession(session: Session | null): Promise<void> {
  try {
    await syncController.stop()
  } catch (err) {
    log.warn('Could not stop background replication', { err })
  }
  if (!session) {
    return
  }
  try {
    // The data stays in IndexedDB; only this session's handle on it closes.
    await session.storage.close()
  } catch (err) {
    log.warn('Could not close the session storage', { err })
  }
}

/**
 * Releases a session nobody ever entered: the storage handle alone. The
 * background sync controller is one per app, and a session that was never
 * logged in never started it, so stopping it here would halt replication for
 * whatever account the user is live in by now.
 *
 * @param session {Session | null}   the never-entered session, or `null`
 * @returns {Promise<void>}
 */
export async function closeUnenteredSession(
  session: Session | null
): Promise<void> {
  if (!session) {
    return
  }
  try {
    await session.storage.close()
  } catch (err) {
    log.warn('Could not close the discarded session storage', { err })
  }
}
