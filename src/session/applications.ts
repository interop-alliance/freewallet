/**
 * The Applications surface's glue: listing the apps connected through App
 * Connect alongside the account key set their grants are checked against, and
 * revoking one app's access. The page renders and confirms; the reads, the
 * best-effort degradation, and the revocation call live here.
 */
import { currentAccountSigningKeys } from '@/session/clients'
import {
  deriveAppGrantsState,
  listConnectedApps,
  revokeAppAccess,
  type AppGrantsState,
  type ConnectedApp
} from '@/lib/connectedApps'
import type { Session } from '@/types/auth'

/**
 * Lists the connected apps together with the enrolled clients' signing keys
 * from the verified account log, for the per-app grant-state check.
 *
 * The key-set half is best-effort: a session without a promoted account (or a
 * log that cannot be fetched right now) degrades to listing the apps without
 * an orphaned marker (`signingKeys: undefined`), never to failing the page.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<{ apps: ConnectedApp[], signingKeys?: Set<string> }>}
 */
export async function listApplicationsView({
  session
}: {
  session: Session
}): Promise<{ apps: ConnectedApp[]; signingKeys?: Set<string> }> {
  const [apps, signingKeys] = await Promise.all([
    listConnectedApps({ storage: session.storage }),
    (async () => {
      try {
        return await currentAccountSigningKeys({ session })
      } catch (err) {
        console.warn(
          'Could not read the account key set for the app list:',
          err
        )
        return undefined
      }
    })()
  ])
  return { apps, signingKeys }
}

/**
 * Revokes one connected app's access. The grant state is derived first,
 * against the same verified key set the listing marked the row with: an
 * orphaned app's grants already stopped verifying with its signing client's
 * revocation, so the per-grant revocation POSTs are skipped while the epoch
 * rotation and the app-key deletion still run.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.app {ConnectedApp}
 * @param [options.signingKeys] {Set<string>}   the account's current signing
 *   keys, or undefined when the check was unavailable
 * @returns {Promise<{ grantsState: AppGrantsState, revoked: number }>}
 */
export async function revokeApplication({
  session,
  app,
  signingKeys
}: {
  session: Session
  app: ConnectedApp
  signingKeys?: Set<string>
}): Promise<{ grantsState: AppGrantsState; revoked: number }> {
  const grantsState = deriveAppGrantsState({
    app,
    currentSigningKeys: signingKeys
  })
  const outcome = await revokeAppAccess({
    storage: session.storage,
    user: session.user,
    app,
    grantsState
  })
  return { grantsState, revoked: outcome.revoked }
}
