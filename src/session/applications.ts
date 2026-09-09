/**
 * The Applications surface's glue: listing the apps connected through App
 * Connect and the agents granted access from an interaction-URL request,
 * alongside the account key set their grants are checked against, and revoking
 * one app's or one agent's access. The page renders and confirms; the reads,
 * the best-effort degradation, and the revocation calls live here.
 */
import { currentAccountSignerCheck } from '@/session/clients'
import {
  deriveGrantsState,
  listConnectedAgents,
  listConnectedApps,
  revokeAgentAccess,
  revokeAppAccess,
  type AccountSignerCheck,
  type ConnectedAgent,
  type ConnectedApp
} from '@/lib/connectedApps'
import type { GrantSignerState } from '@interop/wallet-core/clients'
import type { Session } from '@/types/auth'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:applications')

/**
 * Lists the connected apps and agents together with the account DID and the
 * enrolled clients' signing keys from the verified account log, for the
 * per-row grant-state check.
 *
 * The key-set half is best-effort: a session without a promoted account (or a
 * log that cannot be fetched right now) degrades to listing the rows without
 * an orphaned marker (`signerCheck: undefined`), never to failing the page.
 *
 * Both listings join over the activity history, so it is read and decrypted
 * once here and passed through to each -- on a replica-less session that read
 * is a remote fan-out, and running it twice per page load doubles it.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<{ apps: ConnectedApp[], agents: ConnectedAgent[],
 *   signerCheck?: AccountSignerCheck }>}
 */
export async function listApplicationsView({
  session
}: {
  session: Session
}): Promise<{
  apps: ConnectedApp[]
  agents: ConnectedAgent[]
  signerCheck?: AccountSignerCheck
}> {
  const history = session.storage.listHistoryItems()
  const [apps, agents, signerCheck] = await Promise.all([
    history.then(items =>
      listConnectedApps({ storage: session.storage, items })
    ),
    history.then(items =>
      listConnectedAgents({ storage: session.storage, items })
    ),
    (async () => {
      try {
        return await currentAccountSignerCheck({ session })
      } catch (err) {
        log.warn('Could not read the account key set for the app list', {
          err
        })
        return undefined
      }
    })()
  ])
  return { apps, agents, signerCheck }
}

/**
 * Revokes one connected app's access and words the outcome. The grant state
 * is derived first, against the same verified key set the listing marked the
 * row with, and feeds the wording alone. It does not gate the revocation
 * itself: the recorded revocations are always POSTed, for the reason
 * `revokeAppAccess` states (a transient session's grants derive as unknown,
 * and only the server can say whether their chain is still alive).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.app {ConnectedApp}
 * @param [options.signerCheck] {AccountSignerCheck}   the account DID and
 *   its current signing keys, or undefined when the check was unavailable
 * @returns {Promise<{ outcomeKey: string }>}   the i18n key of the toast to
 *   show ({@link revokeOutcomeKey})
 */
export async function revokeApplication({
  session,
  app,
  signerCheck
}: {
  session: Session
  app: ConnectedApp
  signerCheck?: AccountSignerCheck
}): Promise<{ outcomeKey: string }> {
  const grantsState = deriveGrantsState({ grants: app.grants, signerCheck })
  const outcome = await revokeAppAccess({
    storage: session.storage,
    user: session.user,
    app
  })
  // The rotation revokes an app-provisioned collection's pull grant with the
  // epoch, and the second stage's re-POST of that same capability comes back
  // "already revoked" and counts as skipped -- so `revoked` alone reads as
  // zero for an app whose only grant was just withdrawn.
  return {
    outcomeKey: revokeOutcomeKey({
      grantsState,
      withdrew: outcome.revoked > 0 || outcome.rotated > 0
    })
  }
}

/**
 * The i18n key of the toast an app revocation ends with. What actually
 * happened outranks the row's marker: the revocations are POSTed whatever it
 * says, so a row whose chain was still alive reads as revoked, not as access
 * that had already ended. `withdrew` spans both stages, so a single
 * app-provisioned collection -- whose pull grant the rotation revokes, leaving
 * the second stage nothing but an already-revoked POST -- still reads as
 * revoked. When nothing was withdrawn, an orphaned row names the disconnect
 * that ended its access; any other row reads as access that had already
 * ended, with no cause claimed, since the account document cannot name one:
 * its recorded grants were all refused or expired (a transient session's
 * grant after its generation was collected, or one past its own expiry), or
 * it recorded no revocable capability at all.
 *
 * @param options {object}
 * @param options.grantsState {GrantSignerState}
 * @param options.withdrew {boolean}
 * @returns {string}
 */
export function revokeOutcomeKey({
  grantsState,
  withdrew
}: {
  grantsState: GrantSignerState
  withdrew: boolean
}): string {
  if (withdrew) {
    return 'applications.revokeSuccess'
  }
  return grantsState === 'orphaned'
    ? 'applications.revokeSuccessOrphaned'
    : 'applications.revokeSuccessEnded'
}

/**
 * Revokes one connected agent's storage grants. Unlike the app path this takes
 * no grant state: an agent grant delegated from a transient session is signed
 * by an annex key the account document never lists yet keeps verifying under
 * the generation delegation, so only the server can say whether the chain is
 * dead. A genuinely dead chain comes back from the server as a skipped no-op.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.agent {ConnectedAgent}
 * @returns {Promise<{ revoked: number }>}
 */
export async function revokeAgent({
  session,
  agent
}: {
  session: Session
  agent: ConnectedAgent
}): Promise<{ revoked: number }> {
  const outcome = await revokeAgentAccess({
    storage: session.storage,
    user: session.user,
    agent
  })
  return { revoked: outcome.revoked }
}
