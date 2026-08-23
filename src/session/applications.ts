/**
 * The Applications surface's glue: listing the apps connected through App
 * Connect and the agents granted access from an interaction-URL request,
 * alongside the account key set their grants are checked against, and revoking
 * one app's or one agent's access. The page renders and confirms; the reads,
 * the best-effort degradation, and the revocation calls live here.
 */
import { currentAccountSigningKeys } from '@/session/clients'
import {
  deriveAppGrantsState,
  deriveGrantsState,
  listConnectedAgents,
  listConnectedApps,
  revokeAgentAccess,
  revokeAppAccess,
  type AppGrantsState,
  type ConnectedAgent,
  type ConnectedApp
} from '@/lib/connectedApps'
import type { Session } from '@/types/auth'

/**
 * Lists the connected apps and agents together with the enrolled clients'
 * signing keys from the verified account log, for the per-row grant-state
 * check.
 *
 * The key-set half is best-effort: a session without a promoted account (or a
 * log that cannot be fetched right now) degrades to listing the rows without
 * an orphaned marker (`signingKeys: undefined`), never to failing the page.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<{ apps: ConnectedApp[], agents: ConnectedAgent[],
 *   signingKeys?: Set<string> }>}
 */
export async function listApplicationsView({
  session
}: {
  session: Session
}): Promise<{
  apps: ConnectedApp[]
  agents: ConnectedAgent[]
  signingKeys?: Set<string>
}> {
  const [apps, agents, signingKeys] = await Promise.all([
    listConnectedApps({ storage: session.storage }),
    listConnectedAgents({ storage: session.storage }),
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
  return { apps, agents, signingKeys }
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

/**
 * Revokes one connected agent's storage grants. The grant state is derived
 * first, against the same verified key set the listing marked the row with: an
 * orphaned agent's grants already stopped verifying with its signing client's
 * revocation, so the revocation POSTs are skipped while the revocation is
 * still recorded (which is what takes the row out of the listing).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.agent {ConnectedAgent}
 * @param [options.signingKeys] {Set<string>}   the account's current signing
 *   keys, or undefined when the check was unavailable
 * @returns {Promise<{ grantsState: AppGrantsState, revoked: number }>}
 */
export async function revokeAgent({
  session,
  agent,
  signingKeys
}: {
  session: Session
  agent: ConnectedAgent
  signingKeys?: Set<string>
}): Promise<{ grantsState: AppGrantsState; revoked: number }> {
  const grantsState = deriveGrantsState({
    grants: agent.grants,
    currentSigningKeys: signingKeys
  })
  const outcome = await revokeAgentAccess({
    storage: session.storage,
    user: session.user,
    agent,
    grantsState
  })
  return { grantsState, revoked: outcome.revoked }
}
