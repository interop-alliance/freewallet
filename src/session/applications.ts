/**
 * The Applications surface's glue: listing the apps connected through App
 * Connect and the agents granted access from an interaction-URL request, off
 * one read of the `connections` directory, alongside the account key set
 * their grants are checked against, and revoking one app's or one agent's
 * access. The page renders and confirms; the reads, the best-effort
 * degradation, and the revocation calls live here.
 */
import { readDirectoryListing } from '@/session/clients'
import { currentAccountSignerCheck } from '@/session/accountSignerCheck'
import {
  listConnectedAgents,
  listConnectedApps,
  revokeAgentAccess,
  revokeAppAccess,
  type AccountSignerCheck,
  type ConnectedAgent,
  type ConnectedApp,
  type GrantRevocationStage
} from '@/lib/connectedApps'
import { ceremonyEvents, type CeremonyEmitter } from '@interop/wallet-core'
import type { GrantSignerState } from '@interop/wallet-core/clients'
import type { Session } from '@/types/auth'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:applications')

/**
 * The grant revocation's typed refusals on the ceremony event channel,
 * matched by `err.name`. Every other throw classifies as `failed`.
 */
const GRANT_REVOCATION_REFUSALS = ['ConnectionEntryMissingError']

/**
 * Mints one grant revocation run's emitter, at the entry point the user's
 * click reaches. The shared rotate-then-revoke tail beside the client
 * revocation and the forget emits nothing of its own.
 *
 * @returns {CeremonyEmitter<GrantRevocationStage>}
 */
export function grantRevocationEvents(): CeremonyEmitter<GrantRevocationStage> {
  return ceremonyEvents<GrantRevocationStage>({
    ceremony: 'grant-revocation',
    log,
    refusals: GRANT_REVOCATION_REFUSALS
  })
}

/**
 * The outcome a completed party revocation classifies as. It is always
 * `clean`, since a run that returns has retired the entry and recorded the
 * revocation, even when the access itself had already ended. The detail
 * carries the counts only.
 *
 * @param result {object}
 * @param result.revoked {number}
 * @param result.withdrawn {number}
 * @param result.skipped {number}
 * @param result.rotated {number}
 * @returns {{ outcome: 'clean', detail: object }}
 */
function partyRevocationOutcome(result: {
  revoked: number
  withdrawn: number
  skipped: number
  rotated: number
}): {
  outcome: 'clean'
  detail: {
    revoked: number
    withdrawn: number
    skipped: number
    rotated: number
  }
} {
  const { revoked, withdrawn, skipped, rotated } = result
  return {
    outcome: 'clean',
    detail: { revoked, withdrawn, skipped, rotated }
  }
}

/**
 * Lists the connected apps and agents together with the account DID and the
 * enrolled clients' signing keys from the verified account log, for the
 * per-row grant-state check.
 *
 * Both listings read the one directory listing, matched in memory. The
 * app-key health read (`listAppKeys`) runs beside it, since the page's
 * undecryptable and no-epoch-key warnings and its purge button read the
 * counts that scan leaves on the storage manager; a failed health read is
 * logged and leaves the counts as they were.
 *
 * The key-set half is best-effort: a session without a promoted account (or a
 * log that cannot be fetched right now) degrades to listing the rows without
 * an orphaned marker (`signerCheck: undefined`), never to failing the page.
 * A directory that cannot be listed fails the listing.
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
  const [{ connections, spaceUrl }, signerCheck] = await Promise.all([
    readDirectoryListing({ session }),
    (async () => {
      try {
        return await currentAccountSignerCheck({ session })
      } catch (err) {
        log.warn('Could not read the account key set for the app list', {
          err
        })
        return undefined
      }
    })(),
    (async () => {
      try {
        await session.storage.listAppKeys()
      } catch (err) {
        log.warn('Could not read the app-key collection', { err })
      }
    })()
  ])
  const apps = listConnectedApps({ connections, spaceUrl })
  const agents = await listConnectedAgents({
    storage: session.storage,
    connections,
    spaceUrl
  })
  return { apps, agents, signerCheck }
}

/**
 * Revokes one connected app's access and words the outcome. The grant state
 * the listing marked the row with feeds the wording. `revokeAppAccess`
 * reads the storage manager's own verified-document reading, skipping the
 * POST for a grant that document already reads as dead (expired, orphaned,
 * or chained under a rotted parent delegation) and POSTing every other one,
 * a transient session's grants included, since those derive as unknown
 * while their generation delegation may still stand. This is the grant
 * revocation ceremony's app entry point, and it emits the run's events.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.app {ConnectedApp}
 * @param options.grantsState {GrantSignerState}   the row's grant state as
 *   the listing derived it (`deriveGrantsState`); feeds the wording
 *   alone
 * @returns {Promise<{ outcomeKey: string }>}   the i18n key of the toast to
 *   show ({@link revokeOutcomeKey})
 */
export async function revokeApplication({
  session,
  app,
  grantsState
}: {
  session: Session
  app: ConnectedApp
  grantsState: GrantSignerState
}): Promise<{ outcomeKey: string }> {
  const events = grantRevocationEvents()
  const outcome = await events.run(
    async () =>
      await revokeAppAccess({
        storage: session.storage,
        user: session.user,
        app,
        onStage: (stage, detail) => events.stage(stage, detail)
      }),
    partyRevocationOutcome
  )
  // Only what this run took away counts. `withdrawn` leaves out a grant
  // the server answered `AlreadyRevokedError`. A collection this run
  // re-keyed counts on its own, and it covers the pull-axis grants the
  // rotation revoked, since its grants may all have expired while the
  // rotation still took the app off the current epoch.
  return {
    outcomeKey: revokeOutcomeKey({
      grantsState,
      withdrew: outcome.withdrawn > 0 || outcome.rotated > 0
    })
  }
}

/**
 * The i18n key of the toast an app revocation ends with. What actually
 * happened outranks the row's marker: the revocations are POSTed whatever it
 * says, so a row whose chain was still alive reads as revoked, not as access
 * that had already ended. `withdrew` spans both stages, counting only what
 * this run took away: a grant whose POST landed, or a collection this run
 * re-keyed. So a rotation whose grants had all expired still reads as
 * revoked, while a grant the server had already revoked does not. A revoke
 * that left the app a recipient of some collection's current epoch reaches
 * no wording at all: `revokeAppAccess` throws on a failed
 * rotation, so the page shows its failure copy and keeps the row.
 * When nothing was withdrawn, an orphaned row names the disconnect
 * that ended its access; any other row reads as access that had already
 * ended, with no cause claimed, since the account document cannot name one:
 * its recorded grants were all dead before this run (a transient session's
 * grant after its generation delegation rotted, one past its own expiry, or
 * one the server had already revoked), or it recorded no revocable
 * capability at all.
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
 * Revokes one connected agent's storage grants and words the outcome.
 * `revokeAgentAccess` reads the storage manager's own verified-document
 * reading exactly as the app path does: a grant the verified document already
 * reads as dead is skipped without a POST, and every other one is POSTed, a
 * transient session's included, since its annex signer derives as unknown
 * while its generation delegation may still stand. This is the grant
 * revocation ceremony's agent entry point, and it emits the run's events.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.agent {ConnectedAgent}
 * @returns {Promise<{ outcomeKey: string }>}   the i18n key of the toast to
 *   show ({@link agentRevokeOutcomeKey})
 */
export async function revokeAgent({
  session,
  agent
}: {
  session: Session
  agent: ConnectedAgent
}): Promise<{ outcomeKey: string }> {
  const events = grantRevocationEvents()
  const outcome = await events.run(
    async () =>
      await revokeAgentAccess({
        storage: session.storage,
        user: session.user,
        agent,
        onStage: (stage, detail) => events.stage(stage, detail)
      }),
    partyRevocationOutcome
  )
  return {
    outcomeKey: agentRevokeOutcomeKey({
      withdrew: outcome.withdrawn > 0 || outcome.rotated > 0
    })
  }
}

/**
 * The i18n key of the toast an agent revocation ends with. `withdrew` spans
 * both stages, as on the app path: a grant whose POST landed on this run, or
 * a collection this run re-keyed. A grant the server had already revoked, an
 * expired grant, and one the verified document reads as dead do not count,
 * since that access was already over.
 *
 * @param options {object}
 * @param options.withdrew {boolean}
 * @returns {string}
 */
export function agentRevokeOutcomeKey({
  withdrew
}: {
  withdrew: boolean
}): string {
  return withdrew
    ? 'applications.revokeAgentSuccess'
    : 'applications.revokeAgentSuccessEnded'
}
