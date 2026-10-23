/**
 * Keeping connected agents connected across a ceremony that ends their
 * grants, and the owner's decision about each one.
 *
 * Some ceremonies withdraw signing authority: a client revocation strikes the
 * revoked client's keys, a forget strikes this client's keys, and a
 * credential retirement strikes the credential's ladder VM. A grant to an
 * agent dies with the key that signed it. A root-anchored grant names its
 * signer in its own proof, and an annex-anchored grant names its minter in
 * its embedded parent's proof. {@link agentsSignedByWithdrawnAuthority}
 * reads, from one directory listing, which agents hold a grant those keys
 * signed, so a ceremony's dialog can list them before it runs.
 *
 * The owner ticks the agents to keep. An unticked agent gets the entry's
 * decline marker ({@link declineAgents}). Its grants stay dead and its row
 * stays listed for revocation. Once the ceremony resolves,
 * {@link reconnectAgents} re-mints each ticked agent's in-scope grants under
 * the session's current authority, records them as a fresh consent with the
 * envelope that carries them queued on the entry's `outbox`, writes one Grant
 * activity per agent, and then runs the Settings inbox pass, which pushes the
 * queued envelopes and renews in place any grant whose parent was replaced
 * while its signer still stands. A fresh consent clears the decline marker,
 * so the detail page's Restore runs the same re-mint.
 *
 * The in-scope grants are the latest record per scope that one connection
 * request's consent produced: GET and HEAD on a collection, and POST on
 * `inbox`. Each keeps its `controller`, its `invocationTarget` as stored, and
 * its `allowedAction`. The re-mint follows consent's parent rule: the visit's
 * generation delegation when the session holds one, the Space root
 * otherwise, with the share TTL limited by the parent's own `expires`. It
 * reads no proof check: the owner's tick is the consent.
 *
 * {@link lapsedAgentOffers} is the reader a page that offers a restore at a
 * later visit renders: the agents a recovery spend, a forget, or a failed
 * restore left with no live grant, and the lapsed connections.
 */
import {
  agentConnectionsSignedBy,
  markDeclined,
  recordGrants,
  verifyRecordedGrantProof,
  type ConnectionGrant,
  type ReadConnection
} from '@interop/wallet-core/connections'
import { SHARE_ZCAP_TTL_MS } from '@/app.config'
import { createLogger } from '@/lib/log'
import { renewTransientGenerationDelegation } from '@/session/annexReach'
import {
  addAgentGrantActivity,
  agentGrantEnvelope,
  agentsWithChannel,
  isLiveAgent,
  mintAgentGrants,
  pairwiseOf,
  renewableAgentGrants
} from '@/session/inboxPass'
import { renewAgentGrantsAfterCeremony } from '@/session/menders/encounterSites'
import { isSessionDisposed } from '@/session/sessionLifecycle'
import { verifiedAccountLog } from '@/session/verifiedLog'
import type { Session } from '@/types/auth'

const log = createLogger('fw:inbox')

/**
 * One connected agent a ceremony's dialog or an offer names.
 */
export interface AffectedAgent {
  /**
   * The entry's resource id, which keys the Applications detail route.
   */
  resourceId: string
  /**
   * The agent's DID, the entry's `id`.
   */
  did: string
  /**
   * The display name: the user's `label`, else the agent's own `name`.
   */
  name?: string
  /**
   * The entry's decline marker, when the owner declined it earlier.
   */
  declined?: string
}

/**
 * Why an agent's grants were not restored.
 *
 * - `no-space` -- the session has no remote Space to delegate under.
 * - `not-found` -- no unretired agent entry names the DID, or a revoke
 *   retired it while the restore ran.
 * - `nothing-in-scope` -- the entry holds no grant a connection request's
 *   consent produced, so there is nothing to re-mint and no channel to push
 *   through.
 * - `seed` -- the entry carries no pairwise seed, or its seed fails its tag.
 * - `no-signer-check` -- the account document could not be read.
 * - `parent-not-renewable` -- the generation delegation is stale and could
 *   not be renewed.
 * - `mint-failed` -- signing the grants failed.
 * - `record-failed` -- the entry write failed, or the session ended first.
 * - `push-failed` -- the grants are recorded and queued, but the push to the
 *   agent did not land in this pass.
 */
type AgentRestoreFailure =
  | 'no-space'
  | 'not-found'
  | 'nothing-in-scope'
  | 'seed'
  | 'no-signer-check'
  | 'parent-not-renewable'
  | 'mint-failed'
  | 'record-failed'
  | 'push-failed'

/**
 * What a restore did for one agent.
 */
export type AgentRestoreOutcome =
  | { did: string; name?: string; outcome: 'restored' }
  | {
      did: string
      name?: string
      outcome: 'not-restored'
      reason: AgentRestoreFailure
    }

/**
 * An agent row as a dialog or an offer names it.
 *
 * @param read {ReadConnection}
 * @returns {AffectedAgent}
 */
function affectedAgentOf(read: ReadConnection): AffectedAgent {
  const { entry } = read
  const name = entry.label ?? entry.name
  return {
    resourceId: read.resourceId,
    did: entry.id!,
    ...(name !== undefined && { name }),
    ...(entry.declined !== undefined && { declined: entry.declined })
  }
}

/**
 * The connected agents holding a grant any of the given keys signed, read
 * from one directory listing: a root-anchored grant signed by the key, or an
 * annex-anchored grant whose generation delegation the key minted
 * (wallet-core's `agentConnectionsSignedBy`). Each key is a
 * verification-method id in either DID form, or a bare multibase, and is
 * read against the verified account document as it stands before the
 * withdrawal, the same document each grant's signer resolves through. A
 * session with no remote Space, or no keys, names none. Throws when the
 * directory cannot be listed or the log cannot be verified.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.keys {string[]}   the withdrawn keys or ladder VM ids
 * @returns {Promise<AffectedAgent[]>}   in listing order
 */
export async function agentsSignedByWithdrawnAuthority({
  session,
  keys
}: {
  session: Session
  keys: string[]
}): Promise<AffectedAgent[]> {
  if (keys.length === 0 || !session.storage.hasRemoteStorage) {
    return []
  }
  const { listing, spaceUrl } = await session.storage.readConnectionsListing()
  if (spaceUrl === undefined) {
    return []
  }
  const { doc } = await verifiedAccountLog({ session })
  const entries = listing.entries.map(read => read.entry)
  const signed = new Set<string>()
  for (const keyId of keys) {
    for (const entry of agentConnectionsSignedBy({
      entries,
      keyId,
      spaceUrl,
      doc
    })) {
      signed.add(entry.id!)
    }
  }
  return listing.entries
    .filter(
      read =>
        isLiveAgent(read.entry) &&
        read.entry.id !== undefined &&
        signed.has(read.entry.id)
    )
    .map(affectedAgentOf)
}

/**
 * Writes the decline marker on each agent's entry (wallet-core's
 * `markDeclined`): the owner left it unticked in a ceremony dialog, or
 * declined its offer. An entry already declined keeps its time. A failed
 * write is logged and reported, and the rest still run.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.dids {string[]}   the agents' DIDs
 * @returns {Promise<{ declined: string[], failed: string[] }>}
 */
export async function declineAgents({
  session,
  dids
}: {
  session: Session
  dids: string[]
}): Promise<{ declined: string[]; failed: string[] }> {
  const declined: string[] = []
  const failed: string[] = []
  if (dids.length === 0) {
    return { declined, failed }
  }
  let directory
  try {
    directory = await session.storage.connectionsDirectory()
  } catch (err) {
    log.warn('Could not open the directory to record a decline', { err })
    return { declined, failed: [...dids] }
  }
  const { store, hmacKey } = directory
  for (const did of dids) {
    try {
      await markDeclined({ store, hmacKey, did })
      declined.push(did)
    } catch (err) {
      log.warn("Could not record the owner's decline of an agent", {
        did,
        err
      })
      failed.push(did)
    }
  }
  return { declined, failed }
}

/**
 * A failed outcome for one agent.
 *
 * @param options {object}
 * @param options.did {string}
 * @param [options.name] {string}
 * @param options.reason {AgentRestoreFailure}
 * @returns {AgentRestoreOutcome}
 */
function notRestored({
  did,
  name,
  reason
}: {
  did: string
  name?: string
  reason: AgentRestoreFailure
}): AgentRestoreOutcome {
  return {
    did,
    ...(name !== undefined && { name }),
    outcome: 'not-restored',
    reason
  }
}

/**
 * Re-mints the in-scope grants of each named agent under the session's
 * current authority, and records each agent's as a fresh consent with the
 * envelope that carries them queued on its `outbox`, plus one Grant
 * activity. Pushes nothing. A declined entry with nothing to re-mint still
 * has its marker cleared, by a zero-grant consent. Every record leaves a
 * retired entry as stored (`unlessRetired`): a revoke that landed between
 * the listing and the write ended the connection, and the agent reads
 * `not-found`.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.dids {string[]}
 * @param options.now {Date}
 * @returns {Promise<AgentRestoreOutcome[]>}   one per DID, in order
 */
async function remintAgentGrants({
  session,
  dids,
  now
}: {
  session: Session
  dids: string[]
  now: Date
}): Promise<AgentRestoreOutcome[]> {
  if (!session.storage.hasRemoteStorage) {
    return dids.map(did => notRestored({ did, reason: 'no-space' }))
  }
  const { store, hmacKey, spaceUrl, listing } =
    await session.storage.readConnectionsListing()
  if (spaceUrl === undefined) {
    return dids.map(did => notRestored({ did, reason: 'no-space' }))
  }
  const outcomes = new Map<string, AgentRestoreOutcome>()
  // One agent the re-mint works on: its listing row, its display name, its
  // pairwise did:key, and the grants to re-mint.
  const plans: Array<{
    read: ReadConnection
    name?: string
    pairwiseDid: string
    sources: ConnectionGrant[]
  }> = []
  for (const did of dids) {
    const read = listing.entries.find(
      candidate => isLiveAgent(candidate.entry) && candidate.entry.id === did
    )
    if (read === undefined) {
      outcomes.set(did, notRestored({ did, reason: 'not-found' }))
      continue
    }
    const { entry } = read
    const { name } = affectedAgentOf(read)
    const sources = renewableAgentGrants({ entry, spaceUrl })
    if (sources.length === 0) {
      if (entry.declined !== undefined) {
        try {
          await recordGrants({
            store,
            hmacKey,
            did,
            kind: 'agent',
            spaceUrl,
            grants: [],
            unlessRetired: true,
            now
          })
        } catch (err) {
          log.warn("Could not clear an agent's decline marker", { did, err })
        }
      }
      outcomes.set(did, notRestored({ did, name, reason: 'nothing-in-scope' }))
      continue
    }
    let pairwise
    try {
      pairwise = await pairwiseOf({ entry, hmacKey })
    } catch (err) {
      log.warn("An agent entry's seed fails its tag; not restored", {
        did,
        err
      })
    }
    if (pairwise === undefined) {
      outcomes.set(did, notRestored({ did, name, reason: 'seed' }))
      continue
    }
    plans.push({
      read,
      ...(name !== undefined && { name }),
      pairwiseDid: pairwise.did,
      sources
    })
  }
  const inOrder = (): AgentRestoreOutcome[] =>
    dids.map(did => outcomes.get(did)!)
  const failAll = (reason: AgentRestoreFailure): AgentRestoreOutcome[] => {
    for (const { read, name } of plans) {
      const did = read.entry.id!
      outcomes.set(did, notRestored({ did, name, reason }))
    }
    return inOrder()
  }
  if (plans.length === 0) {
    return inOrder()
  }
  const check = await session.storage.renewalSignerCheck()
  if (check === undefined) {
    return failAll('no-signer-check')
  }
  const notAfter = new Date(now.getTime() + SHARE_ZCAP_TTL_MS)
  let minted
  try {
    minted = await mintAgentGrants({
      session,
      sources: plans.map(plan => plan.sources),
      doc: check.doc,
      renewParent: async () =>
        await renewTransientGenerationDelegation({ session }),
      notAfterOf: () => notAfter
    })
  } catch (err) {
    log.warn("Could not mint an agent's restored grants", { err })
    return failAll('mint-failed')
  }
  if (minted === undefined) {
    return failAll('parent-not-renewable')
  }
  for (const [index, { read, name, pairwiseDid, sources }] of plans.entries()) {
    const zcaps = minted[index]!
    const did = read.entry.id!
    if (isSessionDisposed({ session })) {
      outcomes.set(did, notRestored({ did, name, reason: 'record-failed' }))
      continue
    }
    let recorded
    try {
      recorded = await recordGrants({
        store,
        hmacKey,
        did,
        kind: 'agent',
        spaceUrl,
        grants: zcaps.map((zcap, zcapIndex) => ({
          zcap,
          grantKind: sources[zcapIndex]!.grantKind
        })),
        message: agentGrantEnvelope({ pairwiseDid, zcaps }),
        // A revoke that landed since the listing retired the entry, and
        // the restore must not un-retire it.
        unlessRetired: true,
        now
      })
    } catch (err) {
      log.warn("Could not record an agent's restored grants; discarded", {
        did,
        err
      })
      outcomes.set(did, notRestored({ did, name, reason: 'record-failed' }))
      continue
    }
    if (recorded.outcome === 'unchanged') {
      log.info('An agent was revoked while its restore ran; not restored', {
        did
      })
      outcomes.set(did, notRestored({ did, name, reason: 'not-found' }))
      continue
    }
    outcomes.set(did, {
      did,
      ...(name !== undefined && { name }),
      outcome: 'restored'
    })
    try {
      await addAgentGrantActivity({ session, entry: read.entry, zcaps })
    } catch (err) {
      log.warn('Could not record the restore Grant activity', { did, err })
    }
  }
  return inOrder()
}

/**
 * Restores the named agents' in-scope grants as a fresh consent, then runs
 * the Settings inbox pass (`renewAgentGrantsAfterCeremony`), which pushes
 * the queued envelopes and silently renews grants whose parent was replaced
 * while its signer still stands. With no DIDs, only the pass runs: what a
 * ceremony that withdrew no agent's authority raises once it resolves. An
 * agent whose push the pass reports as failed reads `push-failed`. Never
 * rejects: a directory that cannot be read reports every agent
 * `record-failed`.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.dids {string[]}   the ticked or restored agents' DIDs
 * @param [options.now] {Date}
 * @returns {Promise<{ agents: AgentRestoreOutcome[] }>}   the per-agent
 *   outcomes
 */
export async function reconnectAgents({
  session,
  dids,
  now = new Date()
}: {
  session: Session
  dids: string[]
  now?: Date
}): Promise<{ agents: AgentRestoreOutcome[] }> {
  let agents: AgentRestoreOutcome[] = []
  if (dids.length > 0) {
    try {
      agents = await remintAgentGrants({ session, dids, now })
    } catch (err) {
      log.warn('Could not read the directory to restore agents', { err })
      agents = dids.map(did => notRestored({ did, reason: 'record-failed' }))
    }
  }
  const pass = await renewAgentGrantsAfterCeremony({ session })
  const pushFailed = new Set(
    pass.outcome.pushFailures.map(failure => failure.agentDid)
  )
  return {
    agents: agents.map(agent =>
      agent.outcome === 'restored' && pushFailed.has(agent.did)
        ? notRestored({ ...agent, reason: 'push-failed' })
        : agent
    )
  }
}

/**
 * The agents a later visit offers for a one-tick restore: every unretired
 * agent entry with no decline marker, holding a live channel, whose in-scope
 * grants are all past their `expires` or fail the proof check against the
 * current account document (signed by withdrawn authority). An entry with no
 * in-scope grant is not offered. Reads one directory listing. A session with
 * no remote Space, a guest, or an account document that cannot be read
 * offers none. Throws when the directory cannot be listed.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.now] {Date}
 * @returns {Promise<AffectedAgent[]>}   in listing order
 */
export async function lapsedAgentOffers({
  session,
  now = new Date()
}: {
  session: Session
  now?: Date
}): Promise<AffectedAgent[]> {
  if (!session.storage.hasRemoteStorage || session.isGuest) {
    return []
  }
  const { hmacKey, spaceUrl, listing } =
    await session.storage.readConnectionsListing()
  if (spaceUrl === undefined) {
    return []
  }
  // The synchronous filters run first, so a pairwise key is derived only for
  // an entry that could be offered.
  const inScope = new Map<string, ConnectionGrant[]>()
  for (const read of listing.entries) {
    if (!isLiveAgent(read.entry) || read.entry.declined !== undefined) {
      continue
    }
    const grants = renewableAgentGrants({ entry: read.entry, spaceUrl })
    if (grants.length > 0) {
      inScope.set(read.resourceId, grants)
    }
  }
  if (inScope.size === 0) {
    return []
  }
  const withChannel = await agentsWithChannel({
    entries: listing.entries.filter(read => inScope.has(read.resourceId)),
    hmacKey,
    spaceUrl,
    now
  })
  if (withChannel.length === 0) {
    return []
  }
  const signerCheck = await session.storage.renewalSignerCheck()
  if (signerCheck === undefined) {
    return []
  }
  const lapsed = await Promise.all(
    withChannel.map(async ({ read }) => {
      const results = await Promise.all(
        inScope.get(read.resourceId)!.map(
          async grant =>
            Date.parse(grant.expires) <= now.getTime() ||
            !(
              await verifyRecordedGrantProof({
                zcap: grant.zcap,
                signerCheck
              })
            ).verified
        )
      )
      return results.every(Boolean)
    })
  )
  return withChannel
    .filter((_, index) => lapsed[index])
    .map(({ read }) => affectedAgentOf(read))
}
