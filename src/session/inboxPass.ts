/**
 * The inbox pass: the drain of the account's own `inbox`, then the renewal
 * of the connected agents' grants, then the push of each agent entry's
 * `outbox`. One pass runs after either login chain's block (the tail
 * registration), when the Notifications page opens, and on the Settings page
 * after a ceremony that replaces the generation delegation. Passes on one
 * session never overlap: each waits for the one before it.
 *
 * The drain. The `inbox` is plaintext mail a connected agent posts into: a
 * `Grant` envelope (`parseInboxGrantMessage`) carrying the capability that
 * lets the wallet post into the agent's own inbox (a channel capability). The
 * listing is walked page by page until it is empty, or until the pass has
 * read its byte cap. Each message's metadata is read before its body. The
 * sender is the server-recorded `createdBy`, looked up in the directory
 * listing the pass read. No GET is made at a derived id. A sender the listing
 * does not name gets one listing re-read per pass, since a consent may have
 * written its entry after the first read. Each sender has a byte budget per
 * pass, and a sender past it has its remaining messages left for the next
 * pass. The body's `actor` must equal `createdBy`, and the sender's seed must
 * pass its tag before its pairwise did:key is derived. A channel capability
 * is stored through `recordReceivedGrants`. A capability that targets this
 * Space is ignored and logged: the wallet accepts no renewed grant from an
 * agent. The wallet does not verify a received capability's delegation
 * chain; the agent's server checks it at invocation. Every message is
 * deleted after it is acted on or refused, and a delete that finds it gone
 * counts as done.
 *
 * The renewal. It reads the listing as the drain left it, so a channel the
 * drain just stored is seen. Every unretired agent entry carrying a seed and
 * a live channel is a candidate. Of its grants, only the latest record per
 * scope is read, and only one inside the renewal scope (the reads and the
 * inbox POST one connection request's consent produced). The consent stamps
 * that scope reads come from every inbox grant record on the entry, so a
 * later connection request does not drop an earlier one's reads. A grant is renewed
 * when its proof verifies as this account's against the current document
 * and it is due (`agentGrantDue`). The pointed generation delegation's id is
 * read from the generation log's head, not from memory. Renewals are
 * minted under consent's parent rule, a stale generation delegation renewed
 * first, and recorded through `recordRenewedGrants`, the pivot, which queues
 * the envelope on the entry's `outbox` in the same compare-and-swap. One
 * Grant activity is written per renewed entry per pass.
 *
 * The outbox. Each entry's pending envelopes are POSTed through its live
 * channel, invoking that capability as the pairwise did:key. A delivered
 * item is removed. A network failure or a 5xx keeps it for the next pass. An
 * authorization refusal (401 or 403) stops the pushes to that entry for the
 * pass, and so does a 404, since a WAS host answers every capability denial
 * (revoked, expired, unauthorized) with one. The refused channel record is
 * dropped from the entry (`dropReceivedGrant`), and the queued envelopes
 * stay on the outbox. The next pass pushes nothing to an entry with no
 * channel, and that entry's waiting items do not grade the pass `partial`.
 * The agent's next invitation stores the replacement channel whatever its
 * `expires`, since the dropped record is gone, and the pass after that
 * pushes the queue. A refusal that was not the agent's doing (an agent
 * server whose clock skew answers 401, a 404 during its redeploy) drops the
 * channel too, and only the agent's next invitation brings it back. Until
 * then the renewals queue undelivered, and at worst the agent's grants lapse
 * at their own `expires` and the agent re-invites. That cost is accepted: a
 * 401, 403, or 404 from the agent's own host is that host's answer about the
 * capability, and keeping the record cost one wasted request per pass for
 * the channel's whole life, plus a `partial` grade on every pass that hid a
 * real one. Pushes run in parallel up to a limit, under one time budget per
 * pass. Superseded grant records and outbox items no push can deliver are
 * pruned last.
 *
 * Grading. A listing, read, write, or push failure is `partial`, which does
 * not spend an encounter's once-per-session budget. So is a renewal skipped
 * because its parent's remaining life would not let it outlast its source
 * (`parent-too-short`), since that grant stays due. `refused` is kept for an
 * absent or untrusted `inbox`. Each pass also builds an outcome a
 * Notifications page renders: invitations received, renewals pushed,
 * messages refused per sender and reason, and push failures.
 *
 * Audience targets and the inbox target carry no `*` marker in this build,
 * since the authorization profile that defines it has not shipped. The
 * same-scope comparison reads the target as stored, so a renewal keeps
 * whatever form the consent recorded.
 */
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { httpStatus } from '@interop/pws-client'
import {
  classifyGrantRevocationRefusal,
  embeddedGenerationDelegation,
  type AccountSignerCheck
} from '@interop/wallet-core/clientAnnex'
import {
  agentGrantDue,
  connectionDidKey,
  connectionGrants,
  grantScopeKey,
  isTargetInSpace,
  latestGrantsPerScope,
  latestIndexPerScope,
  liveInboxChannel,
  normalizedActions,
  parseConnectionEntry,
  pruneSupersededGrants,
  dropReceivedGrant,
  receivedGrants,
  recordReceivedGrants,
  recordRenewedGrants,
  renewalScopeGrants,
  settleOutboxItem,
  verifyRecordedGrantProof,
  type ConnectionEntry,
  type ConnectionGrant,
  type ConnectionIdKey,
  type ConnectionZcap,
  type ConnectionsStore,
  type ReadConnection
} from '@interop/wallet-core/connections'
import { errorNameOf, type MendReportEntry } from '@interop/wallet-core/menders'
import {
  inboxGrantMessage,
  parseInboxGrantMessage,
  type InboxMessageZcap
} from '@interop/wallet-core/space'
import {
  REVOCATION_CLOCK_SKEW_MS,
  STANDING_ZCAP_TTL_MS,
  standingZcapStale,
  type PublishedKeyDocument
} from '@interop/wallet-core/webvh'
import type { CeremonyId } from '@interop/wallet-core'
import {
  AGENT_GRANT_RENEWAL_WINDOW_MS,
  INBOX_DRAIN_BYTE_CAP,
  INBOX_MESSAGE_MAX_BYTES,
  INBOX_PUSH_PARALLELISM,
  INBOX_PUSH_TIME_BUDGET_MS,
  INBOX_SENDER_BYTE_BUDGET,
  SHARE_ZCAP_TTL_MS
} from '@/app.config'
import { createLogger } from '@/lib/log'
import { EXTERNAL_REQUEST_ORIGIN } from '@/lib/walletRequest/externalRequest'
import { forcedAgentGrantRenewalWindowMs } from '@/lib/e2eSeams'
import type { InboxRead } from '@/stores/storageManager'
import { renewTransientGenerationDelegation } from '@/session/annexReach'
import { isSessionDisposed } from '@/session/sessionLifecycle'
import type { Session } from '@/types/auth'

const log = createLogger('fw:inbox')

/**
 * The two invariants one pass reports, in report order.
 */
export const INBOX_PASS_REPORTS = [
  'inbox-is-drained',
  'agent-grants-are-current'
] as const

/**
 * Why the drain refused a message. Every refused message is deleted.
 *
 * - `no-creator` -- the server recorded no `createdBy`.
 * - `content-type` -- not `application/json`.
 * - `oversized` -- over the size bound, or no size reported.
 * - `unknown-sender` -- no unretired agent entry names the creator.
 * - `seedless-sender` -- the creator's entry carries no pairwise seed, or a
 *   seed with no tag.
 * - `seed-tag` -- the creator's seed fails its tag.
 * - `malformed` -- the body is not a Grant envelope, or a capability in it
 *   is not one the directory can record.
 * - `actor-mismatch` -- the envelope's `actor` is not the creator.
 */
type InboxRefusalReason =
  | 'no-creator'
  | 'content-type'
  | 'oversized'
  | 'unknown-sender'
  | 'seedless-sender'
  | 'seed-tag'
  | 'malformed'
  | 'actor-mismatch'

/**
 * Why a push did not deliver an outbox item.
 *
 * - `channel-refused` -- the agent's server answered 401, 403, or 404: the
 *   channel capability is expired or revoked. A WAS host answers every
 *   capability denial with a 404. Pushes to the entry stop, and the channel
 *   record is dropped from the entry. The items wait for the agent's next
 *   invitation.
 * - `network` -- no response, or a 5xx. The item waits for the next pass.
 * - `rejected` -- any other refusal. The item waits for the next pass.
 * - `no-channel` -- the entry holds no live channel. The item waits for the
 *   agent's next invitation. It is listed, and is not a failure of the pass.
 * - `seed-tag` -- the entry's seed fails its tag, so no pairwise key signs.
 * - `timed-out` -- the pass's push time budget ran out first.
 */
type InboxPushFailureReason =
  | 'channel-refused'
  | 'network'
  | 'rejected'
  | 'no-channel'
  | 'seed-tag'
  | 'timed-out'

/**
 * What one pass, or one visit's passes together, did for the owner to read:
 * the invitations received (the agent and the channel's effective expiry),
 * the renewals pushed (the agent and the grants), the messages refused (a
 * count per sender and reason), and the push failures (the agent and why).
 */
export interface InboxPassOutcome {
  invitations: Array<{
    agentDid: string
    agentName?: string
    channelExpires: string
  }>
  renewalsPushed: Array<{
    agentDid: string
    agentName?: string
    grants: Array<{
      id: string
      target: string
      allowedActions: string[]
      expires: string
    }>
  }>
  refused: Array<{
    sender?: string
    reason: InboxRefusalReason
    count: number
  }>
  pushFailures: Array<{
    agentDid: string
    agentName?: string
    reason: InboxPushFailureReason
  }>
}

/**
 * The seams one pass reaches past the storage manager, injectable so a test
 * can drive a pass with no server: the pointed generation delegation's id,
 * the push to an agent's inbox, the in-place renewal of a stale generation
 * delegation, and the clock.
 */
interface InboxPassDeps {
  readPointedDelegationId: (options: {
    check: AccountSignerCheck
  }) => Promise<string | undefined>
  push: (options: {
    channel: ConnectionZcap
    message: Record<string, unknown>
    zcapClient: ZcapClient
  }) => Promise<void>
  renewParent: (options: { session: Session }) => Promise<IZcap | null>
  now: () => Date
}

/**
 * The directory one pass works over: the store and key every write takes,
 * this Space's container URL, the listing the pass keeps current, and the
 * pass's pairwise derivations. An entry the pass wrote replaces its copy once
 * it is read back.
 */
interface PassDirectory {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  spaceUrl: string
  entries: Map<string, ReadConnection>
  dirty: Set<string>
  pairwise: PairwiseReader
}

/**
 * The pairwise did:key and its signer for an entry ({@link pairwiseOf}).
 */
type Pairwise = { did: string; zcapClient: ZcapClient }

/**
 * Reads an entry's pairwise did:key as {@link pairwiseOf} does.
 */
type PairwiseReader = (read: ReadConnection) => Promise<Pairwise | undefined>

const passChains = new WeakMap<Session, Promise<unknown>>()
const latestOutcomes = new WeakMap<Session, InboxPassOutcome>()
const visitOutcomes = new WeakMap<Session, InboxPassOutcome>()

/**
 * An empty outcome.
 *
 * @returns {InboxPassOutcome}
 */
function emptyOutcome(): InboxPassOutcome {
  return { invitations: [], renewalsPushed: [], refused: [], pushFailures: [] }
}

/**
 * Reads the pointed generation delegation's id off the head of the
 * generation log the account document points at, through the signer check's
 * annex-document resolver, so the proof checks that follow under the same
 * check find the pointed generation already read. `undefined` when the
 * document points at no generation, or the generation's log is absent or
 * embeds no delegation. Throws what the resolver throws when the log cannot
 * be read.
 *
 * @param options {object}
 * @param options.check {AccountSignerCheck}
 * @returns {Promise<string | undefined>}
 */
export async function readPointedDelegationId({
  check
}: {
  check: AccountSignerCheck
}): Promise<string | undefined> {
  if (check.clientAnnexDid === undefined || check.annexDocument === undefined) {
    return undefined
  }
  const doc = await check.annexDocument({
    clientAnnexDid: check.clientAnnexDid
  })
  if (!doc) {
    return undefined
  }
  const delegation = embeddedGenerationDelegation({
    doc: doc as Parameters<typeof embeddedGenerationDelegation>[0]['doc']
  }) as { id?: unknown } | undefined
  return typeof delegation?.id === 'string' ? delegation.id : undefined
}

/**
 * POSTs one envelope into an agent's inbox, invoking the channel capability
 * as the pairwise did:key. Throws what the request throws.
 *
 * @param options {object}
 * @param options.channel {ConnectionZcap}   the live channel capability
 * @param options.message {object}   the envelope, verbatim
 * @param options.zcapClient {ZcapClient}   signs as the pairwise did:key
 * @returns {Promise<void>}
 */
async function pushEnvelope({
  channel,
  message,
  zcapClient
}: {
  channel: ConnectionZcap
  message: Record<string, unknown>
  zcapClient: ZcapClient
}): Promise<void> {
  await zcapClient.request({
    capability: channel as unknown as IZcap,
    method: 'POST',
    json: message
  })
}

const DEFAULT_DEPS: InboxPassDeps = {
  readPointedDelegationId,
  push: pushEnvelope,
  renewParent: async ({ session }) =>
    await renewTransientGenerationDelegation({ session }),
  now: () => new Date()
}

/**
 * The pairwise did:key and its signer for an entry, once its seed passes its
 * tag; `undefined` for an entry with no seed or no tag. Throws when the tag
 * fails.
 *
 * @param options {object}
 * @param options.entry {ConnectionEntry}
 * @param options.hmacKey {ConnectionIdKey}
 * @returns {Promise<{ did: string, zcapClient: ZcapClient } | undefined>}
 */
export async function pairwiseOf({
  entry,
  hmacKey
}: {
  entry: ConnectionEntry
  hmacKey: ConnectionIdKey
}): Promise<Pairwise | undefined> {
  if (entry.seed === undefined || entry.seedTag === undefined) {
    return undefined
  }
  const { did, zcapClient } = await connectionDidKey({
    hmacKey,
    seed: entry.seed,
    seedTag: entry.seedTag
  })
  return { did, zcapClient }
}

/**
 * A {@link pairwiseOf} that derives each entry's pairwise did:key once. The
 * key names the seed and its tag beside the resource id, so an entry re-read
 * with another seed is derived, and its tag checked, again.
 *
 * @param options {object}
 * @param options.hmacKey {ConnectionIdKey}
 * @returns {PairwiseReader}
 */
function pairwiseMemo({
  hmacKey
}: {
  hmacKey: ConnectionIdKey
}): PairwiseReader {
  const derived = new Map<string, Promise<Pairwise | undefined>>()
  return read => {
    const { seed, seedTag } = read.entry
    const key = JSON.stringify([read.resourceId, seed, seedTag])
    let pairwise = derived.get(key)
    if (!pairwise) {
      pairwise = pairwiseOf({ entry: read.entry, hmacKey })
      derived.set(key, pairwise)
    }
    return pairwise
  }
}

/**
 * Whether a listed entry is an unretired agent entry.
 *
 * @param entry {ConnectionEntry}
 * @returns {boolean}
 */
export function isLiveAgent(entry: ConnectionEntry): boolean {
  return entry.kind === 'agent' && entry.retired === undefined
}

/**
 * Reads back every entry the pass wrote since the last read-back, so the
 * steps behind it see what the writes left.
 *
 * @param options {object}
 * @param options.directory {PassDirectory}
 * @returns {Promise<void>}
 */
async function refreshWritten({
  directory
}: {
  directory: PassDirectory
}): Promise<void> {
  const written = [...directory.dirty]
  directory.dirty.clear()
  await Promise.all(
    written.map(async resourceId => {
      try {
        const stored = await directory.store.get({ resourceId })
        const entry =
          stored === undefined ? undefined : parseConnectionEntry(stored.body)
        if (stored === undefined || entry === undefined) {
          directory.entries.delete(resourceId)
          return
        }
        directory.entries.set(resourceId, {
          resourceId,
          ...(stored.etag !== undefined ? { etag: stored.etag } : {}),
          entry,
          body: stored.body as Record<string, unknown>
        })
      } catch (err) {
        log.warn('Could not read back a connections entry the pass wrote', {
          err
        })
      }
    })
  )
}

/**
 * A listing's entries keyed by resource id.
 *
 * @param entries {ReadConnection[]}
 * @returns {Map<string, ReadConnection>}
 */
function byResourceId(entries: ReadConnection[]): Map<string, ReadConnection> {
  return new Map(entries.map(read => [read.resourceId, read]))
}

/**
 * The unretired agent entries of a listing, keyed by the DID each names. Of
 * two entries naming one DID, the first listed is kept.
 *
 * @param entries {Map<string, ReadConnection>}
 * @returns {Map<string, ReadConnection>}
 */
function liveAgentsByDid(
  entries: Map<string, ReadConnection>
): Map<string, ReadConnection> {
  const agents = new Map<string, ReadConnection>()
  for (const read of entries.values()) {
    const did = read.entry.id
    if (isLiveAgent(read.entry) && did !== undefined && !agents.has(did)) {
      agents.set(did, read)
    }
  }
  return agents
}

/**
 * The base media type of a content type, lowercased, parameters dropped.
 *
 * @param contentType {string | undefined}
 * @returns {string | undefined}
 */
function baseMediaType(contentType: string | undefined): string | undefined {
  return contentType?.split(';')[0]?.trim().toLowerCase()
}

/**
 * Drains the account's own `inbox` (steps 1 to 6 of the module header) and
 * reports `inbox-is-drained`. The message deletes of one listing page run
 * together, and are settled before the next page is read.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.directory {PassDirectory}
 * @param options.inbox {InboxRead}   the inbox read at the pass's start
 * @param options.outcome {InboxPassOutcome}   filled in place
 * @param options.now {Date}
 * @returns {Promise<MendReportEntry>}
 */
export async function drainInbox({
  session,
  directory,
  inbox,
  outcome,
  now
}: {
  session: Session
  directory: PassDirectory
  inbox: InboxRead
  outcome: InboxPassOutcome
  now: Date
}): Promise<MendReportEntry<CeremonyId>> {
  const invariant = 'inbox-is-drained' as const
  if (inbox.trust === 'absent') {
    return { invariant, outcome: 'refused', detail: { reason: 'no-inbox' } }
  }
  if (inbox.trust === 'untrusted') {
    return {
      invariant,
      outcome: 'refused',
      detail: { reason: 'untrusted-inbox', untrusted: inbox.reason }
    }
  }
  const refusals = new Map<string, InboxPassOutcome['refused'][number]>()
  const senderBytes = new Map<string, number>()
  const deletes: Array<Promise<void>> = []
  let agents = liveAgentsByDid(directory.entries)
  let bytesRead = 0
  let deleted = 0
  let deferred = 0
  let failed = 0
  let listingFailed = false
  let capReached = false
  let reread = false

  /**
   * Charges bytes against a sender's budget for the pass.
   *
   * @param options {object}
   * @param options.sender {string}
   * @param options.bytes {number}
   * @returns {void}
   */
  function charge({ sender, bytes }: { sender: string; bytes: number }): void {
    senderBytes.set(sender, (senderBytes.get(sender) ?? 0) + bytes)
  }

  /**
   * Counts one refusal and deletes the message.
   *
   * @param options {object}
   * @param options.resourceId {string}
   * @param [options.sender] {string}
   * @param options.reason {InboxRefusalReason}
   * @returns {void}
   */
  function refuse({
    resourceId,
    sender,
    reason
  }: {
    resourceId: string
    sender?: string
    reason: InboxRefusalReason
  }): void {
    log.info('Refused an inbox message', { reason, sender })
    const key = `${sender ?? ''}\n${reason}`
    const held = refusals.get(key)
    if (held) {
      held.count += 1
    } else {
      refusals.set(key, {
        ...(sender !== undefined ? { sender } : {}),
        reason,
        count: 1
      })
    }
    remove({ resourceId })
  }

  /**
   * Starts the delete of one message, counting a failure. The page's deletes
   * are awaited together ({@link settleDeletes}).
   *
   * @param options {object}
   * @param options.resourceId {string}
   * @returns {void}
   */
  function remove({ resourceId }: { resourceId: string }): void {
    if (isSessionDisposed({ session })) {
      return
    }
    deletes.push(
      session.storage.deleteInboxMessage({ resourceId }).then(
        () => {
          deleted += 1
        },
        (err: unknown) => {
          failed += 1
          log.warn('Could not delete an inbox message; the next pass retries', {
            err
          })
        }
      )
    )
  }

  /**
   * Awaits every delete started so far.
   *
   * @returns {Promise<void>}
   */
  async function settleDeletes(): Promise<void> {
    await Promise.all(deletes.splice(0))
  }

  /**
   * Handles one message. Returns `'stop'` once the pass's byte cap is
   * reached.
   *
   * @param options {object}
   * @param options.resourceId {string}
   * @returns {Promise<'stop' | undefined>}
   */
  async function handle({
    resourceId
  }: {
    resourceId: string
  }): Promise<'stop' | undefined> {
    if (bytesRead >= INBOX_DRAIN_BYTE_CAP) {
      capReached = true
      return 'stop'
    }
    let meta
    try {
      meta = await session.storage.readInboxMessageMeta({ resourceId })
    } catch (err) {
      failed += 1
      log.warn('Could not read an inbox message metadata', { err })
      return undefined
    }
    if (meta === null) {
      return undefined
    }
    const sender = meta.createdBy
    if (sender === undefined) {
      refuse({ resourceId, reason: 'no-creator' })
      return undefined
    }
    if ((senderBytes.get(sender) ?? 0) >= INBOX_SENDER_BYTE_BUDGET) {
      deferred += 1
      return undefined
    }
    const size = meta.size ?? INBOX_MESSAGE_MAX_BYTES + 1
    if (baseMediaType(meta.contentType) !== 'application/json') {
      charge({ sender, bytes: size })
      refuse({ resourceId, sender, reason: 'content-type' })
      return undefined
    }
    if (meta.size === undefined || meta.size > INBOX_MESSAGE_MAX_BYTES) {
      charge({ sender, bytes: size })
      refuse({ resourceId, sender, reason: 'oversized' })
      return undefined
    }
    let read = agents.get(sender)
    if (read === undefined && !reread) {
      // A consent in another tab, or in this one while the tail ran, may
      // have written the entry after the first read.
      reread = true
      try {
        const { listing } = await session.storage.readConnectionsListing()
        directory.entries = byResourceId(listing.entries)
        agents = liveAgentsByDid(directory.entries)
      } catch (err) {
        failed += 1
        log.warn('Could not re-read the connections listing', { err })
        return undefined
      }
      read = agents.get(sender)
    }
    if (read === undefined) {
      refuse({ resourceId, sender, reason: 'unknown-sender' })
      return undefined
    }
    const entry = read.entry
    if (entry.seed === undefined || entry.seedTag === undefined) {
      refuse({ resourceId, sender, reason: 'seedless-sender' })
      return undefined
    }
    let pairwiseDid: string
    try {
      pairwiseDid = (await directory.pairwise(read))!.did
    } catch (err) {
      log.warn("A sender entry's seed fails its tag", { sender, err })
      refuse({ resourceId, sender, reason: 'seed-tag' })
      return undefined
    }
    let body: unknown
    try {
      body = await session.storage.readInboxMessageBody({ resourceId })
    } catch (err) {
      failed += 1
      log.warn('Could not read an inbox message', { err })
      return undefined
    }
    if (body === null) {
      return undefined
    }
    bytesRead += meta.size
    charge({ sender, bytes: meta.size })
    const message = parseInboxGrantMessage(body)
    if (!message) {
      refuse({ resourceId, sender, reason: 'malformed' })
      return undefined
    }
    if (message.actor !== sender) {
      refuse({ resourceId, sender, reason: 'actor-mismatch' })
      return undefined
    }
    const channels: InboxMessageZcap[] = []
    for (const zcap of message.object.zcaps) {
      if (
        isTargetInSpace({
          target: zcap.invocationTarget,
          spaceUrl: directory.spaceUrl
        })
      ) {
        log.info(
          'Ignored a capability targeting this Space; no renewed grant is accepted from an agent',
          { sender, zcapId: zcap.id }
        )
        continue
      }
      if (zcap.controller !== pairwiseDid) {
        log.info('Ignored a capability delegated to another controller', {
          sender,
          zcapId: zcap.id
        })
        continue
      }
      // `recordReceivedGrants` refuses a channel that does not allow POST,
      // or one it cannot record, which refuses the message below.
      channels.push(zcap)
    }
    if (channels.length > 0) {
      if (isSessionDisposed({ session })) {
        return 'stop'
      }
      try {
        const written = await recordReceivedGrants({
          store: directory.store,
          hmacKey: directory.hmacKey,
          did: sender,
          pairwiseDid,
          spaceUrl: directory.spaceUrl,
          grants: channels.map(zcap => ({ zcap, grantKind: 'inbox' as const })),
          channelMaxLifetimeMs: SHARE_ZCAP_TTL_MS,
          now
        })
        if (written.outcome === 'updated' || written.outcome === 'created') {
          directory.dirty.add(written.resourceId)
        }
      } catch (err) {
        if (errorNameOf(err) === 'TypeError') {
          refuse({ resourceId, sender, reason: 'malformed' })
          return undefined
        }
        // The message stays for the next pass, whose re-run stores the same
        // capability.
        failed += 1
        log.warn('Could not record a channel capability', { sender, err })
        return undefined
      }
      const limit = now.getTime() + SHARE_ZCAP_TTL_MS
      for (const zcap of channels) {
        const expires = Date.parse(String(zcap.expires))
        outcome.invitations.push({
          agentDid: sender,
          ...(entry.name !== undefined ? { agentName: entry.name } : {}),
          channelExpires: new Date(
            Number.isNaN(expires) ? limit : Math.min(expires, limit)
          ).toISOString()
        })
      }
    }
    remove({ resourceId })
    return undefined
  }

  try {
    pages: for await (const page of inbox.pages) {
      try {
        for (const resourceId of page) {
          if (isSessionDisposed({ session })) {
            break pages
          }
          if ((await handle({ resourceId })) === 'stop') {
            break pages
          }
        }
      } finally {
        await settleDeletes()
      }
    }
  } catch (err) {
    listingFailed = true
    log.warn('Could not list the inbox; the next pass retries', { err })
  }
  outcome.refused.push(...refusals.values())
  const detail = {
    deleted,
    refused: [...refusals.values()].reduce((sum, row) => sum + row.count, 0),
    ...(deferred > 0 ? { deferred } : {}),
    ...(failed > 0 ? { failed } : {}),
    ...(capReached ? { capReached } : {}),
    ...(listingFailed ? { listingFailed } : {})
  }
  if (failed > 0 || listingFailed || capReached || deferred > 0) {
    return { invariant, outcome: 'partial', detail }
  }
  return { invariant, outcome: deleted > 0 ? 'clean' : 'noop', detail }
}

/**
 * One candidate entry of the renewal: its listing row, its pairwise did:key,
 * and the grants due.
 */
interface RenewalCandidate {
  read: ReadConnection
  pairwiseDid: string
  due: ConnectionGrant[]
}

/**
 * The agent entries a renewal reads: every unretired agent entry carrying a
 * seed that passes its tag and a live channel, with its pairwise did:key. An
 * entry whose seed fails its tag is logged and left out.
 *
 * @param options {object}
 * @param options.entries {ReadConnection[]}   the directory listing
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.spaceUrl {string}   this Space's container URL
 * @param options.now {Date}
 * @param [options.pairwise] {PairwiseReader}   the pass's derivations; a
 *   fresh one by default
 * @returns {Promise<Array<{ read: ReadConnection, pairwiseDid: string }>>}
 */
export async function agentsWithChannel({
  entries,
  hmacKey,
  spaceUrl,
  now,
  pairwise = pairwiseMemo({ hmacKey })
}: {
  entries: ReadConnection[]
  hmacKey: ConnectionIdKey
  spaceUrl: string
  now: Date
  pairwise?: PairwiseReader
}): Promise<Array<{ read: ReadConnection; pairwiseDid: string }>> {
  const derived = await Promise.all(
    entries
      .filter(read => isLiveAgent(read.entry))
      .map(async read => {
        try {
          return { read, pairwise: await pairwise(read) }
        } catch (err) {
          log.warn(
            "An agent entry's seed fails its tag; its grants are not renewed",
            { did: read.entry.id, err }
          )
          return { read, pairwise: undefined }
        }
      })
  )
  const withChannel: Array<{ read: ReadConnection; pairwiseDid: string }> = []
  for (const { read, pairwise: key } of derived) {
    if (key === undefined) {
      continue
    }
    const channel = liveInboxChannel({
      grants: receivedGrants({
        entry: read.entry,
        pairwiseDid: key.did,
        spaceUrl
      }),
      now,
      maxLifetimeMs: SHARE_ZCAP_TTL_MS
    })
    if (channel !== undefined) {
      withChannel.push({ read, pairwiseDid: key.did })
    }
  }
  return withChannel
}

/**
 * An agent entry's renewable grants: its latest record per scope, kept
 * where a connection request's consent put that scope in the renewal's
 * scope. The consent stamps come from every inbox grant record on the
 * entry, a superseded or renewed one included, so a later connection
 * request's inbox grant leaves an earlier consent's reads in scope. A
 * renewed record keeps its `grantedAt`, so a stamp survives the prune of
 * the record it was first written on. The renewal, the restore, and the
 * lapsed-agent offer all read this one selection.
 *
 * @param options {object}
 * @param options.entry {ConnectionEntry}
 * @param options.spaceUrl {string}
 * @returns {ConnectionGrant[]}
 */
export function renewableAgentGrants({
  entry,
  spaceUrl
}: {
  entry: ConnectionEntry
  spaceUrl: string
}): ConnectionGrant[] {
  const grants = connectionGrants({ entry, spaceUrl })
  const inScope = new Set(renewalScopeGrants({ grants, spaceUrl }))
  return latestGrantsPerScope({ grants }).filter(grant => inScope.has(grant))
}

/**
 * The grants a renewal renews, per entry: of each entry's latest record per
 * scope, those inside the renewal scope, passing the proof check
 * (wallet-core's `verifyRecordedGrantProof`), and due.
 * The scope's consent stamps are read over every grant record on the entry,
 * not only the latest per scope.
 * The predicate `agent-grants-are-current` reads, shared by the renewal and
 * the invariant auditor's key holder. `unverified` counts the in-scope
 * grants the proof check refused.
 *
 * @param options {object}
 * @param options.withChannel {Array<object>}   as {@link agentsWithChannel}
 *   returns them
 * @param options.spaceUrl {string}
 * @param options.signerCheck {AccountSignerCheck}
 * @param [options.pointedDelegationId] {string}   read off the pointed
 *   generation log's head
 * @param [options.renewalWindowMs] {number}   how far ahead of its `expires`
 *   a grant counts as due
 * @param options.now {Date}
 * @returns {Promise<{ candidates: RenewalCandidate[], unverified: number }>}
 */
export async function dueAgentGrants({
  withChannel,
  spaceUrl,
  signerCheck,
  pointedDelegationId,
  renewalWindowMs = AGENT_GRANT_RENEWAL_WINDOW_MS,
  now
}: {
  withChannel: Array<{ read: ReadConnection; pairwiseDid: string }>
  spaceUrl: string
  signerCheck: AccountSignerCheck
  pointedDelegationId?: string
  renewalWindowMs?: number
  now: Date
}): Promise<{ candidates: RenewalCandidate[]; unverified: number }> {
  const candidates: RenewalCandidate[] = []
  let unverified = 0
  const perEntry = await Promise.all(
    withChannel.map(async ({ read, pairwiseDid }) => {
      const latest = renewableAgentGrants({ entry: read.entry, spaceUrl })
      const proofs = await Promise.all(
        latest.map(grant =>
          verifyRecordedGrantProof({ zcap: grant.zcap, signerCheck })
        )
      )
      const due: ConnectionGrant[] = []
      let unverifiedHere = 0
      latest.forEach((grant, index) => {
        const proof = proofs[index]!
        if (!proof.verified) {
          unverifiedHere += 1
          log.info(
            "A recorded agent grant's proof does not verify as this account's; not renewed",
            { did: read.entry.id, zcapId: grant.zcapId, reason: proof.reason }
          )
          return
        }
        if (
          agentGrantDue({
            zcap: grant.zcap,
            ...(pointedDelegationId !== undefined
              ? { pointedDelegationId }
              : {}),
            doc: signerCheck.doc,
            renewalWindowMs,
            now: now.getTime()
          })
        ) {
          due.push(grant)
        }
      })
      return { read, pairwiseDid, due, unverified: unverifiedHere }
    })
  )
  for (const entry of perEntry) {
    unverified += entry.unverified
    if (entry.due.length > 0) {
      candidates.push({
        read: entry.read,
        pairwiseDid: entry.pairwiseDid,
        due: entry.due
      })
    }
  }
  return { candidates, unverified }
}

/**
 * Mints fresh grants for agent entries under consent's parent rule: a stale
 * generation delegation is renewed first, and nothing is minted when it
 * cannot be. Each source grant is minted again with its `controller`, its
 * `invocationTarget` as stored, and its actions, at the share TTL and no
 * later than `notAfterOf` it. The minted grants come back grouped as the
 * sources were given. Shared by the renewal and the agent restore.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.sources {ConnectionGrant[][]}   per entry, the grants to
 *   mint again
 * @param options.doc {PublishedKeyDocument}   the verified account document
 *   the parent's staleness is read against
 * @param options.renewParent {Function}   `() => Promise<IZcap | null>`,
 *   renews the generation delegation in place
 * @param options.notAfterOf {Function}   `(source) => Date`, the latest a
 *   source's fresh grant may expire
 * @returns {Promise<ConnectionZcap[][] | undefined>}   the minted grants per
 *   entry, or `undefined` when the parent could not be renewed
 */
export async function mintAgentGrants({
  session,
  sources,
  doc,
  renewParent,
  notAfterOf
}: {
  session: Session
  sources: ConnectionGrant[][]
  doc: PublishedKeyDocument
  renewParent: () => Promise<IZcap | null>
  notAfterOf: (source: ConnectionGrant) => Date
}): Promise<ConnectionZcap[][] | undefined> {
  const minted = await session.storage.delegateRenewalGrants({
    profile: session.profile,
    grants: sources.flat().map(source => ({
      invocationTarget: source.target,
      controller: source.controller,
      allowedActions: normalizedActions(source),
      ttlMs: SHARE_ZCAP_TTL_MS,
      notAfter: notAfterOf(source)
    })),
    parentStale: parent => standingZcapStale({ zcap: parent, doc }),
    renewParent
  })
  if (minted === undefined) {
    return undefined
  }
  let offset = 0
  return sources.map(group => {
    const zcaps = minted.slice(offset, offset + group.length)
    offset += group.length
    return zcaps as unknown as ConnectionZcap[]
  })
}

/**
 * The Grant envelope that carries fresh grants to an agent, queued on its
 * entry's `outbox`.
 *
 * @param options {object}
 * @param options.pairwiseDid {string}   the envelope's `actor`
 * @param options.zcaps {ConnectionZcap[]}
 * @returns {Record<string, unknown>}
 */
export function agentGrantEnvelope({
  pairwiseDid,
  zcaps
}: {
  pairwiseDid: string
  zcaps: ConnectionZcap[]
}): Record<string, unknown> {
  return inboxGrantMessage({
    actor: pairwiseDid,
    zcaps: zcaps as unknown as InboxMessageZcap[]
  }) as unknown as Record<string, unknown>
}

/**
 * Writes the one Grant activity an agent's fresh grants get. Throws what
 * the write throws.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {ConnectionEntry}   the agent's entry, whose `name`
 *   is the activity's actor
 * @param options.zcaps {ConnectionZcap[]}
 * @returns {Promise<void>}
 */
export async function addAgentGrantActivity({
  session,
  entry,
  zcaps
}: {
  session: Session
  entry: ConnectionEntry
  zcaps: ConnectionZcap[]
}): Promise<void> {
  await session.storage.addHistoryGrant({
    user: session.user,
    origin: EXTERNAL_REQUEST_ORIGIN,
    grants: zcaps.map(zcap => ({
      id: zcap.id,
      target: zcap.invocationTarget,
      allowedActions: normalizedActions(zcap),
      expires: zcap.expires,
      zcap: zcap as unknown as IZcap
    })),
    ...(entry.name !== undefined ? { actor: { name: entry.name } } : {})
  })
}

/**
 * A generation log read the proof check's resolver could not complete,
 * carrying the read's own error as `cause`. It marks the one failure the
 * renewal reports as `no-generation-head`.
 */
class GenerationLogReadFailure extends Error {
  constructor(cause: unknown) {
    super("A recorded grant's generation log could not be read", { cause })
    this.name = 'GenerationLogReadFailure'
  }
}

/**
 * The signer check with its annex-document resolver's throws wrapped in
 * {@link GenerationLogReadFailure}, so the renewal tells a failed log read
 * from any other failure of the due check.
 *
 * @param check {AccountSignerCheck}
 * @returns {AccountSignerCheck}
 */
function taggingGenerationReads(check: AccountSignerCheck): AccountSignerCheck {
  const { annexDocument } = check
  if (annexDocument === undefined) {
    return check
  }
  return {
    ...check,
    annexDocument: async options => {
      try {
        return await annexDocument(options)
      } catch (err) {
        throw new GenerationLogReadFailure(err)
      }
    }
  }
}

/**
 * Renews the connected agents' due grants and reports
 * `agent-grants-are-current`. Reads the listing as the drain left it.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.directory {PassDirectory}
 * @param options.deps {InboxPassDeps}
 * @param options.now {Date}
 * @param options.signerCheck {Function}   resolves the account signer check
 *   once, shared with the prune
 * @returns {Promise<{ entry: MendReportEntry, failed: number }>}
 */
export async function renewAgentGrants({
  session,
  directory,
  deps,
  now,
  signerCheck
}: {
  session: Session
  directory: PassDirectory
  deps: InboxPassDeps
  now: Date
  signerCheck: () => Promise<AccountSignerCheck | undefined>
}): Promise<{ entry: MendReportEntry<CeremonyId>; failed: number }> {
  const invariant = 'agent-grants-are-current' as const
  const withChannel = await agentsWithChannel({
    entries: [...directory.entries.values()],
    hmacKey: directory.hmacKey,
    spaceUrl: directory.spaceUrl,
    now,
    pairwise: directory.pairwise
  })
  if (withChannel.length === 0) {
    return {
      entry: { invariant, outcome: 'noop', detail: { reason: 'no-channel' } },
      failed: 0
    }
  }
  const check = await signerCheck()
  if (check === undefined) {
    return {
      entry: {
        invariant,
        outcome: 'partial',
        detail: { reason: 'no-signer-check' }
      },
      failed: 1
    }
  }
  let pointedDelegationId: string | undefined
  try {
    pointedDelegationId = await deps.readPointedDelegationId({ check })
  } catch (err) {
    log.warn(
      'Could not read the pointed generation delegation; renewing no agent grant',
      { err }
    )
    return {
      entry: {
        invariant,
        outcome: 'partial',
        detail: { reason: 'no-generation-head' },
        errorName: errorNameOf(err)
      },
      failed: 1
    }
  }
  let due
  try {
    due = await dueAgentGrants({
      withChannel,
      spaceUrl: directory.spaceUrl,
      signerCheck: taggingGenerationReads(check),
      ...(pointedDelegationId !== undefined ? { pointedDelegationId } : {}),
      renewalWindowMs:
        forcedAgentGrantRenewalWindowMs() ?? AGENT_GRANT_RENEWAL_WINDOW_MS,
      now
    })
  } catch (err) {
    // The proof check's one read past the document is a grant's generation
    // log, through the signer check's resolver. What that read throws is
    // reported here, and renews nothing; anything else propagates.
    if (!(err instanceof GenerationLogReadFailure)) {
      throw err
    }
    log.warn(
      "Could not read a recorded grant's generation log; renewing no agent grant",
      { err: err.cause }
    )
    return {
      entry: {
        invariant,
        outcome: 'partial',
        detail: { reason: 'no-generation-head' },
        errorName: errorNameOf(err.cause)
      },
      failed: 1
    }
  }
  const { candidates, unverified } = due
  const unverifiedDetail = unverified > 0 ? { unverified } : {}
  if (candidates.length === 0) {
    return {
      entry: { invariant, outcome: 'noop', detail: { ...unverifiedDetail } },
      failed: 0
    }
  }
  let minted
  try {
    minted = await mintAgentGrants({
      session,
      sources: candidates.map(candidate => candidate.due),
      doc: check.doc,
      renewParent: async () => await deps.renewParent({ session }),
      notAfterOf: source =>
        new Date(Date.parse(source.expires) + STANDING_ZCAP_TTL_MS)
    })
  } catch (err) {
    log.warn('Could not mint the agent grant renewals', { err })
    return {
      entry: {
        invariant,
        outcome: 'partial',
        detail: { reason: 'mint-failed', ...unverifiedDetail },
        errorName: errorNameOf(err)
      },
      failed: 1
    }
  }
  if (minted === undefined) {
    return {
      entry: {
        invariant,
        outcome: 'partial',
        detail: { reason: 'parent-not-renewable', ...unverifiedDetail }
      },
      failed: 1
    }
  }
  let renewedEntries = 0
  let renewedGrants = 0
  let failed = 0
  let parentTooShort = 0
  for (const [
    candidateIndex,
    { read, pairwiseDid, due }
  ] of candidates.entries()) {
    const mintedHere = minted[candidateIndex]!
    const renewals = due.flatMap((source, index) => {
      const zcap = mintedHere[index]!
      // A renewal limited by its parent to no later than its source would be
      // refused by the pivot, and is due again at once anyway. The grant is
      // left due, so the pass is not clean.
      if (Date.parse(zcap.expires) <= Date.parse(source.expires)) {
        parentTooShort += 1
        log.warn(
          "A renewal would not outlast its source, its parent's life too short; skipped",
          { did: read.entry.id, zcapId: source.zcapId }
        )
        return []
      }
      return [{ zcap, sourceZcapId: source.zcapId }]
    })
    if (renewals.length === 0 || isSessionDisposed({ session })) {
      continue
    }
    const did = read.entry.id!
    const zcaps = renewals.map(renewal => renewal.zcap)
    try {
      const written = await recordRenewedGrants({
        store: directory.store,
        hmacKey: directory.hmacKey,
        did,
        pairwiseDid,
        spaceUrl: directory.spaceUrl,
        renewals,
        message: agentGrantEnvelope({ pairwiseDid, zcaps }),
        channelMaxLifetimeMs: SHARE_ZCAP_TTL_MS,
        now
      })
      if (written.outcome === 'absent') {
        continue
      }
      directory.dirty.add(written.resourceId)
    } catch (err) {
      // A retired entry, a lost channel, or a concurrent renewal: the minted
      // grants are discarded unrecorded, and nothing is queued.
      failed += 1
      log.warn('Could not record an agent grant renewal; discarded', {
        did,
        err
      })
      continue
    }
    renewedEntries += 1
    renewedGrants += renewals.length
    try {
      await addAgentGrantActivity({ session, entry: read.entry, zcaps })
    } catch (err) {
      log.warn('Could not record the renewal Grant activity', { did, err })
    }
  }
  const detail = {
    renewedEntries,
    renewedGrants,
    ...unverifiedDetail,
    ...(parentTooShort > 0
      ? { reason: 'parent-too-short', parentTooShort }
      : {})
  }
  if (failed > 0 || parentTooShort > 0) {
    return {
      entry: {
        invariant,
        outcome: 'partial',
        detail: { ...detail, ...(failed > 0 ? { failed } : {}) }
      },
      failed: failed + parentTooShort
    }
  }
  return {
    entry: {
      invariant,
      outcome: renewedEntries > 0 ? 'clean' : 'noop',
      detail
    },
    failed: 0
  }
}

/**
 * Whether every capability an envelope carries is past its `expires`.
 *
 * @param options {object}
 * @param options.message {object}
 * @param options.now {Date}
 * @returns {boolean}
 */
function envelopeExpired({
  message,
  now
}: {
  message: Record<string, unknown>
  now: Date
}): boolean {
  const zcaps = parseInboxGrantMessage(message)?.object.zcaps
  if (!zcaps) {
    return false
  }
  return zcaps.every(zcap => {
    const expires = Date.parse(String(zcap.expires))
    return !Number.isNaN(expires) && expires <= now.getTime()
  })
}

/**
 * Pushes every agent entry's outbox through its live channel.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.directory {PassDirectory}
 * @param options.deps {InboxPassDeps}
 * @param options.outcome {InboxPassOutcome}   filled in place
 * @param options.now {Date}
 * @returns {Promise<{ pushed: number, failed: number, settled: Map<string,
 *   Set<string>> }>}   `settled` maps each entry's resource id to the scope
 *   keys of the grants a delivered item carried
 */
export async function drainOutboxes({
  session,
  directory,
  deps,
  outcome,
  now
}: {
  session: Session
  directory: PassDirectory
  deps: InboxPassDeps
  outcome: InboxPassOutcome
  now: Date
}): Promise<{
  pushed: number
  failed: number
  settled: Map<string, Set<string>>
}> {
  const settled = new Map<string, Set<string>>()
  let pushed = 0
  let failed = 0
  const queue = [...directory.entries.values()].filter(
    read => isLiveAgent(read.entry) && read.entry.outbox.length > 0
  )
  const deadline = Date.now() + INBOX_PUSH_TIME_BUDGET_MS

  /**
   * Records one push failure in the outcome. Every reason but `no-channel`
   * also counts toward the pass's failures: a channel-less entry waits on
   * the agent's next invitation, which no later pass of this wallet can
   * bring about.
   *
   * @param options {object}
   * @param options.entry {ConnectionEntry}
   * @param options.reason {InboxPushFailureReason}
   * @returns {void}
   */
  function failure({
    entry,
    reason
  }: {
    entry: ConnectionEntry
    reason: InboxPushFailureReason
  }): void {
    if (reason !== 'no-channel') {
      failed += 1
    }
    outcome.pushFailures.push({
      agentDid: entry.id!,
      ...(entry.name !== undefined ? { agentName: entry.name } : {}),
      reason
    })
  }

  /**
   * Pushes one entry's items in queueing order, stopping at the first that
   * is not delivered.
   *
   * @param options {object}
   * @param options.read {ReadConnection}
   * @returns {Promise<void>}
   */
  async function pushEntry({ read }: { read: ReadConnection }): Promise<void> {
    const { entry } = read
    let pairwise
    try {
      pairwise = await directory.pairwise(read)
    } catch (err) {
      log.warn("An agent entry's seed fails its tag; nothing is pushed", {
        did: entry.id,
        err
      })
      failure({ entry, reason: 'seed-tag' })
      return
    }
    if (pairwise === undefined) {
      return
    }
    const channel = liveInboxChannel({
      grants: receivedGrants({
        entry,
        pairwiseDid: pairwise.did,
        spaceUrl: directory.spaceUrl
      }),
      now,
      maxLifetimeMs: SHARE_ZCAP_TTL_MS
    })
    if (channel === undefined) {
      failure({ entry, reason: 'no-channel' })
      return
    }
    const items = [...entry.outbox].sort((first, second) =>
      first.createdAt.localeCompare(second.createdAt)
    )
    for (const item of items) {
      if (envelopeExpired({ message: item.message, now })) {
        // Discarded unsent by the prune behind this step.
        continue
      }
      if (isSessionDisposed({ session })) {
        return
      }
      const remaining = deadline - Date.now()
      if (remaining <= 0) {
        failure({ entry, reason: 'timed-out' })
        return
      }
      let timer: ReturnType<typeof setTimeout> | undefined
      try {
        const result = await Promise.race([
          deps
            .push({
              channel: channel.zcap,
              message: item.message,
              zcapClient: pairwise.zcapClient
            })
            .then(() => 'delivered' as const),
          new Promise<'timed-out'>(resolve => {
            timer = setTimeout(() => resolve('timed-out'), remaining)
          })
        ])
        if (result === 'timed-out') {
          // A delivery that lands later is repeated at the next pass, which
          // the agent adopts by capability id.
          failure({ entry, reason: 'timed-out' })
          return
        }
      } catch (err) {
        const status = httpStatus(err)
        // A WAS host masks every capability denial (revoked, expired,
        // unauthorized) as a 404, so a 404 reads as a dead channel too.
        if (status === 401 || status === 403 || status === 404) {
          log.warn(
            "An agent's server refused its channel capability; pushes to it stop",
            { did: entry.id, status }
          )
          try {
            // The queued envelopes stay on the outbox for the agent's next
            // invitation.
            const written = await dropReceivedGrant({
              store: directory.store,
              hmacKey: directory.hmacKey,
              did: entry.id!,
              zcapId: channel.zcap.id
            })
            directory.dirty.add(written.resourceId)
          } catch (err) {
            // The next pass pushes through it again, and drops it again.
            log.warn('Could not drop a refused channel record', {
              did: entry.id,
              err
            })
          }
          failure({ entry, reason: 'channel-refused' })
          return
        }
        log.warn('Could not push to an agent inbox; the item waits', {
          did: entry.id,
          status,
          err
        })
        failure({
          entry,
          reason: status === undefined || status >= 500 ? 'network' : 'rejected'
        })
        return
      } finally {
        clearTimeout(timer)
      }
      pushed += 1
      const zcaps = parseInboxGrantMessage(item.message)?.object.zcaps ?? []
      outcome.renewalsPushed.push({
        agentDid: entry.id!,
        ...(entry.name !== undefined ? { agentName: entry.name } : {}),
        grants: zcaps.map(zcap => ({
          id: zcap.id,
          target: zcap.invocationTarget,
          // The envelope is host-held, so its actions are read defensively.
          allowedActions: [zcap.allowedAction]
            .flat()
            .filter((action): action is string => typeof action === 'string'),
          expires: String(zcap.expires)
        }))
      })
      try {
        const written = await settleOutboxItem({
          store: directory.store,
          hmacKey: directory.hmacKey,
          did: entry.id!,
          createdAt: item.createdAt
        })
        directory.dirty.add(written.resourceId)
        const scopes = settled.get(read.resourceId) ?? new Set<string>()
        for (const zcap of zcaps) {
          scopes.add(grantScopeKey({ zcap: zcap as unknown as ConnectionZcap }))
        }
        settled.set(read.resourceId, scopes)
      } catch (err) {
        // The item stays queued, and the agent adopts its repeat by
        // capability id.
        log.warn('Could not remove a delivered outbox item', {
          did: entry.id,
          err
        })
      }
    }
  }

  const workers = Array.from(
    { length: Math.min(INBOX_PUSH_PARALLELISM, queue.length) },
    async () => {
      for (let read = queue.shift(); read; read = queue.shift()) {
        await pushEntry({ read })
      }
    }
  )
  await Promise.all(workers)
  return { pushed, failed, settled }
}

/**
 * Prunes, on each agent entry, the superseded grant records past their
 * `expires` plus the clock skew, the superseded records whose chain is dead
 * and whose successor this pass delivered, and the outbox items whose
 * capabilities have all expired. An entry with nothing to prune is not
 * written.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.directory {PassDirectory}
 * @param options.settled {Map<string, Set<string>>}   per entry, the scope
 *   keys a delivered item carried
 * @param [options.signerCheck] {AccountSignerCheck}
 * @param options.now {Date}
 * @returns {Promise<number>}   the failed writes
 */
async function pruneEntries({
  session,
  directory,
  settled,
  signerCheck,
  now
}: {
  session: Session
  directory: PassDirectory
  settled: Map<string, Set<string>>
  signerCheck?: AccountSignerCheck
  now: Date
}): Promise<number> {
  let failed = 0
  const skewed = new Date(now.getTime() - REVOCATION_CLOCK_SKEW_MS)
  for (const read of directory.entries.values()) {
    const { entry } = read
    // A retired entry holds no grant record and no outbox item to prune.
    if (!isLiveAgent(entry) || entry.id === undefined) {
      continue
    }
    const latest = new Set(
      latestIndexPerScope({
        zcaps: entry.grants.map(grant => grant.zcap)
      }).values()
    )
    const deliveredScopes = settled.get(read.resourceId)
    const deadChainZcapIds: string[] = []
    let expiredSuperseded = false
    entry.grants.forEach((grant, index) => {
      if (latest.has(index)) {
        return
      }
      if (Date.parse(grant.zcap.expires) <= skewed.getTime()) {
        expiredSuperseded = true
        return
      }
      if (
        signerCheck !== undefined &&
        deliveredScopes?.has(grantScopeKey({ zcap: grant.zcap })) &&
        classifyGrantRevocationRefusal({
          zcap: grant.zcap as unknown as IZcap,
          signerCheck,
          now: now.getTime()
        }) !== undefined
      ) {
        deadChainZcapIds.push(grant.zcap.id)
      }
    })
    const expiredItems = entry.outbox.some(item =>
      envelopeExpired({ message: item.message, now: skewed })
    )
    if (!expiredSuperseded && deadChainZcapIds.length === 0 && !expiredItems) {
      continue
    }
    if (isSessionDisposed({ session })) {
      return failed
    }
    try {
      await pruneSupersededGrants({
        store: directory.store,
        hmacKey: directory.hmacKey,
        did: entry.id,
        deadChainZcapIds,
        now
      })
    } catch (err) {
      failed += 1
      log.warn('Could not prune superseded agent grants', {
        did: entry.id,
        err
      })
    }
  }
  return failed
}

/**
 * Folds one pass's outcome into the visit's.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.outcome {InboxPassOutcome}
 * @returns {void}
 */
function recordOutcome({
  session,
  outcome
}: {
  session: Session
  outcome: InboxPassOutcome
}): void {
  latestOutcomes.set(session, outcome)
  const visit = visitOutcomes.get(session) ?? emptyOutcome()
  visit.invitations.push(...outcome.invitations)
  visit.renewalsPushed.push(...outcome.renewalsPushed)
  visit.pushFailures.push(...outcome.pushFailures)
  for (const row of outcome.refused) {
    const held = visit.refused.find(
      candidate =>
        candidate.sender === row.sender && candidate.reason === row.reason
    )
    if (held) {
      held.count += row.count
    } else {
      visit.refused.push({ ...row })
    }
  }
  visitOutcomes.set(session, visit)
}

/**
 * One pass, unserialized: the drain, the renewal, the outbox push, then the
 * prune.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.deps {InboxPassDeps}
 * @returns {Promise<object>}   the two report entries and the pass outcome
 */
async function runPass({
  session,
  deps
}: {
  session: Session
  deps: InboxPassDeps
}): Promise<{
  entries: [MendReportEntry<CeremonyId>, MendReportEntry<CeremonyId>]
  outcome: InboxPassOutcome
}> {
  const outcome = emptyOutcome()
  const noSpace = (
    reason: string
  ): [MendReportEntry<CeremonyId>, MendReportEntry<CeremonyId>] => [
    { invariant: 'inbox-is-drained', outcome: 'noop', detail: { reason } },
    {
      invariant: 'agent-grants-are-current',
      outcome: 'noop',
      detail: { reason }
    }
  ]
  if (!session.storage.hasRemoteStorage || session.isGuest) {
    return { entries: noSpace('no-space'), outcome }
  }
  if (isSessionDisposed({ session })) {
    return { entries: noSpace('session-disposed'), outcome }
  }
  const now = deps.now()
  // The directory listing and the inbox read are independent, so they run
  // together. A failed inbox read grades the drain alone.
  const [listed, inboxRead] = await Promise.allSettled([
    session.storage.readConnectionsListing(),
    session.storage.readInbox()
  ])
  if (listed.status === 'rejected') {
    const err: unknown = listed.reason
    // A transient read failure: graded `partial`, so an encounter's budget
    // is left for a retry in the same visit.
    log.warn(
      'Could not read the connections directory; the next pass retries',
      {
        err
      }
    )
    const errorName = errorNameOf(err)
    return {
      entries: [
        {
          invariant: 'inbox-is-drained',
          outcome: 'partial',
          detail: { reason: 'directory-read-failed' },
          errorName
        },
        {
          invariant: 'agent-grants-are-current',
          outcome: 'partial',
          detail: { reason: 'directory-read-failed' },
          errorName
        }
      ],
      outcome
    }
  }
  const { store, hmacKey, spaceUrl, listing } = listed.value
  if (spaceUrl === undefined) {
    return { entries: noSpace('no-space'), outcome }
  }
  const directory: PassDirectory = {
    store,
    hmacKey,
    spaceUrl,
    entries: byResourceId(listing.entries),
    dirty: new Set(),
    pairwise: pairwiseMemo({ hmacKey })
  }
  let drained: MendReportEntry<CeremonyId>
  try {
    if (inboxRead.status === 'rejected') {
      throw inboxRead.reason
    }
    drained = await drainInbox({
      session,
      directory,
      inbox: inboxRead.value,
      outcome,
      now
    })
  } catch (err) {
    log.warn('Could not read the inbox; the next pass retries', { err })
    drained = {
      invariant: 'inbox-is-drained',
      outcome: 'partial',
      detail: { reason: 'inbox-read-failed' },
      errorName: errorNameOf(err)
    }
  }
  await refreshWritten({ directory })
  let checked: Promise<AccountSignerCheck | undefined> | undefined
  const signerCheck = () => (checked ??= session.storage.renewalSignerCheck())
  const renewal = await renewAgentGrants({
    session,
    directory,
    deps,
    now,
    signerCheck
  })
  await refreshWritten({ directory })
  const pushes = await drainOutboxes({
    session,
    directory,
    deps,
    outcome,
    now
  })
  await refreshWritten({ directory })
  const pruneFailed = await pruneEntries({
    session,
    directory,
    settled: pushes.settled,
    ...(checked !== undefined ? { signerCheck: await checked } : {}),
    now
  })
  let renewed = renewal.entry
  const extraFailures = pushes.failed + pruneFailed
  if (extraFailures > 0 || pushes.pushed > 0) {
    const detail = {
      ...renewed.detail,
      pushed: pushes.pushed,
      ...(pushes.failed > 0 ? { pushFailed: pushes.failed } : {}),
      ...(pruneFailed > 0 ? { pruneFailed } : {})
    }
    let graded = renewed.outcome
    if (extraFailures > 0) {
      graded = 'partial'
    } else if (graded === 'noop') {
      graded = 'clean'
    }
    renewed = { ...renewed, outcome: graded, detail }
  }
  return { entries: [drained, renewed], outcome }
}

/**
 * Runs one inbox pass on a live session, after any pass already running on
 * it, and resolves to its two report entries (`inbox-is-drained`, then
 * `agent-grants-are-current`) and its outcome. The outcome also joins the
 * visit's ({@link inboxVisitOutcome}). Throws what the directory read
 * throws; the runner's discipline grades that `failed`.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.deps] {Partial<InboxPassDeps>}   test seams
 * @returns {Promise<object>}
 */
export async function runInboxPass({
  session,
  deps
}: {
  session: Session
  deps?: Partial<InboxPassDeps>
}): Promise<{
  entries: [MendReportEntry<CeremonyId>, MendReportEntry<CeremonyId>]
  outcome: InboxPassOutcome
}> {
  const resolved: InboxPassDeps = { ...DEFAULT_DEPS, ...deps }
  const previous = passChains.get(session) ?? Promise.resolve()
  const run = previous.then(
    () => runPass({ session, deps: resolved }),
    () => runPass({ session, deps: resolved })
  )
  passChains.set(
    session,
    run.catch(() => undefined)
  )
  const result = await run
  recordOutcome({ session, outcome: result.outcome })
  return result
}

/**
 * The latest pass's outcome on a session, or an empty one when no pass has
 * run.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {InboxPassOutcome}
 */
export function latestInboxPassOutcome({
  session
}: {
  session: Session
}): InboxPassOutcome {
  return latestOutcomes.get(session) ?? emptyOutcome()
}

/**
 * Every pass's outcome on a session so far, merged: what a Notifications
 * page renders for the visit.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {InboxPassOutcome}
 */
export function inboxVisitOutcome({
  session
}: {
  session: Session
}): InboxPassOutcome {
  return visitOutcomes.get(session) ?? emptyOutcome()
}
