/**
 * The session bindings of the five encounter registrations the encounter
 * runner runs.
 *
 * The stranded-collection site. Every session's storage manager reports a
 * collection it records as stranded, and the binding runs the
 * stranded-collection encounter over it. The binding does not join a run in
 * flight, since that run's own cipher rebuild re-records any collection
 * still stranded and would wait on itself. A report during a run sets a
 * dirty flag instead, and one trailing run follows it. The binding keeps
 * the set of collections any run has seen: a trailing run that holds a
 * collection outside it runs past a spent budget, so each collection buys
 * at most one such run. Strands recorded before the binding existed (the
 * storage manager builds its first ciphers before the session does) are
 * replayed once the encounter gate opens. Every session kind is bound; the
 * runner's authority check and the registration stand down any session that
 * is not transient on a standing credential.
 *
 * The Dashboard reads {@link strandedCollectionMend}: the current or latest
 * run's entries, or an empty list when no run has fired. It subscribes with
 * {@link subscribeStrandedCollectionMend} to learn of a run that starts
 * mid-visit.
 *
 * The stale-seal site. Settings calls {@link mendUnlockRegistrySeal} when its
 * registry read throws `UnlockRegistryStaleSealError`, and reloads the
 * registry once it settles.
 *
 * The writer-sweep site. Every `connections` directory listing a page reads
 * goes through {@link listConnectionsDirectory}, which holds the listing and
 * starts the writer sweep over it without waiting for it. The page that
 * asked reads the run's entries through {@link connectionWritersMend}. The
 * entries go there and to the event channel, and `session.mends` does not
 * carry them.
 *
 * The two inbox-pass sites. Opening the Notifications page calls
 * {@link openInboxNotifications}, which drains the inbox and renews, and
 * resolves to the run's entries and the visit's outcome so far. The Settings
 * page calls {@link renewAgentGrantsAfterCeremony} once a ceremony that
 * replaces the generation delegation resolves. Each awaits the login's own
 * pass (`session.inboxPass`) before running. The ceremony site runs past a
 * spent budget, since a fresh delegation is evidence no earlier run saw.
 */
import {
  readConnections,
  type ConnectionsListing
} from '@interop/wallet-core/connections'
import type { MendReport } from '@interop/wallet-core/menders'
import type { CeremonyId } from '@interop/wallet-core'
import type { Session } from '@/types/auth'
import { isSessionDisposed } from '@/session/sessionLifecycle'
import { sessionAuthorityKind } from '@/session/accountCeremonyContext'
import { holdDirectoryListing } from '@/session/connectionWriters'
import { createLogger } from '@/lib/log'
import {
  inboxVisitOutcome,
  latestInboxPassOutcome,
  type InboxPassOutcome
} from '@/session/inboxPass'
import { runEncounter } from './encounter.js'
import {
  CONNECTION_WRITERS_SWEEP_ENCOUNTER,
  INBOX_CEREMONY_ENCOUNTER,
  INBOX_NOTIFICATIONS_ENCOUNTER,
  REGISTRY_SEAL_ENCOUNTER,
  STRANDED_COLLECTION_ENCOUNTER
} from './registrations.js'

/**
 * One session's stranded-collection binding.
 */
interface StrandedBinding {
  running: boolean
  latest: Promise<MendReport<CeremonyId>>
  dirty: boolean
  seen: Set<string>
  listeners: Set<() => void>
}

const log = createLogger('fw:session:registry')

const EMPTY_RUN: Promise<MendReport<CeremonyId>> = Promise.resolve([])

const bindings = new WeakMap<Session, StrandedBinding>()

/**
 * The latest writer-sweep run per session.
 */
const writerSweeps = new WeakMap<Session, Promise<MendReport<CeremonyId>>>()

/**
 * Binds a freshly built session's storage manager to the stranded-collection
 * encounter, and replays the collections already stranded once the session's
 * encounter gate opens. Called once, where the session is constructed.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {void}
 */
export function bindStrandedCollectionEncounter({
  session
}: {
  session: Session
}): void {
  const binding: StrandedBinding = {
    running: false,
    latest: EMPTY_RUN,
    dirty: false,
    seen: new Set(),
    listeners: new Set()
  }
  bindings.set(session, binding)
  session.storage.setOnStranded(() => {
    onStranded({ session, binding })
  })
  void session.encounterGate
    .then(() => {
      if (session.storage.strandedCollectionIds.length > 0) {
        onStranded({ session, binding })
      }
    })
    .catch((err: unknown) => {
      log.warn('Could not replay the collections stranded at login', { err })
    })
}

/**
 * A strand report: starts a run, or marks the one in flight dirty.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.binding {StrandedBinding}
 * @returns {void}
 */
function onStranded({
  session,
  binding
}: {
  session: Session
  binding: StrandedBinding
}): void {
  if (isSessionDisposed({ session })) {
    return
  }
  if (binding.running) {
    binding.dirty = true
    return
  }
  startRun({ session, binding })
}

/**
 * Starts one run, and a trailing run behind it when a strand was reported
 * while it ran.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.binding {StrandedBinding}
 * @returns {void}
 */
function startRun({
  session,
  binding
}: {
  session: Session
  binding: StrandedBinding
}): void {
  const candidates = session.storage.strandedCollectionIds
  const freshEvidence = candidates.some(id => !binding.seen.has(id))
  candidates.forEach(id => binding.seen.add(id))
  const run = runEncounter({
    session,
    registration: STRANDED_COLLECTION_ENCOUNTER,
    freshEvidence
  })
  binding.running = true
  binding.latest = run
  binding.listeners.forEach(listener => listener())
  // `runEncounter` never rejects.
  void run.then(() => {
    binding.running = false
    if (binding.dirty) {
      binding.dirty = false
      if (!isSessionDisposed({ session })) {
        startRun({ session, binding })
      }
    }
  })
}

/**
 * The current or latest stranded-collection run's entries, or an empty list
 * when no run has fired (or the session carries no binding). The promise
 * always settles.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<MendReport>}
 */
export function strandedCollectionMend({
  session
}: {
  session: Session
}): Promise<MendReport<CeremonyId>> {
  return bindings.get(session)?.latest ?? EMPTY_RUN
}

/**
 * Subscribes to the start of each stranded-collection run on a session.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.listener {Function}   `() => void`, called when a run starts
 * @returns {Function}   `() => void`, the unsubscriber
 */
export function subscribeStrandedCollectionMend({
  session,
  listener
}: {
  session: Session
  listener: () => void
}): () => void {
  const binding = bindings.get(session)
  if (!binding) {
    return () => undefined
  }
  binding.listeners.add(listener)
  return () => {
    binding.listeners.delete(listener)
  }
}

/**
 * The Settings stale-seal site: runs the registry stale-seal encounter and
 * resolves to its entries. The caller reloads the registry afterward. Never
 * rejects.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<MendReport>}
 */
export async function mendUnlockRegistrySeal({
  session
}: {
  session: Session
}): Promise<MendReport<CeremonyId>> {
  return await runEncounter({ session, registration: REGISTRY_SEAL_ENCOUNTER })
}

/**
 * Reads the session's `connections` directory listing, and starts the writer
 * sweep over it as the encounter site for the writer expiry. The sweep runs
 * behind the encounter gate and is not awaited here, so the listing returns
 * at once. Throws what the listing read throws, the directory refused or
 * absent included; a listing that comes back `null` (the collection is not
 * visible) starts no sweep.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<ConnectionsListing | null>}
 */
export async function listConnectionsDirectory({
  session
}: {
  session: Session
}): Promise<ConnectionsListing | null> {
  const { store, hmacKey } = await session.storage.connectionsDirectory()
  const listing = await readConnections({ store, hmacKey })
  if (listing && !isSessionDisposed({ session })) {
    holdDirectoryListing({ session, listing })
    writerSweeps.set(
      session,
      runEncounter({
        session,
        registration: CONNECTION_WRITERS_SWEEP_ENCOUNTER
      })
    )
  }
  return listing
}

/**
 * The latest writer-sweep run's entries, or an empty list when no listing
 * read has started one. The promise always settles.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<MendReport>}
 */
export function connectionWritersMend({
  session
}: {
  session: Session
}): Promise<MendReport<CeremonyId>> {
  return writerSweeps.get(session) ?? EMPTY_RUN
}

/**
 * The Notifications page's site: drains the inbox and renews the connected
 * agents' grants as an encounter, behind the login's own pass, and resolves
 * to the run's entries and every pass's outcome this visit. A run that
 * ended `refused` (no trusted inbox) spends the session's budget, and a
 * later open gets that run's entries back with the visit's outcome. Never
 * rejects.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<{ entries: MendReport, outcome: InboxPassOutcome }>}
 */
export async function openInboxNotifications({
  session
}: {
  session: Session
}): Promise<{ entries: MendReport<CeremonyId>; outcome: InboxPassOutcome }> {
  const entries = await runEncounter({
    session,
    registration: INBOX_NOTIFICATIONS_ENCOUNTER
  })
  return { entries, outcome: inboxVisitOutcome({ session }) }
}

/**
 * The Settings site, raised once a ceremony that replaces the generation
 * delegation resolves (a ladder-kind passphrase change or credential
 * removal, a client revocation, the last-client transition): drains the
 * inbox, then renews the agent grants the replacement left due, under the
 * delegation the ceremony installed. Resolves to the run's entries and that
 * pass's outcome, which names any agent a push could not reach. It awaits
 * the login's own pass first and runs past a spent budget. Never rejects.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<{ entries: MendReport, outcome: InboxPassOutcome }>}
 */
export async function renewAgentGrantsAfterCeremony({
  session
}: {
  session: Session
}): Promise<{ entries: MendReport<CeremonyId>; outcome: InboxPassOutcome }> {
  const entries = await runEncounter({
    session,
    registration: INBOX_CEREMONY_ENCOUNTER,
    freshEvidence: true
  })
  return { entries, outcome: latestInboxPassOutcome({ session }) }
}

/**
 * Whether an encounter run stood down because this session holds no wrap of
 * the roster's current user key: the session was revoked, its unlock
 * credential retired, or its wrap does not open. Logging in the same way
 * again does not mend that.
 *
 * @param options {object}
 * @param options.entries {MendReport}
 * @returns {boolean}
 */
export function encounterLostRosterWrap({
  entries
}: {
  entries: MendReport<CeremonyId>
}): boolean {
  return entries.some(
    entry =>
      entry.outcome === 'refused' && entry.detail?.reason === 'no-roster-wrap'
  )
}

/**
 * The copy key for a lost roster wrap: which thing can no longer open the
 * account's keys. A ladder-anchored session acts through its unlock
 * credential, so the credential is what changed; every other session acts
 * as this browser's enrolled client. One reader, so the dashboard and the
 * Settings page name the same thing.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {string}
 */
export function rosterWrapLostCopyKey({
  session
}: {
  session: Session
}): string {
  return sessionAuthorityKind({ session })?.kind === 'ladder'
    ? 'common.rosterWrapLostTransient'
    : 'common.rosterWrapLostRemembered'
}
