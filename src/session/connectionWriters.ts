/**
 * The session bindings of the `connections` directory's writer arm
 * (`@interop/wallet-core/connections`): this client's writer registration,
 * and the converger the writer sweep's encounter site runs.
 *
 * - {@link registerOwnConnectionWriter} registers this client's `writerId`
 *   on its own `wallet-client` entry under the second-session rule, and
 *   moves its member's `lastSeen` at most once per touch interval after
 *   that. Only a remembered session runs it: it alone declares a `writerId`
 *   on the wire. The first-seen record the rule reads rides the session's
 *   persistence strategy, keyed by the login credential's unlock Space id.
 *   Ahead of that rule, it un-retires its own entry through wallet-core's
 *   `unretireConnection` while the verified account document still lists
 *   this client: the residue of a forget torn after its retirement. The
 *   login keeps the run's settled promise at `session.writerRegistration`,
 *   and the forget ceremony awaits it before it retires the entry.
 * - {@link holdDirectoryListing} keeps the latest directory listing a page
 *   read, and {@link sweepHeldConnectionWriters} sweeps it: the two-phase
 *   expiry of every entry's `writers`, written back under the ETags the
 *   listing carries. The encounter site in `menders/encounterSites.ts` holds
 *   the listing and runs the registration in `menders/registrations.ts`,
 *   which calls the sweep, so the listing read costs no second read.
 *
 * Every field the writer arm writes is advisory display data, and nothing
 * here is an input to an authorization decision.
 */
import { currentAccountSigningKeys } from '@interop/wallet-core/clients'
import {
  registerConnectionWriter,
  signingKeyMultibaseOfDid,
  sweepConnectionWriters,
  unretireConnection,
  type ConnectionWritersSweep,
  type ConnectionsListing,
  type WriterRegistrationOutcome
} from '@interop/wallet-core/connections'
import type { Session } from '@/types/auth'
import { DEFAULT_CLIENT_LABEL } from '@/app.config'
import { enrolledCeremonyContext } from '@/session/accountCeremonyContext'
import { isRememberedSession } from '@/session/persistence'
import { verifiedAccountLog } from '@/session/verifiedLog'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:connections')

/**
 * The latest listing a page read, per session, until a sweep takes it.
 */
const heldListings = new WeakMap<Session, ConnectionsListing>()

/**
 * Registers this client's writer on its own `wallet-client` entry, or
 * touches its member, under wallet-core's second-session rule. A remembered
 * session with an enrolled client and a known login credential runs it; any
 * other session writes nothing and resolves `undefined`. Best-effort: a
 * failure is logged and resolves `undefined`, and the next login retries.
 *
 * Before the rule is consulted, an entry left retired by a torn forget is
 * un-retired while the verified document lists this client. A forget retires
 * the entry before its removal entry, so a forget torn between the two
 * leaves a retired entry for a client the document still lists. The
 * un-retirement clears `retired` and moves `lastSeen`, and adds no grant;
 * an absent or unretired entry writes nothing. That runs on
 * every such login, whatever the first-seen record says, so the residue
 * does not wait out a touch interval or a second session. Its own failure
 * is logged, and the registration still runs.
 *
 * The un-retirement reads the document long before it writes. A forget that
 * retired the entry in that window would see it un-retired and then remove
 * the client, leaving an unretired entry nothing converges. So the login
 * keeps this run's settled promise at `session.writerRegistration`, and the
 * forget awaits it before its retirement.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.sessionStartedAt {Date}   when this session began; a
 *   first-seen record written at or after it is this session's own
 * @returns {Promise<WriterRegistrationOutcome | undefined>}
 */
export async function registerOwnConnectionWriter({
  session,
  sessionStartedAt
}: {
  session: Session
  sessionStartedAt: Date
}): Promise<WriterRegistrationOutcome | undefined> {
  try {
    const { persistence, isGuest, profile } = session
    if (!isRememberedSession({ persistence, isGuest })) {
      return undefined
    }
    const context = enrolledCeremonyContext({ session })
    const unlockSpaceId = profile.unlockMethod?.unlockSpaceId
    if (!context || unlockSpaceId === undefined) {
      return undefined
    }
    const { pointer, keyAgent } = context
    const enrolledSigningKeys = await currentAccountSigningKeys({
      did: pointer.did,
      verifiedLog: await verifiedAccountLog({ session, pointer })
    })
    const signingKey = signingKeyMultibaseOfDid({ did: keyAgent.id })
    const listedInDocument =
      signingKey !== undefined && enrolledSigningKeys.has(signingKey)
    const { store, hmacKey } = await session.storage.connectionsDirectory()
    if (listedInDocument) {
      try {
        const unretired = await unretireConnection({
          store,
          hmacKey,
          did: keyAgent.id,
          kind: 'wallet-client'
        })
        if (unretired.outcome === 'updated') {
          log.info(
            "Un-retired this client's connections entry, left retired by a " +
              'torn forget'
          )
        }
      } catch (err) {
        log.warn("Could not un-retire this client's connections entry", {
          err
        })
      }
    }
    const outcome = await registerConnectionWriter({
      store,
      hmacKey,
      local: persistence.writerFirstSeen({ unlockSpaceId }),
      accountDid: pointer.did,
      did: keyAgent.id,
      writerId: persistence.getWriterId(),
      label: DEFAULT_CLIENT_LABEL,
      listedInDocument,
      sessionStartedAt
    })
    if (outcome === 'kind-mismatch' || outcome === 'refused') {
      log.warn("Could not register this client's writer", { outcome })
    } else {
      log.debug("This client's writer registration ran", { outcome })
    }
    return outcome
  } catch (err) {
    log.warn("Could not register this client's writer", { err })
    return undefined
  }
}

/**
 * Keeps the latest directory listing a session read, for the next writer
 * sweep to take. A later listing replaces an earlier one not yet swept.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.listing {ConnectionsListing}
 * @returns {void}
 */
export function holdDirectoryListing({
  session,
  listing
}: {
  session: Session
  listing: ConnectionsListing
}): void {
  heldListings.set(session, listing)
}

/**
 * Sweeps the writers of the listing a session last read, taking it so no
 * later run sweeps it again. Resolves `undefined` when no listing is held.
 * Throws when the directory cannot be reached; a write that fails for a
 * reason other than a lost race is reported in `failed` instead.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<ConnectionWritersSweep | undefined>}
 */
export async function sweepHeldConnectionWriters({
  session
}: {
  session: Session
}): Promise<ConnectionWritersSweep | undefined> {
  const listing = heldListings.get(session)
  if (listing === undefined) {
    return undefined
  }
  heldListings.delete(session)
  const { store } = await session.storage.connectionsDirectory()
  return await sweepConnectionWriters({ store, listing })
}
