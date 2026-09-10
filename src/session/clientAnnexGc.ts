/**
 * The client annex GC sweep: the login-time driver of wallet-core's
 * `runClientAnnexGc` -- the quarterly generation swap plus the predicate-driven
 * collect fan-out over every non-pointed `gen-` collection (see the module
 * header there for the ceremony's stage order and constraints). This module
 * supplies what only a freewallet session knows: the enrolled-client
 * preconditions, the verified-log memo, the pin store, the
 * GenerationCollect digest write (through the storage facade, id = the
 * generation id verbatim), and the local annex pin-slot cleanup after a
 * generation's delete.
 *
 * Remembered sessions only, best-effort, and resumable: the caller chains it
 * behind `session.storageReady` beside the other login-time sweeps, a failed
 * pass never fails the login, and the next remembered login's pass picks up
 * exactly the generations the report still lists.
 */
import { isWebvhDid } from '@interop/wallet-core/webvh'
import { runClientAnnexGc } from '@interop/wallet-core/clientAnnex'
import type { ClientAnnexGcReport } from '@interop/wallet-core/clientAnnex'
import { pointedClientAnnexReach } from '@/session/annexReach'
import { enrolledCeremonyContext } from '@/session/accountCeremonyContext'
import { isBrowserLocalSession } from '@/session/persistence'
import { invalidateVerifiedLog } from '@/session/verifiedLog'
import type { Session } from '@/types/auth'

/**
 * Why a session ran no pass at all: the preconditions in the order they are
 * checked, so a skip says which one it was rather than resolving a bare
 * null.
 */
export type ClientAnnexGcSkip =
  'not-browser-local' | 'not-enrolled' | 'no-account-did' | 'no-annex-inventory'

/**
 * One annex GC pass's outcome: the pass's report, or the precondition that
 * refused it.
 */
export type ClientAnnexGcOutcome =
  { report: ClientAnnexGcReport } | { skipped: ClientAnnexGcSkip }

/**
 * One annex GC pass for a live remembered session. Names the precondition
 * when the session cannot run it (not on the browser-local strategy, not an
 * enrolled did:webvh account, no annex inventory) -- the same silent-skip
 * policy as the other login-time sweeps -- and otherwise returns
 * wallet-core's per-pass report. A pass that swapped the generation
 * invalidates the session's verified-log memo (the account log gained the
 * pointer-update entry).
 *
 * @param options {object}
 * @param options.session {Session}   a live session
 * @param [options.ladderSeed] {Uint8Array}   the login credential's ladder
 *   seed, from its unlock record; absent, a due swap is skipped and only the
 *   collect fan-out runs
 * @returns {Promise<ClientAnnexGcOutcome>}
 */
export async function sweepClientAnnexGenerations({
  session,
  ladderSeed
}: {
  session: Session
  ladderSeed?: Uint8Array
}): Promise<ClientAnnexGcOutcome> {
  const persistence = session.profile.persistence
  if (!persistence || !isBrowserLocalSession(persistence)) {
    return { skipped: 'not-browser-local' }
  }
  const context = enrolledCeremonyContext({ session })
  if (!context) {
    return { skipped: 'not-enrolled' }
  }
  const { remoteStore, pointer, clientWebvhKeys } = context
  if (!isWebvhDid(pointer.did)) {
    return { skipped: 'no-account-did' }
  }

  const reach = await pointedClientAnnexReach({ session, pointer })
  if (reach === null) {
    // No annex inventory on this account: nothing to swap, and no
    // auxiliary Space to list orphans in.
    return { skipped: 'no-annex-inventory' }
  }
  const { doc, log, was } = reach

  const report = await runClientAnnexGc({
    was,
    wasServerUrl: pointer.host,
    accountSpaceId: pointer.spaceId,
    account: { did: pointer.did, doc, log },
    idStore: remoteStore.webvhIdStore(),
    updateKeys: clientWebvhKeys,
    zcapClient: session.profile.zcapClient,
    ...(ladderSeed !== undefined ? { ladderSeed } : {}),
    recordDigest: async digest => {
      await session.storage.addHistoryGenerationCollected({
        user: session.user,
        ...digest
      })
    }
  })
  if (report.swap === 'replaced') {
    invalidateVerifiedLog({ profile: session.profile })
  }
  return { report }
}
