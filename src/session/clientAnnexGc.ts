/**
 * The client annex GC sweep: the login-time driver of wallet-core's
 * `runClientAnnexGc` -- the quarterly generation swap, its off-cadence repair
 * of a pointer naming a generation whose log is gone, its off-cadence
 * readmission of a login credential the pointed log does not commit (a
 * credential left out by an unnamed retirement swap or a repair, used only
 * through this enrolled client since), and the predicate-driven collect
 * fan-out over every non-pointed `gen-` collection (see the module header
 * there for the ceremony's stage order and constraints). This module
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
import {
  invalidateVerifiedLog,
  refreshVerifiedAccountLog
} from '@/session/verifiedLog'
import type { Session } from '@/types/auth'

/**
 * One annex GC pass for a live remembered session. Names the precondition
 * when the session cannot run it (not on the browser-local strategy, not an
 * enrolled did:webvh account, no annex inventory) -- the same silent-skip
 * policy as the other login-time sweeps -- and otherwise returns
 * wallet-core's per-pass report. The verified-log memo is refreshed first, so
 * the pass is handed the pointer the host serves now and not the one this
 * login read. The pass reports the pointer it re-read from the account log
 * before its collect fan-out. The memo is invalidated when the pass swapped,
 * repaired, or readmitted the generation, or when the two pointers differ: a `failed`
 * swap whose re-point landed, or a sibling client's swap, also extended the
 * log the memo holds. A pass that rejects invalidates it too, since it
 * rejects only after its swap stage.
 *
 * @param options {object}
 * @param options.session {Session}   a live session
 * @param [options.ladderSeed] {Uint8Array}   the login credential's ladder
 *   seed, from its unlock record; absent, a due swap is skipped and only the
 *   collect fan-out runs
 * @returns {Promise<object>}   the pass's report, or the precondition that
 *   refused it -- named in the order the preconditions are checked, so a skip
 *   says which one it was rather than resolving a bare null
 */
export async function sweepClientAnnexGenerations({
  session,
  ladderSeed
}: {
  session: Session
  ladderSeed?: Uint8Array
}): Promise<
  | { report: ClientAnnexGcReport }
  | {
      skipped:
        | 'not-browser-local'
        | 'not-enrolled'
        | 'no-account-did'
        | 'no-annex-inventory'
    }
> {
  if (!isBrowserLocalSession(session.persistence)) {
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

  // The pass decides a dead pointed generation from the pointer it is handed,
  // and the repair re-points with no quiet gate. A memo taken before a
  // sibling client's swap names the generation that sibling collected, and
  // the repair would move the account off the sibling's live one.
  await refreshVerifiedAccountLog({ session })
  const reach = await pointedClientAnnexReach({ session, pointer })
  if (reach === null) {
    // No annex inventory on this account: nothing to swap, and no
    // auxiliary Space to list orphans in.
    return { skipped: 'no-annex-inventory' }
  }
  const { doc, log, was } = reach

  let report: ClientAnnexGcReport
  try {
    report = await runClientAnnexGc({
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
  } catch (err) {
    // The pass rejects only after its swap stage, on the re-read or the
    // collection listing. A re-point may have landed by then.
    invalidateVerifiedLog({ profile: session.profile })
    throw err
  }
  if (
    report.swap === 'replaced' ||
    report.swap === 'repaired' ||
    report.swap === 'readmitted' ||
    report.pointedDid !== reach.clientAnnexDid
  ) {
    invalidateVerifiedLog({ profile: session.profile })
  }
  return { report }
}
