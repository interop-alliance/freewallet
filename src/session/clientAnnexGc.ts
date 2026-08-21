/**
 * The client annex GC sweep: the login-time driver of wallet-core's
 * `runClientAnnexGc` -- the quarterly generation swap plus the predicate-driven
 * collect fan-out over every non-pointed `gen-` collection (see the module
 * header there for the ceremony's stage order and constraints). This module
 * supplies what only a freewallet session knows: the enrolled-client
 * preconditions, the verified-log memo, the durable pin store, the
 * GenerationCollect digest write (through the storage facade, id = the
 * generation id verbatim), and the local annex pin-slot cleanup after a
 * generation's delete.
 *
 * Durable sessions only, best-effort, and resumable: the caller chains it
 * behind `session.storageReady` beside the other login-time sweeps, a failed
 * pass never fails the login, and the next durable login's pass picks up
 * exactly the generations the report still lists.
 */
import { WasClient } from '@interop/was-client'
import {
  clientAnnexDidParts,
  clientAnnexLogPinId,
  delegatedClientsPointer,
  isWebvhDid,
  runClientAnnexGc
} from '@interop/wallet-core/webvh'
import type { ClientAnnexGcReport } from '@interop/wallet-core/webvh'
import { deleteLogPin } from '@/lib/sessionKey'
import { enrolledClientContext } from '@/session/enrolledContext'
import { isDurableSession } from '@/session/persistence'
import {
  invalidateVerifiedLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
import type { Session } from '@/types/auth'

/**
 * One annex GC pass for a live durable session. Resolves null when the
 * session cannot run it (not durable, not an enrolled did:webvh account) --
 * the same silent-skip posture as the other login-time sweeps -- and
 * otherwise returns wallet-core's per-pass report. A pass that swapped the
 * generation invalidates the session's verified-log memo (the account log
 * gained the pointer-update entry).
 *
 * @param options {object}
 * @param options.session {Session}   a live session
 * @param [options.ladderSeed] {Uint8Array}   the login credential's ladder
 *   seed, from its unlock record; absent, a due swap is skipped and only the
 *   collect fan-out runs
 * @returns {Promise<ClientAnnexGcReport | null>}
 */
export async function sweepClientAnnexGenerations({
  session,
  ladderSeed
}: {
  session: Session
  ladderSeed?: Uint8Array
}): Promise<ClientAnnexGcReport | null> {
  const persistence = session.profile.persistence
  if (!persistence || !isDurableSession(persistence)) {
    return null
  }
  const context = enrolledClientContext({ session })
  if (!context) {
    return null
  }
  const { remoteStore, pointer, clientWebvhKeys } = context
  if (!isWebvhDid(pointer.did)) {
    return null
  }

  const { doc, log } = await verifiedAccountLog({
    profile: session.profile,
    pointer
  })
  const pointedDid = delegatedClientsPointer({ doc })
  if (pointedDid === undefined) {
    // No annex posture on this account: nothing to swap, and no
    // auxiliary Space to list orphans in.
    return null
  }
  const clientAnnexSpaceId = clientAnnexDidParts({ did: pointedDid }).spaceId

  const idbFactory = persistence.idb
  const was = new WasClient({
    serverUrl: pointer.host,
    zcapClient: session.profile.zcapClient
  })
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
    },
    onCollected: async ({ generationId }) => {
      // A collected generation's chain-head pin slot is dropped beside it;
      // the slot key is generation-scoped and generation ids are never
      // reused, so a leftover slot would only ever be dead weight.
      await deleteLogPin({
        logId: clientAnnexLogPinId({
          spaceId: clientAnnexSpaceId,
          generationId
        }),
        ...(idbFactory !== undefined ? { idb: idbFactory } : {})
      })
    },
    pinStore: persistence.logPins
  })
  if (report.swap === 'replaced') {
    invalidateVerifiedLog({ profile: session.profile })
  }
  return report
}
