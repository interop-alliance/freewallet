/**
 * Reaching this account's pointed client annex generation: the preamble every
 * annex-touching surface opens with, resolved once here instead of open-coded
 * per ceremony. The account document's `#DelegatedClients` pointer names the
 * live generation; its did:webvh splits into the auxiliary Space id and the
 * generation id, which together address the generation's log store and its
 * chain-head pin slot, reached through a `WasClient` on the account
 * pointer's host under this session's own authority.
 *
 * "No pointed generation" is resolved as `null` rather than thrown: an
 * account with no annex posture is an ordinary state, and each caller keeps
 * its own reaction to it (the GC sweep and the deletion teardown skip, the
 * revocation cascade reports `no-pointer`, the login-time heal returns).
 *
 * The generation-delegation re-mint adapter lives here too, beside the reach
 * it is always run over: the login-time self-heal, the revocation cascade's
 * re-mint stage, and the bind ceremony's install all drive wallet-core's
 * `ensureGenerationDelegationCurrent` with the same store, ladder seed, and
 * minting closure, differing only in the ladder seed's provenance, whether
 * they hand it a post-edit account document, and whether they wire the pin
 * store -- all three passed in by the caller.
 */
import { WasClient } from '@interop/was-client'
import {
  clientAnnexDidParts,
  clientAnnexLogPinId,
  clientAnnexLogStore,
  delegatedClientsPointer,
  ensureGenerationDelegationCurrent,
  mintGenerationDelegation
} from '@interop/wallet-core/clientAnnex'
import type { ResourceLogPinStore } from '@interop/wallet-core/resourceLog'
import type { PublishedKeyDocument } from '@interop/wallet-core/webvh'
import { verifiedAccountLog } from '@/session/verifiedLog'
import type { Session } from '@/types/auth'

/**
 * The account document a `#DelegatedClients` pointer is read out of.
 */
type AccountDoc = Parameters<typeof delegatedClientsPointer>[0]['doc']

/**
 * Where the account Space lives: everything the reach needs from an account
 * pointer (the host it is served from, and the Space a generation delegation
 * targets).
 */
type ReachPointer = { host: string; spaceId: string }

/**
 * One pointed annex generation, as a ceremony reaches it: the generation's
 * did:webvh and its two parts, the client that talks to the auxiliary Space,
 * the generation log's chain-head pin slot key, and the log store itself
 * (built on first use, so a caller that only wants the Space id does not
 * build one).
 */
export interface ClientAnnexReach {
  clientAnnexDid: string
  spaceId: string
  generationId: string
  was: WasClient
  logId: string
  logStore: () => ReturnType<typeof clientAnnexLogStore>
}

/**
 * The reach for a generation this caller already names.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.pointer {ReachPointer}   the account pointer
 * @param options.clientAnnexDid {string}   the generation's did:webvh
 * @returns {ClientAnnexReach}
 */
export function clientAnnexReachOf({
  session,
  pointer,
  clientAnnexDid
}: {
  session: Session
  pointer: ReachPointer
  clientAnnexDid: string
}): ClientAnnexReach {
  const { spaceId, generationId } = clientAnnexDidParts({
    did: clientAnnexDid
  })
  const was = new WasClient({
    serverUrl: pointer.host,
    zcapClient: session.profile.zcapClient
  })
  let store: ReturnType<typeof clientAnnexLogStore> | undefined
  return {
    clientAnnexDid,
    spaceId,
    generationId,
    was,
    logId: clientAnnexLogPinId({ spaceId, generationId }),
    logStore: () =>
      (store ??= clientAnnexLogStore({ was, spaceId, generationId }))
  }
}

/**
 * The reach for the generation an account document points at, or `null` when
 * it points at none.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.pointer {ReachPointer}   the account pointer
 * @param options.doc {object}   the account document to read the pointer out
 *   of (a ceremony's post-edit document, or a verified one)
 * @returns {ClientAnnexReach | null}
 */
export function clientAnnexReachFor({
  session,
  pointer,
  doc
}: {
  session: Session
  pointer: ReachPointer
  doc: AccountDoc
}): ClientAnnexReach | null {
  const pointedDid = delegatedClientsPointer({ doc })
  if (pointedDid === undefined) {
    return null
  }
  return clientAnnexReachOf({ session, pointer, clientAnnexDid: pointedDid })
}

/**
 * The reach for the generation this session's account currently points at,
 * off the locally verified account log (through the session's verified-log
 * memo), or `null` when the account carries no annex posture. The verified
 * log's document and entries ride along for callers that need them.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.pointer {object}   the account pointer to verify against
 * @returns {Promise<(ClientAnnexReach & { doc, log }) | null>}
 */
export async function pointedClientAnnexReach({
  session,
  pointer
}: {
  session: Session
  pointer: ReachPointer & { did?: string }
}): Promise<
  | (ClientAnnexReach &
      Pick<Awaited<ReturnType<typeof verifiedAccountLog>>, 'doc' | 'log'>)
  | null
> {
  const { doc, log } = await verifiedAccountLog({
    profile: session.profile,
    pointer
  })
  const reach = clientAnnexReachFor({ session, pointer, doc })
  return reach === null ? null : { ...reach, doc, log }
}

/**
 * Runs wallet-core's `ensureGenerationDelegationCurrent` over a reached
 * generation: the embedded generation delegation is installed when the annex
 * document carries none, and renewed when it is expiring or its signer has
 * left the account document. The fresh delegation is minted against the
 * account Space the pointer names, signed by this session's own key; the
 * annex entry that embeds it is signed by the supplied ladder seed's rung.
 *
 * The optional members are the callers' documented divergences: the
 * signer-death axis (`accountDoc`, a post-edit document) is supplied only
 * where a ceremony holds one, and the chain-head pin wiring only where the
 * caller has a pin store to hand.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.pointer {ReachPointer}   the account pointer
 * @param options.reach {ClientAnnexReach}   the pointed generation
 * @param options.ladderSeed {Uint8Array}   the seed whose committed rung
 *   signs the annex entry
 * @param [options.accountDoc] {PublishedKeyDocument}   the account document
 *   the delegation's signer is checked against
 * @param [options.pin] {object}   the generation log's chain-head pin store
 *   and slot key
 * @returns {Promise<{ renewed: boolean }>}
 */
export async function ensureGenerationDelegation({
  session,
  pointer,
  reach,
  ladderSeed,
  accountDoc,
  pin
}: {
  session: Session
  pointer: ReachPointer
  reach: ClientAnnexReach
  ladderSeed: Uint8Array
  accountDoc?: PublishedKeyDocument
  pin?: { pinStore: ResourceLogPinStore; logId: string }
}): Promise<{ renewed: boolean }> {
  return await ensureGenerationDelegationCurrent({
    store: reach.logStore(),
    ladderSeed,
    generationId: reach.generationId,
    mintGenerationDelegation: async ({ clientAnnexDid }) =>
      mintGenerationDelegation({
        zcapClient: session.profile.zcapClient,
        wasServerUrl: pointer.host,
        spaceId: pointer.spaceId,
        clientAnnexDid
      }),
    expectedDid: reach.clientAnnexDid,
    ...(accountDoc !== undefined ? { accountDoc } : {}),
    ...(pin !== undefined ? { pinStore: pin.pinStore, logId: pin.logId } : {})
  })
}
