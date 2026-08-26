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
 * account with no annex inventory is an ordinary state, and each caller keeps
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
  ladderSignedGenerationDelegationMinter,
  ladderVmKeyMultibase,
  mintGenerationDelegation
} from '@interop/wallet-core/clientAnnex'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import { ladderVmIds, verifyAccountLog } from '@interop/wallet-core/webvh'
import type { PublishedKeyDocument } from '@interop/wallet-core/webvh'
import { createLogger } from '@/lib/log'
import { verifiedAccountLog } from '@/session/verifiedLog'
import type { Session } from '@/types/auth'

const log = createLogger('fw:session:annex')

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
 * The reach a CREDENTIAL-ONLY session has over a generation: the annex Space
 * answers to the account did:webvh, which a transient session's per-visit key
 * is not, so its log writes invoke the record's sibling delegation under the
 * credential-derived standing client instead of this session's own key.
 *
 * @param options {object}
 * @param options.pointer {ReachPointer}   the account pointer
 * @param options.clientAnnexDid {string}   the generation's did:webvh
 * @param options.standing {object}   the session's standing members: the
 *   credential's client identity and its annex-Space sibling delegation
 * @returns {ClientAnnexReach}
 */
export function standingClientAnnexReachOf({
  pointer,
  clientAnnexDid,
  standing
}: {
  pointer: ReachPointer
  clientAnnexDid: string
  standing: {
    standingClient: { agents: { zcapClient: ZcapClient } }
    delegatedClients: IZcap
  }
}): ClientAnnexReach {
  const { spaceId, generationId } = clientAnnexDidParts({
    did: clientAnnexDid
  })
  const was = new WasClient({
    serverUrl: pointer.host,
    zcapClient: standing.standingClient.agents.zcapClient
  })
  let store: ReturnType<typeof clientAnnexLogStore> | undefined
  return {
    clientAnnexDid,
    spaceId,
    generationId,
    was,
    logId: clientAnnexLogPinId({ spaceId, generationId }),
    logStore: () =>
      (store ??= clientAnnexLogStore({
        was,
        spaceId,
        generationId,
        capability: standing.delegatedClients
      }))
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
 * memo), or `null` when the account carries no annex inventory. The verified
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
  return await runEnsureGenerationDelegation({
    reach,
    ladderSeed,
    mint: async ({ clientAnnexDid }) =>
      mintGenerationDelegation({
        zcapClient: session.profile.zcapClient,
        wasServerUrl: pointer.host,
        spaceId: pointer.spaceId,
        clientAnnexDid
      }),
    ...(accountDoc !== undefined ? { accountDoc } : {}),
    ...(pin !== undefined ? { pin } : {})
  })
}

/**
 * The same ensure, signed by the credential's LADDER rather than by an
 * enrolled client's key: the fresh delegation is minted by the ladder VM
 * (`ladderSignedGenerationDelegationMinter`), which is the one licensed
 * delegator on a ladder-anchored account -- and the renewal must not depend
 * on the very delegation it replaces. Its callers are the sessions that hold
 * no durable signer at all: the transient visit's grant-approval renewal
 * stage.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account did:webvh, whose ladder
 *   VM signs
 * @param options.pointer {ReachPointer}   the account pointer
 * @param options.reach {ClientAnnexReach}   the pointed generation, reached
 *   under an authority the caller holds over the annex Space
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed --
 *   both the delegation's signer and the rung the annex entry is signed with
 * @param [options.accountDoc] {PublishedKeyDocument}   the account document
 *   the standing delegation's signer is checked against
 * @param [options.pin] {object}   the generation log's chain-head pin store
 *   and slot key
 * @returns {Promise<{ renewed: boolean, delegation: IZcap }>}
 */
export async function ensureLadderSignedGenerationDelegation({
  accountDid,
  pointer,
  reach,
  ladderSeed,
  accountDoc,
  pin
}: {
  accountDid: string
  pointer: ReachPointer
  reach: ClientAnnexReach
  ladderSeed: Uint8Array
  accountDoc?: PublishedKeyDocument
  pin?: { pinStore: ResourceLogPinStore; logId: string }
}): Promise<{ renewed: boolean; delegation: IZcap }> {
  return await runEnsureGenerationDelegation({
    reach,
    ladderSeed,
    mint: ladderSignedGenerationDelegationMinter({
      accountDid,
      ladderSeed,
      wasServerUrl: pointer.host,
      spaceId: pointer.spaceId
    }),
    ...(accountDoc !== undefined ? { accountDoc } : {}),
    ...(pin !== undefined ? { pin } : {})
  })
}

/**
 * The shared body of the two ensures above: everything but which signer
 * mints the fresh delegation.
 *
 * @param options {object}
 * @param options.reach {ClientAnnexReach}   the pointed generation
 * @param options.ladderSeed {Uint8Array}   the seed whose committed rung
 *   signs the annex entry
 * @param options.mint {Function}   `({ clientAnnexDid }) => Promise<IZcap>`
 * @param [options.accountDoc] {PublishedKeyDocument}
 * @param [options.pin] {object}
 * @returns {Promise<{ renewed: boolean, delegation: IZcap }>}
 */
async function runEnsureGenerationDelegation({
  reach,
  ladderSeed,
  mint,
  accountDoc,
  pin
}: {
  reach: ClientAnnexReach
  ladderSeed: Uint8Array
  mint: (options: { clientAnnexDid: string }) => Promise<IZcap>
  accountDoc?: PublishedKeyDocument
  pin?: { pinStore: ResourceLogPinStore; logId: string }
}): Promise<{ renewed: boolean; delegation: IZcap }> {
  return await ensureGenerationDelegationCurrent({
    store: reach.logStore(),
    ladderSeed,
    generationId: reach.generationId,
    mintGenerationDelegation: mint,
    expectedDid: reach.clientAnnexDid,
    ...(accountDoc !== undefined ? { accountDoc } : {}),
    ...(pin !== undefined ? { pinStore: pin.pinStore, logId: pin.logId } : {})
  })
}

/**
 * The grant path's blocking renewal stage: renews a transient session's
 * generation delegation in place -- ladder-signed, through the credential's
 * sibling delegation -- and swaps the fresh one into the live session, so
 * the grants minted after it chain under a parent that outlives them.
 *
 * The ladder-VM gate is this path's own, mirroring the one wallet-core's
 * annex ensure opens with: the account log is re-verified under the visit's
 * pins and the credential's ladder VM must be a verification method of the
 * resolved document. Without it a fresh delegation would be signed by a key
 * the current-key-set rule authorizes nothing under -- and, worse, it would
 * be embedded in the annex log, where every later transient visit adopts it
 * as the generation's delegation until a GC swap. The account this guards is
 * exactly the one the transient login's fallback serves: enrolled durable
 * clients, no ladder VM in the document.
 *
 * Best-effort by contract, `null` by return: a session that is not transient
 * (no invocation capability, no ladder members), a document that does not
 * anchor this ladder, an account log that would not verify, or a renewal
 * that fails for any reason leaves the session untouched, and the caller's
 * stale-delegation refusal stands. Nothing here throws.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<IZcap | null>}   the fresh delegation, or `null` when
 *   none was installed
 */
export async function renewTransientGenerationDelegation({
  session
}: {
  session: Session
}): Promise<IZcap | null> {
  const { profile } = session
  const { ladderSeed, standingUnlock, accountPointer, persistence } = profile
  const delegatedClients = standingUnlock?.delegatedClients
  if (
    !ladderSeed ||
    !standingUnlock ||
    !delegatedClients ||
    !accountPointer?.did ||
    !('clientAnnex' in persistence)
  ) {
    return null
  }
  const accountDid = accountPointer.did
  try {
    // The gate: the verified account document must list this credential's
    // ladder VM. It doubles as the ensure's signer-rot axis below.
    const verified = await verifyAccountLog({
      did: accountDid,
      spaceId: accountPointer.spaceId,
      host: accountPointer.host,
      pinStore: persistence.logPins
    })
    const doc = verified.doc
    const vmKeyMultibase = await ladderVmKeyMultibase({ ladderSeed })
    if (!ladderVmIds({ doc }).includes(`${accountDid}#${vmKeyMultibase}`)) {
      log.warn(
        'Skipping the generation-delegation renewal: the account document ' +
          "does not anchor this credential's ladder VM",
        { accountDid }
      )
      return null
    }
    const reach = standingClientAnnexReachOf({
      pointer: accountPointer,
      clientAnnexDid: persistence.clientAnnex.clientAnnexDid,
      standing: {
        standingClient: standingUnlock.standingClient,
        delegatedClients
      }
    })
    const { delegation } = await ensureLadderSignedGenerationDelegation({
      accountDid,
      pointer: accountPointer,
      reach,
      ladderSeed,
      accountDoc: doc,
      pin: { pinStore: persistence.logPins, logId: reach.logId }
    })
    // The live session adopts it. The profile stamp is what the grant path
    // reads its parent from, and the remote store swaps the capability its
    // requests ride so a listing made after this renewal invokes the fresh
    // delegation rather than the copy it captured at construction. The
    // handle member is rewritten for coherence only: session assembly read
    // it once at login and nothing re-reads it mid-session.
    profile.invocationCapability = delegation
    persistence.clientAnnex.invocationCapability = delegation
    session.storage.remoteStore?.adoptInvocationCapability({
      capability: delegation
    })
    return delegation
  } catch (err) {
    log.warn('Generation-delegation renewal failed', { err })
    return null
  }
}
