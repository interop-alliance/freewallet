/**
 * The account-ceremony context: the authorities a ceremony that acts AS the
 * account runs on, resolved once from a live session and bound to whichever
 * of the two kinds this session is.
 *
 * A remembered session is the ENROLLED kind. Its account-log entries are
 * signed by this client's own did:webvh update keys, its roster appends by
 * this client's key agent, and its WAS requests invoke the Space's root
 * capability.
 *
 * A transient session on a standing unlock credential is the LADDER kind. Its
 * account-log entries are signed by a rung of the credential's update-key
 * ladder and published through the record's bridge delegation, its roster
 * appends by the credential's ladder VM (the ceremony-tail license's
 * anchoring), and its WAS requests are invoked by the per-visit annex VM
 * under the generation delegation. It also carries what only that kind needs:
 * the ladder VM's own delegation signer (every single-verb child and every
 * generation-delegation replacement chains to it, since the annex VM stands
 * in no account document), the DELETE-only child mint the deletion walk uses,
 * the remote-only record binder (a transient visit writes nothing to this
 * browser), the credential's sibling delegation into the client annex, and
 * the standing key-agreement key every roster and registry unwrap needs.
 *
 * A guest, a no-WAS session, and a transient session whose record carries no
 * standing members resolve to `null`: neither kind's authorities exist.
 *
 * The boolean gates the UI enables its controls on are DERIVED from the same
 * resolution rather than restating it, so a gate and its ceremony cannot
 * disagree.
 */
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import {
  didKeyZcapClient,
  isWebvhDid,
  type ClientWebvhUpdateKeys,
  type WebvhIdStore
} from '@interop/wallet-core/webvh'
import type { AccountLogSigner } from '@interop/wallet-core/webvh'
import {
  ladderVmAgent,
  ladderVmZcapClient
} from '@interop/wallet-core/clientAnnex'
import type { SealableEncryptionDescriptorStore } from '@interop/wallet-core/keys'
import { WAS_SERVER_URL } from '@/app.config'
import type { ICapabilityAgent, Session } from '@/types/auth'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'
import { sessionRosterStore } from '@/session/rosterStore'
import { unlockLogStore } from '@/session/standingUnlock'
import { renewTransientGenerationDelegation } from '@/session/annexReach'
import {
  bindRemoteUnlockRecord,
  type RemoteUnlockRecordBind
} from '@/session/keyring'

/**
 * The HTTP authority a ceremony's requests ride: the signing client, plus the
 * delegated capability every request is invoked under when this session holds
 * no root authority over the data Space. The enrolled kind carries no
 * capability and root-invokes.
 */
export interface CeremonyInvoker {
  zcapClient: ZcapClient
  capability?: IZcap
}

/**
 * The single-verb capability mints a ladder-anchored ceremony needs, plus the
 * identity that invokes them: the ladder VM delegates a DELETE-only (or
 * GET-only) child of a Space's root or of a management zcap, to its own bare
 * did:key, which resolves from its own bytes and so outlives the Space.
 */
export interface LadderDeleter {
  /** the delegating signer: the ladder VM under `<accountDid>#<multibase>` */
  zcapClient: ZcapClient
  /** the delegatee and invoker: the ladder VM's own bare did:key */
  invoker: ZcapClient
  /** the delegatee DID */
  controller: string
}

/**
 * What every ceremony reads off the context whichever kind it is.
 */
interface CeremonyContextBase {
  remoteStore: WASRemoteStore
  pointer: AccountPointer & { did: string }
  controller: string
  signer: AccountLogSigner
  /** built on first read: a UI gate resolves the context without one */
  readonly idStore: WebvhIdStore
  /** built on first read, for the same reason */
  readonly rosterStore: SealableEncryptionDescriptorStore
  /**
   * Read LIVE off the session's profile on every access, never snapshotted at
   * resolution: a ceremony that renews its generation delegation mid-run
   * (the rule for a struck signer) replaces the capability every later
   * stage must invoke under, and a stage holding the copy this context was
   * built with would invoke a delegation whose signer the pivot has struck.
   */
  readonly invoker: CeremonyInvoker
}

/**
 * A remembered session's context: this client's own key material signs
 * everything, and every request root-invokes.
 */
export interface EnrolledCeremonyContext extends CeremonyContextBase {
  kind: 'enrolled'
  signer: { kind: 'client'; updateKeys: ClientWebvhUpdateKeys }
  clientWebvhKeys: ClientWebvhUpdateKeys
  clientKeyAgreementKey: IKeyAgreementKey
  keyAgent: ICapabilityAgent
}

/**
 * A transient session's context on a standing unlock credential.
 */
export interface LadderCeremonyContext extends CeremonyContextBase {
  kind: 'ladder'
  signer: { kind: 'ladder'; ladderSeed: Uint8Array }
  /** the credential's ladder seed, restated for the stages that name it */
  ladderSeed: Uint8Array
  /** the ladder VM's zcap signer: every delegation this branch mints */
  delegationSigner: ZcapClient
  /** the DELETE-only / GET-only child mint and its invoker */
  ladderDeleter: LadderDeleter
  /** the remote-only unlock-record binder: nothing lands on this browser */
  bindRecord: RemoteUnlockRecordBind
  /** the record's `delegatedClients` sibling: the one path into the annex */
  sibling?: IZcap
  /** the acting credential's unlock-Space management zcap */
  manageCapability?: IZcap
  /** the acting credential's unlock Space id, the registry's match key */
  unlockSpaceId: string
  /** the standing key-agreement key every roster and registry unwrap needs */
  standingKeyAgreementKey: IKeyAgreementKey
  /**
   * Renews the generation delegation in place and adopts it into the live
   * session (profile stamp, persistence strategy, remote store).
   */
  renew: () => Promise<IZcap | null>
}

export type AccountCeremonyContext =
  EnrolledCeremonyContext | LadderCeremonyContext

/**
 * Which precondition a session misses, in the order they are checked.
 */
type MissingPrecondition =
  'storage' | 'pointer' | 'updateKeys' | 'keyAgreementKey' | 'keyAgent'

/**
 * The shared half both kinds resolve first: a configured storage server with
 * a remote store, and a promoted did:webvh account pointer.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {object | { missing: MissingPrecondition }}
 */
function resolveAccountReach({ session }: { session: Session }):
  | {
      remoteStore: WASRemoteStore
      pointer: AccountPointer & { did: string }
      controller: string
    }
  | { missing: MissingPrecondition } {
  const remoteStore = session.storage.remoteStore
  if (!WAS_SERVER_URL || !remoteStore || session.isGuest) {
    return { missing: 'storage' }
  }
  const pointer = session.profile.accountPointer
  if (!pointer || !isWebvhDid(pointer.did)) {
    return { missing: 'pointer' }
  }
  return {
    remoteStore,
    // The did:webvh guard above is what makes `did` a string here, so the
    // pointer handed back names the account the log must resolve to.
    pointer: { ...pointer, did: pointer.did },
    controller: session.profile.accountController ?? session.user.id
  }
}

/**
 * Resolves the enrolled kind, or names the first precondition the session
 * misses. Synchronous: every member is already in the profile.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {{ context: EnrolledCeremonyContext } | { missing: MissingPrecondition }}
 */
function resolveEnrolledContext({
  session
}: {
  session: Session
}): { context: EnrolledCeremonyContext } | { missing: MissingPrecondition } {
  const reach = resolveAccountReach({ session })
  if ('missing' in reach) {
    return reach
  }
  const { profile } = session
  if (!profile.clientWebvhKeys) {
    return { missing: 'updateKeys' }
  }
  if (!profile.clientKeyAgreementKey) {
    return { missing: 'keyAgreementKey' }
  }
  if (!profile.keyAgent) {
    return { missing: 'keyAgent' }
  }
  let idStore: WebvhIdStore | undefined
  let rosterStore: SealableEncryptionDescriptorStore | undefined
  return {
    context: {
      kind: 'enrolled',
      ...reach,
      signer: { kind: 'client', updateKeys: profile.clientWebvhKeys },
      get idStore() {
        return (idStore ??= reach.remoteStore.webvhIdStore())
      },
      get rosterStore() {
        return (rosterStore ??= sessionRosterStore({ profile }))
      },
      get invoker() {
        return { zcapClient: profile.zcapClient }
      },
      clientWebvhKeys: profile.clientWebvhKeys,
      clientKeyAgreementKey: profile.clientKeyAgreementKey,
      keyAgent: profile.keyAgent
    }
  }
}

/**
 * The enrolled-kind context, or `null` when this session holds no enrolled
 * client's key material. The non-throwing form, for the UI gates and for
 * callers that degrade rather than fail.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {EnrolledCeremonyContext | null}
 */
export function enrolledCeremonyContext({
  session
}: {
  session: Session
}): EnrolledCeremonyContext | null {
  const resolved = resolveEnrolledContext({ session })
  return 'context' in resolved ? resolved.context : null
}

/**
 * The enrolled-kind context, or a throw naming the missing precondition.
 * Callers gate on the derived boolean first, so a throw here is defensive.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.action {string}   the ceremony's name, as the error message
 *   opens ("Client revocation requires ...")
 * @returns {EnrolledCeremonyContext}
 */
export function requireEnrolledCeremonyContext({
  session,
  action
}: {
  session: Session
  action: string
}): EnrolledCeremonyContext {
  const resolved = resolveEnrolledContext({ session })
  if ('context' in resolved) {
    return resolved.context
  }
  switch (resolved.missing) {
    case 'storage':
      throw new Error(`${action} requires a configured storage server.`)
    case 'pointer':
      throw new Error(
        `${action} requires a promoted did:webvh account; this account has ` +
          'not finished provisioning.'
      )
    case 'updateKeys':
      throw new Error(`${action} requires this client's did:webvh update keys.`)
    case 'keyAgent':
      throw new Error(`${action} requires this client's signing key.`)
    default:
      throw new Error(`${action} requires this client's key-agreement key.`)
  }
}

/**
 * The invocation capability a ceremony's requests ride, as a THUNK rather
 * than a value: absent on the enrolled kind (which root-invokes), the
 * visit's generation delegation on the ladder kind. Spread at each call site
 * (`...rides()`) so the two kinds share one call site and every stage picks
 * up a capability a mid-ceremony renewal replaced. A ceremony that captured
 * the value once would invoke a delegation its own pivot has struck.
 *
 * @param options {object}
 * @param options.context {AccountCeremonyContext | null}
 * @returns {Function}   `() => { capability?: IZcap }`
 */
export function ceremonyRides({
  context
}: {
  context: AccountCeremonyContext | null
}): () => { capability?: IZcap } {
  return () =>
    context?.invoker.capability
      ? { capability: context.invoker.capability }
      : {}
}

/**
 * Whether this session can run the account ceremonies at all -- the
 * synchronous predicate behind every Settings gate, true for both kinds.
 * It resolves the same preconditions {@link accountCeremonyContext} does,
 * minus the async signer derivations, so a gate and its ceremony cannot
 * disagree.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {boolean}
 */
export function canRunAccountCeremonies({
  session
}: {
  session: Session
}): boolean {
  if (enrolledCeremonyContext({ session })) {
    return true
  }
  const reach = resolveAccountReach({ session })
  if ('missing' in reach) {
    return false
  }
  const { ladderSeed, standingUnlock } = session.profile
  return !!ladderSeed && !!standingUnlock
}

/**
 * The account-ceremony context for this session, bound to whichever kind it
 * is, or `null` when neither kind's authorities exist.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<AccountCeremonyContext | null>}
 */
export async function accountCeremonyContext({
  session
}: {
  session: Session
}): Promise<AccountCeremonyContext | null> {
  const enrolled = enrolledCeremonyContext({ session })
  if (enrolled) {
    return enrolled
  }
  const reach = resolveAccountReach({ session })
  if ('missing' in reach) {
    return null
  }
  const { profile } = session
  const { ladderSeed, standingUnlock } = profile
  if (!ladderSeed || !standingUnlock) {
    return null
  }
  const accountDid = reach.pointer.did
  const delegationSigner = await ladderVmZcapClient({ accountDid, ladderSeed })
  const agent = await ladderVmAgent({ ladderSeed })
  const standingAgents = standingUnlock.standingClient.agents
  let ladderIdStore: WebvhIdStore | undefined
  let ladderRosterStore: SealableEncryptionDescriptorStore | undefined
  let ladderRosterCapability: IZcap | undefined
  return {
    kind: 'ladder',
    ...reach,
    signer: { kind: 'ladder', ladderSeed },
    ladderSeed,
    // The bridge store: public fetches for the world-readable `did.jsonl`,
    // and the record's PUT-on-`did.jsonl` bridge for the write.
    get idStore() {
      return (ladderIdStore ??= unlockLogStore({
        pointer: reach.pointer,
        delegation: standingUnlock.delegation,
        zcapClient: standingAgents.zcapClient
      }) as WebvhIdStore)
    },
    // Ladder-signed appends, invoked by the annex VM under the generation
    // delegation -- the only authority this session holds over the Space.
    // Memoized against the capability it was built with rather than on first
    // read alone: a mid-ceremony renewal replaces that capability, and a
    // store still riding the replaced one would be refused past the pivot.
    get rosterStore() {
      const capability = profile.invocationCapability
      if (
        ladderRosterStore === undefined ||
        ladderRosterCapability !== capability
      ) {
        ladderRosterCapability = capability
        ladderRosterStore = sessionRosterStore({
          profile,
          keyAgent: agent,
          ...(capability ? { capability } : {})
        })
      }
      return ladderRosterStore
    },
    get invoker() {
      return {
        zcapClient: profile.zcapClient,
        ...(profile.invocationCapability
          ? { capability: profile.invocationCapability }
          : {})
      }
    },
    delegationSigner,
    ladderDeleter: {
      zcapClient: delegationSigner,
      invoker: didKeyZcapClient({ keyAgent: agent }),
      controller: agent.id
    },
    bindRecord: bindRemoteUnlockRecord,
    ...(standingUnlock.delegatedClients
      ? { sibling: standingUnlock.delegatedClients }
      : {}),
    ...(profile.unlockMethod?.manageCapability
      ? { manageCapability: profile.unlockMethod.manageCapability }
      : {}),
    unlockSpaceId: standingUnlock.unlockSpaceId,
    standingKeyAgreementKey: standingAgents.keyAgreementKey as IKeyAgreementKey,
    renew: async () => renewTransientGenerationDelegation({ session })
  }
}
