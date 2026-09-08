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
import type {
  AccountLogSigner,
  DelegatedWebvhLogStore
} from '@interop/wallet-core/webvh'
import {
  ladderVmAgent,
  ladderVmZcapClient
} from '@interop/wallet-core/clientAnnex'
import type { SealableEncryptionDescriptorStore } from '@interop/wallet-core/keys'
import { WAS_SERVER_URL } from '@/app.config'
import type { ICapabilityAgent, Session } from '@/types/auth'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'
import { sessionRosterStore } from '@/session/rosterStore'
import {
  sessionCollectionStores,
  type CollectionStoreFor
} from '@/session/collectionLogStore'
import { unlockLogStore } from '@/session/standingUnlock'
import {
  didWebProjectionStore,
  renewTransientGenerationDelegation
} from '@/session/annexReach'
import {
  bindCredentialAnchoredUnlockSecret,
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
   * Each encrypted collection's log-governed descriptor store, signed by the
   * same key the roster store signs with and reached through the remote
   * store's handle, so a request rides the capability held at call time.
   */
  readonly collectionStore: CollectionStoreFor
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
  /**
   * The DELETE-only / GET-only child mint and its invoker. Its `zcapClient`
   * is also the branch's one delegation signer -- the ladder VM, which every
   * delegation this branch mints is signed by, since the annex VM stands in
   * no account document.
   */
  ladderDeleter: LadderDeleter
  /** the remote-only unlock-record binder: nothing lands on this browser */
  bindRecord: RemoteUnlockRecordBind
  /**
   * The account Space's `id` collection as a did:web projection store, built
   * on first read. A ladder-signed entry writes `did.jsonl` alone, so every
   * ceremony that strikes an inventory PUTs the post-strike projection
   * through this immediately before its own entry.
   */
  readonly projectionStore: DelegatedWebvhLogStore
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
  let collectionStore: CollectionStoreFor | undefined
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
      get collectionStore() {
        return (collectionStore ??= sessionCollectionStores({
          profile,
          remoteStore: reach.remoteStore,
          keyAgent: profile.keyAgent!
        }))
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
  let ladderProjectionStore: DelegatedWebvhLogStore | undefined
  // The live authority, read off the profile on every call rather than
  // snapshotted here: a ceremony that renews or replaces its generation
  // delegation mid-run must have every later request ride the replacement.
  const invokerNow = (): CeremonyInvoker => ({
    zcapClient: profile.zcapClient,
    ...(profile.invocationCapability
      ? { capability: profile.invocationCapability }
      : {})
  })
  return {
    kind: 'ladder',
    ...reach,
    signer: { kind: 'ladder', ladderSeed },
    // The bridge store: public fetches for the world-readable `did.jsonl`,
    // and the record's PUT-on-`did.jsonl` bridge for the write.
    get idStore() {
      return (ladderIdStore ??= unlockLogStore({
        pointer: reach.pointer,
        delegation: standingUnlock.delegation,
        zcapClient: standingAgents.zcapClient,
        pinStore: profile.persistence.logPins
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
    // Not memoized: each collection's handle is taken off the remote store at
    // the call, so a store built after a mid-ceremony renewal rides the
    // replacement delegation with no capability bookkeeping here.
    get collectionStore() {
      return sessionCollectionStores({
        profile,
        remoteStore: reach.remoteStore,
        keyAgent: agent
      })
    },
    get invoker() {
      return invokerNow()
    },
    // Memoized once: the store resolves the invoker on every call of its own,
    // so it never holds a delegation the ceremony's pivot has struck.
    get projectionStore() {
      return (ladderProjectionStore ??= didWebProjectionStore({
        host: reach.pointer.host,
        spaceId: reach.pointer.spaceId,
        invoker: invokerNow,
        pinStore: profile.persistence.logPins
      }))
    },
    ladderDeleter: {
      zcapClient: delegationSigner,
      invoker: didKeyZcapClient({ keyAgent: agent }),
      controller: agent.id
    },
    bindRecord: bindCredentialAnchoredUnlockSecret,
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
