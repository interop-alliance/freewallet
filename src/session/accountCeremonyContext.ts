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
import type {
  CollectionStoreFor,
  SealableEncryptionDescriptorStore
} from '@interop/wallet-core/keys'
import { WAS_SERVER_URL } from '@/app.config'
import type { ControllerProfile, ICapabilityAgent, Session } from '@/types/auth'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'
import { sessionRosterStore } from '@/session/rosterStore'
import { sessionCollectionStores } from '@/session/collectionLogStore'
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
  /**
   * the delegating signer: the ladder VM under `<accountDid>#<multibase>`
   */
  zcapClient: ZcapClient
  /**
   * the delegatee and invoker: the ladder VM's own bare did:key
   */
  invoker: ZcapClient
  /**
   * the delegatee DID
   */
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
  /**
   * built on first read: a UI gate resolves the context without one
   */
  readonly idStore: WebvhIdStore
  /**
   * built on first read, for the same reason
   */
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
  /**
   * the remote-only unlock-record binder: nothing lands on this browser
   */
  bindRecord: RemoteUnlockRecordBind
  /**
   * The account Space's `id` collection as a did:web projection store, built
   * on first read. A ladder-signed entry writes `did.jsonl` alone, so every
   * ceremony that strikes an inventory PUTs the post-strike projection
   * through this immediately before its own entry.
   */
  readonly projectionStore: DelegatedWebvhLogStore
  /**
   * the record's `delegatedClients` sibling: the one path into the annex
   */
  sibling?: IZcap
  /**
   * the acting credential's unlock-Space management zcap
   */
  manageCapability?: IZcap
  /**
   * the acting credential's unlock Space id, the registry's match key
   */
  unlockSpaceId: string
  /**
   * the standing key-agreement key every roster and registry unwrap needs
   */
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
 * An enrolled client's key material off the profile, or the first member
 * missing. The one test of that material: the full resolution below consumes
 * what it hands back, and {@link sessionAuthorityKind} decides the enrolled
 * kind by it.
 *
 * @param options {object}
 * @param options.profile {ControllerProfile}
 * @returns {object | { missing: MissingPrecondition }}
 */
function enrolledKeyMaterial({ profile }: { profile: ControllerProfile }):
  | {
      clientWebvhKeys: ClientWebvhUpdateKeys
      clientKeyAgreementKey: IKeyAgreementKey
      keyAgent: ICapabilityAgent
    }
  | { missing: MissingPrecondition } {
  if (!profile.clientWebvhKeys) {
    return { missing: 'updateKeys' }
  }
  if (!profile.clientKeyAgreementKey) {
    return { missing: 'keyAgreementKey' }
  }
  if (!profile.keyAgent) {
    return { missing: 'keyAgent' }
  }
  return {
    clientWebvhKeys: profile.clientWebvhKeys,
    clientKeyAgreementKey: profile.clientKeyAgreementKey,
    keyAgent: profile.keyAgent
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
  const material = enrolledKeyMaterial({ profile })
  if ('missing' in material) {
    return material
  }
  let idStore: WebvhIdStore | undefined
  let rosterStore: SealableEncryptionDescriptorStore | undefined
  let collectionStore: CollectionStoreFor | undefined
  return {
    context: {
      kind: 'enrolled',
      ...reach,
      signer: { kind: 'client', updateKeys: material.clientWebvhKeys },
      get idStore() {
        return (idStore ??= reach.remoteStore.webvhIdStore())
      },
      get rosterStore() {
        return (rosterStore ??= sessionRosterStore({ session }))
      },
      get collectionStore() {
        return (collectionStore ??= sessionCollectionStores({
          session,
          remoteStore: reach.remoteStore,
          keyAgent: material.keyAgent
        }))
      },
      get invoker() {
        return { zcapClient: profile.zcapClient }
      },
      ...material
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
  if (sessionAuthorityKind({ session })?.kind !== 'ladder') {
    return false
  }
  return !('missing' in resolveAccountReach({ session }))
}

/**
 * The authority kind this session HOLDS, with the key material that decided
 * it, whether or not the account preconditions a full resolution adds are
 * met. A caller consumes what was tested rather than restating the test.
 *
 * It is the mender registry's fallback when {@link accountCeremonyContext}
 * resolves nothing: the preconditions the resolution adds beyond this key
 * material -- a promoted account pointer, a configured storage server with a
 * remote store -- are exactly the states a login chain's identity repairs
 * converge, so a held set computed from the resolution alone would stand
 * those repairs down on the state they exist to fix.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {object | undefined}   `{ kind: 'enrolled' }` with the client's
 *   key material, `{ kind: 'ladder' }` with the credential's ladder seed and
 *   standing members, or `undefined` when the session holds neither
 */
export function sessionAuthorityKind({ session }: { session: Session }):
  | {
      kind: 'enrolled'
      clientWebvhKeys: ClientWebvhUpdateKeys
      clientKeyAgreementKey: IKeyAgreementKey
      keyAgent: ICapabilityAgent
    }
  | {
      kind: 'ladder'
      ladderSeed: Uint8Array
      standingUnlock: NonNullable<ControllerProfile['standingUnlock']>
    }
  | undefined {
  if (session.isGuest) {
    return undefined
  }
  const { profile } = session
  const material = enrolledKeyMaterial({ profile })
  if (!('missing' in material)) {
    return { kind: 'enrolled', ...material }
  }
  const { ladderSeed, standingUnlock } = profile
  if (ladderSeed && standingUnlock) {
    return { kind: 'ladder', ladderSeed, standingUnlock }
  }
  return undefined
}

/**
 * The account-ceremony context for this session, bound to whichever kind it
 * is, or `null` when neither kind's authorities exist.
 *
 * Which kind is {@link sessionAuthorityKind}'s decision alone: the branch
 * below adds the account preconditions a resolution needs, and tests no key
 * material of its own.
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
  const authority = sessionAuthorityKind({ session })
  if (authority?.kind === 'enrolled') {
    return enrolledCeremonyContext({ session })
  }
  if (authority?.kind !== 'ladder') {
    return null
  }
  const reach = resolveAccountReach({ session })
  if ('missing' in reach) {
    return null
  }
  const { profile } = session
  // The key material the kind above tested, handed back by it rather than
  // re-read here.
  const { ladderSeed, standingUnlock } = authority
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
        pinStore: session.persistence.logPins
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
          session,
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
        session,
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
        pinStore: session.persistence.logPins
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
