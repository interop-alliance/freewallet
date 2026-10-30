/**
 * The registration lists: the code half of the mender registry. A
 * registration names the invariants one place converges and returns one
 * report entry per invariant it names, in that order. Registration order
 * within a list is execution order; there is no dependency graph and no
 * priority.
 *
 * Two lists are run by the runner, one per chain trigger. Each is split at
 * the settle point: the registry-writing part settles
 * `session.registryReady`, and the tail settles only `session.mends`. The
 * remembered tail is the annex GC, then the keystore report last, so the
 * sweep does not queue behind its KMS round trip. The transient tail is the
 * keystore promotion alone. Beside them sit the sites that
 * report from their own call sites: the routing entries, whose control flow
 * decides whether a session is built at all, and the did:web projection
 * mend, which a transient visit fires before its chain and in the CHAPI
 * popup. Those are data (`RegistrationSite`) rather than registrations, so
 * nothing can run them out of their own order. The encounter sites that keep
 * their own call are data too.
 *
 * Behind each chain's block runs its inbox tail: the inbox pass (the drain,
 * then the agent grant renewal), which settles `session.inboxPass` alone. It
 * talks to other parties' servers, so neither `session.registryReady` nor
 * `session.mends` waits on it.
 *
 * Five encounter registrations run mid-visit, after the chain has settled,
 * through the encounter runner (`encounter.ts`): the stranded-collection
 * mend, the registry stale-seal mend, the `connections` writer sweep, and the
 * two uses of the inbox pass (the Notifications page open, and the Settings
 * site after a ceremony that replaces the generation delegation).
 */
import {
  errorNameOf,
  type InvariantId,
  type MendOutcome,
  type MendReport,
  type MendReportEntry,
  type Registration,
  type RegistrationSite
} from '@interop/wallet-core/menders'
import {
  readUserKeyRoster,
  type UserKey,
  type UserKeyCascadeResult,
  type UserKeyRosterReadResult
} from '@interop/wallet-core/keys'
import type { CollectionEncryption } from '@interop/was-client'
import type { SealableEncryptionDescriptorStore } from '@interop/wallet-core/keys'
import type { IZcap } from '@interop/data-integrity-core'
import {
  didKeyZcapClient,
  type PublishedKeyDocument
} from '@interop/wallet-core/webvh'
import { ladderVmAgent } from '@interop/wallet-core/clientAnnex'
import type { Session } from '@/types/auth'
import type { CeremonyId } from '@interop/wallet-core'
import type {
  KeyringFetchResult,
  TransientKeyringFetchResult,
  UnlockCredential
} from '@/session/keyring'
import {
  accountCeremonyContext,
  rosterUnwrapKey,
  type AccountCeremonyContext,
  type LadderCeremonyContext
} from '@/session/accountCeremonyContext'
import {
  backfillRegistryPass,
  barePasskeyPass,
  promotedAccountPointer,
  promotedAccountView,
  resealRegistryPass,
  tornRetirementPass,
  type BlockRegistryRead,
  type SharedRegistryPassOptions
} from '@/session/registryPasses'
import {
  refreshVerifiedAccountLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
import {
  adoptFollowerUserKey,
  ownUserKeyRotationInProgress,
  userKeyRosterPosition
} from '@/session/userKeyAdoption'
import { repairStaleUnlockRegistrySeal } from '@/session/registryReseal'
import { isSessionDisposed } from '@/session/sessionLifecycle'
import { sweepUserKeyToDocument } from '@/session/userKeySweep'
import { cascadeCollectionsToUserKey } from '@/session/userKeyCascade'
import {
  refreshCommittedLadderRung,
  refreshStandingDelegations
} from '@/session/standingDelegationRefresh'
import { healAccountPointer } from '@/session/pointerHeal'
import {
  clientAnnexReachFor,
  ensureGenerationDelegation,
  isClientAnnexRungUncommittedError
} from '@/session/annexReach'
import { sweepClientAnnexGenerations } from '@/session/clientAnnexGc'
import { refreshTransientManageCapability } from '@/session/unlockMethods'
import { sweepHeldConnectionWriters } from '@/session/connectionWriters'
import { INBOX_PASS_REPORTS, runInboxPass } from '@/session/inboxPass'
import { KMS_SERVER_URL } from '@/app.config'
import { findKeystoreAgent, promoteKeystoreController } from '@/lib/kms'
import { wasServiceDescription } from '@/lib/wasService'
import { CEREMONY_TAIL_SITES } from '@/session/menders/ceremonyTail'

/**
 * What the remembered login's registrations read. One object per block, its
 * members the locals the login already holds; the runner hands it to every
 * converger unread.
 */
export interface RememberedMenderDeps {
  chain: 'remembered'
  session: Session
  /**
   * The login credential's keyring hit.
   */
  found: KeyringFetchResult
  /**
   * The block's account-ceremony context, resolved once and re-resolved
   * after the pointer heal lands, so the registrations behind that heal see
   * the authority it made available.
   */
  context: () => Promise<AccountCeremonyContext | null>
  /**
   * Drops the resolved context, so the next `context()` resolves afresh.
   * The pointer heal calls it when it promoted the account: the state the
   * block's first resolution ran against is the state that heal fixes. No
   * registration behind the heal reads the context today, so the drop is
   * what keeps one added there correct rather than something the present
   * list depends on.
   */
  refreshContext: () => void
  /**
   * The block's one unlock-methods registry read, so every registration of
   * one login shares one fetch. A pass that wrote the registry drops the
   * memo, and the passes behind it read the record it left.
   */
  registry: BlockRegistryRead
  /**
   * The login's verified roster read, where one succeeded.
   */
  rosterRead?: UserKeyRosterReadResult
  /**
   * The store that read came through, which the sweep writes through.
   */
  rosterStore?: SealableEncryptionDescriptorStore
  /**
   * The typed login secret, for the torn-retirement repair's own arm.
   */
  loginCredential?: { secret?: string | Uint8Array; derived?: UnlockCredential }
  /**
   * Whether this login self-enrolled this browser (the ladder climbed).
   */
  selfEnrolled: boolean
}

/**
 * What the transient login's registrations read.
 */
export interface TransientMenderDeps {
  chain: 'transient'
  session: Session
  found: TransientKeyringFetchResult
  context: () => Promise<AccountCeremonyContext | null>
  /**
   * The block's one unlock-methods registry read, as on the remembered
   * chain.
   */
  registry: BlockRegistryRead
  /**
   * The visit's roster read, whose user key the registry writes seal to.
   */
  rosterRead: UserKeyRosterReadResult
  /**
   * The generation delegation the visit started on.
   */
  generationDelegation: IZcap
  /**
   * The login credential, where the visit holds one. The same member the
   * remembered chain carries, so the shared passes read it with no branch
   * on the chain.
   */
  loginCredential?: { secret?: string | Uint8Array; derived?: UnlockCredential }
}

/**
 * The dependency object either chain's registrations take. The discriminant
 * is what lets one registry serve both blocks.
 */
export type LoginMenderDeps = RememberedMenderDeps | TransientMenderDeps

/**
 * Narrows the block's deps to the remembered chain's. A registration listed
 * under one trigger is never run with the other chain's deps, so this throw
 * is a programming error rather than a state.
 *
 * @param deps {LoginMenderDeps}
 * @returns {RememberedMenderDeps}
 */
function remembered(deps: LoginMenderDeps): RememberedMenderDeps {
  if (deps.chain !== 'remembered') {
    throw new Error(
      'A remembered-chain registration was run with the transient chain deps.'
    )
  }
  return deps
}

/**
 * Narrows the block's deps to the transient chain's.
 *
 * @param deps {LoginMenderDeps}
 * @returns {TransientMenderDeps}
 */
function transient(deps: LoginMenderDeps): TransientMenderDeps {
  if (deps.chain !== 'transient') {
    throw new Error(
      'A transient-chain registration was run with the remembered chain deps.'
    )
  }
  return deps
}

/**
 * The block's seed: storage provisioning. Its failure aborts the block, so
 * none of the registry, bridge, or promotion writes below runs on a session
 * whose provisioning was refused -- which is what a rejected chain seed has
 * always done.
 *
 * The runner admits the seed like any registration, so that abort holds only
 * on a session holding its invariant's authority, `enrolled`: a remembered
 * profile carrying its update keys, key-agreement key, and key agent. A
 * remembered session missing any of them skips the seed and runs the block
 * without the guard. Every remembered path mints the update keys and a
 * pending record resumes enrollment first, so no login reaches here without
 * them today.
 */
export const REMEMBERED_SEED: Registration<LoginMenderDeps, CeremonyId> = {
  trigger: 'remembered-login-chain',
  reports: ['standard-collections-are-provisioned'],
  async converge(deps) {
    const { session } = remembered(deps)
    // The block starts behind the login's own provisioning guard, so a
    // session reaching here always carries `storageReady`.
    await session.storageReady
    return [
      { invariant: 'standard-collections-are-provisioned', outcome: 'clean' }
    ]
  }
}

/**
 * The cascade-completion sweep: the roster convergence and the collection
 * fan-out, one registration reporting three predicates: the roster's wraps,
 * the roster log's seal, and the collection epochs. It runs first because
 * its convergence may rotate the user key and re-seal the registry to the
 * fresh one, and a registry read-modify-write racing that re-seal would
 * rewrite the record under the pre-rotation keys and undo it within one
 * login.
 */
const USER_KEY_SWEEP: Registration<LoginMenderDeps, CeremonyId> = {
  trigger: 'remembered-login-chain',
  reports: [
    'roster-wraps-exactly-the-document-key-set',
    'roster-log-head-anchors-past-the-membership-change',
    'collection-epochs-name-the-current-user-key'
  ],
  async converge(deps) {
    const { session, rosterRead, rosterStore } = remembered(deps)
    const userKey = session.profile.userKey
    if (
      !rosterRead ||
      !rosterStore ||
      !userKey ||
      !session.storage.remoteStore
    ) {
      return uniformEntries({
        registration: USER_KEY_SWEEP,
        outcome: 'noop',
        reason: 'nothing-to-sweep-from'
      })
    }
    const { rotated, sealed, staleRecipients, escrowedRecipients, cascade } =
      await sweepUserKeyToDocument({
        session,
        store: rosterStore,
        userKey,
        read: rosterRead
      })
    // The convergence mends the wraps two ways, and only one of them
    // rotates: it can also escrow a torn enrollment's missing wraps. Either
    // is a login that repaired the roster. The roster log's own predicate is
    // mended by either append this login made to it: the seal backstop's,
    // or the rotation's own, which anchors the head past the membership
    // change just as well.
    const converged = rotated || escrowedRecipients > 0
    const anchored = rotated || sealed
    const rosterDetail = {
      ...(staleRecipients > 0 ? { staleRecipients } : {}),
      ...(escrowedRecipients > 0 ? { escrowedRecipients } : {})
    }
    return [
      {
        invariant: 'roster-wraps-exactly-the-document-key-set',
        outcome: converged ? 'clean' : 'noop',
        ...(Object.keys(rosterDetail).length > 0
          ? { detail: rosterDetail }
          : {})
      },
      {
        invariant: 'roster-log-head-anchors-past-the-membership-change',
        ...(anchored
          ? { outcome: 'clean' as const, detail: { rotated, sealed } }
          : { outcome: 'noop' as const })
      },
      collectionEpochsEntry({ cascade })
    ]
  }
}

/**
 * One entry per invariant a registration reports, all of one outcome: the
 * shape a registration returns when it did not reach its converger.
 *
 * @param options {object}
 * @param options.registration {object}   the registration whose `reports`
 *   list the entries' invariants
 * @param options.outcome {'refused' | 'noop'}
 * @param options.reason {string}
 * @returns {MendReport}
 */
export function uniformEntries({
  registration,
  outcome,
  reason
}: {
  registration: { reports: ReadonlyArray<InvariantId> }
  outcome: 'refused' | 'noop'
  reason: string
}): MendReport<CeremonyId> {
  return registration.reports.map(invariant => ({
    invariant,
    outcome,
    detail: { reason }
  }))
}

/**
 * The report entry a collection fan-out grades to, on either chain: `partial`
 * when a collection failed, `clean` when one rotated, `noop` otherwise.
 *
 * @param options {object}
 * @param options.cascade {UserKeyCascadeResult}
 * @returns {object}   the `collection-epochs-name-the-current-user-key` entry
 */
function collectionEpochsEntry({ cascade }: { cascade: UserKeyCascadeResult }) {
  return {
    invariant: 'collection-epochs-name-the-current-user-key' as const,
    ...(cascade.failed.length > 0
      ? {
          outcome: 'partial' as const,
          // The ids and their errors ride the fan-out's own logger; a
          // report carries the count alone.
          detail: { failedCollections: cascade.failed.length }
        }
      : anyCollectionRotated({ cascade })
        ? { outcome: 'clean' as const }
        : { outcome: 'noop' as const })
  }
}

/**
 * Whether the fan-out moved any collection onto a fresh epoch.
 *
 * @param options {object}
 * @param options.cascade {UserKeyCascadeResult}
 * @returns {boolean}
 */
function anyCollectionRotated({
  cascade
}: {
  cascade: UserKeyCascadeResult
}): boolean {
  return Object.values(cascade.outcomes).some(outcome => outcome === 'rotated')
}

/**
 * What the shared passes read, assembled from either chain's deps.
 *
 * @param deps {LoginMenderDeps}
 * @returns {Promise<SharedRegistryPassOptions>}
 */
async function sharedPassOptions(
  deps: LoginMenderDeps
): Promise<SharedRegistryPassOptions> {
  const { session, found, context, registry, rosterRead, loginCredential } =
    deps
  return {
    session,
    found,
    context: await context(),
    registry,
    ...(rosterRead ? { rosterRead } : {}),
    ...(loginCredential ? { credential: loginCredential } : {})
  }
}

/**
 * The four passes both compositions share, in the order every caller depends
 * on: the stale-seal repair, the torn-retirement repair, the bare-passkey
 * rebuild, then the backfill. Each is its own registration, so the runner's
 * try, warn, and skip discipline covers it and a throwing re-seal does not
 * skip the backfill.
 */
const SHARED_PASSES: ReadonlyArray<{
  invariant: InvariantId
  run: (options: SharedRegistryPassOptions) => Promise<MendOutcome>
}> = [
  {
    invariant: 'unlock-registry-opens-under-the-current-user-key',
    run: resealRegistryPass
  },
  {
    invariant: 'registry-passphrase-entry-names-the-standing-credential',
    run: tornRetirementPass
  },
  {
    invariant: 'passkey-entry-carries-its-standing-configuration',
    run: barePasskeyPass
  },
  {
    invariant: 'registry-lists-the-passphrase-method',
    run: backfillRegistryPass
  }
]

/**
 * The shared passes as one chain's registrations, in pass order.
 *
 * @param trigger {'remembered-login-chain' | 'transient-login-chain'}
 * @returns {ReadonlyArray<Registration>}
 */
function sharedRegistryPasses(
  trigger: 'remembered-login-chain' | 'transient-login-chain'
): ReadonlyArray<Registration<LoginMenderDeps, CeremonyId>> {
  return SHARED_PASSES.map(pass => ({
    trigger,
    reports: [pass.invariant],
    async converge(deps: LoginMenderDeps) {
      const outcome = await pass.run(await sharedPassOptions(deps))
      return [{ invariant: pass.invariant, ...outcome }]
    }
  }))
}

/**
 * The standing-delegation self-refresh, on a promoted account. The account
 * log is handed over as a thunk rather than read here: an expiring bridge or
 * sibling delegation is re-minted from the zcaps in hand, so a did.jsonl the
 * host cannot serve (or a chain-head pin that refuses what it serves) must
 * not stand the re-mint down.
 */
const STANDING_DELEGATION_REFRESH: Registration<LoginMenderDeps, CeremonyId> = {
  trigger: 'remembered-login-chain',
  reports: ['standing-delegations-verify-under-the-current-document'],
  async converge(deps) {
    const { session } = remembered(deps)
    const invariant = 'standing-delegations-verify-under-the-current-document'
    const standing = session.profile.standingUnlock
    if (!standing?.rebindRecord) {
      return [
        {
          invariant,
          outcome: 'noop',
          detail: { reason: 'no-standing-members' }
        }
      ]
    }
    const pointer = promotedAccountPointer({ session })
    if (!pointer) {
      return [
        { invariant, outcome: 'noop', detail: { reason: 'unpromoted-account' } }
      ]
    }
    const refreshed = await refreshStandingDelegations({
      session,
      pointer,
      verifiedLog: async () => verifiedAccountLog({ session }),
      standing: { ...standing, rebindRecord: standing.rebindRecord }
    })
    return [
      { invariant, outcome: refreshed === 'refreshed' ? 'clean' : 'noop' }
    ]
  }
}

/**
 * The recorded ladder rung, after a self-enrollment climbed the ladder.
 */
const LADDER_RUNG_REFRESH: Registration<LoginMenderDeps, CeremonyId> = {
  trigger: 'remembered-login-chain',
  reports: ['registry-records-the-committed-ladder-rung'],
  async converge(deps) {
    const { session, found, selfEnrolled } = remembered(deps)
    const invariant = 'registry-records-the-committed-ladder-rung'
    const ladderSeed = selfEnrolled ? found.standing?.ladderSeed : undefined
    if (!ladderSeed) {
      return [
        {
          invariant,
          outcome: 'noop',
          detail: { reason: 'no-self-enrollment' }
        }
      ]
    }
    const promoted = await promotedAccountView({ session })
    if (!promoted) {
      return [
        {
          invariant,
          outcome: 'noop',
          detail: { reason: 'unpromoted-account' }
        }
      ]
    }
    const recorded = await refreshCommittedLadderRung({
      session,
      verified: promoted.verified,
      ladderSeed,
      unlockSpaceId: found.unlockSpaceId,
      ...(found.standingClient?.keyAgreementKeyMultibase
        ? {
            keyAgreementKeyMultibase:
              found.standingClient.keyAgreementKeyMultibase
          }
        : {})
    })
    return [{ invariant, outcome: recorded === 'recorded' ? 'clean' : 'noop' }]
  }
}

/**
 * The did:webvh pointer heal and the Space-controller promotion behind it.
 * The keystore promotion that promotion fires is left on the storage manager
 * for the tail registration below to read, so `session.registryReady` does
 * not wait on a KMS round trip.
 */
const POINTER_HEAL: Registration<LoginMenderDeps, CeremonyId> = {
  trigger: 'remembered-login-chain',
  reports: [
    'account-pointer-names-the-account-did',
    'space-controller-is-the-account-did'
  ],
  async converge(deps) {
    const { session, found } = remembered(deps)
    const healed = await healAccountPointer({
      session,
      ...(found.persistAccountPointer
        ? { persistAccountPointer: found.persistAccountPointer }
        : {}),
      ...(found.pointer ? { pointer: found.pointer } : {})
    })
    // The heal may have promoted the account, which is the state the
    // block's context was resolved against.
    if (healed.pointer.outcome === 'clean') {
      remembered(deps).refreshContext()
    }
    return [
      { invariant: 'account-pointer-names-the-account-did', ...healed.pointer },
      {
        invariant: 'space-controller-is-the-account-did',
        ...healed.controller
      }
    ]
  }
}

/**
 * The keystore controller, reported from the promotion this login fired: the
 * pointer heal's where the heal ran one, and otherwise storage
 * provisioning's, which fires it on every login of an account whose pointer
 * already names the did:webvh. Either way the promotion is the one the
 * storage manager kept, and the pointer heal runs earlier in the list, so
 * whatever it fired stands here. It sits in the tail rather than beside the
 * heal because awaiting a KMS round trip inside the registry-writing prefix
 * would put every Settings ceremony's `registryReady` wait behind that trip.
 * It reports `noop` only when no promotion ran at all (a session with no
 * remote store or no account DID).
 */
const KEYSTORE_PROMOTION: Registration<LoginMenderDeps, CeremonyId> = {
  trigger: 'remembered-login-chain',
  reports: ['keystore-controller-is-the-account-did'],
  async converge(deps) {
    const { session } = remembered(deps)
    const invariant = 'keystore-controller-is-the-account-did'
    const pending = session.storage.keystorePromotion
    if (!pending) {
      return [
        { invariant, outcome: 'noop', detail: { reason: 'no-promotion' } }
      ]
    }
    return [{ invariant, ...(await pending) }]
  }
}

/**
 * The generation-delegation self-heal: the pointed generation's embedded
 * delegation is renewed when it is expiring OR its signer has left the
 * verified account document.
 */
const GENERATION_DELEGATION_HEAL: Registration<LoginMenderDeps, CeremonyId> = {
  trigger: 'remembered-login-chain',
  reports: ['generation-delegation-is-current'],
  async converge(deps) {
    const { session, found } = remembered(deps)
    const invariant = 'generation-delegation-is-current'
    const ladderSeed = found.standing?.ladderSeed
    if (!ladderSeed) {
      return [
        { invariant, outcome: 'noop', detail: { reason: 'no-ladder-seed' } }
      ]
    }
    const promoted = await promotedAccountView({ session })
    if (!promoted) {
      return [
        { invariant, outcome: 'noop', detail: { reason: 'unpromoted-account' } }
      ]
    }
    const reach = clientAnnexReachFor({
      session,
      pointer: promoted.pointer,
      doc: promoted.verified.doc,
      serviceDescription: await wasServiceDescription()
    })
    if (reach === null) {
      return [
        { invariant, outcome: 'noop', detail: { reason: 'no-annex-reach' } }
      ]
    }
    try {
      const { renewed } = await ensureGenerationDelegation({
        session,
        pointer: promoted.pointer,
        reach,
        ladderSeed,
        accountDoc: promoted.verified.doc as PublishedKeyDocument
      })
      return [{ invariant, outcome: renewed ? 'clean' : 'noop' }]
    } catch (err) {
      // A rung the generation does not commit (a credential bound
      // mid-generation) skips quietly; everything else rides the runner's
      // warn.
      if (!isClientAnnexRungUncommittedError(err)) {
        throw err
      }
      return [
        {
          invariant,
          outcome: 'refused',
          detail: { reason: 'rung-uncommitted' }
        }
      ]
    }
  }
}

/**
 * The annex GC sweep, after the registry-writing entries: a sibling re-mint
 * above lands first. A swap, its off-cadence repair, or a collected
 * generation reads as a mend. A generation the pass deferred (unpointed, and
 * not GC-quiet yet) is a healthy keep, so a pass that only deferred is a
 * `noop`.
 */
const ANNEX_GC: Registration<LoginMenderDeps, CeremonyId> = {
  trigger: 'remembered-login-chain',
  reports: ['no-annex-generation-outlives-its-pointer'],
  async converge(deps) {
    const { session, found } = remembered(deps)
    const ladderSeed = found.standing?.ladderSeed
    const swept = await sweepClientAnnexGenerations({
      session,
      ...(ladderSeed !== undefined ? { ladderSeed } : {})
    })
    if ('skipped' in swept) {
      return [
        {
          invariant: 'no-annex-generation-outlives-its-pointer',
          outcome: 'refused',
          detail: { reason: swept.skipped }
        }
      ]
    }
    const { swap, collected, deferred, failed } = swept.report
    const mended =
      swap === 'replaced' || swap === 'repaired' || collected.length > 0
    let outcome: MendOutcome['outcome'] = mended ? 'clean' : 'noop'
    if (failed.length > 0) {
      outcome = 'partial'
    }
    return [
      {
        invariant: 'no-annex-generation-outlives-its-pointer',
        outcome,
        detail: {
          swap,
          collected: collected.length,
          deferred: deferred.length,
          failed: failed.length
        }
      }
    ]
  }
}

/**
 * The acting credential's management-zcap refresh, last among the transient
 * chain's registry writers: it compare-and-swaps the same registry entry the
 * passes above rewrite, and two writers racing one entry would spend the
 * retry budget undoing each other.
 */
const TRANSIENT_MANAGE_ZCAP_REFRESH: Registration<LoginMenderDeps, CeremonyId> =
  {
    trigger: 'transient-login-chain',
    reports: ['acting-credential-manage-zcap-is-current'],
    async converge(deps) {
      const { session, found, rosterRead, generationDelegation } =
        transient(deps)
      const invariant = 'acting-credential-manage-zcap-is-current'
      // The capability the visit rides now, not the one it started on: a
      // registration above may have renewed the generation delegation.
      const capability =
        session.profile.invocationCapability ?? generationDelegation
      const accountPointer = session.profile.accountPointer
      if (!found.manageCapability || !capability || !accountPointer) {
        return [
          {
            invariant,
            outcome: 'noop',
            detail: { reason: 'no-management-zcap' }
          }
        ]
      }
      const refreshed = await refreshTransientManageCapability({
        zcapClient: session.profile.zcapClient,
        spaceUrl: accountPointer.spaceUrl,
        userKey: rosterRead.userKey,
        capability,
        unlockSpaceId: found.unlockSpaceId,
        manageCapability: found.manageCapability,
        ...(found.standingClient?.keyAgreementKeyMultibase
          ? {
              keyAgreementKeyMultibase:
                found.standingClient.keyAgreementKeyMultibase
            }
          : {})
      })
      if (refreshed === 'failed') {
        return [{ invariant, outcome: 'failed' }]
      }
      return [
        { invariant, outcome: refreshed === 'refreshed' ? 'clean' : 'noop' }
      ]
    }
  }

/**
 * The keystore promotion on the transient chain, in the block's tail. A
 * credential-anchored establishment creates the WebKMS keystore under the
 * ladder VM's bare did:key and promotes its controller to the account
 * did:webvh only in its own tail, so a tear between the unlock-record re-bind
 * and that tail leaves the keystore on the did:key. This registration
 * re-derives that did:key from the login credential's ladder seed, lists
 * keystores under it, and promotes the one it finds. The KMS verifies a
 * keystore configuration update as a root invocation by the stored
 * controller, so the ladder VM's key is the signer that update needs.
 *
 * A miss is a `noop`, and creates nothing. Either the keystore is promoted
 * already, or this credential's ladder never created one. A transient visit
 * cannot list under the account DID to tell the two apart: the ladder VM has
 * no invocation relation, and the KMS answers a failed verification with a
 * 404, as it answers an absence. A keystore created by another credential's
 * ladder lists under that ladder's did:key, so only a login on that
 * credential reaches it.
 */
export const TRANSIENT_KEYSTORE_PROMOTION: Registration<
  LoginMenderDeps,
  CeremonyId
> = {
  trigger: 'transient-login-chain',
  reports: ['keystore-controller-is-the-account-did'],
  async converge(deps) {
    const { session, found } = transient(deps)
    const invariant = 'keystore-controller-is-the-account-did' as const
    const noop = (reason: string) => [
      { invariant, outcome: 'noop' as const, detail: { reason } }
    ]
    if (KMS_SERVER_URL === undefined) {
      return noop('no-kms')
    }
    // Narrows the type: the transient login refuses a record with no seed.
    const ladderSeed = found.standing?.ladderSeed
    if (!ladderSeed) {
      return noop('no-ladder-seed')
    }
    const pointer = promotedAccountPointer({ session })
    if (!pointer) {
      return noop('unpromoted-account')
    }
    const keyAgent = await ladderVmAgent({ ladderSeed })
    const keystoreAgent = await findKeystoreAgent({
      kmsServerUrl: KMS_SERVER_URL,
      keyAgent,
      zcapClient: didKeyZcapClient({ keyAgent })
    })
    if (!keystoreAgent) {
      return noop('no-keystore-under-ladder-did-key')
    }
    const didPromote = await promoteKeystoreController({
      keystoreAgent,
      controller: pointer.did
    })
    return didPromote
      ? [{ invariant, outcome: 'clean' as const, detail: { promoted: true } }]
      : noop('already-promoted')
  }
}

/**
 * The collection half of a ladder-kind session's fan-out: every candidate
 * collection whose current epoch still names a retired user key generation
 * is re-epoch'd onto the roster's current key, each append signed by the
 * credential's ladder VM, and the session's ciphers are rebuilt when that
 * moved anything or a collection is recorded as stranded. The body of the
 * transient chain's collection fan-out, and of any site that re-epochs a
 * known candidate set mid-visit.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {LadderCeremonyContext}   the session's resolved
 *   ladder-kind context
 * @param options.rosterRead {object}   the roster read the fan-out rotates
 *   onto
 * @param options.rosterRead.descriptor {CollectionEncryption}
 * @param options.rosterRead.userKey {UserKey}   the roster's current key
 * @param [options.collectionIds] {string[]}   the candidates; every encrypted
 *   standard collection plus every listed one when omitted
 * @returns {Promise<UserKeyCascadeResult>}
 */
export async function cascadeLadderCollections({
  session,
  context,
  rosterRead,
  collectionIds
}: {
  session: Session
  context: LadderCeremonyContext
  rosterRead: { descriptor: CollectionEncryption; userKey: UserKey }
  collectionIds?: string[]
}): Promise<UserKeyCascadeResult> {
  const cascade = await cascadeCollectionsToUserKey({
    remoteStore: context.remoteStore,
    storeFor: context.collectionStore,
    rosterDescriptor: rosterRead.descriptor,
    clientKeyAgreementKey: context.standingKeyAgreementKey,
    userKey: rosterRead.userKey,
    ...(collectionIds ? { collectionIds } : {})
  })
  if (
    anyCollectionRotated({ cascade }) ||
    session.storage.strandedCollectionIds.length > 0
  ) {
    // The rotated descriptors are refetched and the ciphers rebuilt on
    // them, so this visit's next writes seal under the fresh epochs. A
    // collection built stranded is rebuilt even when this run rotated
    // nothing: another client may have re-epoched it since.
    await session.storage.refreshEncryptedDescriptors()
  }
  return cascade
}

/**
 * The transient chain's collection fan-out: every encrypted collection whose
 * current epoch still names a retired user key generation is re-epoch'd onto
 * the roster's current one. It completes a rotation torn mid-fan-out on a
 * credential-anchored account, which runs no remembered login and so no
 * cascade-completion sweep. Staleness is read from server-held state alone,
 * so a healthy account reads every collection's log and writes nothing.
 *
 * The same fan-out seals each collection's descriptor log: a collection
 * already on the current key whose log head is anchored before the account
 * document's latest `assertionMethod` removal takes a verbatim re-append
 * anchored past it. That is the governed-log invariant, which a forget
 * ceremony leaves open since its fan-out runs before its removal entry. The
 * roster log's own invariant stays with the remembered sweep.
 *
 * It starts from the roster this visit read and converges no roster itself,
 * so a rotation torn before its roster append is not this registration's.
 * Each append is signed by the credential's ladder VM, which a collection
 * descriptor log admits on `assertionMethod` membership alone, and invoked
 * under the generation delegation the visit holds at call time. Also runs in
 * the remote-direct CHAPI popup, as the remembered sweep does.
 *
 * It runs first, as the remembered sweep does, for two reasons. The roster
 * read it rotates onto is current only until a registration behind it
 * rotates the key (the torn-retirement repair can), and a Settings ceremony
 * that rotates the key awaits `session.registryReady`, which this
 * registration therefore settles before, so the two never race one
 * collection's epochs.
 */
const TRANSIENT_COLLECTION_CASCADE: Registration<LoginMenderDeps, CeremonyId> =
  {
    trigger: 'transient-login-chain',
    reports: [
      'collection-epochs-name-the-current-user-key',
      'governed-log-heads-anchor-past-the-membership-change'
    ],
    async converge(deps) {
      const { session, context, rosterRead } = transient(deps)
      const resolved = await context()
      if (resolved?.kind !== 'ladder') {
        return uniformEntries({
          registration: TRANSIENT_COLLECTION_CASCADE,
          outcome: 'noop',
          reason: 'no-ladder-context'
        })
      }
      const cascade = await cascadeLadderCollections({
        session,
        context: resolved,
        rosterRead
      })
      return [
        collectionEpochsEntry({ cascade }),
        {
          invariant: 'governed-log-heads-anchor-past-the-membership-change',
          // The collection logs alone: this registration seals no roster
          // log. A collection that failed may be the one left unsealed.
          ...(cascade.failed.length > 0
            ? {
                outcome: 'partial' as const,
                detail: { failedCollections: cascade.failed.length }
              }
            : Object.values(cascade.outcomes).some(
                  outcome => outcome === 'sealed'
                )
              ? { outcome: 'clean' as const }
              : { outcome: 'noop' as const })
        }
      ]
    }
  }

/**
 * The fresh roster read an encounter decides on. On the ladder kind the
 * generation delegation is renewed first, since every request of a
 * transient session rides it and a delegation the rotation struck comes back
 * as the server's masked 404. The account log is then re-verified through
 * the memo, so a roster entry another client anchored past the login's view
 * is read rather than refused. The read unwraps with the key this session
 * holds a roster wrap for and checks the visit's epoch pin.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext}
 * @returns {Promise<UserKeyRosterReadResult | null | 'revoked'>}   the read,
 *   `null` when no roster head answered, or `revoked` when the current epoch
 *   carries no wrap this session can open
 */
async function encounterRosterRead({
  session,
  context
}: {
  session: Session
  context: AccountCeremonyContext
}): Promise<UserKeyRosterReadResult | null | 'revoked'> {
  if (context.kind === 'ladder') {
    await context.renew()
  }
  await refreshVerifiedAccountLog({ session })
  const unwrapKey = rosterUnwrapKey({ session })
  if (!unwrapKey) {
    return null
  }
  const accountDid = context.pointer.did
  try {
    return await readUserKeyRoster({
      store: context.rosterStore,
      clientKeyAgreementKey: unwrapKey,
      ...(session.profile.userKey ? { userKey: session.profile.userKey } : {}),
      pinnedEpochId: await session.persistence.epochPins.load({ accountDid })
    })
  } catch (err) {
    // Both "no wrap for this session" and "a wrap that would not open":
    // either way this session cannot follow the roster, and standing down
    // writes nothing. Matched by name, since the raising copy of the package
    // can differ from this one's.
    if (errorNameOf(err) === 'UserKeyRosterUnwrapError') {
      return 'revoked'
    }
    throw err
  }
}

/**
 * The roster-following preamble both encounter registrations share. It reads
 * the roster behind a log refresh and grades the reads a converger cannot go
 * on from: no roster head (`failed`), no wrap this session can open
 * (`refused`), an adoption that did not land (`failed`, or `noop` when a
 * rotating ceremony of this session's own owns the key), and a position
 * other than behind or current (`failed`). Behind the roster, it follows the
 * rotation first.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext}
 * @returns {Promise<{ stop: MendOutcome } | { read: UserKeyRosterReadResult,
 *   adopted: boolean, wasBehind: boolean }>}   the outcome to stop on, or the
 *   roster read the session is now current against, whether this call
 *   adopted a newer key, and whether the session was behind before it
 */
async function followRosterForEncounter({
  session,
  context
}: {
  session: Session
  context: AccountCeremonyContext
}): Promise<
  | { stop: MendOutcome }
  | { read: UserKeyRosterReadResult; adopted: boolean; wasBehind: boolean }
> {
  const read = await encounterRosterRead({ session, context })
  if (read === null) {
    return { stop: { outcome: 'failed', detail: { reason: 'no-roster' } } }
  }
  if (read === 'revoked') {
    return {
      stop: { outcome: 'refused', detail: { reason: 'no-roster-wrap' } }
    }
  }
  const position = userKeyRosterPosition({
    session,
    descriptor: read.descriptor
  })
  if (position === 'behind') {
    const adoption = await adoptFollowerUserKey({ session, read })
    if (!adoption.adopted && adoption.position !== 'current') {
      // A rotating ceremony of this session's own owns the key while it
      // runs, and finishes what the converger would (rebuilding the ciphers,
      // re-sealing the registry) itself when it lands. Nothing was written.
      if (ownUserKeyRotationInProgress({ session })) {
        return {
          stop: {
            outcome: 'noop',
            detail: { reason: 'own-rotation-in-progress' }
          }
        }
      }
      return { stop: { outcome: 'failed', detail: { reason: 'not-adopted' } } }
    }
    return { read, adopted: adoption.adopted, wasBehind: true }
  }
  if (position !== 'current') {
    return { stop: { outcome: 'failed', detail: { reason: position } } }
  }
  return { read, adopted: false, wasBehind: false }
}

/**
 * The stranded-collection encounter: a collection whose key epochs name no
 * recipient of the session's user key reads empty and refuses writes. The
 * storage manager reports each such collection as its ciphers are rebuilt,
 * and the session binding (`encounterSites.ts`) runs this. It reports
 * invariant 3 alone; sealing the descriptor logs behind a membership change
 * stays on the login chains.
 *
 * The candidates are read at run time, so a collection recorded after the
 * run began is the next run's. A transient session renews its delegation,
 * refreshes the account log, and re-reads the roster. Behind the roster, it
 * follows the rotation (no registry re-seal) and cascades only what is still
 * stranded after that. Current, it cascades the candidates onto its key.
 * A candidate still stranded after the cascade is graded `failed`, so the
 * session's budget stops the next strand report of it from re-running this.
 * Any other session kind returns `noop`: a remembered session is mended by
 * its login's roster sweep.
 */
export const STRANDED_COLLECTION_ENCOUNTER: Registration<
  { session: Session },
  CeremonyId
> = {
  trigger: 'encounter',
  reports: ['collection-epochs-name-the-current-user-key'],
  reachedBy: ['transient'],
  async converge({ session }) {
    const invariant = 'collection-epochs-name-the-current-user-key' as const
    const graded = (outcome: MendOutcome) => [{ invariant, ...outcome }]
    const stranded = (): string[] => session.storage.strandedCollectionIds
    if (stranded().length === 0) {
      return graded({ outcome: 'noop', detail: { reason: 'nothing-stranded' } })
    }
    const context = await accountCeremonyContext({ session })
    if (context?.kind !== 'ladder') {
      return graded({
        outcome: 'noop',
        detail: { reason: 'no-ladder-context' }
      })
    }
    const followed = await followRosterForEncounter({ session, context })
    if ('stop' in followed) {
      return graded(followed.stop)
    }
    const { read, adopted } = followed
    if (followed.wasBehind && stranded().length === 0) {
      return graded({ outcome: 'clean', detail: { adopted } })
    }
    if (isSessionDisposed({ session })) {
      return graded({ outcome: 'noop', detail: { reason: 'session-disposed' } })
    }
    // A rotating ceremony of this session's own (or an account deletion)
    // began after the read above: the key it names is about to be retired,
    // and the ceremony moves the collections itself.
    if (ownUserKeyRotationInProgress({ session })) {
      return graded({
        outcome: 'noop',
        detail: { reason: 'own-rotation-in-progress' }
      })
    }
    const candidates = stranded()
    const cascade = await cascadeLadderCollections({
      session,
      context,
      rosterRead: read,
      collectionIds: candidates
    })
    const entry: MendReportEntry<CeremonyId> = collectionEpochsEntry({
      cascade
    })
    const left = candidates.filter(id => stranded().includes(id))
    if (left.length > 0) {
      // The evidence still stands: grade it so the budget holds. This run's
      // own rebuild re-reported the collection, and a `partial` would let
      // that report start the same run again.
      return graded({
        outcome: 'failed',
        detail: {
          reason: 'still-stranded',
          strandedCollections: left.length,
          ...entry.detail
        }
      })
    }
    return graded({
      outcome: entry.outcome,
      ...(entry.detail || adopted
        ? { detail: { ...entry.detail, ...(adopted ? { adopted } : {}) } }
        : {})
    })
  }
}

/**
 * The stale-seal encounter: the unlock-methods registry does not open under
 * the session's user key. Settings runs this at mount when its read throws
 * `UnlockRegistryStaleSealError`, then reloads the registry.
 *
 * A stale seal has two causes, and the direction of the fix differs. When
 * another client rotated the user key, this session is behind: it follows
 * the rotation first, since re-sealing from its older key would seal the
 * registry backward and could let a revoked party read it again. Once the
 * session is current, or when it already was, the login pass's repair reads
 * the registry and, when it still does not open, re-seals it forward from
 * the roster's escrow, on a roster read taken fresh behind a log refresh.
 * That covers a rotator whose own re-seal tore.
 */
export const REGISTRY_SEAL_ENCOUNTER: Registration<
  { session: Session },
  CeremonyId
> = {
  trigger: 'encounter',
  reports: ['unlock-registry-opens-under-the-current-user-key'],
  reachedBy: ['remembered', 'transient'],
  async converge({ session }) {
    const invariant =
      'unlock-registry-opens-under-the-current-user-key' as const
    const graded = (outcome: MendOutcome) => [{ invariant, ...outcome }]
    const context = await accountCeremonyContext({ session })
    if (!context) {
      return graded({ outcome: 'noop', detail: { reason: 'no-context' } })
    }
    // Once current after following a rotation, the rotator's own re-seal may
    // have torn, leaving the registry on a generation older still, so it is
    // read again below and re-sealed forward when it still does not open.
    const followed = await followRosterForEncounter({ session, context })
    if ('stop' in followed) {
      return graded(followed.stop)
    }
    const { read, adopted } = followed
    if (isSessionDisposed({ session })) {
      return graded({
        outcome: 'noop',
        detail: { reason: 'session-disposed' }
      })
    }
    const repaired = await repairStaleUnlockRegistrySeal({
      session,
      rosterRead: read,
      context
    })
    if (repaired === 'ok') {
      return adopted
        ? graded({ outcome: 'clean', detail: { adopted } })
        : graded({ outcome: 'noop' })
    }
    if (repaired === 'repaired') {
      return graded({
        outcome: 'clean',
        ...(adopted ? { detail: { adopted } } : {})
      })
    }
    return graded({
      outcome: 'failed',
      detail: { reason: repaired, ...(adopted ? { adopted } : {}) }
    })
  }
}

/**
 * The `connections` writer sweep: the two-phase expiry of every directory
 * entry's `writers`, run over the listing a page just read, so it costs no
 * second read. The listing read's binding (`encounterSites.ts`) holds the
 * listing and runs this; a run with no listing held is a `noop`. Both
 * session kinds read the directory, so both reach it, and a transient
 * listing may write. Every write is conditional on the ETag the listing
 * carries. A lost race is skipped, and any other failed write grades the
 * run `partial`, or `failed` when nothing landed, which spends the session's
 * budget.
 */
export const CONNECTION_WRITERS_SWEEP_ENCOUNTER: Registration<
  { session: Session },
  CeremonyId
> = {
  trigger: 'encounter',
  reports: ['no-registered-writer-outlives-its-expiry'],
  reachedBy: ['remembered', 'transient'],
  async converge({ session }) {
    const invariant = 'no-registered-writer-outlives-its-expiry' as const
    const graded = (outcome: MendOutcome) => [{ invariant, ...outcome }]
    if (isSessionDisposed({ session })) {
      return graded({ outcome: 'noop', detail: { reason: 'session-disposed' } })
    }
    const swept = await sweepHeldConnectionWriters({ session })
    if (swept === undefined) {
      return graded({ outcome: 'noop', detail: { reason: 'no-listing' } })
    }
    const detail = {
      markedInactive: swept.markedInactive.length,
      dropped: swept.dropped.length,
      failed: swept.failed.length
    }
    const landed = detail.markedInactive + detail.dropped
    if (detail.failed > 0) {
      return graded({
        outcome: landed > 0 ? 'partial' : 'failed',
        detail,
        errorName: errorNameOf(swept.failed[0]?.err)
      })
    }
    return graded({ outcome: landed > 0 ? 'clean' : 'noop', detail })
  }
}

/**
 * The inbox pass as one chain's tail registration: the drain, then the
 * agent grant renewal and the outbox push (`src/session/inboxPass.ts`). It
 * reports both invariants, the drain's first. The runner admits it off the
 * CHAPI popup only (both declarations' `when`), and the block's runner
 * starts it only on a session with a Space.
 *
 * @param trigger {'remembered-login-chain' | 'transient-login-chain'}
 * @returns {Registration}
 */
function inboxAndRenewal(
  trigger: 'remembered-login-chain' | 'transient-login-chain'
): Registration<LoginMenderDeps, CeremonyId> {
  return {
    trigger,
    reports: [...INBOX_PASS_REPORTS],
    async converge(deps) {
      const { entries } = await runInboxPass({ session: deps.session })
      return entries
    }
  }
}

/**
 * The remembered chain's inbox tail, run after the whole block (the annex GC
 * and the keystore report included), so a generation the GC swapped is
 * renewed under in the same login.
 */
export const REMEMBERED_INBOX_TAIL: ReadonlyArray<
  Registration<LoginMenderDeps, CeremonyId>
> = [inboxAndRenewal('remembered-login-chain')]

/**
 * The transient chain's inbox tail, run after the whole block.
 */
export const TRANSIENT_INBOX_TAIL: ReadonlyArray<
  Registration<LoginMenderDeps, CeremonyId>
> = [inboxAndRenewal('transient-login-chain')]

/**
 * The inbox pass as an encounter registration. It awaits the session's own
 * login-time pass first, so it never runs beside it and renews nothing
 * twice; passes on one session are serialized beside that as well.
 *
 * @returns {Registration}
 */
function inboxAndRenewalEncounter(): Registration<
  { session: Session },
  CeremonyId
> {
  return {
    trigger: 'encounter',
    reports: [...INBOX_PASS_REPORTS],
    reachedBy: ['remembered', 'transient'],
    async converge({ session }) {
      await session.inboxPass
      if (isSessionDisposed({ session })) {
        return INBOX_PASS_REPORTS.map(invariant => ({
          invariant,
          outcome: 'noop' as const,
          detail: { reason: 'session-disposed' }
        }))
      }
      const { entries } = await runInboxPass({ session })
      return entries
    }
  }
}

/**
 * The Notifications page's encounter: opening the page drains the inbox and
 * renews, so an invitation an agent posted after this visit's consent is
 * read in the same visit.
 */
export const INBOX_NOTIFICATIONS_ENCOUNTER = inboxAndRenewalEncounter()

/**
 * The Settings site's encounter, raised once a ceremony that replaces the
 * generation delegation resolves (a ladder-kind passphrase change or
 * credential removal, a client revocation, the last-client transition). The
 * drain runs first, so a channel stored in the same visit is pushed through.
 */
export const INBOX_CEREMONY_ENCOUNTER = inboxAndRenewalEncounter()

/**
 * The remembered block's registry-writing registrations, in execution order.
 * `session.registryReady` settles when the last of these has reported, which
 * is the meaning its awaiters have always had.
 */
export const REMEMBERED_REGISTRY_REGISTRATIONS: ReadonlyArray<
  Registration<LoginMenderDeps, CeremonyId>
> = [
  USER_KEY_SWEEP,
  ...sharedRegistryPasses('remembered-login-chain'),
  STANDING_DELEGATION_REFRESH,
  LADDER_RUNG_REFRESH,
  POINTER_HEAL,
  GENERATION_DELEGATION_HEAL
]

/**
 * The remembered block's tail: the annex GC and the keystore report, which
 * nothing waits on but `session.mends`. The keystore report is last, so the
 * sweep does not queue behind its KMS round trip.
 */
const REMEMBERED_TAIL_REGISTRATIONS: ReadonlyArray<
  Registration<LoginMenderDeps, CeremonyId>
> = [ANNEX_GC, KEYSTORE_PROMOTION]

/**
 * The remembered block, seed excluded (the runner takes that separately).
 */
export const REMEMBERED_REGISTRATIONS: ReadonlyArray<
  Registration<LoginMenderDeps, CeremonyId>
> = [...REMEMBERED_REGISTRY_REGISTRATIONS, ...REMEMBERED_TAIL_REGISTRATIONS]

/**
 * The transient block's registry-writing registrations, in execution order:
 * the collection fan-out first, then the registry-writing passes, the
 * management-zcap refresh last among them. `session.registryReady` settles
 * when the last of these has reported.
 */
export const TRANSIENT_REGISTRY_REGISTRATIONS: ReadonlyArray<
  Registration<LoginMenderDeps, CeremonyId>
> = [
  TRANSIENT_COLLECTION_CASCADE,
  ...sharedRegistryPasses('transient-login-chain'),
  TRANSIENT_MANAGE_ZCAP_REFRESH
]

/**
 * The transient block's tail: the keystore promotion, which nothing waits on
 * but `session.mends`.
 */
const TRANSIENT_TAIL_REGISTRATIONS: ReadonlyArray<
  Registration<LoginMenderDeps, CeremonyId>
> = [TRANSIENT_KEYSTORE_PROMOTION]

/**
 * The transient block: the registry-writing registrations, then the tail.
 * The inbox tail is not part of it, so neither `registryReady` nor `mends`
 * waits on another party's server.
 */
export const TRANSIENT_REGISTRATIONS: ReadonlyArray<
  Registration<LoginMenderDeps, CeremonyId>
> = [...TRANSIENT_REGISTRY_REGISTRATIONS, ...TRANSIENT_TAIL_REGISTRATIONS]

/**
 * The sites that report from their own call sites rather than from a block:
 * the routing entries, which decide whether a session is built at all, the
 * did:web projection mend, fired before the transient chain and in the
 * CHAPI popup, and the two ceremony tails that grade an entry through
 * `reportCeremonyTail` (`CEREMONY_TAIL_SITES`). They carry no `converge`,
 * so nothing can run them out of their own order.
 */
const REPORTING_SITES: ReadonlyArray<RegistrationSite> = [
  // The did:web projection mend, `refreshDidWebProjection`
  // (`src/session/annexReach.ts`), void-fired by the transient composition
  // before its chain.
  {
    trigger: 'transient-login-chain',
    reports: ['did-web-projection-matches-the-log']
  },
  // `mendCredentialAnchoredAccount` (wallet-core `/clientAnnex`) runs every
  // arm in one call, so one site reports all four of its invariants.
  {
    trigger: 'login-routing',
    reports: [
      'unlock-record-points-at-the-account-did',
      'space-controller-is-the-account-did',
      'roster-and-collection-epochs-exist',
      'registry-records-the-establishing-credential'
    ]
  },
  // The transient composition's annex-readiness stage,
  // `ensureClientAnnexGenerationReady` (`src/session/transientLogin.ts`),
  // which readies the generation, refreshes the standing delegations, and
  // heals the generation delegation in one call.
  {
    trigger: 'login-routing',
    reports: [
      'annex-generation-is-reachable',
      'standing-delegations-verify-under-the-current-document',
      'generation-delegation-is-current'
    ]
  },
  // The dead-pointer prompt's accept, `removeDeadPointerSignInData`
  // (`src/session/deadAccountPointer.ts`): the first-contact account-log
  // read of the transient login (`transientSessionFromKeyringHit`), of the
  // remembered login (`loginWithUnlockCredential`), of a pending record proof's
  // settlement (`settlePendingRecordProof`), and of a recovery code's
  // locate step and spend refuses on a 404 with the removal closure, and
  // the login, recover, or interaction-URL page runs it on the user's
  // accept.
  {
    trigger: 'login-routing',
    reports: ['no-unlock-space-outlives-its-credential']
  },
  // The four routing sites behind the client-key-record probe
  // (`src/session/initSession.ts`), in the order routing reaches them:
  // `wipeStaleClientResidue` and `assertClientStillEnrolled`
  // (`src/session/forget.ts`), `resumePendingEnrollment`
  // (`src/session/pendingEnrollment.ts`), and the `resumeRecoverySpend`
  // (`src/session/recovery.ts`) it dispatches.
  {
    trigger: 'login-routing',
    reports: ['client-key-record-matches-the-pointed-account'],
    guardedBy: 'client-key-record'
  },
  {
    trigger: 'login-routing',
    reports: ['this-browser-is-still-an-enrolled-client'],
    guardedBy: 'client-key-record'
  },
  {
    trigger: 'login-routing',
    reports: ['no-client-key-record-stays-pending'],
    guardedBy: 'client-key-record'
  },
  {
    trigger: 'login-routing',
    reports: ['recovery-spend-is-completed'],
    guardedBy: 'client-key-record'
  },
  // The encounter sites that keep their own call, since the caller needs a
  // return value or a thrown refusal back. None is run through the encounter
  // runner, and none evaluates a declaration's `when`.
  //
  // The App Connect grant path's generation-delegation renewal
  // (`src/lib/walletRequest/processZcaps.ts`), which throws
  // `GenerationDelegationStaleError` when it cannot renew.
  {
    trigger: 'encounter',
    reports: ['generation-delegation-is-current'],
    reachedBy: ['transient']
  },
  // The account deletion walk's `renewVisitDelegation`
  // (`src/session/accountSettings.ts`).
  {
    trigger: 'encounter',
    reports: ['generation-delegation-is-current'],
    reachedBy: ['transient']
  },
  // The Settings mount's `loadUnlockRegistry`
  // (`src/session/accountSettings.ts`): the passphrase-entry backfill on
  // either session kind, and on a transient session the acting credential's
  // management-zcap refresh inside the same call. Two sites, since the two
  // reach different session kinds.
  {
    trigger: 'encounter',
    reports: ['registry-lists-the-passphrase-method'],
    reachedBy: ['remembered', 'transient']
  },
  {
    trigger: 'encounter',
    reports: ['acting-credential-manage-zcap-is-current'],
    reachedBy: ['transient']
  },
  // The account deletion walk's in-place stale-seal repair
  // (`src/session/accountSettings.ts`), which refuses the deletion when the
  // repair does not land.
  {
    trigger: 'encounter',
    reports: ['unlock-registry-opens-under-the-current-user-key'],
    reachedBy: ['remembered', 'transient']
  },
  // The two ceremony tails that report an entry, keyed by ceremony in
  // `ceremonyTail.ts` so a reporter's entries are checked against its site.
  ...Object.values(CEREMONY_TAIL_SITES)
]

/**
 * Every registration site the registry indexes: both blocks in execution
 * order (the seed first), each followed by its inbox tail, the five
 * encounter registrations the encounter runner runs, then the sites that
 * report from their own call sites, the two ceremony tails last. The
 * audit's derived sets read this list.
 */
export const MENDER_SITES: ReadonlyArray<RegistrationSite> = [
  REMEMBERED_SEED,
  ...REMEMBERED_REGISTRATIONS,
  ...REMEMBERED_INBOX_TAIL,
  ...TRANSIENT_REGISTRATIONS,
  ...TRANSIENT_INBOX_TAIL,
  STRANDED_COLLECTION_ENCOUNTER,
  REGISTRY_SEAL_ENCOUNTER,
  CONNECTION_WRITERS_SWEEP_ENCOUNTER,
  INBOX_NOTIFICATIONS_ENCOUNTER,
  INBOX_CEREMONY_ENCOUNTER,
  ...REPORTING_SITES
]
