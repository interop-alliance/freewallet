/**
 * The registration lists: the code half of the mender registry. A
 * registration names the invariants one place converges and returns one
 * report entry per invariant it names, in that order. Registration order
 * within a list is execution order; there is no dependency graph and no
 * priority.
 *
 * Two lists are run by the runner, one per chain trigger. The remembered
 * list is split at the settle point: the registry-writing part settles
 * `session.registryReady`, and the tail (the keystore report, the app-key
 * sweep, and the annex GC) settles only `session.mends`. Beside them sit the sites that report from
 * their own call sites: the routing entries, whose control flow decides
 * whether a session is built at all, and the did:web projection mend, which
 * a transient visit fires before its chain and in the CHAPI popup. Those are
 * data (`RegistrationSite`) rather than registrations, so nothing can run
 * them out of their own order.
 */
import type {
  InvariantId,
  MendOutcome,
  Registration,
  RegistrationSite
} from '@interop/wallet-core/menders'
import type { UserKeyRosterReadResult } from '@interop/wallet-core/keys'
import type { SealableEncryptionDescriptorStore } from '@interop/wallet-core/keys'
import type { IZcap } from '@interop/data-integrity-core'
import type { PublishedKeyDocument } from '@interop/wallet-core/webvh'
import type { Session } from '@/types/auth'
import type { FreewalletCeremonyId } from '@/session/ceremonies'
import type {
  KeyringFetchResult,
  TransientKeyringFetchResult,
  UnlockCredential
} from '@/session/keyring'
import type { AccountCeremonyContext } from '@/session/accountCeremonyContext'
import {
  backfillRegistryPass,
  barePasskeyPass,
  blockRegistryRead,
  promotedAccountPointer,
  promotedAccountView,
  resealRegistryPass,
  tornRetirementPass,
  type BlockRegistryRead,
  type SharedRegistryPassOptions
} from '@/session/registryPasses'
import { sweepUserKeyToDocument } from '@/session/userKeySweep'
import {
  refreshCommittedLadderRung,
  refreshStandingDelegations
} from '@/session/standingDelegationRefresh'
import { healAccountPointer } from '@/session/pointerHeal'
import {
  clientAnnexReachFor,
  ensureGenerationDelegation
} from '@/session/annexReach'
import { sweepStrandedAppKeys } from '@/session/appKeySweep'
import { sweepClientAnnexGenerations } from '@/session/clientAnnexGc'
import { refreshTransientManageCapability } from '@/session/unlockMethods'

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
   * Where the pointer heal leaves the keystore promotion it fired, read by
   * the tail registration that reports the keystore controller. With no
   * `pending` that registration falls back to the promotion storage
   * provisioning fired, which is the ordinary case on an account whose
   * pointer already names the did:webvh.
   */
  keystorePromotion: { pending?: Promise<MendOutcome> }
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
   * The visit's roster read, whose user key the registry writes seal to.
   */
  rosterRead: UserKeyRosterReadResult
  /**
   * The generation delegation the visit started on.
   */
  generationDelegation: IZcap
  /**
   * The derived unlock credential, where the visit holds one.
   */
  credential?: UnlockCredential
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
 */
export const REMEMBERED_SEED: Registration<
  LoginMenderDeps,
  FreewalletCeremonyId
> = {
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
 * fan-out, one registration reporting both predicates. It runs first because
 * its convergence may rotate the user key and re-seal the registry to the
 * fresh one, and a registry read-modify-write racing that re-seal would
 * rewrite the record under the pre-rotation keys and undo it within one
 * login.
 */
const USER_KEY_SWEEP: Registration<LoginMenderDeps, FreewalletCeremonyId> = {
  trigger: 'remembered-login-chain',
  reports: [
    'roster-wraps-exactly-the-document-key-set',
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
      const detail = { reason: 'nothing-to-sweep-from' }
      return [
        {
          invariant: 'roster-wraps-exactly-the-document-key-set',
          outcome: 'noop',
          detail
        },
        {
          invariant: 'collection-epochs-name-the-current-user-key',
          outcome: 'noop',
          detail
        }
      ]
    }
    const { rotated, sealed, staleRecipients, escrowedRecipients, cascade } =
      await sweepUserKeyToDocument({
        session,
        store: rosterStore,
        userKey,
        read: rosterRead
      })
    // The convergence mends the predicate three ways, and only one of them
    // rotates: it can also escrow a torn enrollment's missing wraps, or seal
    // the roster log's head past a membership change. Any of the three is a
    // login that repaired the roster.
    const converged = rotated || sealed || escrowedRecipients > 0
    const rosterDetail = {
      ...(staleRecipients > 0 ? { staleRecipients } : {}),
      ...(escrowedRecipients > 0 ? { escrowedRecipients } : {}),
      ...(sealed ? { sealed } : {})
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
        invariant: 'collection-epochs-name-the-current-user-key',
        ...(cascade.failed.length > 0
          ? {
              outcome: 'partial' as const,
              // The ids and their errors ride the sweep's own logger; a
              // report carries the count alone.
              detail: { failedCollections: cascade.failed.length }
            }
          : Object.values(cascade.outcomes).some(
                outcome => outcome === 'rotated'
              )
            ? { outcome: 'clean' as const }
            : { outcome: 'noop' as const })
      }
    ]
  }
}

/**
 * The block's one unlock-methods registry read, keyed by the deps object the
 * block was started with. The deps object IS the block, so every
 * registration of one login shares one fetch while two logins in flight keep
 * their own. A pass that wrote the registry drops the memo, so the passes
 * behind it read the record it left.
 */
const BLOCK_REGISTRY_READS = new WeakMap<LoginMenderDeps, BlockRegistryRead>()

/**
 * The block's registry read, created on the first registration that asks.
 *
 * @param deps {LoginMenderDeps}
 * @returns {BlockRegistryRead}
 */
function blockRegistry(deps: LoginMenderDeps): BlockRegistryRead {
  let memo = BLOCK_REGISTRY_READS.get(deps)
  if (!memo) {
    memo = blockRegistryRead({ session: deps.session })
    BLOCK_REGISTRY_READS.set(deps, memo)
  }
  return memo
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
  const { session, found, context, rosterRead } = deps
  const credential =
    deps.chain === 'remembered'
      ? deps.loginCredential
      : deps.credential
        ? { derived: deps.credential }
        : undefined
  return {
    session,
    found,
    context: await context(),
    registry: blockRegistry(deps),
    ...(rosterRead ? { rosterRead } : {}),
    ...(credential ? { credential } : {})
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
): ReadonlyArray<Registration<LoginMenderDeps, FreewalletCeremonyId>> {
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
const STANDING_DELEGATION_REFRESH: Registration<
  LoginMenderDeps,
  FreewalletCeremonyId
> = {
  trigger: 'remembered-login-chain',
  reports: ['standing-delegations-verify-under-the-current-document'],
  async converge(deps) {
    const { session, found } = remembered(deps)
    const invariant = 'standing-delegations-verify-under-the-current-document'
    const rebindStandingRecord = found.rebindStandingRecord
    const delegation = found.standing?.delegation
    const standingClientDid = found.standingClient?.clientDid
    if (!rebindStandingRecord || !delegation || !standingClientDid) {
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
      verifiedLog: async () => {
        const promoted = await promotedAccountView({ session })
        if (!promoted) {
          throw new Error(
            'The account pointer stopped naming a did:webvh mid-refresh.'
          )
        }
        return promoted.verified
      },
      rebindStandingRecord,
      delegation,
      ...(found.standing?.delegatedClients
        ? { delegatedClients: found.standing.delegatedClients }
        : {}),
      standingClientDid,
      unlockSpaceId: found.unlockSpaceId,
      ...(found.standingClient?.keyAgreementKeyMultibase
        ? {
            keyAgreementKeyMultibase:
              found.standingClient.keyAgreementKeyMultibase
          }
        : {})
    })
    return [
      { invariant, outcome: refreshed === 'refreshed' ? 'clean' : 'noop' }
    ]
  }
}

/**
 * The recorded ladder rung, after a self-enrollment climbed the ladder.
 */
const LADDER_RUNG_REFRESH: Registration<LoginMenderDeps, FreewalletCeremonyId> =
  {
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
      return [
        { invariant, outcome: recorded === 'recorded' ? 'clean' : 'noop' }
      ]
    }
  }

/**
 * The did:webvh pointer heal and the Space-controller promotion behind it.
 * The keystore promotion that promotion fires is left on the deps for the
 * tail registration below, so `session.registryReady` does not wait on a
 * KMS round trip.
 */
const POINTER_HEAL: Registration<LoginMenderDeps, FreewalletCeremonyId> = {
  trigger: 'remembered-login-chain',
  reports: [
    'account-pointer-names-the-account-did',
    'space-controller-is-the-account-did'
  ],
  async converge(deps) {
    const { session, found, keystorePromotion } = remembered(deps)
    const healed = await healAccountPointer({
      session,
      ...(found.persistAccountPointer
        ? { persistAccountPointer: found.persistAccountPointer }
        : {}),
      ...(found.pointer ? { pointer: found.pointer } : {})
    })
    if (healed.keystorePromotion) {
      keystorePromotion.pending = healed.keystorePromotion
    }
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
 * already names the did:webvh. It sits in the tail rather than beside the
 * heal because awaiting a KMS round trip inside the registry-writing prefix
 * would put every Settings ceremony's `registryReady` wait behind that trip.
 * It reports `noop` only when no promotion ran at all (a session with no
 * remote store or no account DID).
 */
const KEYSTORE_PROMOTION: Registration<LoginMenderDeps, FreewalletCeremonyId> =
  {
    trigger: 'remembered-login-chain',
    reports: ['keystore-controller-is-the-account-did'],
    async converge(deps) {
      const { session, keystorePromotion } = remembered(deps)
      const invariant = 'keystore-controller-is-the-account-did'
      const pending =
        keystorePromotion.pending ?? session.storage.keystorePromotion
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
const GENERATION_DELEGATION_HEAL: Registration<
  LoginMenderDeps,
  FreewalletCeremonyId
> = {
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
      doc: promoted.verified.doc
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
      if (
        (err as { name?: string }).name !== 'ClientAnnexRungUncommittedError'
      ) {
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
 * The stranded app-key sweep. Registered behind the registry-writing
 * entries, so it settles under `session.mends` alone.
 */
const APP_KEY_SWEEP: Registration<LoginMenderDeps, FreewalletCeremonyId> = {
  trigger: 'remembered-login-chain',
  reports: ['app-keys-live-only-in-app-connections'],
  async converge(deps) {
    const { session } = remembered(deps)
    const { deleted, retracted } = await sweepStrandedAppKeys({
      storage: session.storage
    })
    return [
      {
        invariant: 'app-keys-live-only-in-app-connections',
        outcome: deleted + retracted > 0 ? 'clean' : 'noop',
        detail: { deleted, retracted }
      }
    ]
  }
}

/**
 * The annex GC sweep, last: a sibling re-mint above lands first.
 */
const ANNEX_GC: Registration<LoginMenderDeps, FreewalletCeremonyId> = {
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
    const { swap, collected, failed } = swept.report
    return [
      {
        invariant: 'no-annex-generation-outlives-its-pointer',
        outcome:
          failed.length > 0
            ? 'partial'
            : swap === 'replaced' || collected.length > 0
              ? 'clean'
              : 'noop',
        detail: {
          swap,
          collected: collected.length,
          failed: failed.length
        }
      }
    ]
  }
}

/**
 * The acting credential's management-zcap refresh, last on the transient
 * chain: it compare-and-swaps the same registry entry the passes above
 * rewrite, and two writers racing one entry would spend the retry budget
 * undoing each other.
 */
const TRANSIENT_MANAGE_ZCAP_REFRESH: Registration<
  LoginMenderDeps,
  FreewalletCeremonyId
> = {
  trigger: 'transient-login-chain',
  reports: ['acting-credential-manage-zcap-is-current'],
  async converge(deps) {
    const { session, found, rosterRead, generationDelegation } = transient(deps)
    const invariant = 'acting-credential-manage-zcap-is-current'
    // The capability the visit rides now, not the one it started on: a
    // registration above may have renewed the generation delegation.
    const capability =
      session.profile.invocationCapability ?? generationDelegation
    const spaceId = session.profile.accountPointer?.spaceId
    if (!found.manageCapability || !capability || !spaceId) {
      return [
        {
          invariant,
          outcome: 'noop',
          detail: { reason: 'no-management-zcap' }
        }
      ]
    }
    await refreshTransientManageCapability({
      zcapClient: session.profile.zcapClient,
      spaceId,
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
    return [{ invariant, outcome: 'clean' }]
  }
}

/**
 * The remembered block's registry-writing registrations, in execution order.
 * `session.registryReady` settles when the last of these has reported, which
 * is the meaning its awaiters have always had.
 */
export const REMEMBERED_REGISTRY_REGISTRATIONS: ReadonlyArray<
  Registration<LoginMenderDeps, FreewalletCeremonyId>
> = [
  USER_KEY_SWEEP,
  ...sharedRegistryPasses('remembered-login-chain'),
  STANDING_DELEGATION_REFRESH,
  LADDER_RUNG_REFRESH,
  POINTER_HEAL,
  GENERATION_DELEGATION_HEAL
]

/**
 * The remembered block's tail: the keystore report and the two sweeps,
 * which nothing waits on but `session.mends`.
 */
export const REMEMBERED_TAIL_REGISTRATIONS: ReadonlyArray<
  Registration<LoginMenderDeps, FreewalletCeremonyId>
> = [KEYSTORE_PROMOTION, APP_KEY_SWEEP, ANNEX_GC]

/**
 * The remembered block, seed excluded (the runner takes that separately).
 */
export const REMEMBERED_REGISTRATIONS: ReadonlyArray<
  Registration<LoginMenderDeps, FreewalletCeremonyId>
> = [...REMEMBERED_REGISTRY_REGISTRATIONS, ...REMEMBERED_TAIL_REGISTRATIONS]

/**
 * The transient block, every entry of which is registry-writing.
 */
export const TRANSIENT_REGISTRATIONS: ReadonlyArray<
  Registration<LoginMenderDeps, FreewalletCeremonyId>
> = [
  ...sharedRegistryPasses('transient-login-chain'),
  TRANSIENT_MANAGE_ZCAP_REFRESH
]

/**
 * The sites that report from their own call sites rather than from a block:
 * the routing entries, which decide whether a session is built at all, and
 * the did:web projection mend, fired before the transient chain and in the
 * CHAPI popup. They carry no `converge`, so nothing can run them out of
 * their own order.
 */
export const REPORTING_SITES: ReadonlyArray<RegistrationSite> = [
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
  }
]

/**
 * Every registration site the registry indexes: both blocks in execution
 * order (the seed first), then the sites that report from their own call
 * sites. The audit's derived sets read this list.
 */
export const MENDER_SITES: ReadonlyArray<RegistrationSite> = [
  REMEMBERED_SEED,
  ...REMEMBERED_REGISTRATIONS,
  ...TRANSIENT_REGISTRATIONS,
  ...REPORTING_SITES
]
