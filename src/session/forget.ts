/**
 * The forget affordance: removing this browser from a wallet account. Two
 * grades, split by whether the unlock credential is in hand:
 *
 * - **The forget ceremony** (`forgetThisBrowser`, run from a live
 *   remembered session): wallet-core's `forgetEnrolledClient` -- the roster
 *   rotation off this client's wrap and the collection fan-out under this
 *   client's still-standing authority, then ONE atomic ladder-signed
 *   removal entry through the standing credential's bridge -- followed by
 *   the shared local wipe (the FW-199 enumeration, `clearWriter: true`).
 *   The wipe runs LAST, so a tear anywhere before the removal entry reads
 *   as "not forgotten" and a re-click resumes; the ceremony is convergent
 *   under a naive re-run.
 *
 * - **The last-client transition** (the same `forgetThisBrowser` entry with
 *   `lastClient: true`, confirmed against transition-stating copy): when
 *   this browser is the account's LAST enrolled client, wallet-core's
 *   `forgetLastEnrolledClient` runs instead -- the two-entry ceremony that
 *   lands the account client-less and ladder-anchored (the state a
 *   credential-anchored signup and a transient recovery produce): the ladder
 *   VM's install entry, the ladder-signed roster rotation anchored there and
 *   the fan-out under this client's still-standing authority, the forced
 *   ladder-signed generation-delegation replacement and the revocation of
 *   every ladder-signed delegation the annex history embedded, the OTHER
 *   unlock methods' record re-mint (every other standing credential's and
 *   recovery code's bridge and sibling re-signed by the ladder VM and its
 *   record re-sealed through the entry's management zcap -- the revocation
 *   cascade's re-mint pass over the registry, this client's last window of
 *   registry authority, since on a client-less account no remembered login's
 *   refresh block will ever heal them), the login credential's record
 *   re-bind (bridge and sibling re-signed by the ladder VM through the hit's
 *   re-bind closure, the registry pair refreshed), then the removal entry.
 *   The ordinary ceremony's `LastEnrolledClientForgetError` (name-stable) is
 *   the routing signal when the caller's view was stale.
 *   The transition's own name-stable refusal, `RecordRemintFailedError`
 *   (another sign-in method's record could not be re-sealed, so the
 *   removal entry was withheld), propagates before the wipe: this browser
 *   is still connected, and a re-run resumes at the re-mint. Before any of
 *   it runs, the transition refuses on a pending-shaped passphrase registry
 *   entry (`PendingRetirementForgetError`): a passphrase change torn before
 *   its retirement landed is mended only by the torn-retirement repair,
 *   which needs a remembered login -- the very thing this ceremony ends
 *   forever. It refuses just as early when the registry does not cover
 *   every standing credential the account document publishes
 *   (`UnrecordedCredentialForgetError`): the re-mint pass walks the
 *   registry, so an unrecorded credential's bridge would rot at the removal
 *   entry with no login left to heal it.
 *
 * - **The no-unlock-material grade** (`forgetBrowserWalletData`, run from
 *   the login page's refusal states): nothing can be derived or signed, so
 *   no ceremony runs -- the wipe is whole-database and browser-scoped
 *   ("forget all wallet data on this browser"): the `freewallet-session`
 *   database and every replica database are deleted wholesale, with the
 *   cross-account blast radius stated in the calling surface's copy (other
 *   accounts remembered on this browser lose their client-key records; no
 *   account is lost -- a standing credential self-enrolls at the next
 *   login). The standing document client gets NO flag anywhere: with no
 *   unlock material nothing can be signed, and the honest residue is
 *   stated in the copy, pointing at the Connected wallets disconnect from a
 *   logged-in client.
 *
 * The login-time detector (`assertClientStillEnrolled`) maps the
 * removal-published-but-wipe-torn state -- an ENROLLED-shape local client-key
 * record present while this client's verification method is gone from the
 * verified account document (a forget torn before its wipe, or a disconnect
 * run from another client) -- to finish-the-wipe plus a typed
 * `BrowserForgottenError`, never raw authorization errors. A pending-shape
 * record (a self-enrollment's persist-before-publish residue) is spared and
 * routed to the resume instead (freewallet `decisions/0007`), whose
 * published-then-removed branch hands the genuine removal case back to the
 * same wipe. Nothing about the detection is persisted; it is recomputed from
 * durable state at each login.
 *
 * The honest limits are the wipe seam's and the cascade's: deleted IndexedDB
 * data stays forensically recoverable, the partitioned CHAPI popup buckets
 * and the mediator-origin registration bit are unreachable, and ciphertext
 * this browser already fetched stays readable to whoever holds it.
 */
import { deriveNextKeyHash, type DIDLog } from '@interop/did-method-webvh'
import { WasClient } from '@interop/was-client'
import {
  clientAnnexLogStore,
  delegatedClientsDelegationSpaceId,
  forgetEnrolledClient,
  forgetLastEnrolledClient,
  ladderVmAgent,
  ladderVmZcapClient,
  mintDelegatedClientsDelegation
} from '@interop/wallet-core/clientAnnex'
import type {
  EnrolledClientForgetResult,
  LastEnrolledClientForgetResult
} from '@interop/wallet-core/clientAnnex'
import { agentsFromSeed } from '@interop/wallet-core/identity'
import { getUnlockKeyringWithCapability } from '@interop/wallet-core/keyring'
import {
  unlockKeyVmId,
  unlockRecordSealedTo
} from '@interop/wallet-core/unlock'
import {
  userKeyRosterDescriptorStore,
  userKeyRosterLogSigner
} from '@interop/wallet-core/keys'
import {
  delegateLogWrite,
  delegationProofKeyId
} from '@interop/wallet-core/recovery'
import { webvhResourceLogController } from '@interop/wallet-core/resourceLog'
import {
  accountLogPinId,
  clientKeyAgreementController,
  clientSigningKeyMultibase,
  isWebvhDid,
  keyAgreementCommitment,
  relationIds,
  resolvedKeyAgreementMethods,
  updateKeyMultibase,
  verifyAccountLog
} from '@interop/wallet-core/webvh'
import type { RevokedClientKeys } from '@interop/wallet-core/webvh'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import { WAS_SERVER_URL } from '@/app.config'
import type { Session, User } from '@/types/auth'
import { deriveSpaceId } from '@interop/was-client/sync'
import type { VerifiedAccountLog } from '@interop/wallet-core/clients'
import { SESSION_DB_NAME } from '@/lib/sessionKey'
import { clearWriterId } from '@/lib/writerId'
import { BrowserStore, migrationMarkerKeys } from '@/stores/browserStore'
import {
  assertAccountCeremonyAllowed,
  deleteAllLocalCacheFamilies,
  LOCAL_CACHE_FAMILY_PREFIXES
} from '@/session/persistence'
import { requireEnrolledClientContext } from '@/session/enrolledContext'
import type { KeyringFetchResult } from '@/session/keyring'
import {
  recordRemintedEntry,
  recoveryEntriesOf,
  remintEntriesOf
} from '@/session/recovery'
import { sessionRosterStore } from '@/session/rosterStore'
import { unlockLogStore } from '@/session/standingUnlock'
import {
  getUnlockMethods,
  managementZcapClient,
  refreshStandingDelegationFields,
  type PassphraseUnlockMethod,
  type UnlockMethod
} from '@/session/unlockMethods'
import { adoptRotatedUserKeyInBand } from '@/session/userKeyAdoption'
import { cascadeCollections } from '@/session/userKeyCascade'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:forget')
import {
  invalidateVerifiedLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
import {
  executeLocalWipe,
  snapshotWipeTargets,
  type WipeTargets
} from '@/session/wipe'

/**
 * Thrown by the login-time detector when this browser's client-key record is
 * still present but its verification method is gone from the verified
 * account document: the browser was forgotten (or disconnected from another
 * client) and only the local wipe remained. The detector finishes the wipe
 * before throwing, so the login page can state the clean outcome ("this
 * browser was forgotten; log in again to reconnect") instead of surfacing
 * raw authorization errors.
 */
export class BrowserForgottenError extends Error {
  wipeFailed: string[]
  wipeUnverified: string[]
  constructor({
    wipeFailed,
    wipeUnverified
  }: {
    wipeFailed: string[]
    wipeUnverified: string[]
  }) {
    super(
      "This browser's wallet access was removed from the account; its " +
        'local wallet data has been cleared.'
    )
    this.name = 'BrowserForgottenError'
    this.wipeFailed = wipeFailed
    this.wipeUnverified = wipeUnverified
  }
}

/**
 * Thrown by the last-client transition when the unlock-methods registry
 * carries a pending-shaped passphrase entry: the entry's unlock Space and
 * management zcap name one credential while its identity members name
 * another, the state a passphrase change torn before its retirement leaves.
 * The transition is refused because it would destroy that state's only
 * mender -- the torn-retirement repair runs from a remembered login,
 * which the transition ends forever, leaving the half-retired credential
 * standing and decryptable with nothing left to finish the change. Matched
 * on `name` by the settings surface.
 */
export class PendingRetirementForgetError extends Error {
  constructor() {
    super(
      'This browser cannot be forgotten yet: a passphrase change on this ' +
        'account did not finish, and this browser is the only one that can ' +
        'finish it.'
    )
    this.name = 'PendingRetirementForgetError'
  }
}

/**
 * Thrown by the last-client transition when the account document publishes a
 * standing credential's `keyAgreement` entry that no unlock-methods registry
 * entry names. Every walk the transition and the client-less account after
 * it perform is registry-driven -- the other methods' record re-mint, the
 * removal entry's latent-hash vouching, the recovery health sweep -- so an
 * unrecorded credential's bridge delegation would rot un-re-minted at the
 * removal entry and its self-enrollment would brick silently, on an account
 * no remembered login will ever heal again. Matched on `name` by the settings
 * surface.
 */
export class UnrecordedCredentialForgetError extends Error {
  unrecorded: number
  constructor({ unrecorded }: { unrecorded: number }) {
    super(
      `This browser cannot be forgotten yet: ${unrecorded} sign-in ` +
        "method(s) on this account are not recorded in the wallet's " +
        'sign-in registry.'
    )
    this.name = 'UnrecordedCredentialForgetError'
    this.unrecorded = unrecorded
  }
}

/**
 * What a completed forget reports: which ceremony ran (`lastClient: false`
 * is the ordinary forget, `true` the last-client transition) with that
 * ceremony's own result, plus the local wipe's failed-stage names and the
 * names of the stages that ran without confirmation (both empty on a clean,
 * verified wipe).
 */
type ForgetCeremonyOutcome =
  | { lastClient: false; ceremony: EnrolledClientForgetResult }
  | { lastClient: true; ceremony: LastEnrolledClientForgetResult }
export type ForgetOutcome = ForgetCeremonyOutcome & {
  wipeFailed: string[]
  wipeUnverified: string[]
}

/**
 * Runs the forget for this browser, from a live remembered session: snapshot
 * the wipe targets first, then the ceremony, then the shared local wipe with
 * `clearWriter: true`. The caller logs the session out once this resolves;
 * there is no audit record, because this client's invocations die with the
 * removal entry and the world-readable log entry IS the audit.
 *
 * Which ceremony runs is the caller's `lastClient` choice, because the two
 * carry different consequences the user confirms against: `false` is
 * wallet-core's `forgetEnrolledClient` (rotation, fan-out, removal entry --
 * the self-forget inversion), and `true` is `forgetLastEnrolledClient` (the
 * two-entry transition to the client-less, ladder-anchored account; see the
 * module doc). A `false` run that turns out to be the last client -- the
 * caller's listing was stale -- refuses with wallet-core's name-stable
 * `LastEnrolledClientForgetError` before any write, so the caller can
 * re-confirm against the transition copy; a `true` run on an account with
 * another enrolled client refuses from the ceremony's pre-install read, and
 * one that could not re-seal another sign-in method's record refuses with
 * the name-stable `RecordRemintFailedError` before its removal entry (the
 * local wipe never runs on a refusal, so the browser stays connected and
 * the next run resumes).
 *
 * Refusals before anything runs: a pending-shaped passphrase registry entry
 * on the transition (`PendingRetirementForgetError`), a registry on the
 * transition that does not name every standing credential the account
 * document publishes (`UnrecordedCredentialForgetError`), a transient session
 * (`StepUpRequiredError`
 * via the shared ceremony gate) and a session whose login did not carry the
 * credential's standing members (the bridge delegation and ladder seed; the
 * transition additionally needs the hit's record re-bind closure, since a
 * removal entry leaving the login credential's bridge rotted would strand
 * the account).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.lastClient] {boolean}   run the last-client transition
 *   (default false: the ordinary forget)
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<ForgetOutcome>}
 */
export async function forgetThisBrowser({
  session,
  lastClient = false,
  idb
}: {
  session: Session
  lastClient?: boolean
  idb?: IDBFactory
}): Promise<ForgetOutcome> {
  assertAccountCeremonyAllowed({
    persistence: session.profile.persistence,
    ceremony: 'Forgetting this browser'
  })
  // Wait out the login-time registry passes rather than racing their
  // read-modify-writes (the ceremony re-seals the registry and, on the
  // last-client transition, re-mints every entry); on a settled session
  // the chain resolved long ago.
  await session.registryReady
  const { remoteStore, pointer, clientWebvhKeys, keyAgent } =
    requireEnrolledClientContext({ session, action: 'Forgetting this browser' })
  const standing = session.profile.standingUnlock
  const ladderSeed = session.profile.ladderSeed
  if (!standing || !ladderSeed) {
    throw new Error(
      "Forgetting this browser needs the login credential's standing " +
        'members (the bridge delegation and ladder seed), which this ' +
        'session does not carry; log in again with the passphrase or ' +
        'passkey first.'
    )
  }
  const rebindRecord = standing.rebindRecord
  if (lastClient && !rebindRecord) {
    throw new Error(
      "Forgetting the account's last connected browser needs the login " +
        "credential's record re-bind, which this session does not carry; " +
        'log in again with the passphrase or passkey first.'
    )
  }
  const keyAgreementKeyMultibase = (
    session.profile.clientKeyAgreementKey as unknown as {
      publicKeyMultibase?: string
    }
  )?.publicKeyMultibase
  if (!keyAgreementKeyMultibase) {
    throw new Error(
      "Forgetting this browser needs this client's key-agreement key " +
        'multibase to name its roster wrap.'
    )
  }

  // One registry read serves the removal entry's latent-hash vouching, the
  // wipe snapshot's unlock-Space enumeration, and (the transition) the other
  // unlock methods' record re-mint. Best-effort for the ordinary forget,
  // like the revocation cascade's; the transition cannot walk entries it
  // could not read, and a record it leaves unreached would rot for good at
  // the removal entry, so there the read failure refuses up front.
  const { epochPins } = session.profile.persistence
  let registryUnread = false
  const [registry, pinnedEpochId] = await Promise.all([
    getUnlockMethods({ session }).catch((err: unknown) => {
      if (lastClient) {
        throw new Error(
          'Could not read the unlock-methods registry, which the last-' +
            "client forget needs to re-seal the other sign-in methods' " +
            'records; try again.',
          { cause: err }
        )
      }
      log.warn(
        'Could not read the unlock-methods registry for the forget ceremony',
        { err }
      )
      registryUnread = true
      return null
    }),
    epochPins.load({ accountDid: pointer.did })
  ])
  const latentMultibases = [
    ...recoveryEntriesOf({ record: registry }).map(
      entry => entry.updateKeyMultibase
    ),
    ...(registry?.methods ?? []).flatMap(method =>
      (method.type === 'passphrase' || method.type === 'passkey') &&
      method.updateKeyMultibase
        ? [method.updateKeyMultibase]
        : []
    )
  ]

  // The transition's pending-retirement guard, before anything is written:
  // a passphrase change torn before its retirement landed leaves a registry
  // entry only a remembered login can finish, and this ceremony ends
  // remembered logins on this account forever.
  if (lastClient) {
    await assertNoPendingPassphraseEntry({ session, pointer, registry })
    await assertRegistryCoversStandingCredentials({
      session,
      pointer,
      registry
    })
  }

  // Snapshot-first: every wipe target derives from the live session BEFORE
  // the ceremony ends this client's authority (and before anything deletes).
  // The login credential's own local state is enumerated from the session
  // itself, so an unread registry narrows the wipe to the other methods' and
  // is reported on the outcome, rather than leaving this browser's
  // client-key record behind a wipe that reads as clean.
  const targets = snapshotWipeTargets({
    session,
    registry,
    registryUnread
  })

  const forgottenClient: RevokedClientKeys = {
    signingKeyMultibase: clientSigningKeyMultibase({ keyAgent }),
    updateKeyMultibase: await updateKeyMultibase({
      seed: clientWebvhKeys.updateSeed
    })
  }
  const shared = {
    logStore: unlockLogStore({
      pointer,
      delegation: standing.delegation,
      zcapClient: standing.standingClient.agents.zcapClient
    }),
    ladderSeed,
    forgottenClient,
    forgottenKeyAgreementKeyMultibase: keyAgreementKeyMultibase,
    knownLatentHashes: await Promise.all(
      latentMultibases.map(multibase => deriveNextKeyHash(multibase))
    ),
    expectedDid: pointer.did,
    // The account log's chain-head pin: every read the ceremony makes (the
    // pre-edit read the roster rotation's recipient document comes from,
    // and each ladder entry's own read) is checked against it, so a served
    // truncated prefix is refused before anything is built on it.
    pinStore: session.profile.persistence.logPins,
    ...(session.profile.userKey ? { userKey: session.profile.userKey } : {}),
    credentialKeyAgreementKey: standing.standingClient.agents.keyAgreementKey,
    pinnedEpochId,
    onUserKeyAdopted: async ({
      userKey,
      latestEpochId,
      descriptor
    }: {
      userKey: NonNullable<Session['profile']['userKey']>
      latestEpochId: string
      descriptor: Parameters<
        typeof epochPins.saveFromDescriptor
      >[0]['descriptor']
    }) =>
      // The in-band adoption. The registry is sealed to the vault keys, so it
      // is re-sealed to the rotated key -- first, while this browser's
      // browser-local copy of the old one still exists -- and the live
      // session swapped onto it, so the later registry writes below read
      // under the current key; the surviving readers -- other enrolled
      // clients, transient logins -- would otherwise find it sealed to a
      // retired
      // generation. The client-key record persists behind it, so a run torn
      // before the removal entry leaves this browser consistent for the
      // resuming re-click.
      await adoptRotatedUserKeyInBand({
        session,
        spaceId: pointer.spaceId,
        accountDid: pointer.did,
        userKey,
        latestEpochId,
        descriptor
      }),
    collections: cascadeCollections({ remoteStore })
  }

  // The ceremony opens with reads and ends with a document edit; no session
  // surface may keep serving a pre-edit view.
  invalidateVerifiedLog({ profile: session.profile })
  let outcome: ForgetCeremonyOutcome
  try {
    if (!lastClient) {
      const ceremony = await forgetEnrolledClient({
        ...shared,
        logId: accountLogPinId({ spaceId: pointer.spaceId }),
        rosterStore: sessionRosterStore({ profile: session.profile })
      })
      outcome = { lastClient: false, ceremony }
    } else {
      const ceremony = await forgetLastEnrolledClient({
        ...shared,
        rosterStoreFor: await ladderSignedRosterStoreFor({
          session,
          pointer,
          ladderSeed
        }),
        annex: annexCeremonyReach({ session, pointer }),
        unlockMethods: unlockMethodsRemintReach({
          session,
          pointer,
          registry,
          loginUnlockSpaceId: standing.unlockSpaceId
        }),
        onBeforeRemoval: async ({ did }) =>
          rebindLoginCredentialRecord({
            session,
            pointer,
            accountDid: did,
            ladderSeed,
            standing: { ...standing, rebindRecord: rebindRecord! }
          })
      })
      outcome = { lastClient: true, ceremony }
    }
  } finally {
    invalidateVerifiedLog({ profile: session.profile })
  }

  // The local wipe runs strictly last -- it is what makes a torn run read as
  // "not forgotten" -- and clears the browser-global writerId (the forget
  // grade's one writerId consumer).
  const { failed, unverified } = await executeLocalWipe({
    targets,
    storage: session.storage ?? undefined,
    idb,
    clearWriter: true
  })
  return { ...outcome, wipeFailed: failed, wipeUnverified: unverified }
}

/**
 * The last-client transition's roster store builder: appends SIGNED BY THE
 * LADDER VM (the key the post-removal document still lists, so the roster
 * head needs no seal repair on an account where no enrolled client's
 * login sweep will ever run again), the controller view resolved from the
 * post-install log the ceremony supplies (the ceremony-tail license's
 * inventory-changing anchor), and the HTTP requests invoked under this
 * still-standing client.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.pointer {{ host: string, spaceId: string }}
 * @param options.ladderSeed {Uint8Array}
 * @returns {Promise<Function>}   `({ did, log }) => store`
 */
async function ladderSignedRosterStoreFor({
  session,
  pointer,
  ladderSeed
}: {
  session: Session
  pointer: { host: string; spaceId: string }
  ladderSeed: Uint8Array
}) {
  const signer = userKeyRosterLogSigner({
    keyAgent: await ladderVmAgent({ ladderSeed })
  })
  return ({ did, log }: { did: string; log: DIDLog }) =>
    userKeyRosterDescriptorStore({
      storageServerUrl: pointer.host,
      zcapClient: session.profile.zcapClient,
      spaceId: pointer.spaceId,
      resolveController: async () => webvhResourceLogController({ did, log }),
      pinStore: session.profile.persistence.logPins,
      signer
    })
}

/**
 * The last-client transition's reach into the client annex, under this
 * still-standing client's authority: the pointed generation's log store
 * (read and write), the revocation POST for the doomed ladder-signed
 * generation delegations, the chain-head pin store, and the account Space
 * the fresh delegation targets.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.pointer {{ host: string, spaceId: string }}
 * @returns {object}   the ceremony's `annex` option
 */
function annexCeremonyReach({
  session,
  pointer
}: {
  session: Session
  pointer: { host: string; spaceId: string }
}) {
  const was = new WasClient({
    serverUrl: pointer.host,
    zcapClient: session.profile.zcapClient
  })
  return {
    storeFor: ({
      spaceId,
      generationId
    }: {
      spaceId: string
      generationId: string
    }) => clientAnnexLogStore({ was, spaceId, generationId }),
    revoke: async (delegation: Parameters<WasClient['revoke']>[0]) =>
      was.revoke(delegation),
    wasServerUrl: pointer.host,
    accountSpaceId: pointer.spaceId,
    pinStore: session.profile.persistence.logPins
  }
}

/**
 * The transition's reach into the OTHER unlock methods' records (the
 * ceremony's `unlockMethods` stage): every registry entry but the login
 * credential's own (re-bound through the hit's closure in the
 * `onBeforeRemoval` seam instead), in the revocation cascade's re-mint shape,
 * with the management zcaps invoked under this still-standing client and the
 * refreshed fields written back to the registry while this client can still
 * write it. An unreachable record refuses the removal entry inside the
 * ceremony (`RecordRemintFailedError`), so nothing here is best-effort.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.pointer {AccountPointer}
 * @param options.registry {UnlockMethodsRecord | null}
 * @param options.loginUnlockSpaceId {string}   the login credential's
 *   unlock Space, whose entry is left out
 * @returns {UnlockMethodsRemintReach}
 */
function unlockMethodsRemintReach({
  session,
  pointer,
  registry,
  loginUnlockSpaceId
}: {
  session: Session
  pointer: Parameters<typeof delegateLogWrite>[0]['pointer']
  registry: Parameters<typeof remintEntriesOf>[0]['record']
  loginUnlockSpaceId: string
}): NonNullable<
  Parameters<typeof forgetLastEnrolledClient>[0]['unlockMethods']
> {
  return {
    entries: remintEntriesOf({
      record: registry,
      excludeUnlockSpaceIds: [loginUnlockSpaceId]
    }),
    pointer,
    storageServerUrl: WAS_SERVER_URL ?? pointer.host,
    managementZcapClient: ({ capability }) =>
      managementZcapClient({ session, capability }),
    recordEntry: async ({ entry }) =>
      recordRemintedEntry({
        session,
        entry: entry as Parameters<typeof recordRemintedEntry>[0]['entry']
      })
  }
}

/**
 * The transition's record re-bind (the ceremony's `onBeforeRemoval` seam):
 * the login credential's bridge delegation and its `delegatedClients`
 * sibling are re-signed by the LADDER VM -- listed under
 * `capabilityDelegation` from the install entry on, and the one key the
 * post-removal document still backs -- and the unlock record is re-sealed
 * through the hit's re-bind closure, with the registry pair refreshed under
 * this client's last window of registry authority. Idempotent (a resumed
 * run re-mints and re-binds again). The sibling's auxiliary Space id rides
 * in the old sibling, the id's one carrier; a record without a sibling
 * re-binds the bridge alone.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.pointer {AccountPointer}
 * @param options.accountDid {string}   the post-install DID (the ladder
 *   VM's id is minted against it)
 * @param options.ladderSeed {Uint8Array}
 * @param options.standing {object}   the profile's standing members with
 *   the re-bind closure present
 * @returns {Promise<void>}
 */
async function rebindLoginCredentialRecord({
  session,
  pointer,
  accountDid,
  ladderSeed,
  standing
}: {
  session: Session
  pointer: Parameters<typeof delegateLogWrite>[0]['pointer']
  accountDid: string
  ladderSeed: Uint8Array
  standing: NonNullable<Session['profile']['standingUnlock']> & {
    rebindRecord: NonNullable<
      NonNullable<Session['profile']['standingUnlock']>['rebindRecord']
    >
  }
}): Promise<void> {
  const ladderClient = await ladderVmZcapClient({ accountDid, ladderSeed })
  const controller = standing.standingClient.clientDid
  const delegation = await delegateLogWrite({
    zcapClient: ladderClient,
    pointer,
    recoveryClientDid: controller
  })
  let delegatedClients
  if (standing.delegatedClients) {
    const clientAnnexSpaceId = delegatedClientsDelegationSpaceId({
      delegation: standing.delegatedClients
    })
    if (clientAnnexSpaceId) {
      delegatedClients = await mintDelegatedClientsDelegation({
        zcapClient: ladderClient,
        wasServerUrl: pointer.host,
        clientAnnexSpaceId,
        controller
      })
    }
  }
  await standing.rebindRecord({
    delegation,
    ...(delegatedClients ? { delegatedClients } : {})
  })
  await refreshStandingDelegationFields({
    session,
    unlockSpaceId: standing.unlockSpaceId,
    keyAgreementKeyMultibase: standing.standingClient.keyAgreementKeyMultibase,
    delegationKeyId: delegationProofKeyId(delegation),
    delegationExpires: (delegation as { expires?: string }).expires,
    ...(delegatedClients
      ? {
          delegatedClientsKeyId: delegationProofKeyId(delegatedClients),
          delegatedClientsExpires: (delegatedClients as { expires?: string })
            .expires
        }
      : {})
  })
}

/**
 * The login-time finish-the-wipe detector: called on the remembered login path
 * when the keyring hit carries this browser's client keys and the pointer names
 * a did:webvh. A cleanly verified account document that no longer lists this
 * client's verification method means the removal entry landed (a forget torn
 * before its wipe, or a disconnect from another client), so the local residue
 * is wiped -- targets derived from the hit alone, since the registry is
 * unreachable without account authority -- and the typed
 * `BrowserForgottenError` surfaces the state. Every verification failure
 * (network, a missing log, a continuity refusal) skips detection and lets the
 * ordinary login proceed to its own handling: only a VERIFIED document may
 * trigger a wipe.
 *
 * Returns the verification it performed, so the session being built can
 * seed its verified-log memo with it instead of fetching and re-verifying
 * the same log moments later; `undefined` means detection was skipped.
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}   a hit carrying `clientKeys`
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<VerifiedAccountLog | undefined>}
 */
export async function assertClientStillEnrolled({
  found,
  idb
}: {
  found: KeyringFetchResult
  idb?: IDBFactory
}): Promise<VerifiedAccountLog | undefined> {
  const { clientKeys, pointer } = found
  if (!clientKeys || !pointer || !isWebvhDid(pointer.did)) {
    return undefined
  }
  // The trigger is deliberately narrowed to records holding a user key: a
  // PENDING record (`userKey` absent -- a self-enrollment's
  // persist-before-publish residue) is the resume's to route. Its VM may
  // never have been published, and wiping it would destroy the resume's only
  // key set; the resume's own published-then-removed branch hands the
  // genuine removal case back to this wipe (`finishForgottenBrowserWipe`).
  if (!clientKeys.userKey) {
    return undefined
  }
  let verified: VerifiedAccountLog
  let clientDid: string
  let signingKeyMultibase: string
  try {
    const agents = await agentsFromSeed({ seed: clientKeys.clientSeed })
    clientDid = agents.keyAgent.id
    signingKeyMultibase = clientSigningKeyMultibase({
      keyAgent: agents.keyAgent
    })
    verified = await verifyAccountLog({
      did: pointer.did,
      spaceId: pointer.spaceId,
      host: pointer.host,
      pinStore: memoryResourceLogPinStore()
    })
  } catch {
    // Unverifiable is not "forgotten": a flap, a missing log, and a
    // continuity refusal all fall through to the ordinary login, whose own
    // policy (and error mapping) applies.
    return undefined
  }
  const vmId = `${pointer.did}#${signingKeyMultibase}`
  const doc = verified.doc as { verificationMethod?: unknown }
  const methods = Array.isArray(doc.verificationMethod)
    ? (doc.verificationMethod as { id?: string }[])
    : []
  if (methods.some(method => method.id === vmId)) {
    return verified
  }
  return finishForgottenBrowserWipe({ found, clientDid, idb })
}

/**
 * The detector's finish-the-wipe tail: the removal entry landed for this
 * client, so the local residue is wiped from what the hit alone can derive
 * (this credential's local state, this client's replica and cache families,
 * the account's Space-to-DID mapping) and the typed `BrowserForgottenError`
 * surfaces the state.
 * Exported for the pending-record resume, whose published-then-removed branch
 * is the same removal case reached through a pending-shape record.
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}   a hit carrying `clientKeys` and
 *   a promoted pointer
 * @param options.clientDid {string}   this client's did:key, derived from the
 *   record's seed
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<never>}   always throws `BrowserForgottenError`
 */
export async function finishForgottenBrowserWipe({
  found,
  clientDid,
  idb
}: {
  found: KeyringFetchResult
  clientDid: string
  idb?: IDBFactory
}): Promise<never> {
  const pointer = found.pointer!
  const { failed, unverified } = await wipeClientResidue({
    clientDid,
    accountSpaceId: pointer.spaceId,
    unlockSpaceId: found.unlockSpaceId,
    idb,
    clearWriter: true
  })
  throw new BrowserForgottenError({
    wipeFailed: failed,
    wipeUnverified: unverified
  })
}

/**
 * The wipe body the record-triggered login wipes share: builds the
 * client-keyed targets (replica prefix, cache scopes), the account's
 * Space-to-DID mapping, and the credential's local state, and runs the
 * shared executor. No registry read happens on either caller (it needs
 * account authority the hit does not carry), so the enumeration is narrowed
 * by design rather than by a failed read.
 *
 * @param options {object}
 * @param options.clientDid {string}
 * @param [options.accountSpaceId] {string}
 * @param options.unlockSpaceId {string}
 * @param [options.idb] {IDBFactory}
 * @param [options.clearWriter] {boolean}
 * @returns {Promise<{ failed: string[], unverified: string[] }>}
 */
async function wipeClientResidue({
  clientDid,
  accountSpaceId,
  unlockSpaceId,
  idb,
  clearWriter = false
}: {
  clientDid: string
  accountSpaceId?: string
  unlockSpaceId: string
  idb?: IDBFactory
  clearWriter?: boolean
}): Promise<{ failed: string[]; unverified: string[] }> {
  const targets: WipeTargets = {
    clientDid,
    ...(accountSpaceId ? { accountSpaceId } : {}),
    unlockSpaceIds: [unlockSpaceId],
    registryUnread: false,
    cacheScopes: [
      ...(accountSpaceId ? [accountSpaceId] : []),
      `local:${clientDid}`
    ]
  }
  const { localStore } = await BrowserStore.initClient({
    user: { id: clientDid } as User
  })
  return executeLocalWipe({
    targets,
    storage: { wipeLocalStorage: () => localStore.wipeStorage() },
    idb,
    clearWriter
  })
}

/**
 * Recovers the Space id a did:webvh account id embeds
 * (`did:webvh:<scid>:<host>:space:<spaceId>:<collection>`, the host segment
 * percent-encoded so it carries no `:`); undefined when the id does not
 * follow that shape.
 *
 * @param did {string}
 * @returns {string | undefined}
 */
function spaceIdOfWebvhDid(did: string): string | undefined {
  const segments = did.split(':')
  return segments[0] === 'did' &&
    segments[1] === 'webvh' &&
    segments[4] === 'space'
    ? segments[5]
    : undefined
}

/**
 * The stale-record wipe: the login found a client-key record whose stamped
 * `pointerDid` names a DIFFERENT account than the unlock record points at --
 * the residue of a prior account under a reused passphrase, gone server-side,
 * so no wipe ever ran on this browser. Every target derives from the record
 * itself (snapshot-first, before anything is deleted): the stale client's
 * did:key keys the replica database and the cache families, the record's
 * `pointerDid` keys the dead account's Space-to-DID mapping (its Space id
 * recovered from the did itself), and the unlock Space id keys the
 * credential's whole local state -- deleting that is what deletes the
 * record, so the wipe is also the record's deleter, and it clears the
 * keyring cache the fetch wrote moments earlier. Best-effort: the caller
 * re-routes on whatever this reports, and a record the wipe could not
 * delete surfaces on the next pass as the loud unusable-record refusal.
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}   a hit carrying `clientKeys`
 *   whose `pointerDid` mismatches the hit's pointer
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<{ failed: string[], unverified: string[] }>}
 */
export async function wipeStaleClientResidue({
  found,
  idb
}: {
  found: KeyringFetchResult
  idb?: IDBFactory
}): Promise<{ failed: string[]; unverified: string[] }> {
  const clientKeys = found.clientKeys!
  const { keyAgent } = await agentsFromSeed({ seed: clientKeys.clientSeed })
  const accountDid = clientKeys.pointerDid
  const accountSpaceId = accountDid ? spaceIdOfWebvhDid(accountDid) : undefined
  return wipeClientResidue({
    clientDid: keyAgent.id,
    ...(accountSpaceId ? { accountSpaceId } : {}),
    unlockSpaceId: found.unlockSpaceId,
    idb
  })
}

/**
 * The IndexedDB database-name shapes a wallet replica can carry: the current
 * `-wallet-db` and the legacy `-credentials-db` / `-sync-db`, each embedded
 * in the storage adapter's own naming.
 */
const REPLICA_DB_NAME_PATTERN = /-(?:wallet|credentials|sync)-db/

/**
 * Whether this browser holds any forgettable wallet data at all: a replica
 * database, the session database, or any per-account localStorage family.
 * The never-remembered login surface renders "nothing to delete" on false.
 *
 * A browser that has IndexedDB but no `indexedDB.databases()` cannot be
 * asked what it holds, and an unanswerable question is not a "no": the
 * localStorage evidence is consulted first, and failing that the answer is
 * still true, since the storage that could not be enumerated may well hold
 * a replica or the session database. The cost of the conservative answer is
 * a destructive confirm on a browser that turns out to hold nothing (the
 * wipe then reports the deletion as unconfirmed); the cost of the other
 * answer would be telling a user their data is already gone when it is not.
 *
 * @returns {Promise<boolean>}
 */
export async function hasForgettableBrowserData(): Promise<boolean> {
  const haveIndexedDb = typeof indexedDB !== 'undefined'
  const canEnumerate =
    haveIndexedDb && typeof indexedDB.databases === 'function'
  if (canEnumerate) {
    const databases = await indexedDB.databases().catch(() => [])
    if (
      databases.some(
        db =>
          db.name === SESSION_DB_NAME ||
          (db.name !== undefined && REPLICA_DB_NAME_PATTERN.test(db.name))
      )
    ) {
      return true
    }
  }
  if (typeof localStorage !== 'undefined') {
    for (let index = 0; index < localStorage.length; index++) {
      const key = localStorage.key(index)
      if (key?.startsWith('freewallet:')) {
        return true
      }
    }
  }
  return haveIndexedDb && !canEnumerate
}

/**
 * The no-unlock-material forget grade: "forget all wallet data on this
 * browser". Whole-database and browser-scoped -- the `freewallet-session`
 * database and every replica database it can name are deleted wholesale
 * (each replica prefix gets the cross-tab teardown and, where the engine
 * allows it, the verified completion of the shared replica wipe), every
 * per-account localStorage family goes by prefix scan, and the
 * browser-global `writerId` is cleared. Global UI prefs stay.
 * No ceremony runs and nothing is signed or flagged anywhere: each
 * account's standing document client remains, stated in the calling
 * surface's copy.
 *
 * Enumeration (`indexedDB.databases()`) is a discovery and verification
 * aid, never the gate on deleting: the session database has a known name,
 * and replica prefixes that no enumeration reports are recovered from
 * localStorage (see `derivableReplicaPrefixes`). Without the API the
 * deletes still run, and what could not be confirmed -- or, for replicas,
 * what could not even be discovered -- is reported on `unverified` rather
 * than passed off as a clean wipe.
 *
 * @returns {Promise<{ failed: string[], unverified: string[] }>}   the
 *   stage names that failed and the ones that ran unconfirmed (best-effort
 *   throughout, like the shared enumeration's executor)
 */
export async function forgetBrowserWalletData(): Promise<{
  failed: string[]
  unverified: string[]
}> {
  const failed: string[] = []
  const unverified: string[] = []
  const haveIndexedDb = typeof indexedDB !== 'undefined'
  const canEnumerate =
    haveIndexedDb && typeof indexedDB.databases === 'function'

  // Every replica database, by discovered prefix: a name like
  // `rxdb-dexie-<prefix>-wallet-db--...` yields its logical prefix, and the
  // per-prefix wipe carries the teardown broadcast and the verified
  // completion. The localStorage half of the discovery runs BEFORE the
  // families below are deleted -- it reads the very keys they remove.
  const prefixes = derivableReplicaPrefixes()
  if (canEnumerate) {
    const databases = await indexedDB.databases().catch(() => [])
    for (const db of databases) {
      const name = db.name
      if (!name || !REPLICA_DB_NAME_PATTERN.test(name)) {
        continue
      }
      let prefix = name.split(REPLICA_DB_NAME_PATTERN)[0]!
      if (prefix.startsWith('rxdb-dexie-')) {
        prefix = prefix.slice('rxdb-dexie-'.length)
      }
      if (prefix) {
        prefixes.add(prefix)
      }
    }
  } else if (haveIndexedDb) {
    // A replica whose prefix left no localStorage trace cannot be named at
    // all here; say so rather than let the report read as exhaustive.
    unverified.push('replica-discovery')
  }
  if (haveIndexedDb) {
    for (const prefix of prefixes) {
      try {
        const store = new BrowserStore({ dbPrefix: prefix })
        const { verified } = await store.wipeStorage()
        if (!verified) {
          unverified.push(`replica:${prefix}`)
        }
      } catch (err) {
        failed.push(`replica:${prefix}`)
        log.warn('Could not delete the replica databases', { prefix, err })
      }
    }

    // The session database, wholesale (every account's unlock-local state
    // and caches live inside it) and by its known name, so it goes whatever
    // the engine can enumerate.
    try {
      await new Promise<void>(resolve => {
        const request = indexedDB.deleteDatabase(SESSION_DB_NAME)
        request.onsuccess = () => resolve()
        request.onerror = () => resolve()
        // A sibling tab holding the database open queues the delete; give it
        // a moment, then let the verification below report honestly.
        setTimeout(resolve, 10_000)
      })
      if (canEnumerate) {
        const remaining = await indexedDB.databases().catch(() => [])
        if (remaining.some(db => db.name === SESSION_DB_NAME)) {
          failed.push('session-db')
        }
      } else {
        unverified.push('session-db')
      }
    } catch (err) {
      failed.push('session-db')
      log.warn('Could not delete the session database', { err })
    }
  }

  // The per-account localStorage families, wholesale by prefix scan; the
  // marker prefixes come from the shared key builders with an empty scope.
  try {
    if (typeof localStorage !== 'undefined') {
      const emptyMarkers = migrationMarkerKeys('')
      const markerPrefixes = [emptyMarkers.plaintext, emptyMarkers.publicCids]
      const keys: string[] = []
      for (let index = 0; index < localStorage.length; index++) {
        const key = localStorage.key(index)
        if (key && markerPrefixes.some(prefix => key.startsWith(prefix))) {
          keys.push(key)
        }
      }
      keys.forEach(key => localStorage.removeItem(key))
    }
    deleteAllLocalCacheFamilies()
  } catch (err) {
    failed.push('cache-families')
    log.warn('Could not delete the localStorage families', { err })
  }
  try {
    clearWriterId()
  } catch (err) {
    failed.push('writer-id')
    log.warn('Could not clear the writer id', { err })
  }
  return { failed, unverified }
}

/**
 * The replica database prefixes this browser can name without enumerating
 * IndexedDB, recovered from the localStorage traces a replica leaves: the
 * per-`dbPrefix` migration markers
 * (`freewallet:<name>-migrated:<dbPrefix>`, written the first time a
 * replica's collections open) carry the prefix verbatim, and a local-mode
 * descriptor or meta cache key (`<family>:local:<clientDid>:<collectionId>`)
 * carries the client did:key the prefix is derived from. Nothing else on
 * this browser names a replica: the remote-mode cache scope is an account
 * Space id, and the unlock-methods cache lives inside the session database.
 * Must be called before the localStorage families are deleted.
 *
 * @returns {Set<string>}
 */
function derivableReplicaPrefixes(): Set<string> {
  const prefixes = new Set<string>()
  if (typeof localStorage === 'undefined') {
    return prefixes
  }
  const emptyMarkers = migrationMarkerKeys('')
  const markerPrefixes = [emptyMarkers.plaintext, emptyMarkers.publicCids]
  const localScopePrefixes = LOCAL_CACHE_FAMILY_PREFIXES.map(
    prefix => `${prefix}:local:`
  )
  for (let index = 0; index < localStorage.length; index++) {
    const key = localStorage.key(index)
    if (!key) {
      continue
    }
    for (const marker of markerPrefixes) {
      if (key.startsWith(marker)) {
        const prefix = key.slice(marker.length)
        if (prefix) {
          prefixes.add(prefix)
        }
      }
    }
    for (const scoped of localScopePrefixes) {
      if (!key.startsWith(scoped)) {
        continue
      }
      // `<clientDid>:<collectionId>`; a collection id carries no colon, so
      // the last one separates the two.
      const rest = key.slice(scoped.length)
      const clientDid = rest.slice(0, rest.lastIndexOf(':'))
      if (clientDid.startsWith('did:')) {
        prefixes.add(deriveSpaceId(clientDid))
      }
    }
  }
  return prefixes
}

/**
 * Refuses the last-client transition on a pending-shaped passphrase entry
 * ({@link PendingRetirementForgetError}): the unlock record served at the
 * entry's `unlockSpaceId` is sealed to a credential other than the one the
 * entry's identity members name (wallet-core's `unlockRecordSealedTo`), the
 * residue of a passphrase change torn before its retirement landed.
 *
 * The record IS the detector, deliberately, rather than the session-derived
 * comparison the torn-retirement repair opens with: that comparison needs
 * the repair's direction guard (an entry naming another credential is also
 * what an OLD passphrase sees, logging in after a change that completed
 * elsewhere, on a perfectly healthy account), and the record settles the
 * question outright for a passkey login too.
 *
 * An entry carrying no management zcap or no unlock key-agreement multibase
 * is unsettleable either way and passes: it is a bare entry, not a pending
 * one. A record that cannot be read, parsed, or read for its recipients
 * refuses too, with the registry-read refusal's reasoning -- the transition
 * must not run over an entry it could not settle.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.pointer {AccountPointer}
 * @param options.registry {UnlockMethodsRecord | null}
 * @returns {Promise<void>}
 */
async function assertNoPendingPassphraseEntry({
  session,
  pointer,
  registry
}: {
  session: Session
  pointer: Parameters<typeof delegateLogWrite>[0]['pointer']
  registry: { methods?: unknown[] } | null
}): Promise<void> {
  const entries = (
    (registry?.methods ?? []) as PassphraseUnlockMethod[]
  ).filter(method => method.type === 'passphrase')
  for (const entry of entries) {
    if (!entry.manageCapability || !entry.unlockKeyAgreementKeyMultibase) {
      continue
    }
    let sealedToEntry: boolean
    try {
      const record = await getUnlockKeyringWithCapability({
        storageServerUrl: WAS_SERVER_URL ?? pointer.host,
        zcapClient: managementZcapClient({
          session,
          capability: entry.manageCapability
        }),
        spaceId: entry.unlockSpaceId,
        capability: entry.manageCapability
      })
      // Inside the same try: a malformed frame or a degenerate descriptor
      // is a record this ceremony could not settle, not a pending entry and
      // not a generic ceremony failure.
      sealedToEntry = unlockRecordSealedTo({
        record,
        keyAgreementKeyMultibase: entry.unlockKeyAgreementKeyMultibase
      })
    } catch (err) {
      throw new Error(
        'Could not read the sign-in record the unlock-methods registry ' +
          'names, which the last-client forget must settle before it runs; ' +
          'try again.',
        { cause: err }
      )
    }
    if (!sealedToEntry) {
      throw new PendingRetirementForgetError()
    }
  }
}

/**
 * Refuses the last-client transition when the unlock-methods registry does
 * not cover every standing credential the account document publishes
 * ({@link UnrecordedCredentialForgetError}).
 *
 * A credential's `keyAgreement` entry is the document's whole record of it.
 * Every walk from here on is registry-driven: the other methods' record
 * re-mint, the removal entry's latent-hash vouching, and the recovery health
 * sweep all read the registry, so a credential no entry names keeps a bridge
 * delegation the removal entry rots and gets no replacement -- and on the
 * client-less account this ceremony produces, no remembered login will run
 * the repairs that would notice.
 *
 * The credential entries are the `keyAgreement` methods that carry no client
 * controller marker: an enrolled client's method is published under
 * `controller: did:key:<its signing multibase>`, so filtering by the markers
 * the document's `capabilityInvocation` relation implies leaves exactly the
 * unlock credentials' entries (a ladder VM holds no key-agreement relation,
 * and the KMS convenience key is published under `authentication` alone).
 * Coverage is computed per registry entry from its recorded key-agreement
 * multibase, in BOTH published forms -- the verbatim id a passkey or
 * recovery code publishes under, and the commitment id a passphrase
 * publishes under -- since either form covers the entry it belongs to.
 *
 * A registry that read as absent covers nothing, so a document publishing
 * any credential entry refuses here.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.pointer {AccountPointer}
 * @param options.registry {UnlockMethodsRecord | null}
 * @returns {Promise<void>}
 */
async function assertRegistryCoversStandingCredentials({
  session,
  pointer,
  registry
}: {
  session: Session
  pointer: { did: string; spaceId: string; host: string }
  registry: { methods?: unknown[] } | null
}): Promise<void> {
  const { doc } = await verifiedAccountLog({
    profile: session.profile,
    pointer
  })
  const credentialVmIds = credentialKeyAgreementVmIds({
    doc,
    did: pointer.did
  })
  if (credentialVmIds.length === 0) {
    return
  }
  const covered = new Set<string>()
  const multibases = ((registry?.methods ?? []) as UnlockMethod[]).flatMap(
    method =>
      typeof method?.keyAgreementKeyMultibase === 'string'
        ? [method.keyAgreementKeyMultibase]
        : []
  )
  for (const keyAgreementKeyMultibase of multibases) {
    covered.add(
      unlockKeyVmId({
        did: pointer.did,
        keyAgreement: { publicKeyMultibase: keyAgreementKeyMultibase }
      })
    )
    covered.add(
      unlockKeyVmId({
        did: pointer.did,
        keyAgreement: {
          commitment: await keyAgreementCommitment({ keyAgreementKeyMultibase })
        }
      })
    )
  }
  const unrecorded = credentialVmIds.filter(vmId => !covered.has(vmId))
  if (unrecorded.length > 0) {
    log.warn(
      'The last-client forget refused: the unlock-methods registry does not name these credential key-agreement methods',
      { unrecorded }
    )
    throw new UnrecordedCredentialForgetError({
      unrecorded: unrecorded.length
    })
  }
}

/**
 * The verification-method ids of the standing credentials' `keyAgreement`
 * entries in a verified account document: every resolved key-agreement
 * method whose `controller` is not an enrolled client's marker (the did:key
 * of a signing key the document lists under `capabilityInvocation`). A
 * method carrying no id of its own is named by the id its published key
 * material implies, the form {@link unlockKeyVmId} builds.
 *
 * @param options {object}
 * @param options.doc {object}   the verified account document
 * @param options.did {string}   the account's did:webvh
 * @returns {string[]}
 */
function credentialKeyAgreementVmIds({
  doc,
  did
}: {
  doc: object
  did: string
}): string[] {
  const invocation = (
    doc as { capabilityInvocation?: Array<string | { id?: string }> }
  ).capabilityInvocation
  const markers = new Set(
    relationIds(invocation).map(id =>
      clientKeyAgreementController({
        signingKeyMultibase: id.slice(id.lastIndexOf('#') + 1)
      })
    )
  )
  const vmIds: string[] = []
  for (const method of resolvedKeyAgreementMethods({ doc })) {
    if (method.controller && markers.has(method.controller)) {
      continue
    }
    const fragment = method.publicKeyMultibase ?? method.publicKeyCommitment
    const vmId =
      method.id ??
      (fragment
        ? unlockKeyVmId({
            did,
            keyAgreement: method.publicKeyMultibase
              ? { publicKeyMultibase: method.publicKeyMultibase }
              : { commitment: method.publicKeyCommitment! }
          })
        : undefined)
    if (vmId) {
      vmIds.push(vmId)
    }
  }
  return [...new Set(vmIds)]
}
