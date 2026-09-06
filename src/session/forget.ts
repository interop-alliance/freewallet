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
 *   every ladder-signed delegation the annex history embedded, the login
 *   credential's record re-bind (bridge and sibling re-signed by the ladder
 *   VM through the hit's re-bind closure, the registry pair refreshed), then
 *   the removal entry. That re-bind is the only unlock record this ceremony
 *   writes: every OTHER credential's record is signed by its own
 *   credential's unlock identity and ladder VM, which this ceremony does not
 *   strike. The ordinary ceremony's `LastEnrolledClientForgetError`
 *   (name-stable) is the routing signal when the caller's view was stale.
 *   Before any of it runs, the transition refuses on a pending-shaped
 *   passphrase registry entry (`PendingRetirementForgetError`): a passphrase
 *   change torn before its retirement landed is mended only by the
 *   torn-retirement repair, which needs a remembered login -- the very thing
 *   this ceremony ends forever.
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
import { deriveNextKeyHash } from '@interop/did-method-webvh'
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
import {
  delegateLogWrite,
  delegationProofKeyId
} from '@interop/wallet-core/recovery'
import {
  clientSigningKeyMultibase,
  isWebvhDid,
  updateKeyMultibase,
  verifyAccountLog
} from '@interop/wallet-core/webvh'
import type { RevokedClientKeys } from '@interop/wallet-core/webvh'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import type { Session, User } from '@/types/auth'
import { deriveSpaceId } from '@interop/was-client/sync'
import type { VerifiedAccountLog } from '@interop/wallet-core/clients'
import { SESSION_DB_NAME } from '@/lib/sessionKey'
import { clearWriterId } from '@/lib/writerId'
import { BrowserStore } from '@/stores/browserStore'
import { syncController } from '@/stores/syncController'
import {
  assertBrowserLocalSession,
  deleteAllLocalCacheFamilies,
  LOCAL_CACHE_FAMILY_PREFIXES
} from '@/session/persistence'
import {
  requireEnrolledCeremonyContext,
  type LadderDeleter
} from '@/session/accountCeremonyContext'
import type { KeyringFetchResult } from '@/session/keyring'
import { recoveryEntriesOf } from '@/session/recovery'
import { findPendingPassphraseEntries } from '@/session/credentialCoverage'
import { sessionRosterStore } from '@/session/rosterStore'
import { unlockLogStore } from '@/session/standingUnlock'
import {
  getUnlockMethods,
  refreshStandingDelegationFields,
  unlockEntryReaderFor
} from '@/session/unlockMethods'
import { adoptRotatedUserKeyInBand } from '@/session/userKeyAdoption'
import { cascadeCollections } from '@/session/userKeyCascade'
import { createLogger } from '@/lib/log'
import { zcapExpires } from '@/lib/zcap'

const log = createLogger('fw:session:forget')
import { invalidateVerifiedLog } from '@/session/verifiedLog'
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
 * another enrolled client refuses from the ceremony's pre-install read.
 *
 * Refusals before anything runs: a pending-shaped passphrase registry entry
 * on the transition (`PendingRetirementForgetError`), a session that is
 * not browser-local (`BrowserLocalSessionRequiredError`: this ceremony's
 * subject is this browser) and a session whose login did not carry the
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
  assertBrowserLocalSession({
    persistence: session.profile.persistence,
    ceremony: 'Forgetting this browser'
  })
  // Wait out the login-time registry passes rather than racing their
  // read-modify-writes (the ceremony re-seals the registry and, on the
  // last-client transition, re-mints every entry); on a settled session
  // the chain resolved long ago.
  await session.registryReady
  const { remoteStore, pointer, clientWebvhKeys, keyAgent } =
    requireEnrolledCeremonyContext({
      session,
      action: 'Forgetting this browser'
    })
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
      zcapClient: standing.standingClient.agents.zcapClient,
      pinStore: session.profile.persistence.logPins
    }),
    ladderSeed,
    forgottenClient,
    forgottenKeyAgreementKeyMultibase: keyAgreementKeyMultibase,
    knownLatentHashes: await Promise.all(
      latentMultibases.map(multibase => deriveNextKeyHash(multibase))
    ),
    // Every read the ceremony makes (the pre-edit read the roster rotation's
    // recipient document comes from, and each ladder entry's own read) runs
    // under the chain-head pin the log stores carry, so a served truncated
    // prefix is refused before anything is built on it.
    expectedDid: pointer.did,
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
        // The post-removal did:web projection PUT, made immediately before
        // the removal entry under this still-standing client's root
        // authority: the removal entry itself publishes `did.jsonl` alone
        // (all the credential's bridge in `logStore` allows), so without
        // this the served `id/did.json` would keep publishing the forgotten
        // client's verification methods until a later writer's
        // `ensureDidWebProjection` caught it.
        clientLogStore: remoteStore.webvhIdStore(),
        rosterStore: sessionRosterStore({ profile: session.profile })
      })
      outcome = { lastClient: false, ceremony }
    } else {
      const ceremony = await forgetLastEnrolledClient({
        ...shared,
        // The ladder VM's strike-and-reinstall pair publishes under this
        // still-standing client's root authority: the credential's bridge in
        // `logStore` is signed by the VM the strike removes, so a
        // bridge-invoked reinstall would be refused under the
        // current-key-set rule.
        clientLogStore: remoteStore.webvhIdStore(),
        // Appends SIGNED BY THE LADDER VM: the key the post-removal document
        // still lists, so the roster head needs no seal repair on an account
        // where no enrolled client's login sweep will ever run again. The
        // ceremony anchors the store's controller view itself
        // (`setMinimumControllerVersion`); the requests invoke under this
        // still-standing client.
        rosterStore: sessionRosterStore({
          profile: session.profile,
          keyAgent: await ladderVmAgent({ ladderSeed })
        }),
        annex: annexCeremonyReach({ session, pointer }),
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

  // Quiesce first: stop background replication before the replica database
  // goes, so the controller's poll timer does not keep driving reSync()
  // against a closed handle (the order account deletion and logout keep).
  try {
    await syncController.stop()
  } catch (err) {
    log.warn('Could not stop background replication before the wipe', { err })
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
    }) =>
      clientAnnexLogStore({
        was,
        spaceId,
        generationId,
        pinStore: session.profile.persistence.logPins
      }),
    revoke: async (delegation: Parameters<WasClient['revoke']>[0]) =>
      was.revoke(delegation),
    wasServerUrl: pointer.host,
    accountSpaceId: pointer.spaceId
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
    delegationExpires: zcapExpires(delegation),
    ...(delegatedClients
      ? {
          delegatedClientsKeyId: delegationProofKeyId(delegatedClients),
          delegatedClientsExpires: zcapExpires(delegatedClients)
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
 * @param options.pinStore {ResourceLogPinStore}   the login's chain-head
 *   pins; this read establishes or checks the account log's slot, and the
 *   session built afterwards reads under the same store
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<VerifiedAccountLog | undefined>}
 */
export async function assertClientStillEnrolled({
  found,
  pinStore,
  idb
}: {
  found: KeyringFetchResult
  pinStore: ResourceLogPinStore
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
      pinStore
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
    accountDids: [],
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
 * The IndexedDB database-name shape a wallet replica carries, `-wallet-db`,
 * embedded in the storage adapter's own naming. The shared replica wipe
 * matches the same shape, so what this probe reports is what the wipe
 * removes.
 */
const REPLICA_DB_NAME_PATTERN = /-wallet-db/

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

  // The per-account localStorage families, wholesale by prefix scan.
  try {
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
 * IndexedDB, recovered from the one localStorage trace a replica leaves: a
 * local-mode descriptor or meta cache key
 * (`<family>:local:<clientDid>:<collectionId>`) carries the client did:key
 * the prefix is derived from. Nothing else on this browser names a replica:
 * the remote-mode cache scope is an account Space id, and the
 * unlock-methods cache lives inside the session database. Must be called
 * before the localStorage families are deleted.
 *
 * @returns {Set<string>}
 */
function derivableReplicaPrefixes(): Set<string> {
  const prefixes = new Set<string>()
  if (typeof localStorage === 'undefined') {
    return prefixes
  }
  const localScopePrefixes = LOCAL_CACHE_FAMILY_PREFIXES.map(
    prefix => `${prefix}:local:`
  )
  for (let index = 0; index < localStorage.length; index++) {
    const key = localStorage.key(index)
    if (!key) {
      continue
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
export async function assertNoPendingPassphraseEntry({
  session,
  pointer,
  registry,
  signer
}: {
  session: Session
  pointer: Parameters<typeof delegateLogWrite>[0]['pointer']
  registry: { methods?: unknown[] } | null
  signer?: LadderDeleter
}): Promise<void> {
  const pending = await findPendingPassphraseEntries({
    registry,
    host: pointer.host,
    readerFor: unlockEntryReaderFor({
      session,
      ...(signer ? { signer } : {})
    })
  })
  if (pending.length > 0) {
    throw new PendingRetirementForgetError()
  }
}
