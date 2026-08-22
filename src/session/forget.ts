/**
 * The forget affordance: removing this browser from a wallet account. Two
 * grades, split by whether the unlock credential is in hand:
 *
 * - **The forget ceremony** (`forgetThisBrowser`, run from a live durable
 *   session): wallet-core's `forgetDurableClient` -- the roster rotation off
 *   this client's wrap and the collection fan-out under this client's
 *   still-standing authority, then ONE atomic ladder-signed removal entry
 *   through the standing credential's bridge -- followed by the shared local
 *   wipe (the FW-199 enumeration, `clearWriter: true`). The wipe runs LAST,
 *   so a tear anywhere before the removal entry reads as "not forgotten" and
 *   a re-click resumes; the ceremony is convergent under a naive re-run.
 *
 * - **The last-client transition** (the same `forgetThisBrowser` entry with
 *   `lastClient: true`, confirmed against transition-stating copy): when
 *   this browser is the account's LAST enrolled durable client, wallet-core's
 *   `forgetLastDurableClient` runs instead -- the two-entry ceremony that
 *   lands the account client-less and ladder-anchored (the state a
 *   credential-anchored signup and a transient recovery produce): the ladder
 *   VM's install entry, the ladder-signed roster rotation anchored there and
 *   the fan-out under this client's still-standing authority, the forced
 *   ladder-signed generation-delegation replacement and the revocation of
 *   every ladder-signed delegation the annex history embedded, the login
 *   credential's record re-bind (bridge and sibling re-signed by the ladder
 *   VM through the hit's re-bind closure, the registry pair refreshed),
 *   then the removal entry. The ordinary ceremony's `LastDurableClientForgetError`
 *   (name-stable) is the routing signal when the caller's view was stale.
 *   The transition's own name-stable refusal, `RecordRemintFailedError`
 *   (another sign-in method's record could not be re-sealed, so the
 *   removal entry was withheld), propagates before the wipe: this browser
 *   is still connected, and a re-run resumes at the re-mint.
 *
 * - **The no-unlock-material grade** (`forgetBrowserWalletData`, run from
 *   the login page's refusal states): nothing can be derived or signed, so
 *   no ceremony runs -- the wipe is whole-database and browser-scoped
 *   ("forget all wallet data on this browser"): the `freewallet-session`
 *   database and every replica database are deleted wholesale, with the
 *   cross-account blast radius stated in the calling surface's copy (other
 *   remembered accounts lose their continuity pins; none is lost -- a
 *   standing credential self-enrolls at the next login). The standing
 *   document client gets NO flag anywhere: with no unlock material nothing
 *   can be signed, and the honest residue is stated in the copy, pointing at
 *   the Connected wallets disconnect from a logged-in client.
 *
 * The login-time detector (`assertClientStillEnrolled`) maps the
 * removal-published-but-wipe-torn state -- a local client-key record present
 * while this client's verification method is gone from the verified account
 * document (a forget torn before its wipe, or a disconnect run from another
 * client) -- to finish-the-wipe plus a typed `BrowserForgottenError`, never
 * raw authorization errors. Nothing about the detection is persisted; it is
 * recomputed from durable state at each login.
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
  forgetDurableClient,
  forgetLastDurableClient,
  ladderVmAgent,
  ladderVmZcapClient,
  mintDelegatedClientsDelegation
} from '@interop/wallet-core/clientAnnex'
import type {
  DurableClientForgetResult,
  LastDurableClientForgetResult
} from '@interop/wallet-core/clientAnnex'
import { agentsFromSeed } from '@interop/wallet-core/identity'
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
  clientSigningKeyMultibase,
  isWebvhDid,
  updateKeyMultibase,
  verifyAccountLog
} from '@interop/wallet-core/webvh'
import type { RevokedClientKeys } from '@interop/wallet-core/webvh'
import type { Session, User } from '@/types/auth'
import type { VerifiedAccountLog } from '@interop/wallet-core/clients'
import { SESSION_DB_NAME, sessionLogPinStore } from '@/lib/sessionKey'
import { clearWriterId } from '@/lib/writerId'
import { BrowserStore, migrationMarkerKeys } from '@/stores/browserStore'
import {
  assertAccountCeremonyAllowed,
  deleteAllLocalCacheFamilies
} from '@/session/persistence'
import { requireEnrolledClientContext } from '@/session/enrolledContext'
import type { KeyringFetchResult } from '@/session/keyring'
import { recoveryEntriesOf } from '@/session/recovery'
import { sessionRosterStore } from '@/session/rosterStore'
import { unlockLogStore } from '@/session/standingUnlock'
import {
  getUnlockMethods,
  refreshStandingDelegationFields
} from '@/session/unlockMethods'
import { pointedClientAnnexReach } from '@/session/annexReach'
import { adoptRotatedUserKey } from '@/session/userKeyAdoption'
import { cascadeCollections } from '@/session/userKeyCascade'
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
  constructor({ wipeFailed }: { wipeFailed: string[] }) {
    super(
      "This browser's wallet access was removed from the account; its " +
        'local wallet data has been cleared.'
    )
    this.name = 'BrowserForgottenError'
    this.wipeFailed = wipeFailed
  }
}

/**
 * What a completed forget reports: which ceremony ran (`lastClient: false`
 * is the ordinary forget, `true` the last-client transition) with that
 * ceremony's own result, plus the local wipe's failed-stage names (empty on
 * a clean wipe).
 */
type ForgetCeremonyOutcome =
  | { lastClient: false; ceremony: DurableClientForgetResult }
  | { lastClient: true; ceremony: LastDurableClientForgetResult }
export type ForgetOutcome = ForgetCeremonyOutcome & { wipeFailed: string[] }

/**
 * Runs the forget for this browser, from a live durable session: snapshot
 * the wipe targets first, then the ceremony, then the shared local wipe with
 * `clearWriter: true`. The caller logs the session out once this resolves;
 * there is no audit record, because this client's invocations die with the
 * removal entry and the world-readable log entry IS the audit.
 *
 * Which ceremony runs is the caller's `lastClient` choice, because the two
 * carry different consequences the user confirms against: `false` is
 * wallet-core's `forgetDurableClient` (rotation, fan-out, removal entry --
 * the self-forget inversion), and `true` is `forgetLastDurableClient` (the
 * two-entry transition to the client-less, ladder-anchored account; see the
 * module doc). A `false` run that turns out to be the last client -- the
 * caller's listing was stale -- refuses with wallet-core's name-stable
 * `LastDurableClientForgetError` before any write, so the caller can
 * re-confirm against the transition copy; a `true` run on an account with
 * another durable client refuses from the ceremony's pre-install read, and
 * one that could not re-seal another sign-in method's record refuses with
 * the name-stable `RecordRemintFailedError` before its removal entry (the
 * local wipe never runs on a refusal, so the browser stays connected and
 * the next run resumes).
 *
 * Refusals before anything runs: a transient session (`StepUpRequiredError`
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

  // One registry read serves the removal entry's latent-hash vouching AND
  // the wipe snapshot's unlock-Space enumeration; best-effort, like the
  // revocation cascade's.
  const { epochPins } = session.profile.persistence
  const [registry, pinnedEpochId] = await Promise.all([
    getUnlockMethods({ session }).catch((err: unknown) => {
      console.warn(
        'Could not read the unlock-methods registry for the forget ' +
          'ceremony:',
        err
      )
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

  // The annex Space id, for the wipe's pin-slot enumeration. Best-effort.
  let clientAnnexSpaceId: string | undefined
  try {
    const reach = await pointedClientAnnexReach({ session, pointer })
    if (reach) {
      clientAnnexSpaceId = reach.spaceId
    }
  } catch (err) {
    console.warn(
      'Could not resolve the annex Space id for the forget wipe:',
      err
    )
  }

  // Snapshot-first: every wipe target derives from the live session BEFORE
  // the ceremony ends this client's authority (and before anything deletes).
  const targets = snapshotWipeTargets({
    session,
    registry,
    ...(clientAnnexSpaceId ? { clientAnnexSpaceId } : {})
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
    }) => {
      // Persisted so a run torn before the removal entry leaves this browser
      // consistent for the resuming re-click: the pin never advances without
      // the key that authenticated the roster it advanced to.
      await epochPins.saveFromDescriptor({
        accountDid: pointer.did,
        epochId: latestEpochId,
        descriptor
      })
      await session.profile.persistClientKeys?.({ userKey })
      // The unlock-methods registry is sealed to the vault keys, so it is
      // re-sealed to the rotated key (and the live session swapped onto it,
      // so the later registry writes below read under the current key) while
      // this client still invokes; the surviving readers -- other durable
      // clients, transient logins -- would otherwise find it sealed to a
      // retired generation.
      await adoptRotatedUserKey({
        session,
        spaceId: pointer.spaceId,
        userKey
      })
    },
    collections: cascadeCollections({ remoteStore })
  }

  // The ceremony opens with reads and ends with a document edit; no session
  // surface may keep serving a pre-edit view.
  invalidateVerifiedLog({ profile: session.profile })
  let outcome: ForgetCeremonyOutcome
  try {
    if (!lastClient) {
      const ceremony = await forgetDurableClient({
        ...shared,
        rosterStore: sessionRosterStore({ profile: session.profile })
      })
      outcome = { lastClient: false, ceremony }
    } else {
      const ceremony = await forgetLastDurableClient({
        ...shared,
        rosterStoreFor: await ladderSignedRosterStoreFor({
          session,
          pointer,
          ladderSeed
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

  // The local wipe runs strictly last -- it is what makes a torn run read as
  // "not forgotten" -- and clears the browser-global writerId (the forget
  // grade's one writerId consumer).
  const { failed } = await executeLocalWipe({
    targets,
    storage: session.storage ?? undefined,
    idb,
    clearWriter: true
  })
  return { ...outcome, wipeFailed: failed }
}

/**
 * The last-client transition's roster store builder: appends SIGNED BY THE
 * LADDER VM (the key the post-removal document still lists, so the roster
 * head needs no seal completer on an account where no enrolled client's
 * login sweep will ever run again), the controller view resolved from the
 * post-install log the ceremony supplies (the ceremony-tail license's
 * posture-changing anchor), and the HTTP requests invoked under this
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
 * The login-time finish-the-wipe detector: called on the durable login path
 * when the keyring hit carries this browser's client keys and the pointer
 * names a did:webvh. A cleanly verified account document that no longer
 * lists this client's verification method means the removal entry landed
 * (a forget torn before its wipe, or a disconnect from another client), so
 * the local residue is wiped -- targets derived from the hit alone, since
 * the registry is unreachable without account authority -- and the typed
 * `BrowserForgottenError` surfaces the state. Every verification failure
 * (network, a missing log, a continuity refusal) skips detection and lets
 * the ordinary login proceed to its own handling: only a VERIFIED document
 * may trigger a wipe.
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
      pinStore: sessionLogPinStore({ idb })
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
  // The removal entry landed; finish the wipe from what the hit alone can
  // derive (this credential's trio, this client's replica and cache
  // families, the account's pins).
  const targets: WipeTargets = {
    clientDid,
    accountDid: pointer.did,
    accountSpaceId: pointer.spaceId,
    unlockSpaceIds: [found.unlockSpaceId],
    cacheScopes: [pointer.spaceId, `local:${clientDid}`]
  }
  const { localStore } = await BrowserStore.initClient({
    user: { id: clientDid } as User
  })
  const { failed } = await executeLocalWipe({
    targets,
    storage: { wipeLocalStorage: () => localStore.wipeStorage() },
    idb,
    clearWriter: true
  })
  throw new BrowserForgottenError({ wipeFailed: failed })
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
 * @returns {Promise<boolean>}
 */
export async function hasForgettableBrowserData(): Promise<boolean> {
  if (typeof indexedDB !== 'undefined' && indexedDB.databases) {
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
  return false
}

/**
 * The no-unlock-material forget grade: "forget all wallet data on this
 * browser". Whole-database and browser-scoped -- the `freewallet-session`
 * database and every replica database are deleted wholesale (each replica
 * prefix gets the cross-tab teardown and verified completion of the shared
 * replica wipe), every per-account localStorage family goes by prefix scan,
 * and the browser-global `writerId` is cleared. Global UI prefs stay.
 * No ceremony runs and nothing is signed or flagged anywhere: each
 * account's standing document client remains, stated in the calling
 * surface's copy.
 *
 * @returns {Promise<{ failed: string[] }>}   the stage names that failed
 *   (best-effort throughout, like the shared enumeration's executor)
 */
export async function forgetBrowserWalletData(): Promise<{
  failed: string[]
}> {
  const failed: string[] = []

  // Every replica database, by discovered prefix: a name like
  // `rxdb-dexie-<prefix>-wallet-db--...` yields its logical prefix, and the
  // per-prefix wipe carries the teardown broadcast and the verified
  // completion.
  if (typeof indexedDB !== 'undefined' && indexedDB.databases) {
    const databases = await indexedDB.databases().catch(() => [])
    const prefixes = new Set<string>()
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
    for (const prefix of prefixes) {
      try {
        const store = new BrowserStore({ dbPrefix: prefix })
        await store.wipeStorage()
      } catch (err) {
        failed.push(`replica:${prefix}`)
        console.warn(`Could not delete the replica databases "${prefix}":`, err)
      }
    }

    // The session database, wholesale (every account's trios, pins, and
    // caches live inside it).
    try {
      await new Promise<void>(resolve => {
        const request = indexedDB.deleteDatabase(SESSION_DB_NAME)
        request.onsuccess = () => resolve()
        request.onerror = () => resolve()
        // A sibling tab holding the database open queues the delete; give it
        // a moment, then let the verification below report honestly.
        setTimeout(resolve, 10_000)
      })
      const remaining = await indexedDB.databases().catch(() => [])
      if (remaining.some(db => db.name === SESSION_DB_NAME)) {
        failed.push('session-db')
      }
    } catch (err) {
      failed.push('session-db')
      console.warn('Could not delete the session database:', err)
    }
  }

  // The per-account localStorage families, wholesale by prefix scan; the
  // marker prefixes come from the shared key builders with an empty scope.
  try {
    if (typeof localStorage !== 'undefined') {
      const emptyMarkers = migrationMarkerKeys('')
      const prefixes = [emptyMarkers.plaintext, emptyMarkers.publicCids]
      const keys: string[] = []
      for (let index = 0; index < localStorage.length; index++) {
        const key = localStorage.key(index)
        if (key && prefixes.some(prefix => key.startsWith(prefix))) {
          keys.push(key)
        }
      }
      keys.forEach(key => localStorage.removeItem(key))
    }
    deleteAllLocalCacheFamilies()
  } catch (err) {
    failed.push('cache-families')
    console.warn('Could not delete the localStorage families:', err)
  }
  try {
    clearWriterId()
  } catch (err) {
    failed.push('writer-id')
    console.warn('Could not clear the writer id:', err)
  }
  return { failed }
}
