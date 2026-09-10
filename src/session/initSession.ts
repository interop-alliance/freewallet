/**
 * Session bootstrap. Builds a did:key identity from this client's locally
 * minted 32-byte seed via CapabilityAgent, instantiates a ZcapClient for
 * signing storage requests, and initializes the StorageManager (local or
 * remote depending on env vars). The resulting Session object is stored in
 * authStore. A passphrase (or passkey) login resolves through the keyring:
 * the unlock identity locates the account (the encrypted account pointer) and
 * unwraps this client's local key set. On a fresh browser holding no key set,
 * the default (with a WAS server) is the TRANSIENT login -- the
 * public-terminal composition in `src/session/transientLogin.ts`, which
 * persists nothing locally. A STANDING credential -- one whose unlock record
 * carries the bridge delegation and update-key ladder seed -- self-enrolls
 * an ordinary enrolled client in place on the programmatic
 * `rememberBrowser: true` entry (loud log entries first, then the first
 * roster read through the credential's standing wrap); a plain pointer
 * record -- which only a no-WAS bind produces, since every WAS signup writes
 * the standing layout before the Space exists -- still surfaces the
 * not-enrolled state and the connect-another-wallet ceremony.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import type { DIDLog } from '@interop/did-method-webvh'
import { agentsFromSeed } from '@interop/was-client/identity'
import type { ControllerProfile, Session, User } from '@/types/auth'
import { KMS_SERVER_URL, PASSKEY_KDF, WAS_SERVER_URL } from '@/app.config'
import { ensureKeystore } from '@/lib/kms'
import { assertPasskeyPrf } from '@/lib/passkey'
import {
  isWebvhDid,
  webvhCapabilityAgent,
  webvhZcapClient,
  type ClientWebvhUpdateKeys,
  type ICapabilityAgent
} from '@interop/wallet-core/webvh'
import {
  mintUserKey,
  userKeyVaultKeys,
  type SealableEncryptionDescriptorStore,
  type UserKey,
  type UserKeyRosterReadResult
} from '@interop/wallet-core/keys'
import { accountRosterStore } from '@/session/rosterStore'
import { checkUserKeyRosterAtLogin as sharedCheckUserKeyRosterAtLogin } from '@interop/wallet-core/clients'
import {
  browserLocalSessionPersistence,
  isBrowserLocalSession,
  isRememberedSession,
  type BrowserLocalSessionPersistence,
  type SessionPersistence
} from '@/session/persistence'
import { StorageManager } from '@/stores/storageManager'
import {
  deriveUnlockCredential,
  fetchKeyring,
  fetchTransientKeyring,
  KeyringRecordUnusableError
} from '@/session/keyring'
import {
  mendCredentialAnchoredAccount,
  passphraseRegistryUpsertHook,
  reportCredentialAnchoredMend
} from '@/session/credentialAnchoredGenesis'
import { KEYRING_KDF, type UnlockKdf } from '@interop/wallet-core/keyring'
import {
  routeUnlockLogin,
  transientSessionFromKeyringHit
} from '@/session/transientLogin'
import {
  canSelfEnroll,
  selfEnrollStandingClient
} from '@/session/standingUnlock'
import {
  isPendingKeyringHit,
  PendingEnrollmentError,
  resumePendingEnrollment
} from '@/session/pendingEnrollment'
import type {
  RecoverySpendPrompt,
  RecoverySpendResumeReport
} from '@/session/recovery'
import {
  assertClientStillEnrolled,
  wipeStaleClientResidue
} from '@/session/forget'
import {
  mendReportAccumulator,
  type MendReportAccumulator
} from '@interop/wallet-core/menders'
import type { FreewalletCeremonyId } from '@/session/ceremonies'
import {
  blockCeremonyContext,
  startLoginMenderBlock
} from '@/session/menders/run'
import { primeVerifiedAccountLog } from '@/session/verifiedLog'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import type {
  KeyringFetchResult,
  PersistableClientKeys,
  UnlockCredential
} from '@/session/keyring'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:init')

/**
 * Internal control-flow signal, thrown by `sessionFromKeyringHit` when the
 * keyring hit carried an enrolled-shape client-key record whose stamped
 * `pointerDid` names a DIFFERENT account than the unlock record points at --
 * stale residue of a prior account under a reused passphrase (the prior
 * account gone server-side, so no wipe ever ran on this browser). The
 * record's residue, the record itself included, has already been wiped when
 * this throws (`wipeStaleClientResidue`); the login entry points catch it
 * and re-route once as a record-less browser (transient by default). It
 * stays module-internal and is not surfaced to the login page.
 */
class StaleClientKeyRecordError extends Error {
  constructor() {
    super('The client-key record is bound to a different account.')
    this.name = 'StaleClientKeyRecordError'
  }
}

/**
 * Creates a random guest session.
 */
export async function initGuestSession() {
  const randomGuestSecret = new Uint8Array(32)
  crypto.getRandomValues(randomGuestSecret)

  const guestEmail = 'guest@example.com'

  // The random 32 bytes are used directly as the client seed (no salted-hash
  // step). A guest identity is ephemeral and never keyring-bound.
  // Guest is a new-wallet flow: `provisionNewWallet` owns collection
  // provisioning (plus the initial history + welcome credential), so session
  // creation must not also fire it. The guest user key is minted fresh like the
  // rest of the guest identity and, being keyring-less, dies with the session.
  const { session } = await initSessionFromSeed({
    seed: randomGuestSecret,
    userKey: await mintUserKey(),
    email: guestEmail,
    isGuest: true,
    provisionStorage: false
  })

  return { session }
}

/**
 * Initializes a session (user, profile with zcap agents, storage manager) from
 * an already-obtained 32-byte client seed. This is the shared core behind the
 * keyring path (`loginWithPassphrase`, `SignupPage`) and the guest bootstrap:
 * everything downstream of "client seed in hand" -- KMS keystore provisioning,
 * storage clients -- is identical regardless of how the seed was obtained.
 *
 * For non-guest sessions the seed is carried on `profile.clientSeed` (so
 * Settings can re-bind unlock methods); guests skip it (a guest identity is
 * ephemeral and never keyring-bound).
 *
 * Collection provisioning is folded in here rather than left as a separate
 * post-login step at every callsite: when `provisionStorage` is set (the
 * default -- returning-login and CHAPI-popup flows) the session's
 * `ensureUserCollections` is *fired but not awaited* and its promise exposed as
 * `session.storageReady`, so a caller can run a hot read concurrently with
 * provisioning yet still `await session.storageReady` when it needs the
 * collections ready. Provisioning is also the login-time mender block's
 * seed, and the block is the caller's to start: this seam returns the
 * login's roster read and the store it came through, which the block's
 * cascade-completion sweep runs on. The new-wallet flows (signup, guest)
 * pass `provisionStorage: false`: their provisioning is a deliberately ordered
 * sequence owned by `provisionNewWallet` (signup must bind the passphrase
 * before the data Space is created), so session creation must not fire it.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   this client's 32-byte seed
 * @param [options.userKey] {UserKey}   the per-user key -- recovered from the local
 *   client-key record on login, or freshly minted by a provisioning flow.
 *   When present, its KAK (not the seed-derived vault KAK) becomes the
 *   profile's key-agreement key, i.e. recipient zero of every encrypted
 *   collection. Absent only on legacy accounts provisioned before the user key,
 *   which keep the seed-derived KAK until re-provisioned.
 * @param [options.webvhUpdateKeys] {ClientWebvhUpdateKeys}   this client's
 *   did:webvh update-key seeds (from the client-key record, or freshly minted
 *   by a provisioning flow), stamped on the profile for log maintenance
 * @param [options.persistClientKeys] {function}   re-wraps the client-key
 *   record with changed members (rotated user key, rolled update-key seeds)
 *   without the unlock secret; stamped on the profile
 * @param [options.accountPointer] {AccountPointer}   the account pointer this
 *   client holds as local state, stamped on the profile. A pointer naming a
 *   did:webvh marks the account promoted: the session signs data-Space
 *   requests with the `<did:webvh>#<multibase>` keyId from the start
 * @param [options.email] {string}
 * @param [options.isGuest] {boolean}
 * @param [options.popup] {boolean}   this session is a CHAPI popup visit, in
 *   the third-party partitioned iframe. Two consequences, both of the
 *   partitioning: credential + history operations route straight to the
 *   remote WAS collections (the local replica there is a bucket no sync
 *   controller ever drives), and the browser-local variant's localStorage
 *   cache families are suppressed for the visit on a WAS deployment (the
 *   Storage Access handle unpartitions IndexedDB and does not reach
 *   localStorage, so a persisted cache would be partitioned residue no
 *   top-level wipe can reach -- see the shared wipe enumeration's stated
 *   limits; the local-mode carve-out is at the call below). Default false
 * @param [options.provisionStorage] {boolean}   fire `ensureUserCollections`
 *   from session creation and expose it as `session.storageReady`; default
 *   true. Set false for the new-wallet flows that provision explicitly.
 * @param [options.idb] {IDBFactory}   first-party IndexedDB for the
 *   `freewallet-session` database (CHAPI popups thread the Storage Access
 *   API handle here)
 * @param [options.accountLog] {DIDLog}   the account log this login already
 *   verified for the same pointer (the forgotten-browser detector's read),
 *   handed to the login-time roster read in place of a second fetch and
 *   verification of the same `did.jsonl`
 * @param [options.mends] {MendReportAccumulator}   the login's report
 *   accumulator, which the routing entries have already reported into. The
 *   session's `mends` resolves from it; a caller supplying none gets a
 *   settled empty report
 * @param [options.persistence] {SessionPersistence}   the typed persistence
 *   strategy for this session; defaults to the browser-local variant built
 *   over `idb` (with cache persistence off for guests). A transient login
 *   supplies the in-memory variant here, which carries the client-annex
 *   identity: the annex DID whose generation holds this visit's
 *   verification method (every WAS request signs as `<clientAnnexDid>#<vm>`
 *   in place of the account-document form) and the generation delegation
 *   every request rides (stamped as `profile.invocationCapability`). The
 *   in-memory variant also skips the KMS keystore, the login-time roster
 *   read (the standing-wrap read already happened), `profile.clientSeed`,
 *   provisioning and the login-time sweeps.
 * @returns {Promise<object>}   the session, whether the account exists, and
 *   this login's verified roster read with the store it came through --
 *   what the caller's cascade-completion sweep and registry re-seal repair
 *   run on
 */
export async function initSessionFromSeed({
  seed,
  userKey,
  webvhUpdateKeys,
  persistClientKeys,
  accountPointer,
  email,
  isGuest = false,
  popup = false,
  provisionStorage = true,
  idb,
  accountLog,
  mends: accumulator,
  persistence: suppliedPersistence
}: {
  seed: Uint8Array
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  persistClientKeys?: (changes: PersistableClientKeys) => Promise<void>
  accountPointer?: AccountPointer
  email?: string
  isGuest?: boolean
  popup?: boolean
  provisionStorage?: boolean
  idb?: IDBFactory
  accountLog?: DIDLog
  mends?: MendReportAccumulator<FreewalletCeremonyId>
  persistence?: SessionPersistence
}) {
  // A popup's localStorage cache pair is suppressed -- but only where the
  // pair is genuinely a CACHE. With a WAS server the descriptors are served
  // and the local copy is the offline fallback, so dropping it costs the
  // popup nothing and spares the partitioned bucket residue no top-level
  // wipe can reach (the Storage Access handle unpartitions IndexedDB, never
  // localStorage). With no WAS server the same store is the only record of
  // the locally minted key epochs, so dropping it would mint fresh ones and
  // orphan everything already encrypted.
  const suppressPopupCaches = popup && !!WAS_SERVER_URL
  const persistence =
    suppliedPersistence ??
    browserLocalSessionPersistence({
      idb,
      persistCaches: !isGuest && !suppressPopupCaches
    })
  const { keyAgent, zcapClient, keyAgreementKey, keyResolver } =
    await agentsFromSeed({ seed })

  // Once the account pointer names a did:webvh, the Space controller has
  // been promoted: every data-Space request must be signed with this
  // client's verification method in the did:webvh document
  // (`<did:webvh>#<multibase>`), not its did:key. Same key, promoted keyId.
  // An in-memory strategy's verification method lives in the annex
  // generation's document instead (the strategy carries the annex DID), so
  // its requests sign as `<clientAnnexDid>#<multibase>` and ride the
  // generation delegation -- the account-document form is structurally
  // out of a transient session's reach.
  const accountDid = accountPointer?.did
  const sessionZcapClient = !isBrowserLocalSession(persistence)
    ? webvhZcapClient({ keyAgent, did: persistence.clientAnnex.clientAnnexDid })
    : isWebvhDid(accountDid)
      ? webvhZcapClient({ keyAgent, did: accountDid })
      : zcapClient

  // Ensure a KMS keystore exists for this controller (list-by-controller,
  // create on first login) and bind a KeystoreAgent to it. Guests skip the
  // KMS entirely, as they skip WAS. This provisioning round trip is started
  // here and awaited at the `Promise.all` below, so it runs concurrently with
  // the roster read and with storage init -- nothing in either depends on the
  // keystore, so the independent trips need not be serialized.
  // Failure is non-fatal for now: no wallet feature depends on
  // the keystore yet, so a KMS outage must not lock users out -- the settings
  // page surfaces the unprovisioned state. Gated on `isRememberedSession`:
  // a guest and a transient visit both skip the KMS whole, since keystore
  // provisioning is account bootstrap rather than per-visit state.
  const keystorePromise =
    isRememberedSession({ persistence, isGuest }) && KMS_SERVER_URL
      ? ensureKeystore({
          kmsServerUrl: KMS_SERVER_URL,
          keyAgent,
          // Once promoted, the keystore is looked up under (and invoked as)
          // the account's did:webvh; before promotion, the did:key defaults
          // apply.
          zcapClient: sessionZcapClient,
          ...(isWebvhDid(accountDid)
            ? {
                controller: accountDid,
                capabilityAgent: webvhCapabilityAgent({
                  keyAgent,
                  did: accountDid
                }),
                fallbackZcapClient: zcapClient
              }
            : {})
        }).catch(err => {
          log.warn('KMS keystore provisioning failed', { err })
          return undefined
        })
      : Promise.resolve(undefined)

  // The direct user key roster read (the `key-map/user-key.jsonl` log's
  // verified head): confirms the cached user key
  // current, or -- on an epoch mismatch (a rotation by another client) --
  // delivers the fresh user key, which the session adopts and `persistClientKeys`
  // writes into this client's client-key record. Runs before the storage clients are built, since the vault
  // keys below must be the CURRENT user key's. The read result is retained: its
  // descriptor feeds the cascade-completion sweep fired further down.
  // Gated on a promoted pointer: the log-governed roster anchors its entry
  // proofs in the did:webvh document, so an unpromoted account has no roster
  // to read. A transient session skips it too -- its user key just came
  // out of the credential's standing wrap, so a second read would be the
  // same read again.
  let activeUserKey = userKey
  let rosterRead: UserKeyRosterReadResult | null = null
  // The store instance the login read came through: the sweep below writes
  // through the same one, so its convergence is seeded from that read.
  let loginRosterStore: SealableEncryptionDescriptorStore | undefined
  let userKeyPersistFailed = false
  if (
    userKey &&
    isRememberedSession({ persistence, isGuest }) &&
    WAS_SERVER_URL &&
    accountPointer &&
    isWebvhDid(accountPointer.did)
  ) {
    const rosterCheck = await checkUserKeyRosterAtLogin({
      zcapClient: sessionZcapClient,
      keyAgent,
      pointer: { ...accountPointer, did: accountPointer.did },
      userKey,
      clientKeyAgreementKey: keyAgreementKey,
      persistence,
      ...(accountLog ? { log: accountLog } : {})
    })
    rosterRead = rosterCheck.read
    loginRosterStore = rosterCheck.store
    if (rosterRead?.rotated) {
      activeUserKey = rosterRead.userKey
      // A failed client-key-record write is non-fatal: the session runs on
      // the freshly adopted key, and only this browser's copy stayed behind
      // (the next login's roster read rotates it again).
      try {
        await persistClientKeys?.({ userKey: rosterRead.userKey })
      } catch (err) {
        userKeyPersistFailed = true
        log.warn('Could not persist the rotated user key', { err })
      }
    }
  }

  // Recipient zero becomes the user key: when the account carries one, the vault
  // key pair the storage layer consumes is the user key's KAK + resolver in place
  // of the seed-derived pair. The rest of the profile (signing identity,
  // zcap client) is untouched.
  const vaultKeys = activeUserKey
    ? userKeyVaultKeys({ userKey: activeUserKey })
    : { keyAgreementKey, keyResolver }

  const user: User = {
    id: keyAgent.id, // a did:key DID
    email
  }
  const profile: ControllerProfile = {
    keyAgent,
    zcapClient: sessionZcapClient,
    persistence,
    keyAgreementKey: vaultKeys.keyAgreementKey,
    keyResolver: vaultKeys.keyResolver,
    // This client's own (identity) KAK, distinct from the user-key-backed vault
    // KAK above: its entry in the user key wrap-set roster.
    clientKeyAgreementKey: keyAgreementKey,
    ...(activeUserKey ? { userKey: activeUserKey } : {}),
    ...(webvhUpdateKeys ? { clientWebvhKeys: webvhUpdateKeys } : {}),
    ...(persistClientKeys ? { persistClientKeys } : {}),
    ...(accountPointer ? { accountPointer } : {}),
    // Every remote request a transient session makes rides the generation
    // delegation the strategy carries (WASRemoteStore invokes it in place of
    // the root capability).
    ...(!isBrowserLocalSession(persistence)
      ? { invocationCapability: persistence.clientAnnex.invocationCapability }
      : {})
  }
  if (isRememberedSession({ persistence, isGuest })) {
    // The client seed backs the unlock-method re-bind ceremonies, which
    // only a remembered session runs; a transient session's per-visit seed
    // must not back one.
    profile.clientSeed = seed
  }
  if (isWebvhDid(accountDid)) {
    // The pointer names a published did:webvh: surface it on the profile so
    // provisioning treats the log as already adopted (it re-verifies against
    // the published copy either way).
    profile.didWebvh = { did: accountDid }
  }

  const [keystoreAgent, { storage, userExists }] = await Promise.all([
    keystorePromise,
    StorageManager.initStorageClients({
      user,
      profile,
      isGuest,
      remoteDirect: popup
    })
  ])
  // Bind the provisioned keystore onto the (already-shared) profile object;
  // the session below references the same profile.
  profile.keystoreAgent = keystoreAgent

  const session = { user, profile, storage, isGuest } as Session
  if (userKeyPersistFailed) {
    session.userKeyPersistFailed = true
  }

  // Fold collection provisioning into the session-creation seam: fire (do not
  // await) `ensureUserCollections` and expose it as `session.storageReady`, so
  // callers get a session that is provisioning itself rather than a separate
  // post-login step they must each remember. `ensureUserCollections` opens the
  // always-present local RxDB collections and, only when a remote store is
  // configured, provisions the remote Space / did:web -- so it is correct for
  // guests (local only) and returning logins alike. The new-wallet flows opt
  // out (`provisionStorage: false`) and provision explicitly.
  // A transient session skips provisioning: its bare-Space-URL reads and
  // promotion PUTs belong to the remembered login's account bootstrap, and
  // the sweeps the remembered block runs behind it (roster convergence,
  // epoch rotation, the app-key deletes) are governed writes a transient
  // session must not run.
  if (provisionStorage && isBrowserLocalSession(persistence)) {
    session.storageReady = storage.ensureUserCollections({ user, profile, idb })
  }

  // A session whose caller builds no mender block still carries a settled
  // report, so every reader has one shape to read.
  const mends = accumulator ?? mendReportAccumulator<FreewalletCeremonyId>()
  session.mends = mends.settled
  if (!accumulator) {
    mends.settle()
  }

  return { session, userExists, rosterRead, rosterStore: loginRosterStore }
}

/**
 * The login-time user key roster check: one direct read of the
 * `key-map/user-key.jsonl` roster log's verified head with the session's root
 * signing key, before any storage client exists. Returns the full roster read
 * -- `rotated` marks whether the
 * roster's current epoch differs from the cached user key (a rotation by another
 * client), and the descriptor feeds the cascade-completion sweep -- or
 * `null` when no roster exists yet (an account whose provisioning has not
 * created it -- the idempotent ensure will). Either way the served roster
 * resolves only from a verified log head (entry proofs anchored in the
 * account's did:webvh document, the chain-head pin enforced) and is checked
 * against the locally pinned latest-seen epoch, and both pins advance to what
 * was just verified.
 *
 * Failure semantics: the roster refusals -- a fabricated or discontinuous
 * roster log, a rolled-back/replayed roster, and a current epoch
 * this client cannot unwrap -- rethrow and refuse the login (the same
 * continuity class as a substituted account pointer). A chain-head rollback
 * is the carve-out (possibly nothing worse than replication lag): wallet-core
 * degrades it to the transport class, so the session keeps the cached user
 * key and nothing rolled back is adopted. Anything else (an unreachable
 * server, offline) warns and returns `null`, so offline logins keep working
 * from the cached user key.
 *
 * A failed pin advance is reported, not thrown: the adopted key
 * authenticated against the verified roster, so the session is fine -- only
 * this visit's in-memory epoch pin stayed behind. The caller's own
 * client-key record write is non-fatal the same way, surfaced as "this
 * browser could not be remembered" rather than a login failure.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the session's root signing client
 * @param options.keyAgent {ICapabilityAgent}   this client's signing key
 *   agent, for the store's log appends and pin custody
 * @param options.pointer {AccountPointer & { did: string }}   the promoted
 *   account pointer; its `did` keys the roster-epoch pin
 * @param options.userKey {UserKey}   the cached per-user key
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) KAK -- its roster entry
 * @param options.persistence {SessionPersistence}   the session's persistence
 *   strategy: both continuity pins (the chain-head pin and the epoch pin)
 *   ride it, in memory on either variant, and both guard this visit alone
 * @param [options.log] {DIDLog}   the account log this login already verified
 *   for the same pointer, resolving the store's controller view with no
 *   second fetch
 * @returns {Promise<object>}   the roster read (or null), and the store
 *   instance it came through, which the cascade-completion sweep writes
 *   through so its convergence is seeded from that read
 */
async function checkUserKeyRosterAtLogin({
  zcapClient,
  keyAgent,
  pointer,
  userKey,
  clientKeyAgreementKey,
  persistence,
  log: accountLog
}: {
  zcapClient: ZcapClient
  keyAgent: ICapabilityAgent
  pointer: AccountPointer & { did: string }
  userKey: UserKey
  clientKeyAgreementKey: IKeyAgreementKey
  persistence: SessionPersistence
  log?: DIDLog
}): Promise<{
  read: UserKeyRosterReadResult | null
  store: SealableEncryptionDescriptorStore
}> {
  const accountDid = pointer.did
  const store = accountRosterStore({
    zcapClient,
    keyAgent,
    pointer: {
      did: accountDid,
      spaceId: pointer.spaceId,
      host: pointer.host
    },
    pinStore: persistence.logPins,
    ...(accountLog ? { log: accountLog } : {})
  })
  const read = await sharedCheckUserKeyRosterAtLogin({
    store,
    userKey,
    clientKeyAgreementKey,
    pinnedEpochId: await persistence.epochPins.load({ accountDid }),
    // The pin advances to the epoch just authenticated, guarding this
    // visit's later roster reads against an older served epoch.
    onRosterRead: async ({ latestEpochId, descriptor }) => {
      await persistence.epochPins.saveFromDescriptor({
        accountDid,
        epochId: latestEpochId,
        descriptor
      })
    }
  })
  return { read, store }
}

/**
 * The remembered resume of a remembered (or passkey) signup torn before the
 * establishment's re-bind: a keyring hit whose record carries a ladder seed
 * but whose pointer names no did:webvh yet. Runs the shared mend ceremony's
 * establishment arm (the establishment re-run from the record's own ladder
 * seed, or a record re-bind when the log already resolves), with the
 * read-first registry hook (a passphrase credential's; a passkey entry
 * stays the add-a-passkey ceremony's own write), then re-fetches the
 * keyring so the caller continues into the ordinary self-enrollment. One attempt only:
 * a run that does not converge hands the original hit back (the arm's error
 * is warned, not thrown) and the existing routing stands. Reached only on
 * the explicit `rememberBrowser: true` entry; a remembered login reached by
 * the silent ratchet never runs it.
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}   the torn hit (ladder seed
 *   present, pointer not a did:webvh)
 * @param options.credential {UnlockCredential}   the derived unlock
 *   credential
 * @param options.type {'passphrase' | 'passkey'}   sets `lowEntropy`
 * @param [options.email] {string}
 * @param options.persistence {BrowserLocalSessionPersistence}   the
 *   login's persistence strategy; the mend and the re-fetch read under its
 *   chain-head pins
 * @param [options.idb] {IDBFactory}
 * @param options.mends {MendReportAccumulator}   this login's report, which
 *   the mend's four arms report into from here
 * @returns {Promise<KeyringFetchResult>}   the refreshed hit, or the
 *   original when the re-fetch missed
 */
async function healUnpromotedRememberedAccount({
  found,
  credential,
  type,
  email,
  persistence,
  idb,
  mends
}: {
  found: KeyringFetchResult
  credential: UnlockCredential
  type: 'passphrase' | 'passkey'
  email?: string
  persistence: BrowserLocalSessionPersistence
  idb?: IDBFactory
  mends: MendReportAccumulator<FreewalletCeremonyId>
}): Promise<KeyringFetchResult> {
  const ladderSeed = found.standing?.ladderSeed
  const pointer = found.pointer
  if (!ladderSeed || !pointer) {
    return found
  }
  const report = await mendCredentialAnchoredAccount({
    credential,
    ladderSeed,
    pointer,
    controller: found.controller,
    lowEntropy: type === 'passphrase',
    email: email ?? found.email,
    priorCreatedAt: found.createdAt,
    persistence,
    // The resume runs only on a pointer naming no did:webvh, so there is no
    // account DID to key a roster-epoch pin by and this caller states that
    // it holds none rather than dropping the option.
    hasRosterEpochPin: async () => false,
    ...(found.standing?.delegatedClients
      ? { delegatedClients: found.standing.delegatedClients }
      : {}),
    ...(type === 'passphrase'
      ? {
          beforePromotion: passphraseRegistryUpsertHook({
            spaceId: pointer.spaceId
          })
        }
      : {})
  })
  reportCredentialAnchoredMend({ report, mends })
  // A `reenterRepairShaped` report needs no re-entry glue here: the
  // remembered login continues into the self-enrollment, whose own
  // login-time registry backfill records the passphrase entry the arm left
  // unwritten.
  const refreshed = report.reenter
    ? await fetchKeyring({
        credential,
        idb,
        mintManageCapability: true,
        accountLogPinStore: persistence.logPins
      })
    : undefined
  if (!refreshed || !isWebvhDid(refreshed.pointer?.did)) {
    // The mend did not converge: the pointer still names no did:webvh, so
    // the self-enrollment that follows would die on it with a generic
    // failure and no pending record to resume from. The arm's own error is
    // rethrown instead, so a transport-class failure maps to the offline
    // copy and a refusal maps to its own.
    log.error('The remembered-signup resume mend did not converge', {
      err: report.establishment?.error
    })
    throw (
      report.establishment?.error ??
      new Error(
        'The remembered-signup resume could not promote the account ' +
          'pointer to a did:webvh.'
      )
    )
  }
  return refreshed
}

/**
 * Passphrase login (keyring v2). The keyring is the only login path: the
 * passphrase derives an unlock identity that locates the account and unwraps
 * this client's local key set.
 *
 * The post-KDF login routing runs first (`routeUnlockLogin`): with a WAS
 * server configured and no client-key record held for this credential, the
 * DEFAULT is the transient login -- the public-terminal composition in
 * `src/session/transientLogin.ts`, which persists nothing locally -- and the
 * remembered branches below are reached on a remembered browser (the silent
 * ratchet), with `rememberBrowser: true` (the programmatic standing
 * self-enrollment entry), or with no WAS server. The CHAPI popup runs the
 * same routing: a granted Storage Access handle lets the probe see the
 * first-party record and a remembered browser proceeds remembered, while a
 * denied one routes transient like any non-remembered browser
 * (`decisions/0009`). The remembered branches:
 *
 * - **Enrolled hit**: the keyring record was found AND this client holds a
 *   key set under the passphrase's unlock method; the session is built from
 *   the local client seed (`initSessionFromSeed`). The record's stamped
 *   `pointerDid` is cross-checked against the unlock record's pointer
 *   FIRST: a record bound to a different account is stale residue (a prior
 *   account under this reused passphrase, gone server-side), so its local
 *   residue is wiped and the login re-routes once as a record-less browser
 *   instead of feeding the forgotten-browser detector a client that was
 *   never part of this account. Returns
 *   `{ session, userExists }` -- a hit whose data Space
 *   is missing legitimately reports `userExists: false` (a half-finished
 *   signup), and the caller sends it to signup, which rebinds.
 * - **Located, not enrolled**: the keyring record was found (the account
 *   exists) but this client holds no key set -- a fresh browser. A standing
 *   record self-enrolls this browser right here and the login proceeds as an
 *   enrolled hit; only a plain pointer record (the no-WAS reduced path)
 *   returns `{ session: null, userExists: true }`, and the caller surfaces
 *   the not-enrolled guidance. A popup visit reaches this branch only on a
 *   no-WAS deployment: with a WAS server, a record-less popup routed
 *   transient long before here. On the
 *   explicit `rememberBrowser: true` entry, a standing record whose pointer
 *   names no did:webvh yet (a remembered signup torn before the
 *   establishment's re-bind) first runs the remembered resume heal
 *   (`healUnpromotedRememberedAccount`) and then self-enrolls from the
 *   refreshed record.
 * - **Miss**: no keyring anywhere, so there is no account. Returns
 *   `{ session: null, userExists: false }` and the caller routes to signup.
 *
 * `fetchKeyring` rethrows when the remote could not be reached (so the
 * caller's storage-unreachable handling fires rather than misreading it as "no
 * account"), throws `KeyringRecordForgedError` on an authenticity refusal,
 * and all storage/network errors from session init propagate unchanged.
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @param [options.email] {string}
 * @param [options.idb] {IDBFactory}   first-party IndexedDB for the keyring
 *   cache (CHAPI popups thread the Storage Access API handle here)
 * @param [options.popup] {boolean}   this login runs in the CHAPI popup's
 *   partitioned iframe. It no longer forces the remembered route -- the
 *   routing decides that from the record probe over the Storage Access
 *   handle -- and gates only what the partitioning actually implies:
 *   remote-direct storage, suppressed localStorage caches on a WAS
 *   deployment, and the remembered arm's popup refusals (no
 *   self-enrollment, no pending resume, and the login-time chain passes
 *   that carry the guard). Default false
 * @param [options.provisionStorage] {boolean}   fire `ensureUserCollections`
 *   from session creation and expose it as `session.storageReady`; default
 *   true. Signup's existence probe passes false (it discards the session after
 *   reading `userExists`, so nothing should provision on its behalf).
 * @param [options.credential] {UnlockCredential}   an already-derived unlock
 *   credential for this passphrase, so a caller that has just unlocked (the
 *   enrollment ceremony) does not run the KDF again
 * @param [options.rememberBrowser] {boolean}   the explicit routing input:
 *   `true` proceeds remembered (running the standing self-enrollment on a fresh
 *   browser -- the programmatic entry the signup probe, the recovery tail,
 *   and tests use until the login form grows the choice); `false` demands
 *   the transient session (refused as `AlreadyRememberedError` on a browser
 *   already holding this credential's client-key record). Absent, the
 *   routing decides: record present -> remembered (the silent ratchet), absent
 *   -> transient, the default on a non-remembered browser
 * @param [options.persistence] {BrowserLocalSessionPersistence}   the
 *   remembered session's persistence strategy, when a caller's reads
 *   already ran under its chain-head pins (the enrollment completion, the
 *   remembered signup's establishment) and the login must check its own
 *   reads against the same heads; built here when absent
 * @returns {Promise<{ session: Session | null, userExists: boolean }>}
 */
export async function loginWithPassphrase({
  passphrase,
  email,
  idb,
  popup = false,
  provisionStorage = true,
  credential,
  rememberBrowser,
  persistence
}: {
  passphrase: string
  email?: string
  idb?: IDBFactory
  popup?: boolean
  provisionStorage?: boolean
  credential?: UnlockCredential
  rememberBrowser?: boolean
  persistence?: BrowserLocalSessionPersistence
}): Promise<{ session: Session | null; userExists: boolean }> {
  return loginWithUnlockCredential({
    secret: passphrase,
    kdf: KEYRING_KDF,
    type: 'passphrase',
    email,
    // For the torn-retirement repair's establish-first arm, which may need
    // to make this credential standing before it can retire the one a
    // residual pending-shaped entry names.
    loginCredential: { secret: passphrase },
    idb,
    popup,
    provisionStorage,
    credential,
    rememberBrowser,
    ...(persistence ? { persistence } : {})
  })
}

/**
 * The one keyring login body both entry points run: the routing decision,
 * the transient arm, the keyring fetch, the `rememberBrowser` heal of a
 * standing record whose pointer names no did:webvh yet, and the bounded
 * stale-client-key-record retry around `sessionFromKeyringHit`. The entries
 * differ only in the secret and its KDF, the method literal, and the
 * passphrase-only members (`email`, `loginCredential`).
 *
 * The retry: a stale client-key record (bound to a different account than
 * the unlock record points at) is wiped inside `sessionFromKeyringHit`, and
 * the login re-routes as a record-less browser -- transient by default,
 * self-enrolling under `rememberBrowser: true`. A credential the routing
 * derived (the probed default path) is carried across the retry so the KDF
 * (or the one WebAuthn tap behind a passkey credential) is never repeated;
 * the explicit-`rememberBrowser` arms derive inside `fetchKeyring` as before.
 *
 * @param options {object}
 * @param [options.secret] {string | Uint8Array}   the unlock secret; may be
 *   absent only when `credential` is supplied
 * @param options.kdf {UnlockKdf}   the unlock method's KDF parameters
 * @param options.type {'passphrase' | 'passkey'}   the unlock method
 * @param [options.email] {string}   passphrase logins only
 * @param [options.loginCredential] {object}   the typed secret, threaded
 *   (with the derived credential once the routing has run the KDF) to the
 *   torn-retirement repair; passphrase logins only
 * @param [options.idb] {IDBFactory}
 * @param [options.popup] {boolean}
 * @param [options.provisionStorage] {boolean}
 * @param [options.credential] {UnlockCredential}   an already-derived unlock
 *   credential for the same secret
 * @param [options.rememberBrowser] {boolean}   the explicit routing input
 * @param [options.persistence] {BrowserLocalSessionPersistence}   the
 *   remembered session's persistence strategy, when the caller's own reads
 *   already ran under its chain-head pins; built here when absent
 * @returns {Promise<{ session: Session | null, userExists: boolean }>}
 */
async function loginWithUnlockCredential({
  secret,
  kdf,
  type,
  email,
  loginCredential,
  idb,
  popup,
  provisionStorage,
  credential,
  rememberBrowser,
  persistence: suppliedPersistence
}: {
  secret?: string | Uint8Array
  kdf: UnlockKdf
  type: 'passphrase' | 'passkey'
  email?: string
  loginCredential?: { secret: string }
  idb?: IDBFactory
  popup: boolean
  provisionStorage: boolean
  credential?: UnlockCredential
  rememberBrowser?: boolean
  persistence?: BrowserLocalSessionPersistence
}): Promise<{ session: Session | null; userExists: boolean }> {
  let derived = credential
  // One report per login attempt loop, so the routing entries a re-routed
  // attempt already reported (the stale-record wipe) stay in the report the
  // session finally carries.
  const mends = mendReportAccumulator<FreewalletCeremonyId>()
  for (let staleRetries = 0; ; staleRetries++) {
    const routed = await routeUnlockLogin({
      ...(secret !== undefined ? { secret } : {}),
      kdf,
      credential: derived,
      idb,
      rememberBrowser
    })
    if (routed.login === 'transient') {
      const found = await fetchTransientKeyring({
        credential: routed.credential,
        accountLogPinStore: routed.persistence.logPins
      })
      if (!found) {
        return { session: null, userExists: false }
      }
      return transientSessionFromKeyringHit({
        found,
        type,
        email,
        persistence: routed.persistence,
        credential: routed.credential,
        popup,
        mends
      })
    }
    derived = routed.credential ?? derived

    // The remembered session's persistence strategy, built BEFORE the
    // keyring fetch: its chain-head pin store rides every account-log read
    // on this path (the pending-proof settlement, the forgotten-browser
    // detector, the self-enrollment or the pending resume) and then the
    // session itself, so the reads that follow are checked against the
    // head the first one saw rather than each starting pin-less. Caches
    // are suppressed for a popup exactly as the seed-based tail decides.
    const persistence =
      suppliedPersistence ??
      browserLocalSessionPersistence({
        idb,
        persistCaches: !(popup && !!WAS_SERVER_URL)
      })
    let found = await fetchKeyring({
      ...(secret !== undefined ? { secret } : {}),
      kdf,
      idb,
      mintManageCapability: true,
      ...(derived ? { credential: derived } : {}),
      accountLogPinStore: persistence.logPins
    })
    if (!found) {
      return { session: null, userExists: false }
    }

    // The remembered resume entry: only under the explicit remember input,
    // and only for a standing record whose pointer names no did:webvh (a
    // remembered signup torn before the establishment's re-bind), healed and
    // re-fetched before the self-enrollment.
    if (
      rememberBrowser === true &&
      found.standing?.ladderSeed &&
      found.pointer &&
      !isWebvhDid(found.pointer.did)
    ) {
      derived =
        derived ??
        (await deriveUnlockCredential({
          secret: secret as string | Uint8Array,
          kdf
        }))
      found = await healUnpromotedRememberedAccount({
        found,
        credential: derived,
        type,
        email,
        persistence,
        idb,
        mends
      })
    }

    try {
      return await sessionFromKeyringHit({
        found,
        type,
        email,
        popup,
        provisionStorage,
        persistence,
        idb,
        mends,
        ...(loginCredential
          ? {
              loginCredential: {
                ...loginCredential,
                ...(derived ? { derived } : {})
              }
            }
          : {})
      })
    } catch (err) {
      if (!(err instanceof StaleClientKeyRecordError)) {
        throw err
      }
      if (staleRetries > 0) {
        // The record was wiped on the first pass, so a second stale signal
        // can only be a persistence fault; surface the standard unusable
        // refusal rather than looping.
        throw new KeyringRecordUnusableError({ cause: err })
      }
    }
  }
}

/**
 * Shared tail of the keyring login paths: builds the session from a keyring
 * hit's local client key set. An enrolled-shape record whose stamped
 * `pointerDid` names another account than the unlock record points at is
 * wiped as stale residue and signalled back to the entry points with the
 * module-internal `StaleClientKeyRecordError` (they re-route once as a
 * record-less browser); the check runs before the forgotten-browser
 * detector, so a record from another account cannot read as "forgotten"
 * here. A controller mismatch still throws `KeyringRecordUnusableError` --
 * the loud corrupt-record refusal -- rather than
 * proceeding under the wrong identity. A hit with no `clientKeys` -- a fresh
 * browser that located the account but is not enrolled -- returns
 * `{ session: null, userExists: true }` without touching storage. The session
 * email prefers the caller's fresh value (the login form) over the one
 * carried by the keyring record.
 *
 * Records which unlock method produced this full session on
 * `profile.unlockMethod` (its type, unlock Space id, and the management zcap
 * `fetchKeyring` minted), so Settings can backfill the unlock-methods
 * registry without re-prompting for the secret.
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}   the keyring hit
 * @param options.type {'passphrase' | 'passkey'}   the method that unlocked
 * @param [options.email] {string}   caller-supplied email, when any
 * @param [options.popup] {boolean}   the CHAPI popup's partitioned iframe:
 *   remote-direct storage, suppressed localStorage caches, and the
 *   remembered arm's popup refusals
 * @param [options.provisionStorage] {boolean}
 * @param [options.idb] {IDBFactory}   first-party IndexedDB for the
 *   `freewallet-session` database
 * @param [options.loginCredential] {object}   the unlock secret this login
 *   typed (and the derived credential, when the routing already ran the
 *   KDF), threaded to the torn-retirement repair so its establish-first arm
 *   can make the credential standing; passphrase logins only
 * @returns {Promise<{ session: Session | null, userExists: boolean }>}
 */
async function sessionFromKeyringHit({
  found,
  type,
  email,
  popup = false,
  provisionStorage = true,
  persistence,
  idb,
  loginCredential,
  mends
}: {
  found: KeyringFetchResult
  type: 'passphrase' | 'passkey'
  email?: string
  popup?: boolean
  provisionStorage?: boolean
  persistence: BrowserLocalSessionPersistence
  idb?: IDBFactory
  loginCredential?: { secret: string | Uint8Array; derived?: UnlockCredential }
  mends: MendReportAccumulator<FreewalletCeremonyId>
}): Promise<{ session: Session | null; userExists: boolean }> {
  // The three-way record routing, keyed on `userKey` presence: a record
  // holding a user key proceeds through the detector and the ordinary login;
  // a PENDING record (`userKey` absent -- a self-enrollment's
  // persist-before-publish residue) routes to the resume; an absent record
  // self-enrolls when the credential can. The pending arm is fail-closed: a
  // pending record
  // never reaches session construction outside the resume -- nothing
  // downstream refuses a userKey-less record, it would run on seed-derived
  // vault keys with every encrypted collection failing closed silently.
  const pendingResume = isPendingKeyringHit({ found })
  if (!found.clientKeys) {
    // The account was located (the keyring record exists) but this client
    // holds no key set for it -- a fresh browser. When the record carries
    // standing authority (the bridge delegation and ladder seed, both
    // credential-authenticated), the credential self-enrolls this browser as
    // an ordinary client right here -- loud log entries first, then the
    // first roster read through the credential's standing wrap -- and the
    // login proceeds enrolled. A remote-direct session (the partitioned
    // CHAPI popup) deliberately does not: its storage bucket is ephemeral,
    // and an enrolled client minted per popup visit would litter the account
    // log. Without standing authority (a plain pointer record -- the no-WAS
    // reduced path; every WAS signup writes the standing layout) the caller
    // surfaces the not-enrolled state and offers the connect-another-wallet
    // ceremony.
    if (popup || !canSelfEnroll({ found })) {
      return { session: null, userExists: true }
    }
  }
  if (pendingResume && popup) {
    // The pending arm's own popup guard: a partitioned popup visit never
    // resumes a ceremony (mirroring the record-less branch above), and must
    // not fall through to a fail-open session either.
    throw new PendingEnrollmentError({ reason: 'popup' })
  }
  // The record-to-account cross-check, BEFORE the forgotten-browser detector
  // below. The account-identity test is POINTER-based, matching the pending
  // arm's discard: the record's stamped `pointerDid` against the DID the
  // (signed, MAC-authenticated) unlock record now points at. The record's `controller` is deliberately NOT the discriminator --
  // it is an identity label that legitimately varies (see the routing note
  // in `keyring.ts`), and the loud unusable-record refusal below stays its
  // check. A mismatching `pointerDid` is stale residue: a prior account
  // under this reused passphrase, gone server-side, so no wipe ever ran on
  // this browser. It is not this account's remembered browser, and without
  // this check the detector would misread it as "forgotten" (the stale
  // client's verification method is absent from the pointed account's
  // document) and wipe with the wrong copy. The stale wipe clears what the
  // record alone derives -- the dead account's replica and caches, its
  // Space-to-DID mapping, and the credential's whole local state, the
  // record included (keeping the
  // record would route every later login remembered onto the same dead end) --
  // and the entry points catch the typed signal and re-route once as a
  // record-less browser. A pending-shape record is the resume's to route
  // (its `pointerDid` discard branch covers the foreign-account case).
  if (found.clientKeys && !pendingResume) {
    const recordPointerDid = found.clientKeys.pointerDid
    const pointedDid = found.pointer?.did
    if (recordPointerDid && pointedDid && recordPointerDid !== pointedDid) {
      log.warn(
        'Stale client-key record: bound to a different account than the unlock record points at; wiping its residue and treating this browser as not remembered',
        { unlockSpaceId: found.unlockSpaceId }
      )
      const wiped = await wipeStaleClientResidue({ found, idb })
      mends.report({
        invariant: 'client-key-record-matches-the-pointed-account',
        outcome:
          wiped.failed.length + wiped.unverified.length > 0
            ? 'partial'
            : 'clean',
        // The Space ids ride the wipe's own logger; a report carries counts.
        detail: {
          failed: wiped.failed.length,
          unverified: wiped.unverified.length
        }
      })
      throw new StaleClientKeyRecordError()
    }
  }
  // The finish-the-wipe detector: a userKey-holding client-key record whose
  // verification method is gone from the cleanly verified account document
  // means this browser was forgotten (or disconnected) with the local wipe
  // torn or never run -- the residue is wiped here and the typed refusal
  // surfaces the state, instead of the raw authorization errors the dead key
  // would hit downstream. Skips itself on any verification failure. A
  // pending-shape record is the resume's to route (its own
  // published-then-removed branch hands the genuine removal back to the same
  // wipe).
  const pinStore = persistence.logPins
  const detected =
    found.clientKeys && !pendingResume
      ? await assertClientStillEnrolled({ found, pinStore, idb })
      : undefined
  const detectorLog = detected === 'unverified' ? undefined : detected
  if (detectorLog) {
    // The detector refuses by throwing, so a return means the predicate
    // holds and nothing was mended.
    mends.report({
      invariant: 'this-browser-is-still-an-enrolled-client',
      outcome: 'noop'
    })
  } else if (detected === 'unverified') {
    // The detector stood down on a log it could not verify, which is a
    // different state from one it never ran on.
    mends.report({
      invariant: 'this-browser-is-still-an-enrolled-client',
      outcome: 'refused',
      detail: { reason: 'unverified' }
    })
  }
  const enrolled = !found.clientKeys
    ? await selfEnrollStandingClient({ found, pinStore })
    : pendingResume
      ? await resumePendingEnrollment({ found, pinStore, idb })
      : undefined
  if (pendingResume) {
    // Both entries below are graded from what the resume RETURNED rather
    // than from the record's ceremony marker: a spend resume's two
    // best-effort stages are swallowed on failure, and its record
    // completion is gated on the show-once confirm the returned prompt
    // carries. The arms that finish no ceremony -- the removed-client wipe
    // and the two discards -- throw out of the resume, so this block never
    // runs on them and neither entry is reported at all.
    const spendResume = (
      enrolled as { spendResume?: RecoverySpendResumeReport } | undefined
    )?.spendResume
    // The pending carrier clears inside the spend's confirm-gated
    // completion, so a record still owing that confirm is still pending.
    const confirmOwed = spendResume?.completion === 'confirm-pending'
    mends.report({
      invariant: 'no-client-key-record-stays-pending',
      outcome: confirmOwed ? 'partial' : 'clean',
      ...(confirmOwed ? { detail: { owed: 'save-code-confirm' } } : {})
    })
    if (found.clientKeys?.pending?.ceremony === 'recovery-spend') {
      // `clean` only where the resume observed every stage landed. The
      // confirm-gated completion cannot report the closing entry itself:
      // `session.mends` resolves from an accumulator this login settles at
      // the end of the mender block, and a report from `complete()` -- a
      // user click later -- would land in no report at all. So `partial`
      // at login is the honest outcome, and the next login's resume grades
      // the invariant again.
      const outstanding =
        !spendResume ||
        confirmOwed ||
        spendResume.standing === 'pending' ||
        spendResume.registry === 'skipped'
      mends.report({
        invariant: 'recovery-spend-is-completed',
        // No spend stage ran at all: the marker says the record was
        // spend-written, and the resume reported nothing.
        outcome: !spendResume ? 'noop' : outstanding ? 'partial' : 'clean',
        ...(spendResume
          ? {
              detail: {
                completion: spendResume.completion,
                standing: spendResume.standing,
                registry: spendResume.registry
              }
            }
          : {})
      })
    }
  }
  const clientKeys = enrolled?.clientKeys ?? found.clientKeys!
  const persistClientKeys =
    enrolled?.persistClientKeys ?? found.persistClientKeys
  const { session, userExists, rosterRead, rosterStore } =
    await initSessionFromSeed({
      seed: clientKeys.clientSeed,
      userKey: clientKeys.userKey,
      webvhUpdateKeys: clientKeys.webvhUpdateKeys,
      persistClientKeys,
      accountPointer: found.pointer,
      email: email ?? found.email,
      popup,
      provisionStorage,
      persistence,
      idb,
      mends,
      // The detector above verified this account's log for the same pointer,
      // moments ago and freshest in this sequence: the login-time roster read
      // resolves its controller view from that head rather than fetching and
      // verifying the same `did.jsonl` again.
      ...(detectorLog ? { accountLog: detectorLog.log } : {})
    })
  // The detector above already verified this account's log; seed the memo
  // with it so the tails below read it instead of verifying it again.
  if (detectorLog && found.pointer?.did) {
    primeVerifiedAccountLog({
      profile: session.profile,
      pointer: {
        did: found.pointer.did,
        spaceId: found.pointer.spaceId,
        host: found.pointer.host
      },
      verified: detectorLog
    })
  }
  // The local key set must have been bound for THIS account: an enrolled
  // client's record carries the controller it was bound under; a legacy
  // record (pre-enrollment) was necessarily written by the first client,
  // whose own did:key is the controller. The pointer-based stale check
  // above already re-routed a record whose `pointerDid` names another
  // account, so a mismatch here means a corrupt record (or a foreign key
  // set) -- refused loudly rather than proceeding under the wrong identity.
  const boundController = clientKeys.controller ?? session.user.id
  if (boundController !== found.controller) {
    // A corrupt record under the correct unlock Space: the session is
    // discarded, so settle its fired provisioning promise rather than leave it
    // an unhandled rejection if it also fails.
    session.storageReady?.catch(() => {})
    throw new KeyringRecordUnusableError({
      cause: new Error(
        'The unwrapped controller does not match the derived identity.'
      )
    })
  }
  // The profile object is plain; stamp the account controller the record was
  // bound under (recovery-code issuance re-states it in the records it
  // mints) and the unlock method that produced this session so Settings can
  // backfill the registry without the secret.
  session.profile.accountController = found.controller
  session.profile.unlockMethod = {
    type,
    unlockSpaceId: found.unlockSpaceId,
    manageCapability: found.manageCapability
  }
  // A resumed recovery spend still owes the show-once replacement-code
  // display: the prompt rides the session so the login surface can render
  // the save-this-code dialog and run the confirm-gated completion before
  // navigating on.
  const recoverySpendPrompt = (
    enrolled as { recoverySpendPrompt?: RecoverySpendPrompt } | undefined
  )?.recoverySpendPrompt
  if (recoverySpendPrompt) {
    session.recoverySpendPrompt = recoverySpendPrompt
  }
  // The login credential's ladder seed, for the mid-session ceremonies that
  // write the annex (the revocation cascade's generation-delegation
  // re-mint, the rotation's strike-or-swap).
  if (found.standing?.ladderSeed) {
    session.profile.ladderSeed = found.standing.ladderSeed
  }
  // The credential's other standing members, for the ceremonies that act
  // through the bridge mid-session (the forget ceremony's ladder-signed
  // removal entry) without re-prompting for the secret.
  if (found.standing?.delegation && found.standingClient) {
    session.profile.standingUnlock = {
      delegation: found.standing.delegation,
      ...(found.standing.delegatedClients
        ? { delegatedClients: found.standing.delegatedClients }
        : {}),
      standingClient: found.standingClient,
      unlockSpaceId: found.unlockSpaceId,
      ...(found.rebindStandingRecord
        ? { rebindRecord: found.rebindStandingRecord }
        : {})
    }
  }

  // The login-time mender block: every pass below is a registration of the
  // remembered chain's list, run by the mender runner in registration order
  // (`src/session/menders/`). The runner owns the try, warn, and skip
  // discipline once. Its seed is storage provisioning, whose failure aborts
  // the block: the login page surfaces that failure and the session is
  // abandoned, and none of the block's registry, bridge, or promotion
  // writes is wanted on it. `session.registryReady` settles when the
  // registry-writing registrations have reported, and `session.mends` when
  // the whole block has, the app-key sweep and the annex GC included.
  // No provisioning, no block: the signup existence probe logs in with
  // `provisionStorage: false` and discards the session at once, and none of
  // the block's registry, bridge, or promotion writes is wanted on its
  // behalf.
  if (!session.storageReady) {
    mends.settle()
    return { session, userExists }
  }
  const { context, refreshContext } = blockCeremonyContext({ session })
  startLoginMenderBlock({
    accumulator: mends,
    route: { popup },
    deps: {
      chain: 'remembered',
      session,
      found,
      context,
      refreshContext,
      keystorePromotion: {},
      selfEnrolled: !!enrolled,
      ...(rosterRead ? { rosterRead } : {}),
      ...(rosterStore ? { rosterStore } : {}),
      ...(loginCredential ? { loginCredential } : {})
    }
  })

  return { session, userExists }
}

/**
 * Passkey login. Runs the one-tap PRF assertion ceremony (the browser account
 * picker scopes to this RP's discoverable credentials), derives the unlock
 * identity from the PRF output under the passkey KDF, and resolves it through
 * the keyring exactly like the passphrase path -- the two differ only in the
 * secret and its KDF, including the self-enrolling continuation on a fresh
 * browser (a standing record enrolls this client in place) and the
 * "located, not enrolled" state (`{ session: null, userExists: true }`) on a
 * plain pointer record.
 * The email (absent from any login form here) is recovered from the keyring
 * record when one was bound.
 *
 * Ceremony failures propagate as the typed errors from `src/lib/passkey.ts`
 * (`PasskeyCancelledError`, `PasskeyPrfUnsupportedError`); a keyring miss --
 * a passkey with no bound wallet, e.g. one orphaned by a revocation --
 * returns `{ session: null, userExists: false }`. `fetchKeyring`
 * rethrows when the remote could not be reached, so callers'
 * storage-unreachable handling fires rather than misreading it as "no
 * account".
 *
 * @param options {object}
 * @param [options.idb] {IDBFactory}   first-party IndexedDB for the keyring
 *   cache (CHAPI popups thread the Storage Access API handle here)
 * @param [options.popup] {boolean}   the CHAPI popup's partitioned iframe,
 *   exactly as on `loginWithPassphrase`; default false
 * @param [options.provisionStorage] {boolean}   fire `ensureUserCollections`
 *   from session creation and expose it as `session.storageReady`; default
 *   true
 * @param [options.signal] {AbortSignal}   aborts the WebAuthn ceremony
 * @param [options.rememberBrowser] {boolean}   the explicit routing input,
 *   exactly as on `loginWithPassphrase`
 * @param [options.credential] {UnlockCredential}   an already-derived unlock
 *   credential for this passkey's PRF output, which SKIPS the PRF assertion
 *   ceremony -- the passkey signup's login half passes it so one signup runs
 *   one WebAuthn ceremony
 * @param [options.persistence] {BrowserLocalSessionPersistence}   exactly
 *   as on `loginWithPassphrase`
 * @returns {Promise<{ session: Session | null, userExists: boolean }>}
 */
export async function loginWithPasskey({
  idb,
  popup = false,
  provisionStorage = true,
  signal,
  rememberBrowser,
  credential,
  persistence
}: {
  idb?: IDBFactory
  popup?: boolean
  provisionStorage?: boolean
  signal?: AbortSignal
  rememberBrowser?: boolean
  credential?: UnlockCredential
  persistence?: BrowserLocalSessionPersistence
} = {}): Promise<{ session: Session | null; userExists: boolean }> {
  // The one WebAuthn tap, skipped when the caller already holds the derived
  // credential; the shared body's stale-record retry never repeats it.
  let prfOutput: Uint8Array | undefined
  if (!credential) {
    ;({ prfOutput } = await assertPasskeyPrf({ signal }))
  }
  return loginWithUnlockCredential({
    ...(prfOutput !== undefined ? { secret: prfOutput } : {}),
    kdf: PASSKEY_KDF,
    type: 'passkey',
    idb,
    popup,
    provisionStorage,
    credential,
    rememberBrowser,
    ...(persistence ? { persistence } : {})
  })
}
