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
 * an ordinary durable client in place on the programmatic
 * `rememberBrowser: true` entry (loud log entries first, then the first
 * roster read through the credential's standing wrap); a plain pointer
 * record -- which only a no-WAS bind produces, since every WAS signup writes
 * the standing layout before the Space exists -- still surfaces the
 * not-enrolled state and the connect-another-wallet ceremony.
 */
import type { CollectionEncryption } from '@interop/was-client'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { agentsFromSeed } from '@interop/wallet-core/identity'
import type { ControllerProfile, Session, User } from '@/types/auth'
import { KMS_SERVER_URL, PASSKEY_KDF, WAS_SERVER_URL } from '@/app.config'
import { ensureKeystore } from '@/lib/kms'
import { assertPasskeyPrf } from '@/lib/passkey'
import {
  delegationKeyInDocument,
  isWebvhDid,
  webvhCapabilityAgent,
  webvhZcapClient,
  type ClientWebvhUpdateKeys,
  type ICapabilityAgent,
  type PublishedKeyDocument
} from '@interop/wallet-core/webvh'
import {
  attributeLadderRung,
  delegatedClientsDelegationSpaceId,
  mintDelegatedClientsDelegation
} from '@interop/wallet-core/clientAnnex'
import {
  mintUserKey,
  userKeyVaultKeys,
  type UserKey,
  type UserKeyRosterReadResult
} from '@interop/wallet-core/keys'
import { accountRosterStore, sessionRosterStore } from '@/session/rosterStore'
import {
  checkUserKeyRosterAtLogin as sharedCheckUserKeyRosterAtLogin,
  convergeUserKeyRosterToAccount
} from '@interop/wallet-core/clients'
import { adoptRotatedUserKeyInBand } from '@/session/userKeyAdoption'
import { cascadeCollectionsToUserKey } from '@/session/userKeyCascade'
import { sweepStrandedAppKeys } from '@/session/appKeySweep'
import { sweepClientAnnexGenerations } from '@/session/clientAnnexGc'
import {
  durableSessionPersistence,
  isDurableSession,
  type SessionPersistence
} from '@/session/persistence'
import { StorageManager } from '@/stores/storageManager'
import {
  deriveUnlockCredential,
  fetchKeyring,
  fetchTransientKeyring,
  KeyringRecordUnusableError
} from '@/session/keyring'
import { establishCredentialAnchoredAccount } from '@/session/credentialAnchoredGenesis'
import { sessionLogPinStore } from '@/lib/sessionKey'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
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
import type { RecoverySpendPrompt } from '@/session/recovery'
import {
  assertClientStillEnrolled,
  wipeStaleClientResidue
} from '@/session/forget'
import {
  delegateLogWrite,
  delegationProofKeyId,
  zcapExpiring
} from '@interop/wallet-core/recovery'
import {
  ensureGenerationDelegation,
  pointedClientAnnexReach
} from '@/session/annexReach'
import {
  backfillPassphraseUnlockMethod,
  refreshStandingDelegationFields
} from '@/session/unlockMethods'
import { repairStaleUnlockRegistrySeal } from '@/session/registryReseal'
import {
  rebuildBarePasskeyEntry,
  repairTornPassphraseRetirement
} from '@/session/pendingRetirement'
import {
  primeVerifiedAccountLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
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
 * collections ready. On the same seam, when the login's roster read
 * succeeded and a remote store is attached, the cascade-completion sweep is
 * fired behind provisioning and exposed as `session.userKeySweep` (best-effort;
 * see the Session type). The new-wallet flows (signup, guest) pass
 * `provisionStorage: false`: their provisioning is a deliberately ordered
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
 * @param [options.remoteDirectStorage] {boolean}   route credential + history
 *   operations straight to the remote WAS collections (the CHAPI popup, whose
 *   local IndexedDB is third-party partitioned); default false
 * @param [options.provisionStorage] {boolean}   fire `ensureUserCollections`
 *   from session creation and expose it as `session.storageReady`; default
 *   true. Set false for the new-wallet flows that provision explicitly.
 * @param [options.idb] {IDBFactory}   first-party IndexedDB for the user key
 *   roster-epoch pin (CHAPI popups thread the Storage Access API handle here)
 * @param [options.persistence] {SessionPersistence}   the typed persistence
 *   handle for this session; defaults to the durable one built over `idb`
 *   (with cache persistence off for guests). A transient login supplies the
 *   transient handle here, which carries the client-annex identity: the
 *   annex DID whose generation holds this visit's verification method
 *   (every WAS request signs as `<clientAnnexDid>#<vm>` in place of the
 *   account-document spelling) and the generation delegation every request
 *   rides (stamped as `profile.invocationCapability`). The non-durable
 *   variant also skips the KMS keystore, the login-time roster read (the
 *   standing-wrap read already happened), `profile.clientSeed`,
 *   provisioning, the login-time sweeps, and every durable pin write.
 * @returns {Promise<{ session: Session, userExists: boolean,
 *   rosterRead: UserKeyRosterReadResult | null }>}   `rosterRead` is this
 *   login's verified roster read, which the caller's registry re-seal repair
 *   takes its escrowed user key generations from
 */
export async function initSessionFromSeed({
  seed,
  userKey,
  webvhUpdateKeys,
  persistClientKeys,
  accountPointer,
  email,
  isGuest = false,
  remoteDirectStorage = false,
  provisionStorage = true,
  idb,
  persistence: suppliedPersistence
}: {
  seed: Uint8Array
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  persistClientKeys?: (changes: PersistableClientKeys) => Promise<void>
  accountPointer?: AccountPointer
  email?: string
  isGuest?: boolean
  remoteDirectStorage?: boolean
  provisionStorage?: boolean
  idb?: IDBFactory
  persistence?: SessionPersistence
}) {
  const persistence =
    suppliedPersistence ??
    durableSessionPersistence({ idb, persistCaches: !isGuest })
  const { keyAgent, zcapClient, keyAgreementKey, keyResolver } =
    await agentsFromSeed({ seed })

  // Once the account pointer names a did:webvh, the Space controller has
  // been promoted: every data-Space request must be signed with this
  // client's verification method in the did:webvh document
  // (`<did:webvh>#<multibase>`), not its did:key. Same key, promoted keyId.
  // A transient handle's verification method lives in the annex
  // generation's document instead (the handle carries the annex DID), so
  // its requests sign as `<clientAnnexDid>#<multibase>` and ride the
  // generation delegation -- the account-document spelling is structurally
  // out of a transient session's reach.
  const accountDid = accountPointer?.did
  const sessionZcapClient = !isDurableSession(persistence)
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
  // page surfaces the unprovisioned state. A non-durable handle skips the
  // KMS whole: keystore provisioning is durable account bootstrap.
  const keystorePromise =
    !isGuest && isDurableSession(persistence) && KMS_SERVER_URL
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
  // to read. A non-durable handle skips it too -- its user key just came
  // out of the credential's standing wrap, so a second read would be the
  // same read again.
  let activeUserKey = userKey
  let rosterRead: UserKeyRosterReadResult | null = null
  let userKeyPersistFailed = false
  if (
    userKey &&
    !isGuest &&
    isDurableSession(persistence) &&
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
      persistence
    })
    rosterRead = rosterCheck.read
    userKeyPersistFailed = rosterCheck.persistFailed
    if (rosterRead?.rotated) {
      activeUserKey = rosterRead.userKey
      // A failed client-key-record write is the same non-fatal state as a
      // failed pin persist: the session runs on the freshly adopted key, and
      // only this browser's durable copy stayed behind (the next login's
      // roster read rotates it again).
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
    // delegation the handle carries (WASRemoteStore invokes it in place of
    // the root capability).
    ...(!isDurableSession(persistence)
      ? { invocationCapability: persistence.clientAnnex.invocationCapability }
      : {})
  }
  if (!isGuest && isDurableSession(persistence)) {
    // The client seed backs the unlock-method re-bind ceremonies, all of
    // them durable; a transient session's per-visit seed must never be one.
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
      remoteDirect: remoteDirectStorage
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
  // A transient session skips provisioning and every login-time sweep: the
  // sweeps perform governed writes (roster convergence, epoch rotation, the
  // app-key deletes) a transient session must not run, and provisioning's
  // bare-Space-URL reads and promotion PUTs are the durable bootstrap's.
  if (provisionStorage && isDurableSession(persistence)) {
    const storageReady = storage.ensureUserCollections({ user, profile, idb })
    session.storageReady = storageReady

    // The app-key sweep: app keys now live in their own `app-connections`
    // collection, so any left in `private-credentials` by an earlier version
    // are deleted here rather than migrated -- their seeds must not stay
    // reachable from the credential-wide surfaces (a public link, a share of
    // the credentials collection). A second pass retracts the world-readable
    // copies left with no private row behind them. Chained behind provisioning and strictly
    // best-effort, like the cascade sweep below: a failed sweep never fails
    // the login, and the next login runs it again.
    session.appKeySweep = storageReady
      .catch(() => {})
      .then(() => sweepStrandedAppKeys({ storage }))
      .catch((err): null => {
        log.warn('The stranded app-key sweep failed', { err })
        return null
      })

    // The cascade-completion sweep: with the roster in hand (the direct read
    // above) and a remote store attached, re-run the collection fan-out of
    // the user key cascade in the background. A collection is stale exactly when
    // its current epoch names a non-current user key generation -- durable state
    // alone -- so a cascade another client crashed partway is completed
    // here, and a healthy account's sweep reads descriptors and writes
    // nothing. Chained behind provisioning (so freshly ensured collections
    // are visible) and strictly best-effort: a failed sweep never fails the
    // login, and the next login (or revocation) converges the same branch.
    const remoteStore = storage.remoteStore
    if (rosterRead && activeUserKey && remoteStore) {
      const loginUserKey = activeUserKey
      const loginDescriptor = rosterRead.descriptor
      session.userKeySweep = storageReady
        .catch(() => {})
        .then(async () => {
          // The roster stage first: a disconnect torn between the document
          // edit and the roster rotation leaves the roster still wrapping the
          // CURRENT key to a recipient the document no longer keys -- durable
          // and silent, since the disconnected client's document edit will
          // never be re-run. Converging it here before the fan-out is what
          // makes the collections below take a key the disconnected client
          // cannot open.
          const { userKey: sweepUserKey, rosterDescriptor } =
            await convergeRosterToDocument({
              session,
              pointer: accountPointer,
              userKey: loginUserKey,
              descriptor: loginDescriptor,
              clientKeyAgreementKey: keyAgreementKey,
              persistence
            })
          const result = await cascadeCollectionsToUserKey({
            remoteStore,
            rosterDescriptor,
            clientKeyAgreementKey: keyAgreementKey,
            userKey: sweepUserKey
          })
          // The session's ciphers were built before the sweep ran: when the
          // sweep moved any collection's current epoch (`rotated`; the
          // rotation-only cascade never installs epochs -- provisioning does
          // -- and an escrow leaves the current epoch in place), refresh the
          // descriptors and ciphers so the rest of the session seals writes
          // under the fresh epoch instead of the retired one.
          if (
            Object.values(result.outcomes).some(
              outcome => outcome === 'rotated'
            )
          ) {
            await storage.refreshEncryptedDescriptors()
          }
          return result
        })
        .catch((err): null => {
          log.warn('The user key cascade-completion sweep failed', { err })
          return null
        })
    }
  }

  return { session, userExists, rosterRead }
}

/**
 * The roster stage of the cascade-completion sweep: converges the wrap-set
 * roster onto the account's locally verified did:webvh document, so a
 * revocation torn between its document edit and its roster rotation is
 * finished here rather than leaving the current per-user key wrapped to a
 * client the document no longer keys.
 *
 * When the convergence rotates, the fresh key is read back and adopted the
 * ordinary way -- persisted into this client's client-key record, pinned, and
 * swapped into the live session's vault keys and storage ciphers -- and
 * handed back for the collection fan-out to run against. A healthy account
 * reads the descriptor and writes nothing; a document that cannot be fetched
 * or verified (offline, an unpromoted account) leaves the login's own roster
 * read in place, since the sweep is best-effort by design.
 *
 * @param options {object}
 * @param options.session {Session}   the live session, whose vault keys and
 *   ciphers adopt a rotation
 * @param [options.pointer] {AccountPointer}
 * @param options.userKey {UserKey}   the login's current per-user key
 * @param options.descriptor {CollectionEncryption}   the login's roster read
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) KAK -- its roster entry
 * @param options.persistence {SessionPersistence}   the session's persistence
 *   handle (the pins ride it)
 * @returns {Promise<{ userKey: UserKey, rosterDescriptor: CollectionEncryption }>}
 *   the key and roster descriptor the collection fan-out should use
 */
async function convergeRosterToDocument({
  session,
  pointer,
  userKey,
  descriptor,
  clientKeyAgreementKey,
  persistence
}: {
  session: Session
  pointer?: AccountPointer
  userKey: UserKey
  descriptor: CollectionEncryption
  clientKeyAgreementKey: IKeyAgreementKey
  persistence: SessionPersistence
}): Promise<{ userKey: UserKey; rosterDescriptor: CollectionEncryption }> {
  const { keyAgent } = session.profile
  if (!pointer || !isWebvhDid(pointer.did) || !WAS_SERVER_URL || !keyAgent) {
    return { userKey, rosterDescriptor: descriptor }
  }
  // The did:webvh check above is what makes the pins' account DID available:
  // the three continuity pins are keyed by it, and an unpromoted account
  // returned early.
  const accountDid = pointer.did
  const { userKey: convergedUserKey, descriptor: convergedDescriptor } =
    await convergeUserKeyRosterToAccount({
      pointer: {
        did: accountDid,
        spaceId: pointer.spaceId,
        host: pointer.host
      },
      store: sessionRosterStore({ profile: session.profile }),
      userKey,
      descriptor,
      clientKeyAgreementKey,
      pinnedEpochId: await persistence.epochPins.load({ accountDid }),
      accountLogPinStore: persistence.logPins,
      // Adoption is app-side and in band: the unlock-methods registry is
      // re-sealed to the adopted key first (while this browser's durable
      // copy of the pre-rotation one still exists), then the key is
      // persisted for the next login, pinned, and swapped into the live
      // session -- all before the collection fan-out runs against it. A
      // failed re-seal leaves the session on the pre-rotation keys and no
      // backstop runs here (the sweep has no post-ceremony adoption step);
      // the next login's re-seal repair is the mender.
      onUserKeyAdopted: async ({
        userKey: adopted,
        latestEpochId,
        descriptor: read
      }) =>
        await adoptRotatedUserKeyInBand({
          session,
          spaceId: pointer.spaceId,
          accountDid,
          userKey: adopted,
          latestEpochId,
          descriptor: read
        })
    })
  return { userKey: convergedUserKey, rosterDescriptor: convergedDescriptor }
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
 * A failed PIN persist is reported, not thrown: the adopted key
 * authenticated against the verified roster, so the session is fine -- only
 * this browser's durable state did not advance, which the caller surfaces as
 * "this browser could not be remembered" rather than a login failure.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the session's root signing client
 * @param options.keyAgent {ICapabilityAgent}   this client's signing key
 *   agent, for the store's log appends and pin custody
 * @param options.pointer {AccountPointer & { did: string }}   the promoted
 *   account pointer; its `did` keys the continuity pins
 * @param options.userKey {UserKey}   the cached per-user key
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) KAK -- its roster entry
 * @param options.persistence {SessionPersistence}   the session's persistence
 *   handle: both continuity pins (the chain-head pin and the epoch pin) ride
 *   it, so a transient session pins in memory for the visit
 * @returns {Promise<object>}   the roster read (or null), and whether the
 *   epoch-pin persist failed
 */
async function checkUserKeyRosterAtLogin({
  zcapClient,
  keyAgent,
  pointer,
  userKey,
  clientKeyAgreementKey,
  persistence
}: {
  zcapClient: ZcapClient
  keyAgent: ICapabilityAgent
  pointer: AccountPointer & { did: string }
  userKey: UserKey
  clientKeyAgreementKey: IKeyAgreementKey
  persistence: SessionPersistence
}): Promise<{ read: UserKeyRosterReadResult | null; persistFailed: boolean }> {
  const accountDid = pointer.did
  let persistFailed = false
  const read = await sharedCheckUserKeyRosterAtLogin({
    store: accountRosterStore({
      zcapClient,
      keyAgent,
      pointer: {
        did: accountDid,
        spaceId: pointer.spaceId,
        host: pointer.host
      },
      pinStore: persistence.logPins
    }),
    userKey,
    clientKeyAgreementKey,
    pinnedEpochId: await persistence.epochPins.load({ accountDid }),
    // The pin advances to the epoch just authenticated. A throw from here
    // propagates out of the shared check (it is no longer swallowed into the
    // offline null path), so the failure is caught HERE, where its meaning
    // is known: the read itself succeeded, only the local persist did not.
    onRosterRead: async ({ latestEpochId, descriptor }) => {
      try {
        await persistence.epochPins.saveFromDescriptor({
          accountDid,
          epochId: latestEpochId,
          descriptor
        })
      } catch (err) {
        persistFailed = true
        log.warn('Could not persist the user key epoch pin', { err })
      }
    }
  })
  return { read, persistFailed }
}

/**
 * The durable resume of a remembered (or passkey) signup torn before the
 * establishment's re-bind: a keyring hit whose record carries a ladder seed
 * but whose pointer names no did:webvh yet. Runs the same heal the transient
 * composition runs -- the credential-anchored establishment re-run from the
 * record's own ladder seed (every stage an ensure; the published log, if
 * any, adopted by ladder attribution), under the DURABLE pin store -- then
 * re-fetches the keyring so the caller continues into the ordinary
 * self-enrollment. One attempt only: a re-run that does not converge hands
 * the original hit back and the existing routing stands. Reached only on the
 * explicit `rememberBrowser: true` entry; the default durable login never
 * runs it.
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}   the torn hit (ladder seed
 *   present, pointer not a did:webvh)
 * @param options.credential {UnlockCredential}   the derived unlock
 *   credential
 * @param options.type {'passphrase' | 'passkey'}   sets `lowEntropy`
 * @param [options.email] {string}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<KeyringFetchResult>}   the refreshed hit, or the
 *   original when the re-fetch missed
 */
async function healUnpromotedRememberedAccount({
  found,
  credential,
  type,
  email,
  idb
}: {
  found: KeyringFetchResult
  credential: UnlockCredential
  type: 'passphrase' | 'passkey'
  email?: string
  idb?: IDBFactory
}): Promise<KeyringFetchResult> {
  const ladderSeed = found.standing?.ladderSeed
  const pointer = found.pointer
  if (!ladderSeed || !pointer) {
    return found
  }
  await establishCredentialAnchoredAccount({
    credential,
    ladderSeed,
    pointer,
    lowEntropy: type === 'passphrase',
    email: email ?? found.email,
    priorCreatedAt: found.createdAt,
    persistence: { logPins: sessionLogPinStore({ idb }) }
  })
  const refreshed = await fetchKeyring({
    credential,
    idb,
    mintManageCapability: true
  })
  return refreshed ?? found
}

/**
 * Passphrase login (keyring v2). The keyring is the only login path: the
 * passphrase derives an unlock identity that locates the account and unwraps
 * this client's local key set.
 *
 * The post-KDF durability routing runs first (`routeUnlockLogin`): with a WAS
 * server configured and no client-key record held for this credential, the
 * DEFAULT is the transient login -- the public-terminal composition in
 * `src/session/transientLogin.ts`, which persists nothing locally -- and the
 * durable branches below are reached on a remembered browser (the silent
 * ratchet), with `rememberBrowser: true` (the programmatic standing
 * self-enrollment entry), in a remote-direct popup, or with no WAS server.
 * The durable branches:
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
 *   enrolled hit; only a plain pointer record (the no-WAS reduced path, or a
 *   remote-direct popup session) returns `{ session: null, userExists:
 *   true }`, and the caller surfaces the not-enrolled guidance. On the
 *   explicit `rememberBrowser: true` entry, a standing record whose pointer
 *   names no did:webvh yet (a remembered signup torn before the
 *   establishment's re-bind) first runs the durable resume heal
 *   (`healUnpromotedRememberedAccount`) and then self-enrolls from the
 *   refreshed record.
 * - **Miss**: no keyring anywhere, so there is no account. Returns
 *   `{ session: null, userExists: false }` and the caller routes to signup.
 *
 * `fetchKeyring` rethrows when the remote could not be reached (so the
 * caller's storage-unreachable handling fires rather than misreading it as "no
 * account"), throws `KeyringRecordForgedError` or
 * `KeyringRecordRolledBackError` on an authenticity or freshness refusal, and
 * all storage/network errors from session init propagate unchanged.
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @param [options.email] {string}
 * @param [options.idb] {IDBFactory}   first-party IndexedDB for the keyring
 *   cache (CHAPI popups thread the Storage Access API handle here)
 * @param [options.remoteDirectStorage] {boolean}   route credential + history
 *   operations straight to the remote WAS collections (the CHAPI popup);
 *   default false
 * @param [options.provisionStorage] {boolean}   fire `ensureUserCollections`
 *   from session creation and expose it as `session.storageReady`; default
 *   true. Signup's existence probe passes false (it discards the session after
 *   reading `userExists`, so nothing should provision on its behalf).
 * @param [options.credential] {UnlockCredential}   an already-derived unlock
 *   credential for this passphrase, so a caller that has just unlocked (the
 *   enrollment ceremony) does not run the KDF again
 * @param [options.rememberBrowser] {boolean}   the explicit durability input:
 *   `true` proceeds durable (running the standing self-enrollment on a fresh
 *   browser -- the programmatic entry the signup probe, the recovery tail,
 *   and tests use until the login form grows the choice); `false` demands
 *   the transient session (refused as `AlreadyRememberedError` on a browser
 *   already holding this credential's client-key record). Absent, the
 *   routing decides: record present -> durable (the silent ratchet), absent
 *   -> transient, the default on a non-remembered browser
 * @returns {Promise<{ session: Session | null, userExists: boolean }>}
 */
export async function loginWithPassphrase({
  passphrase,
  email,
  idb,
  remoteDirectStorage = false,
  provisionStorage = true,
  credential,
  rememberBrowser
}: {
  passphrase: string
  email?: string
  idb?: IDBFactory
  remoteDirectStorage?: boolean
  provisionStorage?: boolean
  credential?: UnlockCredential
  rememberBrowser?: boolean
}): Promise<{ session: Session | null; userExists: boolean }> {
  // One bounded retry around the routing: a stale client-key record (bound
  // to a different account than the unlock record points at) is wiped
  // inside `sessionFromKeyringHit`, and the login re-routes as a
  // record-less browser -- transient by default, self-enrolling under
  // `rememberBrowser: true`. A credential the routing derived (the probed
  // default path) is carried across the retry so the KDF does not re-run
  // there; the explicit-durability arms derive inside `fetchKeyring` as
  // before.
  let derived = credential
  for (let staleRetries = 0; ; staleRetries++) {
    const routed = await routeUnlockLogin({
      secret: passphrase,
      kdf: KEYRING_KDF,
      credential: derived,
      idb,
      remoteDirectStorage,
      rememberBrowser
    })
    if (routed.durability === 'transient') {
      const found = await fetchTransientKeyring({
        credential: routed.credential,
        accountLogPinStore: routed.persistence.logPins
      })
      if (!found) {
        return { session: null, userExists: false }
      }
      return transientSessionFromKeyringHit({
        found,
        type: 'passphrase',
        email,
        persistence: routed.persistence,
        credential: routed.credential
      })
    }
    derived = routed.credential ?? derived

    let found = await fetchKeyring({
      passphrase,
      idb,
      mintManageCapability: true,
      ...(derived ? { credential: derived } : {})
    })

    if (!found) {
      return { session: null, userExists: false }
    }

    // The durable resume entry: only under the explicit remember input, and
    // only for a standing record whose pointer names no did:webvh (a
    // remembered signup torn before its re-bind).
    if (
      rememberBrowser === true &&
      found.standing?.ladderSeed &&
      found.pointer &&
      !isWebvhDid(found.pointer.did)
    ) {
      derived =
        derived ??
        (await deriveUnlockCredential({
          secret: passphrase,
          kdf: KEYRING_KDF
        }))
      found = await healUnpromotedRememberedAccount({
        found,
        credential: derived,
        type: 'passphrase',
        email,
        idb
      })
    }

    try {
      return await sessionFromKeyringHit({
        found,
        type: 'passphrase',
        email,
        remoteDirectStorage,
        provisionStorage,
        idb,
        // For the torn-retirement repair's establish-first arm, which may
        // need to make this credential standing before it can retire the
        // one a residual pending-shaped entry names.
        loginCredential: {
          secret: passphrase,
          ...(derived ? { derived } : {})
        }
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
 * @param [options.remoteDirectStorage] {boolean}
 * @param [options.provisionStorage] {boolean}
 * @param [options.idb] {IDBFactory}   first-party IndexedDB for the user key
 *   roster-epoch pin
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
  remoteDirectStorage = false,
  provisionStorage = true,
  idb,
  loginCredential
}: {
  found: KeyringFetchResult
  type: 'passphrase' | 'passkey'
  email?: string
  remoteDirectStorage?: boolean
  provisionStorage?: boolean
  idb?: IDBFactory
  loginCredential?: { secret: string | Uint8Array; derived?: UnlockCredential }
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
    // and a durable client minted per popup visit would litter the account
    // log. Without standing authority (a plain pointer record -- the no-WAS
    // reduced path; every WAS signup writes the standing layout) the caller
    // surfaces the not-enrolled state and offers the connect-another-wallet
    // ceremony.
    if (remoteDirectStorage || !canSelfEnroll({ found })) {
      return { session: null, userExists: true }
    }
  }
  if (pendingResume && remoteDirectStorage) {
    // The pending arm's own popup guard: a partitioned popup visit never
    // resumes a ceremony (mirroring the record-less branch above), and must
    // not fall through to a fail-open session either.
    throw new PendingEnrollmentError({ reason: 'popup' })
  }
  // The record-to-account cross-check, BEFORE the forgotten-browser detector
  // below. The account-identity test is POINTER-based, matching the pending
  // arm's discard: the record's stamped `pointerDid` against the DID the
  // (signed, MAC-authenticated, freshness-pinned) unlock record now points
  // at. The record's `controller` is deliberately NOT the discriminator --
  // it is an identity label that legitimately varies (see the routing note
  // in `keyring.ts`), and the loud unusable-record refusal below stays its
  // check. A mismatching `pointerDid` is stale residue: a prior account
  // under this reused passphrase, gone server-side, so no wipe ever ran on
  // this browser. It is not this account's remembered browser, and without
  // this check the detector would misread it as "forgotten" (the stale
  // client's verification method is absent from the pointed account's
  // document) and wipe with the wrong copy. The stale wipe clears what the
  // record alone derives -- the dead account's replica, caches, and pins,
  // and the credential's whole local trio, the record included (keeping the
  // record would route every later login durable onto the same dead end) --
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
      await wipeStaleClientResidue({ found, idb })
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
  const detectorLog =
    found.clientKeys && !pendingResume
      ? await assertClientStillEnrolled({ found, idb })
      : undefined
  const enrolled = !found.clientKeys
    ? await selfEnrollStandingClient({ found, idb })
    : pendingResume
      ? await resumePendingEnrollment({ found, idb })
      : undefined
  const clientKeys = enrolled?.clientKeys ?? found.clientKeys!
  const persistClientKeys =
    enrolled?.persistClientKeys ?? found.persistClientKeys
  const { session, userExists, rosterRead } = await initSessionFromSeed({
    seed: clientKeys.clientSeed,
    userKey: clientKeys.userKey,
    webvhUpdateKeys: clientKeys.webvhUpdateKeys,
    persistClientKeys,
    accountPointer: found.pointer,
    email: email ?? found.email,
    remoteDirectStorage,
    provisionStorage,
    idb
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

  // Every registry pass below rides `session.registryReady` -- one ordered
  // promise chain seeded behind storage provisioning, kept OFF
  // `session.storageReady` so the login pages can navigate as soon as the
  // collections are provisioned while the single total order among the
  // registry writers is preserved (FW-300). The chain starts by folding in
  // the login's user key sweep, not merely provisioning: the sweep's roster
  // convergence may rotate the user key and re-seal the registry to the
  // fresh one, and a registry read-modify-write racing that re-seal would
  // rewrite the record under the pre-rotation keys and undo it within one
  // login. The seed propagates a provisioning rejection, so every stage is
  // skipped when provisioning itself failed -- the login page surfaces that
  // failure and the session is abandoned, and none of the chain's registry,
  // bridge, or promotion writes are wanted on it. The trailing catch after
  // the last append keeps `registryReady` settling for its awaiters. The
  // sweep promise never rejects (it resolves null on failure), so the fold
  // only orders the two, and a session with no sweep chains behind nothing.
  if (session.storageReady) {
    session.registryReady = session.storageReady.then(
      async () => void (await session.userKeySweep)
    )
  }

  // The re-seal repair: an unlock-methods registry left sealed to a
  // superseded user key generation (a rotation whose in-band re-seal was
  // lost) is re-opened from this login's roster escrow and re-sealed to the
  // current key. First in the chain, because every registry writer below
  // reads the record: a stale seal would make each of them warn and skip on
  // a registry this same login can mend. Gated on the login's roster read
  // having succeeded -- that read is where the superseded generations come
  // from. Best-effort behind provisioning.
  if (session.registryReady && !remoteDirectStorage && rosterRead) {
    const loginRosterRead = rosterRead
    session.registryReady = session.registryReady.then(async () => {
      try {
        await repairStaleUnlockRegistrySeal({
          session,
          rosterRead: loginRosterRead
        })
      } catch (err) {
        log.warn(
          'Could not repair the unlock-methods registry seal; the next login retries',
          { err }
        )
      }
    })
  }

  // The torn-retirement repair: a passphrase change whose retirement
  // failed at its document edit leaves the registry's passphrase entry
  // naming the OLD credential's standing configuration under the new unlock Space, and
  // nothing else can find that credential (the roster sweep only rotates
  // away recipients the document does not back). This login retires it and
  // records its own standing configuration. Ordered ahead of the ladder-rung refresh below,
  // which would otherwise overwrite the entry's recorded rung -- the very
  // anchor the retirement attributes by. Best-effort behind provisioning.
  if (session.registryReady && !remoteDirectStorage) {
    session.registryReady = session.registryReady.then(async () => {
      try {
        await repairTornPassphraseRetirement({
          session,
          found,
          ...(loginCredential ? { credential: loginCredential } : {})
        })
      } catch (err) {
        log.warn(
          'Could not finish the pending passphrase retirement; the next login retries',
          { err }
        )
      }
    })
  }

  // The passkey half of the bare-entry rebuild, in the same slot and for the
  // same reason: it settles a registry entry's standing identity, which the
  // backfill's refresh write must not run ahead of. A passkey login is the
  // only thing that can mend its own entry -- the torn-retirement repair
  // above is a passphrase's. Best-effort behind provisioning.
  if (session.registryReady && !remoteDirectStorage) {
    session.registryReady = session.registryReady.then(async () => {
      try {
        await rebuildBarePasskeyEntry({ session, found })
      } catch (err) {
        log.warn(
          'Could not rebuild the bare passkey unlock-method entry; the next login retries',
          { err }
        )
      }
    })
  }

  // The registry backfill: the passphrase entry's unlock Space and
  // management zcap, recorded from this full session without a second
  // passphrase prompt. It covers the passkey login too (the shared tail),
  // and runs after the two repairs above, whose writes settle which
  // credential the entry names -- the backfill only refreshes fields on it.
  // An existing registry not yet materialized stays that way (no
  // `createIfMissing`). The remote-direct popup is excluded, as it always
  // was; a transient session has no `registryReady` and so no backfill,
  // which is the durable-only rule the registry lives under.
  if (session.registryReady && !remoteDirectStorage) {
    session.registryReady = session.registryReady.then(async () => {
      try {
        await backfillPassphraseUnlockMethod({ session })
      } catch (err) {
        log.warn('Could not backfill the unlock-methods registry', { err })
      }
    })
  }
  // The standing-delegation self-refresh: a standing credential's own login
  // re-mints its bridge delegation -- and the annex-Space sibling, where
  // the record carries one -- when either is stale on either axis: expired
  // or inside the renewal window (the same annual clock and shared predicate
  // as the recovery delegations), or its signer no longer in the verified
  // account document (the current-key-set rot a self-enrollment's window
  // close inflicts on ladder-VM-signed members -- the ceremony tail below
  // reseals them in the same login, and this predicate is what makes a torn
  // tail heal at the next login). One pass reseals both. Best-effort, behind
  // provisioning.
  const rebindStandingRecord = found.rebindStandingRecord
  const standingDelegation = found.standing?.delegation
  const standingDelegatedClients = found.standing?.delegatedClients
  const standingClientDid = found.standingClient?.clientDid
  // This credential's key-agreement multibase, the identity every registry
  // write below matches the entry on beside its unlock Space id.
  const standingKeyAgreementKeyMultibase =
    found.standingClient?.keyAgreementKeyMultibase
  if (
    session.registryReady &&
    rebindStandingRecord &&
    standingDelegation &&
    standingClientDid
  ) {
    const unlockSpaceId = found.unlockSpaceId
    session.registryReady = session.registryReady.then(async () => {
      try {
        const pointer = session.profile.accountPointer
        if (!pointer || !isWebvhDid(pointer.did)) {
          return
        }
        const expiring =
          zcapExpiring({
            expires: (standingDelegation as { expires?: string }).expires
          }) ||
          (!!standingDelegatedClients &&
            zcapExpiring({
              expires: (standingDelegatedClients as { expires?: string })
                .expires
            }))
        if (!expiring) {
          const { doc } = await verifiedAccountLog({
            profile: session.profile,
            pointer
          })
          const rotted = (member: IZcap) =>
            !delegationKeyInDocument({
              doc: doc as PublishedKeyDocument,
              delegationKeyId: delegationProofKeyId(member)
            })
          if (
            !rotted(standingDelegation) &&
            (!standingDelegatedClients || !rotted(standingDelegatedClients))
          ) {
            return
          }
        }
        const delegation = await delegateLogWrite({
          zcapClient: session.profile.zcapClient,
          pointer,
          recoveryClientDid: standingClientDid
        })
        // The sibling reseals in the same pass; its target auxiliary Space
        // id rides in the old delegation (the id's one carrier).
        let delegatedClients
        if (standingDelegatedClients) {
          const clientAnnexSpaceId = delegatedClientsDelegationSpaceId({
            delegation: standingDelegatedClients
          })
          if (clientAnnexSpaceId) {
            delegatedClients = await mintDelegatedClientsDelegation({
              zcapClient: session.profile.zcapClient,
              wasServerUrl: pointer.host,
              clientAnnexSpaceId,
              controller: standingClientDid
            })
          }
        }
        await rebindStandingRecord({
          delegation,
          ...(delegatedClients ? { delegatedClients } : {})
        })
        // The live session acts through the members it carries, so the
        // refreshed ones replace the stale pair there too (a forget run
        // later this session signs through the delegation that verifies).
        if (session.profile.standingUnlock) {
          session.profile.standingUnlock = {
            ...session.profile.standingUnlock,
            delegation,
            ...(delegatedClients ? { delegatedClients } : {})
          }
        }
        await refreshStandingDelegationFields({
          session,
          unlockSpaceId,
          // The entry may still record an earlier credential's standing configuration (a
          // pending retirement); these members are this credential's.
          ...(standingKeyAgreementKeyMultibase
            ? {
                keyAgreementKeyMultibase: standingKeyAgreementKeyMultibase
              }
            : {}),
          delegationKeyId: delegationProofKeyId(delegation),
          delegationExpires: (delegation as { expires?: string }).expires,
          ...(delegatedClients
            ? {
                delegatedClientsKeyId: delegationProofKeyId(delegatedClients),
                delegatedClientsExpires: (
                  delegatedClients as { expires?: string }
                ).expires
              }
            : {})
        })
      } catch (err) {
        log.warn(
          'Could not refresh the expiring standing delegations; the next login retries',
          { err }
        )
      }
    })
  }

  // The login credential's ladder seed, shared by the three best-effort
  // ceremonies below (the ladder-rung refresh, the generation-delegation
  // heal, and the annex GC sweep) -- already stamped on `profile.ladderSeed`
  // above.
  const ladderSeed = found.standing?.ladderSeed

  // After a self-enrollment climbed the update-key ladder, refresh the
  // registry entry's recorded rung to the freshly committed one, so the
  // revocation edit's latent-hash attribution stays answerable. Best-effort:
  // a stale rung only makes that attribution fail closed later, never
  // silently misattribute.
  const enrolledLadderSeed = enrolled ? ladderSeed : undefined
  if (session.registryReady && enrolledLadderSeed) {
    const unlockSpaceId = found.unlockSpaceId
    session.registryReady = session.registryReady.then(async () => {
      try {
        const pointer = session.profile.accountPointer
        if (!pointer || !isWebvhDid(pointer.did)) {
          return
        }
        const published = await verifiedAccountLog({
          profile: session.profile,
          pointer
        })
        const { rung, state } = await attributeLadderRung({
          ladderSeed: enrolledLadderSeed,
          published
        })
        if (state === 'committed') {
          await refreshStandingDelegationFields({
            session,
            unlockSpaceId,
            ...(standingKeyAgreementKeyMultibase
              ? {
                  keyAgreementKeyMultibase: standingKeyAgreementKeyMultibase
                }
              : {}),
            updateKeyMultibase: rung.keyMultibase
          })
        }
      } catch (err) {
        log.warn(
          'Could not refresh the recorded ladder rung after self-enrolling; a later disconnect attribution fails closed instead',
          { err }
        )
      }
    })
  }

  // The did:webvh heal path: an account whose signup-time backfill never ran
  // (a KMS or WAS hiccup -- the pointer still names a did:key) re-attempts
  // the pointer backfill and controller promotion behind provisioning, which
  // is where `ensureDidWebvh` publishes (or adopts) the log and sets
  // `profile.didWebvh`. Signup was previously the ONLY site that ran these,
  // so one transient provisioning failure left the account permanently
  // unpromoted -- enrollment, recovery codes, and client revocation all
  // refused forever. Best-effort like the signup original: a failed heal
  // warns and the next login retries from durable state.
  const persistAccountPointer = found.persistAccountPointer
  if (
    session.registryReady &&
    persistAccountPointer &&
    found.pointer &&
    !isWebvhDid(found.pointer.did)
  ) {
    const staleServerPointer = found.pointer
    session.registryReady = session.registryReady.then(async () => {
      const did = session.profile.didWebvh?.did
      if (!did || !isWebvhDid(did)) {
        return
      }
      const fullPointer = { ...staleServerPointer, did }
      try {
        await persistAccountPointer(fullPointer)
        session.profile.accountPointer = fullPointer
        await session.storage.ensurePromotedController({
          profile: session.profile
        })
      } catch (err) {
        log.warn(
          'Could not backfill the did:webvh pointer and promote the controller; the next login retries',
          { err }
        )
      }
    })
  }

  // The generation-delegation self-heal: the pointed generation's embedded
  // delegation is renewed when it is expiring OR its signer has left the
  // verified account document -- the rot a self-enrollment's window close
  // inflicts on a ladder-VM-signed delegation (the ceremony-tail half of
  // that reseal), and the standing backstop for a revocation cascade whose
  // own re-mint stage was skipped. Signed by the login credential's static
  // annex rung 0; a healthy delegation is one no-op read. Best-effort: a
  // rung the generation does not commit (a credential bound mid-generation)
  // skips quietly, everything else warns and the next login retries.
  if (session.registryReady && !remoteDirectStorage && ladderSeed) {
    session.registryReady = session.registryReady.then(async () => {
      try {
        const pointer = session.profile.accountPointer
        if (!pointer || !isWebvhDid(pointer.did)) {
          return
        }
        const reach = await pointedClientAnnexReach({ session, pointer })
        if (reach === null) {
          return
        }
        const logPins = session.profile.persistence?.logPins
        await ensureGenerationDelegation({
          session,
          pointer,
          reach,
          ladderSeed,
          accountDoc: reach.doc as PublishedKeyDocument,
          ...(logPins ? { pin: { pinStore: logPins, logId: reach.logId } } : {})
        })
      } catch (err) {
        if (
          (err as { name?: string }).name === 'ClientAnnexRungUncommittedError'
        ) {
          return
        }
        log.warn(
          'Could not heal the generation delegation; the next login retries',
          { err }
        )
      }
    })
  }

  // The annex GC sweep: the quarterly generation swap (when due and the
  // pointed generation is GC-quiet) plus the collect fan-out over every
  // non-pointed `gen-` collection -- revoke, digest, delete. Chained behind
  // the registryReady tail (so a sibling re-mint above lands first),
  // durable-only for free (`registryReady` only exists then), and strictly
  // best-effort like the sweeps beside it: a failed pass never fails the
  // login, and the next durable login resumes from durable state alone. The
  // remote-direct popup deliberately does not run it: a popup visit is a
  // constrained, latency-sensitive context, and the next top-level durable
  // login sweeps the same durable state.
  if (session.registryReady && !remoteDirectStorage) {
    session.clientAnnexGcSweep = session.registryReady
      .catch(() => {})
      .then(() =>
        sweepClientAnnexGenerations({
          session,
          ...(ladderSeed !== undefined ? { ladderSeed } : {})
        })
      )
      .catch((err): null => {
        log.warn('The annex GC sweep failed', { err })
        return null
      })
  }

  // Settle the chain for its awaiters: a provisioning rejection skipped
  // every stage above (the rejection propagated through their `.then`s),
  // and this catch keeps `registryReady` itself from rejecting, so a gated
  // ceremony on an abandoned session resolves instead of hanging on an
  // unsettled rejection.
  if (session.registryReady) {
    session.registryReady = session.registryReady.catch(() => {})
  }
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
 * @param [options.remoteDirectStorage] {boolean}   route credential + history
 *   operations straight to the remote WAS collections; default false
 * @param [options.provisionStorage] {boolean}   fire `ensureUserCollections`
 *   from session creation and expose it as `session.storageReady`; default
 *   true
 * @param [options.signal] {AbortSignal}   aborts the WebAuthn ceremony
 * @param [options.rememberBrowser] {boolean}   the explicit durability input,
 *   exactly as on `loginWithPassphrase`
 * @param [options.credential] {UnlockCredential}   an already-derived unlock
 *   credential for this passkey's PRF output, which SKIPS the PRF assertion
 *   ceremony -- the passkey signup's login half passes it so one signup runs
 *   one WebAuthn ceremony
 * @returns {Promise<{ session: Session | null, userExists: boolean }>}
 */
export async function loginWithPasskey({
  idb,
  remoteDirectStorage = false,
  provisionStorage = true,
  signal,
  rememberBrowser,
  credential
}: {
  idb?: IDBFactory
  remoteDirectStorage?: boolean
  provisionStorage?: boolean
  signal?: AbortSignal
  rememberBrowser?: boolean
  credential?: UnlockCredential
} = {}): Promise<{ session: Session | null; userExists: boolean }> {
  let derived: UnlockCredential | undefined = credential
  let prfOutput: Uint8Array | undefined
  if (!derived) {
    ;({ prfOutput } = await assertPasskeyPrf({ signal }))
  }

  // The same bounded stale-record retry as the passphrase path: the retry
  // re-routes with the already-derived credential, so the one WebAuthn tap
  // above is never repeated.
  for (let staleRetries = 0; ; staleRetries++) {
    const routed = await routeUnlockLogin({
      ...(prfOutput !== undefined ? { secret: prfOutput } : {}),
      kdf: PASSKEY_KDF,
      credential: derived,
      idb,
      remoteDirectStorage,
      rememberBrowser
    })
    if (routed.durability === 'transient') {
      const found = await fetchTransientKeyring({
        credential: routed.credential,
        accountLogPinStore: routed.persistence.logPins
      })
      if (!found) {
        return { session: null, userExists: false }
      }
      return transientSessionFromKeyringHit({
        found,
        type: 'passkey',
        persistence: routed.persistence,
        credential: routed.credential
      })
    }
    derived = routed.credential ?? derived

    let found = await fetchKeyring({
      ...(prfOutput !== undefined ? { secret: prfOutput } : {}),
      kdf: PASSKEY_KDF,
      idb,
      mintManageCapability: true,
      ...(derived ? { credential: derived } : {})
    })
    if (!found) {
      return { session: null, userExists: false }
    }

    // The durable resume entry, exactly as on the passphrase path: a
    // standing record whose pointer names no did:webvh yet (a passkey
    // signup torn before the establishment's re-bind) is healed and
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
          secret: prfOutput as Uint8Array,
          kdf: PASSKEY_KDF
        }))
      found = await healUnpromotedRememberedAccount({
        found,
        credential: derived,
        type: 'passkey',
        idb
      })
    }

    try {
      return await sessionFromKeyringHit({
        found,
        type: 'passkey',
        remoteDirectStorage,
        provisionStorage,
        idb
      })
    } catch (err) {
      if (!(err instanceof StaleClientKeyRecordError)) {
        throw err
      }
      if (staleRetries > 0) {
        throw new KeyringRecordUnusableError({ cause: err })
      }
    }
  }
}
