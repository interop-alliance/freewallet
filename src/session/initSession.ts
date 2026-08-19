/**
 * Session bootstrap. Builds a did:key identity from this client's locally
 * minted 32-byte seed via CapabilityAgent, instantiates a ZcapClient for
 * signing storage requests, and initializes the StorageManager (local or
 * remote depending on env vars). The resulting Session object is stored in
 * authStore. A passphrase (or passkey) login resolves through the keyring:
 * the unlock identity locates the account (the encrypted account pointer) and
 * unwraps this client's local key set. On a fresh browser holding no key set,
 * a STANDING credential -- one whose unlock record carries the bridge
 * delegation and update-key ladder seed -- self-enrolls an ordinary client
 * in place (loud log entries first, then the first roster read through the
 * credential's standing wrap) and the login proceeds enrolled; a plain
 * pointer record still surfaces the not-enrolled state and the
 * connect-another-wallet ceremony.
 */
import type { CollectionEncryption } from '@interop/was-client'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { agentsFromSeed } from '@interop/wallet-core/identity'
import type { ControllerProfile, Session, User } from '@/types/auth'
import { KMS_SERVER_URL, PASSKEY_KDF, WAS_SERVER_URL } from '@/app.config'
import { ensureKeystore } from '@/lib/kms'
import { assertPasskeyPrf } from '@/lib/passkey'
import {
  delegatedClientsDelegationSpaceId,
  isWebvhDid,
  mintDelegatedClientsDelegation,
  webvhCapabilityAgent,
  webvhZcapClient,
  type ClientWebvhUpdateKeys,
  type ICapabilityAgent
} from '@interop/wallet-core/webvh'
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
import { swapSessionVaultKeys } from '@/session/userKeyAdoption'
import { cascadeCollectionsToUserKey } from '@/session/userKeyCascade'
import { sweepStrandedAppKeys } from '@/session/appKeySweep'
import {
  loadUserKeyEpochPin,
  savePinFromDescriptor,
  sessionLogPinStore
} from '@/lib/sessionKey'
import { StorageManager } from '@/stores/storageManager'
import { fetchKeyring, KeyringRecordUnusableError } from '@/session/keyring'
import {
  canSelfEnroll,
  selfEnrollStandingClient
} from '@/session/standingUnlock'
import {
  delegateLogWrite,
  delegationProofKeyId,
  zcapExpiring
} from '@interop/wallet-core/recovery'
import { attributeLadderRung } from '@interop/wallet-core/unlock'
import { refreshStandingDelegationFields } from '@/session/unlockMethods'
import { verifiedAccountLog } from '@/session/verifiedLog'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import type {
  KeyringFetchResult,
  PersistableClientKeys,
  UnlockCredential
} from '@/session/keyring'

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
 * @returns {Promise<{ session: Session, userExists: boolean }>}
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
  idb
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
}) {
  const { keyAgent, zcapClient, keyAgreementKey, keyResolver } =
    await agentsFromSeed({ seed })

  // Once the account pointer names a did:webvh, the Space controller has
  // been promoted: every data-Space request must be signed with this
  // client's verification method in the did:webvh document
  // (`<did:webvh>#<multibase>`), not its did:key. Same key, promoted keyId.
  const accountDid = accountPointer?.did
  const sessionZcapClient = isWebvhDid(accountDid)
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
  // page surfaces the unprovisioned state.
  const keystorePromise =
    !isGuest && KMS_SERVER_URL
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
          console.warn('KMS keystore provisioning failed:', err)
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
  // to read.
  let activeUserKey = userKey
  let rosterRead: UserKeyRosterReadResult | null = null
  let userKeyPersistFailed = false
  if (
    userKey &&
    !isGuest &&
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
      idb
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
        console.warn('Could not persist the rotated user key:', err)
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
    keyAgreementKey: vaultKeys.keyAgreementKey,
    keyResolver: vaultKeys.keyResolver,
    // This client's own (identity) KAK, distinct from the user-key-backed vault
    // KAK above: its entry in the user key wrap-set roster.
    clientKeyAgreementKey: keyAgreementKey,
    ...(activeUserKey ? { userKey: activeUserKey } : {}),
    ...(webvhUpdateKeys ? { clientWebvhKeys: webvhUpdateKeys } : {}),
    ...(persistClientKeys ? { persistClientKeys } : {}),
    ...(accountPointer ? { accountPointer } : {})
  }
  if (!isGuest) {
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
  if (provisionStorage) {
    const storageReady = storage.ensureUserCollections({ user, profile, idb })
    session.storageReady = storageReady

    // The app-key sweep: app keys now live in their own `app-connections`
    // collection, so any left in `private-credentials` by an earlier version
    // are deleted here rather than migrated -- their seeds must not stay
    // reachable from the credential-wide surfaces (a public link, a share of
    // the credentials collection). Chained behind provisioning and strictly
    // best-effort, like the cascade sweep below: a failed sweep never fails
    // the login, and the next login runs it again.
    session.appKeySweep = storageReady
      .catch(() => {})
      .then(() => sweepStrandedAppKeys({ storage }))
      .catch((err): null => {
        console.warn('The stranded app-key sweep failed:', err)
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
              idb,
              persistClientKeys
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
          console.warn('The user key cascade-completion sweep failed:', err)
          return null
        })
    }
  }

  return { session, userExists }
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
 * @param [options.idb] {IDBFactory}
 * @param [options.persistClientKeys] {function}   re-wraps this client's
 *   client-key record with the adopted user key
 * @returns {Promise<{ userKey: UserKey, rosterDescriptor: CollectionEncryption }>}
 *   the key and roster descriptor the collection fan-out should use
 */
async function convergeRosterToDocument({
  session,
  pointer,
  userKey,
  descriptor,
  clientKeyAgreementKey,
  idb,
  persistClientKeys
}: {
  session: Session
  pointer?: AccountPointer
  userKey: UserKey
  descriptor: CollectionEncryption
  clientKeyAgreementKey: IKeyAgreementKey
  idb?: IDBFactory
  persistClientKeys?: (changes: PersistableClientKeys) => Promise<void>
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
      store: sessionRosterStore({ profile: session.profile, idb }),
      userKey,
      descriptor,
      clientKeyAgreementKey,
      pinnedEpochId: await loadUserKeyEpochPin({ accountDid, idb }),
      accountLogPinStore: sessionLogPinStore({ idb }),
      // Adoption is app-side: persisted for the next login, pinned, and
      // swapped into the live session -- all before the collection fan-out
      // runs against it.
      onUserKeyAdopted: async ({
        userKey: adopted,
        latestEpochId,
        descriptor: read
      }) => {
        await savePinFromDescriptor({
          accountDid,
          epochId: latestEpochId,
          descriptor: read,
          idb
        })
        await persistClientKeys?.({ userKey: adopted })
        await swapSessionVaultKeys({ session, userKey: adopted })
      }
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
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<object>}   the roster read (or null), and whether the
 *   epoch-pin persist failed
 */
async function checkUserKeyRosterAtLogin({
  zcapClient,
  keyAgent,
  pointer,
  userKey,
  clientKeyAgreementKey,
  idb
}: {
  zcapClient: ZcapClient
  keyAgent: ICapabilityAgent
  pointer: AccountPointer & { did: string }
  userKey: UserKey
  clientKeyAgreementKey: IKeyAgreementKey
  idb?: IDBFactory
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
      idb
    }),
    userKey,
    clientKeyAgreementKey,
    pinnedEpochId: await loadUserKeyEpochPin({ accountDid, idb }),
    // The pin advances to the epoch just authenticated. A throw from here
    // propagates out of the shared check (it is no longer swallowed into the
    // offline null path), so the failure is caught HERE, where its meaning
    // is known: the read itself succeeded, only the local persist did not.
    onRosterRead: async ({ latestEpochId, descriptor }) => {
      try {
        await savePinFromDescriptor({
          accountDid,
          epochId: latestEpochId,
          descriptor,
          idb
        })
      } catch (err) {
        persistFailed = true
        console.warn('Could not persist the user key epoch pin:', err)
      }
    }
  })
  return { read, persistFailed }
}

/**
 * Passphrase login (keyring v2). The keyring is the only login path: the
 * passphrase derives an unlock identity that locates the account and unwraps
 * this client's local key set. Three branches:
 *
 * - **Enrolled hit**: the keyring record was found AND this client holds a
 *   key set under the passphrase's unlock method; the session is built from
 *   the local client seed (`initSessionFromSeed`). The record's controller is
 *   sanity-checked against the derived did:key -- a mismatch means a corrupt
 *   record (or a foreign key set) and throws `KeyringRecordUnusableError`
 *   rather than proceeding under the wrong identity (the same error
 *   `fetchKeyring` throws for a record that fails to unwrap, so callers
 *   surface one "keyring record unusable" state). Returns
 *   `{ session, userExists }` -- a hit whose data Space
 *   is missing legitimately reports `userExists: false` (a half-finished
 *   signup), and the caller sends it to signup, which rebinds.
 * - **Located, not enrolled**: the keyring record was found (the account
 *   exists) but this client holds no key set -- a fresh browser. A standing
 *   record self-enrolls this browser right here and the login proceeds as an
 *   enrolled hit; only a plain pointer record (pre-promotion, no-WAS, or a
 *   remote-direct popup session) returns `{ session: null, userExists:
 *   true }`, and the caller surfaces the not-enrolled guidance.
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
 * @returns {Promise<{ session: Session | null, userExists: boolean }>}
 */
export async function loginWithPassphrase({
  passphrase,
  email,
  idb,
  remoteDirectStorage = false,
  provisionStorage = true,
  credential
}: {
  passphrase: string
  email?: string
  idb?: IDBFactory
  remoteDirectStorage?: boolean
  provisionStorage?: boolean
  credential?: UnlockCredential
}): Promise<{ session: Session | null; userExists: boolean }> {
  const found = await fetchKeyring({
    passphrase,
    idb,
    mintManageCapability: true,
    ...(credential ? { credential } : {})
  })

  if (!found) {
    return { session: null, userExists: false }
  }

  return sessionFromKeyringHit({
    found,
    type: 'passphrase',
    email,
    remoteDirectStorage,
    provisionStorage,
    idb
  })
}

/**
 * Shared tail of the keyring login paths: builds the session from a keyring
 * hit's local client key set and sanity-checks the recovered controller
 * against the derived did:key. A mismatch means a corrupt record (or a
 * foreign key set) and throws `KeyringRecordUnusableError` rather than
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
 * @returns {Promise<{ session: Session | null, userExists: boolean }>}
 */
async function sessionFromKeyringHit({
  found,
  type,
  email,
  remoteDirectStorage = false,
  provisionStorage = true,
  idb
}: {
  found: KeyringFetchResult
  type: 'passphrase' | 'passkey'
  email?: string
  remoteDirectStorage?: boolean
  provisionStorage?: boolean
  idb?: IDBFactory
}): Promise<{ session: Session | null; userExists: boolean }> {
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
    // log. Without standing authority (a plain pointer record -- the
    // pre-promotion or no-WAS reduced path) the caller surfaces the
    // not-enrolled state and offers the connect-another-wallet ceremony.
    if (remoteDirectStorage || !canSelfEnroll({ found })) {
      return { session: null, userExists: true }
    }
  }
  const enrolled = found.clientKeys
    ? undefined
    : await selfEnrollStandingClient({ found, idb })
  const clientKeys = found.clientKeys ?? enrolled!.clientKeys
  const persistClientKeys =
    enrolled?.persistClientKeys ?? found.persistClientKeys
  const { session, userExists } = await initSessionFromSeed({
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
  // The local key set must have been bound for THIS account: an enrolled
  // client's record carries the controller it was bound under; a legacy
  // record (pre-enrollment) was necessarily written by the first client,
  // whose own did:key is the controller. Either way a mismatch means the
  // keyring record was swapped for another account's (or the key set is
  // foreign) -- refuse rather than proceed under the wrong identity.
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

  // The delegation-expiry self-refresh: a standing credential's own login
  // re-mints its bridge delegation -- and the companion-Space sibling, where
  // the record carries one -- when either is expired or inside the renewal
  // window (the same annual clock and shared predicate as the recovery
  // delegations), so neither lapses silently between revocations. One pass
  // reseals both. Best-effort, behind provisioning.
  const rebindStandingRecord = found.rebindStandingRecord
  const standingDelegation = found.standing?.delegation
  const standingDelegatedClients = found.standing?.delegatedClients
  const standingClientDid = found.standingClient?.clientDid
  if (
    session.storageReady &&
    rebindStandingRecord &&
    standingDelegation &&
    standingClientDid &&
    (zcapExpiring({
      expires: (standingDelegation as { expires?: string }).expires
    }) ||
      (!!standingDelegatedClients &&
        zcapExpiring({
          expires: (standingDelegatedClients as { expires?: string }).expires
        })))
  ) {
    const unlockSpaceId = found.unlockSpaceId
    session.storageReady = session.storageReady.then(async () => {
      try {
        const pointer = session.profile.accountPointer
        if (!pointer || !isWebvhDid(pointer.did)) {
          return
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
          const companionSpaceId = delegatedClientsDelegationSpaceId({
            delegation: standingDelegatedClients
          })
          if (companionSpaceId) {
            delegatedClients = await mintDelegatedClientsDelegation({
              zcapClient: session.profile.zcapClient,
              wasServerUrl: pointer.host,
              companionSpaceId,
              controller: standingClientDid
            })
          }
        }
        await rebindStandingRecord({
          delegation,
          ...(delegatedClients ? { delegatedClients } : {})
        })
        await refreshStandingDelegationFields({
          session,
          unlockSpaceId,
          delegationKeyId: delegationProofKeyId(delegation),
          delegationExpires: (delegation as { expires?: string }).expires,
          ...(delegatedClients
            ? {
                delegatedClientsKeyId: delegationProofKeyId(delegatedClients),
                delegatedClientsExpires: (
                  delegatedClients as { expires?: string }
                ).expires
              }
            : {}),
          idb
        })
      } catch (err) {
        console.warn(
          'Could not refresh the expiring standing delegations; the ' +
            'next login retries:',
          err
        )
      }
    })
  }

  // After a self-enrollment climbed the update-key ladder, refresh the
  // registry entry's recorded rung to the freshly committed one, so the
  // revocation edit's latent-hash attribution stays answerable. Best-effort:
  // a stale rung only makes that attribution fail closed later, never
  // silently misattribute.
  const enrolledLadderSeed = enrolled ? found.standing?.ladderSeed : undefined
  if (session.storageReady && enrolledLadderSeed) {
    const unlockSpaceId = found.unlockSpaceId
    session.storageReady = session.storageReady.then(async () => {
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
            updateKeyMultibase: rung.keyMultibase,
            idb
          })
        }
      } catch (err) {
        console.warn(
          'Could not refresh the recorded ladder rung after self-enrolling; ' +
            'a later disconnect attribution fails closed instead:',
          err
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
    session.storageReady &&
    persistAccountPointer &&
    found.pointer &&
    !isWebvhDid(found.pointer.did)
  ) {
    const staleServerPointer = found.pointer
    session.storageReady = session.storageReady.then(async () => {
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
        console.warn(
          'Could not backfill the did:webvh pointer and promote the ' +
            'controller; the next login retries:',
          err
        )
      }
    })
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
 * @returns {Promise<{ session: Session | null, userExists: boolean }>}
 */
export async function loginWithPasskey({
  idb,
  remoteDirectStorage = false,
  provisionStorage = true,
  signal
}: {
  idb?: IDBFactory
  remoteDirectStorage?: boolean
  provisionStorage?: boolean
  signal?: AbortSignal
} = {}): Promise<{ session: Session | null; userExists: boolean }> {
  const { prfOutput } = await assertPasskeyPrf({ signal })

  const found = await fetchKeyring({
    secret: prfOutput,
    kdf: PASSKEY_KDF,
    idb,
    mintManageCapability: true
  })
  if (!found) {
    return { session: null, userExists: false }
  }

  return sessionFromKeyringHit({
    found,
    type: 'passkey',
    remoteDirectStorage,
    provisionStorage,
    idb
  })
}
