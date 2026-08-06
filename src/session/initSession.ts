/**
 * Session bootstrap. Builds a did:key identity from this client's locally
 * minted 32-byte seed via CapabilityAgent, instantiates a ZcapClient for
 * signing storage requests, and initializes the StorageManager (local or
 * remote depending on env vars). The resulting Session object is stored in
 * authStore. A passphrase (or passkey) login resolves through the keyring:
 * the unlock identity locates the account (the encrypted account pointer) and
 * unwraps this client's local key set -- it never reconstructs the account
 * from the secret, so a client with no local key set can locate the account
 * but not act (not enrolled).
 */
import type { CollectionEncryption } from '@interop/was-client'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { agentsFromSeed } from '@interop/wallet-core/identity'
import { deriveSpaceId } from '@interop/was-client/sync'
import type { ControllerProfile, Session, User } from '@/types/auth'
import { KMS_SERVER_URL, PASSKEY_KDF, WAS_SERVER_URL } from '@/app.config'
import { ensureKeystore } from '@/lib/kms'
import { assertPasskeyPrf } from '@/lib/passkey'
import {
  isWebvhDid,
  webvhCapabilityAgent,
  webvhZcapClient,
  type ClientWebvhUpdateKeys
} from '@interop/wallet-core/webvh'
import {
  mintUserKey,
  userKeyRosterDescriptorStore,
  userKeyRosterEpochsSigner,
  userKeyVaultKeys,
  type UserKey,
  type UserKeyRosterReadResult
} from '@interop/wallet-core/keys'
import {
  checkUserKeyRosterAtLogin as sharedCheckUserKeyRosterAtLogin,
  convergeUserKeyRosterToAccount
} from '@interop/wallet-core/clients'
import { cascadeCollectionsToUserKey } from '@/session/userKeyCascade'
import { loadUserKeyEpochPin, saveUserKeyEpochPin } from '@/lib/sessionKey'
import { StorageManager } from '@/stores/storageManager'
import { fetchKeyring, KeyringRecordUnusableError } from '@/session/keyring'
import type {
  AccountPointer,
  UnlockIdentity
} from '@interop/wallet-core/keyring'
import type {
  KeyringFetchResult,
  PersistableClientKeys
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

  // The direct user key roster read (`key-map/user-key.json`): confirms the cached user key
  // current, or -- on an epoch mismatch (a rotation by another client) --
  // delivers the fresh user key, which the session adopts and `persistClientKeys`
  // writes into this client's client-key record. Runs before the storage clients are built, since the vault
  // keys below must be the CURRENT user key's. The read result is retained: its
  // descriptor feeds the cascade-completion sweep fired further down.
  let activeUserKey = userKey
  let rosterRead: UserKeyRosterReadResult | null = null
  const spaceId = accountPointer?.spaceId ?? deriveSpaceId(keyAgent.id)
  if (userKey && !isGuest && WAS_SERVER_URL && accountPointer?.did) {
    rosterRead = await checkUserKeyRosterAtLogin({
      zcapClient: sessionZcapClient,
      pointer: { ...accountPointer, did: accountPointer.did },
      spaceId,
      userKey,
      clientKeyAgreementKey: keyAgreementKey,
      idb
    })
    if (rosterRead?.rotated) {
      activeUserKey = rosterRead.userKey
      await persistClientKeys?.({ userKey: rosterRead.userKey })
    }
  }

  // Recipient zero becomes the user key: when the account carries one, the vault
  // key pair the storage layer consumes is the user key's KAK + resolver in place
  // of the seed-derived pair. The rest of the profile (signing identity,
  // zcap client) is untouched.
  const vaultKeys = activeUserKey
    ? userKeyVaultKeys({ userKey: activeUserKey })
    : { keyAgreementKey, keyResolver }

  // Ensure a KMS keystore exists for this controller (list-by-controller,
  // create on first login) and bind a KeystoreAgent to it. Guests skip the
  // KMS entirely, as they skip WAS. This provisioning round trip runs
  // concurrently with storage init below -- nothing in the storage bootstrap
  // depends on the keystore, so the two independent trips need not be
  // serialized. Failure is non-fatal for now: no wallet feature depends on
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
              zcapClient: sessionZcapClient,
              spaceId,
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
          // sweep moved any collection's current epoch (`installed` or
          // `rotated` -- an escrow leaves the current epoch in place), refresh
          // the descriptors and ciphers so the rest of the session seals
          // writes under the fresh epoch instead of the retired one.
          if (
            Object.values(result.outcomes).some(
              outcome => outcome === 'installed' || outcome === 'rotated'
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
 * @param options.zcapClient {ZcapClient}   the session's signing client
 * @param options.spaceId {string}   the data Space id
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
  zcapClient,
  spaceId,
  userKey,
  descriptor,
  clientKeyAgreementKey,
  idb,
  persistClientKeys
}: {
  session: Session
  pointer?: AccountPointer
  zcapClient: ZcapClient
  spaceId: string
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
  const { userKey: convergedUserKey, descriptor: convergedDescriptor } =
    await convergeUserKeyRosterToAccount({
      pointer: {
        did: pointer.did,
        spaceId: pointer.spaceId,
        host: pointer.host
      },
      store: userKeyRosterDescriptorStore({
        storageServerUrl: WAS_SERVER_URL,
        zcapClient,
        spaceId
      }),
      userKey,
      descriptor,
      clientKeyAgreementKey,
      signEpochs: userKeyRosterEpochsSigner({ keyAgent }),
      pinnedEpochId: await loadUserKeyEpochPin({ spaceId, idb }),
      // Adoption is app-side: persisted for the next login, pinned, and
      // swapped into the live session -- all before the collection fan-out
      // runs against it.
      onUserKeyAdopted: async ({
        userKey: adopted,
        latestEpochId,
        descriptor: read
      }) => {
        await saveUserKeyEpochPin({
          spaceId,
          epochId: latestEpochId,
          epochIds: (read.epochs ?? []).map(epoch => epoch.id),
          idb
        })
        await persistClientKeys?.({ userKey: adopted })
        const vaultKeys = userKeyVaultKeys({ userKey: adopted })
        session.profile.userKey = adopted
        session.profile.keyAgreementKey = vaultKeys.keyAgreementKey
        session.profile.keyResolver = vaultKeys.keyResolver
        await session.storage.adoptRotatedVaultKeys(vaultKeys)
      }
    })
  return { userKey: convergedUserKey, rosterDescriptor: convergedDescriptor }
}

/**
 * The login-time user key roster check: one direct compare-and-swap-style read of
 * `key-map/user-key.json` with the session's root signing key, before any storage
 * client exists. Returns the full roster read -- `rotated` marks whether the
 * roster's current epoch differs from the cached user key (a rotation by another
 * client), and the descriptor feeds the cascade-completion sweep -- or
 * `null` when no roster exists yet (an account whose provisioning has not
 * created it -- the idempotent ensure will). Either way the served roster is
 * authenticated (`epochsMac`) and checked against the locally pinned
 * latest-seen epoch, and the pin advances to the epoch just seen.
 *
 * Failure semantics: the three roster refusals -- a rolled-back/replayed
 * roster, a configuration that fails authentication, and a current epoch
 * this client cannot unwrap -- rethrow and refuse the login (the same
 * continuity class as a substituted account pointer). Anything else (an
 * unreachable server, offline) warns and returns `null`, so offline logins
 * keep working from the cached user key.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the session's root signing client
 * @param options.spaceId {string}   the data Space id
 * @param options.userKey {UserKey}   the cached per-user key
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) KAK -- its roster entry
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<UserKeyRosterReadResult | null>}   the roster read, or null
 */
async function checkUserKeyRosterAtLogin({
  zcapClient,
  pointer,
  spaceId,
  userKey,
  clientKeyAgreementKey,
  idb
}: {
  zcapClient: ZcapClient
  pointer: AccountPointer & { did: string }
  spaceId: string
  userKey: UserKey
  clientKeyAgreementKey: IKeyAgreementKey
  idb?: IDBFactory
}): Promise<UserKeyRosterReadResult | null> {
  return await sharedCheckUserKeyRosterAtLogin({
    store: userKeyRosterDescriptorStore({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient,
      spaceId
    }),
    pointer: {
      did: pointer.did,
      spaceId: pointer.spaceId,
      host: pointer.host
    },
    userKey,
    clientKeyAgreementKey,
    pinnedEpochId: await loadUserKeyEpochPin({ spaceId, idb }),
    // The pin advances to the epoch just authenticated, atomically with the
    // key that authenticated it.
    onRosterRead: async ({ latestEpochId, descriptor }) => {
      await saveUserKeyEpochPin({
        spaceId,
        epochId: latestEpochId,
        epochIds: (descriptor.epochs ?? []).map(epoch => epoch.id),
        idb
      })
    }
  })
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
 *   exists) but this client holds no key set -- a fresh browser. Unlocking is
 *   no longer sufficient to BE the account: nothing about the account is
 *   derivable from the passphrase, so until this client is enrolled it cannot
 *   act. Returns `{ session: null, userExists: true }` and the caller
 *   surfaces the not-enrolled guidance.
 * - **Miss**: no keyring anywhere, so there is no account. Returns
 *   `{ session: null, userExists: false }` and the caller routes to signup.
 *
 * `fetchKeyring` rethrows when the remote could not be reached (so the
 * caller's storage-unreachable handling fires rather than misreading it as "no
 * account"), throws `AccountPointerChangedError` on a continuity refusal, and
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
 * @param [options.unlock] {UnlockIdentity}   an already-derived unlock
 *   identity for this passphrase, so a caller that has just unlocked (the
 *   enrollment ceremony) does not run the KDF again
 * @returns {Promise<{ session: Session | null, userExists: boolean }>}
 */
export async function loginWithPassphrase({
  passphrase,
  email,
  idb,
  remoteDirectStorage = false,
  provisionStorage = true,
  unlock
}: {
  passphrase: string
  email?: string
  idb?: IDBFactory
  remoteDirectStorage?: boolean
  provisionStorage?: boolean
  unlock?: UnlockIdentity
}): Promise<{ session: Session | null; userExists: boolean }> {
  const found = await fetchKeyring({
    passphrase,
    idb,
    mintManageCapability: true,
    ...(unlock ? { unlock } : {})
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
    // holds no key set for it: the passphrase can no longer reconstruct the
    // account. The caller surfaces the not-enrolled state.
    return { session: null, userExists: true }
  }
  const { session, userExists } = await initSessionFromSeed({
    seed: found.clientKeys.clientSeed,
    userKey: found.clientKeys.userKey,
    webvhUpdateKeys: found.clientKeys.webvhUpdateKeys,
    persistClientKeys: found.persistClientKeys,
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
  const boundController = found.clientKeys.controller ?? session.user.id
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
 * secret and its KDF, including the "located, not enrolled" state
 * (`{ session: null, userExists: true }`) on a client holding no key set.
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
