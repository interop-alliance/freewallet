/**
 * Session bootstrap. Derives a did:key identity from the user's passphrase
 * via CapabilityAgent, instantiates a ZcapClient for signing storage requests,
 * and initializes the StorageManager (local or remote depending on env vars).
 * The resulting Session object is stored in authStore.
 */
import { agentsFromSeed } from '@interop/wallet-core/identity'
import type { ControllerProfile, Session, User } from '@/types/auth'
import { KMS_SERVER_URL, PASSKEY_KDF } from '@/app.config'
import { ensureKeystore } from '@/lib/kms'
import { assertPasskeyPrf } from '@/lib/passkey'
import { StorageManager } from '@/stores/storageManager'
import { fetchKeyringSeed, KeyringRecordUnusableError } from '@/session/keyring'
import type { KeyringFetchResult } from '@/session/keyring'

/**
 * Creates a random guest session.
 */
export async function initGuestSession() {
  const randomGuestSecret = new Uint8Array(32)
  crypto.getRandomValues(randomGuestSecret)

  const guestEmail = 'guest@example.com'

  // The random 32 bytes are used directly as the data seed (no salted-hash
  // step). A guest identity is ephemeral and never keyring-bound, so the
  // derivation change relative to a passphrase login is harmless here.
  // Guest is a new-wallet flow: `provisionNewWallet` owns collection
  // provisioning (plus the initial history + welcome credential), so session
  // creation must not also fire it.
  const { session } = await initSessionFromSeed({
    seed: randomGuestSecret,
    email: guestEmail,
    isGuest: true,
    provisionStorage: false
  })

  return { session }
}

/**
 * Initializes a session (user, profile with zcap agents, storage manager) from
 * an already-derived 32-byte data seed. This is the shared core behind the
 * keyring path (`loginWithPassphrase`, `SignupPage`) and the guest bootstrap:
 * everything downstream of "data seed in hand" -- KMS keystore provisioning,
 * storage clients -- is identical regardless of how the seed was obtained.
 *
 * For non-guest sessions the seed is carried on `profile.dataSeed` (so Settings
 * can re-bind the passphrase); guests skip it (a guest identity is ephemeral
 * and never keyring-bound).
 *
 * Collection provisioning is folded in here rather than left as a separate
 * post-login step at every callsite: when `provisionStorage` is set (the
 * default -- returning-login and CHAPI-popup flows) the session's
 * `ensureUserCollections` is *fired but not awaited* and its promise exposed as
 * `session.storageReady`, so a caller can run a hot read concurrently with
 * provisioning yet still `await session.storageReady` when it needs the
 * collections ready. The new-wallet flows (signup, guest) pass
 * `provisionStorage: false`: their provisioning is a deliberately ordered
 * sequence owned by `provisionNewWallet` (signup must bind the passphrase
 * before the data Space is created), so session creation must not fire it.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   the 32-byte data seed
 * @param [options.email] {string}
 * @param [options.isGuest] {boolean}
 * @param [options.remoteDirectStorage] {boolean}   route credential + history
 *   operations straight to the remote WAS collections (the CHAPI popup, whose
 *   local IndexedDB is third-party partitioned); default false
 * @param [options.provisionStorage] {boolean}   fire `ensureUserCollections`
 *   from session creation and expose it as `session.storageReady`; default
 *   true. Set false for the new-wallet flows that provision explicitly.
 * @returns {Promise<{ session: Session, userExists: boolean }>}
 */
export async function initSessionFromSeed({
  seed,
  email,
  isGuest = false,
  remoteDirectStorage = false,
  provisionStorage = true
}: {
  seed: Uint8Array
  email?: string
  isGuest?: boolean
  remoteDirectStorage?: boolean
  provisionStorage?: boolean
}) {
  const { keyAgent, zcapClient, keyAgreementKey, keyResolver } =
    await agentsFromSeed({ seed })

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
          zcapClient
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
    zcapClient,
    keyAgreementKey,
    keyResolver
  }
  if (!isGuest) {
    profile.dataSeed = seed
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
    session.storageReady = storage.ensureUserCollections({ user, profile })
  }

  return { session, userExists }
}

/**
 * Passphrase login (keyring v2). The keyring is the only login path: the
 * passphrase derives an unlock identity that locates and unwraps the account's
 * real data seed. Two branches:
 *
 * - **Keyring hit**: the passphrase's unlock identity located a keyring record;
 *   the session is built from the unwrapped data seed (`initSessionFromSeed`).
 *   The unwrapped controller is sanity-checked against the derived did:key -- a
 *   mismatch means a corrupt record and throws `KeyringRecordUnusableError`
 *   rather than proceeding under the wrong identity (the same error
 *   `fetchKeyringSeed` throws for a record that fails to unwrap, so callers
 *   surface one "keyring record unusable" state). Returns
 *   `{ session, userExists }` -- a hit whose data Space
 *   is missing legitimately reports `userExists: false` (a half-finished
 *   signup), and the caller sends it to signup, which rebinds.
 * - **Miss**: no keyring anywhere, so there is no account. Returns
 *   `{ session: null, userExists: false }` and the caller routes to signup.
 *
 * `fetchKeyringSeed` rethrows when the remote could not be reached (so the
 * caller's storage-unreachable handling fires rather than misreading it as "no
 * account"), and all storage/network errors from session init propagate
 * unchanged.
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
 * @returns {Promise<{ session: Session | null, userExists: boolean }>}
 */
export async function loginWithPassphrase({
  passphrase,
  email,
  idb,
  remoteDirectStorage = false,
  provisionStorage = true
}: {
  passphrase: string
  email?: string
  idb?: IDBFactory
  remoteDirectStorage?: boolean
  provisionStorage?: boolean
}): Promise<{ session: Session | null; userExists: boolean }> {
  const found = await fetchKeyringSeed({
    passphrase,
    idb,
    mintManageCapability: true
  })

  if (!found) {
    return { session: null, userExists: false }
  }

  return sessionFromKeyringHit({
    found,
    type: 'passphrase',
    email,
    remoteDirectStorage,
    provisionStorage
  })
}

/**
 * Shared tail of the keyring login paths: builds the session from an unwrapped
 * keyring hit and sanity-checks the recovered controller against the derived
 * did:key. A mismatch means a corrupt record and throws
 * `KeyringRecordUnusableError` rather than proceeding under the wrong
 * identity. The session email prefers the caller's fresh value (the login
 * form) over the one carried by the keyring record.
 *
 * Records which unlock method produced this full session on
 * `profile.unlockMethod` (its type, unlock Space id, and the management zcap
 * `fetchKeyringSeed` minted), so Settings can backfill the unlock-methods
 * registry without re-prompting for the secret.
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}   the unwrapped keyring hit
 * @param options.type {'passphrase' | 'passkey'}   the method that unlocked
 * @param [options.email] {string}   caller-supplied email, when any
 * @param [options.remoteDirectStorage] {boolean}
 * @param [options.provisionStorage] {boolean}
 * @returns {Promise<{ session: Session, userExists: boolean }>}
 */
async function sessionFromKeyringHit({
  found,
  type,
  email,
  remoteDirectStorage = false,
  provisionStorage = true
}: {
  found: KeyringFetchResult
  type: 'passphrase' | 'passkey'
  email?: string
  remoteDirectStorage?: boolean
  provisionStorage?: boolean
}): Promise<{ session: Session; userExists: boolean }> {
  const { session, userExists } = await initSessionFromSeed({
    seed: found.seed,
    email: email ?? found.email,
    remoteDirectStorage,
    provisionStorage
  })
  if (session.user.id !== found.controller) {
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
  // The profile object is plain; stamp the unlock method that produced this
  // session so Settings can backfill the registry without the secret.
  session.profile.unlockMethod = {
    type,
    unlockSpaceId: found.unlockSpaceId,
    manageCapability: found.manageCapability
  }
  return { session, userExists }
}

/**
 * Passkey login. Runs the one-tap PRF assertion ceremony (the browser account
 * picker scopes to this RP's discoverable credentials), derives the unlock
 * identity from the PRF output under the passkey KDF, and resolves it through
 * the keyring exactly like the passphrase path -- the two differ only in the
 * secret and its KDF. The email (absent from any login form here) is
 * recovered from the keyring record when one was bound.
 *
 * Ceremony failures propagate as the typed errors from `src/lib/passkey.ts`
 * (`PasskeyCancelledError`, `PasskeyPrfUnsupportedError`); a keyring miss --
 * a passkey with no bound wallet, e.g. one orphaned by a revocation --
 * returns `{ session: null, userExists: false }`. `fetchKeyringSeed`
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

  const found = await fetchKeyringSeed({
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
    provisionStorage
  })
}
