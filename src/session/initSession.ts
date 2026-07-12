/**
 * Session bootstrap. Derives a did:key identity from the user's passphrase
 * via CapabilityAgent, instantiates a ZcapClient for signing storage requests,
 * and initializes the StorageManager (local or remote depending on env vars).
 * The resulting Session object is stored in authStore.
 */
import { CapabilityAgent } from '@interop/webkms-client'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { ZcapClient } from '@interop/ezcap'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { ControllerProfile, Session, User } from '@/types/auth'
import { KMS_SERVER_URL } from '@/app.config'
import { ensureKeystore } from '@/lib/kms'
import { StorageManager } from '@/stores/storageManager'
import { fetchKeyringSeed, KeyringRecordUnusableError } from '@/session/keyring'

/**
 * Creates bootstrap CapabilityAgent and ZcapClient instances from an
 * already-derived 32-byte seed, plus the X25519 key agreement key used for
 * encrypted storage. These will be used to manage DIDs, sign zCaps, interface
 * with storage, etc. The seed enters `CapabilityAgent.fromSeed` under the
 * fixed `'bootstrap'` / `'boostrap-key'` names (the typo is load-bearing --
 * every account's data identity derives through these exact names, so they
 * can never change without stranding existing wallets).
 */
export async function agentsFromSeed({ seed }: { seed: Uint8Array }) {
  const keyAgent = await CapabilityAgent.fromSeed({
    seed,
    handle: 'bootstrap',
    keyName: 'boostrap-key'
  })
  const signer = keyAgent.getSigner()
  const zcapClient = new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    invocationSigner: signer,
    // The root key also signs delegations: the session zcaps minted at login
    // (src/session/delegatedSession.ts) and any future sharing grants.
    delegationSigner: signer
  })

  // Derive an X25519 key agreement key (KAK) from the same Ed25519 key pair the
  // CapabilityAgent already holds -- exactly what did:key's encryption key
  // derivation does (the KAK is the Montgomery form of the signing key). This
  // is deterministic: the same passphrase always yields the same KAK, so a
  // returning user can decrypt their vault. The KAK lives under the same
  // did:key DID as the user identity, making keyResolver / controller wiring
  // trivial.
  const keyAgreementKey =
    X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
      keyPair: keyAgent.getVerificationKeyPair()
    })
  const keyResolver = async ({ id }: { id?: string }) => {
    if (id !== keyAgreementKey.id) {
      throw new Error(`Unknown key id "${id}".`)
    }
    return {
      id: keyAgreementKey.id,
      type: keyAgreementKey.type,
      publicKeyMultibase: keyAgreementKey.publicKeyMultibase
    }
  }

  return { keyAgent, zcapClient, keyAgreementKey, keyResolver }
}

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
  const { session } = await initSessionFromSeed({
    seed: randomGuestSecret,
    email: guestEmail,
    isGuest: true
  })

  return { session }
}

/**
 * Initializes a session (user, profile with zcap agents, storage manager) from
 * an already-derived 32-byte data seed. This is the shared core behind the
 * keyring path (`loginWithPassphrase`, `SignupPage`) and the guest bootstrap:
 * everything downstream of "data seed in hand" -- KMS keystore provisioning,
 * storage clients, the `full` tier stamp -- is identical regardless of how the
 * seed was obtained.
 *
 * For non-guest sessions the seed is carried on `profile.dataSeed` (so Settings
 * can re-bind the passphrase); guests skip it (a guest identity is ephemeral
 * and never keyring-bound).
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   the 32-byte data seed
 * @param [options.email] {string}
 * @param [options.isGuest] {boolean}
 * @param [options.remoteDirectStorage] {boolean}   route credential + history
 *   operations straight to the remote WAS collections (the CHAPI popup, whose
 *   local IndexedDB is third-party partitioned); default false
 * @returns {Promise<{ session: Session, userExists: boolean }>}
 */
export async function initSessionFromSeed({
  seed,
  email,
  isGuest = false,
  remoteDirectStorage = false
}: {
  seed: Uint8Array
  email?: string
  isGuest?: boolean
  remoteDirectStorage?: boolean
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
    // `id` is always set on the KAK here (a controller was supplied at
    // derivation), so it satisfies IKeyAgreementKey's required `id`.
    keyAgreementKey: keyAgreementKey as IKeyAgreementKey,
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

  const session = { user, profile, storage, isGuest, tier: 'full' } as Session

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
 * @returns {Promise<{ session: Session | null, userExists: boolean }>}
 */
export async function loginWithPassphrase({
  passphrase,
  email,
  idb,
  remoteDirectStorage = false
}: {
  passphrase: string
  email?: string
  idb?: IDBFactory
  remoteDirectStorage?: boolean
}): Promise<{ session: Session | null; userExists: boolean }> {
  const found = await fetchKeyringSeed({ passphrase, idb })

  if (!found) {
    return { session: null, userExists: false }
  }

  const { session, userExists } = await initSessionFromSeed({
    seed: found.seed,
    email,
    remoteDirectStorage
  })
  if (session.user.id !== found.controller) {
    throw new KeyringRecordUnusableError({
      cause: new Error(
        'The unwrapped controller does not match the derived identity.'
      )
    })
  }
  return { session, userExists }
}
