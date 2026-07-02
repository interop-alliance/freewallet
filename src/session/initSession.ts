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

/**
 * Creates bootstrap CapabilityAgent and ZcapClient instances from a secret
 * passphrase, plus the X25519 key agreement key used for encrypted storage.
 * These will be used to manage DIDs, sign zCaps, interface with storage, etc.
 */
export async function agentsFromSecret({
  secret
}: {
  secret: string | Uint8Array
}) {
  const keyAgent = await CapabilityAgent.fromSecret({
    secret,
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

  const { session } = await initSessionFromSecret({
    secret: randomGuestSecret,
    email: guestEmail,
    isGuest: true
  })

  return { session }
}

/**
 * Initializes a session (user, profile with zcap agents, storage manager)
 * for a given email and passphrase.
 */
export async function initSessionFromSecret({
  email,
  secret,
  isGuest = false
}: {
  email?: string
  secret: string | Uint8Array
  isGuest?: boolean
}) {
  const { keyAgent, zcapClient, keyAgreementKey, keyResolver } =
    await agentsFromSecret({
      secret: secret
    })

  // Ensure a KMS keystore exists for this controller (list-by-controller,
  // create on first login) and bind a KeystoreAgent to it. Guests skip the
  // KMS entirely, as they skip WAS. Failure is non-fatal for now: no wallet
  // feature depends on the keystore yet, so a KMS outage must not lock
  // users out -- the settings page surfaces the unprovisioned state.
  let keystoreAgent
  if (!isGuest && KMS_SERVER_URL) {
    try {
      keystoreAgent = await ensureKeystore({
        kmsServerUrl: KMS_SERVER_URL,
        keyAgent,
        zcapClient
      })
    } catch (err) {
      console.warn('KMS keystore provisioning failed:', err)
    }
  }

  const user: User = {
    id: keyAgent.id, // a did:key DID
    email
  }
  const profile: ControllerProfile = {
    keyAgent,
    zcapClient,
    keystoreAgent,
    // `id` is always set on the KAK here (a controller was supplied at
    // derivation), so it satisfies IKeyAgreementKey's required `id`.
    keyAgreementKey: keyAgreementKey as IKeyAgreementKey,
    keyResolver
  }

  const { storage, userExists } = await StorageManager.initStorageClients({
    user,
    profile,
    isGuest
  })

  const session = { user, profile, storage, isGuest, tier: 'full' } as Session

  return { session, userExists }
}
