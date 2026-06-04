/**
 * Session bootstrap. Derives a did:key identity from the user's passphrase
 * via CapabilityAgent, instantiates a ZcapClient for signing storage requests,
 * and initializes the StorageManager (local or remote depending on env vars).
 * The resulting Session object is stored in authStore.
 */
import { CapabilityAgent } from '@digitalbazaar/webkms-client'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { ZcapClient } from '@interop/ezcap'
import type { ControllerProfile, Session, User } from '@/types/auth'
import { StorageManager } from '@/stores/storageManager'

/**
 * Creates bootstrap CapabilityAgent and ZcapClient instances from a secret
 * passphrase. These will be used to manage DIDs, sign zCaps, interface with
 * storage, etc.
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
    invocationSigner: signer
  })
  return { keyAgent, zcapClient }
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
  const { keyAgent, zcapClient } = await agentsFromSecret({
    secret: secret
  })

  const user: User = {
    id: keyAgent.id, // a did:key DID
    email
  }
  const profile: ControllerProfile = {
    keyAgent,
    zcapClient
  }

  const { storage, userExists } = await StorageManager.initStorageClients({
    user,
    profile
  })

  const session = { user, profile, storage, isGuest } as Session

  return { session, userExists }
}
