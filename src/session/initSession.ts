import { CapabilityAgent } from '@digitalbazaar/webkms-client'
import { Ed25519Signature2020 } from '@digitalcredentials/ed25519-signature-2020'
import { ZcapClient } from '@digitalcredentials/ezcap'
import type { ControllerProfile, Session, User } from '@/types/auth'
import { StorageManager } from '@/stores/storageManager'
import { welcomeCredential } from '@/fixtures/welcomeCredential'

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

  return initSessionFromSecret({
    secret: randomGuestSecret,
    email: guestEmail
  })
}

/**
 * Initializes a session (user, profile with zcap agents, storage manager)
 * for a given email and passphrase.
 */
export async function initSessionFromSecret({
  email,
  secret
}: {
  email?: string
  secret: string | Uint8Array
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

  const { storage } = await StorageManager.initStorage({ user })

  // Add a "welcome" credential to storage
  await storage.addCredential({ credential: welcomeCredential })

  const session = { user, profile, storage } as Session

  return { session }
}
