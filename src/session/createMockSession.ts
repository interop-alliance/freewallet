import { CapabilityAgent } from '@digitalbazaar/webkms-client'
import { Ed25519Signature2020 } from '@digitalcredentials/ed25519-signature-2020'
import { ZcapClient } from '@digitalcredentials/ezcap'
import type { ControllerProfile, Session, User } from '@/types/auth'
import { StorageManager } from '@/stores/storageManager'
import { welcomeCredential } from '@/fixtures/welcomeCredential'

export async function createGuestSession() {
  const user = {
    id: '00000',
    email: 'guest@example.com'
  } as User
  const profile = {} as ControllerProfile
  const session = { user, profile } as Session

  return { session }
}

/**
 * Mock hardcoded login session
 */
export async function createMockSession({
  email,
  passphrase
}: {
  email?: string
  passphrase?: string
}) {
  const keyAgent = await CapabilityAgent.fromSecret({
    secret: passphrase,
    handle: 'bootstrap',
    keyName: 'boostrap-key'
  })
  console.log('keyAgent', keyAgent)
  const signer = keyAgent.getSigner()
  const zcapClient = new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    invocationSigner: signer,
    delegationSigner: signer
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
