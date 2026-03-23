import type { ControllerProfile, Session, User } from '@/types/auth'
import { StorageManager } from '@/stores/storageManager'
import { welcomeCredential } from '@/fixtures/welcomeCredential.ts'

export async function createGuestSession() {
  const user = {
    id: '00000',
    email: 'guest@example.com'
  } as User
  const profile = {
    passphrase: '99999'
  } as ControllerProfile
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
  const user = {
    id: '12345',
    email
  } as User
  const profile = {
    passphrase
  } as ControllerProfile

  const { storage } = await StorageManager.initStorage({ user })

  // Add a "welcome" credential to storage
  await storage.addCredential({ credential: welcomeCredential })

  const session = { user, profile, storage } as Session

  return { session }
}
