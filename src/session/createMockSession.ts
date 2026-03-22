import type { ControllerProfile, Session, User } from '@/types/auth.ts'

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
  const session = { user, profile } as Session

  return { session }
}
