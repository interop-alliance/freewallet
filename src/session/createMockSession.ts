import type { ControllerProfile, Session, User } from '@/types/auth.ts'

/**
 * Mock hardcoded login session
 */
export async function createMockSession({
  email,
  passphrase
}: {
  email?: string
  passphrase?: string
}): Promise<{ session: Session }> {
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
