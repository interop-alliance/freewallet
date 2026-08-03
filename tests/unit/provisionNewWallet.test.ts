// @vitest-environment node
/**
 * Unit tests for the new-wallet provisioning sequence
 * (`src/session/provisionNewWallet.ts`) shared by the signup and guest flows:
 * it provisions the collections, records the initial account + space-created
 * history, seeds the default contacts, and seeds the welcome credential -- in
 * that order, and without double-logging the welcome credential's own
 * created-history (which `StorageManager.addCredential` records internally).
 */
import { describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'
import { welcomeCredential } from '@/fixtures/welcomeCredential'
import { selfContact } from '@interop/social-core'
import { interopAllianceTeamContact } from '@/fixtures/defaultContacts'
import { provisionNewWallet } from '@/session/provisionNewWallet'

/**
 * A session stub whose storage records the provisioning calls, plus a shared
 * `order` array capturing the sequence in which they ran.
 */
function sessionStub() {
  const order: string[] = []
  const track =
    (name: string) =>
    (...args: unknown[]) => {
      order.push(name)
      return Promise.resolve(args)
    }
  const storage = {
    ensureUserCollections: vi.fn(track('ensureUserCollections')),
    addHistoryNewAccount: vi.fn(track('addHistoryNewAccount')),
    addHistorySpaceCreated: vi.fn(track('addHistorySpaceCreated')),
    addContact: vi.fn(track('addContact')),
    addCredential: vi.fn(track('addCredential'))
  }
  const user = { id: 'did:key:z6MkNew', email: 'new@example.test' }
  const profile = { zcapClient: {} } as unknown as Session['profile']
  const session = {
    user,
    profile,
    storage,
    isGuest: false
  } as unknown as Session
  return { session, storage, user, profile, order }
}

describe('provisionNewWallet', () => {
  it('provisions collections, history, and the welcome credential in order', async () => {
    const { session, storage, user, profile, order } = sessionStub()

    await provisionNewWallet({ session })

    expect(storage.ensureUserCollections).toHaveBeenCalledWith({
      user,
      profile
    })
    expect(storage.addHistoryNewAccount).toHaveBeenCalledWith({ user })
    expect(storage.addHistorySpaceCreated).toHaveBeenCalledWith({ user })
    expect(storage.addContact).toHaveBeenCalledWith({
      contact: interopAllianceTeamContact
    })
    expect(storage.addContact).toHaveBeenCalledWith({
      contact: selfContact({
        dids: [profile.didWeb?.did, profile.didWebvh?.did].filter(
          (did): did is string => Boolean(did)
        ),
        email: user.email
      })
    })
    expect(storage.addCredential).toHaveBeenCalledWith({
      credential: welcomeCredential,
      user
    })
    expect(order).toEqual([
      'ensureUserCollections',
      'addHistoryNewAccount',
      'addHistorySpaceCreated',
      'addContact',
      'addContact',
      'addCredential'
    ])
  })

  it('omits the email from the self-contact for a guest session', async () => {
    // A guest's `user.email` is the internal placeholder from
    // `initGuestSession` ('guest@example.com'), never something the user
    // typed, so it must not leak into the seeded self-contact.
    const { session, storage, user, profile } = sessionStub()
    session.isGuest = true
    user.email = 'guest@example.com'

    await provisionNewWallet({ session })

    expect(storage.addContact).toHaveBeenCalledWith({
      contact: selfContact({
        dids: [profile.didWeb?.did, profile.didWebvh?.did].filter(
          (did): did is string => Boolean(did)
        )
      })
    })
  })

  it('does not separately record credential-created history (addCredential owns it)', async () => {
    const { session, storage } = sessionStub()
    // The welcome write is the only credential; addCredential logs its own
    // created-history entry, so provisionNewWallet must not call any
    // addHistoryCredential* itself.
    ;(
      storage as unknown as { addHistoryCredentialCreated?: unknown }
    ).addHistoryCredentialCreated = vi.fn()

    await provisionNewWallet({ session })

    expect(
      (
        storage as unknown as {
          addHistoryCredentialCreated: ReturnType<typeof vi.fn>
        }
      ).addHistoryCredentialCreated
    ).not.toHaveBeenCalled()
  })

  it('propagates a provisioning failure to the caller', async () => {
    const { session, storage } = sessionStub()
    vi.mocked(storage.ensureUserCollections).mockRejectedValueOnce(
      new Error('space unreachable')
    )

    await expect(provisionNewWallet({ session })).rejects.toThrow(
      'space unreachable'
    )
    // A failure at the first step stops the sequence.
    expect(storage.addHistoryNewAccount).not.toHaveBeenCalled()
  })
})
