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
import { addSink, captureSink } from '@interop/logger'
import type { Session } from '@/types/auth'
import { welcomeCredential } from '@/fixtures/welcomeCredential'
import { selfContact } from '@interop/social-core'
import { interopAllianceTeamContact } from '@/fixtures/defaultContacts'
import {
  provisionNewWallet,
  seedWelcomeContent
} from '@/session/provisionNewWallet'

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

describe('seedWelcomeContent', () => {
  it('seeds the two history records and the welcome credential', async () => {
    const { session, storage, user, order } = sessionStub()
    // The seeds must be attributed to the account pointer's did:webvh --
    // never to the per-visit ephemeral `user.id`, and not to the record's
    // bound controller either (on a credential-anchored account that is the
    // ladder VM's bootstrap did:key, retired at the first self-enrollment).
    ;(
      session.profile as unknown as {
        accountController?: string
        accountPointer?: { did?: string }
      }
    ).accountController = 'did:key:z6MkBootstrapLadderVm'
    ;(
      session.profile as unknown as { accountPointer?: { did?: string } }
    ).accountPointer = {
      did: 'did:webvh:QmScid:was.example.test:space:s1:id'
    }
    const seedUser = {
      ...user,
      id: 'did:webvh:QmScid:was.example.test:space:s1:id'
    }

    await seedWelcomeContent({ session })

    expect(storage.addHistoryNewAccount).toHaveBeenCalledWith({
      user: seedUser
    })
    expect(storage.addHistorySpaceCreated).toHaveBeenCalledWith({
      user: seedUser
    })
    expect(storage.addCredential).toHaveBeenCalledWith({
      credential: welcomeCredential,
      user: seedUser
    })
    // The seed writes nothing else: no collections ensure, no contacts, and
    // no separate credential-created history (addCredential owns it).
    expect(storage.ensureUserCollections).not.toHaveBeenCalled()
    expect(storage.addContact).not.toHaveBeenCalled()
    expect(order).toEqual([
      'addHistoryNewAccount',
      'addHistorySpaceCreated',
      'addCredential'
    ])
  })

  it('resolves and warns on a storage failure (best-effort)', async () => {
    const capture = captureSink()
    addSink(capture.sink)
    const { session, storage } = sessionStub()
    vi.mocked(storage.addCredential).mockRejectedValueOnce(
      new Error('remote unreachable')
    )

    await expect(seedWelcomeContent({ session })).resolves.toBeUndefined()

    expect(
      capture.events.some(
        event => event.msg === 'Could not seed the welcome content'
      )
    ).toBe(true)
  })

  it('falls back to the ephemeral user id with no account controller', async () => {
    const { session, storage, user } = sessionStub()

    await seedWelcomeContent({ session })

    expect(storage.addHistoryNewAccount).toHaveBeenCalledWith({ user })
  })

  it('resolves and warns when the seeding hangs past the timeout', async () => {
    vi.useFakeTimers()
    try {
      const capture = captureSink()
      addSink(capture.sink)
      const { session, storage } = sessionStub()
      // A hung request: never resolves, never rejects.
      vi.mocked(storage.addCredential).mockImplementationOnce(
        () => new Promise(() => {})
      )

      const pending = seedWelcomeContent({ session })
      await vi.advanceTimersByTimeAsync(15_000)
      await expect(pending).resolves.toBeUndefined()

      expect(
        capture.events.some(
          event => event.msg === 'Could not seed the welcome content: timed out'
        )
      ).toBe(true)
    } finally {
      vi.useRealTimers()
    }
  })
})
