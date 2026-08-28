// @vitest-environment node
/**
 * Unit tests for the folded WAS signups (`src/session/signup.ts`, design
 * section 7): on a WAS deployment `signUpWithPassphrase` never binds a plain
 * record (`bindPassphrase` is unreachable there); the remembered branch runs
 * the credential-anchored establishment and then the ordinary durable login,
 * reporting `userExists: false` with the login's durable session; the
 * passkey signup runs the same fold under the PRF credential with exactly
 * one WebAuthn ceremony (the login half takes the derived credential and
 * skips its own PRF assertion); and neither durable branch ever enters the
 * transient composition (no annex enrollment write). The module seams are
 * mocked the way `signupRouting.test.ts` mocks them.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return state.wasUrl
  }
}))

vi.mock('@/session/keyring', () => ({
  bindPassphrase: vi.fn(),
  deriveUnlockCredential: vi.fn(async () => ({
    unlock: { spaceId: 'unlock-space-1' },
    standing: {}
  })),
  fetchTransientKeyring: vi.fn()
}))

vi.mock('@/session/initSession', () => ({
  initSessionFromSeed: vi.fn(),
  loginWithPassphrase: vi.fn(),
  loginWithPasskey: vi.fn()
}))

vi.mock('@/session/credentialAnchoredGenesis', () => ({
  establishCredentialAnchoredAccount: vi.fn(async () => ({
    did: 'did:webvh:QmScid:was.example.test:space:space-1:id',
    unlockSpaceId: 'unlock-space-1',
    standingFields: {}
  }))
}))

vi.mock('@/session/transientLogin', () => ({
  transientSessionFromKeyringHit: vi.fn(async () => ({
    session: { isTransient: true },
    userExists: false
  }))
}))

vi.mock('@/session/provisionNewWallet', () => ({
  provisionNewWallet: vi.fn(),
  seedWelcomeContent: vi.fn(async () => {})
}))

vi.mock('@/session/unlockMethods', () => ({
  emptyUnlockMethodsRegistry: vi.fn(() => ({
    version: 1,
    webAuthnUserId: 'handle',
    methods: []
  })),
  enrollPasskey: vi.fn(),
  updateUnlockMethods: vi.fn(),
  updateUnlockMethodsWithClient: vi.fn(),
  upsertPassphraseUnlockMethod: vi.fn(({ record }) => record),
  upsertPasskeyUnlockMethod: vi.fn(({ record }) => record)
}))

vi.mock('@/lib/passkey', () => ({
  registerPasskey: vi.fn(async () => ({
    credentialId: new Uint8Array([1, 2, 3]),
    transports: ['internal'],
    prfOutput: new Uint8Array(32),
    backupEligibility: false,
    backupState: false
  })),
  assertPasskeyPrf: vi.fn()
}))

import { assertPasskeyPrf, registerPasskey } from '@/lib/passkey'
import { bindPassphrase, fetchTransientKeyring } from '@/session/keyring'
import { loginWithPassphrase, loginWithPasskey } from '@/session/initSession'
import { establishCredentialAnchoredAccount } from '@/session/credentialAnchoredGenesis'
import { transientSessionFromKeyringHit } from '@/session/transientLogin'
import { signUpWithPassphrase, signUpWithPasskey } from '@/session/signup'

/**
 * The durable session the mocked login halves hand back.
 */
function durableSession() {
  return {
    user: { id: 'did:key:z6MkFirstClient' },
    profile: {
      persistence: { passkeyNotices: { save: vi.fn() } }
    },
    storage: {},
    isGuest: false
  }
}

beforeEach(() => {
  vi.mocked(fetchTransientKeyring)
    .mockReset()
    .mockResolvedValueOnce(null)
    .mockResolvedValueOnce({ unlockSpaceId: 'unlock-space-1' } as never)
  vi.mocked(loginWithPassphrase).mockResolvedValue({
    session: durableSession(),
    userExists: true
  } as never)
  vi.mocked(loginWithPasskey).mockResolvedValue({
    session: durableSession(),
    userExists: true
  } as never)
})

afterEach(() => {
  vi.clearAllMocks()
  state.wasUrl = 'https://was.example.test'
})

describe('signUpWithPassphrase on a WAS deployment', () => {
  it('never binds a plain record (default branch)', async () => {
    await signUpWithPassphrase({ passphrase: 'correct horse' })
    expect(bindPassphrase).not.toHaveBeenCalled()
    expect(establishCredentialAnchoredAccount).toHaveBeenCalledOnce()
  })

  it('never binds a plain record (remembered branch)', async () => {
    await signUpWithPassphrase({
      passphrase: 'correct horse',
      rememberBrowser: true
    })
    expect(bindPassphrase).not.toHaveBeenCalled()
  })

  it('remembered: establishment, then the durable login, userExists: false', async () => {
    const result = await signUpWithPassphrase({
      passphrase: 'correct horse',
      email: 'a@example.test',
      rememberBrowser: true
    })

    expect(establishCredentialAnchoredAccount).toHaveBeenCalledOnce()
    // The establishment settled before the login ran.
    const establishOrder = vi.mocked(establishCredentialAnchoredAccount).mock
      .invocationCallOrder[0]!
    const loginOrder =
      vi.mocked(loginWithPassphrase).mock.invocationCallOrder[0]!
    expect(establishOrder).toBeLessThan(loginOrder)
    expect(loginWithPassphrase).toHaveBeenCalledWith(
      expect.objectContaining({
        passphrase: 'correct horse',
        email: 'a@example.test',
        rememberBrowser: true,
        credential: expect.anything()
      })
    )
    // The durable session, and the result contract: the inner login's
    // `userExists: true` never passes through.
    expect(result.session).toBeTruthy()
    expect(result.userExists).toBe(false)
  })

  it('remembered: never enters the transient composition (no annex write)', async () => {
    await signUpWithPassphrase({
      passphrase: 'correct horse',
      rememberBrowser: true
    })
    expect(transientSessionFromKeyringHit).not.toHaveBeenCalled()
  })
})

describe('signUpWithPasskey on a WAS deployment', () => {
  it('runs the fold with exactly one WebAuthn ceremony', async () => {
    const { session } = await signUpWithPasskey({
      locale: 'en',
      userName: 'someone',
      promptForPrfRetry: async () => true
    })

    expect(session).toBeTruthy()
    // One ceremony: the registration. The login half takes the derived
    // credential, so no PRF assertion ever fires in the signup.
    expect(registerPasskey).toHaveBeenCalledOnce()
    expect(assertPasskeyPrf).not.toHaveBeenCalled()
    const establishCall = vi.mocked(establishCredentialAnchoredAccount).mock
      .calls[0]![0]
    // The PRF key is high-entropy and publishes verbatim.
    expect(establishCall.lowEntropy).toBe(false)
    expect(loginWithPasskey).toHaveBeenCalledWith(
      expect.objectContaining({
        rememberBrowser: true,
        credential: expect.anything()
      })
    )
    // Never the transient composition.
    expect(transientSessionFromKeyringHit).not.toHaveBeenCalled()
  })
})
