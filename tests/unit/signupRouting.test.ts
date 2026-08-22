// @vitest-environment node
/**
 * Unit tests for the signup durability routing (`src/session/signup.ts`): a
 * WAS-configured signup on a non-remembered browser runs CREDENTIAL-ANCHORED
 * (a ladder-anchored genesis, transient entry, a create-nothing probe),
 * while an explicit `rememberBrowser: true` runs the durable flow with its
 * self-enrolling probe. The heavy boundaries -- the establishment, the
 * transient composition, the keyring -- are mocked at the module seam; what
 * runs here is the routing and the probe-then-establish-then-enter wiring.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'

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
  bindUnlockSecret: vi.fn(),
  deriveUnlockCredential: vi.fn(async () => ({
    unlock: { spaceId: 'unlock-space-1' },
    standing: {}
  })),
  fetchTransientKeyring: vi.fn(),
  unlockManagementGrantee: vi.fn()
}))

vi.mock('@/session/initSession', () => ({
  initSessionFromSeed: vi.fn(),
  loginWithPassphrase: vi.fn()
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
  provisionNewWallet: vi.fn()
}))

vi.mock('@/session/standingUnlock', () => ({
  establishPassphraseStanding: vi.fn(),
  establishStandingUnlock: vi.fn()
}))

vi.mock('@/session/unlockMethods', () => ({
  emptyUnlockMethodsRegistry: vi.fn(() => ({
    version: 1,
    userHandle: 'handle',
    methods: []
  })),
  enrollPasskey: vi.fn(),
  putUnlockMethods: vi.fn(),
  putUnlockMethodsWithClient: vi.fn(),
  upsertPassphraseUnlockMethod: vi.fn(({ record }) => record)
}))

import {
  deriveUnlockCredential,
  fetchTransientKeyring
} from '@/session/keyring'
import { loginWithPassphrase } from '@/session/initSession'
import { establishCredentialAnchoredAccount } from '@/session/credentialAnchoredGenesis'
import { transientSessionFromKeyringHit } from '@/session/transientLogin'
import { signUpWithPassphrase } from '@/session/signup'

afterEach(() => {
  vi.clearAllMocks()
  state.wasUrl = 'https://was.example.test'
})

describe('signUpWithPassphrase -- durability routing', () => {
  it('runs credential-anchored by default: probe, establish, transient entry', async () => {
    // The probe misses; the post-establishment fetch hits.
    vi.mocked(fetchTransientKeyring)
      .mockResolvedValueOnce(null)
      .mockResolvedValue({ unlockSpaceId: 'unlock-space-1' } as never)

    const result = await signUpWithPassphrase({
      passphrase: 'correct horse',
      email: 'a@example.test'
    })

    expect(result.userExists).toBe(false)
    expect(result.session).toBeTruthy()
    // The create-nothing probe, never the durable self-enrolling one.
    expect(loginWithPassphrase).not.toHaveBeenCalled()
    expect(fetchTransientKeyring).toHaveBeenCalledTimes(2)
    // One KDF run threads the whole signup.
    expect(deriveUnlockCredential).toHaveBeenCalledTimes(1)
    const establishCall = vi.mocked(establishCredentialAnchoredAccount).mock
      .calls[0]![0]
    expect(establishCall.lowEntropy).toBe(true)
    expect(establishCall.pointer.host).toBe('https://was.example.test')
    expect(establishCall.ladderSeed).toHaveLength(32)
    expect(transientSessionFromKeyringHit).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'passphrase' })
    )
  })

  it('reports an existing account from the create-nothing probe alone', async () => {
    vi.mocked(fetchTransientKeyring).mockResolvedValue({
      unlockSpaceId: 'unlock-space-1'
    } as never)

    const result = await signUpWithPassphrase({ passphrase: 'correct horse' })

    expect(result).toEqual({ userExists: true })
    expect(establishCredentialAnchoredAccount).not.toHaveBeenCalled()
    expect(transientSessionFromKeyringHit).not.toHaveBeenCalled()
  })

  it('runs the durable flow on rememberBrowser: true', async () => {
    vi.mocked(loginWithPassphrase).mockResolvedValue({
      session: null,
      userExists: true
    } as never)

    const result = await signUpWithPassphrase({
      passphrase: 'correct horse',
      rememberBrowser: true
    })

    expect(result.userExists).toBe(true)
    expect(loginWithPassphrase).toHaveBeenCalledWith(
      expect.objectContaining({ rememberBrowser: true })
    )
    expect(establishCredentialAnchoredAccount).not.toHaveBeenCalled()
  })

  it('runs the durable flow with no WAS server configured', async () => {
    state.wasUrl = undefined
    vi.mocked(loginWithPassphrase).mockResolvedValue({
      session: null,
      userExists: true
    } as never)

    await signUpWithPassphrase({ passphrase: 'correct horse' })

    expect(loginWithPassphrase).toHaveBeenCalled()
    expect(establishCredentialAnchoredAccount).not.toHaveBeenCalled()
    expect(fetchTransientKeyring).not.toHaveBeenCalled()
  })
})
