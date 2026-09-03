// @vitest-environment node
/**
 * Unit tests for the signup login routing (`src/session/signup.ts`): a
 * WAS-configured signup ALWAYS runs the credential-anchored establishment --
 * the non-remembered default then enters transiently, while an explicit
 * `rememberBrowser: true` follows the establishment with the ordinary
 * remembered login, not the transient composition, and reports
 * `userExists: false`.
 * The heavy boundaries -- the establishment, the transient composition, the
 * keyring, the login -- are mocked at the module seam; what runs here is the
 * routing and the probe-then-establish-then-enter wiring.
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

const ESTABLISHED_LOG = {
  did: 'did:webvh:QmScid:was.example.test:space:space-1:id',
  log: [{ entry: 'established' }],
  doc: { id: 'did:webvh:QmScid:was.example.test:space:space-1:id' },
  updateKeys: [],
  nextKeyHashes: []
}

vi.mock('@/session/credentialAnchoredGenesis', () => ({
  establishCredentialAnchoredAccount: vi.fn(async () => ({
    did: 'did:webvh:QmScid:was.example.test:space:space-1:id',
    accountLog: ESTABLISHED_LOG,
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
  registerPasskey: vi.fn()
}))

import {
  deriveUnlockCredential,
  fetchTransientKeyring
} from '@/session/keyring'
import { loginWithPassphrase } from '@/session/initSession'
import { establishCredentialAnchoredAccount } from '@/session/credentialAnchoredGenesis'
import { transientSessionFromKeyringHit } from '@/session/transientLogin'
import { seedWelcomeContent } from '@/session/provisionNewWallet'
import { signUpWithPassphrase } from '@/session/signup'

afterEach(() => {
  vi.clearAllMocks()
  state.wasUrl = 'https://was.example.test'
})

describe('signUpWithPassphrase -- login routing', () => {
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
    // The create-nothing probe, not the remembered self-enrolling one.
    expect(loginWithPassphrase).not.toHaveBeenCalled()
    expect(fetchTransientKeyring).toHaveBeenCalledTimes(2)
    // One KDF run threads the whole signup.
    expect(deriveUnlockCredential).toHaveBeenCalledTimes(1)
    const establishCall = vi.mocked(establishCredentialAnchoredAccount).mock
      .calls[0]![0]
    expect(establishCall.lowEntropy).toBe(true)
    expect(establishCall.pointer.host).toBe('https://was.example.test')
    expect(establishCall.ladderSeed).toHaveLength(32)
    // The establishment's own verified head rides into the composition, so
    // the entry half's first contact reads it instead of fetching the log
    // this signup just published.
    expect(transientSessionFromKeyringHit).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'passphrase',
        accountLog: ESTABLISHED_LOG
      })
    )
    // The tail kicks off the welcome seeding without awaiting it, stamping
    // the (never-rejecting) promise on the session for the dashboard's
    // indicator.
    expect(seedWelcomeContent).toHaveBeenCalledWith({
      session: result.session
    })
    expect(result.session!.welcomeSeedReady).toBeInstanceOf(Promise)
    await expect(result.session!.welcomeSeedReady).resolves.toBeUndefined()
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

  it('rememberBrowser: true runs the establishment then the remembered login', async () => {
    // The create-nothing probe misses; the establishment runs; the
    // remembered login self-enrolls this browser.
    vi.mocked(fetchTransientKeyring).mockResolvedValueOnce(null)
    const rememberedSession = {
      user: { id: 'did:key:z6MkFirstClient' },
      profile: {},
      storage: {},
      isGuest: false
    }
    vi.mocked(loginWithPassphrase).mockResolvedValue({
      session: rememberedSession,
      userExists: true
    } as never)

    const result = await signUpWithPassphrase({
      passphrase: 'correct horse',
      email: 'a@example.test',
      rememberBrowser: true
    })

    // The establishment ran under the remembered seams.
    const establishCall = vi.mocked(establishCredentialAnchoredAccount).mock
      .calls[0]![0]
    expect(establishCall.lowEntropy).toBe(true)
    // Then the ordinary remembered login, with the derived credential.
    expect(loginWithPassphrase).toHaveBeenCalledWith(
      expect.objectContaining({
        rememberBrowser: true,
        credential: expect.anything()
      })
    )
    // Never the transient composition: no per-visit annex client is minted.
    expect(transientSessionFromKeyringHit).not.toHaveBeenCalled()
    // The inner login's `userExists: true` (the account it just created)
    // does not pass through.
    expect(result.userExists).toBe(false)
    expect(result.session).toBe(rememberedSession)
    expect(seedWelcomeContent).toHaveBeenCalledWith({
      session: rememberedSession
    })
  })

  it('rememberBrowser: true still reports an existing account from the probe', async () => {
    vi.mocked(fetchTransientKeyring).mockResolvedValue({
      unlockSpaceId: 'unlock-space-1'
    } as never)

    const result = await signUpWithPassphrase({
      passphrase: 'correct horse',
      rememberBrowser: true
    })

    expect(result).toEqual({ userExists: true })
    expect(establishCredentialAnchoredAccount).not.toHaveBeenCalled()
    expect(loginWithPassphrase).not.toHaveBeenCalled()
  })

  it('runs the remembered flow with no WAS server configured', async () => {
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
