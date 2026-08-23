// @vitest-environment node
/**
 * Unit tests for the two signup registry writes in `src/session/signup.ts`
 * being read-first: the credential-anchored signup's `beforePromotion` hook
 * and the passkey signup's registry mint. Both used to PUT from an
 * unconditionally fresh registry, which a re-run (the transient login's
 * heal branch re-runs the establishment end to end) turns into a clobber --
 * the user handle re-minted, every other entry dropped. Here the registry is
 * an in-memory double behind the mocked read/write helpers, the real upsert
 * helpers run, and each signup is fired twice.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type {
  PasskeyUnlockMethod,
  UnlockMethodsRecord
} from '@/session/unlockMethods'

const state = vi.hoisted(() => ({
  registry: null as UnlockMethodsRecord | null,
  readThrows: false
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  WAS_SERVER_URL: 'https://was.example.test'
}))

vi.mock('@/session/keyring', () => ({
  bindPassphrase: vi.fn(),
  bindUnlockSecret: vi.fn(async () => ({})),
  deriveUnlockCredential: vi.fn(async () => ({
    unlock: { spaceId: 'unlock-space-1' },
    standing: {}
  })),
  fetchTransientKeyring: vi.fn(),
  unlockManagementGrantee: vi.fn(() => 'did:key:z6MkGrantee')
}))

vi.mock('@/session/initSession', () => ({
  initSessionFromSeed: vi.fn(async () => ({
    session: {
      user: { id: 'did:key:z6MkFirstClient' },
      profile: {
        persistence: { passkeyNotices: { save: vi.fn() } }
      },
      storage: {},
      isGuest: false
    }
  })),
  loginWithPassphrase: vi.fn()
}))

vi.mock('@/session/credentialAnchoredGenesis', () => ({
  // The establishment fires the hook the way the real one does: inside the
  // pre-promotion window, best-effort.
  establishCredentialAnchoredAccount: vi.fn(async ({ beforePromotion }) => {
    const establishment = {
      did: 'did:webvh:QmScid:was.example.test:space:space-1:id',
      unlockSpaceId: 'unlock-space-1',
      standingFields: { keyAgreementKeyMultibase: 'z6LSpassphrase' }
    }
    try {
      await beforePromotion?.({
        was: {},
        zcapClient: {},
        did: establishment.did,
        userKey: { id: 'did:key:z6MkUserKey' },
        establishment
      })
    } catch (err) {
      console.warn('The pre-promotion tail failed (continuing):', err)
    }
    return establishment
  })
}))

vi.mock('@/session/transientLogin', () => ({
  transientSessionFromKeyringHit: vi.fn(async () => ({
    session: { isTransient: true }
  }))
}))

vi.mock('@/session/provisionNewWallet', () => ({
  provisionNewWallet: vi.fn()
}))

vi.mock('@/session/standingUnlock', () => ({
  establishPassphraseStanding: vi.fn(),
  establishStandingUnlock: vi.fn(async () => ({
    persistClientKeys: vi.fn(),
    standingFields: { keyAgreementKeyMultibase: 'z6LSpasskey' }
  }))
}))

vi.mock('@/session/unlockMethods', async importOriginal => {
  const original =
    await importOriginal<typeof import('@/session/unlockMethods')>()
  const read = async () => {
    if (state.readThrows) {
      throw new Error('registry read refused')
    }
    return state.registry ? structuredClone(state.registry) : null
  }
  const write = async ({ record }: { record: UnlockMethodsRecord }) => {
    state.registry = structuredClone(record)
  }
  return {
    ...original,
    enrollPasskey: vi.fn(),
    getUnlockMethods: vi.fn(read),
    putUnlockMethods: vi.fn(write),
    getUnlockMethodsWithClient: vi.fn(read),
    putUnlockMethodsWithClient: vi.fn(write)
  }
})

import { base64urlnopad } from '@scure/base'
import { fetchTransientKeyring } from '@/session/keyring'
import {
  enrollPasskey,
  putUnlockMethods,
  putUnlockMethodsWithClient
} from '@/session/unlockMethods'
import { signUpWithPassphrase, signUpWithPasskey } from '@/session/signup'

/**
 * A passkey entry the way `enrollPasskey` would build it for the given
 * credential id.
 */
function passkeyEntry(credentialId: string): PasskeyUnlockMethod {
  return {
    type: 'passkey',
    label: `Passkey ${credentialId}`,
    createdAt: '2026-08-23T00:00:00.000Z',
    credentialId,
    transports: ['internal'],
    backupEligibility: false,
    backupState: false,
    unlockSpaceId: `unlock-${credentialId}`
  }
}

beforeEach(() => {
  state.registry = null
  state.readThrows = false
  vi.mocked(fetchTransientKeyring)
    .mockReset()
    .mockResolvedValueOnce(null)
    .mockResolvedValueOnce({ unlockSpaceId: 'unlock-space-1' } as never)
    .mockResolvedValueOnce(null)
    .mockResolvedValueOnce({ unlockSpaceId: 'unlock-space-1' } as never)
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('the credential-anchored signup hook -- read-first registry write', () => {
  it('mints a fresh registry on a true absent', async () => {
    await signUpWithPassphrase({ passphrase: 'correct horse' })

    expect(putUnlockMethodsWithClient).toHaveBeenCalledTimes(1)
    expect(state.registry?.methods).toEqual([
      expect.objectContaining({
        type: 'passphrase',
        unlockSpaceId: 'unlock-space-1',
        keyAgreementKeyMultibase: 'z6LSpassphrase'
      })
    ])
    expect(state.registry?.userHandle).toBeTruthy()
  })

  it('upserts into the existing registry on a heal re-run', async () => {
    await signUpWithPassphrase({ passphrase: 'correct horse' })
    const first = structuredClone(state.registry!)
    // Something else recorded an entry between the two firings.
    state.registry = {
      ...first,
      methods: [...first.methods, passkeyEntry('cred-1')]
    }

    await signUpWithPassphrase({ passphrase: 'correct horse' })

    expect(putUnlockMethodsWithClient).toHaveBeenCalledTimes(2)
    expect(state.registry?.userHandle).toBe(first.userHandle)
    expect(state.registry?.methods.map(method => method.type)).toEqual([
      'passphrase',
      'passkey'
    ])
    // The passphrase entry is replaced, not duplicated, and keeps its
    // original creation stamp.
    const passphrase = state.registry?.methods[0]
    expect(passphrase?.createdAt).toBe(first.methods[0]!.createdAt)
  })

  it('skips the write on a thrown read -- never falls back to empty', async () => {
    await signUpWithPassphrase({ passphrase: 'correct horse' })
    const first = structuredClone(state.registry!)
    state.readThrows = true
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const result = await signUpWithPassphrase({ passphrase: 'correct horse' })

    // The establishment is not failed by the skipped write.
    expect(result.session).toBeTruthy()
    expect(putUnlockMethodsWithClient).toHaveBeenCalledTimes(1)
    expect(state.registry).toEqual(first)
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('skipping the passphrase entry'),
      expect.any(Error)
    )
    warn.mockRestore()
  })
})

describe('the passkey signup -- read-first registry mint', () => {
  /**
   * Runs one passkey signup whose enrollment yields the given credential id,
   * returning the user handle the WebAuthn ceremony was handed.
   */
  async function signUp(credentialId: string): Promise<string> {
    let handedHandle = ''
    vi.mocked(enrollPasskey).mockImplementationOnce(async ({ userHandle }) => {
      handedHandle = base64urlnopad.encode(userHandle)
      return {
        registration: {
          prfOutput: new Uint8Array(32),
          backupEligibility: false,
          backupState: false
        },
        entry: passkeyEntry(credentialId),
        persistClientKeys: vi.fn()
      } as never
    })
    await signUpWithPasskey({
      locale: 'en',
      userName: 'someone',
      promptForPrfRetry: async () => true
    })
    return handedHandle
  }

  it('mints the registry from the registered handle on a true absent', async () => {
    const handle = await signUp('cred-1')

    expect(putUnlockMethods).toHaveBeenCalledTimes(1)
    expect(state.registry).toEqual({
      version: 1,
      userHandle: handle,
      methods: [
        expect.objectContaining({ type: 'passkey', credentialId: 'cred-1' })
      ]
    })
  })

  it('preserves the existing handle and entries on a second firing', async () => {
    const firstHandle = await signUp('cred-1')
    const secondHandle = await signUp('cred-2')

    expect(secondHandle).not.toBe(firstHandle)
    expect(state.registry?.userHandle).toBe(firstHandle)
    expect(
      state.registry?.methods.map(method =>
        method.type === 'passkey' ? method.credentialId : method.type
      )
    ).toEqual(['cred-1', 'cred-2'])
  })

  it('replaces rather than duplicates an entry for the same credential', async () => {
    await signUp('cred-1')
    await signUp('cred-1')

    expect(state.registry?.methods).toHaveLength(1)
  })

  it('skips the write on a thrown read and still completes the signup', async () => {
    await signUp('cred-1')
    const first = structuredClone(state.registry!)
    state.readThrows = true
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    await signUp('cred-2')

    expect(putUnlockMethods).toHaveBeenCalledTimes(1)
    expect(state.registry).toEqual(first)
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('Could not record the new passkey'),
      expect.any(Error)
    )
    warn.mockRestore()
  })
})
