// @vitest-environment node
/**
 * Unit tests for the two signup registry writes in `src/session/signup.ts`
 * being read-first: the credential-anchored signup's passphrase hook and the
 * passkey signup's registry hook. Both write from the establishment's
 * pre-promotion window, and a re-run (the transient login's heal branch
 * re-runs the establishment end to end) must upsert, never clobber -- the
 * WebAuthn user id kept, every other entry carried. The two differ in
 * failure semantics: the passphrase hook swallows its own failures (the
 * entry is re-recordable at the next durable login), while the passkey hook
 * throws through and fails the signup (an absent passkey entry has no
 * rebuild). Here the registry is an in-memory double behind the mocked
 * read/write helpers, the real upsert helpers run, and each signup is fired
 * twice.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type {
  PasskeyUnlockMethod,
  UnlockMethodsRecord
} from '@/session/unlockMethods'

const state = vi.hoisted(() => ({
  registry: null as UnlockMethodsRecord | null,
  readThrows: false,
  // Landed registry writes, labeled by wrapper flavor ('session' | 'client').
  writes: [] as string[]
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  WAS_SERVER_URL: 'https://was.example.test'
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
  loginWithPasskey: vi.fn(async () => ({
    session: {
      user: { id: 'did:key:z6MkFirstClient' },
      profile: {
        persistence: { passkeyNotices: { save: vi.fn() } }
      },
      storage: {},
      isGuest: false
    },
    userExists: true
  }))
}))

vi.mock('@/session/credentialAnchoredGenesis', () => ({
  // The establishment fires the hook the way the real one does: inside the
  // pre-promotion window. A hook throw is FATAL to the establishment (the
  // Stage-1 contract) -- a hook that must be best-effort swallows its own
  // failures.
  establishCredentialAnchoredAccount: vi.fn(async ({ beforePromotion }) => {
    const establishment = {
      did: 'did:webvh:QmScid:was.example.test:space:space-1:id',
      unlockSpaceId: 'unlock-space-1',
      standingFields: { keyAgreementKeyMultibase: 'z6LSstanding' }
    }
    await beforePromotion?.({
      was: {},
      zcapClient: {},
      did: establishment.did,
      userKey: { id: 'did:key:z6MkUserKey' },
      establishment
    })
    return establishment
  })
}))

vi.mock('@/session/transientLogin', () => ({
  transientSessionFromKeyringHit: vi.fn(async () => ({
    session: { isTransient: true }
  }))
}))

vi.mock('@/session/provisionNewWallet', () => ({
  provisionNewWallet: vi.fn(),
  seedWelcomeContent: vi.fn(async () => {})
}))

vi.mock('@/lib/passkey', () => ({
  registerPasskey: vi.fn()
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
  const update = (label: string) =>
    vi.fn(
      async ({
        mutate
      }: {
        mutate: (
          current: UnlockMethodsRecord | null
        ) => UnlockMethodsRecord | null | Promise<UnlockMethodsRecord | null>
      }) => {
        const current = await read()
        const next = await mutate(current)
        if (next === null) {
          return current
        }
        state.writes.push(label)
        await write({ record: next })
        return next
      }
    )
  return {
    ...original,
    enrollPasskey: vi.fn(),
    getUnlockMethods: vi.fn(read),
    getUnlockMethodsWithClient: vi.fn(read),
    updateUnlockMethods: update('session'),
    updateUnlockMethodsWithClient: update('client')
  }
})

import { base64urlnopad } from '@scure/base'
import { fetchTransientKeyring } from '@/session/keyring'
import { registerPasskey } from '@/lib/passkey'
import { signUpWithPassphrase, signUpWithPasskey } from '@/session/signup'

/**
 * A passkey entry shaped the way another writer would have recorded it.
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
  state.writes = []
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

    expect(state.writes.filter(write => write === 'client')).toHaveLength(1)
    expect(state.registry?.methods).toEqual([
      expect.objectContaining({
        type: 'passphrase',
        unlockSpaceId: 'unlock-space-1',
        keyAgreementKeyMultibase: 'z6LSstanding'
      })
    ])
    expect(state.registry?.webAuthnUserId).toBeTruthy()
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

    expect(state.writes.filter(write => write === 'client')).toHaveLength(2)
    expect(state.registry?.webAuthnUserId).toBe(first.webAuthnUserId)
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

    // The establishment is not failed by the skipped write: the passphrase
    // hook swallows its own failure (the entry is re-recordable later).
    expect(result.session).toBeTruthy()
    expect(state.writes.filter(write => write === 'client')).toHaveLength(1)
    expect(state.registry).toEqual(first)
    expect(warn).toHaveBeenCalledWith(
      '[%s] %s',
      'fw:session:signup',
      expect.stringContaining('skipping the passphrase entry'),
      expect.any(Error),
      ''
    )
    warn.mockRestore()
  })
})

describe('the passkey signup -- read-first, fatal registry hook', () => {
  /**
   * Runs one passkey signup whose WebAuthn registration yields the given
   * credential id, returning the base64url WebAuthn user id the ceremony was
   * handed.
   */
  async function signUp(credentialId: string): Promise<string> {
    let handedUserId = ''
    vi.mocked(registerPasskey).mockImplementationOnce(
      async ({ userHandle }) => {
        handedUserId = base64urlnopad.encode(userHandle)
        return {
          credentialId: new TextEncoder().encode(credentialId),
          transports: ['internal'],
          prfOutput: new Uint8Array(32),
          backupEligibility: false,
          backupState: false
        }
      }
    )
    await signUpWithPasskey({
      locale: 'en',
      userName: 'someone',
      promptForPrfRetry: async () => true
    })
    return handedUserId
  }

  it('mints the registry from the registered user id on a true absent', async () => {
    const userId = await signUp('cred-1')

    expect(state.writes.filter(write => write === 'client')).toHaveLength(1)
    expect(state.registry).toEqual({
      version: 1,
      webAuthnUserId: userId,
      methods: [
        expect.objectContaining({
          type: 'passkey',
          credentialId: base64urlnopad.encode(
            new TextEncoder().encode('cred-1')
          ),
          unlockSpaceId: 'unlock-space-1',
          keyAgreementKeyMultibase: 'z6LSstanding'
        })
      ]
    })
  })

  it('preserves the existing user id and entries on a second firing', async () => {
    const firstUserId = await signUp('cred-1')
    const secondUserId = await signUp('cred-2')

    expect(secondUserId).not.toBe(firstUserId)
    expect(state.registry?.webAuthnUserId).toBe(firstUserId)
    expect(
      state.registry?.methods.map(method =>
        method.type === 'passkey' ? method.credentialId : method.type
      )
    ).toEqual([
      base64urlnopad.encode(new TextEncoder().encode('cred-1')),
      base64urlnopad.encode(new TextEncoder().encode('cred-2'))
    ])
  })

  it('replaces rather than duplicates an entry for the same credential', async () => {
    await signUp('cred-1')
    await signUp('cred-1')

    expect(state.registry?.methods).toHaveLength(1)
  })

  it('a thrown registry read fails the passkey signup (no silent skip)', async () => {
    await signUp('cred-1')
    const first = structuredClone(state.registry!)
    state.readThrows = true
    vi.mocked(registerPasskey).mockResolvedValueOnce({
      credentialId: new TextEncoder().encode('cred-2'),
      transports: ['internal'],
      prfOutput: new Uint8Array(32),
      backupEligibility: false,
      backupState: false
    })

    await expect(
      signUpWithPasskey({
        locale: 'en',
        userName: 'someone',
        promptForPrfRetry: async () => true
      })
    ).rejects.toThrow('registry read refused')
    // Nothing was written over the standing registry, and no half-recorded
    // signup reported success.
    expect(state.writes.filter(write => write === 'client')).toHaveLength(1)
    expect(state.registry).toEqual(first)
  })
})
