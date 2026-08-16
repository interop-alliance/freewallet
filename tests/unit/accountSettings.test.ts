// @vitest-environment node
/**
 * Unit tests for the account-settings orchestrators
 * (`src/session/accountSettings.ts`): the account-deletion phase order (verify
 * the passphrase, wipe the data, retire the keyring) and its refusals, and the
 * passphrase change adopting the rebind into the live session. Every durable
 * seam is mocked; only the ordering is under test.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  calls: [] as string[],
  verifyFails: null as 'wrong' | 'other' | null,
  wipeFails: false
}))

class FakeWrongPassphraseError extends Error {}

vi.mock('@/session/keyring', () => ({
  WrongPassphraseError: FakeWrongPassphraseError,
  verifyPassphrase: vi.fn(async () => {
    state.calls.push('verifyPassphrase')
    if (state.verifyFails === 'wrong') {
      throw new FakeWrongPassphraseError('nope')
    }
    if (state.verifyFails === 'other') {
      throw new Error('remote unreachable')
    }
  }),
  deleteKeyring: vi.fn(async () => {
    state.calls.push('deleteKeyring')
    return { unlockSpaceDeleted: true }
  }),
  changePassphrase: vi.fn(async () => {
    state.calls.push('changePassphrase')
    return {
      oldPassphraseRetired: true,
      unlockSpaceId: 'space-new',
      manageCapability: undefined,
      persistClientKeys: async () => {}
    }
  }),
  bindPassphrase: vi.fn(async () => ({ unlockSpaceId: 'space-bound' })),
  bindUnlockSecret: vi.fn(async () => ({ unlockSpaceId: 'space-bound' })),
  deriveUnlockCredential: vi.fn(async () => ({ unlock: {}, standing: {} })),
  unlockManagementGrantee: vi.fn(() => 'did:key:grantee')
}))

vi.mock('@/session/unlockMethods', () => ({
  adoptPassphraseRebind: vi.fn(() => {
    state.calls.push('adoptPassphraseRebind')
  }),
  backfillPassphraseUnlockMethod: vi.fn(async () => null),
  canRevokeWithoutCeremony: vi.fn(() => true),
  emptyUnlockMethodsRegistry: vi.fn(() => ({
    version: 1,
    userHandle: 'handle',
    methods: []
  })),
  enrollPasskey: vi.fn(async () => ({ entry: {}, registration: {} })),
  getUnlockMethods: vi.fn(async () => null),
  putUnlockMethods: vi.fn(async () => {}),
  refreshStandingDelegationFields: vi.fn(async () => {}),
  revokeUnlockMethod: vi.fn(async () => {}),
  revokeUnlockMethodByCeremony: vi.fn(async () => {}),
  upsertPassphraseUnlockMethod: vi.fn(({ record }) => record)
}))

vi.mock('@/lib/sessionKey', () => ({
  deletePasskeySafetyNotice: vi.fn(async () => {
    state.calls.push('deletePasskeySafetyNotice')
  }),
  deleteUserKeyEpochPin: vi.fn(async () => {
    state.calls.push('deleteUserKeyEpochPin')
  }),
  deleteLogPin: vi.fn(async ({ logId }: { logId: string }) => {
    state.calls.push(`deleteLogPin:${logId}`)
  }),
  deleteAccountDidForSpace: vi.fn(async () => {
    state.calls.push('deleteAccountDidForSpace')
  }),
  saveUserKeyEpochPin: vi.fn(async () => {}),
  sessionLogPinStore: vi.fn(() => ({
    read: async () => null,
    write: async () => undefined
  }))
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  rotateWebvhUpdateKey: vi.fn(async () => {})
}))

vi.mock('@/lib/loginCredential', () => ({
  findLoginCredential: vi.fn(() => null),
  loginHandleOf: vi.fn(() => '')
}))

const { changeAccountPassphrase, deleteAccount } =
  await import('@/session/accountSettings')
const { accountLogPinId } = await import('@interop/wallet-core/webvh')
const { userKeyRosterPinId } = await import('@interop/wallet-core/keys')

function makeSession() {
  return {
    user: { id: 'did:key:zClient' },
    isGuest: false,
    profile: {
      clientSeed: new Uint8Array(32),
      accountController: 'did:key:zAccount',
      accountPointer: {
        did: 'did:webvh:QmScid:was.example.test:space:space-123:id',
        spaceId: 'space-123',
        host: 'https://was.example.test'
      }
    },
    storage: {
      wipeStorage: vi.fn(async () => {
        state.calls.push('wipeStorage')
        if (state.wipeFails) {
          throw new Error('wipe failed')
        }
      })
    }
    // The orchestrators read a small, stable slice of the session.
  } as unknown as Parameters<typeof deleteAccount>[0]['session']
}

beforeEach(() => {
  state.calls = []
  state.verifyFails = null
  state.wipeFails = false
})

describe('deleteAccount', () => {
  it('verifies the passphrase, wipes the data, and only then retires the keyring', async () => {
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('deleted')
    // The local continuity pins go with the account: the keyring retirement
    // drops the pointer pin, and the key-roster epoch pin plus the Space-keyed
    // bookkeeping (the two chain-head pin slots and the Space-to-DID mapping)
    // are cleared beside it.
    expect(state.calls).toEqual([
      'verifyPassphrase',
      'wipeStorage',
      'deleteKeyring',
      'deletePasskeySafetyNotice',
      'deleteUserKeyEpochPin',
      `deleteLogPin:${accountLogPinId({ spaceId: 'space-123' })}`,
      `deleteLogPin:${userKeyRosterPinId({ spaceId: 'space-123' })}`,
      'deleteAccountDidForSpace'
    ])
  })

  it('refuses a wrong passphrase without touching any data', async () => {
    state.verifyFails = 'wrong'
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'wrong'
    })
    expect(result).toBe('wrong-passphrase')
    expect(state.calls).toEqual(['verifyPassphrase'])
  })

  it('reports a verification failure as a generic failure, data untouched', async () => {
    state.verifyFails = 'other'
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('failed')
    expect(state.calls).toEqual(['verifyPassphrase'])
  })

  it('keeps the keyring when the wipe fails, so the Space is never orphaned', async () => {
    state.wipeFails = true
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('failed')
    expect(state.calls).toEqual(['verifyPassphrase', 'wipeStorage'])
  })
})

describe('changeAccountPassphrase', () => {
  it('adopts the rebind into the live session right after the change', async () => {
    const { oldPassphraseRetired, unlockSpaceId } =
      await changeAccountPassphrase({
        session: makeSession(),
        oldPassphrase: 'old',
        newPassphrase: 'new'
      })
    expect(oldPassphraseRetired).toBe(true)
    expect(unlockSpaceId).toBe('space-new')
    expect(state.calls).toEqual(['changePassphrase', 'adoptPassphraseRebind'])
  })
})
