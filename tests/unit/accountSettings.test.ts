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
  wipeFails: false,
  // What the credential-rotation ceremony reports back: a rotation with a
  // fresh key, a skip (nothing standing to retire), or a failure.
  rotation: 'skipped' as 'rotated' | 'skipped' | 'failed'
}))

const FRESH_USER_KEY = { id: 'did:key:z6LSFreshUserKey' }

vi.mock('@/session/credentialRotation', () => ({
  rotateOffUnlockCredential: vi.fn(async () => {
    state.calls.push('rotateOffUnlockCredential')
    if (state.rotation === 'failed') {
      throw new Error('log conflict')
    }
    return state.rotation === 'rotated'
      ? {
          rotated: true,
          collections: { outcomes: {}, failed: [] },
          userKey: FRESH_USER_KEY
        }
      : { rotated: false, collections: { outcomes: {}, failed: [] } }
  })
}))

vi.mock('@/session/userKeyAdoption', () => ({
  adoptRotatedUserKey: vi.fn(async () => {
    state.calls.push('adoptRotatedUserKey')
  })
}))

vi.mock('@/session/standingUnlock', () => ({
  establishPassphrasePosture: vi.fn(async () => {
    state.calls.push('establishPassphrasePosture')
  }),
  establishStandingUnlock: vi.fn(async () => ({
    unlockSpaceId: 'space-bound',
    standingFields: {}
  }))
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
  revokeUnlockMethod: vi.fn(async () => {
    state.calls.push('revokeUnlockMethod')
    return state.rotation === 'rotated'
      ? {
          rotated: true,
          collections: { outcomes: {}, failed: [] },
          userKey: FRESH_USER_KEY
        }
      : null
  }),
  revokeUnlockMethodByCeremony: vi.fn(async () => {
    state.calls.push('revokeUnlockMethodByCeremony')
    return state.rotation === 'rotated'
      ? {
          rotated: true,
          collections: { outcomes: {}, failed: [] },
          userKey: FRESH_USER_KEY
        }
      : null
  }),
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

const { changeAccountPassphrase, deleteAccount, removeAccountPasskey } =
  await import('@/session/accountSettings')
const { rotateOffUnlockCredential } =
  await import('@/session/credentialRotation')
const { adoptRotatedUserKey } = await import('@/session/userKeyAdoption')
const {
  revokeUnlockMethod,
  revokeUnlockMethodByCeremony,
  canRevokeWithoutCeremony
} = await import('@/session/unlockMethods')
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
  state.rotation = 'skipped'
  vi.clearAllMocks()
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
  it('adopts the rebind, then retires the old credential', async () => {
    const { oldPassphraseRetired, unlockSpaceId, rotation } =
      await changeAccountPassphrase({
        session: makeSession(),
        oldPassphrase: 'old',
        newPassphrase: 'new'
      })
    expect(oldPassphraseRetired).toBe(true)
    expect(unlockSpaceId).toBe('space-new')
    expect(rotation).toBe('skipped')
    // The new passphrase gets its standing posture before the old one is
    // retired, so the account is never left with no standing credential.
    expect(state.calls).toEqual([
      'changePassphrase',
      'adoptPassphraseRebind',
      'establishPassphrasePosture',
      'rotateOffUnlockCredential'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).toHaveBeenCalledWith(
      expect.objectContaining({
        method: expect.objectContaining({ type: 'passphrase' }),
        verb: 'changing the passphrase'
      })
    )
    expect(vi.mocked(adoptRotatedUserKey)).not.toHaveBeenCalled()
  })

  it('adopts the rotated user key when the retirement rotated', async () => {
    state.rotation = 'rotated'
    const { rotation } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    expect(rotation).toBe('rotated')
    expect(state.calls).toEqual([
      'changePassphrase',
      'adoptPassphraseRebind',
      'establishPassphrasePosture',
      'rotateOffUnlockCredential',
      'adoptRotatedUserKey'
    ])
    expect(vi.mocked(adoptRotatedUserKey)).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: 'space-123',
        userKey: FRESH_USER_KEY
      })
    )
  })

  it('reports a failed retirement without failing the change', async () => {
    state.rotation = 'failed'
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { oldPassphraseRetired, rotation } = await changeAccountPassphrase({
      session: makeSession(),
      oldPassphrase: 'old',
      newPassphrase: 'new'
    })
    // The passphrase change itself has landed and cannot roll back.
    expect(oldPassphraseRetired).toBe(true)
    expect(rotation).toBe('failed')
    expect(vi.mocked(adoptRotatedUserKey)).not.toHaveBeenCalled()
    error.mockRestore()
  })
})

describe('removeAccountPasskey', () => {
  const ENTRY = {
    type: 'passkey',
    label: 'Passkey',
    createdAt: '2026-08-01T00:00:00.000Z',
    credentialId: 'Y3JlZC1pZA',
    transports: ['internal'],
    backupEligibility: true,
    backupState: true,
    unlockSpaceId: 'unlock-space-abc'
  } as Parameters<typeof removeAccountPasskey>[0]['entry']

  it('revokes tap-free and adopts the rotated user key', async () => {
    state.rotation = 'rotated'
    await removeAccountPasskey({ session: makeSession(), entry: ENTRY })
    expect(state.calls).toEqual(['revokeUnlockMethod', 'adoptRotatedUserKey'])
    expect(vi.mocked(revokeUnlockMethod)).toHaveBeenCalledWith(
      expect.objectContaining({ entry: ENTRY, verb: 'removing a passkey' })
    )
    expect(vi.mocked(adoptRotatedUserKey)).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: 'space-123',
        userKey: FRESH_USER_KEY
      })
    )
  })

  it('falls back to the ceremony path and skips adoption with no rotation', async () => {
    vi.mocked(canRevokeWithoutCeremony).mockReturnValueOnce(false)
    await removeAccountPasskey({ session: makeSession(), entry: ENTRY })
    expect(state.calls).toEqual(['revokeUnlockMethodByCeremony'])
    expect(vi.mocked(revokeUnlockMethodByCeremony)).toHaveBeenCalledOnce()
    expect(vi.mocked(adoptRotatedUserKey)).not.toHaveBeenCalled()
  })

  it('propagates a failed revocation, so a retry can converge', async () => {
    vi.mocked(revokeUnlockMethod).mockRejectedValueOnce(new Error('down'))
    await expect(
      removeAccountPasskey({ session: makeSession(), entry: ENTRY })
    ).rejects.toThrow('down')
    expect(vi.mocked(adoptRotatedUserKey)).not.toHaveBeenCalled()
  })
})
