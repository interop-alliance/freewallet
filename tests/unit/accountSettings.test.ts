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
  rotation: 'skipped' as 'rotated' | 'skipped' | 'failed',
  // The deletion's (a2)/(b0)/(b1) seams: the registry snapshot, the account
  // document the companion is discovered through, and the auxiliary Space's
  // collection listing.
  registry: null as unknown,
  registryFails: false,
  accountDoc: { id: 'did:webvh:account' } as unknown,
  accountLogFails: false,
  companionCollections: [] as string[],
  companionDeleteFails: false,
  artifactFailures: [] as string[]
}))

const FRESH_USER_KEY = { id: 'did:key:z6LSFreshUserKey' }
const NEW_LADDER_SEED = new Uint8Array(32).fill(7)

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
    return { ladderSeed: NEW_LADDER_SEED }
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
  deleteUnlockMethodArtifacts: vi.fn(
    async ({ entry }: { entry: { type: string } }) => {
      state.calls.push(`deleteUnlockMethodArtifacts:${entry.type}`)
      if (state.artifactFailures.includes(entry.type)) {
        throw new Error(`could not delete the ${entry.type} artifacts`)
      }
    }
  ),
  getUnlockMethods: vi.fn(async () => {
    if (state.registryFails) {
      throw new Error('registry unreadable')
    }
    return state.registry
  }),
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

vi.mock('@/session/verifiedLog', () => ({
  invalidateVerifiedLog: vi.fn(),
  verifiedAccountLog: vi.fn(async () => {
    if (state.accountLogFails) {
      throw new Error('account log unreachable')
    }
    return { doc: state.accountDoc }
  })
}))

vi.mock('@interop/was-client', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client')>()),
  // The auxiliary companion Space handle: its `gen-` collection listing (the
  // pin slots to drop) and the one recursive delete.
  WasClient: class {
    space(spaceId: string) {
      return {
        collectionsPages: async function* () {
          yield {
            items: state.companionCollections.map(id => ({ id }))
          }
        },
        delete: async () => {
          state.calls.push(`companionSpaceDelete:${spaceId}`)
          if (state.companionDeleteFails) {
            throw new Error('auxiliary Space delete failed')
          }
        }
      }
    }
  }
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
const { deleteUnlockMethodArtifacts } = await import('@/session/unlockMethods')
const { accountLogPinId, companionLogPinId } =
  await import('@interop/wallet-core/webvh')
const { userKeyRosterPinId } = await import('@interop/wallet-core/keys')
const { durableSessionPersistence } = await import('@/session/persistence')

const ACCOUNT_DID = 'did:webvh:QmScid:was.example.test:space:space-123:id'
const COMPANION_SPACE_ID = 'companion-space-1'
const GENERATION_ID = 'gen-Ux3v0kQf9aPmB2hZ'
const COMPANION_DID =
  'did:webvh:QmCompanionScid:was.example.test:space:' +
  `${COMPANION_SPACE_ID}:${GENERATION_ID}`

/**
 * An account document whose `#DelegatedClients` service entry points at the
 * companion above -- what the deletion's discovery step reads.
 *
 * @returns {object}
 */
function docWithCompanionPointer(): object {
  return {
    id: ACCOUNT_DID,
    service: [
      {
        id: `${ACCOUNT_DID}#delegated-clients`,
        type: 'https://w3id.org/byoe#DelegatedClients',
        serviceEndpoint: COMPANION_DID
      }
    ]
  }
}

/**
 * Two registry entries, so the walk's per-entry best-effort is observable.
 *
 * @returns {object}
 */
function registryWithTwoMethods(): object {
  return {
    version: 1,
    userHandle: 'AAAAAAAAAAAAAAAAAAAAAA',
    methods: [
      {
        type: 'passphrase',
        createdAt: '2026-08-01T00:00:00.000Z',
        unlockSpaceId: 'unlock-space-passphrase'
      },
      {
        type: 'passkey',
        label: 'Passkey',
        createdAt: '2026-08-02T00:00:00.000Z',
        credentialId: 'Y3JlZC1pZA',
        transports: ['internal'],
        backupEligibility: true,
        backupState: true,
        unlockSpaceId: 'unlock-space-passkey'
      }
    ]
  }
}

function makeSession() {
  return {
    user: { id: 'did:key:zClient' },
    isGuest: false,
    profile: {
      persistence: durableSessionPersistence(),
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
  state.registry = null
  state.registryFails = false
  state.accountDoc = { id: ACCOUNT_DID }
  state.accountLogFails = false
  state.companionCollections = []
  state.companionDeleteFails = false
  state.artifactFailures = []
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

  it("deletes every unlock method's artifacts before the wipe", async () => {
    state.registry = registryWithTwoMethods()
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('deleted')
    expect(vi.mocked(deleteUnlockMethodArtifacts)).toHaveBeenCalledTimes(2)
    expect(vi.mocked(deleteUnlockMethodArtifacts)).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        entry: expect.objectContaining({ type: 'passphrase' })
      })
    )
    expect(vi.mocked(deleteUnlockMethodArtifacts)).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        entry: expect.objectContaining({ type: 'passkey' })
      })
    )
    // The dangling existence-oracle Spaces go before the fatal wipe.
    expect(state.calls).toEqual([
      'verifyPassphrase',
      'deleteUnlockMethodArtifacts:passphrase',
      'deleteUnlockMethodArtifacts:passkey',
      'wipeStorage',
      'deleteKeyring',
      'deletePasskeySafetyNotice',
      'deleteUserKeyEpochPin',
      `deleteLogPin:${accountLogPinId({ spaceId: 'space-123' })}`,
      `deleteLogPin:${userKeyRosterPinId({ spaceId: 'space-123' })}`,
      'deleteAccountDidForSpace'
    ])
  })

  it('walks past an entry whose artifacts cannot be deleted', async () => {
    state.registry = registryWithTwoMethods()
    state.artifactFailures = ['passphrase']
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    // One entry failing stops neither the next entry nor the deletion.
    expect(result).toBe('deleted')
    expect(vi.mocked(deleteUnlockMethodArtifacts)).toHaveBeenCalledTimes(2)
    expect(state.calls).toContain('deleteUnlockMethodArtifacts:passkey')
    expect(state.calls).toContain('wipeStorage')
    warn.mockRestore()
  })

  it('tears the auxiliary Space down before the wipe and drops its pin slots', async () => {
    state.accountDoc = docWithCompanionPointer()
    state.companionCollections = [GENERATION_ID, 'not-a-generation']
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('deleted')
    // Before the wipe: once the account Space is gone the server can no
    // longer resolve the auxiliary Space's did:webvh controller.
    expect(state.calls).toEqual([
      'verifyPassphrase',
      `companionSpaceDelete:${COMPANION_SPACE_ID}`,
      `deleteLogPin:${companionLogPinId({
        spaceId: COMPANION_SPACE_ID,
        generationId: GENERATION_ID
      })}`,
      'wipeStorage',
      'deleteKeyring',
      'deletePasskeySafetyNotice',
      'deleteUserKeyEpochPin',
      `deleteLogPin:${accountLogPinId({ spaceId: 'space-123' })}`,
      `deleteLogPin:${userKeyRosterPinId({ spaceId: 'space-123' })}`,
      'deleteAccountDidForSpace'
    ])
  })

  it('deletes the account even when the discovery steps fail', async () => {
    state.registryFails = true
    state.accountLogFails = true
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    // Warn-only: an unreadable registry or log narrows the teardown.
    expect(result).toBe('deleted')
    expect(vi.mocked(deleteUnlockMethodArtifacts)).not.toHaveBeenCalled()
    expect(state.calls).toContain('wipeStorage')
    warn.mockRestore()
  })

  it('survives a failing auxiliary-Space delete, leaving a typed orphan', async () => {
    state.accountDoc = docWithCompanionPointer()
    state.companionCollections = [GENERATION_ID]
    state.companionDeleteFails = true
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const result = await deleteAccount({
      session: makeSession(),
      passphrase: 'correct horse battery staple'
    })
    expect(result).toBe('deleted')
    expect(state.calls).toContain('wipeStorage')
    // The generation pin slot rides behind the Space delete, so a failure
    // leaves it for the next login's own bookkeeping.
    expect(state.calls).not.toContain(
      `deleteLogPin:${companionLogPinId({
        spaceId: COMPANION_SPACE_ID,
        generationId: GENERATION_ID
      })}`
    )
    warn.mockRestore()
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
        verb: 'changing the passphrase',
        survivingLadderSeed: NEW_LADDER_SEED
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
