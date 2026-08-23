// @vitest-environment node
/**
 * Unit tests for the login-time completer
 * (`src/session/pendingRetirement.ts`): when a registry entry naming a
 * credential other than the one logging in is a pending retirement, when it
 * is not, what the completer writes afterwards, when a bare or absent
 * passphrase entry is rebuilt from the credential logging in, and the passkey
 * sibling that rebuilds a bare passkey entry.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const MY_KAK = 'z6LSgJbFbAEq4zhHZ7FrQKqF6ja8tcjNpVu8ZbhnxmunPkN7'
const OTHER_KAK = 'z6LStRqthDcQTuohXDkypMe9aQ2ZCLWrV7u79pB25oza2u7D'

const POINTER = {
  did: 'did:webvh:QmScid:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

const FRESH_USER_KEY = { id: 'did:key:z6LSFreshUserKey' }

const state = vi.hoisted(() => ({
  calls: [] as string[],
  enrolled: true,
  // Whether a registry record exists at all.
  registry: true,
  // The registry's passphrase entry, as this login reads it.
  entry: null as unknown,
  // The registry's passkey entries, as a passkey login reads them.
  passkeyEntries: [] as unknown[],
  // Whether the account document lists the LOGIN credential's VERBATIM
  // key-agreement VM -- the form a passkey publishes under.
  loginPasskeyStanding: true,
  // Whether the account document lists the LOGIN credential's commitment VM.
  loginCredentialStanding: true,
  // Whether it still lists the NAMED (pending) credential's: gone means the
  // torn run's document edit landed and only its registry write was lost.
  namedCredentialStanding: true,
  rotationThrows: false
}))

vi.mock('@/session/enrolledContext', () => ({
  enrolledClientContext: vi.fn(() =>
    state.enrolled ? { pointer: POINTER } : null
  )
}))

vi.mock('@/session/credentialRotation', () => ({
  rotateOffUnlockCredential: vi.fn(async () => {
    state.calls.push('rotateOffUnlockCredential')
    if (state.rotationThrows) {
      throw new Error('log conflict')
    }
    return {
      rotated: true,
      collections: { outcomes: {}, failed: [] },
      userKey: FRESH_USER_KEY
    }
  })
}))

vi.mock('@/session/userKeyAdoption', () => ({
  adoptRotatedUserKey: vi.fn(async () => {
    state.calls.push('adoptRotatedUserKey')
  })
}))

vi.mock('@/session/standingUnlock', () => ({
  standingFieldsOfKeyringHit: vi.fn(async () => ({
    keyAgreementKeyMultibase: MY_KAK,
    updateKeyMultibase: 'z6MkMyRung0'
  }))
}))

vi.mock('@/session/verifiedLog', () => ({
  verifiedAccountLog: vi.fn(async () => {
    state.calls.push('verifiedAccountLog')
    return { doc: await accountDocument() }
  })
}))

vi.mock('@/session/unlockMethods', () => ({
  getUnlockMethods: vi.fn(async () => {
    state.calls.push('getUnlockMethods')
    if (!state.registry) {
      return null
    }
    const methods = [
      ...(state.entry ? [state.entry] : []),
      ...state.passkeyEntries
    ]
    return { version: 1, userHandle: 'handle', methods }
  }),
  putUnlockMethods: vi.fn(async () => {
    state.calls.push('putUnlockMethods')
  }),
  upsertPassphraseUnlockMethod: vi.fn(({ record }) => record),
  upsertPasskeyUnlockMethod: vi.fn(({ record }) => record)
}))

import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import { unlockKeyVmId } from '@interop/wallet-core/unlock'
import { rotateOffUnlockCredential } from '@/session/credentialRotation'
import { adoptRotatedUserKey } from '@/session/userKeyAdoption'
import {
  putUnlockMethods,
  upsertPassphraseUnlockMethod,
  upsertPasskeyUnlockMethod
} from '@/session/unlockMethods'
import {
  rebuildBarePasskeyEntry,
  repairTornPassphraseRetirement
} from '@/session/pendingRetirement'
import type { KeyringFetchResult } from '@/session/keyring'
import type { Session } from '@/types/auth'

/**
 * The account document, listing the login credential's commitment
 * verification method only when the scenario says it is standing.
 *
 * @returns {Promise<object>}
 */
async function accountDocument(): Promise<object> {
  const listed: string[] = []
  if (state.loginCredentialStanding) {
    listed.push(await commitmentVmId(MY_KAK))
  }
  if (state.namedCredentialStanding) {
    listed.push(await commitmentVmId(OTHER_KAK))
  }
  if (state.loginPasskeyStanding) {
    listed.push(
      unlockKeyVmId({
        did: POINTER.did,
        keyAgreement: { publicKeyMultibase: MY_KAK }
      })
    )
  }
  return {
    id: POINTER.did,
    verificationMethod: listed.map(id => ({ id, type: 'MultikeyCommitment' })),
    keyAgreement: listed
  }
}

/**
 * The commitment verification-method id a passphrase publishes under.
 *
 * @param keyAgreementKeyMultibase {string}
 * @returns {Promise<string>}
 */
async function commitmentVmId(
  keyAgreementKeyMultibase: string
): Promise<string> {
  return unlockKeyVmId({
    did: POINTER.did,
    keyAgreement: {
      commitment: await keyAgreementCommitment({ keyAgreementKeyMultibase })
    }
  })
}

/**
 * A registry entry recording one credential's standing configuration.
 *
 * @param options {object}
 * @param options.keyAgreementKeyMultibase {string}
 * @returns {object}
 */
function entryFor({
  keyAgreementKeyMultibase
}: {
  keyAgreementKeyMultibase: string
}): object {
  return {
    type: 'passphrase',
    createdAt: '2026-08-01T00:00:00.000Z',
    unlockSpaceId: 'unlock-space-new',
    manageCapability: { id: 'urn:zcap:stored-manage' },
    keyAgreementKeyMultibase,
    updateKeyMultibase: 'z6MkRecordedRung'
  }
}

/**
 * A passphrase entry missing its identity members -- the bare state an
 * earlier defect left behind.
 *
 * @returns {object}
 */
function bareEntry(): object {
  return {
    type: 'passphrase',
    createdAt: '2026-08-01T00:00:00.000Z',
    unlockSpaceId: 'unlock-space-new',
    manageCapability: { id: 'urn:zcap:stored-manage' }
  }
}

function makeSession(type: 'passphrase' | 'passkey' = 'passphrase'): Session {
  return {
    user: { id: 'did:key:zClient' },
    isGuest: false,
    storage: { spaceId: POINTER.spaceId },
    profile: {
      accountPointer: POINTER,
      unlockMethod: { type, unlockSpaceId: 'unlock-space-new' }
    }
  } as unknown as Session
}

function makeFound(): KeyringFetchResult {
  return {
    unlockSpaceId: 'unlock-space-new',
    manageCapability: { id: 'urn:zcap:manage' },
    standingClient: { keyAgreementKeyMultibase: MY_KAK }
  } as unknown as KeyringFetchResult
}

beforeEach(() => {
  state.calls = []
  state.enrolled = true
  state.registry = true
  state.entry = entryFor({ keyAgreementKeyMultibase: OTHER_KAK })
  state.passkeyEntries = []
  state.loginPasskeyStanding = true
  state.loginCredentialStanding = true
  state.namedCredentialStanding = true
  state.rotationThrows = false
  vi.clearAllMocks()
})

describe('repairTornPassphraseRetirement', () => {
  it('retires the named credential and records its own standing configuration', async () => {
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      'rotateOffUnlockCredential',
      'adoptRotatedUserKey',
      'getUnlockMethods',
      'putUnlockMethods'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).toHaveBeenCalledWith(
      expect.objectContaining({
        method: expect.objectContaining({
          keyAgreementKeyMultibase: OTHER_KAK
        }),
        verb: 'finishing a passphrase change'
      })
    )
    expect(vi.mocked(adoptRotatedUserKey)).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: POINTER.spaceId,
        userKey: FRESH_USER_KEY
      })
    )
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith({
      record: expect.anything(),
      unlockSpaceId: 'unlock-space-new',
      manageCapability: { id: 'urn:zcap:manage' },
      standing: {
        keyAgreementKeyMultibase: MY_KAK,
        updateKeyMultibase: 'z6MkMyRung0'
      }
    })
  })

  it('keeps the stored management zcap when this login minted none', async () => {
    const found = makeFound()
    delete (found as { manageCapability?: unknown }).manageCapability
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found
    })
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith(
      expect.objectContaining({
        manageCapability: { id: 'urn:zcap:stored-manage' }
      })
    )
  })

  it('records the standing configuration without retiring when the edit already landed', async () => {
    // The torn run's document edit landed and only its registry write was
    // lost: the roster and cascade residue is the ordinary login sweep's,
    // and a retirement here would swap the annex generation every login.
    state.namedCredentialStanding = false
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      'getUnlockMethods',
      'putUnlockMethods'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(vi.mocked(adoptRotatedUserKey)).not.toHaveBeenCalled()
  })

  it('skips an entry already naming the credential logging in', async () => {
    state.entry = entryFor({ keyAgreementKeyMultibase: MY_KAK })
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods'])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
  })

  it('writes nothing when the login credential is not in the document', async () => {
    // The other reading of the same registry state: an OLD passphrase whose
    // unlock Space delete failed, logging in after a change that completed.
    // Retiring the entry's credential there would strip the CURRENT one.
    state.loginCredentialStanding = false
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods', 'verifiedAccountLog'])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(vi.mocked(putUnlockMethods)).not.toHaveBeenCalled()
  })

  it('rebuilds a bare entry when the login credential is standing', async () => {
    state.entry = bareEntry()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      'putUnlockMethods'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith({
      record: expect.anything(),
      unlockSpaceId: 'unlock-space-new',
      manageCapability: { id: 'urn:zcap:manage' },
      standing: {
        keyAgreementKeyMultibase: MY_KAK,
        updateKeyMultibase: 'z6MkMyRung0'
      }
    })
    warn.mockRestore()
  })

  it('leaves a bare entry alone when the login credential is not standing', async () => {
    // A bare entry on a credential the document never carried is honest:
    // nothing has been established for it to record.
    state.entry = bareEntry()
    state.loginCredentialStanding = false
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods', 'verifiedAccountLog'])
    expect(vi.mocked(putUnlockMethods)).not.toHaveBeenCalled()
  })

  it('rebuilds an absent passphrase entry the same way', async () => {
    state.entry = null
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      'putUnlockMethods'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith(
      expect.objectContaining({
        standing: {
          keyAgreementKeyMultibase: MY_KAK,
          updateKeyMultibase: 'z6MkMyRung0'
        }
      })
    )
    warn.mockRestore()
  })

  it('writes nothing for an entry naming another credential with no rung', async () => {
    // The repair attributes the named credential's ladder by its recorded
    // rung, and rebuilding the entry from this login would silently un-name
    // a credential that may still stand.
    const entry = entryFor({ keyAgreementKeyMultibase: OTHER_KAK }) as {
      updateKeyMultibase?: string
    }
    delete entry.updateKeyMultibase
    state.entry = entry
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods'])
    expect(vi.mocked(putUnlockMethods)).not.toHaveBeenCalled()
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    warn.mockRestore()
  })

  it('rebuilds an entry naming THIS credential with no rung', async () => {
    const entry = entryFor({ keyAgreementKeyMultibase: MY_KAK }) as {
      updateKeyMultibase?: string
    }
    delete entry.updateKeyMultibase
    state.entry = entry
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      'putUnlockMethods'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    warn.mockRestore()
  })

  it('writes nothing when there is no registry at all', async () => {
    // The backfill creates the record; the login after that finds an entry.
    state.registry = false
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods'])
    expect(vi.mocked(putUnlockMethods)).not.toHaveBeenCalled()
  })

  it('skips a passkey login', async () => {
    await repairTornPassphraseRetirement({
      session: makeSession('passkey'),
      found: makeFound()
    })
    expect(state.calls).toEqual([])
  })

  it('skips a session that cannot act as an enrolled client', async () => {
    state.enrolled = false
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([])
  })

  it('leaves the entry alone when the retirement throws', async () => {
    state.rotationThrows = true
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(
      repairTornPassphraseRetirement({
        session: makeSession(),
        found: makeFound()
      })
    ).rejects.toThrow('log conflict')
    expect(vi.mocked(putUnlockMethods)).not.toHaveBeenCalled()
    warn.mockRestore()
  })
})

/**
 * A passkey registry entry, bare unless standing members are supplied.
 *
 * @param [options] {object}
 * @param [options.keyAgreementKeyMultibase] {string}
 * @returns {object}
 */
function passkeyEntry({
  keyAgreementKeyMultibase
}: {
  keyAgreementKeyMultibase?: string
} = {}): object {
  return {
    type: 'passkey',
    label: 'Yubikey',
    createdAt: '2026-08-01T00:00:00.000Z',
    credentialId: 'Y3JlZC1vbGQ',
    transports: ['usb'],
    backupEligibility: false,
    backupState: false,
    unlockSpaceId: 'unlock-space-new',
    ...(keyAgreementKeyMultibase ? { keyAgreementKeyMultibase } : {})
  }
}

describe('rebuildBarePasskeyEntry', () => {
  beforeEach(() => {
    // A passkey login reads no passphrase entry; only its own.
    state.entry = null
  })

  it('rebuilds a bare passkey entry when the credential is standing', async () => {
    state.passkeyEntries = [passkeyEntry()]
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await rebuildBarePasskeyEntry({
      session: makeSession('passkey'),
      found: makeFound()
    })
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      'putUnlockMethods'
    ])
    expect(vi.mocked(upsertPasskeyUnlockMethod)).toHaveBeenCalledWith({
      record: expect.anything(),
      entry: expect.objectContaining({
        type: 'passkey',
        credentialId: 'Y3JlZC1vbGQ',
        keyAgreementKeyMultibase: MY_KAK,
        updateKeyMultibase: 'z6MkMyRung0'
      })
    })
    warn.mockRestore()
  })

  it('writes nothing when the passkey is not in the document', async () => {
    // A passkey publishes its key-agreement key VERBATIM, so the commitment
    // form standing for a passphrase does not cover it.
    state.passkeyEntries = [passkeyEntry()]
    state.loginPasskeyStanding = false
    await rebuildBarePasskeyEntry({
      session: makeSession('passkey'),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods', 'verifiedAccountLog'])
    expect(vi.mocked(putUnlockMethods)).not.toHaveBeenCalled()
  })

  it('leaves an entry that already names a credential alone', async () => {
    state.passkeyEntries = [passkeyEntry({ keyAgreementKeyMultibase: MY_KAK })]
    await rebuildBarePasskeyEntry({
      session: makeSession('passkey'),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods'])
    expect(vi.mocked(putUnlockMethods)).not.toHaveBeenCalled()
  })

  it('writes nothing when this passkey has no entry at all', async () => {
    // Creating one needs members no keyring hit carries (the WebAuthn
    // credential id, the label, the registration flags).
    state.passkeyEntries = []
    await rebuildBarePasskeyEntry({
      session: makeSession('passkey'),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods'])
    expect(vi.mocked(putUnlockMethods)).not.toHaveBeenCalled()
  })

  it('skips a passphrase login', async () => {
    state.passkeyEntries = [passkeyEntry()]
    await rebuildBarePasskeyEntry({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([])
  })
})
