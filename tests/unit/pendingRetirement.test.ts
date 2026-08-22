// @vitest-environment node
/**
 * Unit tests for the login-time completer
 * (`src/session/pendingRetirement.ts`): when a registry entry naming a
 * credential other than the one logging in is a pending retirement, when it
 * is not, and what the completer writes afterwards.
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
  // The registry's passphrase entry, as this login reads it.
  entry: null as unknown,
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
    return state.entry
      ? { version: 1, userHandle: 'handle', methods: [state.entry] }
      : { version: 1, userHandle: 'handle', methods: [] }
  }),
  putUnlockMethods: vi.fn(async () => {
    state.calls.push('putUnlockMethods')
  }),
  upsertPassphraseUnlockMethod: vi.fn(({ record }) => record)
}))

import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import { unlockKeyVmId } from '@interop/wallet-core/unlock'
import { rotateOffUnlockCredential } from '@/session/credentialRotation'
import { adoptRotatedUserKey } from '@/session/userKeyAdoption'
import {
  putUnlockMethods,
  upsertPassphraseUnlockMethod
} from '@/session/unlockMethods'
import { finishPendingPassphraseRetirement } from '@/session/pendingRetirement'
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
  state.entry = entryFor({ keyAgreementKeyMultibase: OTHER_KAK })
  state.loginCredentialStanding = true
  state.namedCredentialStanding = true
  state.rotationThrows = false
  vi.clearAllMocks()
})

describe('finishPendingPassphraseRetirement', () => {
  it('retires the named credential and records its own standing configuration', async () => {
    await finishPendingPassphraseRetirement({
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
    await finishPendingPassphraseRetirement({
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
    await finishPendingPassphraseRetirement({
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
    await finishPendingPassphraseRetirement({
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
    await finishPendingPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods', 'verifiedAccountLog'])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(vi.mocked(putUnlockMethods)).not.toHaveBeenCalled()
  })

  it('skips a passkey login', async () => {
    await finishPendingPassphraseRetirement({
      session: makeSession('passkey'),
      found: makeFound()
    })
    expect(state.calls).toEqual([])
  })

  it('skips a session that cannot act as an enrolled client', async () => {
    state.enrolled = false
    await finishPendingPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([])
  })

  it('leaves the entry alone when the retirement throws', async () => {
    state.rotationThrows = true
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(
      finishPendingPassphraseRetirement({
        session: makeSession(),
        found: makeFound()
      })
    ).rejects.toThrow('log conflict')
    expect(vi.mocked(putUnlockMethods)).not.toHaveBeenCalled()
    warn.mockRestore()
  })
})
