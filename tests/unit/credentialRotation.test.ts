// @vitest-environment node
/**
 * Unit tests for freewallet's half of the standing-unlock-credential
 * retirement ceremony (`src/session/credentialRotation.ts`). The ceremony
 * itself -- the document posture edit, the roster rotation, the collection
 * fan-out, and their convergence -- is `retireUnlockCredential` in
 * `@interop/wallet-core/unlock` and is covered by that package's own tests;
 * what is exercised here is the glue this wallet supplies: the two skip
 * conditions, the posture shape handed over per method type, the stores and
 * pins, the adoption callback's paired persistence, the error discipline, and
 * the verified-log memo invalidation on both sides of the call.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined,
  calls: [] as string[]
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return state.wasUrl
  }
}))

vi.mock('@interop/wallet-core/unlock', () => ({
  retireUnlockCredential: vi.fn()
}))

vi.mock('@/lib/sessionKey', () => ({
  savePinFromDescriptor: vi.fn(async () => {
    state.calls.push('savePinFromDescriptor')
  }),
  loadUserKeyEpochPin: vi.fn(async () => {
    state.calls.push('loadUserKeyEpochPin')
    return 'did:key:z6LSOldUserKey'
  }),
  // Built eagerly by the durable persistence handle the fixture carries.
  sessionLogPinStore: vi.fn(() => ({
    read: async () => null,
    write: async () => undefined
  }))
}))

vi.mock('@/session/rosterStore', () => ({
  sessionRosterStore: vi.fn(() => ({ rosterStore: true }))
}))

vi.mock('@/session/userKeyCascade', () => ({
  cascadeCollections: vi.fn(() => ({
    collectionIds: async () => ['private-credentials'],
    storeFor: () => ({ isDescriptorStore: true }),
    isEncrypted: async () => true
  }))
}))

vi.mock('@/session/verifiedLog', () => ({
  invalidateVerifiedLog: vi.fn(() => {
    state.calls.push('invalidateVerifiedLog')
  })
}))

import { retireUnlockCredential } from '@interop/wallet-core/unlock'
import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import { loadUserKeyEpochPin, savePinFromDescriptor } from '@/lib/sessionKey'
import { durableSessionPersistence } from '@/session/persistence'
import { sessionRosterStore } from '@/session/rosterStore'
import { cascadeCollections } from '@/session/userKeyCascade'
import { invalidateVerifiedLog } from '@/session/verifiedLog'
import { rotateOffUnlockCredential } from '@/session/credentialRotation'
import type { Session } from '@/types/auth'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

const OLD_USER_KEY = {
  id: 'did:key:z6LSOldUserKey',
  secret: new Uint8Array(32).fill(1)
}
const FRESH_USER_KEY = {
  id: 'did:key:z6LSFreshUserKey',
  secret: new Uint8Array(32).fill(2)
}
const ROSTER_DESCRIPTOR = { epochs: [{ id: FRESH_USER_KEY.id }] }

/**
 * A standing passphrase posture (the registry entry's public halves).
 */
const PASSPHRASE_METHOD = {
  type: 'passphrase' as const,
  keyAgreementKeyMultibase: 'z6LSgJbFbAEq4zhHZ7FrQKqF6ja8tcjNpVu8ZbhnxmunPkN7',
  updateKeyMultibase: 'z6MkPassphraseRung'
}

const PASSKEY_METHOD = {
  type: 'passkey' as const,
  keyAgreementKeyMultibase: 'z6LStRqthDcQTuohXDkypMe9aQ2ZCLWrV7u79pB25oza2u7D',
  updateKeyMultibase: 'z6MkPasskeyRung'
}

/**
 * A stand-in for the shared ceremony that drives its adoption callback where
 * the real one does, so the freewallet-side persistence is exercised in place.
 *
 * @param [options] {object}
 * @param [options.rotated] {boolean}   whether the roster rotated on this run
 * @returns {Function}
 */
function ceremonyDriving({ rotated = true } = {}) {
  return async (options: Parameters<typeof retireUnlockCredential>[0]) => {
    state.calls.push('retireUnlockCredential')
    const userKey = rotated ? FRESH_USER_KEY : OLD_USER_KEY
    if (rotated) {
      await options.onUserKeyAdopted?.({
        userKey,
        latestEpochId: userKey.id,
        descriptor: ROSTER_DESCRIPTOR as never
      })
    }
    return {
      rotated,
      collections: {
        outcomes: { 'private-credentials': 'rotated' },
        failed: []
      },
      document: { id: POINTER.did },
      userKey,
      rosterDescriptor: ROSTER_DESCRIPTOR
    } as never
  }
}

/**
 * A live-session fixture carrying exactly what the ceremony touches.
 */
function sessionWith(
  overrides: Partial<{
    remoteStore: unknown
    pointerDid: string | undefined
    clientWebvhKeys: unknown
    clientKeyAgreementKey: unknown
  }> = {}
): Session {
  const remoteStore =
    'remoteStore' in overrides
      ? overrides.remoteStore
      : { webvhIdStore: vi.fn(() => ({ isWebvhIdStore: true })) }
  return {
    user: { id: 'did:key:z6MkRetiringClient' },
    isGuest: false,
    storage: { remoteStore },
    profile: {
      accountPointer:
        'pointerDid' in overrides && overrides.pointerDid === undefined
          ? undefined
          : { ...POINTER, did: overrides.pointerDid ?? POINTER.did },
      keyAgent: { id: 'did:key:z6MkRetiringClient' },
      zcapClient: { isZcapClient: true },
      clientWebvhKeys:
        'clientWebvhKeys' in overrides
          ? overrides.clientWebvhKeys
          : { updateSeed: new Uint8Array(32), stagedSeed: new Uint8Array(32) },
      clientKeyAgreementKey:
        'clientKeyAgreementKey' in overrides
          ? overrides.clientKeyAgreementKey
          : { id: 'did:key:z6MkRetiringClient#z6LSRetiringClient' },
      userKey: OLD_USER_KEY,
      persistence: durableSessionPersistence(),
      persistClientKeys: vi.fn(async () => {
        state.calls.push('persistClientKeys')
      })
    }
  } as unknown as Session
}

beforeEach(() => {
  state.wasUrl = 'https://was.example.test'
  state.calls = []
  vi.clearAllMocks()
  vi.mocked(retireUnlockCredential).mockImplementation(ceremonyDriving())
})

describe('the skip conditions', () => {
  it('skips a method with no standing posture recorded', async () => {
    const withoutKak = await rotateOffUnlockCredential({
      session: sessionWith(),
      method: { type: 'passphrase', updateKeyMultibase: 'z6MkRung' },
      verb: 'changing the passphrase'
    })
    const withoutRung = await rotateOffUnlockCredential({
      session: sessionWith(),
      method: { type: 'passkey', keyAgreementKeyMultibase: 'z6LSKak' },
      verb: 'removing a passkey'
    })
    expect(withoutKak).toBeNull()
    expect(withoutRung).toBeNull()
    expect(vi.mocked(retireUnlockCredential)).not.toHaveBeenCalled()
  })

  it('skips a session that cannot act as an enrolled client', async () => {
    state.wasUrl = undefined
    expect(
      await rotateOffUnlockCredential({
        session: sessionWith(),
        method: PASSPHRASE_METHOD,
        verb: 'changing the passphrase'
      })
    ).toBeNull()

    state.wasUrl = 'https://was.example.test'
    for (const override of [
      { pointerDid: 'did:key:z6MkNotPromoted' },
      { clientWebvhKeys: undefined },
      { clientKeyAgreementKey: undefined },
      { remoteStore: undefined }
    ]) {
      expect(
        await rotateOffUnlockCredential({
          session: sessionWith(override),
          method: PASSPHRASE_METHOD,
          verb: 'changing the passphrase'
        })
      ).toBeNull()
    }
    expect(vi.mocked(retireUnlockCredential)).not.toHaveBeenCalled()
  })
})

describe('the ceremony hand-off', () => {
  it('publishes a passphrase posture as a hash commitment', async () => {
    const session = sessionWith()
    await rotateOffUnlockCredential({
      session,
      method: PASSPHRASE_METHOD,
      verb: 'changing the passphrase'
    })

    expect(vi.mocked(retireUnlockCredential)).toHaveBeenCalledWith(
      expect.objectContaining({
        idStore: { isWebvhIdStore: true },
        rosterStore: { rosterStore: true },
        updateKeys: session.profile.clientWebvhKeys,
        expectedDid: POINTER.did,
        verb: 'changing the passphrase',
        userKey: OLD_USER_KEY,
        clientKeyAgreementKey: session.profile.clientKeyAgreementKey,
        pinnedEpochId: OLD_USER_KEY.id,
        unlockKeys: {
          keyAgreement: {
            commitment: await keyAgreementCommitment({
              keyAgreementKeyMultibase:
                PASSPHRASE_METHOD.keyAgreementKeyMultibase
            })
          },
          updateKeyMultibase: PASSPHRASE_METHOD.updateKeyMultibase
        }
      })
    )
    expect(vi.mocked(sessionRosterStore)).toHaveBeenCalledWith(
      expect.objectContaining({ profile: session.profile })
    )
    expect(vi.mocked(cascadeCollections)).toHaveBeenCalledWith({
      remoteStore: session.storage.remoteStore
    })
    expect(vi.mocked(loadUserKeyEpochPin)).toHaveBeenCalledWith(
      expect.objectContaining({ accountDid: POINTER.did })
    )
  })

  it("publishes a passkey's high-entropy key verbatim", async () => {
    await rotateOffUnlockCredential({
      session: sessionWith(),
      method: PASSKEY_METHOD,
      verb: 'removing a passkey'
    })
    expect(vi.mocked(retireUnlockCredential)).toHaveBeenCalledWith(
      expect.objectContaining({
        unlockKeys: {
          keyAgreement: {
            publicKeyMultibase: PASSKEY_METHOD.keyAgreementKeyMultibase
          },
          updateKeyMultibase: PASSKEY_METHOD.updateKeyMultibase
        }
      })
    )
  })

  it('pins the fresh epoch and persists the rotated key together', async () => {
    const session = sessionWith()
    const outcome = await rotateOffUnlockCredential({
      session,
      method: PASSPHRASE_METHOD,
      verb: 'changing the passphrase'
    })

    expect(outcome).toEqual({
      rotated: true,
      collections: {
        outcomes: { 'private-credentials': 'rotated' },
        failed: []
      },
      userKey: FRESH_USER_KEY
    })
    expect(vi.mocked(savePinFromDescriptor)).toHaveBeenCalledWith(
      expect.objectContaining({
        accountDid: POINTER.did,
        epochId: FRESH_USER_KEY.id,
        descriptor: ROSTER_DESCRIPTOR
      })
    )
    expect(session.profile.persistClientKeys).toHaveBeenCalledWith({
      userKey: FRESH_USER_KEY
    })
    expect(state.calls).toEqual([
      'loadUserKeyEpochPin',
      'invalidateVerifiedLog',
      'retireUnlockCredential',
      'savePinFromDescriptor',
      'persistClientKeys',
      'invalidateVerifiedLog'
    ])
  })

  it('reports an already-retired credential as unrotated', async () => {
    vi.mocked(retireUnlockCredential).mockImplementation(
      ceremonyDriving({ rotated: false })
    )
    const session = sessionWith()
    const outcome = await rotateOffUnlockCredential({
      session,
      method: PASSPHRASE_METHOD,
      verb: 'changing the passphrase'
    })
    expect(outcome?.rotated).toBe(false)
    expect(session.profile.persistClientKeys).not.toHaveBeenCalled()
  })

  it('propagates a failed ceremony, memo dropped either way', async () => {
    vi.mocked(retireUnlockCredential).mockImplementation(async () => {
      state.calls.push('retireUnlockCredential')
      throw new Error('log conflict')
    })
    await expect(
      rotateOffUnlockCredential({
        session: sessionWith(),
        method: PASSPHRASE_METHOD,
        verb: 'changing the passphrase'
      })
    ).rejects.toThrow('log conflict')
    expect(vi.mocked(invalidateVerifiedLog)).toHaveBeenCalledTimes(2)
  })
})
