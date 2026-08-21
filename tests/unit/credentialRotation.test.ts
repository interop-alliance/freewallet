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
  calls: [] as string[],
  // The annex strike-or-swap stage's seams: what the strike reports, and
  // whether either half throws.
  struck: true,
  strikeError: null as Error | null,
  swapError: null as Error | null
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

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  clientAnnexLogStore: vi.fn(() => ({ isClientAnnexLogStore: true })),
  retireClientAnnexRung: vi.fn(async () => {
    state.calls.push('retireClientAnnexRung')
    if (state.strikeError) {
      throw state.strikeError
    }
    return { struck: state.struck }
  }),
  swapClientAnnexGeneration: vi.fn(async () => {
    state.calls.push('swapClientAnnexGeneration')
    if (state.swapError) {
      throw state.swapError
    }
    return { did: 'did:webvh:fresh-generation' }
  })
}))

vi.mock('@interop/was-client', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client')>()),
  WasClient: class {
    isWasClient = true
  }
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
import {
  clientAnnexLogPinId,
  clientAnnexLogStore,
  keyAgreementCommitment,
  retireClientAnnexRung,
  swapClientAnnexGeneration
} from '@interop/wallet-core/webvh'
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
 * @param [options.document] {object}   the post-edit account document handed
 *   to the annex strike-or-swap stage; when given, that stage is driven
 *   the way the real ceremony's stage 1b drives it
 * @returns {Function}
 */
function ceremonyDriving({
  rotated = true,
  document
}: { rotated?: boolean; document?: object } = {}) {
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
    const clientAnnex = document
      ? await options.retireClientAnnexPosture?.({ document } as never)
      : undefined
    return {
      rotated,
      collections: {
        outcomes: { 'private-credentials': 'rotated' },
        failed: []
      },
      document: document ?? { id: POINTER.did },
      userKey,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      ...(clientAnnex ? { clientAnnex } : {})
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
    ladderSeed: Uint8Array | undefined
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
      ...('ladderSeed' in overrides
        ? { ladderSeed: overrides.ladderSeed }
        : {}),
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
  state.struck = true
  state.strikeError = null
  state.swapError = null
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

  it('leaves the annex stage out of the outcome when it reports nothing', async () => {
    const outcome = await rotateOffUnlockCredential({
      session: sessionWith(),
      method: PASSPHRASE_METHOD,
      verb: 'changing the passphrase'
    })
    expect(outcome).not.toHaveProperty('clientAnnex')
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

describe('the annex strike-or-swap stage', () => {
  const RETIRED_SEED = new Uint8Array(32).fill(3)
  const SURVIVING_SEED = new Uint8Array(32).fill(4)
  const CLIENT_ANNEX_SPACE_ID = 'clientAnnex-space-1'
  const GENERATION_ID = 'gen-Ux3v0kQf9aPmB2hZ'
  const CLIENT_ANNEX_DID =
    'did:webvh:QmClientAnnexScid:was.example.test:space:' +
    `${CLIENT_ANNEX_SPACE_ID}:${GENERATION_ID}`

  /**
   * The post-edit account document the ceremony's stage 1b hands over: with a
   * `#DelegatedClients` service entry, or without one.
   *
   * @param [options] {object}
   * @param [options.pointed] {boolean}   carry the annex pointer
   * @returns {object}
   */
  function accountDocument({ pointed = true } = {}): object {
    return {
      id: POINTER.did,
      ...(pointed
        ? {
            service: [
              {
                id: `${POINTER.did}#delegated-clients`,
                type: 'https://w3id.org/byoe#DelegatedClients',
                serviceEndpoint: CLIENT_ANNEX_DID
              }
            ]
          }
        : {})
    }
  }

  /**
   * Runs the retirement with the annex stage driven, over a session and a
   * method carrying the given ladder seeds.
   *
   * @param [options] {object}
   * @param [options.retiredLadderSeed] {Uint8Array}
   * @param [options.survivingLadderSeed] {Uint8Array}
   * @param [options.sessionLadderSeed] {Uint8Array}
   * @param [options.pointed] {boolean}
   * @returns {Promise<object | null>}
   */
  async function retire({
    retiredLadderSeed,
    survivingLadderSeed,
    sessionLadderSeed,
    pointed = true
  }: {
    retiredLadderSeed?: Uint8Array
    survivingLadderSeed?: Uint8Array
    sessionLadderSeed?: Uint8Array
    pointed?: boolean
  } = {}) {
    vi.mocked(retireUnlockCredential).mockImplementation(
      ceremonyDriving({ document: accountDocument({ pointed }) })
    )
    return await rotateOffUnlockCredential({
      session: sessionWith({ ladderSeed: sessionLadderSeed }),
      method: {
        ...PASSPHRASE_METHOD,
        ...(retiredLadderSeed ? { ladderSeed: retiredLadderSeed } : {})
      },
      ...(survivingLadderSeed ? { survivingLadderSeed } : {}),
      verb: 'changing the passphrase'
    })
  }

  it('strikes the retired rung with a surviving credential as the signer', async () => {
    const outcome = await retire({
      retiredLadderSeed: RETIRED_SEED,
      survivingLadderSeed: SURVIVING_SEED
    })

    expect(outcome?.clientAnnex).toEqual({ action: 'struck' })
    expect(vi.mocked(retireClientAnnexRung)).toHaveBeenCalledWith(
      expect.objectContaining({
        store: { isClientAnnexLogStore: true },
        retiredLadderSeed: RETIRED_SEED,
        actingLadderSeed: SURVIVING_SEED,
        generationId: GENERATION_ID,
        expectedDid: CLIENT_ANNEX_DID,
        logId: clientAnnexLogPinId({
          spaceId: CLIENT_ANNEX_SPACE_ID,
          generationId: GENERATION_ID
        })
      })
    )
    expect(vi.mocked(clientAnnexLogStore)).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: CLIENT_ANNEX_SPACE_ID,
        generationId: GENERATION_ID
      })
    )
    expect(vi.mocked(swapClientAnnexGeneration)).not.toHaveBeenCalled()
  })

  it('reports a generation the retired credential never wrote as clean', async () => {
    state.struck = false
    const outcome = await retire({
      retiredLadderSeed: RETIRED_SEED,
      survivingLadderSeed: SURVIVING_SEED
    })
    expect(outcome?.clientAnnex).toEqual({ action: 'clean' })
  })

  it('falls through to a generation swap when no rung can sign the strike', async () => {
    const uncommitted = new Error('rung 0 is not committed')
    uncommitted.name = 'ClientAnnexRungUncommittedError'
    state.strikeError = uncommitted

    const outcome = await retire({
      retiredLadderSeed: RETIRED_SEED,
      survivingLadderSeed: SURVIVING_SEED
    })

    expect(outcome?.clientAnnex).toEqual({ action: 'swapped' })
    expect(state.calls).toContain('retireClientAnnexRung')
    expect(vi.mocked(swapClientAnnexGeneration)).toHaveBeenCalledWith(
      expect.objectContaining({
        accountSpaceId: POINTER.spaceId,
        wasServerUrl: POINTER.host,
        ladderSeed: SURVIVING_SEED,
        idStore: { isWebvhIdStore: true }
      })
    )
  })

  it("prefers the surviving seed but takes the session's when there is none", async () => {
    await retire({
      retiredLadderSeed: RETIRED_SEED,
      sessionLadderSeed: SURVIVING_SEED
    })
    expect(vi.mocked(retireClientAnnexRung)).toHaveBeenCalledWith(
      expect.objectContaining({ actingLadderSeed: SURVIVING_SEED })
    )
  })

  it('skips with no-pointer when the document names no annex', async () => {
    const outcome = await retire({
      retiredLadderSeed: RETIRED_SEED,
      survivingLadderSeed: SURVIVING_SEED,
      pointed: false
    })
    expect(outcome?.clientAnnex).toEqual({
      action: 'skipped',
      reason: 'no-pointer'
    })
    expect(vi.mocked(retireClientAnnexRung)).not.toHaveBeenCalled()
    expect(vi.mocked(swapClientAnnexGeneration)).not.toHaveBeenCalled()
  })

  it('skips with no-ladder-seed when no seed survives the retirement', async () => {
    const outcome = await retire({ retiredLadderSeed: RETIRED_SEED })
    expect(outcome?.clientAnnex).toEqual({
      action: 'skipped',
      reason: 'no-ladder-seed'
    })

    // The retired credential's own seed is not a survivor, even when the
    // session and the caller both still carry it.
    const sameBytes = await retire({
      retiredLadderSeed: RETIRED_SEED,
      survivingLadderSeed: new Uint8Array(32).fill(3),
      sessionLadderSeed: new Uint8Array(32).fill(3)
    })
    expect(sameBytes?.clientAnnex).toEqual({
      action: 'skipped',
      reason: 'no-ladder-seed'
    })
    expect(vi.mocked(retireClientAnnexRung)).not.toHaveBeenCalled()
    expect(vi.mocked(swapClientAnnexGeneration)).not.toHaveBeenCalled()
  })

  it('swaps outright when the retired credential has no seed in hand', async () => {
    const outcome = await retire({ survivingLadderSeed: SURVIVING_SEED })
    expect(vi.mocked(retireClientAnnexRung)).not.toHaveBeenCalled()
    expect(outcome?.clientAnnex).toEqual({ action: 'swapped' })
  })

  it('reports a hard failure as skipped, the rotation still done', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    state.strikeError = new Error('annex log unreachable')

    const outcome = await retire({
      retiredLadderSeed: RETIRED_SEED,
      survivingLadderSeed: SURVIVING_SEED
    })

    // Best-effort by the ceremony's contract: the roster rotation -- the
    // retirement's essential remedy -- still ran.
    expect(outcome?.rotated).toBe(true)
    expect(outcome?.clientAnnex).toEqual({
      action: 'skipped',
      reason: 'failed'
    })
    expect(vi.mocked(swapClientAnnexGeneration)).not.toHaveBeenCalled()
    warn.mockRestore()
  })

  it('reports a failed swap as skipped too', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    state.swapError = new Error('log conflict')
    const outcome = await retire({ survivingLadderSeed: SURVIVING_SEED })
    expect(outcome?.clientAnnex).toEqual({
      action: 'skipped',
      reason: 'failed'
    })
    expect(outcome?.rotated).toBe(true)
    warn.mockRestore()
  })
})
