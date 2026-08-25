// @vitest-environment node
/**
 * Unit tests for the self-enrollment wrapper (`selfEnrollStandingClient` in
 * `src/session/standingUnlock.ts`) under the persist-before-publish seam
 * (FW-280): the required `onCommitted` hook writes the PENDING-shape
 * client-key record before the ceremony's pivot entry, the completion
 * overwrites it with the enrolled shape after the core returns, the epoch
 * pin stays after the completion (the FW-254 order), a hook-less core return
 * is refused as build skew (after persisting the key set the stale core
 * already published), and the resume mode replays the recorded key set
 * through the record's own persist closure. Wallet-core's
 * `selfEnrollClientCore` is mocked (its own ordering is covered in
 * wallet-core's suites); everything else runs real.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'

vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/clientAnnex')
  >()),
  selfEnrollClientCore: vi.fn()
}))

vi.mock('@/lib/sessionKey', async importOriginal => ({
  ...(await importOriginal<typeof import('@/lib/sessionKey')>()),
  saveUserKeyEpochPin: vi.fn(async () => {}),
  sessionLogPinStore: vi.fn(() => ({
    read: async () => null,
    write: async () => undefined
  }))
}))

import { selfEnrollClientCore } from '@interop/wallet-core/clientAnnex'
import { saveUserKeyEpochPin } from '@/lib/sessionKey'
import {
  selfEnrollStandingClient,
  SelfEnrollmentSkewError
} from '@/session/standingUnlock'
import type { KeyringFetchResult } from '@/session/keyring'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const BUILT_ON_HEAD = { scid: 'QmScidForTests', versionId: '2-head' }

function randomSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

const USER_KEY = { id: 'did:key:zUserKey', secret: new Uint8Array(32) }

function makeFound(overrides: Partial<KeyringFetchResult> = {}) {
  const enrolledPersister = vi.fn(async () => {})
  const enrollClientKeys = vi.fn(async (_changes: unknown) => enrolledPersister)
  const persistClientKeys = vi.fn(async () => {})
  const found = {
    controller: 'did:key:zAccount',
    pointer: POINTER,
    unlockSpaceId: 'unlock-space-test',
    createdAt: new Date().toISOString(),
    standing: {
      delegation: { id: 'urn:zcap:bridge' },
      ladderSeed: randomSeed()
    },
    standingClient: {
      clientDid: 'did:key:zCredential',
      recipientKid: 'did:key:zCredential#zKak',
      keyAgreementKeyMultibase: 'z6LSkak',
      agents: {
        keyAgreementKey: { id: 'did:key:zCredential#zKak' },
        zcapClient: { isZcapClient: true }
      }
    },
    enrollClientKeys,
    persistClientKeys,
    ...overrides
  } as unknown as KeyringFetchResult
  return { found, enrolledPersister, enrollClientKeys, persistClientKeys }
}

/**
 * A core mock that fires the hook once with the given key set (minting its
 * own when the call is not a resume) and returns the enrolled result.
 */
function coreFiringHook({
  userKey = USER_KEY,
  committed = true as boolean | 'omitted',
  hookFires = 1
} = {}) {
  return vi
    .mocked(selfEnrollClientCore)
    .mockImplementation(async (options: unknown) => {
      const { onCommitted, resume } = options as {
        onCommitted: (committed: {
          builtOnHead: { scid: string; versionId: string }
          clientSeed: Uint8Array
          webvhUpdateKeys: { updateSeed: Uint8Array; stagedSeed: Uint8Array }
        }) => Promise<void>
        resume?: {
          clientSeed: Uint8Array
          webvhUpdateKeys: { updateSeed: Uint8Array; stagedSeed: Uint8Array }
          builtOnHead: { scid: string; versionId: string }
        }
      }
      const clientSeed = resume?.clientSeed ?? randomSeed()
      const webvhUpdateKeys = resume?.webvhUpdateKeys ?? {
        updateSeed: randomSeed(),
        stagedSeed: randomSeed()
      }
      for (let fire = 0; fire < hookFires; fire++) {
        await onCommitted({
          builtOnHead: resume?.builtOnHead ?? BUILT_ON_HEAD,
          clientSeed,
          webvhUpdateKeys
        })
      }
      return {
        clientSeed,
        webvhUpdateKeys,
        clientDid: 'did:key:zNewClient',
        did: POINTER.did,
        userKey,
        latestEpochId: USER_KEY.id,
        ...(committed !== 'omitted' ? { committed } : {})
      } as never
    })
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('selfEnrollStandingClient -- the persist hook (fresh run)', () => {
  it('writes the pending shape in the hook, then completes to the enrolled shape before the pin', async () => {
    const { found, enrolledPersister, enrollClientKeys } = makeFound()
    coreFiringHook()
    const order: string[] = []
    enrollClientKeys.mockImplementation(async () => {
      order.push('enroll')
      return enrolledPersister
    })
    enrolledPersister.mockImplementation(async () => {
      order.push('complete')
    })
    vi.mocked(saveUserKeyEpochPin).mockImplementation(async () => {
      order.push('pin')
    })

    const { clientKeys } = await selfEnrollStandingClient({ found })

    // The hook's pending write: seeds + controller + pointerDid + pending,
    // and NO userKey -- the pending discriminator.
    expect(enrollClientKeys).toHaveBeenCalledTimes(1)
    const pendingWrite = enrollClientKeys.mock.calls[0]![0] as Record<
      string,
      unknown
    >
    expect(pendingWrite.userKey).toBeUndefined()
    expect(pendingWrite.pointerDid).toBe(POINTER.did)
    expect(pendingWrite.pending).toEqual({
      ceremony: 'self-enrollment',
      builtOnHead: BUILT_ON_HEAD
    })
    // The completion: user key in, pending cleared, persisted BEFORE the pin.
    expect(enrolledPersister).toHaveBeenCalledWith(
      expect.objectContaining({
        userKey: USER_KEY,
        pointerDid: POINTER.did,
        pending: null
      })
    )
    expect(order).toEqual(['enroll', 'complete', 'pin'])
    expect(clientKeys.userKey).toBe(USER_KEY)
    expect(clientKeys.pointerDid).toBe(POINTER.did)
  })

  it('propagates a hook (pending persist) failure without completing or pinning', async () => {
    const { found, enrolledPersister, enrollClientKeys } = makeFound()
    // The mock core awaits the hook, so a throwing persist aborts the core
    // exactly as the real ceremony withholds the pivot on a hook throw.
    coreFiringHook()
    enrollClientKeys.mockRejectedValue(new Error('quota exceeded'))

    await expect(selfEnrollStandingClient({ found })).rejects.toThrow(
      'quota exceeded'
    )
    expect(enrolledPersister).not.toHaveBeenCalled()
    expect(saveUserKeyEpochPin).not.toHaveBeenCalled()
  })

  it('logs the named event when the hook re-fires on a conflict retry', async () => {
    const capture = captureSink()
    addSink(capture.sink)
    const { found } = makeFound()
    coreFiringHook({ hookFires: 2 })

    await selfEnrollStandingClient({ found })

    expect(
      capture.events.some(
        event =>
          event.msg ===
          'Self-enrollment persist hook re-fired on a conflict retry'
      )
    ).toBe(true)
  })

  it('still succeeds when the pin write rejects (persist-before-pin, FW-254)', async () => {
    const { found } = makeFound()
    coreFiringHook()
    vi.mocked(saveUserKeyEpochPin).mockRejectedValue(new Error('blocked'))

    const { clientKeys } = await selfEnrollStandingClient({ found })
    expect(clientKeys.userKey).toBe(USER_KEY)
  })
})

describe('selfEnrollStandingClient -- the build-skew guard', () => {
  it('persists the returned key set, then refuses a hook-less core (the real skew)', async () => {
    // The skew that can actually occur: a stale wallet-core body ignores
    // `onCommitted` entirely -- both entries and the escrow already landed
    // when the core returns without `committed`. The key set must be
    // persisted (enrolled shape) BEFORE the refusal, or every retry would
    // publish another phantom client no browser can answer for.
    const { found, enrollClientKeys } = makeFound()
    coreFiringHook({ committed: 'omitted', hookFires: 0 })

    await expect(selfEnrollStandingClient({ found })).rejects.toThrow(
      SelfEnrollmentSkewError
    )
    expect(enrollClientKeys).toHaveBeenCalledTimes(1)
    const persisted = enrollClientKeys.mock.calls[0]![0] as Record<
      string,
      unknown
    >
    expect(persisted.userKey).toBe(USER_KEY)
    expect(persisted.pointerDid).toBe(POINTER.did)
    expect(persisted.pending).toBeUndefined()
    // Refused before the pin: nothing pretended the ceremony completed.
    expect(saveUserKeyEpochPin).not.toHaveBeenCalled()
  })

  it('still refuses when even the skew persist fails (the key set could not be saved)', async () => {
    const { found, enrollClientKeys } = makeFound()
    coreFiringHook({ committed: 'omitted', hookFires: 0 })
    enrollClientKeys.mockRejectedValue(new Error('quota exceeded'))

    await expect(selfEnrollStandingClient({ found })).rejects.toThrow(
      SelfEnrollmentSkewError
    )
    expect(saveUserKeyEpochPin).not.toHaveBeenCalled()
  })
})

describe('selfEnrollStandingClient -- the resume mode', () => {
  it('threads the recorded key set into the core and completes through the record persister', async () => {
    const { found, persistClientKeys, enrollClientKeys } = makeFound()
    const resume = {
      clientSeed: randomSeed(),
      webvhUpdateKeys: { updateSeed: randomSeed(), stagedSeed: randomSeed() },
      builtOnHead: BUILT_ON_HEAD
    }
    coreFiringHook()

    const { clientKeys } = await selfEnrollStandingClient({ found, resume })

    // The core was handed the resume verbatim (the mint skip + fork guard).
    const coreOptions = vi.mocked(selfEnrollClientCore).mock
      .calls[0]![0] as Record<string, unknown>
    expect(coreOptions.resume).toBe(resume)
    // The hook re-persisted the pending marker through the record's own
    // closure; the fresh-enroll path was never used.
    expect(enrollClientKeys).not.toHaveBeenCalled()
    expect(persistClientKeys).toHaveBeenCalledWith(
      expect.objectContaining({
        pending: {
          ceremony: 'self-enrollment',
          builtOnHead: BUILT_ON_HEAD
        },
        pointerDid: POINTER.did
      })
    )
    // The completion cleared the pending group on the RETURN, whatever
    // `committed` said.
    expect(persistClientKeys).toHaveBeenCalledWith(
      expect.objectContaining({ userKey: USER_KEY, pending: null })
    )
    // The replayed seeds are the record's own -- no second client minted.
    expect(Array.from(clientKeys.clientSeed)).toEqual(
      Array.from(resume.clientSeed)
    )
  })

  it('completes a resume that met an already-complete continuation (committed: false, no hook)', async () => {
    const { found, persistClientKeys } = makeFound()
    const resume = {
      clientSeed: randomSeed(),
      webvhUpdateKeys: { updateSeed: randomSeed(), stagedSeed: randomSeed() },
      builtOnHead: BUILT_ON_HEAD
    }
    coreFiringHook({ committed: false, hookFires: 0 })

    const { clientKeys } = await selfEnrollStandingClient({ found, resume })

    expect(clientKeys.userKey).toBe(USER_KEY)
    expect(persistClientKeys).toHaveBeenCalledWith(
      expect.objectContaining({ userKey: USER_KEY, pending: null })
    )
  })

  it('refuses a resume on a hit with no record persist closure', async () => {
    const { found } = makeFound({ persistClientKeys: undefined })
    await expect(
      selfEnrollStandingClient({
        found,
        resume: {
          clientSeed: randomSeed(),
          webvhUpdateKeys: {
            updateSeed: randomSeed(),
            stagedSeed: randomSeed()
          },
          builtOnHead: BUILT_ON_HEAD
        }
      })
    ).rejects.toThrow('cannot resume')
    expect(selfEnrollClientCore).not.toHaveBeenCalled()
  })
})
