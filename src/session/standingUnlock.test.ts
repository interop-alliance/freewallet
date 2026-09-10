// @vitest-environment node
/**
 * The standing self-enrollment's persist-before-publish ordering
 * (`selfEnrollStandingClient`): the pending-shape record is written inside
 * the required `onCommitted` seam and the enrolled shape on the return, and
 * a rejecting persist stays fatal (an unpersisted key set past the add entry
 * is the phantom-client window the ordering closes).
 *
 * Beside it, the enrolled branch of `establishStandingUnlock`: the record is
 * written before the document entry (the seed's one durable home, so a torn
 * run can read it back), and a run given no seed reuses the one a prior run
 * sealed into this account's record before minting a fresh one.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { KeyringFetchResult } from '@/session/keyring'
import type { AccountCeremonyContext } from '@/session/accountCeremonyContext'
import type { Session } from '@/types/auth'

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  WAS_SERVER_URL: 'https://was.example'
}))

vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => {
  const actual = await importOriginal<object>()
  return {
    ...actual,
    selfEnrollClientCore: vi.fn(),
    ladderVmZcapClient: vi.fn()
  }
})
const { selfEnrollClientCore, ladderRung } =
  await import('@interop/wallet-core/clientAnnex')

vi.mock('@interop/wallet-core/unlock', async importOriginal => ({
  ...(await importOriginal<object>()),
  publishUnlockKey: vi.fn()
}))
const { publishUnlockKey } = await import('@interop/wallet-core/unlock')

vi.mock('@interop/wallet-core/recovery', async importOriginal => ({
  ...(await importOriginal<object>()),
  delegateLogWrite: vi.fn(),
  delegationProofKeyId: vi.fn()
}))
const { delegateLogWrite, delegationProofKeyId } =
  await import('@interop/wallet-core/recovery')

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<object>()),
  addUserKeyRosterRecipient: vi.fn()
}))
const { addUserKeyRosterRecipient } = await import('@interop/wallet-core/keys')

vi.mock('@/session/verifiedLog', () => ({
  verifiedAccountLog: vi.fn(),
  invalidateVerifiedLog: vi.fn()
}))
const { verifiedAccountLog } = await import('@/session/verifiedLog')

vi.mock('@/session/keyring', async importOriginal => ({
  ...(await importOriginal<object>()),
  bindUnlockSecret: vi.fn(),
  fetchTransientKeyring: vi.fn()
}))
const { bindUnlockSecret, fetchTransientKeyring } =
  await import('@/session/keyring')

const { establishStandingUnlock, selfEnrollStandingClient } =
  await import('@/session/standingUnlock')

/**
 * The key set wallet-core's continuation hands back, threaded through the
 * persist call and the returned `clientKeys` alike.
 */
const CORE_RESULT = {
  clientSeed: new Uint8Array(32).fill(9),
  webvhUpdateKeys: { updateSeed: new Uint8Array(32).fill(4) },
  clientDid: 'did:key:zFreshClient',
  did: 'did:webvh:scid-a:example.com:space-1',
  userKey: { id: 'did:key:zUserKey' }
}

/**
 * The call order the persist mocks push into, so the write ordering is
 * asserted on rather than inferred.
 */
let order: string[] = []

/**
 * The persist closure `enrollClientKeys` hands back, returned verbatim as
 * the call's `persistClientKeys`.
 */
const persistClosure = vi.fn(async () => {
  order.push('persist')
})

/**
 * A minimal keyring hit carrying exactly what the self-enrollment reads:
 * the standing members, the credential's client identity, the pointer, the
 * controller, and the enrollment persist closure.
 *
 * @returns {KeyringFetchResult}
 */
function hit(): KeyringFetchResult {
  return {
    controller: 'did:key:zController',
    unlockSpaceId: 'unlock-1',
    pointer: {
      did: 'did:webvh:scid-a:example.com:space-1',
      spaceId: 'space-1',
      host: 'https://storage.example'
    },
    standing: {
      delegation: {},
      ladderSeed: new Uint8Array(32).fill(2)
    },
    standingClient: {
      clientDid: 'did:key:zClient',
      agents: { keyAgreementKey: {}, zcapClient: {} }
    },
    enrollClientKeys: vi.fn(async () => {
      order.push('persist')
      return persistClosure
    })
  } as unknown as KeyringFetchResult
}

beforeEach(() => {
  vi.clearAllMocks()
  order = []
  // The core fires the required persist hook once (the pending write) and
  // returns with `committed` stated, as the real ceremony does.
  vi.mocked(selfEnrollClientCore).mockImplementation(
    async (options: unknown) => {
      const { onCommitted } = options as {
        onCommitted: (committed: {
          builtOnHead: { scid: string; versionId: string }
          clientSeed: Uint8Array
          webvhUpdateKeys: unknown
        }) => Promise<void>
      }
      await onCommitted({
        builtOnHead: { scid: 'scid-a', versionId: '2-head' },
        clientSeed: CORE_RESULT.clientSeed,
        webvhUpdateKeys: CORE_RESULT.webvhUpdateKeys
      })
      return { ...CORE_RESULT, committed: true } as never
    }
  )
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('selfEnrollStandingClient', () => {
  it('persists the pending shape in the hook and the enrolled shape on the return', async () => {
    const found = hit()
    const outcome = await selfEnrollStandingClient({
      pinStore: memoryResourceLogPinStore(),
      found
    })
    // Two persists: the hook's pending write (pre-pivot), then the
    // completion's enrolled shape.
    expect(order).toEqual(['persist', 'persist'])
    expect(found.enrollClientKeys).toHaveBeenNthCalledWith(1, {
      clientSeed: CORE_RESULT.clientSeed,
      webvhUpdateKeys: CORE_RESULT.webvhUpdateKeys,
      controller: found.controller,
      pointerDid: found.pointer!.did,
      pending: {
        ceremony: 'self-enrollment',
        builtOnHead: { scid: 'scid-a', versionId: '2-head' }
      }
    })
    // The completion clears the pending group through the persist closure.
    expect(persistClosure).toHaveBeenCalledWith({
      userKey: CORE_RESULT.userKey,
      webvhUpdateKeys: CORE_RESULT.webvhUpdateKeys,
      pointerDid: CORE_RESULT.did,
      pending: null
    })
    expect(outcome.clientKeys).toEqual({
      clientSeed: CORE_RESULT.clientSeed,
      userKey: CORE_RESULT.userKey,
      webvhUpdateKeys: CORE_RESULT.webvhUpdateKeys,
      controller: found.controller,
      pointerDid: CORE_RESULT.did
    })
    expect(outcome.persistClientKeys).toBe(persistClosure)
  })

  it('stays fatal when the key-set persist itself rejects', async () => {
    const found = hit()
    vi.mocked(found.enrollClientKeys!).mockRejectedValue(
      new Error('client-key record write failed')
    )
    await expect(
      selfEnrollStandingClient({ pinStore: memoryResourceLogPinStore(), found })
    ).rejects.toThrow(/client-key record write failed/)
  })
})

/**
 * The account the enrolled branch binds against, and a seed a prior run
 * sealed into that account's record (distinct from a fresh mint).
 */
const ACCOUNT_DID = 'did:webvh:scid-a:example.com:space-1'
const SEALED_SEED = new Uint8Array(32).fill(7)

/**
 * A minimal live session shaped as the enrolled branch reads it: the user
 * key and this client's seed for the record write, the pin store the sealed
 * seed read rides, and no acting ladder seed (the annex commit never runs
 * here, the account document carrying no generation pointer).
 *
 * @returns {Session}
 */
function fakeSession(): Session {
  return {
    user: { id: 'did:key:zClientA' },
    isGuest: false,
    profile: {
      userKey: { id: 'did:key:zUserKey' },
      clientSeed: new Uint8Array(32).fill(1),
      accountController: ACCOUNT_DID
    },
    persistence: { logPins: memoryResourceLogPinStore() }
  } as unknown as Session
}

/**
 * The enrolled ceremony context, passed explicitly so the ceremony resolves
 * neither the session's context nor the KDF.
 *
 * @returns {AccountCeremonyContext}
 */
function enrolledContext(): AccountCeremonyContext {
  return {
    kind: 'enrolled',
    pointer: {
      did: ACCOUNT_DID,
      spaceId: 'space-1',
      host: 'https://storage.example'
    },
    controller: ACCOUNT_DID,
    signer: { kind: 'client', updateKeys: {} },
    clientWebvhKeys: { updateSeed: new Uint8Array(32).fill(3) },
    clientKeyAgreementKey: { id: 'did:key:zClientKak' },
    idStore: {},
    rosterStore: {}
  } as unknown as AccountCeremonyContext
}

/**
 * The already-derived credential the ceremony is handed, so no KDF runs.
 *
 * @returns {never}
 */
function fakeCredential(): never {
  return {
    unlock: { did: 'did:key:zUnlock' },
    standing: {
      clientDid: 'did:key:zStandingClient',
      recipientKid: 'did:key:zStandingClient#zKak',
      keyAgreementKeyMultibase: 'zStandingKak'
    }
  } as never
}

/**
 * Runs the enrolled branch with the shared fakes.
 *
 * @param [options] {object}
 * @param [options.ladderSeed] {Uint8Array}
 * @returns {Promise<{ ladderSeed: Uint8Array }>}
 */
async function runEstablish({
  ladderSeed
}: { ladderSeed?: Uint8Array } = {}): Promise<{ ladderSeed: Uint8Array }> {
  return await establishStandingUnlock({
    session: fakeSession(),
    context: enrolledContext(),
    secret: 'correct horse battery staple',
    kdf: { salt: 'zSalt' } as never,
    lowEntropy: false,
    credential: fakeCredential(),
    ...(ladderSeed ? { ladderSeed } : {})
  })
}

/**
 * The `ladderSeed` one mocked collaborator was called with.
 *
 * @param mock {{ mock: { calls: unknown[][] } }}
 * @returns {Uint8Array}
 */
function seedOf(mock: { mock: { calls: unknown[][] } }): Uint8Array {
  return (mock.mock.calls[0][0] as { ladderSeed: Uint8Array }).ladderSeed
}

describe('establishStandingUnlock (the enrolled branch)', () => {
  beforeEach(() => {
    vi.mocked(verifiedAccountLog).mockResolvedValue({ doc: {} } as never)
    vi.mocked(delegateLogWrite).mockResolvedValue({
      id: 'urn:zcap:bridge',
      expires: '2030-01-01T00:00:00Z'
    } as never)
    vi.mocked(delegationProofKeyId).mockReturnValue(
      `${ACCOUNT_DID}#zLadderVm` as never
    )
    vi.mocked(addUserKeyRosterRecipient).mockResolvedValue(undefined as never)
    vi.mocked(bindUnlockSecret).mockResolvedValue({
      unlockSpaceId: 'unlock-1',
      manageCapability: { id: 'urn:zcap:manage' }
    } as never)
    vi.mocked(publishUnlockKey).mockResolvedValue(undefined as never)
    vi.mocked(fetchTransientKeyring).mockResolvedValue(null as never)
  })

  it('writes the unlock record before the document entry, on the same seed', async () => {
    const outcome = await runEstablish()

    // Persist-before-publish: the record (the seed's one durable home) is
    // written before the entry that commits its rung-0 hash, and after the
    // roster escrow the branch opens with.
    const [rosterCall] = vi.mocked(addUserKeyRosterRecipient).mock
      .invocationCallOrder
    const [bindCall] = vi.mocked(bindUnlockSecret).mock.invocationCallOrder
    const [publishCall] = vi.mocked(publishUnlockKey).mock.invocationCallOrder
    expect(rosterCall).toBeLessThan(bindCall)
    expect(bindCall).toBeLessThan(publishCall)

    // One seed reaches both writes, and it is the one handed back.
    const boundSeed = seedOf(vi.mocked(bindUnlockSecret))
    expect(seedOf(vi.mocked(publishUnlockKey))).toBe(boundSeed)
    expect(outcome.ladderSeed).toBe(boundSeed)
  })

  it("reuses the seed a prior run sealed into this account's record", async () => {
    vi.mocked(fetchTransientKeyring).mockResolvedValue({
      pointer: { did: ACCOUNT_DID },
      standing: { ladderSeed: SEALED_SEED }
    } as never)

    const outcome = await runEstablish()

    expect(vi.mocked(fetchTransientKeyring)).toHaveBeenCalledOnce()
    expect(vi.mocked(fetchTransientKeyring).mock.calls[0][0]).toMatchObject({
      credential: expect.objectContaining({ standing: expect.anything() })
    })
    expect(outcome.ladderSeed).toBe(SEALED_SEED)
    expect(seedOf(vi.mocked(bindUnlockSecret))).toBe(SEALED_SEED)
    expect(seedOf(vi.mocked(publishUnlockKey))).toBe(SEALED_SEED)
    // The entry restates the sealed seed's rung 0, which is what makes the
    // re-run's commitment match the standing member's.
    const rung0 = await ladderRung({ ladderSeed: SEALED_SEED, index: 0 })
    expect(
      vi.mocked(publishUnlockKey).mock.calls[0][0].unlockKeys.updateKeyMultibase
    ).toBe(rung0.keyMultibase)
  })

  it('mints a fresh seed when no standing record stands', async () => {
    const outcome = await runEstablish()

    expect(vi.mocked(fetchTransientKeyring)).toHaveBeenCalledOnce()
    expect(outcome.ladderSeed).toBeInstanceOf(Uint8Array)
    expect(outcome.ladderSeed).toHaveLength(32)
    expect(outcome.ladderSeed).not.toEqual(SEALED_SEED)
  })

  it('refuses a caller-minted seed that differs from the sealed one', async () => {
    vi.mocked(fetchTransientKeyring).mockResolvedValue({
      pointer: { did: ACCOUNT_DID },
      standing: { ladderSeed: SEALED_SEED }
    } as never)
    await expect(
      runEstablish({ ladderSeed: new Uint8Array(32).fill(9) })
    ).rejects.toThrow(/different ladder seed/)
    expect(vi.mocked(bindUnlockSecret)).not.toHaveBeenCalled()
    expect(vi.mocked(publishUnlockKey)).not.toHaveBeenCalled()
  })

  it('ignores a standing record that names a different account', async () => {
    vi.mocked(fetchTransientKeyring).mockResolvedValue({
      pointer: { did: 'did:webvh:scid-b:example.com:space-2' },
      standing: { ladderSeed: SEALED_SEED }
    } as never)

    const outcome = await runEstablish()

    expect(outcome.ladderSeed).not.toEqual(SEALED_SEED)
    expect(seedOf(vi.mocked(bindUnlockSecret))).toBe(outcome.ladderSeed)
    expect(seedOf(vi.mocked(publishUnlockKey))).toBe(outcome.ladderSeed)
  })
})
