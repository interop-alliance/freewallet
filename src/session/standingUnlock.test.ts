// @vitest-environment node
/**
 * The standing self-enrollment's persist-before-publish ordering
 * (`selfEnrollStandingClient`): the pending-shape record is written inside
 * the required `onCommitted` seam and the enrolled shape on the return, and
 * a rejecting persist stays fatal (an unpersisted key set past the add entry
 * is the phantom-client window the ordering closes).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { KeyringFetchResult } from '@/session/keyring'

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  WAS_SERVER_URL: 'https://was.example'
}))

vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => {
  const actual = await importOriginal<object>()
  return {
    ...actual,
    selfEnrollClientCore: vi.fn()
  }
})
const { selfEnrollClientCore } =
  await import('@interop/wallet-core/clientAnnex')

const { selfEnrollStandingClient } = await import('@/session/standingUnlock')

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
    const outcome = await selfEnrollStandingClient({ found })
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
    await expect(selfEnrollStandingClient({ found })).rejects.toThrow(
      /client-key record write failed/
    )
  })
})
