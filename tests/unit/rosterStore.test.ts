// @vitest-environment node
/**
 * Unit tests for the bare-parts user key roster store builder
 * (`accountRosterStore` in `src/session/rosterStore.ts`): how it resolves the
 * controller view -- from a fresh `verifyAccountLog` of the pointer, or from
 * a head the caller's own ceremony already stands on.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  userKeyRosterDescriptorStore: vi.fn(options => ({ options })),
  userKeyRosterLogSigner: vi.fn(() => ({ isRosterSigner: true }))
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  verifyAccountLog: vi.fn()
}))

vi.mock('@interop/wallet-core/resourceLog', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/resourceLog')
  >()),
  webvhResourceLogController: vi.fn(options => ({ controllerFor: options }))
}))

import { userKeyRosterDescriptorStore } from '@interop/wallet-core/keys'
import { verifyAccountLog } from '@interop/wallet-core/webvh'
import { webvhResourceLogController } from '@interop/wallet-core/resourceLog'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import { accountRosterStore } from '@/session/rosterStore'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const PARTS = {
  zcapClient: { isZcapClient: true },
  keyAgent: { id: 'did:key:zAgent' }
} as never as {
  zcapClient: Parameters<typeof accountRosterStore>[0]['zcapClient']
  keyAgent: Parameters<typeof accountRosterStore>[0]['keyAgent']
}

/**
 * The `resolveController` closure the builder handed wallet-core's store.
 *
 * @param options {object}
 * @param [options.log] {unknown}   the seeded head, when the caller has one
 * @param options.pinStore {unknown}
 * @returns {Function}
 */
function resolveControllerOf({
  log,
  pinStore
}: {
  log?: unknown
  pinStore: unknown
}): () => Promise<unknown> {
  accountRosterStore({
    ...PARTS,
    pointer: POINTER,
    pinStore: pinStore as never,
    ...(log !== undefined ? { log: log as never } : {})
  })
  const options = vi.mocked(userKeyRosterDescriptorStore).mock.calls[0]![0]
  return options.resolveController as () => Promise<unknown>
}

afterEach(() => {
  vi.clearAllMocks()
})

describe('accountRosterStore -- the controller view', () => {
  it('verifies the account log under the supplied pin store', async () => {
    const pinStore = memoryResourceLogPinStore()
    vi.mocked(verifyAccountLog).mockResolvedValue({
      doc: { id: POINTER.did },
      log: [{ entry: 'served' }],
      updateKeys: [],
      nextKeyHashes: []
    } as never)
    const resolveController = resolveControllerOf({ pinStore })

    await resolveController()
    await resolveController()

    // One verification for the store's whole life: the in-flight promise is
    // the memo.
    expect(vi.mocked(verifyAccountLog).mock.calls).toHaveLength(1)
    expect(vi.mocked(verifyAccountLog).mock.calls[0]![0]).toEqual({
      did: POINTER.did,
      spaceId: POINTER.spaceId,
      host: POINTER.host,
      pinStore
    })
    expect(webvhResourceLogController).toHaveBeenCalledWith({
      did: POINTER.did,
      log: [{ entry: 'served' }]
    })
  })

  it('resolves a seeded head without reading did.jsonl at all', async () => {
    const pinStore = memoryResourceLogPinStore()
    const seeded = [{ entry: 'this run' }]
    const resolveController = resolveControllerOf({ log: seeded, pinStore })

    const controller = await resolveController()

    expect(verifyAccountLog).not.toHaveBeenCalled()
    expect(webvhResourceLogController).toHaveBeenCalledWith({
      did: POINTER.did,
      log: seeded
    })
    expect(controller).toEqual({
      controllerFor: { did: POINTER.did, log: seeded }
    })
  })

  it('re-reads after a failed verification rather than caching it', async () => {
    const pinStore = memoryResourceLogPinStore()
    vi.mocked(verifyAccountLog)
      .mockRejectedValueOnce(new Error('the host flapped'))
      .mockResolvedValueOnce({
        doc: { id: POINTER.did },
        log: [{ entry: 'served' }],
        updateKeys: [],
        nextKeyHashes: []
      } as never)
    const resolveController = resolveControllerOf({ pinStore })

    await expect(resolveController()).rejects.toThrow('the host flapped')
    await resolveController()

    expect(vi.mocked(verifyAccountLog).mock.calls).toHaveLength(2)
  })
})
