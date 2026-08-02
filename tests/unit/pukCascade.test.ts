// @vitest-environment node
/**
 * Unit tests for the collection fan-out of the PUK cascade
 * (`src/session/pukCascade.ts`): the enumeration (encrypted standard
 * collections plus every remotely listed encrypted collection, deduplicated,
 * degrading to the standard set when the remote listing fails), the
 * skip-undeclared branch (a collection the server does not declare encrypted
 * takes no work), and the best-effort driving (a failing collection is
 * collected in `failed`, never aborting the rest). The per-collection
 * staleness/rotation logic itself lives in `@interop/wallet-core/keys` and
 * is mocked here.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  unwrapPukGenerations: vi.fn(async () => []),
  rotateCollectionEpochsToPuk: vi.fn(async () => 'noop')
}))

vi.mock('@interop/was-client/edv', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client/edv')>()),
  collectionDescriptorStore: vi.fn(
    ({ collection }: { collection: unknown }) => ({ collection })
  )
}))

import {
  rotateCollectionEpochsToPuk,
  unwrapPukGenerations
} from '@interop/wallet-core/keys'
import { WALLET_STANDARD_COLLECTIONS } from '@/app.config'
import { cascadeCollectionsToPuk } from '@/session/pukCascade'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'
import type { CollectionEncryption } from '@interop/was-client'

const PUK = { id: 'did:key:z6LSFreshPuk', secret: new Uint8Array(32).fill(2) }
const GENERATIONS = [
  { id: 'did:key:z6LSOldPuk', secret: new Uint8Array(32).fill(1) },
  PUK
]
const ROSTER_DESCRIPTOR = { rosterDescriptor: true } as CollectionEncryption
const CLIENT_KAK = { id: 'did:key:z6MkClient#z6LSClient' } as never

const STANDARD_ENCRYPTED_IDS = WALLET_STANDARD_COLLECTIONS.filter(
  spec => spec.encryption
).map(spec => spec.id)

/**
 * A remote-store stub: `listCollections` yields the given remote items,
 * `collectionEncryption` declares every collection encrypted unless the test
 * overrides it, and `collectionHandle` returns a per-collection marker the
 * descriptor-store mock passes through.
 */
function makeFakeRemoteStore({
  remoteItems = [] as Array<{ id?: string; isEncrypted?: boolean }>,
  listFails = false
} = {}) {
  return {
    listCollections: vi.fn(async () => {
      if (listFails) {
        throw new Error('listing down')
      }
      return remoteItems
    }),
    collectionEncryption: vi.fn(
      async () => ({ scheme: 'edv' }) as unknown as CollectionEncryption
    ),
    collectionHandle: vi.fn(({ collectionId }: { collectionId: string }) => ({
      collectionId
    }))
  } as unknown as WASRemoteStore
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(unwrapPukGenerations).mockResolvedValue(GENERATIONS as never)
  vi.mocked(rotateCollectionEpochsToPuk).mockResolvedValue('noop')
})

describe('cascadeCollectionsToPuk', () => {
  it('rotates the encrypted standard collections plus the remotely listed encrypted ones, deduplicated', async () => {
    const remoteStore = makeFakeRemoteStore({
      remoteItems: [
        // A duplicate of a standard collection, an app-provisioned one, and
        // a plaintext one that must be excluded.
        { id: STANDARD_ENCRYPTED_IDS[0], isEncrypted: true },
        { id: 'app-notes', isEncrypted: true },
        { id: 'public-credentials', isEncrypted: false }
      ]
    })
    const { outcomes, failed } = await cascadeCollectionsToPuk({
      remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      puk: PUK
    })

    const expectedIds = [...STANDARD_ENCRYPTED_IDS, 'app-notes']
    expect(Object.keys(outcomes).sort()).toEqual([...expectedIds].sort())
    expect(failed).toEqual([])
    expect(vi.mocked(rotateCollectionEpochsToPuk)).toHaveBeenCalledTimes(
      expectedIds.length
    )
    // The unwrapped generations and the current PUK feed every per-collection
    // call, over that collection's own descriptor store.
    expect(vi.mocked(unwrapPukGenerations)).toHaveBeenCalledExactlyOnceWith({
      descriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK
    })
    expect(vi.mocked(rotateCollectionEpochsToPuk)).toHaveBeenCalledWith({
      store: { collection: { collectionId: 'app-notes' } },
      puk: PUK,
      generations: GENERATIONS
    })
  })

  it('degrades to the standard set when the remote listing fails', async () => {
    const remoteStore = makeFakeRemoteStore({ listFails: true })
    const { outcomes, failed } = await cascadeCollectionsToPuk({
      remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      puk: PUK
    })
    expect(Object.keys(outcomes).sort()).toEqual(
      [...STANDARD_ENCRYPTED_IDS].sort()
    )
    expect(failed).toEqual([])
  })

  it('skips a collection the server does not declare encrypted', async () => {
    const remoteStore = makeFakeRemoteStore()
    vi.mocked(remoteStore.collectionEncryption).mockResolvedValue(null)

    const { outcomes, failed } = await cascadeCollectionsToPuk({
      remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      puk: PUK
    })
    expect(outcomes).toEqual({})
    expect(failed).toEqual([])
    expect(vi.mocked(rotateCollectionEpochsToPuk)).not.toHaveBeenCalled()
  })

  it('collects a failing collection and proceeds with the rest', async () => {
    const stuckId = STANDARD_ENCRYPTED_IDS[0]
    const remoteStore = makeFakeRemoteStore()
    vi.mocked(rotateCollectionEpochsToPuk).mockImplementation(
      async ({ store }) => {
        const marked = store as unknown as {
          collection: { collectionId: string }
        }
        if (marked.collection.collectionId === stuckId) {
          throw new Error('stuck collection')
        }
        return 'rotated'
      }
    )

    const { outcomes, failed } = await cascadeCollectionsToPuk({
      remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      puk: PUK
    })
    expect(failed).toEqual([
      { collectionId: stuckId, error: expect.any(Error) }
    ])
    expect(outcomes[stuckId!]).toBeUndefined()
    expect(Object.keys(outcomes).sort()).toEqual(
      STANDARD_ENCRYPTED_IDS.filter(id => id !== stuckId).sort()
    )
    expect(
      Object.values(outcomes).every(outcome => outcome === 'rotated')
    ).toBe(true)
  })
})
