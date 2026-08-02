// @vitest-environment node
/**
 * Unit tests for the collection fan-out of the PUK cascade
 * (`src/session/pukCascade.ts`): the enumeration (encrypted standard
 * collections plus every remotely listed encrypted collection, deduplicated,
 * degrading to the standard set when the remote listing fails) and the
 * remote-store adapters handed to the `@interop/wallet-core/keys` driver
 * (`storeFor` over the collection handle, `isEncrypted` over the encryption
 * descriptor). The driving and the per-collection staleness/rotation logic
 * live in wallet-core and are mocked here.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  cascadeCollectionsToPuk: vi.fn(async () => ({ outcomes: {}, failed: [] }))
}))

vi.mock('@interop/was-client/edv', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client/edv')>()),
  collectionDescriptorStore: vi.fn(
    ({ collection }: { collection: unknown }) => ({ collection })
  )
}))

import { cascadeCollectionsToPuk as driveCascade } from '@interop/wallet-core/keys'
import { WALLET_STANDARD_COLLECTIONS } from '@/app.config'
import { cascadeCollectionsToPuk } from '@/session/pukCascade'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'
import type { CollectionEncryption } from '@interop/was-client'

const PUK = { id: 'did:key:z6LSFreshPuk', secret: new Uint8Array(32).fill(2) }
const ROSTER_DESCRIPTOR = {
  rosterDescriptor: true
} as unknown as CollectionEncryption
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

/**
 * The arguments the mocked wallet-core driver was handed on its sole call.
 */
function driverArgs() {
  expect(vi.mocked(driveCascade)).toHaveBeenCalledTimes(1)
  return vi.mocked(driveCascade).mock.calls[0]![0]
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(driveCascade).mockResolvedValue({ outcomes: {}, failed: [] })
})

describe('cascadeCollectionsToPuk', () => {
  it('names the encrypted standard collections plus the remotely listed encrypted ones, deduplicated', async () => {
    const remoteStore = makeFakeRemoteStore({
      remoteItems: [
        // A duplicate of a standard collection, an app-provisioned one, and
        // a plaintext one that must be excluded.
        { id: STANDARD_ENCRYPTED_IDS[0], isEncrypted: true },
        { id: 'app-notes', isEncrypted: true },
        { id: 'public-credentials', isEncrypted: false }
      ]
    })
    await cascadeCollectionsToPuk({
      remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      puk: PUK
    })

    const args = driverArgs()
    expect([...args.collectionIds].sort()).toEqual(
      [...STANDARD_ENCRYPTED_IDS, 'app-notes'].sort()
    )
    expect(args.rosterDescriptor).toBe(ROSTER_DESCRIPTOR)
    expect(args.clientKeyAgreementKey).toBe(CLIENT_KAK)
    expect(args.puk).toBe(PUK)
  })

  it('degrades to the standard set when the remote listing fails', async () => {
    const remoteStore = makeFakeRemoteStore({ listFails: true })
    await cascadeCollectionsToPuk({
      remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      puk: PUK
    })
    expect([...driverArgs().collectionIds].sort()).toEqual(
      [...STANDARD_ENCRYPTED_IDS].sort()
    )
  })

  it("adapts storeFor to the collection handle's descriptor store", async () => {
    const remoteStore = makeFakeRemoteStore()
    await cascadeCollectionsToPuk({
      remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      puk: PUK
    })
    const store = driverArgs().storeFor('app-notes')
    expect(store).toEqual({ collection: { collectionId: 'app-notes' } })
    expect(remoteStore.collectionHandle).toHaveBeenCalledWith({
      collectionId: 'app-notes'
    })
  })

  it('adapts isEncrypted to the encryption-descriptor read', async () => {
    const remoteStore = makeFakeRemoteStore()
    await cascadeCollectionsToPuk({
      remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      puk: PUK
    })
    const { isEncrypted } = driverArgs()
    await expect(isEncrypted!('private-credentials')).resolves.toBe(true)
    // An undeclared (plaintext or absent) collection reads back undefined.
    vi.mocked(remoteStore.collectionEncryption).mockResolvedValue(undefined)
    await expect(isEncrypted!('public-credentials')).resolves.toBe(false)
    expect(remoteStore.collectionEncryption).toHaveBeenCalledWith({
      collectionId: 'private-credentials'
    })
  })

  it("passes the driver's result through, warning per failed collection", async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const driverResult = {
      outcomes: { 'wallet-activity': 'rotated' as const },
      failed: [{ collectionId: 'app-notes', error: new Error('stuck') }]
    }
    vi.mocked(driveCascade).mockResolvedValue(driverResult)

    const result = await cascadeCollectionsToPuk({
      remoteStore: makeFakeRemoteStore(),
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      puk: PUK
    })
    expect(result).toBe(driverResult)
    expect(warn).toHaveBeenCalledWith(
      'Could not rotate collection "app-notes" onto the current PUK:',
      driverResult.failed[0]!.error
    )
    warn.mockRestore()
  })
})
