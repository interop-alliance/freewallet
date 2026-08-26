// @vitest-environment node
/**
 * Unit tests for the collection fan-out of the user key cascade
 * (`src/session/userKeyCascade.ts`): the enumeration (encrypted standard
 * collections plus every remotely listed encrypted collection, deduplicated,
 * degrading to the standard set when the remote listing fails) and the
 * remote-store adapters handed to the `@interop/wallet-core/keys` driver
 * (`storeFor` over the collection handle, `isEncrypted` over the encryption
 * descriptor). The driving and the per-collection staleness/rotation logic
 * live in wallet-core and are mocked here.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  cascadeCollectionsToUserKey: vi.fn(async () => ({ outcomes: {}, failed: [] }))
}))

vi.mock('@interop/was-client/edv', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client/edv')>()),
  collectionDescriptorStore: vi.fn(
    ({ collection }: { collection: unknown }) => ({ collection })
  )
}))

import { cascadeCollectionsToUserKey as driveCascade } from '@interop/wallet-core/keys'
import { WALLET_STANDARD_COLLECTIONS } from '@/app.config'
import { cascadeCollectionsToUserKey } from '@/session/userKeyCascade'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'
import type { CollectionEncryption } from '@interop/was-client'

const USER_KEY = {
  id: 'did:key:z6LSFreshUserKey',
  secret: new Uint8Array(32).fill(2)
}
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

describe('cascadeCollectionsToUserKey', () => {
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
    await cascadeCollectionsToUserKey({
      remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      userKey: USER_KEY
    })

    const args = driverArgs()
    expect([...args.collectionIds].sort()).toEqual(
      [...STANDARD_ENCRYPTED_IDS, 'app-notes'].sort()
    )
    expect(args.rosterDescriptor).toBe(ROSTER_DESCRIPTOR)
    expect(args.clientKeyAgreementKey).toBe(CLIENT_KAK)
    expect(args.userKey).toBe(USER_KEY)
  })

  it('degrades to the standard set when the remote listing fails', async () => {
    const remoteStore = makeFakeRemoteStore({ listFails: true })
    await cascadeCollectionsToUserKey({
      remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      userKey: USER_KEY
    })
    expect([...driverArgs().collectionIds].sort()).toEqual(
      [...STANDARD_ENCRYPTED_IDS].sort()
    )
  })

  it("adapts storeFor to the collection handle's descriptor store", async () => {
    const remoteStore = makeFakeRemoteStore()
    await cascadeCollectionsToUserKey({
      remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      userKey: USER_KEY
    })
    const store = driverArgs().storeFor('app-notes')
    expect(store).toEqual({ collection: { collectionId: 'app-notes' } })
    expect(remoteStore.collectionHandle).toHaveBeenCalledWith({
      collectionId: 'app-notes'
    })
  })

  it('lists the Space once and answers isEncrypted from that listing', async () => {
    const remoteStore = makeFakeRemoteStore({
      remoteItems: [
        { id: 'app-notes', isEncrypted: true },
        { id: 'public-credentials', isEncrypted: false }
      ]
    })
    await cascadeCollectionsToUserKey({
      remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      userKey: USER_KEY
    })
    const { isEncrypted } = driverArgs()
    await expect(isEncrypted!('app-notes')).resolves.toBe(true)
    await expect(isEncrypted!('public-credentials')).resolves.toBe(false)
    // One listing for the enumeration and both probes, and no describe at all
    // for a collection the listing already covered.
    expect(remoteStore.listCollections).toHaveBeenCalledOnce()
    expect(remoteStore.collectionEncryption).not.toHaveBeenCalled()
  })

  it('falls back to the encryption-descriptor read off the listing', async () => {
    const remoteStore = makeFakeRemoteStore()
    await cascadeCollectionsToUserKey({
      remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      userKey: USER_KEY
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
    const capture = captureSink()
    addSink(capture.sink)
    const driverResult = {
      outcomes: { 'wallet-activity': 'rotated' as const },
      failed: [{ collectionId: 'app-notes', error: new Error('stuck') }]
    }
    vi.mocked(driveCascade).mockResolvedValue(driverResult)

    const result = await cascadeCollectionsToUserKey({
      remoteStore: makeFakeRemoteStore(),
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      userKey: USER_KEY
    })
    expect(result).toBe(driverResult)
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        ns: 'fw:session:cascade',
        level: 'warn',
        msg: 'Could not rotate collection onto the current user key',
        err: driverResult.failed[0]!.error,
        data: { collectionId: 'app-notes' }
      })
    )
    warn.mockRestore()
  })
})
