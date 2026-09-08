// @vitest-environment node
/**
 * Unit tests for the collection fan-out of the user key cascade
 * (`src/session/userKeyCascade.ts`): the enumeration (encrypted standard
 * collections plus every remotely listed encrypted collection, deduplicated,
 * degrading to the standard set when the remote listing fails) and the
 * remote-store adapter handed to the `@interop/wallet-core/keys` driver
 * (`isEncrypted` over the encryption descriptor), plus the caller's
 * per-collection descriptor-store lookup, which the fan-out now takes rather
 * than builds. The driving and the per-collection staleness/rotation logic
 * live in wallet-core and are mocked here.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  cascadeCollectionsToUserKey: vi.fn(async () => ({ outcomes: {}, failed: [] }))
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

/**
 * The caller's per-collection descriptor-store lookup, recording which
 * collections it was asked for. The fan-out takes it whole rather than
 * building one, so a ceremony's own signing key is what every append carries.
 */
function recordingStoreFor({
  governed = () => true
}: { governed?: (collectionId: string) => boolean } = {}) {
  const asked: string[] = []
  const storeFor = vi.fn((collectionId: string) => {
    asked.push(collectionId)
    return {
      collectionId,
      // A collection with no governing log reads back `null`, the way the
      // real store answers an absent `meta/log`.
      read: async () =>
        governed(collectionId)
          ? { descriptor: ROSTER_DESCRIPTOR, etag: '"1"' }
          : null
    } as never
  })
  return { storeFor, asked }
}

const STANDARD_ENCRYPTED_IDS = WALLET_STANDARD_COLLECTIONS.filter(
  spec => spec.encryption
).map(spec => spec.id)

/**
 * A remote-store stub: `listCollections` yields the given remote items, and
 * `collectionEncryption` declares every collection encrypted unless the test
 * overrides it.
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
    )
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
      storeFor: recordingStoreFor().storeFor,
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
      storeFor: recordingStoreFor().storeFor,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      userKey: USER_KEY
    })
    expect([...driverArgs().collectionIds].sort()).toEqual(
      [...STANDARD_ENCRYPTED_IDS].sort()
    )
  })

  it("passes the caller's descriptor-store lookup straight to the driver", async () => {
    const remoteStore = makeFakeRemoteStore()
    const { storeFor, asked } = recordingStoreFor()
    await cascadeCollectionsToUserKey({
      remoteStore,
      storeFor,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      userKey: USER_KEY
    })
    // The fan-out builds no store of its own: the lookup a ceremony hands in
    // is the one the driver calls, so every append carries that ceremony's
    // own licensed signing key.
    const store = driverArgs().storeFor('app-notes')
    expect(store).toMatchObject({ collectionId: 'app-notes' })
    expect(asked).toEqual(['app-notes'])
  })

  it('answers isEncrypted from the collection log, not the listing', async () => {
    const remoteStore = makeFakeRemoteStore({
      remoteItems: [
        { id: 'app-notes', isEncrypted: true },
        { id: 'public-credentials', isEncrypted: false }
      ]
    })
    const stores = recordingStoreFor({
      governed: collectionId => collectionId !== 'public-credentials'
    })
    await cascadeCollectionsToUserKey({
      remoteStore,
      storeFor: stores.storeFor,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      userKey: USER_KEY
    })
    const { isEncrypted } = driverArgs()
    await expect(isEncrypted!('app-notes')).resolves.toBe(true)
    await expect(isEncrypted!('public-credentials')).resolves.toBe(false)
    // One listing, for the enumeration alone: the probe reads the
    // collection's own verified log, so the server's derived `encryption`
    // member decides nothing here.
    expect(remoteStore.listCollections).toHaveBeenCalledOnce()
    expect(remoteStore.collectionEncryption).not.toHaveBeenCalled()
    expect(stores.asked).toEqual(
      expect.arrayContaining(['app-notes', 'public-credentials'])
    )
  })

  it('treats a listed-encrypted collection with no log as not encrypted', async () => {
    const remoteStore = makeFakeRemoteStore({
      remoteItems: [{ id: 'app-notes', isEncrypted: true }]
    })
    await cascadeCollectionsToUserKey({
      remoteStore,
      storeFor: recordingStoreFor({ governed: () => false }).storeFor,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: CLIENT_KAK,
      userKey: USER_KEY
    })
    const { isEncrypted } = driverArgs()
    await expect(isEncrypted!('app-notes')).resolves.toBe(false)
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
      storeFor: recordingStoreFor().storeFor,
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
