// @vitest-environment node
/**
 * Unit tests for the log-governed collection descriptor store builders
 * (`src/session/collectionLogStore.ts`): how the bare-parts builder resolves
 * the controller view across a fan-out of collections, that it builds
 * nothing until the first lookup, the address each store is aimed at (the
 * collection's own `meta/log`, whose pin slot the library names), and which
 * agent a live session's appends sign with.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  collectionDescriptorLogStore: vi.fn(options => ({ options })),
  userKeyRosterLogSigner: vi.fn(() => ({ isDescriptorLogSigner: true }))
}))

vi.mock('@interop/wallet-core/descriptors', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/descriptors')
  >()),
  logGovernedDescriptorSource: vi.fn(options => ({ options }))
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

import type { Collection } from '@interop/was-client'
import {
  collectionDescriptorLogStore,
  userKeyRosterLogSigner
} from '@interop/wallet-core/keys'
import {
  collectionDescriptorLogPinId,
  logGovernedDescriptorSource
} from '@interop/wallet-core/descriptors'
import { verifyAccountLog } from '@interop/wallet-core/webvh'
import { webvhResourceLogController } from '@interop/wallet-core/resourceLog'
import { ladderVmAgent } from '@interop/wallet-core/clientAnnex'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import {
  accountCollectionStores,
  descriptorLogSignerAgent,
  sessionCollectionDescriptorSource,
  sessionCollectionStores,
  type CollectionStoreFor
} from '@/session/collectionLogStore'
import {
  browserLocalSessionPersistence,
  inMemorySessionPersistence,
  transientSessionStores
} from '@/session/persistence'
import type { ControllerProfile } from '@/types/auth'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const SERVED_LOG = [{ entry: 'served' }]
const PARTS = {
  // was-client reads the wrapped signer's id to derive the controller DID, so
  // a bare stub is not enough to build a Space handle from.
  zcapClient: { invocationSigner: { id: 'did:key:zAgent#zAgent' } },
  keyAgent: { id: 'did:key:zAgent' }
} as never as {
  zcapClient: Parameters<typeof accountCollectionStores>[0]['zcapClient']
  keyAgent: Parameters<typeof accountCollectionStores>[0]['keyAgent']
}

/**
 * The options the builder handed wallet-core's per-collection store, in the
 * order the lookups were made.
 *
 * @returns {Array<object>}
 */
function capturedStoreOptions(): Array<{
  collection: Collection
  resolveController: () => Promise<unknown>
  pinStore: unknown
  signer: unknown
}> {
  return vi
    .mocked(collectionDescriptorLogStore)
    .mock.calls.map(([options]) => options)
}

/**
 * A live session's profile, cut down to the members the two session-shaped
 * builders read.
 *
 * @param options {object}
 * @param [options.did] {string}   the account pointer's DID, absent for the
 *   no-pointer refusals
 * @returns {ControllerProfile}
 */
function sessionProfile({ did }: { did?: string } = {}): ControllerProfile {
  return {
    accountPointer: did ? { ...POINTER, did } : {},
    persistence: browserLocalSessionPersistence()
  } as never as ControllerProfile
}

/**
 * The remote store stand-in: the collection handles the session builders
 * reach each collection through.
 *
 * @returns {WASRemoteStore}
 */
function remoteStoreStub(): WASRemoteStore {
  return {
    spaceId: POINTER.spaceId,
    collectionHandle: ({ collectionId }: { collectionId: string }) => ({
      spaceId: POINTER.spaceId,
      id: collectionId,
      isRemoteHandle: true
    })
  } as never as WASRemoteStore
}

afterEach(() => {
  vi.clearAllMocks()
})

describe('accountCollectionStores -- the controller view', () => {
  it('verifies the account log once across a fan-out of collections', async () => {
    const pinStore = memoryResourceLogPinStore()
    vi.mocked(verifyAccountLog).mockResolvedValue({
      doc: { id: POINTER.did },
      log: SERVED_LOG,
      updateKeys: [],
      nextKeyHashes: []
    } as never)
    const storeFor = accountCollectionStores({
      ...PARTS,
      pointer: POINTER,
      pinStore
    })

    storeFor('private-credentials')
    storeFor('wallet-activity')
    storeFor('contacts')
    // Every collection's store resolves its own controller view, as
    // wallet-core resolves it per operation.
    for (const options of capturedStoreOptions()) {
      await options.resolveController()
    }

    // One verification for the whole lookup: the in-flight promise is the memo.
    expect(vi.mocked(verifyAccountLog).mock.calls).toHaveLength(1)
    expect(vi.mocked(verifyAccountLog).mock.calls[0]![0]).toEqual({
      did: POINTER.did,
      spaceId: POINTER.spaceId,
      host: POINTER.host,
      pinStore
    })
    expect(webvhResourceLogController).toHaveBeenCalledWith({
      did: POINTER.did,
      log: SERVED_LOG
    })
  })

  it('resolves a seeded head without reading did.jsonl at all', async () => {
    const seeded = [{ entry: 'this run' }]
    const storeFor = accountCollectionStores({
      ...PARTS,
      pointer: POINTER,
      pinStore: memoryResourceLogPinStore(),
      log: seeded as never
    })

    storeFor('private-credentials')
    const controller = await capturedStoreOptions()[0]!.resolveController()

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
    vi.mocked(verifyAccountLog)
      .mockRejectedValueOnce(new Error('the host flapped'))
      .mockResolvedValueOnce({
        doc: { id: POINTER.did },
        log: SERVED_LOG,
        updateKeys: [],
        nextKeyHashes: []
      } as never)
    const storeFor = accountCollectionStores({
      ...PARTS,
      pointer: POINTER,
      pinStore: memoryResourceLogPinStore()
    })

    storeFor('private-credentials')
    const { resolveController } = capturedStoreOptions()[0]!
    await expect(resolveController()).rejects.toThrow('the host flapped')
    await resolveController()

    expect(vi.mocked(verifyAccountLog).mock.calls).toHaveLength(2)
  })
})

describe('accountCollectionStores -- what it builds, and when', () => {
  it('touches the signing client only at the first lookup', () => {
    // A client with no invocation signer cannot build a Space handle, so a
    // construction that survives it is one that built nothing: a lookup
    // handed to a ceremony that installs no epoch costs nothing.
    let storeFor: CollectionStoreFor | undefined
    expect(() => {
      storeFor = accountCollectionStores({
        zcapClient: {} as never,
        keyAgent: PARTS.keyAgent,
        pointer: POINTER,
        pinStore: memoryResourceLogPinStore()
      })
    }).not.toThrow()
    expect(collectionDescriptorLogStore).not.toHaveBeenCalled()
    expect(userKeyRosterLogSigner).not.toHaveBeenCalled()
    expect(verifyAccountLog).not.toHaveBeenCalled()

    expect(() => storeFor!('private-credentials')).toThrow(/invocationSigner/)
  })

  it('builds the store on the first lookup, fetching nothing', () => {
    const storeFor = accountCollectionStores({
      ...PARTS,
      pointer: POINTER,
      pinStore: memoryResourceLogPinStore()
    })

    storeFor('private-credentials')

    expect(collectionDescriptorLogStore).toHaveBeenCalledTimes(1)
    expect(userKeyRosterLogSigner).toHaveBeenCalledTimes(1)
    // Nothing fetched yet: the controller view is resolved per operation.
    expect(verifyAccountLog).not.toHaveBeenCalled()
  })

  it('shares one Space handle and one signer across its collections', () => {
    const storeFor = accountCollectionStores({
      ...PARTS,
      pointer: POINTER,
      pinStore: memoryResourceLogPinStore()
    })

    storeFor('private-credentials')
    storeFor('wallet-activity')

    expect(userKeyRosterLogSigner).toHaveBeenCalledTimes(1)
    expect(userKeyRosterLogSigner).toHaveBeenCalledWith({
      keyAgent: PARTS.keyAgent
    })
    const [first, second] = capturedStoreOptions()
    expect(first!.signer).toBe(second!.signer)
  })

  it("aims each store at the collection's own meta/log pin slot", () => {
    const pinStore = memoryResourceLogPinStore()
    const storeFor = accountCollectionStores({
      ...PARTS,
      pointer: POINTER,
      pinStore
    })

    storeFor('private-credentials')
    storeFor('wallet-activity')

    const [credentials, activity] = capturedStoreOptions()
    // The handle IS the address: wallet-core derives the store's chain-head
    // pin slot from the handle's Space and collection ids, so the slot the
    // library names for it is the one this store pins under.
    expect(credentials!.collection.spaceId).toBe(POINTER.spaceId)
    expect(credentials!.collection.id).toBe('private-credentials')
    expect(
      collectionDescriptorLogPinId({
        spaceId: credentials!.collection.spaceId,
        collectionId: credentials!.collection.id
      })
    ).toBe('space/space-123/private-credentials/meta/log')
    expect(
      collectionDescriptorLogPinId({
        spaceId: activity!.collection.spaceId,
        collectionId: activity!.collection.id
      })
    ).toBe('space/space-123/wallet-activity/meta/log')
    // One keyed pin store serves every collection's slot.
    expect(credentials!.pinStore).toBe(pinStore)
    expect(activity!.pinStore).toBe(pinStore)
  })
})

describe('sessionCollectionStores', () => {
  it('reaches each collection through the remote store, under the session pins', () => {
    const profile = sessionProfile({ did: POINTER.did })
    const storeFor = sessionCollectionStores({
      profile,
      remoteStore: remoteStoreStub(),
      keyAgent: PARTS.keyAgent
    })

    storeFor('contacts')

    const [contacts] = capturedStoreOptions()
    expect(contacts!.collection).toMatchObject({
      spaceId: POINTER.spaceId,
      id: 'contacts',
      isRemoteHandle: true
    })
    expect(contacts!.pinStore).toBe(profile.persistence.logPins)
    expect(
      collectionDescriptorLogPinId({
        spaceId: contacts!.collection.spaceId,
        collectionId: contacts!.collection.id
      })
    ).toBe('space/space-123/contacts/meta/log')
  })

  it('refuses a session whose pointer names no DID', () => {
    expect(() =>
      sessionCollectionStores({
        profile: sessionProfile(),
        remoteStore: remoteStoreStub(),
        keyAgent: PARTS.keyAgent
      })
    ).toThrow(/account pointer/)
  })
})

describe('sessionCollectionDescriptorSource', () => {
  it("names the session's Space and rides its pins", () => {
    const profile = sessionProfile({ did: POINTER.did })

    sessionCollectionDescriptorSource({
      profile,
      remoteStore: remoteStoreStub()
    })

    const options = vi.mocked(logGovernedDescriptorSource).mock.calls[0]![0]
    expect(options.spaceId).toBe(POINTER.spaceId)
    expect(options.pinStore).toBe(profile.persistence.logPins)
  })

  it('refuses a session whose pointer names no DID', () => {
    expect(() =>
      sessionCollectionDescriptorSource({
        profile: sessionProfile(),
        remoteStore: remoteStoreStub()
      })
    ).toThrow(/account pointer/)
  })
})

describe('descriptorLogSignerAgent', () => {
  /**
   * A transient session's strategy over fresh in-memory stores.
   *
   * @returns {ReturnType<typeof inMemorySessionPersistence>}
   */
  function transientPersistence() {
    return inMemorySessionPersistence({
      stores: transientSessionStores(),
      clientAnnex: {
        clientAnnexDid: 'did:webvh:example:annex',
        invocationCapability: {} as never
      }
    })
  }

  it("signs with this client's own key agent on a browser-local session", async () => {
    const keyAgent = { id: 'did:key:zEnrolledClient' }
    const agent = await descriptorLogSignerAgent({
      profile: {
        persistence: browserLocalSessionPersistence(),
        keyAgent
      } as never as ControllerProfile
    })

    expect(agent).toBe(keyAgent)
  })

  it('refuses a browser-local session holding no key agent', async () => {
    await expect(
      descriptorLogSignerAgent({
        profile: {
          persistence: browserLocalSessionPersistence()
        } as never as ControllerProfile
      })
    ).rejects.toThrow(/client key agent/)
  })

  it("signs with the credential's ladder VM on a transient session", async () => {
    const ladderSeed = new Uint8Array(32).fill(7)
    const agent = await descriptorLogSignerAgent({
      profile: {
        persistence: transientPersistence(),
        // The per-visit key stands in no account document, so a remembered
        // client's agent beside it must not be what signs.
        keyAgent: { id: 'did:key:zTransientVisitKey' },
        ladderSeed
      } as never as ControllerProfile
    })

    const expected = await ladderVmAgent({ ladderSeed })
    expect(agent.id).toBe(expected.id)
    expect(agent.id).not.toBe('did:key:zTransientVisitKey')
  })

  it('refuses a transient session holding no ladder seed', async () => {
    await expect(
      descriptorLogSignerAgent({
        profile: {
          persistence: transientPersistence()
        } as never as ControllerProfile
      })
    ).rejects.toThrow(/ladder seed/)
  })
})
