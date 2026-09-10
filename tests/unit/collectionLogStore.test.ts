// @vitest-environment node
/**
 * Unit tests for the session-shaped collection descriptor store wiring
 * (`src/session/collectionLogStore.ts`): what the live session's binding
 * hands wallet-core's `collectionDescriptorStores` (the remote store's
 * collection handle, the session pins, the signer, the verified-log
 * controller), the address each store is aimed at (the collection's own
 * `meta/log`, whose pin slot the library names), and which agent a live
 * session's appends sign with. The bare-parts builder's own behavior is
 * wallet-core's to test.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  collectionDescriptorStores: vi.fn(options => ({ options })),
  userKeyRosterLogSigner: vi.fn(() => ({ isDescriptorLogSigner: true }))
}))

vi.mock('@interop/wallet-core/descriptors', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/descriptors')
  >()),
  logGovernedDescriptorSource: vi.fn(options => ({ options }))
}))

vi.mock('@/session/verifiedLog', () => ({
  verifiedAccountLog: vi.fn()
}))

vi.mock('@interop/wallet-core/resourceLog', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/resourceLog')
  >()),
  webvhResourceLogController: vi.fn(options => ({ controllerFor: options }))
}))

import type { Collection } from '@interop/was-client'
import {
  collectionDescriptorStores,
  userKeyRosterLogSigner
} from '@interop/wallet-core/keys'
import {
  collectionDescriptorLogPinId,
  logGovernedDescriptorSource
} from '@interop/wallet-core/descriptors'
import { ladderVmAgent } from '@interop/wallet-core/clientAnnex'
import { verifiedAccountLog } from '@/session/verifiedLog'
import {
  descriptorLogSignerAgent,
  sessionCollectionDescriptorSource,
  sessionCollectionStores
} from '@/session/collectionLogStore'
import {
  browserLocalSessionPersistence,
  inMemorySessionPersistence,
  transientSessionStores
} from '@/session/persistence'
import type { ControllerProfile, Session } from '@/types/auth'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const KEY_AGENT = { id: 'did:key:zAgent' } as never as Parameters<
  typeof sessionCollectionStores
>[0]['keyAgent']

/**
 * The options the session binding handed wallet-core's lookup builder.
 *
 * @returns {object}
 */
function capturedBuilderOptions(): {
  collectionFor: (collectionId: string) => Collection
  resolveController: () => Promise<unknown>
  pinStore: unknown
  signer: unknown
} {
  return vi.mocked(collectionDescriptorStores).mock.calls[0]![0]
}

/**
 * A live session, cut down to the members the two session-shaped builders
 * read: the profile's account pointer and the session's persistence
 * strategy.
 *
 * @param options {object}
 * @param [options.did] {string}   the account pointer's DID, absent for the
 *   no-pointer refusals
 * @returns {object}
 */
function sessionFixture({ did }: { did?: string } = {}): Pick<
  Session,
  'profile' | 'persistence'
> {
  return {
    profile: {
      accountPointer: did ? { ...POINTER, did } : {}
    } as never as ControllerProfile,
    persistence: browserLocalSessionPersistence()
  }
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

describe('sessionCollectionStores', () => {
  it('reaches each collection through the remote store, under the session pins', () => {
    const session = sessionFixture({ did: POINTER.did })
    sessionCollectionStores({
      session,
      remoteStore: remoteStoreStub(),
      keyAgent: KEY_AGENT
    })

    const { collectionFor, pinStore, signer } = capturedBuilderOptions()
    const contacts = collectionFor('contacts')
    expect(contacts).toMatchObject({
      spaceId: POINTER.spaceId,
      id: 'contacts',
      isRemoteHandle: true
    })
    expect(pinStore).toBe(session.persistence.logPins)
    expect(userKeyRosterLogSigner).toHaveBeenCalledWith({ keyAgent: KEY_AGENT })
    expect(signer).toEqual({ isDescriptorLogSigner: true })
    expect(
      collectionDescriptorLogPinId({
        spaceId: contacts.spaceId,
        collectionId: contacts.id
      })
    ).toBe('space/space-123/contacts/meta/log')
  })

  it("resolves the controller through the session's verified-log memo", async () => {
    const session = sessionFixture({ did: POINTER.did })
    const log = [{ entry: 'memo' }]
    vi.mocked(verifiedAccountLog).mockResolvedValue({ log } as never)
    sessionCollectionStores({
      session,
      remoteStore: remoteStoreStub(),
      keyAgent: KEY_AGENT
    })

    const controller = await capturedBuilderOptions().resolveController()

    expect(verifiedAccountLog).toHaveBeenCalledWith({ session })
    expect(controller).toEqual({ controllerFor: { did: POINTER.did, log } })
  })

  it('refuses a session whose pointer names no DID', () => {
    expect(() =>
      sessionCollectionStores({
        session: sessionFixture(),
        remoteStore: remoteStoreStub(),
        keyAgent: KEY_AGENT
      })
    ).toThrow(/account pointer/)
  })
})

describe('sessionCollectionDescriptorSource', () => {
  it("names the session's Space and rides its pins", () => {
    const session = sessionFixture({ did: POINTER.did })

    sessionCollectionDescriptorSource({
      session,
      remoteStore: remoteStoreStub()
    })

    const options = vi.mocked(logGovernedDescriptorSource).mock.calls[0]![0]
    expect(options.spaceId).toBe(POINTER.spaceId)
    expect(options.pinStore).toBe(session.persistence.logPins)
  })

  it('refuses a session whose pointer names no DID', () => {
    expect(() =>
      sessionCollectionDescriptorSource({
        session: sessionFixture(),
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
      session: {
        persistence: browserLocalSessionPersistence(),
        profile: { keyAgent } as never as ControllerProfile
      }
    })

    expect(agent).toBe(keyAgent)
  })

  it('refuses a browser-local session holding no key agent', async () => {
    await expect(
      descriptorLogSignerAgent({
        session: {
          persistence: browserLocalSessionPersistence(),
          profile: {} as never as ControllerProfile
        }
      })
    ).rejects.toThrow(/client key agent/)
  })

  it("signs with the credential's ladder VM on a transient session", async () => {
    const ladderSeed = new Uint8Array(32).fill(7)
    const agent = await descriptorLogSignerAgent({
      session: {
        persistence: transientPersistence(),
        profile: {
          // The per-visit key stands in no account document, so a remembered
          // client's agent beside it must not be what signs.
          keyAgent: { id: 'did:key:zTransientVisitKey' },
          ladderSeed
        } as never as ControllerProfile
      }
    })

    const expected = await ladderVmAgent({ ladderSeed })
    expect(agent.id).toBe(expected.id)
    expect(agent.id).not.toBe('did:key:zTransientVisitKey')
  })

  it('refuses a transient session holding no ladder seed', async () => {
    await expect(
      descriptorLogSignerAgent({
        session: {
          persistence: transientPersistence(),
          profile: {} as never as ControllerProfile
        }
      })
    ).rejects.toThrow(/ladder seed/)
  })
})
