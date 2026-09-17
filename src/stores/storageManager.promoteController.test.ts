/**
 * Unit tests for the login-time controller promotion
 * (`StorageManager.ensurePromotedController`), specifically what it hands
 * was-client's `Space.configure()` as `current`. The promoted-signer read it
 * makes is a description in hand, so it rides along with that read's `ETag`
 * and the pre-merge re-describe is skipped. Two answers do not ride along: a
 * `null`, since an unauthorized answer under the promoted signer is masked as
 * the same 404 an absent description returns, and a read carrying no `ETag`,
 * which is no compare-and-swap baseline -- was-client refuses such a write
 * rather than sending it unconditionally.
 *
 * @vitest-environment node
 */
import { describe, expect, it, vi } from 'vitest'
import type { ZcapClient } from '@interop/ezcap'
import type { SpaceMetadata } from '@interop/was-client'
import {
  inMemorySessionPersistence,
  transientSessionStores
} from '@/session/persistence'
import type { IZcap } from '@interop/was-client'
import type { ControllerProfile } from '@/types/auth'
import { StorageManager } from './storageManager'
import type { WASRemoteStore } from './wasRemoteStore'

const ACCOUNT_DID = 'did:webvh:QmScid:was.example:space:s-space'

/**
 * A recording stand-in for the remote store's promotion surface: the Space
 * handle's `describeWithEtag`, the controller rebinds, and the promotion PUT.
 * The read answers as a real WAS server does, with the Description and its
 * validator, since the validator is what the promotion write is pinned to.
 */
function fakeRemote({
  describeResult
}: {
  describeResult:
    { description: SpaceMetadata; etag?: string } | null | (() => never)
}) {
  const promoteSpaceController = vi.fn().mockResolvedValue(undefined)
  const rebindController = vi.fn()
  const describeSpace = vi.fn().mockImplementation(async () => {
    if (typeof describeResult === 'function') {
      return describeResult()
    }
    return describeResult
  })
  const remoteStore = {
    spaceId: 's-space',
    controller: ACCOUNT_DID,
    spaceHandle: () => ({ describeWithEtag: describeSpace }),
    rebindController,
    promoteSpaceController
  } as unknown as WASRemoteStore
  return {
    remoteStore,
    promoteSpaceController,
    rebindController,
    describeSpace
  }
}

/**
 * A StorageManager over that fake, plus the profile the promotion reads: a
 * signer-shaped key agent (`didKeyZcapClient` only calls `getSigner()`) and
 * the account's did:webvh.
 */
function managerFor(remoteStore: WASRemoteStore): {
  manager: StorageManager
  profile: ControllerProfile
} {
  const manager = new StorageManager({
    remoteStore,
    persistence: inMemorySessionPersistence({
      stores: transientSessionStores(),
      clientAnnex: {
        clientAnnexDid: 'did:webvh:example:annex',
        invocationCapability: {} as IZcap
      }
    })
  })
  const profile = {
    zcapClient: {} as ZcapClient,
    keyAgent: {
      id: 'did:key:z6MkTestClient',
      getSigner: () => ({
        id: 'did:key:z6MkTestClient#z6MkTestClient',
        type: 'Ed25519VerificationKey2020',
        sign: async () => new Uint8Array()
      })
    },
    didWebvh: { did: ACCOUNT_DID }
  } as unknown as ControllerProfile
  return { manager, profile }
}

describe('StorageManager.ensurePromotedController', () => {
  it('passes the non-null read through as `current`, validator included', async () => {
    const { remoteStore, promoteSpaceController, describeSpace } = fakeRemote({
      // The Space is there, but still controlled by the did:key: the
      // promotion PUT never landed.
      describeResult: {
        description: {
          id: 's-space',
          controller: 'did:key:z6MkTestClient'
        } as unknown as SpaceMetadata,
        etag: '"1"'
      }
    })
    const { manager, profile } = managerFor(remoteStore)

    await manager.ensurePromotedController({ profile })

    expect(describeSpace).toHaveBeenCalledOnce()
    expect(promoteSpaceController).toHaveBeenCalledWith({
      controller: ACCOUNT_DID,
      current: {
        id: 's-space',
        controller: 'did:key:z6MkTestClient',
        etag: '"1"'
      }
    })
  })

  it('drops `current` when the read carried no validator', async () => {
    const { remoteStore, promoteSpaceController } = fakeRemote({
      // No `ETag` reached the client (a proxy stripping the header, a
      // browser without it exposed): the read is no baseline, so the write
      // goes out without one and `configure` reads for itself instead of
      // being refused for a baseline it cannot pin to.
      describeResult: {
        description: {
          id: 's-space',
          controller: 'did:key:z6MkTestClient'
        } as unknown as SpaceMetadata
      }
    })
    const { manager, profile } = managerFor(remoteStore)

    await manager.ensurePromotedController({ profile })

    expect(promoteSpaceController).toHaveBeenCalledWith({
      controller: ACCOUNT_DID
    })
  })

  it('omits `current` when that read came back null', async () => {
    const { remoteStore, promoteSpaceController } = fakeRemote({
      describeResult: null
    })
    const { manager, profile } = managerFor(remoteStore)

    await manager.ensurePromotedController({ profile })

    expect(promoteSpaceController).toHaveBeenCalledWith({
      controller: ACCOUNT_DID
    })
  })

  it('skips the promotion entirely when the server already agrees', async () => {
    const { remoteStore, promoteSpaceController } = fakeRemote({
      describeResult: {
        description: {
          id: 's-space',
          controller: ACCOUNT_DID
        } as unknown as SpaceMetadata,
        etag: '"1"'
      }
    })
    const { manager, profile } = managerFor(remoteStore)

    await manager.ensurePromotedController({ profile })

    expect(promoteSpaceController).not.toHaveBeenCalled()
  })

  it('skips the promotion when the confirming read throws', async () => {
    const { remoteStore, promoteSpaceController } = fakeRemote({
      describeResult: () => {
        throw new Error('network flake')
      }
    })
    const { manager, profile } = managerFor(remoteStore)

    await manager.ensurePromotedController({ profile })

    expect(promoteSpaceController).not.toHaveBeenCalled()
  })
})
