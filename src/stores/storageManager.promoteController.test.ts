/**
 * Unit tests for the login-time controller promotion
 * (`StorageManager.ensurePromotedController`), specifically what it hands
 * was-client's `Space.configure()` as `current`. The promoted-signer read it
 * makes is a description in hand, so it rides along and the pre-merge
 * re-describe is skipped; a `null` from that read is not, since an
 * unauthorized answer under the promoted signer is masked as the same 404 an
 * absent description returns.
 *
 * @vitest-environment node
 */
import { describe, expect, it, vi } from 'vitest'
import type { ZcapClient } from '@interop/ezcap'
import type { SpaceDescription } from '@interop/was-client'
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
 * handle's `describe`, the controller rebinds, and the promotion PUT.
 */
function fakeRemote({
  describeResult
}: {
  describeResult: SpaceDescription | null | (() => never)
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
    spaceHandle: () => ({ describe: describeSpace }),
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
  it('passes the non-null read through as `current`', async () => {
    const { remoteStore, promoteSpaceController, describeSpace } = fakeRemote({
      // The Space is there, but still controlled by the did:key: the
      // promotion PUT never landed.
      describeResult: {
        id: 's-space',
        controller: 'did:key:z6MkTestClient'
      } as unknown as SpaceDescription
    })
    const { manager, profile } = managerFor(remoteStore)

    await manager.ensurePromotedController({ profile })

    expect(describeSpace).toHaveBeenCalledOnce()
    expect(promoteSpaceController).toHaveBeenCalledWith({
      controller: ACCOUNT_DID,
      current: { id: 's-space', controller: 'did:key:z6MkTestClient' }
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
        id: 's-space',
        controller: ACCOUNT_DID
      } as unknown as SpaceDescription
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
