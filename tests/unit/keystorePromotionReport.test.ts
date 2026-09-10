// @vitest-environment node
/**
 * Unit test for the keystore promotion a login keeps for its mend report
 * (`StorageManager.ensurePromotedController` and the `keystorePromotion`
 * accessor beside it).
 *
 * Storage provisioning calls `ensurePromotedController` on every login of an
 * account whose pointer already names the did:webvh, and that call fires the
 * keystore promotion. Provisioning has nowhere to hand the promise back to,
 * so the manager keeps it: the login block's tail registration reads it
 * there and reports the promotion that actually ran, rather than reporting
 * `noop` because the pointer heal fired none.
 */
import { describe, expect, it } from 'vitest'
import { browserLocalSessionPersistence } from '@/session/persistence'
import { StorageManager } from '@/stores/storageManager'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'
import type { ControllerProfile } from '@/types/auth'

const ACCOUNT_DID =
  'did:webvh:QmScidForTests:was.example.test:space:space-123:id'

/**
 * A remote store bound to the promoted controller already, whose one
 * describe confirms the server agrees.
 */
function promotedRemoteStore(): WASRemoteStore {
  return {
    controller: ACCOUNT_DID,
    spaceHandle: () => ({
      describe: async () => ({ controller: ACCOUNT_DID })
    })
  } as unknown as WASRemoteStore
}

/**
 * A profile carrying the account DID and a signing key, and no keystore
 * agent -- so the promotion resolves without a KMS round trip.
 */
function profileWithNoKeystore(): ControllerProfile {
  return {
    didWebvh: { did: ACCOUNT_DID },
    keyAgent: { id: 'did:key:z6MkClient#z6MkClient' }
  } as unknown as ControllerProfile
}

describe('the keystore promotion a login keeps', () => {
  it('is empty until a promotion runs', () => {
    const storage = new StorageManager({
      remoteStore: promotedRemoteStore(),
      persistence: browserLocalSessionPersistence()
    })
    expect(storage.keystorePromotion).toBeUndefined()
  })

  it('keeps the promotion a confirming promotion check fired', async () => {
    const storage = new StorageManager({
      remoteStore: promotedRemoteStore(),
      persistence: browserLocalSessionPersistence()
    })

    const { promoted } = await storage.ensurePromotedController({
      profile: profileWithNoKeystore()
    })

    // The server already agreed, so nothing was promoted here -- but the
    // keystore half ran, and the manager kept it for the block's tail.
    expect(promoted).toBe(false)
    expect(storage.keystorePromotion).toBeDefined()
    expect(await storage.keystorePromotion).toEqual({ outcome: 'noop' })
  })

  it('fires no promotion, and keeps none, without an account DID', async () => {
    const storage = new StorageManager({
      remoteStore: promotedRemoteStore(),
      persistence: browserLocalSessionPersistence()
    })

    const { promoted } = await storage.ensurePromotedController({
      profile: { keyAgent: { id: 'did:key:z6MkClient#z6MkClient' } } as never
    })

    expect(promoted).toBe(false)
    expect(storage.keystorePromotion).toBeUndefined()
  })
})
