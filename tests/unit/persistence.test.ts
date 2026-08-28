/**
 * The session durability seam: the transient handle's in-memory
 * members and refusals, and the durable handle's cache memoization.
 */
import { describe, expect, it } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import {
  assertAccountCeremonyAllowed,
  assertBrowserLocalSession,
  BrowserLocalSessionRequiredError,
  browserLocalSessionPersistence,
  isBrowserLocalSession,
  StepUpRequiredError,
  inMemorySessionPersistence,
  transientSessionStores,
  type InMemorySessionPersistence
} from '@/session/persistence'

/**
 * A full transient handle over fresh stores, with a stub annex identity --
 * what the composition hands the session once the enrollment has run.
 */
function transientHandle(): InMemorySessionPersistence {
  return inMemorySessionPersistence({
    stores: transientSessionStores(),
    clientAnnex: {
      clientAnnexDid: 'did:webvh:example:annex',
      invocationCapability: {} as IZcap
    }
  })
}

describe('the transient persistence handle', () => {
  it('is typed non-durable and carries no idb factory member', () => {
    const handle = transientHandle()
    expect(isBrowserLocalSession(handle)).toBe(false)
    expect('idb' in handle).toBe(false)
  })

  it('composes the annex identity over the stores unchanged', async () => {
    const stores = transientSessionStores()
    const accountDid = 'did:webvh:example'
    await stores.epochPins.saveFromDescriptor({
      accountDid,
      epochId: 'epoch-0',
      descriptor: { epochs: [{ id: 'epoch-0' }] }
    })
    const handle = inMemorySessionPersistence({
      stores,
      clientAnnex: {
        clientAnnexDid: 'did:webvh:example:annex',
        invocationCapability: {} as IZcap
      }
    })
    // The annex identity is attached...
    expect(handle.clientAnnex.clientAnnexDid).toBe('did:webvh:example:annex')
    // ...and the stores carry through: a pin written before the session is
    // readable through the composed handle, and the writer id is the same.
    expect(await handle.epochPins.load({ accountDid })).toBe('epoch-0')
    expect(handle.getWriterId()).toBe(stores.getWriterId())
  })

  it('mints one writer id per handle, not per call', () => {
    const handle = transientSessionStores()
    const other = transientSessionStores()
    expect(handle.getWriterId()).toBe(handle.getWriterId())
    expect(handle.getWriterId()).not.toBe(other.getWriterId())
  })

  it('serves one descriptor/meta cache pair whatever scope asks', async () => {
    const handle = transientSessionStores()
    const cache = handle.descriptorCache({ scope: 'a' })
    expect(cache).toBeDefined()
    expect(handle.descriptorCache({ scope: 'b' })).toBe(cache)
    expect(handle.metaCache({ scope: 'a' })).toBe(
      handle.metaCache({ scope: 'b' })
    )
  })

  it('retains the login-seeded descriptor when no refresh overwrites it', async () => {
    const handle = transientSessionStores()
    const cache = handle.descriptorCache({ scope: 'space' })!
    const seeded = { currentEpoch: 'epoch-0', epochs: [] }
    await cache.writeDescriptor({
      collectionId: 'private-credentials',
      descriptor: seeded as never
    })
    // A failed mid-session refresh writes nothing, so the read falls back to
    // the snapshot login seeded.
    expect(
      await cache.readDescriptor({ collectionId: 'private-credentials' })
    ).toEqual(seeded)
  })

  it('keeps the roster-epoch pin forward-only within the visit', async () => {
    const handle = transientSessionStores()
    const accountDid = 'did:webvh:example'
    const descriptor = {
      epochs: [{ id: 'epoch-0' }, { id: 'epoch-1' }, { id: 'epoch-2' }]
    }
    await handle.epochPins.saveFromDescriptor({
      accountDid,
      epochId: 'epoch-1',
      descriptor
    })
    expect(await handle.epochPins.load({ accountDid })).toBe('epoch-1')
    // A write behind the pin along the served epoch order is dropped.
    await handle.epochPins.saveFromDescriptor({
      accountDid,
      epochId: 'epoch-0',
      descriptor
    })
    expect(await handle.epochPins.load({ accountDid })).toBe('epoch-1')
    // An epoch the descriptor cannot order against the pin is dropped too.
    await handle.epochPins.saveFromDescriptor({
      accountDid,
      epochId: 'unlisted',
      descriptor
    })
    expect(await handle.epochPins.load({ accountDid })).toBe('epoch-1')
    // A newer epoch advances it.
    await handle.epochPins.saveFromDescriptor({
      accountDid,
      epochId: 'epoch-2',
      descriptor
    })
    expect(await handle.epochPins.load({ accountDid })).toBe('epoch-2')
  })

  it('round-trips the unlock-methods cache in memory', async () => {
    const handle = transientSessionStores()
    const controller = 'did:key:controller'
    expect(await handle.unlockMethodsCache.load({ controller })).toBeNull()
    await handle.unlockMethodsCache.save({ controller, record: { v: 1 } })
    expect(await handle.unlockMethodsCache.load({ controller })).toEqual({
      v: 1
    })
    await handle.unlockMethodsCache.delete({ controller })
    expect(await handle.unlockMethodsCache.load({ controller })).toBeNull()
  })

  it('serves an empty passkey-notice store', async () => {
    const handle = transientSessionStores()
    const controller = 'did:key:controller'
    await handle.passkeyNotices.save({
      controller,
      backupEligibility: true,
      backupState: true
    })
    expect(await handle.passkeyNotices.load({ controller })).toBeNull()
  })
})

describe('the durable persistence handle', () => {
  it('is typed durable and memoizes one cache pair per scope', () => {
    const handle = browserLocalSessionPersistence()
    expect(isBrowserLocalSession(handle)).toBe(true)
    const cache = handle.descriptorCache({ scope: 'space-a' })
    expect(cache).toBeDefined()
    expect(handle.descriptorCache({ scope: 'space-a' })).toBe(cache)
    expect(handle.descriptorCache({ scope: 'space-b' })).not.toBe(cache)
  })

  it('serves in-memory caches for a guest (persistCaches: false)', async () => {
    const handle = browserLocalSessionPersistence({ persistCaches: false })
    const cache = handle.descriptorCache({ scope: 'space' })
    const descriptor = { currentEpoch: 'epoch-0', epochs: [] }
    await cache.writeDescriptor({
      collectionId: 'contacts',
      descriptor: descriptor as never
    })
    expect(await cache.readDescriptor({ collectionId: 'contacts' })).toEqual(
      descriptor
    )
    // The write reached no durable storage.
    expect(
      localStorage.getItem('freewallet:collection-encryption:space:contacts')
    ).toBeNull()
  })
})

describe('the durability refusals', () => {
  it('refuses a durable-subject ceremony from a transient session', () => {
    const transient = transientHandle()
    expect(() =>
      assertBrowserLocalSession({
        persistence: transient,
        ceremony: 'Update-key rotation'
      })
    ).toThrow(BrowserLocalSessionRequiredError)
    expect(() =>
      assertBrowserLocalSession({
        persistence: browserLocalSessionPersistence(),
        ceremony: 'Update-key rotation'
      })
    ).not.toThrow()
  })

  it('refuses an account ceremony outside a step-up', () => {
    const transient = transientHandle()
    expect(() =>
      assertAccountCeremonyAllowed({
        persistence: transient,
        ceremony: 'Deleting the account'
      })
    ).toThrow(StepUpRequiredError)
    expect(() =>
      assertAccountCeremonyAllowed({
        persistence: browserLocalSessionPersistence(),
        ceremony: 'Deleting the account'
      })
    ).not.toThrow()
  })
})
