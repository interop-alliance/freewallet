/**
 * Coverage for the transient roster-epoch pin (`transientSessionStores()`'s
 * `epochPins` member) against the shared `epochPinWriteAllowed` predicate it
 * shares with the durable variant (`saveUserKeyEpochPin` in
 * `src/lib/sessionKey.ts`). FW-261: a served descriptor that omits the
 * pinned epoch must be refused as a rollback, matching the durable twin,
 * rather than adopted because the stored pin cannot be located in the
 * served order.
 */
import { describe, expect, it } from 'vitest'
import { epochPinWriteAllowed } from '@/lib/sessionKey'
import { transientSessionStores } from '@/session/persistence'

const ACCOUNT_DID = 'did:webvh:example:account'

function descriptorWithEpochIds(epochIds: string[]): {
  epochs: Array<{ id: string }>
} {
  return { epochs: epochIds.map(id => ({ id })) }
}

describe('transientSessionStores epochPins.saveFromDescriptor', () => {
  it('adopts a first pin when nothing is stored yet', async () => {
    const stores = transientSessionStores()
    await stores.epochPins.saveFromDescriptor({
      accountDid: ACCOUNT_DID,
      epochId: 'epoch-1',
      descriptor: descriptorWithEpochIds(['epoch-1'])
    })
    expect(await stores.epochPins.load({ accountDid: ACCOUNT_DID })).toBe(
      'epoch-1'
    )
  })

  it('leaves the pin unchanged when restating the stored value', async () => {
    const stores = transientSessionStores()
    await stores.epochPins.saveFromDescriptor({
      accountDid: ACCOUNT_DID,
      epochId: 'epoch-1',
      descriptor: descriptorWithEpochIds(['epoch-1', 'epoch-2'])
    })
    await stores.epochPins.saveFromDescriptor({
      accountDid: ACCOUNT_DID,
      epochId: 'epoch-1',
      descriptor: descriptorWithEpochIds(['epoch-1', 'epoch-2'])
    })
    expect(await stores.epochPins.load({ accountDid: ACCOUNT_DID })).toBe(
      'epoch-1'
    )
  })

  it('adopts a forward advance along the served epoch order', async () => {
    const stores = transientSessionStores()
    await stores.epochPins.saveFromDescriptor({
      accountDid: ACCOUNT_DID,
      epochId: 'epoch-1',
      descriptor: descriptorWithEpochIds(['epoch-1', 'epoch-2'])
    })
    await stores.epochPins.saveFromDescriptor({
      accountDid: ACCOUNT_DID,
      epochId: 'epoch-2',
      descriptor: descriptorWithEpochIds(['epoch-1', 'epoch-2'])
    })
    expect(await stores.epochPins.load({ accountDid: ACCOUNT_DID })).toBe(
      'epoch-2'
    )
  })

  it('refuses a backward move along the served epoch order', async () => {
    const stores = transientSessionStores()
    await stores.epochPins.saveFromDescriptor({
      accountDid: ACCOUNT_DID,
      epochId: 'epoch-2',
      descriptor: descriptorWithEpochIds(['epoch-1', 'epoch-2'])
    })
    await stores.epochPins.saveFromDescriptor({
      accountDid: ACCOUNT_DID,
      epochId: 'epoch-1',
      descriptor: descriptorWithEpochIds(['epoch-1', 'epoch-2'])
    })
    expect(await stores.epochPins.load({ accountDid: ACCOUNT_DID })).toBe(
      'epoch-2'
    )
  })

  it('refuses a descriptor that omits the pinned epoch (FW-261)', async () => {
    const stores = transientSessionStores()
    await stores.epochPins.saveFromDescriptor({
      accountDid: ACCOUNT_DID,
      epochId: 'epoch-2',
      descriptor: descriptorWithEpochIds(['epoch-1', 'epoch-2'])
    })
    // A hostile or lagging host serves a descriptor whose epoch order
    // no longer lists the pinned epoch at all: it must not be treated
    // as a fresh start just because the stored pin cannot be located.
    await stores.epochPins.saveFromDescriptor({
      accountDid: ACCOUNT_DID,
      epochId: 'epoch-1',
      descriptor: descriptorWithEpochIds(['epoch-1'])
    })
    expect(await stores.epochPins.load({ accountDid: ACCOUNT_DID })).toBe(
      'epoch-2'
    )
  })
})

describe('epochPinWriteAllowed', () => {
  it('allows establishing a first pin', () => {
    expect(
      epochPinWriteAllowed({ stored: null, epochId: 'epoch-1', epochIds: [] })
    ).toBe(true)
  })

  it('allows restating the stored pin', () => {
    expect(
      epochPinWriteAllowed({
        stored: 'epoch-1',
        epochId: 'epoch-1',
        epochIds: []
      })
    ).toBe(true)
  })

  it('refuses a differing write with an empty served epoch order', () => {
    expect(
      epochPinWriteAllowed({
        stored: 'epoch-1',
        epochId: 'epoch-2',
        epochIds: []
      })
    ).toBe(false)
  })

  it('refuses a write when the stored pin is absent from the served order', () => {
    expect(
      epochPinWriteAllowed({
        stored: 'epoch-2',
        epochId: 'epoch-1',
        epochIds: ['epoch-1']
      })
    ).toBe(false)
  })

  it('refuses a write when the new epoch is absent from the served order', () => {
    expect(
      epochPinWriteAllowed({
        stored: 'epoch-1',
        epochId: 'epoch-2',
        epochIds: ['epoch-1']
      })
    ).toBe(false)
  })

  it('allows a forward advance along the served order', () => {
    expect(
      epochPinWriteAllowed({
        stored: 'epoch-1',
        epochId: 'epoch-2',
        epochIds: ['epoch-1', 'epoch-2']
      })
    ).toBe(true)
  })

  it('refuses a backward move along the served order', () => {
    expect(
      epochPinWriteAllowed({
        stored: 'epoch-2',
        epochId: 'epoch-1',
        epochIds: ['epoch-1', 'epoch-2']
      })
    ).toBe(false)
  })
})
