/**
 * Tests for the share surface's two collection sets. The roster's `shareable`
 * flag is the allowlist a new share may name. It is narrower than the
 * encrypted set -- `app-connections` and `wallet-activity` carry key-epoch
 * rosters and are deliberately never shareable, since their rows are the
 * connected apps' private seeds and the account's grant history. The shares
 * listing (`listSharedCollections` in `src/session/shares.ts`) reads the whole
 * encrypted set instead, so a reader escrowed into a collection that is not
 * shareable stays visible and removable.
 */
import { describe, expect, it, vi } from 'vitest'
import {
  ENCRYPTED_STANDARD_COLLECTIONS,
  WALLET_STANDARD_COLLECTIONS
} from '@/app.config'
import { listSharedCollections } from '@/session/shares'
import type { Session } from '@/types/auth'

const ids = (collections: Array<{ id: string }>) =>
  collections.map(({ id }) => id)

const SHAREABLE = WALLET_STANDARD_COLLECTIONS.filter(
  ({ shareable }) => shareable
)

describe('the shareable flag', () => {
  it('admits exactly the wallet collections a new reader may join', () => {
    expect(ids(SHAREABLE).sort()).toEqual([
      'contacts',
      'contacts-history',
      'private-credentials'
    ])
  })

  it('excludes app-connections, which is encrypted all the same', () => {
    expect(ids(ENCRYPTED_STANDARD_COLLECTIONS)).toContain('app-connections')
    expect(ids(SHAREABLE)).not.toContain('app-connections')
  })

  it('excludes wallet-activity, whose rows carry the delegated zcaps', () => {
    expect(ids(ENCRYPTED_STANDARD_COLLECTIONS)).toContain('wallet-activity')
    expect(ids(SHAREABLE)).not.toContain('wallet-activity')
  })

  it('admits only encrypted collections (a share needs an epoch roster)', () => {
    for (const collection of SHAREABLE) {
      expect(collection.encryption).toEqual({ scheme: 'edv' })
    }
    // The plaintext collection is out for that reason rather than by name.
    const publicCredentials = WALLET_STANDARD_COLLECTIONS.find(
      ({ id }) => id === 'public-credentials'
    )
    expect(publicCredentials?.encryption).toBeUndefined()
    expect(publicCredentials?.shareable).toBe(false)
  })
})

describe('listSharedCollections', () => {
  it('lists the readers of every encrypted collection, shareable or not', async () => {
    const reader = { recipientId: 'did:key:z6LSreader#z6LSreader' }
    const listCollectionShares = vi.fn(
      async ({ collectionId }: { collectionId: string }) =>
        collectionId === 'wallet-activity' ? [reader] : []
    )
    const session = {
      storage: {
        listHistoryItems: vi.fn(async () => ({ entries: [], unreadable: 0 })),
        listCollectionShares
      }
    } as unknown as Session

    const listing = await listSharedCollections({ session })

    expect(Object.keys(listing).sort()).toEqual(
      ids(ENCRYPTED_STANDARD_COLLECTIONS).sort()
    )
    // A reader escrowed before the collection stopped being shareable.
    expect(listing['wallet-activity']).toEqual([reader])
  })
})
