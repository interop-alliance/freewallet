/**
 * Tests for the share surface's allowlist (`SHAREABLE_COLLECTIONS` in
 * `src/session/shares.ts`): which of the wallet's own collections may be
 * offered to a reader, straight off the collection roster's `shareable` flag.
 * The one property worth pinning is that the allowlist is narrower than the
 * encrypted set -- `app-connections` and `wallet-activity` carry key-epoch
 * rosters and are deliberately never shareable, since their rows are the
 * connected apps' private seeds and the account's grant history.
 */
import { describe, expect, it } from 'vitest'
import {
  ENCRYPTED_STANDARD_COLLECTIONS,
  WALLET_STANDARD_COLLECTIONS
} from '@/app.config'
import { SHAREABLE_COLLECTIONS } from '@/session/shares'

describe('SHAREABLE_COLLECTIONS', () => {
  it('is exactly the wallet collections a reader may be escrowed into', () => {
    expect(SHAREABLE_COLLECTIONS.map(({ id }) => id).sort()).toEqual([
      'contacts',
      'contacts-history',
      'private-credentials'
    ])
  })

  it('excludes app-connections, which is encrypted all the same', () => {
    const ids = (collections: Array<{ id: string }>) =>
      collections.map(({ id }) => id)
    expect(ids(ENCRYPTED_STANDARD_COLLECTIONS)).toContain('app-connections')
    expect(ids(SHAREABLE_COLLECTIONS)).not.toContain('app-connections')
  })

  it('excludes wallet-activity, whose rows carry the delegated zcaps', () => {
    const ids = (collections: Array<{ id: string }>) =>
      collections.map(({ id }) => id)
    expect(ids(ENCRYPTED_STANDARD_COLLECTIONS)).toContain('wallet-activity')
    expect(ids(SHAREABLE_COLLECTIONS)).not.toContain('wallet-activity')
  })

  it('admits only encrypted collections (a share needs an epoch roster)', () => {
    for (const collection of SHAREABLE_COLLECTIONS) {
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
