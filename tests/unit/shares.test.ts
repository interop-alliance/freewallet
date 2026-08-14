/**
 * Tests for the share surface's allowlist (`SHAREABLE_COLLECTIONS` in
 * `src/session/shares.ts`): which of the wallet's own collections may be
 * offered to a reader, straight off the collection roster's `shareable` flag.
 * The one property worth pinning is that the allowlist is narrower than the
 * encrypted set -- `app-connections` carries a key-epoch roster and is
 * deliberately never shareable, since its rows are the connected apps' private
 * seeds.
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
      'private-credentials',
      'wallet-activity'
    ])
  })

  it('excludes app-connections, which is encrypted all the same', () => {
    const ids = (collections: Array<{ id: string }>) =>
      collections.map(({ id }) => id)
    expect(ids(ENCRYPTED_STANDARD_COLLECTIONS)).toContain('app-connections')
    expect(ids(SHAREABLE_COLLECTIONS)).not.toContain('app-connections')
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
