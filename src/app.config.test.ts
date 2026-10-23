/**
 * Unit tests for the roster projections in the app config: the standard and
 * system collection lists carry the roster spec fields verbatim.
 */
import { describe, it, expect } from 'vitest'
import {
  WALLET_SPACE_SYNCED_SPECS,
  WALLET_SPACE_SYSTEM_SPECS
} from '@interop/wallet-core/space'
import {
  ENCRYPTED_WALLET_COLLECTION_IDS,
  isProtectedCollection,
  SYSTEM_COLLECTIONS,
  WALLET_STANDARD_COLLECTIONS
} from './app.config'

describe('roster projections', () => {
  it('projects grantable verbatim onto the standard collections', () => {
    expect(
      WALLET_STANDARD_COLLECTIONS.map(({ id, grantable }) => [id, grantable])
    ).toEqual(
      WALLET_SPACE_SYNCED_SPECS.map(spec => [spec.collectionId, spec.grantable])
    )
  })

  it('reads a boolean grantable off every installed roster entry', () => {
    // Guards the installed dist: a wallet-core release whose roster carried
    // no `grantable` would project `undefined` on both sides, pass the
    // verbatim checks, and refuse every standard collection at runtime.
    for (const { id, grantable } of WALLET_STANDARD_COLLECTIONS) {
      expect(typeof grantable, id).toBe('boolean')
    }
    expect(
      WALLET_STANDARD_COLLECTIONS.find(({ id }) => id === 'private-credentials')
        ?.grantable
    ).toBe(true)
  })

  it('projects grantable verbatim onto the system collections', () => {
    expect(
      SYSTEM_COLLECTIONS.map(({ id, grantable }) => [id, grantable])
    ).toEqual(
      WALLET_SPACE_SYSTEM_SPECS.map(spec => [spec.collectionId, spec.grantable])
    )
  })
})

describe('the roster-wide collection sets', () => {
  it('names the connections directory among the encrypted collections', () => {
    expect([...ENCRYPTED_WALLET_COLLECTION_IDS].sort()).toEqual([
      'app-keys',
      'connections',
      'contacts',
      'contacts-history',
      'private-credentials',
      'wallet-activity'
    ])
  })

  it('protects every roster collection, the connections directory included', () => {
    for (const id of [
      'connections',
      'private-credentials',
      'app-keys',
      'key-map',
      'id'
    ]) {
      expect(isProtectedCollection(id), id).toBe(true)
    }
    expect(isProtectedCollection('app-notes')).toBe(false)
    expect(isProtectedCollection(undefined)).toBe(false)
  })

  it('keeps the synced sets synced-only', () => {
    expect(WALLET_STANDARD_COLLECTIONS.map(({ id }) => id)).not.toContain(
      'connections'
    )
  })
})
