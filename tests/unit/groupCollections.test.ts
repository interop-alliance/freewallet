/**
 * Tests for the Storage page's collection grouping: known wallet collections
 * split into the Wallet Contents and Wallet System groups, everything
 * unrecognized lands in Application Collections; every group is sorted
 * alphabetically by display name.
 */
import type { TFunction } from 'i18next'
import { describe, expect, it } from 'vitest'
import {
  getCollectionDisplayName,
  groupCollections
} from '@/components/storage/displayUtils'
import type { StorageCollection } from '@/lib/storage'

function collection(id: string, name?: string): StorageCollection {
  return { id, name: name ?? id, url: `https://example.com/space/x/${id}` }
}

// A stand-in translator that resolves every key to its untranslated
// defaultValue -- the canonical wallet collection names.
const t = ((key: string, options?: { defaultValue?: string }) =>
  options?.defaultValue ?? key) as TFunction

describe('groupCollections', () => {
  it('splits known wallet collections from application collections', () => {
    const { contents, app, system } = groupCollections({
      t,
      collections: [
        collection('wallet-activity', 'Wallet Activity Log'),
        collection('zulu-app-data'),
        collection(
          'public-credentials',
          'Publicly Shared Verifiable Credentials'
        ),
        collection('unlock-methods', 'Unlock Methods'),
        collection('alpha-app-data'),
        collection('id', 'Identity'),
        collection('key-map', 'Key Map'),
        collection('private-credentials', 'Verifiable Credentials'),
        collection('contacts', 'Contacts'),
        collection('contacts-history', 'Contacts History')
      ]
    })

    // Sorted by display name: Contacts, then the two credential collections.
    expect(contents.map(({ id }) => id)).toEqual([
      'contacts',
      'private-credentials',
      'public-credentials'
    ])
    // Sorted by display name: Contacts History, Identity, Key Map, Unlock
    // Methods, Wallet Activity Log.
    expect(system.map(({ id }) => id)).toEqual([
      'contacts-history',
      'id',
      'key-map',
      'unlock-methods',
      'wallet-activity'
    ])
    // Application collections sort by display name.
    expect(app.map(({ id }) => id)).toEqual(['alpha-app-data', 'zulu-app-data'])
  })

  it('prefers the canonical name for wallet collections over the stored one', () => {
    // A pre-rename space still stores the old provisioning-time name.
    expect(
      getCollectionDisplayName(
        collection(
          'public-credentials',
          'Publicly Shared Verifiable Credentials'
        ),
        t
      )
    ).toEqual('Verifiable Credentials (Publicly Shared)')
    expect(
      getCollectionDisplayName(collection('some-app-data', 'App Data'), t)
    ).toEqual('App Data')
  })

  it('returns empty groups for collections that are not present', () => {
    const { contents, app, system } = groupCollections({
      t,
      collections: [collection('private-credentials')]
    })
    expect(contents.map(({ id }) => id)).toEqual(['private-credentials'])
    expect(app).toEqual([])
    expect(system).toEqual([])
  })
})
