/**
 * Tests for the Storage page's collection grouping: known wallet collections
 * split into the Wallet Contents and Wallet System groups in declaration
 * order, everything unrecognized lands in Application Collections sorted by
 * display name.
 */
import { describe, expect, it } from 'vitest'
import { groupCollections } from '@/components/storage/displayUtils'
import type { StorageCollection } from '@/lib/storage'

function collection(id: string, name?: string): StorageCollection {
  return { id, name: name ?? id, url: `https://example.com/space/x/${id}` }
}

describe('groupCollections', () => {
  it('splits known wallet collections from application collections', () => {
    const { contents, app, system } = groupCollections({
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
        collection('private-credentials', 'Verifiable Credentials')
      ]
    })

    expect(contents.map(({ id }) => id)).toEqual([
      'private-credentials',
      'public-credentials'
    ])
    expect(system.map(({ id }) => id)).toEqual([
      'wallet-activity',
      'id',
      'unlock-methods'
    ])
    // Application collections sort by display name.
    expect(app.map(({ id }) => id)).toEqual(['alpha-app-data', 'zulu-app-data'])
  })

  it('returns empty groups for collections that are not present', () => {
    const { contents, app, system } = groupCollections({
      collections: [collection('private-credentials')]
    })
    expect(contents.map(({ id }) => id)).toEqual(['private-credentials'])
    expect(app).toEqual([])
    expect(system).toEqual([])
  })
})
