// @vitest-environment node
import { describe, it, expect, vi } from 'vitest'
import { WASRemoteStore } from '../src/stores/storageManager'

describe('WASRemoteStore.listCollectionItems', () => {
  it('uses `items` from the list response format', async () => {
    const items = [{ id: 'abc', url: '/abc', contentType: 'application/json' }]
    const zcapClient = {
      request: vi.fn().mockResolvedValue({
        data: {
          id: 'collection-id',
          url: '/space/123/collection-id',
          name: 'Test Collection',
          type: ['Collection'],
          totalItems: 1,
          items
        }
      })
    }
    const store = new WASRemoteStore({
      storageServerUrl: 'https://example.test',
      zcapClient: zcapClient as any,
      spaceId: 'space-id',
      controller: 'did:key:test'
    })
    const fetchAllSpy = vi.spyOn(store, 'fetchAll').mockResolvedValue([])

    await store.listCollectionItems({ url: 'https://example.test/collection' })

    expect(fetchAllSpy).toHaveBeenCalledWith({ rows: items })
  })

  it('passes an empty `items` list through correctly', async () => {
    const items: any[] = []
    const zcapClient = {
      request: vi.fn().mockResolvedValue({
        data: {
          id: 'collection-id',
          url: '/space/123/collection-id',
          name: 'Test Collection',
          type: ['Collection'],
          totalItems: 0,
          items
        }
      })
    }
    const store = new WASRemoteStore({
      storageServerUrl: 'https://example.test',
      zcapClient: zcapClient as any,
      spaceId: 'space-id',
      controller: 'did:key:test'
    })
    const fetchAllSpy = vi.spyOn(store, 'fetchAll').mockResolvedValue([])

    await store.listCollectionItems({ url: 'https://example.test/collection' })

    expect(fetchAllSpy).toHaveBeenCalledWith({ rows: items })
  })
})
