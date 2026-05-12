// @vitest-environment node
import { describe, it, expect, vi } from 'vitest'
import { WASRemoteStore } from '../src/stores/storageManager'
import { bufferToBase64Url, digestHash } from '../src/lib/cidFrom'

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

describe('WASRemoteStore.listCollections', () => {
  it('loads collection refs from the space collections endpoint', async () => {
    const items = [
      {
        id: 'private-credentials',
        url: '/space/space-id/private-credentials'
      }
    ]
    const zcapClient = {
      request: vi.fn().mockResolvedValue({
        data: {
          url: '/space/space-id/collections/',
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

    await expect(store.listCollections()).resolves.toEqual(items)
    expect(zcapClient.request).toHaveBeenCalledWith({
      url: 'https://example.test/space/space-id/collections/',
      method: 'GET',
      headers: {
        accept: 'application/json'
      }
    })
  })
})

describe('WASRemoteStore.initClient', () => {
  it('uses signer DID as controller and space-id seed', async () => {
    const controller = 'did:key:z6MktestControllerDid'
    const { remoteStore } = await WASRemoteStore.initClient({
      storageServerUrl: 'https://example.test',
      user: { id: 'user-id-that-is-not-controller' } as any,
      profile: {
        keyAgent: { id: controller },
        zcapClient: { request: vi.fn() }
      } as any
    })

    const expectedSpaceId = bufferToBase64Url(await digestHash(controller))
    expect(remoteStore.controller).toBe(controller)
    expect(remoteStore.spaceId).toBe(expectedSpaceId)
  })
})

describe('WASRemoteStore.ensureUserCollections', () => {
  it('throws if space creation fails', async () => {
    const zcapClient = {
      request: vi.fn().mockRejectedValue({ data: { errors: [{ detail: 'boom' }] } })
    }
    const store = new WASRemoteStore({
      storageServerUrl: 'https://example.test',
      zcapClient: zcapClient as any,
      spaceId: 'space-id',
      controller: 'did:key:test'
    })

    await expect(
      store.ensureUserCollections({
        user: { id: 'user-id', email: 'user@example.test' } as any
      })
    ).rejects.toThrow(/Error creating space/)
  })
})
