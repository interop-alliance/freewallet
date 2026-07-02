// @vitest-environment node
import { describe, it, expect, vi } from 'vitest'
import type { ZcapClient } from '@interop/ezcap'
import type { WasClient } from '@interop/was-client'
import { WASRemoteStore } from '../../src/stores/wasRemoteStore'
import { bufferToBase64Url, digestHash } from '../../src/lib/cidFrom'
import type { ControllerProfile, User } from '../../src/types/auth'

/**
 * Builds a WASRemoteStore whose `was` client has been replaced with a stub, so
 * tests exercise the store's handle navigation without real network/ezcap I/O.
 */
function storeWithStubbedClient(was: unknown): WASRemoteStore {
  const store = new WASRemoteStore({
    storageServerUrl: 'https://example.test',
    zcapClient: { request: vi.fn() } as unknown as ZcapClient,
    spaceId: 'space-id',
    controller: 'did:key:test'
  })
  store.was = was as WasClient
  return store
}

describe('WASRemoteStore.listCollections', () => {
  it('returns collections with isPublic from collection.isPublic()', async () => {
    const items = [
      { id: 'private-credentials', url: '/space/space-id/private-credentials' }
    ]
    const collections = vi.fn().mockResolvedValue({
      url: '/space/space-id/collections/',
      totalItems: 1,
      items
    })
    const isPublic = vi.fn().mockResolvedValue(false)
    const collection = vi.fn().mockReturnValue({ isPublic })
    const store = storeWithStubbedClient({
      space: vi.fn().mockReturnValue({ collections, collection })
    })

    await expect(store.listCollections()).resolves.toEqual([
      { ...items[0], isPublic: false }
    ])
    expect(collections).toHaveBeenCalledOnce()
    expect(collection).toHaveBeenCalledWith('private-credentials')
    expect(isPublic).toHaveBeenCalledOnce()
  })

  it('returns an empty array when the space is missing', async () => {
    const store = storeWithStubbedClient({
      space: vi.fn().mockReturnValue({
        collections: vi.fn().mockResolvedValue(null)
      })
    })

    await expect(store.listCollections()).resolves.toEqual([])
  })
})

describe('WASRemoteStore.listCollectionResources', () => {
  it('returns listed resources without isPublic for private collections', async () => {
    const items = [
      {
        id: 'credential.json',
        url: '/space/space-id/private-credentials/credential.json',
        contentType: 'application/json',
        modified: '2026-05-01T00:00:00.000Z'
      }
    ]
    const list = vi.fn().mockResolvedValue({
      id: 'private-credentials',
      url: '/space/space-id/private-credentials',
      totalItems: 1,
      items
    })
    const collectionIsPublic = vi.fn().mockResolvedValue(false)
    const collection = vi
      .fn()
      .mockReturnValue({ list, isPublic: collectionIsPublic })
    const space = vi.fn().mockReturnValue({ collection })
    const store = storeWithStubbedClient({ space })

    await expect(
      store.listCollectionResources({
        collectionUrl: '/space/space-id/private-credentials'
      })
    ).resolves.toEqual(items)
    expect(space).toHaveBeenCalledWith('space-id', {})
    expect(collection).toHaveBeenCalledWith('private-credentials')
    expect(collectionIsPublic).toHaveBeenCalledOnce()
  })

  it('marks all resources public when the collection is public', async () => {
    const items = [
      {
        id: 'shared.json',
        url: '/space/space-id/public-credentials/shared.json'
      }
    ]
    const list = vi.fn().mockResolvedValue({ totalItems: 1, items })
    const collectionIsPublic = vi.fn().mockResolvedValue(true)
    const collection = vi
      .fn()
      .mockReturnValue({ list, isPublic: collectionIsPublic })
    const space = vi.fn().mockReturnValue({ collection })
    const store = storeWithStubbedClient({ space })

    await expect(
      store.listCollectionResources({
        collectionUrl: '/space/space-id/public-credentials'
      })
    ).resolves.toEqual([{ ...items[0], isPublic: true }])
    expect(collectionIsPublic).toHaveBeenCalledOnce()
  })
})

describe('WASRemoteStore.fetchCollectionResource', () => {
  it('returns parsed JSON for an object body', async () => {
    const get = vi.fn().mockResolvedValue({ hello: 'world' })
    const resource = vi.fn().mockReturnValue({ get })
    const collection = vi.fn().mockReturnValue({ resource })
    const store = storeWithStubbedClient({
      space: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.fetchCollectionResource({
        id: 'doc',
        url: '/space/space-id/notes/doc'
      })
    ).resolves.toEqual({ kind: 'json', data: { hello: 'world' } })
  })

  it('returns binary for a non-text blob body', async () => {
    const blob = new Blob([new Uint8Array([1, 2, 3])], {
      type: 'image/png'
    })
    const get = vi.fn().mockResolvedValue(blob)
    const store = storeWithStubbedClient({
      space: vi.fn().mockReturnValue({
        collection: vi.fn().mockReturnValue({
          resource: vi.fn().mockReturnValue({ get })
        })
      })
    })

    const result = await store.fetchCollectionResource({
      id: 'logo.png',
      url: '/space/space-id/files/logo.png'
    })
    expect(result.kind).toBe('binary')
    if (result.kind === 'binary') {
      expect(result.contentType).toBe('image/png')
    }
  })
})

describe('WASRemoteStore.initClient', () => {
  it('uses signer DID as controller and space-id seed', async () => {
    const controller = 'did:key:z6MktestControllerDid'
    const { remoteStore } = await WASRemoteStore.initClient({
      storageServerUrl: 'https://example.test',
      user: { id: 'user-id-that-is-not-controller' } as unknown as User,
      profile: {
        keyAgent: { id: controller },
        zcapClient: { request: vi.fn() }
      } as unknown as ControllerProfile
    })

    const expectedSpaceId = bufferToBase64Url(await digestHash(controller))
    expect(remoteStore.controller).toBe(controller)
    expect(remoteStore.spaceId).toBe(expectedSpaceId)
  })
})

describe('WASRemoteStore.ensureUserCollections', () => {
  it('throws if space creation fails', async () => {
    const store = storeWithStubbedClient({
      space: vi.fn().mockReturnValue({
        configure: vi.fn().mockRejectedValue(new Error('boom'))
      })
    })

    await expect(
      store.ensureUserCollections({
        user: { id: 'user-id', email: 'user@example.test' } as unknown as User
      })
    ).rejects.toThrow(/Error creating space/)
  })
})
