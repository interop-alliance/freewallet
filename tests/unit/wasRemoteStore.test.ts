// @vitest-environment node
import { describe, it, expect, vi } from 'vitest'
import type { ZcapClient } from '@interop/ezcap'
import type { WasClient } from '@interop/was-client'
import {
  WASRemoteStore,
  type SessionCapabilities
} from '../../src/stores/wasRemoteStore'
import { bufferToBase64Url, digestHash } from '../../src/lib/cidFrom'
import type { ControllerProfile, User } from '../../src/types/auth'

/**
 * Builds a WASRemoteStore whose `was` client has been replaced with a stub, so
 * tests exercise the store's handle navigation without real network/ezcap I/O.
 * Passing `sessionCapabilities` puts the store in the delegated tier (it
 * attaches those capabilities rather than invoking root capabilities).
 */
function storeWithStubbedClient(
  was: unknown,
  sessionCapabilities?: SessionCapabilities
): WASRemoteStore {
  const store = new WASRemoteStore({
    storageServerUrl: 'https://example.test',
    zcapClient: { request: vi.fn() } as unknown as ZcapClient,
    spaceId: 'space-id',
    controller: 'did:key:test',
    sessionCapabilities
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

  it('forces the plaintext override so a marked collection returns its raw envelope', async () => {
    // The store's WasClient is built with a fail-closed encryption provider, so
    // the storage browser must read encryption-marked resources as plaintext:
    // the raw EDV envelope, not a decoded body it cannot key for.
    const envelope = { id: 'z6Env1', jwe: { ciphertext: 'x' } }
    const get = vi.fn().mockResolvedValue(envelope)
    const resource = vi.fn().mockReturnValue({ get })
    const collection = vi.fn().mockReturnValue({ resource })
    const store = storeWithStubbedClient({
      space: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.fetchCollectionResource({
        id: 'z6Env1',
        url: '/space/space-id/private-credentials/z6Env1'
      })
    ).resolves.toEqual({ kind: 'json', data: envelope })
    expect(resource).toHaveBeenCalledWith('z6Env1', { encryption: 'plaintext' })
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

/**
 * A delegated-tier capability set: a Space-read zcap plus a read/write zcap on
 * the `private-credentials` collection.
 */
const SESSION_CAPABILITIES = {
  spaceRead: { id: 'urn:zcap:space-read' },
  collections: {
    'private-credentials': { id: 'urn:zcap:private-credentials' }
  }
} as unknown as SessionCapabilities

describe('WASRemoteStore.listSyncedResources', () => {
  it('lists resource ids/urls of a standard collection (id-addressed)', async () => {
    const items = [
      { id: 'z6Env1', url: '/space/space-id/private-credentials/z6Env1' },
      { id: 'z6Env2', url: '/space/space-id/private-credentials/z6Env2' }
    ]
    const list = vi.fn().mockResolvedValue({ totalItems: 2, items })
    const collection = vi.fn().mockReturnValue({ list })
    const space = vi.fn().mockReturnValue({ collection })
    const store = storeWithStubbedClient({ space })

    await expect(
      store.listSyncedResources({ logicalKey: 'privateCredentials' })
    ).resolves.toEqual(items)
    // Full tier: no capability attached to the space handle.
    expect(space).toHaveBeenCalledWith('space-id', {})
    expect(collection).toHaveBeenCalledWith('private-credentials')
  })

  it('attaches the space-read capability in the delegated tier', async () => {
    const list = vi.fn().mockResolvedValue({ totalItems: 0, items: [] })
    const collection = vi.fn().mockReturnValue({ list })
    const space = vi.fn().mockReturnValue({ collection })
    const store = storeWithStubbedClient({ space }, SESSION_CAPABILITIES)

    await store.listSyncedResources({ logicalKey: 'privateCredentials' })
    expect(space).toHaveBeenCalledWith('space-id', {
      capability: SESSION_CAPABILITIES.spaceRead
    })
  })
})

describe('WASRemoteStore.getSyncedResource', () => {
  it('reads the raw stored body via a root GET in the full tier', async () => {
    const envelope = { id: 'z6Env1', sequence: 0, jwe: { ciphertext: 'x' } }
    const request = vi.fn().mockResolvedValue({ data: envelope })
    const store = storeWithStubbedClient({ request })

    await expect(
      store.getSyncedResource({
        logicalKey: 'privateCredentials',
        resourceId: 'z6Env1'
      })
    ).resolves.toEqual(envelope)
    expect(request).toHaveBeenCalledWith({
      capability: undefined,
      path: '/space/space-id/private-credentials/z6Env1',
      method: 'GET'
    })
  })

  it('attaches the space-read capability in the delegated tier', async () => {
    const request = vi.fn().mockResolvedValue({ data: {} })
    const store = storeWithStubbedClient({ request }, SESSION_CAPABILITIES)

    await store.getSyncedResource({
      logicalKey: 'privateCredentials',
      resourceId: 'z6Env1'
    })
    expect(request).toHaveBeenCalledWith(
      expect.objectContaining({ capability: SESSION_CAPABILITIES.spaceRead })
    )
  })

  it('returns undefined on a 404', async () => {
    const request = vi.fn().mockRejectedValue({ status: 404 })
    const store = storeWithStubbedClient({ request })

    await expect(
      store.getSyncedResource({
        logicalKey: 'privateCredentials',
        resourceId: 'missing'
      })
    ).resolves.toBeUndefined()
  })
})

describe('WASRemoteStore.putSyncedResource', () => {
  it('creates the raw envelope with If-None-Match: * (full tier)', async () => {
    const envelope = { id: 'z6Env1', sequence: 0, jwe: { ciphertext: 'x' } }
    const request = vi.fn().mockResolvedValue({})
    const store = storeWithStubbedClient({ request })

    await expect(
      store.putSyncedResource({
        logicalKey: 'privateCredentials',
        resourceId: 'z6Env1',
        body: envelope
      })
    ).resolves.toEqual({ created: true })
    expect(request).toHaveBeenCalledWith({
      capability: undefined,
      path: '/space/space-id/private-credentials/z6Env1',
      method: 'PUT',
      json: envelope,
      headers: { 'if-none-match': '*' }
    })
  })

  it('attaches the collection read/write capability in the delegated tier', async () => {
    const request = vi.fn().mockResolvedValue({})
    const store = storeWithStubbedClient({ request }, SESSION_CAPABILITIES)

    await store.putSyncedResource({
      logicalKey: 'privateCredentials',
      resourceId: 'z6Env1',
      body: { jwe: {} }
    })
    expect(request).toHaveBeenCalledWith(
      expect.objectContaining({
        capability: SESSION_CAPABILITIES.collections['private-credentials']
      })
    )
  })

  it('tolerates a 412 as an already-existing row (created: false)', async () => {
    const request = vi.fn().mockRejectedValue({ status: 412 })
    const store = storeWithStubbedClient({ request })

    await expect(
      store.putSyncedResource({
        logicalKey: 'privateCredentials',
        resourceId: 'z6Env1',
        body: { jwe: {} }
      })
    ).resolves.toEqual({ created: false })
  })

  it('propagates a non-412 write error', async () => {
    const request = vi.fn().mockRejectedValue({ status: 500 })
    const store = storeWithStubbedClient({ request })

    await expect(
      store.putSyncedResource({
        logicalKey: 'privateCredentials',
        resourceId: 'z6Env1',
        body: { jwe: {} }
      })
    ).rejects.toEqual({ status: 500 })
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
