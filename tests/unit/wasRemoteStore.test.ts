// @vitest-environment node
import { describe, it, expect, vi } from 'vitest'
import type { ZcapClient } from '@interop/ezcap'
import type { WasClient } from '@interop/was-client'
import { mintSpaceId, WASRemoteStore } from '../../src/stores/wasRemoteStore'
import { deriveSpaceId } from '@interop/was-client/sync'
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
  it('uses the inline public flag without probing isPublic()', async () => {
    const items = [
      {
        id: 'private-credentials',
        url: '/space/space-id/private-credentials',
        public: false
      },
      {
        id: 'public-credentials',
        url: '/space/space-id/public-credentials',
        public: true
      }
    ]
    const collections = vi.fn().mockResolvedValue({
      url: '/space/space-id/collections/',
      totalItems: 2,
      items
    })
    const isPublic = vi.fn().mockResolvedValue(false)
    const describeCollection = vi.fn().mockResolvedValue({})
    const collection = vi
      .fn()
      .mockReturnValue({ isPublic, describe: describeCollection })
    const store = storeWithStubbedClient({
      space: vi.fn().mockReturnValue({ collections, collection })
    })

    await expect(store.listCollections()).resolves.toEqual([
      { ...items[0], isPublic: false, isEncrypted: false },
      { ...items[1], isPublic: true, isEncrypted: false }
    ])
    expect(isPublic).not.toHaveBeenCalled()
    expect(describeCollection).toHaveBeenCalledTimes(2)
  })

  it('falls back to probing isPublic() when the listing omits the flag', async () => {
    const items = [
      { id: 'private-credentials', url: '/space/space-id/private-credentials' }
    ]
    const collections = vi.fn().mockResolvedValue({
      url: '/space/space-id/collections/',
      totalItems: 1,
      items
    })
    const isPublic = vi.fn().mockResolvedValue(false)
    const describeCollection = vi.fn().mockResolvedValue({})
    const collection = vi
      .fn()
      .mockReturnValue({ isPublic, describe: describeCollection })
    const store = storeWithStubbedClient({
      space: vi.fn().mockReturnValue({ collections, collection })
    })

    await expect(store.listCollections()).resolves.toEqual([
      { ...items[0], isPublic: false, isEncrypted: false }
    ])
    expect(collections).toHaveBeenCalledOnce()
    expect(collection).toHaveBeenCalledWith('private-credentials')
    expect(isPublic).toHaveBeenCalledOnce()
    expect(describeCollection).toHaveBeenCalledOnce()
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

describe('WASRemoteStore.listCollectionPublicStates', () => {
  it('answers from the inline public flag with no describe() reads', async () => {
    const items = [
      {
        id: 'private-credentials',
        url: '/space/space-id/private-credentials',
        public: false
      },
      {
        id: 'example-app-public',
        url: '/space/space-id/example-app-public',
        public: true
      }
    ]
    const collections = vi.fn().mockResolvedValue({ totalItems: 2, items })
    const isPublic = vi.fn().mockResolvedValue(false)
    const describeCollection = vi.fn().mockResolvedValue({})
    const collection = vi
      .fn()
      .mockReturnValue({ isPublic, describe: describeCollection })
    const store = storeWithStubbedClient({
      space: vi.fn().mockReturnValue({ collections, collection })
    })

    await expect(store.listCollectionPublicStates()).resolves.toEqual([
      { id: 'private-credentials', isPublic: false },
      { id: 'example-app-public', isPublic: true }
    ])
    // The lean listing is one GET on a current server: no policy probes and,
    // unlike listCollections, no per-collection description reads.
    expect(isPublic).not.toHaveBeenCalled()
    expect(describeCollection).not.toHaveBeenCalled()
  })

  it('probes isPublic() only when the listing omits the flag', async () => {
    const items = [
      { id: 'legacy-collection', url: '/space/space-id/legacy-collection' }
    ]
    const collections = vi.fn().mockResolvedValue({ totalItems: 1, items })
    const isPublic = vi.fn().mockResolvedValue(true)
    const describeCollection = vi.fn().mockResolvedValue({})
    const collection = vi
      .fn()
      .mockReturnValue({ isPublic, describe: describeCollection })
    const store = storeWithStubbedClient({
      space: vi.fn().mockReturnValue({ collections, collection })
    })

    await expect(store.listCollectionPublicStates()).resolves.toEqual([
      { id: 'legacy-collection', isPublic: true }
    ])
    expect(isPublic).toHaveBeenCalledOnce()
    expect(describeCollection).not.toHaveBeenCalled()
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
    expect(space).toHaveBeenCalledWith('space-id', { capability: undefined })
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

describe('WASRemoteStore.collectionMeta', () => {
  /**
   * A stubbed `was` client whose collection handle answers `meta()` with the
   * given value (or rejects with the given error), plus the `collection` spy so
   * a test can assert the plaintext-override handle it was opened with.
   *
   * @param options {object}
   * @param [options.meta] {unknown}   what `meta()` resolves to
   * @param [options.error] {unknown}  what `meta()` rejects with instead
   * @returns {object}   the store plus the `collection` spy
   */
  function storeWithMeta({
    meta,
    error
  }: {
    meta?: unknown
    error?: unknown
  }): { store: WASRemoteStore; collection: ReturnType<typeof vi.fn> } {
    const metaFn = error
      ? vi.fn().mockRejectedValue(error)
      : vi.fn().mockResolvedValue(meta)
    const collection = vi.fn().mockReturnValue({ meta: metaFn })
    const space = vi.fn().mockReturnValue({ collection })
    return {
      store: storeWithStubbedClient({ space }),
      collection
    }
  }

  it('returns the stored custom envelope verbatim', async () => {
    const custom = { jwe: { ciphertext: 'opaque-metadata' } }
    const { store, collection } = storeWithMeta({
      meta: { custom, name: 'ignored' }
    })

    await expect(
      store.collectionMeta({ collectionId: 'private-credentials' })
    ).resolves.toEqual({ custom })
    // The raw (still encrypted) value is what the cipher decodes, so the
    // handle must be opened with the plaintext codec override.
    expect(collection).toHaveBeenCalledWith('private-credentials', {
      encryption: 'plaintext'
    })
  })

  it('returns undefined when the collection has no metadata resource', async () => {
    const { store } = storeWithMeta({ meta: null })

    await expect(
      store.collectionMeta({ collectionId: 'private-credentials' })
    ).resolves.toBeUndefined()
  })

  it('returns undefined for an absent custom value', async () => {
    // The plaintext-override codec reports an absent `custom` as `{}`.
    const { store } = storeWithMeta({ meta: { custom: {} } })

    await expect(
      store.collectionMeta({ collectionId: 'private-credentials' })
    ).resolves.toBeUndefined()

    const { store: noCustom } = storeWithMeta({ meta: { name: 'no custom' } })
    await expect(
      noCustom.collectionMeta({ collectionId: 'private-credentials' })
    ).resolves.toBeUndefined()
  })

  it('returns undefined when the server lacks metadata support', async () => {
    // Matched on `name`, not `instanceof`: the error class may come from
    // another copy of was-client.
    const notImplemented = Object.assign(new Error('no metadata here'), {
      name: 'NotImplementedError'
    })
    const { store } = storeWithMeta({ error: notImplemented })

    await expect(
      store.collectionMeta({ collectionId: 'private-credentials' })
    ).resolves.toBeUndefined()
  })

  it('rethrows any other error', async () => {
    const { store } = storeWithMeta({ error: new Error('network down') })

    await expect(
      store.collectionMeta({ collectionId: 'private-credentials' })
    ).rejects.toThrow('network down')
  })
})

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
    // No capability attached to the space handle: root invocation.
    expect(space).toHaveBeenCalledWith('space-id', { capability: undefined })
    expect(collection).toHaveBeenCalledWith('private-credentials')
  })
})

describe('WASRemoteStore.getSyncedResource', () => {
  it('reads the raw stored body via a root GET', async () => {
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
  it('creates the raw envelope with If-None-Match: *', async () => {
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

    const expectedSpaceId = deriveSpaceId(controller)
    expect(remoteStore.controller).toBe(controller)
    expect(remoteStore.spaceId).toBe(expectedSpaceId)
  })

  it('binds to the pointer Space id and stays did:key-controlled pre-promotion', async () => {
    const clientDid = 'did:key:z6MktestControllerDid'
    const { remoteStore } = await WASRemoteStore.initClient({
      storageServerUrl: 'https://example.test',
      user: { id: clientDid } as unknown as User,
      profile: {
        keyAgent: { id: clientDid },
        zcapClient: { request: vi.fn() },
        accountPointer: { spaceId: 'minted-space-id', host: 'https://h' }
      } as unknown as ControllerProfile
    })

    expect(remoteStore.spaceId).toBe('minted-space-id')
    expect(remoteStore.controller).toBe(clientDid)
  })

  it('binds to the promoted did:webvh controller once the pointer names it', async () => {
    const clientDid = 'did:key:z6MktestControllerDid'
    const webvhDid = 'did:webvh:zQmScid:example.test:space:minted-space-id:id'
    const { remoteStore } = await WASRemoteStore.initClient({
      storageServerUrl: 'https://example.test',
      user: { id: clientDid } as unknown as User,
      profile: {
        keyAgent: { id: clientDid },
        zcapClient: { request: vi.fn() },
        accountPointer: {
          did: webvhDid,
          spaceId: 'minted-space-id',
          host: 'https://h'
        }
      } as unknown as ControllerProfile
    })

    expect(remoteStore.spaceId).toBe('minted-space-id')
    expect(remoteStore.controller).toBe(webvhDid)
  })
})

describe('mintSpaceId', () => {
  it('mints distinct base64url identifiers', () => {
    const first = mintSpaceId()
    const second = mintSpaceId()
    // 32 random bytes -> 43 base64url chars, no padding.
    expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(second).not.toBe(first)
  })
})

describe('WASRemoteStore.ensureCollection', () => {
  it('configures a plaintext collection and skips setPublic by default', async () => {
    const configure = vi.fn().mockResolvedValue(undefined)
    const setPublic = vi.fn().mockResolvedValue(undefined)
    const collection = vi.fn().mockReturnValue({ configure, setPublic })
    const store = storeWithStubbedClient({
      space: vi.fn().mockReturnValue({ collection })
    })

    await store.ensureCollection({ id: 'example-app-data' })
    expect(collection).toHaveBeenCalledWith('example-app-data')
    // No encryption descriptor: the collection is provisioned plaintext.
    expect(configure).toHaveBeenCalledWith({
      name: 'example-app-data',
      force: true
    })
    expect(setPublic).not.toHaveBeenCalled()
  })

  it('sets a collection-level PublicCanRead policy with isPublic', async () => {
    const configure = vi.fn().mockResolvedValue(undefined)
    const setPublic = vi.fn().mockResolvedValue(undefined)
    const collection = vi.fn().mockReturnValue({ configure, setPublic })
    const store = storeWithStubbedClient({
      space: vi.fn().mockReturnValue({ collection })
    })

    await store.ensureCollection({ id: 'example-app-public', isPublic: true })
    expect(configure).toHaveBeenCalledWith({
      name: 'example-app-public',
      force: true
    })
    expect(setPublic).toHaveBeenCalledOnce()
  })

  it('wraps a setPublic failure in the provisioning error', async () => {
    const configure = vi.fn().mockResolvedValue(undefined)
    const setPublic = vi.fn().mockRejectedValue(new Error('policy boom'))
    const collection = vi.fn().mockReturnValue({ configure, setPublic })
    const store = storeWithStubbedClient({
      space: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.ensureCollection({ id: 'example-app-public', isPublic: true })
    ).rejects.toThrow(/Error provisioning collection/)
  })
})

describe('WASRemoteStore.ensureUserCollections', () => {
  const USER = { id: 'user-id', email: 'user@example.test' } as unknown as User

  // Provisioning now runs through the shared `provisionWalletSpace`
  // (`@interop/wallet-core/space`), so these tests drive the real roster and
  // provisioner against a recording stub of the was-client handle surface it
  // touches, rather than stubbing the library's `ensureSpaceAndCollection`.
  function recordingWas({
    fail = () => false
  }: {
    fail?: (id: string) => boolean
  } = {}) {
    const configures: Array<{
      id: string
      name?: string
      encryption?: { scheme: string }
      force?: boolean
    }> = []
    const setPublics: string[] = []
    // The 0.29.x ensure is non-clobbering: it describes first (a `null` here
    // means "absent", so every collection takes its creation path) and checks
    // the public policy before granting it.
    const was = {
      space: () => ({
        describe: async () => null,
        configure: async () => undefined,
        collection: (id: string) => ({
          describe: async () => null,
          configure: async (opts: {
            name?: string
            encryption?: { scheme: string }
            force?: boolean
          }) => {
            if (fail(id)) {
              throw new Error('boom')
            }
            configures.push({ id, ...opts })
          },
          isPublic: async () => false,
          setPublic: async () => {
            setPublics.push(id)
          }
        })
      })
    }
    return { was, configures, setPublics }
  }

  it('throws if provisioning fails', async () => {
    // A plaintext collection gets no name-only retry, so its failure surfaces
    // as the shared provisioner's per-collection error.
    const { was } = recordingWas({ fail: id => id === 'key-map' })
    const store = storeWithStubbedClient(was)

    await expect(store.ensureUserCollections({ user: USER })).rejects.toThrow(
      /Error provisioning collection "key-map"/
    )
  })

  it('provisions id as collection-level public and key-map capability-only', async () => {
    const { was, configures, setPublics } = recordingWas()
    const store = storeWithStubbedClient(was)

    await store.ensureUserCollections({ user: USER })

    // Both system collections are plaintext (a descriptor-less `force`
    // upsert), under their shared display names; only `id` goes public.
    expect(configures.find(({ id }) => id === 'id')).toEqual({
      id: 'id',
      name: 'Identity',
      force: true
    })
    expect(setPublics).toContain('id')
    expect(configures.find(({ id }) => id === 'key-map')).toEqual({
      id: 'key-map',
      name: 'Key Map',
      force: true
    })
    expect(setPublics).not.toContain('key-map')
    // The synced standard collections are provisioned alongside them.
    expect(configures.map(({ id }) => id)).toContain('private-credentials')
  })
})
