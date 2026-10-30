// @vitest-environment node
import { describe, it, expect, vi } from 'vitest'
import { TEST_SERVICE_DESCRIPTION } from '../shared/wasServiceFixture'

import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { ZcapClient } from '@interop/ezcap'
import type { IZcap } from '@interop/data-integrity-core'
import type {
  CollectionEncryption,
  ResourceChangeDocument,
  SpaceMetadata,
  WasClient
} from '@interop/was-client'

vi.mock('../../src/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('../../src/app.config')>()),
  // Small feed pages so the listSyncedDocuments walk exercises resumption.
  WAS_SYNC_BATCH_SIZE: 2
}))

import { ensureIndexedFirstEpoch } from '@interop/wallet-core/keys'
import { createEdvDocCipher, ownerRecipient } from '@interop/was-client/edv'
import { memoryDescriptorStores } from './fakeDescriptorStores'
import { generateVaultKeys } from '../../src/stores/testing/vaultKeys'
import { mintSpaceId, WASRemoteStore } from '../../src/stores/wasRemoteStore'
import { deriveSpaceId } from '@interop/was-client/sync'
import type { ControllerProfile, User } from '../../src/types/auth'
import type { SessionPersistence } from '../../src/session/persistence'

/**
 * The Space URL every store built here is bound to.
 */
const SPACE_URL = 'https://example.test/space/space-id/'

/**
 * Builds a WASRemoteStore whose `was` client has been replaced with a stub, so
 * tests exercise the store's handle navigation without real network/ezcap I/O.
 */
function storeWithStubbedClient(was: unknown): WASRemoteStore {
  const store = new WASRemoteStore({
    serviceDescription: TEST_SERVICE_DESCRIPTION,
    pinStore: memoryResourceLogPinStore(),
    baseServerUrl: 'https://example.test/',
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
        url: 'https://example.test/space/space-id/private-credentials',
        public: false
      },
      {
        id: 'public-credentials',
        url: 'https://example.test/space/space-id/public-credentials',
        public: true
      }
    ]
    const collections = vi.fn().mockResolvedValue({
      url: 'https://example.test/space/space-id/collections/',
      totalItems: 2,
      items
    })
    const isPublic = vi.fn().mockResolvedValue(false)
    const describeCollection = vi.fn().mockResolvedValue({})
    const collection = vi
      .fn()
      .mockReturnValue({ isPublic, describe: describeCollection })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collections, collection })
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
      {
        id: 'private-credentials',
        url: 'https://example.test/space/space-id/private-credentials'
      }
    ]
    const collections = vi.fn().mockResolvedValue({
      url: 'https://example.test/space/space-id/collections/',
      totalItems: 1,
      items
    })
    const isPublic = vi.fn().mockResolvedValue(false)
    const describeCollection = vi.fn().mockResolvedValue({})
    const collection = vi
      .fn()
      .mockReturnValue({ isPublic, describe: describeCollection })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collections, collection })
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
      spaceAt: vi.fn().mockReturnValue({
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
        url: 'https://example.test/space/space-id/private-credentials',
        public: false
      },
      {
        id: 'example-app-public',
        url: 'https://example.test/space/space-id/example-app-public',
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
      spaceAt: vi.fn().mockReturnValue({ collections, collection })
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
      {
        id: 'legacy-collection',
        url: 'https://example.test/space/space-id/legacy-collection'
      }
    ]
    const collections = vi.fn().mockResolvedValue({ totalItems: 1, items })
    const isPublic = vi.fn().mockResolvedValue(true)
    const describeCollection = vi.fn().mockResolvedValue({})
    const collection = vi
      .fn()
      .mockReturnValue({ isPublic, describe: describeCollection })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collections, collection })
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
        url: 'https://example.test/space/space-id/private-credentials/credential.json',
        contentType: 'application/json',
        modified: '2026-05-01T00:00:00.000Z'
      }
    ]
    const list = vi.fn().mockResolvedValue({
      id: 'private-credentials',
      url: 'https://example.test/space/space-id/private-credentials',
      totalItems: 1,
      items
    })
    const collectionIsPublic = vi.fn().mockResolvedValue(false)
    const collection = vi
      .fn()
      .mockReturnValue({ list, isPublic: collectionIsPublic })
    const space = vi.fn().mockReturnValue({ collection })
    const store = storeWithStubbedClient({ spaceAt: space })

    await expect(
      store.listCollectionResources({
        collectionUrl: 'https://example.test/space/space-id/private-credentials'
      })
    ).resolves.toEqual(items)
    expect(space).toHaveBeenCalledWith(SPACE_URL, { capability: undefined })
    expect(collection).toHaveBeenCalledWith('private-credentials')
    expect(collectionIsPublic).toHaveBeenCalledOnce()
  })

  it('marks all resources public when the collection is public', async () => {
    const items = [
      {
        id: 'shared.json',
        url: 'https://example.test/space/space-id/public-credentials/shared.json'
      }
    ]
    const list = vi.fn().mockResolvedValue({ totalItems: 1, items })
    const collectionIsPublic = vi.fn().mockResolvedValue(true)
    const collection = vi
      .fn()
      .mockReturnValue({ list, isPublic: collectionIsPublic })
    const space = vi.fn().mockReturnValue({ collection })
    const store = storeWithStubbedClient({ spaceAt: space })

    await expect(
      store.listCollectionResources({
        collectionUrl: 'https://example.test/space/space-id/public-credentials'
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
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.fetchCollectionResource({
        id: 'doc',
        url: 'https://example.test/space/space-id/notes/doc'
      })
    ).resolves.toEqual({ kind: 'json', data: { hello: 'world' } })
  })

  it('resolves a listing path reference against the Space URL', async () => {
    const get = vi.fn().mockResolvedValue({ hello: 'world' })
    const resource = vi.fn().mockReturnValue({ get })
    const collection = vi.fn().mockReturnValue({ resource })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.fetchCollectionResource({
        id: 'doc',
        url: '/space/space-id/notes/doc'
      })
    ).resolves.toEqual({ kind: 'json', data: { hello: 'world' } })
    expect(collection).toHaveBeenCalledWith('notes')
  })

  it('refuses a URL under another Space', async () => {
    const store = storeWithStubbedClient({ spaceAt: vi.fn() })

    await expect(
      store.fetchCollectionResource({
        id: 'doc',
        url: 'https://example.test/space/other-space/notes/doc'
      })
    ).rejects.toThrow()
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
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.fetchCollectionResource({
        id: 'z6Env1',
        url: 'https://example.test/space/space-id/private-credentials/z6Env1'
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
      spaceAt: vi.fn().mockReturnValue({
        collection: vi.fn().mockReturnValue({
          resource: vi.fn().mockReturnValue({ get })
        })
      })
    })

    const result = await store.fetchCollectionResource({
      id: 'logo.png',
      url: 'https://example.test/space/space-id/files/logo.png'
    })
    expect(result.kind).toBe('binary')
    if (result.kind === 'binary') {
      expect(result.contentType).toBe('image/png')
    }
  })
})

describe('WASRemoteStore.collectionMetadata', () => {
  /**
   * A stubbed `was` client whose collection handle answers `describe()` with
   * the given value (or rejects with the given error), plus the `collection`
   * spy so a test can assert how the handle was opened.
   *
   * @param options {object}
   * @param [options.metadata] {unknown}   what `describe()` resolves to
   * @param [options.error] {unknown}      what `describe()` rejects with
   * @returns {object}   the store plus the `collection` spy
   */
  function storeWithMetadata({
    metadata,
    error
  }: {
    metadata?: unknown
    error?: unknown
  }): { store: WASRemoteStore; collection: ReturnType<typeof vi.fn> } {
    const describeFn = error
      ? vi.fn().mockRejectedValue(error)
      : vi.fn().mockResolvedValue(metadata)
    const collection = vi.fn().mockReturnValue({ describe: describeFn })
    const space = vi.fn().mockReturnValue({ collection })
    return {
      store: storeWithStubbedClient({ spaceAt: space }),
      collection
    }
  }

  it('serves the descriptor and the stored custom from one read', async () => {
    const custom = { jwe: { ciphertext: 'opaque-metadata' } }
    const encryption = { epochs: [{ id: 'urn:uuid:e0' }] }
    const { store, collection } = storeWithMetadata({
      metadata: { custom, encryption, name: 'ignored' }
    })

    await expect(
      store.collectionMetadata({ collectionId: 'private-credentials' })
    ).resolves.toMatchObject({ custom, encryption })
    await expect(
      store.collectionEncryption({ collectionId: 'private-credentials' })
    ).resolves.toEqual(encryption)
    await expect(
      store.collectionMeta({ collectionId: 'private-credentials' })
    ).resolves.toEqual({ custom })
    // The configuration read, which never resolves the codec, so no
    // plaintext override is needed to keep `custom` opaque.
    expect(collection).toHaveBeenCalledWith('private-credentials')
  })

  it('returns undefined when the collection is missing or unreadable', async () => {
    const { store } = storeWithMetadata({ metadata: null })

    await expect(
      store.collectionMetadata({ collectionId: 'private-credentials' })
    ).resolves.toBeUndefined()
    await expect(
      store.collectionMeta({ collectionId: 'private-credentials' })
    ).resolves.toBeUndefined()
    await expect(
      store.collectionEncryption({ collectionId: 'private-credentials' })
    ).resolves.toBeUndefined()
  })

  it('returns undefined for an absent custom value', async () => {
    // A cleared `custom` (`null` or `{}` as stored) is dropped by was-client's
    // read itself, so the one shape the store sees for absence is no member.
    const { store: noCustom } = storeWithMetadata({
      metadata: { name: 'no custom' }
    })
    await expect(
      noCustom.collectionMeta({ collectionId: 'private-credentials' })
    ).resolves.toBeUndefined()
  })

  it('rethrows a read error', async () => {
    const { store } = storeWithMetadata({ error: new Error('network down') })

    await expect(
      store.collectionMeta({ collectionId: 'private-credentials' })
    ).rejects.toThrow('network down')
  })
})

describe('WASRemoteStore.listSyncedDocuments', () => {
  it('reads the feed snapshot under the bound capability at the configured page size', async () => {
    const capability = { id: 'urn:zcap:gen' } as unknown as IZcap
    const feed: ResourceChangeDocument[] = ['b', 'c'].map((id, position) => ({
      kind: 'resource',
      id,
      contentType: 'application/json',
      deleted: false,
      updatedAt: 't',
      updatedAtCounter: 0,
      originId: 'stub',
      checkpoint: String(position + 1),
      data: { n: position + 3 }
    }))
    const documents = vi.fn().mockResolvedValue(feed)
    const collection = vi.fn().mockReturnValue({ documents })
    const space = vi.fn().mockReturnValue({ collection })
    const store = storeWithStubbedClient({ spaceAt: space })
    store.adoptInvocationCapability({ capability })

    await expect(
      store.listSyncedDocuments({ logicalKey: 'walletActivity' })
    ).resolves.toEqual([
      { id: 'b', data: { n: 3 } },
      { id: 'c', data: { n: 4 } }
    ])
    expect(space).toHaveBeenCalledWith(SPACE_URL, { capability })
    expect(collection).toHaveBeenCalledWith('wallet-activity')
    expect(documents).toHaveBeenCalledWith({ limit: 2 })
  })

  it('lists a missing collection as empty', async () => {
    const documents = vi.fn().mockResolvedValue(null)
    const collection = vi.fn().mockReturnValue({ documents })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.listSyncedDocuments({ logicalKey: 'appKeys' })
    ).resolves.toEqual([])
  })

  it('wraps a failed walk in a named error', async () => {
    const documents = vi.fn().mockRejectedValue(new Error('boom'))
    const collection = vi.fn().mockReturnValue({ documents })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.listSyncedDocuments({ logicalKey: 'contacts' })
    ).rejects.toThrow('Failed to list documents in collection "contacts".')
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
      url: 'https://example.test/space/space-id/private-credentials/z6Env1',
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
      url: 'https://example.test/space/space-id/private-credentials/z6Env1',
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
      baseServerUrl: 'https://example.test/',
      user: { id: 'user-id-that-is-not-controller' } as unknown as User,
      session: {
        profile: {
          keyAgent: { id: controller },
          zcapClient: { request: vi.fn() }
        } as unknown as ControllerProfile,
        persistence: {
          logPins: memoryResourceLogPinStore()
        } as unknown as SessionPersistence
      }
    })

    const expectedSpaceId = deriveSpaceId(controller)
    expect(remoteStore.controller).toBe(controller)
    expect(remoteStore.spaceId).toBe(expectedSpaceId)
  })

  it('binds to the pointer Space id and stays did:key-controlled pre-promotion', async () => {
    const clientDid = 'did:key:z6MktestControllerDid'
    const { remoteStore } = await WASRemoteStore.initClient({
      baseServerUrl: 'https://example.test/',
      user: { id: clientDid } as unknown as User,
      session: {
        profile: {
          keyAgent: { id: clientDid },
          zcapClient: { request: vi.fn() },
          accountPointer: {
            spaceUrl: 'https://example.test/space/minted-space-id/'
          }
        } as unknown as ControllerProfile,
        persistence: {
          logPins: memoryResourceLogPinStore()
        } as unknown as SessionPersistence
      }
    })

    expect(remoteStore.spaceId).toBe('minted-space-id')
    expect(remoteStore.controller).toBe(clientDid)
  })

  it('binds to the promoted did:webvh controller once the pointer names it', async () => {
    const clientDid = 'did:key:z6MktestControllerDid'
    const webvhDid = 'did:webvh:zQmScid:example.test:space:minted-space-id:id'
    const { remoteStore } = await WASRemoteStore.initClient({
      baseServerUrl: 'https://example.test/',
      user: { id: clientDid } as unknown as User,
      session: {
        profile: {
          keyAgent: { id: clientDid },
          zcapClient: { request: vi.fn() },
          accountPointer: {
            did: webvhDid,
            spaceUrl: 'https://example.test/space/minted-space-id/'
          }
        } as unknown as ControllerProfile,
        persistence: {
          logPins: memoryResourceLogPinStore()
        } as unknown as SessionPersistence
      }
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
  /**
   * The server's echo of a create, the shape `replaceDescription` resolves.
   */
  const echo = vi.fn(async (description: unknown) => ({
    description,
    etag: 'v1'
  }))

  it('creates a plaintext collection and skips setPublic by default', async () => {
    const describeWithEtag = vi.fn().mockResolvedValue(null)
    const replaceDescription = vi.fn(echo)
    const setPublic = vi.fn().mockResolvedValue(undefined)
    const collection = vi
      .fn()
      .mockReturnValue({ describeWithEtag, replaceDescription, setPublic })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.ensureCollection({ id: 'example-app-data' })
    ).resolves.toEqual({ created: true })
    expect(collection).toHaveBeenCalledWith('example-app-data')
    // No encryption descriptor: the collection is provisioned plaintext, by
    // a guarded create.
    expect(replaceDescription).toHaveBeenCalledWith(
      { name: 'example-app-data' },
      { ifNoneMatch: true }
    )
    expect(setPublic).not.toHaveBeenCalled()
  })

  it('stamps the generator attribution on the create', async () => {
    const describeWithEtag = vi.fn().mockResolvedValue(null)
    const replaceDescription = vi.fn(echo)
    const collection = vi
      .fn()
      .mockReturnValue({ describeWithEtag, replaceDescription })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await store.ensureCollection({
      id: 'example-app-data',
      generator: {
        id: 'did:key:z6MkApp',
        origin: 'https://app.example',
        url: 'https://app.example/app',
        name: 'Example App'
      }
    })
    expect(replaceDescription).toHaveBeenCalledWith(
      {
        name: 'example-app-data',
        generator: {
          id: 'did:key:z6MkApp',
          origin: 'https://app.example',
          url: 'https://app.example/app',
          name: 'Example App'
        }
      },
      { ifNoneMatch: true }
    )
  })

  it('leaves a standing log-governed collection untouched', async () => {
    const describeWithEtag = vi.fn().mockResolvedValue({
      description: {
        name: 'Example App Data',
        encryption: {
          scheme: 'edv',
          currentEpoch: 'epoch-0',
          history: {
            method: 'resource-log:0.1',
            resource:
              'https://example.test/space/space-id/example-app-data/meta/log'
          }
        }
      },
      etag: 'v0'
    })
    const replaceDescription = vi.fn().mockResolvedValue(undefined)
    const collection = vi
      .fn()
      .mockReturnValue({ describeWithEtag, replaceDescription })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.ensureCollection({ id: 'example-app-data' })
    ).resolves.toEqual({ created: false })
    // The served `encryption` is the server's projection of the governing
    // log; a Description PUT carrying it would be refused, so none is sent.
    expect(replaceDescription).not.toHaveBeenCalled()
  })

  it('sets a collection-level PublicCanRead policy with isPublic', async () => {
    const describeWithEtag = vi.fn().mockResolvedValue(null)
    const replaceDescription = vi.fn(echo)
    const setPublic = vi.fn().mockResolvedValue(undefined)
    const collection = vi
      .fn()
      .mockReturnValue({ describeWithEtag, replaceDescription, setPublic })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await store.ensureCollection({ id: 'example-app-public', isPublic: true })
    expect(replaceDescription).toHaveBeenCalledWith(
      { name: 'example-app-public' },
      { ifNoneMatch: true }
    )
    expect(setPublic).toHaveBeenCalledOnce()
  })

  it('wraps a setPublic failure in the provisioning error', async () => {
    const describeWithEtag = vi.fn().mockResolvedValue(null)
    const replaceDescription = vi.fn(echo)
    const setPublic = vi.fn().mockRejectedValue(new Error('policy boom'))
    const collection = vi
      .fn()
      .mockReturnValue({ describeWithEtag, replaceDescription, setPublic })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.ensureCollection({ id: 'example-app-public', isPublic: true })
    ).rejects.toThrow(/Error provisioning collection/)
  })
})

describe('WASRemoteStore.ensureGovernedCollection', () => {
  /**
   * A governing log's projection pointer, the member that marks a
   * Description's `encryption` as server-derived rather than client-written.
   */
  const HISTORY = {
    method: 'resource-log:0.1',
    resource: 'https://example.test/space/space-id/example-app-data/meta/log'
  }

  /**
   * The server's echo of a create, the shape `replaceDescription` resolves.
   */
  const echo = vi.fn(async (description: unknown) => ({
    description,
    etag: 'v1'
  }))

  it('creates an absent collection with a bare guarded declaration', async () => {
    const describeWithEtag = vi.fn().mockResolvedValue(null)
    const replaceDescription = vi.fn(echo)
    const collection = vi
      .fn()
      .mockReturnValue({ describeWithEtag, replaceDescription })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.ensureGovernedCollection({ id: 'example-app-data' })
    ).resolves.toEqual({ created: true })
    expect(replaceDescription).toHaveBeenCalledOnce()
    // The declaration carries the name alone: the `encryption` member is the
    // server's to derive from the collection's governing log.
    expect(replaceDescription).toHaveBeenCalledWith(
      { name: 'example-app-data' },
      { ifNoneMatch: true }
    )
    const [body] = replaceDescription.mock.calls[0]
    expect(body).not.toHaveProperty('encryption')
    expect(describeWithEtag).toHaveBeenCalledOnce()
  })

  it('leaves a collection already governed untouched', async () => {
    const describeWithEtag = vi.fn().mockResolvedValue({
      description: {
        name: 'Example App Data',
        encryption: { scheme: 'edv', currentEpoch: 'epoch-0', history: HISTORY }
      },
      etag: 'v0'
    })
    const replaceDescription = vi.fn().mockResolvedValue(undefined)
    const collection = vi
      .fn()
      .mockReturnValue({ describeWithEtag, replaceDescription })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.ensureGovernedCollection({ id: 'example-app-data' })
    ).resolves.toEqual({ created: false })
    expect(replaceDescription).not.toHaveBeenCalled()
  })

  it('refuses a collection carrying a client-written encryption descriptor', async () => {
    const describeWithEtag = vi.fn().mockResolvedValue({
      description: {
        name: 'Example App Data',
        encryption: { scheme: 'edv', currentEpoch: 'epoch-0' }
      },
      etag: 'v0'
    })
    const replaceDescription = vi.fn().mockResolvedValue(undefined)
    const collection = vi
      .fn()
      .mockReturnValue({ describeWithEtag, replaceDescription })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.ensureGovernedCollection({ id: 'example-app-data' })
    ).rejects.toThrow(/cannot be governed by a history log/)
    expect(replaceDescription).not.toHaveBeenCalled()
  })

  it('rides the bound invocation capability and skips the Space half', async () => {
    const capability = { id: 'urn:zcap:generation' } as never
    const describeWithEtag = vi.fn().mockResolvedValue(null)
    const replaceDescription = vi.fn(echo)
    const describe = vi.fn()
    const collection = vi
      .fn()
      .mockReturnValue({ describeWithEtag, replaceDescription })
    const space = vi.fn().mockReturnValue({ collection, describe })
    const store = new WASRemoteStore({
      serviceDescription: TEST_SERVICE_DESCRIPTION,
      pinStore: memoryResourceLogPinStore(),
      baseServerUrl: 'https://example.test/',
      zcapClient: { request: vi.fn() } as unknown as ZcapClient,
      spaceId: 'space-id',
      controller: 'did:key:test',
      capability
    })
    store.was = { spaceAt: space } as unknown as WasClient

    await expect(
      store.ensureGovernedCollection({ id: 'example-app-data' })
    ).resolves.toEqual({ created: true })
    // A generation delegation cannot reach the bare Space URL: the Space is
    // neither described nor created, and every handle carries the capability.
    expect(describe).not.toHaveBeenCalled()
    expect(space).toHaveBeenCalledWith(SPACE_URL, { capability })
    expect(replaceDescription).toHaveBeenCalledWith(
      { name: 'example-app-data' },
      { ifNoneMatch: true }
    )
  })

  it('reads a lost create race back as the collection that stands', async () => {
    const describeWithEtag = vi
      .fn()
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({
        description: {
          name: 'Example App Data',
          encryption: {
            scheme: 'edv',
            currentEpoch: 'epoch-0',
            history: HISTORY
          }
        },
        etag: 'v0'
      })
    const replaceDescription = vi
      .fn()
      .mockRejectedValue(
        Object.assign(new Error('precondition failed'), { status: 412 })
      )
    const collection = vi
      .fn()
      .mockReturnValue({ describeWithEtag, replaceDescription })
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ collection })
    })

    await expect(
      store.ensureGovernedCollection({ id: 'example-app-data' })
    ).resolves.toEqual({ created: false })
    expect(describeWithEtag).toHaveBeenCalledTimes(2)
  })
})

describe('WASRemoteStore.promoteSpaceController', () => {
  it('forwards a supplied `current` to the Space configure, validator included', async () => {
    // The caller's baseline carries the `ETag` of the read it came from:
    // was-client pins the promotion write to it, and refuses a baseline
    // without one rather than writing unconditionally.
    const current: SpaceMetadata & { etag?: string } = {
      id: 'space-id',
      type: ['Space'],
      controller: 'did:key:test',
      etag: '"1"'
    }
    const configure = vi.fn().mockResolvedValue(undefined)
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ configure })
    })

    await store.promoteSpaceController({
      controller: 'did:webvh:promoted',
      current
    })
    expect(configure).toHaveBeenCalledWith({
      name: 'Wallet Space',
      controller: 'did:webvh:promoted',
      current
    })
    expect(store.controller).toBe('did:webvh:promoted')
  })

  it('omits `current` when the caller holds no read', async () => {
    const configure = vi.fn().mockResolvedValue(undefined)
    const store = storeWithStubbedClient({
      spaceAt: vi.fn().mockReturnValue({ configure })
    })

    await store.promoteSpaceController({ controller: 'did:webvh:promoted' })
    expect(configure).toHaveBeenCalledWith({
      name: 'Wallet Space',
      controller: 'did:webvh:promoted'
    })
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
    const creates: Array<{
      id: string
      fields: { name?: string; encryption?: { scheme: string } }
      options: { ifMatch?: string; ifNoneMatch?: boolean }
    }> = []
    const setPublics: string[] = []
    // The ensure is non-clobbering and creates through the guarded write: it
    // describes first (a `null` here means "absent", so every collection takes
    // its creation path) and writes the absent description with
    // `replaceDescription(fields, { ifNoneMatch: true })`. A collection this
    // run just created has no policy document yet, so its `isPublic()` is
    // never read before the world-read grant.
    //
    // `replaceDescription` answers with the description the server echoes on a
    // create, plus its `ETag`, as both real handles do. The Space's return is
    // what `provisionWalletSpace` threads into every collection branch so the
    // Space is ensured once rather than once per collection.
    const spaceHandle = (spaceUrl: string) => ({
      url: spaceUrl,
      describe: async () => null,
      replaceDescription: async (fields: {
        name?: string
        controller: string
      }) => ({
        description: { id: spaceUrl, type: ['Space'], ...fields },
        etag: '"1"'
      }),
      collection: (id: string) => ({
        describeWithEtag: async () => null,
        replaceDescription: async (
          fields: { name?: string; encryption?: { scheme: string } },
          options: { ifMatch?: string; ifNoneMatch?: boolean } = {}
        ) => {
          if (fail(id)) {
            throw new Error('boom')
          }
          creates.push({ id, fields, options })
          return {
            description: { id, type: ['Collection'], ...fields },
            etag: '"1"'
          }
        },
        isPublic: async () => false,
        setPublic: async () => {
          setPublics.push(id)
        }
      })
    })
    const was = {
      // The shared provisioner reads the Space URL off an id-opened handle,
      // then opens every handle by that URL.
      space: (spaceId: string) =>
        spaceHandle(`https://example.test/space/${spaceId}/`),
      spaceAt: spaceHandle
    }
    return { was, creates, setPublics }
  }

  it('throws if provisioning fails', async () => {
    // A failed create is re-read (the lost-race adoption) and, with nothing
    // there, rethrown -- so it surfaces as the shared provisioner's
    // per-collection error.
    const { was } = recordingWas({ fail: id => id === 'key-map' })
    const store = storeWithStubbedClient(was)

    await expect(store.ensureUserCollections({ user: USER })).rejects.toThrow(
      /Error provisioning collection "key-map"/
    )
  })

  it('provisions id as collection-level public and key-map capability-only', async () => {
    const { was, creates, setPublics } = recordingWas()
    const store = storeWithStubbedClient(was)

    await store.ensureUserCollections({ user: USER })

    // Both system collections are plaintext (a descriptor-less create), under
    // their shared display names; only `id` goes public. Every create is
    // guarded, so two clients booting at once cannot both create.
    expect(creates.find(({ id }) => id === 'id')).toEqual({
      id: 'id',
      fields: { name: 'Identity' },
      options: { ifNoneMatch: true }
    })
    expect(setPublics).toContain('id')
    expect(creates.find(({ id }) => id === 'key-map')).toEqual({
      id: 'key-map',
      fields: { name: 'Key Map' },
      options: { ifNoneMatch: true }
    })
    expect(setPublics).not.toContain('key-map')
    // An `edv` roster collection is created bare: its `encryption` member is
    // the server's to derive from the governing history log, so the create
    // carries the display name alone.
    expect(creates.find(({ id }) => id === 'private-credentials')).toEqual({
      id: 'private-credentials',
      fields: { name: 'Verifiable Credentials' },
      options: { ifNoneMatch: true }
    })
  })
})

describe('WASRemoteStore.keyedCollectionHandle', () => {
  /**
   * Builds a store with the bound invocation capability a transient session
   * hands over (the generation delegation its every request rides), over a
   * recording fake client.
   *
   * @param [capability] {IZcap}
   * @returns {object}
   */
  function storeWithCapability(capability?: IZcap) {
    const collection = vi.fn().mockReturnValue({ isHandle: true })
    const space = vi.fn().mockReturnValue({ collection })
    const store = new WASRemoteStore({
      serviceDescription: TEST_SERVICE_DESCRIPTION,
      pinStore: memoryResourceLogPinStore(),
      baseServerUrl: 'https://example.test/',
      zcapClient: { request: vi.fn() } as unknown as ZcapClient,
      spaceId: 'space-id',
      controller: 'did:webvh:zQmScid:example.test:space:space-id:id',
      ...(capability ? { capability } : {})
    })
    store.was = { spaceAt: space } as unknown as WasClient
    return { store, space, collection }
  }

  const ENCRYPTION = {
    scheme: 'edv',
    currentEpoch: 'epoch-0'
  } as unknown as CollectionEncryption

  /**
   * Opens the `connections` handle through `store`.
   *
   * @param store {WASRemoteStore}
   * @returns {Promise<void>}
   */
  async function openHandle(store: WASRemoteStore): Promise<void> {
    const { keyAgreementKey, keyResolver } = await generateVaultKeys({
      controller: 'did:key:z6MkOwner'
    })
    store.keyedCollectionHandle({
      collectionId: 'connections',
      encryption: ENCRYPTION,
      keyAgreementKey,
      keyResolver
    })
  }

  it('rides the bound capability on a transient session', async () => {
    // A transient session's only authority over the Space is the generation
    // delegation, so the directory's reads and writes invoke under it.
    const capability = { id: 'urn:zcap:generation' } as unknown as IZcap
    const { store, space } = storeWithCapability(capability)
    await openHandle(store)
    expect(space).toHaveBeenCalledWith(SPACE_URL, { capability })
  })

  it('root-invokes with no capability bound', async () => {
    const { store, space } = storeWithCapability()
    await openHandle(store)
    expect(space).toHaveBeenCalledWith(SPACE_URL, { capability: undefined })
  })

  it('reads the capability at each build, so a renewal reaches the next one', async () => {
    const original = { id: 'urn:zcap:generation' } as unknown as IZcap
    const { store, space } = storeWithCapability(original)
    await openHandle(store)
    const renewed = { id: 'urn:zcap:generation-fresh' } as unknown as IZcap
    store.adoptInvocationCapability({ capability: renewed })
    await openHandle(store)
    expect(space).toHaveBeenCalledTimes(2)
    expect(space).toHaveBeenNthCalledWith(1, SPACE_URL, {
      capability: original
    })
    expect(space).toHaveBeenNthCalledWith(2, SPACE_URL, {
      capability: renewed
    })
  })

  it('carries the descriptor and the reader keys as the handle override', async () => {
    const { store, collection } = storeWithCapability()
    await openHandle(store)
    const [collectionId, options] = collection.mock.calls.at(-1)!
    expect(collectionId).toBe('connections')
    expect(options.encryption).toMatchObject({
      scheme: 'edv',
      currentEpoch: 'epoch-0',
      keys: {
        keyAgreementKey: expect.anything(),
        keyResolver: expect.any(Function)
      }
    })
  })
})

describe('WASRemoteStore.declareCollectionIndexes', () => {
  it('seals the schema through its keystore-less client with the handle override', async () => {
    const { keyAgreementKey, keyResolver } = await generateVaultKeys({
      controller: 'did:key:z6MkOwner'
    })
    const stores = memoryDescriptorStores()
    const { descriptor: encryption } = await ensureIndexedFirstEpoch({
      store: await stores.storeFor('app-notes'),
      recipients: [ownerRecipient({ keyAgreementKey })]
    })

    // A stub server holding the one Collection Metadata object, enforcing
    // `If-Match` on its version.
    let meta: { document: Record<string, unknown>; version: number } = {
      document: { id: 'app-notes', type: ['Collection'], encryption },
      version: 0
    }
    const response = (data: unknown, etag?: string) => ({
      status: 200,
      headers: new Headers(etag !== undefined ? { etag } : {}),
      data,
      async json() {
        return data
      }
    })
    const request = vi.fn(
      async (args: {
        url: string
        method?: string
        json?: unknown
        headers?: Record<string, string>
      }) => {
        const path = new URL(args.url).pathname
        const method = args.method ?? 'GET'
        if (path === '/space/space-id/app-notes/meta' && method === 'GET') {
          return response(meta.document, `"${meta.version}"`)
        }
        if (path === '/space/space-id/app-notes/meta' && method === 'PUT') {
          meta = {
            document: {
              ...(args.json as Record<string, unknown>),
              type: ['Collection'],
              encryption
            },
            version: meta.version + 1
          }
          return response({}, `"${meta.version}"`)
        }
        throw Object.assign(new Error('not found'), { status: 404 })
      }
    )
    const store = new WASRemoteStore({
      serviceDescription: TEST_SERVICE_DESCRIPTION,
      pinStore: memoryResourceLogPinStore(),
      // This store builds a real WasClient, which refuses a base server URL
      // the service description does not describe, so the base matches
      // TEST_SERVICE_DESCRIPTION's.
      baseServerUrl: 'http://localhost/',
      zcapClient: {
        request,
        invocationSigner: { id: 'did:key:test#key' }
      } as unknown as ZcapClient,
      spaceId: 'space-id',
      controller: 'did:key:test'
    })

    const schema = await store.declareCollectionIndexes({
      collectionId: 'app-notes',
      encryption,
      keyAgreementKey,
      keyResolver,
      indexes: [{ attribute: 'content.type' }]
    })

    expect(schema.indexes).toEqual([{ attribute: 'content.type', addedIn: 1 }])
    // The server holds an opaque envelope, which a cipher over the same keys
    // opens back into the declared schema.
    const custom = meta.document.custom
    expect(JSON.stringify(custom)).not.toContain('content.type')
    const cipher = await createEdvDocCipher({
      keyAgreementKey,
      keyResolver,
      collectionId: 'app-notes',
      encryption
    })
    expect(await cipher.applyMeta({ custom })).toEqual(schema)
  })
})
