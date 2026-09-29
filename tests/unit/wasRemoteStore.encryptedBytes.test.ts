// @vitest-environment node
/**
 * Unit tests for `WASRemoteStore.putEncryptedResourceBytes`, the write the
 * content migration lands a bytes Resource of an encrypted app collection
 * through. The store's client is a real `WasClient` over an in-memory WAS
 * server (`memoryWasServer`), with a small blob limit, so a payload takes
 * was-client's chunked write, and the create-if-absent `412`, the read-back
 * that reassembles chunks, the pending stub a torn write leaves, and a `507`
 * all run through was-client's own code.
 */
import { describe, expect, it } from 'vitest'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { ZcapClient } from '@interop/ezcap'
import {
  createEdvDocCipher,
  edvIdFromBytes,
  mintEpoch,
  ownerRecipient,
  wrapEpochSecret
} from '@interop/was-client/edv'
import type { CollectionEncryption } from '@interop/was-client'
import type { Json } from '@interop/was-sync'
import { errorNameOf } from '@interop/wallet-core/menders'
import { TEST_SERVICE_DESCRIPTION } from '../shared/wasServiceFixture'
import { MEMORY_SERVER_URL, memoryWasServer } from './memoryWasServer'
import { generateVaultKeys } from '../../src/stores/testing/vaultKeys'
import { WASRemoteStore } from '../../src/stores/wasRemoteStore'

const COLLECTION_ID = 'app-photos'

/**
 * A store over the in-memory server, the owner's keys, a single-epoch
 * descriptor the owner is recipient zero of, and the pending-stub check the
 * storage manager hands in.
 *
 * @returns {Promise<object>}
 */
async function setup() {
  const keys = await generateVaultKeys()
  const { epochId, secret } = await mintEpoch()
  const recipient = await wrapEpochSecret({
    epochSecret: secret,
    recipient: ownerRecipient({ keyAgreementKey: keys.keyAgreementKey })
  })
  const encryption: CollectionEncryption = {
    scheme: 'edv',
    epochs: [{ id: epochId, recipients: [recipient] }],
    currentEpoch: epochId
  }
  const server = memoryWasServer()
  const store = new WASRemoteStore({
    serviceDescription: TEST_SERVICE_DESCRIPTION,
    pinStore: memoryResourceLogPinStore(),
    storageServerUrl: MEMORY_SERVER_URL,
    zcapClient: {} as ZcapClient,
    spaceId: 's-space',
    controller: 'did:key:test'
  })
  store.was = server.client({ maxBlobBytes: 16, chunkSize: 24 })
  const cipher = await createEdvDocCipher({
    ...keys,
    collectionId: COLLECTION_ID,
    encryption
  })
  const put = ({
    resourceId,
    bytes,
    contentType = 'image/png'
  }: {
    resourceId: string
    bytes: Uint8Array
    contentType?: string
  }) =>
    store.putEncryptedResourceBytes({
      collectionId: COLLECTION_ID,
      resourceId,
      bytes,
      contentType,
      encryption,
      ...keys,
      isPendingStub: (envelope: Json) =>
        cipher.isPendingStub({ id: resourceId, envelope })
    })
  return { server, store, cipher, put }
}

/**
 * A fresh EDV document id, the shape an archived random-id Resource carries.
 *
 * @returns {string}
 */
function freshId(): string {
  return edvIdFromBytes(crypto.getRandomValues(new Uint8Array(16)))
}

const LARGE = new Uint8Array(64).map((_value, index) => (index * 3) % 251)
const SMALL = new Uint8Array([1, 2, 3, 4])

describe('WASRemoteStore.putEncryptedResourceBytes', () => {
  it('writes a large payload as chunks at the id, and reads it back on a re-run', async () => {
    const { server, put } = await setup()
    const resourceId = freshId()

    await expect(put({ resourceId, bytes: LARGE })).resolves.toEqual({
      created: true
    })
    const chunks = [...server.store.keys()].filter(path =>
      path.startsWith(`/space/s-space/${COLLECTION_ID}/${resourceId}/chunks/`)
    )
    expect(chunks.length).toBe(3)

    const again = await put({ resourceId, bytes: LARGE })
    expect(again.created).toBe(false)
    expect(again.created === false && again.held).toEqual(LARGE)
  })

  it('writes a small payload at the id, and returns the held bytes when it is taken', async () => {
    const { put } = await setup()
    const resourceId = freshId()

    await expect(put({ resourceId, bytes: SMALL })).resolves.toEqual({
      created: true
    })
    const other = await put({ resourceId, bytes: new Uint8Array([9]) })
    expect(other.created === false && other.held).toEqual(SMALL)
  })

  it('removes the pending stub a torn chunked write left, and writes again', async () => {
    const { server, put } = await setup()
    const resourceId = freshId()
    const documentPath = `/space/s-space/${COLLECTION_ID}/${resourceId}`

    // Tear the write after its first document write: the second chunk and
    // the cleanup delete both fail, so the stub stays with one chunk.
    server.failWhen.test = (args, path) =>
      (args.method === 'PUT' && path.endsWith('/chunks/1')) ||
      args.method === 'DELETE'
    await expect(put({ resourceId, bytes: LARGE })).rejects.toThrow()
    server.failWhen.test = undefined
    expect(server.store.has(documentPath)).toBe(true)

    await expect(put({ resourceId, bytes: LARGE })).resolves.toEqual({
      created: true
    })
    const again = await put({ resourceId, bytes: LARGE })
    expect(again.created === false && again.held).toEqual(LARGE)
  })

  it('leaves a held copy that fails its decrypt and is no stub in place', async () => {
    const { server, put } = await setup()
    const resourceId = freshId()
    const documentPath = `/space/s-space/${COLLECTION_ID}/${resourceId}`
    await put({ resourceId, bytes: SMALL })
    // Another Resource's envelope stored under this id: bound elsewhere.
    const otherId = freshId()
    await put({ resourceId: otherId, bytes: SMALL })
    const foreign = server.store.get(
      `/space/s-space/${COLLECTION_ID}/${otherId}`
    )!
    server.store.set(documentPath, foreign)

    await expect(put({ resourceId, bytes: SMALL })).rejects.toThrow()
    expect(server.store.get(documentPath)).toEqual(foreign)
  })

  it('surfaces a 507 during a chunked write as QuotaExceededError', async () => {
    const { server, put } = await setup()
    server.failWhen.status = 507
    server.failWhen.test = (args, path) =>
      args.method === 'PUT' && path.endsWith('/chunks/1')

    const failure = await put({ resourceId: freshId(), bytes: LARGE }).catch(
      (err: unknown) => err
    )
    expect(errorNameOf(failure)).toBe('QuotaExceededError')
  })
})
