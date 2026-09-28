/**
 * Unit tests for StorageManager's app-collection import methods, the ones
 * the content migration re-creates a connected app's collection through:
 * `ensureImportedAppCollection`, `snapshotAppCollection`, and
 * `importAppCollectionRow`, plus the owner-only form of
 * `provisionEncryptedCollection` they ride.
 *
 * The session is replica-less, since app collections are remote-only on
 * every session kind. The remote WAS store is a structural fake over the
 * in-memory descriptor stores (each collection's governing log, with real
 * create-if-absent semantics), the stored `/meta` values, and the raw
 * resource bodies per collection. Its index declaration seals the schema
 * with was-client's own EDV codec, so the row cipher really installs it, and
 * the ciphers are real EDV codecs over freshly generated X25519 keys.
 *
 * @vitest-environment node
 */
import { describe, expect, it } from 'vitest'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import {
  QuotaExceededError,
  type CollectionEncryption,
  type CollectionGenerator,
  type IDelegatedZcap,
  type IndexSchema,
  type ResourceMetadataCustom
} from '@interop/was-client'
import {
  createEdvDocCipher,
  createEdvEncryption,
  ownerRecipient,
  removeRecipient
} from '@interop/was-client/edv'
import type { Json } from '@interop/was-sync'
import {
  descriptorLogsFrom,
  memoryDescriptorStores,
  type MemoryDescriptorStores
} from '../../tests/unit/fakeDescriptorStores'
import {
  inMemorySessionPersistence,
  transientSessionStores
} from '@/session/persistence'
import { StorageManager } from './storageManager'
import { generateVaultKeys } from './testing/vaultKeys'
import type { WASRemoteStore } from './wasRemoteStore'

type Keys = { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }

const GENERATOR: CollectionGenerator = {
  id: 'did:key:z6MkApp',
  origin: 'https://app.example',
  url: 'https://app.example/',
  name: 'Example App'
}

const OTHER_GENERATOR: CollectionGenerator = {
  id: 'did:key:z6MkOtherApp',
  origin: 'https://other.example',
  url: 'https://other.example/',
  name: 'Other App'
}

const INDEX_SCHEMA: IndexSchema = {
  revision: 1,
  indexes: [{ attribute: 'content.type', addedIn: 1 }]
}

/**
 * Seals a collection's `/meta` custom carrying an index schema, the way a
 * Collection handle's `declareIndexes` persists it.
 *
 * @param options {object}
 * @param options.collectionId {string}
 * @param options.encryption {CollectionEncryption}
 * @param options.keys {Keys}
 * @param options.schema {IndexSchema}
 * @returns {Promise<{ custom: unknown }>}
 */
async function sealSchema({
  collectionId,
  encryption,
  keys,
  schema
}: {
  collectionId: string
  encryption: CollectionEncryption
  keys: Keys
  schema: IndexSchema
}): Promise<{ custom: unknown }> {
  const codec = await createEdvEncryption({
    resolveKeys: async () => keys
  }).codecFor({ spaceId: 's-space', collectionId, scheme: 'edv', encryption })
  if (!codec) {
    throw new Error('expected an EDV codec')
  }
  const { custom } = await codec.encodeMeta({
    custom: { indexSchema: schema } as ResourceMetadataCustom,
    slot: { kind: 'collection' }
  })
  return { custom }
}

/**
 * A structural fake of WASRemoteStore holding what the app-collection import
 * reaches: the governing logs (through `stores`), the plaintext collections,
 * the stored `/meta` values, and each collection's raw resource bodies.
 *
 * @param stores {MemoryDescriptorStores}
 * @returns {object}
 */
function makeFakeRemote(stores: MemoryDescriptorStores) {
  const plaintext = new Set<string>()
  // Collections created bare by a governed ensure, before their log genesis.
  const bare = new Set<string>()
  // Collections carrying the collection-level world-read grant.
  const publicIds = new Set<string>()
  let setPublicCalls = 0
  let setPublicFailure: Error | undefined
  // Each created collection's attribution, stamped on the create only.
  const generators = new Map<string, CollectionGenerator>()
  // Collections encrypted under a client-written descriptor (no `history`).
  const clientWritten = new Map<string, CollectionEncryption>()
  // A rival create slipped in between the import's read and its own create.
  let rival: (() => void | Promise<void>) | undefined
  let declareFailure: Error | undefined
  // The `Key-Epoch` each encrypted write carried, in order.
  const putEpochs: Array<string | undefined> = []
  const metas = new Map<string, { custom: unknown }>()
  const resources = new Map<string, Map<string, Json>>()
  // Non-JSON plaintext resources, keyed by `<collectionId>/<resourceId>`.
  const blobs = new Map<string, { bytes: Uint8Array; contentType: string }>()
  const governed: Array<{ id: string; generator?: CollectionGenerator }> = []
  const ensured: Array<{
    id: string
    isPublic?: boolean
    generator?: CollectionGenerator
  }> = []
  const declared: Array<{
    collectionId: string
    indexes: Array<{ attribute: string | string[]; unique?: boolean }>
  }> = []
  let putFailure: Error | undefined
  const rowsOf = (collectionId: string): Map<string, Json> => {
    let rows = resources.get(collectionId)
    if (!rows) {
      rows = new Map()
      resources.set(collectionId, rows)
    }
    return rows
  }
  const stands = (collectionId: string): boolean =>
    stores.descriptorOf(collectionId) !== undefined ||
    clientWritten.has(collectionId) ||
    plaintext.has(collectionId) ||
    bare.has(collectionId)
  // The served `encryption` member: a governed collection's carries the
  // server's `history` pointer, a client-written one's does not.
  const servedEncryption = (
    collectionId: string
  ): CollectionEncryption | undefined => {
    const governedDescriptor = stores.descriptorOf(collectionId)
    if (governedDescriptor) {
      return {
        ...governedDescriptor,
        history: {
          method: 'resource-log:0.1',
          resource: `https://was.example/space/s-space/${collectionId}/meta/log`
        }
      }
    }
    return clientWritten.get(collectionId)
  }
  const runRival = async () => {
    const slip = rival
    rival = undefined
    await slip?.()
  }
  const remoteStore = {
    spaceId: 's-space',
    async collectionMetadata({ collectionId }: { collectionId: string }) {
      if (!stands(collectionId)) {
        return undefined
      }
      const encryption = servedEncryption(collectionId)
      const generator = generators.get(collectionId)
      return {
        ...(encryption !== undefined && { encryption }),
        ...(generator !== undefined && { generator })
      }
    },
    async collectionEncryption({ collectionId }: { collectionId: string }) {
      return servedEncryption(collectionId)
    },
    collectionHandle({ collectionId }: { collectionId: string }) {
      return {
        async isPublic() {
          return publicIds.has(collectionId)
        },
        async setPublic() {
          if (setPublicFailure) {
            const failure = setPublicFailure
            setPublicFailure = undefined
            throw failure
          }
          setPublicCalls++
          publicIds.add(collectionId)
        },
        async list() {
          return { items: [...rowsOf(collectionId).keys()].map(id => ({ id })) }
        },
        async *listPages() {
          yield { items: [...rowsOf(collectionId).keys()].map(id => ({ id })) }
        }
      }
    },
    async ensureGovernedCollection(options: {
      id: string
      generator?: CollectionGenerator
    }) {
      governed.push(options)
      await runRival()
      if (clientWritten.has(options.id)) {
        throw Object.assign(new Error('cannot be governed'), {
          name: 'ValidationError'
        })
      }
      const created = !stands(options.id)
      if (created) {
        bare.add(options.id)
        if (options.generator) {
          generators.set(options.id, options.generator)
        }
      }
      return { created }
    },
    async ensureCollection(options: {
      id: string
      isPublic?: boolean
      generator?: CollectionGenerator
    }) {
      ensured.push(options)
      await runRival()
      // was-client's ensure: a standing collection is left as it is, but
      // gets the world-read grant when `isPublic` is asked for.
      const created = !stands(options.id)
      if (created) {
        plaintext.add(options.id)
        if (options.generator) {
          generators.set(options.id, options.generator)
        }
      }
      if (options.isPublic && (created || !publicIds.has(options.id))) {
        setPublicCalls++
        publicIds.add(options.id)
      }
      return { created }
    },
    async collectionMeta({ collectionId }: { collectionId: string }) {
      return metas.get(collectionId)
    },
    async declareCollectionIndexes({
      collectionId,
      encryption,
      keyAgreementKey,
      keyResolver,
      indexes
    }: {
      collectionId: string
      encryption: CollectionEncryption
      keyAgreementKey: IKeyAgreementKey
      keyResolver: IKeyResolver
      indexes: Array<{ attribute: string; unique?: true }>
    }) {
      if (declareFailure) {
        const failure = declareFailure
        declareFailure = undefined
        throw failure
      }
      declared.push({ collectionId, indexes })
      const schema: IndexSchema = {
        revision: 1,
        indexes: indexes.map(index => ({ ...index, addedIn: 1 }))
      }
      metas.set(
        collectionId,
        await sealSchema({
          collectionId,
          encryption,
          keys: { keyAgreementKey, keyResolver },
          schema
        })
      )
      return schema
    },
    async listCollectionDocuments({ collectionId }: { collectionId: string }) {
      return [...rowsOf(collectionId)].map(([id, data]) => ({ id, data }))
    },
    async putPlaintextResource({
      collectionId,
      resourceId,
      data,
      contentType
    }: {
      collectionId: string
      resourceId: string
      data: Json | Uint8Array
      contentType: string
    }) {
      const rows = rowsOf(collectionId)
      if (rows.has(resourceId) || blobs.has(`${collectionId}/${resourceId}`)) {
        return { created: false }
      }
      if (data instanceof Uint8Array) {
        blobs.set(`${collectionId}/${resourceId}`, { bytes: data, contentType })
      } else {
        rows.set(resourceId, data)
      }
      return { created: true }
    },
    async getResourceBytes({
      collectionId,
      resourceId
    }: {
      collectionId: string
      resourceId: string
    }) {
      return blobs.get(`${collectionId}/${resourceId}`)?.bytes
    },
    async putCollectionResource({
      collectionId,
      resourceId,
      body,
      epoch
    }: {
      collectionId: string
      resourceId: string
      body: Json
      epoch?: string
    }) {
      putEpochs.push(epoch)
      if (putFailure) {
        throw putFailure
      }
      const rows = rowsOf(collectionId)
      if (rows.has(resourceId)) {
        return { created: false }
      }
      rows.set(resourceId, body)
      return { created: true }
    }
  } as unknown as WASRemoteStore
  return {
    remoteStore,
    governed,
    ensured,
    declared,
    rowsOf,
    blobs,
    publicIds,
    putEpochs,
    setPublicCalls: () => setPublicCalls,
    /**
     * Seeds a plaintext collection the account already holds.
     *
     * @param options {object}
     * @param options.collectionId {string}
     * @param [options.isPublic] {boolean}
     * @param [options.rows] {Record<string, Json>}
     */
    seedPlaintext({
      collectionId,
      isPublic = false,
      rows = {}
    }: {
      collectionId: string
      isPublic?: boolean
      rows?: Record<string, Json>
    }) {
      plaintext.add(collectionId)
      if (isPublic) {
        publicIds.add(collectionId)
      }
      for (const [id, row] of Object.entries(rows)) {
        rowsOf(collectionId).set(id, row)
      }
    },
    failPuts(err: Error) {
      putFailure = err
    },
    /**
     * Fails the next index declaration, a run torn after its first epoch.
     *
     * @param err {Error}
     */
    failNextDeclare(err: Error) {
      declareFailure = err
    },
    /**
     * Fails the next world-read grant, a run torn after its create.
     *
     * @param err {Error}
     */
    failNextSetPublic(err: Error) {
      setPublicFailure = err
    },
    /**
     * Runs `slip` once, inside the next ensure and before its create, as a
     * rival create landing between the import's read and its own.
     *
     * @param slip {function}
     */
    rivalCreates(slip: () => void | Promise<void>) {
      rival = slip
    },
    /**
     * Seeds a collection encrypted under a client-written descriptor.
     *
     * @param collectionId {string}
     */
    seedClientWritten(collectionId: string) {
      clientWritten.set(collectionId, {
        scheme: 'edv',
        currentEpoch: 'epoch-0'
      } as CollectionEncryption)
    },
    /**
     * Stamps an attribution on a seeded collection.
     *
     * @param collectionId {string}
     * @param generator {CollectionGenerator}
     */
    attribute(collectionId: string, generator: CollectionGenerator) {
      generators.set(collectionId, generator)
    }
  }
}

/**
 * A replica-less StorageManager over the fake remote, the descriptor logs,
 * and the owner's vault keys.
 *
 * @returns {Promise<object>}
 */
async function setup() {
  const owner = await generateVaultKeys()
  const stores = memoryDescriptorStores()
  const fake = makeFakeRemote(stores)
  const storage = new StorageManager({
    persistence: inMemorySessionPersistence({
      stores: transientSessionStores(),
      clientAnnex: {
        clientAnnexDid: 'did:webvh:example:annex',
        invocationCapability: {} as IDelegatedZcap
      }
    }),
    remoteStore: fake.remoteStore,
    descriptorLogs: descriptorLogsFrom(stores),
    vaultKeys: owner
  })
  return { owner, stores, storage, ...fake }
}

/**
 * The current epoch's recipient kids.
 *
 * @param descriptor {CollectionEncryption | undefined}
 * @returns {string[]}
 */
function currentEpochKids(
  descriptor: CollectionEncryption | undefined
): string[] {
  const epoch = descriptor?.epochs?.find(
    entry => entry.id === descriptor.currentEpoch
  )
  return (epoch?.recipients ?? []).map(recipient => recipient.header.kid)
}

describe('StorageManager.canProvisionAppCollections', () => {
  it('is true with remote storage and descriptor logs', async () => {
    const { storage } = await setup()
    expect(storage.canProvisionAppCollections).toBe(true)
  })
})

describe('StorageManager.provisionEncryptedCollection with no grantee', () => {
  it('mints the first epoch wrapped to the owner alone, with a blinding key', async () => {
    const { owner, stores, storage, governed } = await setup()

    const descriptor = await storage.provisionEncryptedCollection({
      collectionId: 'app-notes',
      generator: GENERATOR
    })

    expect(descriptor.epochs).toHaveLength(1)
    expect(currentEpochKids(descriptor)).toEqual([owner.keyAgreementKey.id])
    expect(descriptor.hmac?.id).toMatch(/^urn:uuid:/)
    expect(stores.descriptorOf('app-notes')).toEqual(descriptor)
    expect(governed).toEqual([{ id: 'app-notes', generator: GENERATOR }])
  })

  it('still escrows a grantee when one is given', async () => {
    const { owner, storage } = await setup()
    const app = await generateVaultKeys()

    const descriptor = await storage.provisionEncryptedCollection({
      collectionId: 'app-notes',
      recipient: ownerRecipient({ keyAgreementKey: app.keyAgreementKey })
    })

    expect(currentEpochKids(descriptor)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, app.keyAgreementKey.id])
    )
  })
})

describe('StorageManager app-collection import (encrypted)', () => {
  it('declares the archived index schema and writes rows carrying blinded entries', async () => {
    const { owner, stores, storage, declared, rowsOf } = await setup()

    await storage.ensureImportedAppCollection({
      collectionId: 'app-notes',
      encrypted: true,
      generator: GENERATOR,
      indexSchema: INDEX_SCHEMA
    })
    expect(declared).toEqual([
      { collectionId: 'app-notes', indexes: [{ attribute: 'content.type' }] }
    ])

    const held = await storage.snapshotAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    const row = { id: 'note-1', type: 'Note', text: 'hello' }
    const outcome = await storage.importAppCollectionRow({
      collectionId: 'app-notes',
      encrypted: true,
      resourceId: 'archived-id',
      contentType: 'application/json',
      content: { row },
      held
    })

    expect(outcome).toBe('accepted')
    const [[resourceId, envelope]] = [...rowsOf('app-notes')]
    // A fresh content-derived id, not the archived one.
    expect(resourceId).not.toBe('archived-id')
    expect(
      (envelope as { indexed?: unknown[] }).indexed?.length
    ).toBeGreaterThan(0)
    // The row opens under the owner's keys and the collection's descriptor.
    const reader = await createEdvDocCipher({
      ...owner,
      collectionId: 'app-notes',
      encryption: stores.descriptorOf('app-notes')!
    })
    expect(await reader.decrypt({ id: resourceId!, envelope })).toEqual(row)
  })

  it('writes rows without index entries when no schema is given', async () => {
    const { storage, declared, rowsOf } = await setup()

    await storage.ensureImportedAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    const held = await storage.snapshotAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    await storage.importAppCollectionRow({
      collectionId: 'app-notes',
      encrypted: true,
      resourceId: 'r',
      contentType: 'application/json',
      content: { row: { id: 'note-1', type: 'Note' } },
      held
    })

    expect(declared).toEqual([])
    const [envelope] = [...rowsOf('app-notes').values()]
    expect((envelope as { indexed?: unknown[] }).indexed ?? []).toEqual([])
  })

  it('skips a held row, reports a changed one as conflicting, and dedupes an id-less row by content', async () => {
    const { storage, rowsOf } = await setup()
    await storage.ensureImportedAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    const first = await storage.snapshotAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    const rows: Json[] = [{ id: 'note-1', text: 'one' }, { text: 'no id' }]
    for (const row of rows) {
      await storage.importAppCollectionRow({
        collectionId: 'app-notes',
        encrypted: true,
        resourceId: 'r',
        contentType: 'application/json',
        content: { row },
        held: first
      })
    }

    // A second run reads what the first one wrote.
    await storage.ensureImportedAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    const held = await storage.snapshotAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    const importRow = (row: Json) =>
      storage.importAppCollectionRow({
        collectionId: 'app-notes',
        encrypted: true,
        resourceId: 'r',
        contentType: 'application/json',
        content: { row },
        held
      })

    expect(await importRow({ id: 'note-1', text: 'one' })).toBe('skipped')
    expect(await importRow({ id: 'note-1', text: 'changed' })).toBe(
      'conflicting'
    )
    expect(await importRow({ text: 'no id' })).toBe('skipped')
    expect(await importRow({ id: 'note-2', text: 'two' })).toBe('accepted')
    expect(rowsOf('app-notes').size).toBe(3)
  })

  it('reports a failed write as failed, and rethrows a full Space', async () => {
    const { storage, failPuts } = await setup()
    await storage.ensureImportedAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    const held = await storage.snapshotAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    const importRow = (row: Json) =>
      storage.importAppCollectionRow({
        collectionId: 'app-notes',
        encrypted: true,
        resourceId: 'r',
        contentType: 'application/json',
        content: { row },
        held
      })

    failPuts(new Error('boom'))
    expect(await importRow({ id: 'a' })).toBe('failed')
    failPuts(new QuotaExceededError('full'))
    await expect(importRow({ id: 'b' })).rejects.toMatchObject({
      name: 'QuotaExceededError'
    })
  })

  it('refuses a row of a collection it has not ensured', async () => {
    const { storage } = await setup()
    expect(
      await storage.importAppCollectionRow({
        collectionId: 'app-notes',
        encrypted: true,
        resourceId: 'r',
        contentType: 'application/json',
        content: { row: { id: 'a' } },
        held: new Map()
      })
    ).toBe('failed')
  })
})

describe('StorageManager app-collection import (plaintext)', () => {
  it('ensures the collection with its attribution and public read', async () => {
    const { storage, ensured, governed, publicIds } = await setup()

    await storage.ensureImportedAppCollection({
      collectionId: 'public-posts',
      encrypted: false,
      isPublic: true,
      generator: GENERATOR
    })

    // Ensured private; the world-read grant follows the create.
    expect(ensured).toEqual([
      { id: 'public-posts', isPublic: false, generator: GENERATOR }
    ])
    expect(publicIds.has('public-posts')).toBe(true)
    expect(governed).toEqual([])
  })

  it('keeps the archived resource id, and skips or conflicts on a held one', async () => {
    const { storage, rowsOf } = await setup()
    await storage.ensureImportedAppCollection({
      collectionId: 'posts',
      encrypted: false
    })
    rowsOf('posts').set('held-post', { text: 'held' })
    const held = await storage.snapshotAppCollection({
      collectionId: 'posts',
      encrypted: false
    })
    const importRow = (resourceId: string, row: Json) =>
      storage.importAppCollectionRow({
        collectionId: 'posts',
        encrypted: false,
        resourceId,
        contentType: 'application/json',
        content: { row },
        held
      })

    expect(await importRow('post-1', { text: 'one' })).toBe('accepted')
    expect(rowsOf('posts').get('post-1')).toEqual({ text: 'one' })
    expect(await importRow('post-1', { text: 'one' })).toBe('skipped')
    expect(await importRow('held-post', { text: 'held' })).toBe('skipped')
    expect(await importRow('held-post', { text: 'other' })).toBe('conflicting')
  })

  it('writes a non-JSON row as its bytes, skipping the same bytes on a re-run', async () => {
    const { storage, blobs } = await setup()
    await storage.ensureImportedAppCollection({
      collectionId: 'media',
      encrypted: false
    })
    const held = await storage.snapshotAppCollection({
      collectionId: 'media',
      encrypted: false
    })
    const importBytes = (bytes: Uint8Array) =>
      storage.importAppCollectionRow({
        collectionId: 'media',
        encrypted: false,
        resourceId: 'photo',
        contentType: 'image/png',
        content: { bytes },
        held
      })

    expect(await importBytes(new Uint8Array([1, 2, 3]))).toBe('accepted')
    expect(blobs.get('media/photo')).toEqual({
      bytes: new Uint8Array([1, 2, 3]),
      contentType: 'image/png'
    })
    expect(await importBytes(new Uint8Array([1, 2, 3]))).toBe('skipped')
    expect(await importBytes(new Uint8Array([9]))).toBe('conflicting')
  })

  it('refuses a standing collection that turns out to be encrypted', async () => {
    const { storage } = await setup()
    await storage.provisionEncryptedCollection({ collectionId: 'notes' })

    await expect(
      storage.ensureImportedAppCollection({
        collectionId: 'notes',
        encrypted: false
      })
    ).rejects.toThrow(/already stands encrypted/)
  })
})

describe('StorageManager app-collection import into a standing collection', () => {
  it('refuses a standing private collection when the archive is public, leaving it private', async () => {
    const { storage, ensured, publicIds, setPublicCalls, seedPlaintext } =
      await setup()
    seedPlaintext({ collectionId: 'posts', rows: { p: { text: 'held' } } })

    await expect(
      storage.ensureImportedAppCollection({
        collectionId: 'posts',
        encrypted: false,
        isPublic: true
      })
    ).rejects.toMatchObject({ name: 'AppCollectionMismatchError' })
    expect(publicIds.has('posts')).toBe(false)
    expect(setPublicCalls()).toBe(0)
    expect(ensured).toEqual([])
  })

  it('refuses a standing public collection when the archive is private', async () => {
    const { storage, publicIds, seedPlaintext } = await setup()
    seedPlaintext({ collectionId: 'posts', isPublic: true })

    await expect(
      storage.ensureImportedAppCollection({
        collectionId: 'posts',
        encrypted: false
      })
    ).rejects.toMatchObject({ name: 'AppCollectionMismatchError' })
    expect(publicIds.has('posts')).toBe(true)
  })

  it('refuses a standing encrypted collection for a public plaintext archive, granting no public read', async () => {
    const { storage, ensured, setPublicCalls } = await setup()
    await storage.provisionEncryptedCollection({ collectionId: 'notes' })

    await expect(
      storage.ensureImportedAppCollection({
        collectionId: 'notes',
        encrypted: false,
        isPublic: true
      })
    ).rejects.toMatchObject({ name: 'AppCollectionMismatchError' })
    expect(setPublicCalls()).toBe(0)
    expect(ensured).toEqual([])
  })

  it('refuses a standing plaintext collection holding rows for an encrypted archive', async () => {
    const { storage, stores, seedPlaintext } = await setup()
    seedPlaintext({ collectionId: 'notes', rows: { p: { text: 'held' } } })

    await expect(
      storage.ensureImportedAppCollection({
        collectionId: 'notes',
        encrypted: true
      })
    ).rejects.toMatchObject({ name: 'AppCollectionMismatchError' })
    expect(stores.descriptorOf('notes')).toBeUndefined()
  })

  it('adopts a matching standing plaintext collection, changing none of its settings', async () => {
    const { storage, ensured, seedPlaintext, rowsOf, setPublicCalls } =
      await setup()
    seedPlaintext({
      collectionId: 'posts',
      isPublic: true,
      rows: { p: { text: 'held' } }
    })

    await storage.ensureImportedAppCollection({
      collectionId: 'posts',
      encrypted: false,
      isPublic: true,
      generator: GENERATOR
    })
    // The ensure finds the collection standing and writes nothing.
    expect(ensured).toEqual([
      { id: 'posts', isPublic: false, generator: GENERATOR }
    ])
    expect(setPublicCalls()).toBe(0)
    const held = await storage.snapshotAppCollection({
      collectionId: 'posts',
      encrypted: false
    })
    expect(
      await storage.importAppCollectionRow({
        collectionId: 'posts',
        encrypted: false,
        resourceId: 'q',
        contentType: 'application/json',
        content: { row: { text: 'new' } },
        held
      })
    ).toBe('accepted')
    expect(rowsOf('posts').size).toBe(2)
  })

  it('refuses an empty collection a torn encrypted provision left, for a plaintext archive', async () => {
    const { storage, remoteStore, rowsOf, stores } = await setup()
    // App Connect created the collection bare and tore before its log.
    await remoteStore.ensureGovernedCollection({ id: 'notes' })

    await expect(
      storage.ensureImportedAppCollection({
        collectionId: 'notes',
        encrypted: false
      })
    ).rejects.toMatchObject({ name: 'AppCollectionMismatchError' })
    expect(rowsOf('notes').size).toBe(0)

    // An encrypted archive finishes the provision instead.
    await storage.ensureImportedAppCollection({
      collectionId: 'notes',
      encrypted: true
    })
    expect(stores.descriptorOf('notes')?.epochs).toHaveLength(1)
  })

  it('declares the archived index schema on a created collection only', async () => {
    const { storage, declared, rowsOf } = await setup()
    await storage.provisionEncryptedCollection({ collectionId: 'app-notes' })

    await storage.ensureImportedAppCollection({
      collectionId: 'app-notes',
      encrypted: true,
      indexSchema: {
        revision: 1,
        indexes: [{ attribute: 'content.type', unique: true, addedIn: 1 }]
      }
    })
    expect(declared).toEqual([])

    const held = await storage.snapshotAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    await storage.importAppCollectionRow({
      collectionId: 'app-notes',
      encrypted: true,
      resourceId: 'r',
      contentType: 'application/json',
      content: { row: { id: 'note-1', type: 'Note' } },
      held
    })
    const [envelope] = [...rowsOf('app-notes').values()]
    expect((envelope as { indexed?: unknown[] }).indexed ?? []).toEqual([])
  })

  it('refreshes a rotated epoch for the snapshot and seals later rows under it', async () => {
    const { owner, stores, storage, rowsOf, putEpochs } = await setup()
    const extra = await generateVaultKeys()
    await storage.provisionEncryptedCollection({
      collectionId: 'app-notes',
      recipient: ownerRecipient({ keyAgreementKey: extra.keyAgreementKey })
    })
    await storage.ensureImportedAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })

    // Another client rotates the epoch and writes a row under the new one.
    const rotated = await removeRecipient({
      store: stores.storeFor('app-notes'),
      recipientId: extra.keyAgreementKey.id!,
      pull: async () => {},
      resolveRecipientKey: async kid =>
        kid === owner.keyAgreementKey.id
          ? ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })
          : null
    })
    const writer = await createEdvDocCipher({
      ...owner,
      collectionId: 'app-notes',
      encryption: rotated
    })
    const sealed = await writer.encrypt({ data: { id: 'note-1', text: 'a' } })
    rowsOf('app-notes').set(sealed.id, sealed.envelope)

    const held = await storage.snapshotAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    expect(held.has('id:note-1')).toBe(true)
    expect(
      await storage.importAppCollectionRow({
        collectionId: 'app-notes',
        encrypted: true,
        resourceId: 'r',
        contentType: 'application/json',
        content: { row: { id: 'note-2', text: 'b' } },
        held
      })
    ).toBe('accepted')
    expect(putEpochs).toEqual([rotated.currentEpoch])
  })

  it('handles a bundle-supplied __proto__ collection id', async () => {
    const { storage, rowsOf } = await setup()
    await storage.ensureImportedAppCollection({
      collectionId: '__proto__',
      encrypted: true
    })
    const held = await storage.snapshotAppCollection({
      collectionId: '__proto__',
      encrypted: true
    })
    expect(
      await storage.importAppCollectionRow({
        collectionId: '__proto__',
        encrypted: true,
        resourceId: 'r',
        contentType: 'application/json',
        content: { row: { id: 'a' } },
        held
      })
    ).toBe('accepted')
    expect(rowsOf('__proto__').size).toBe(1)
    // Another collection is still refused as not ensured.
    expect(
      await storage.importAppCollectionRow({
        collectionId: 'other',
        encrypted: true,
        resourceId: 'r',
        contentType: 'application/json',
        content: { row: { id: 'a' } },
        held: new Map()
      })
    ).toBe('failed')
  })
})

describe('StorageManager app-collection import re-runs and races', () => {
  it('declares the archived schema on a re-run after a tear before the declaration', async () => {
    const { storage, declared, rowsOf, failNextDeclare } = await setup()
    failNextDeclare(new Error('torn'))
    await expect(
      storage.ensureImportedAppCollection({
        collectionId: 'app-notes',
        encrypted: true,
        generator: GENERATOR,
        indexSchema: INDEX_SCHEMA
      })
    ).rejects.toThrow('torn')
    expect(declared).toEqual([])

    await storage.ensureImportedAppCollection({
      collectionId: 'app-notes',
      encrypted: true,
      generator: GENERATOR,
      indexSchema: INDEX_SCHEMA
    })
    expect(declared).toEqual([
      { collectionId: 'app-notes', indexes: [{ attribute: 'content.type' }] }
    ])
    const held = await storage.snapshotAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    await storage.importAppCollectionRow({
      collectionId: 'app-notes',
      encrypted: true,
      resourceId: 'r',
      contentType: 'application/json',
      content: { row: { id: 'note-1', type: 'Note' } },
      held
    })
    const [envelope] = [...rowsOf('app-notes').values()]
    expect(
      (envelope as { indexed?: unknown[] }).indexed?.length
    ).toBeGreaterThan(0)
  })

  it('does not declare the schema again on a finished create that already declares one', async () => {
    const { storage, declared } = await setup()
    await storage.ensureImportedAppCollection({
      collectionId: 'app-notes',
      encrypted: true,
      generator: GENERATOR,
      indexSchema: INDEX_SCHEMA
    })
    await storage.ensureImportedAppCollection({
      collectionId: 'app-notes',
      encrypted: true,
      generator: GENERATOR,
      indexSchema: INDEX_SCHEMA
    })
    expect(declared).toHaveLength(1)
  })

  it('grants the missed public read on a re-run after a tear before it', async () => {
    const { storage, publicIds, failNextSetPublic } = await setup()
    failNextSetPublic(new Error('torn'))
    await expect(
      storage.ensureImportedAppCollection({
        collectionId: 'posts',
        encrypted: false,
        isPublic: true,
        generator: GENERATOR
      })
    ).rejects.toThrow('torn')
    expect(publicIds.has('posts')).toBe(false)

    await storage.ensureImportedAppCollection({
      collectionId: 'posts',
      encrypted: false,
      isPublic: true,
      generator: GENERATOR
    })
    expect(publicIds.has('posts')).toBe(true)
  })

  it('proceeds into its own empty private plaintext collection on a re-run', async () => {
    const { storage, rowsOf } = await setup()
    const ensure = () =>
      storage.ensureImportedAppCollection({
        collectionId: 'posts',
        encrypted: false,
        generator: GENERATOR
      })
    await ensure()
    // The first run tore before any row landed.
    await ensure()
    const held = await storage.snapshotAppCollection({
      collectionId: 'posts',
      encrypted: false
    })
    expect(
      await storage.importAppCollectionRow({
        collectionId: 'posts',
        encrypted: false,
        resourceId: 'p',
        contentType: 'application/json',
        content: { row: { text: 'one' } },
        held
      })
    ).toBe('accepted')
    expect(rowsOf('posts').size).toBe(1)
  })

  it('refuses an empty private plaintext collection carrying a different attribution', async () => {
    const { storage, seedPlaintext, attribute } = await setup()
    seedPlaintext({ collectionId: 'posts' })
    attribute('posts', OTHER_GENERATOR)

    await expect(
      storage.ensureImportedAppCollection({
        collectionId: 'posts',
        encrypted: false,
        generator: GENERATOR
      })
    ).rejects.toMatchObject({ name: 'AppCollectionMismatchError' })
  })

  it('refuses an empty private plaintext collection when neither side is attributed', async () => {
    const { storage, seedPlaintext } = await setup()
    seedPlaintext({ collectionId: 'posts' })

    await expect(
      storage.ensureImportedAppCollection({
        collectionId: 'posts',
        encrypted: false
      })
    ).rejects.toMatchObject({ name: 'AppCollectionMismatchError' })
  })

  it('checks a rival plaintext collection that won the create race, granting nothing', async () => {
    const {
      storage,
      seedPlaintext,
      attribute,
      rivalCreates,
      setPublicCalls,
      publicIds
    } = await setup()
    rivalCreates(() => {
      seedPlaintext({ collectionId: 'posts', rows: { r: { text: 'rival' } } })
      attribute('posts', OTHER_GENERATOR)
    })

    await expect(
      storage.ensureImportedAppCollection({
        collectionId: 'posts',
        encrypted: false,
        isPublic: true,
        generator: GENERATOR
      })
    ).rejects.toMatchObject({ name: 'AppCollectionMismatchError' })
    expect(setPublicCalls()).toBe(0)
    expect(publicIds.has('posts')).toBe(false)
  })

  it('adopts a rival encrypted collection that won the create race, declaring no schema', async () => {
    const { storage, remoteStore, rivalCreates, declared, stores } =
      await setup()
    rivalCreates(async () => {
      await remoteStore.ensureGovernedCollection({
        id: 'app-notes',
        generator: OTHER_GENERATOR
      })
    })

    await storage.ensureImportedAppCollection({
      collectionId: 'app-notes',
      encrypted: true,
      generator: GENERATOR,
      indexSchema: INDEX_SCHEMA
    })
    expect(declared).toEqual([])
    // The rival's provision is finished with its first epoch.
    expect(stores.descriptorOf('app-notes')?.epochs).toHaveLength(1)
  })

  it('refuses a standing collection encrypted under a client-written descriptor', async () => {
    const { storage, seedClientWritten, governed } = await setup()
    seedClientWritten('notes')

    await expect(
      storage.ensureImportedAppCollection({
        collectionId: 'notes',
        encrypted: true
      })
    ).rejects.toMatchObject({ name: 'AppCollectionMismatchError' })
    expect(governed).toEqual([])
  })

  it('refuses a rival client-written collection that won the create race', async () => {
    const { storage, seedClientWritten, rivalCreates } = await setup()
    rivalCreates(() => seedClientWritten('notes'))

    await expect(
      storage.ensureImportedAppCollection({
        collectionId: 'notes',
        encrypted: true
      })
    ).rejects.toMatchObject({
      name: 'AppCollectionMismatchError',
      cause: { name: 'ValidationError' }
    })
  })

  it('ignores the archived public read of an encrypted collection on a re-run', async () => {
    const { storage, setPublicCalls } = await setup()
    const ensure = () =>
      storage.ensureImportedAppCollection({
        collectionId: 'app-notes',
        encrypted: true,
        isPublic: true,
        generator: GENERATOR
      })
    await ensure()
    await ensure()
    expect(setPublicCalls()).toBe(0)
  })

  it('seals a row after a mid-run epoch rotation under the new epoch', async () => {
    const { owner, stores, storage, putEpochs } = await setup()
    const extra = await generateVaultKeys()
    await storage.provisionEncryptedCollection({
      collectionId: 'app-notes',
      recipient: ownerRecipient({ keyAgreementKey: extra.keyAgreementKey })
    })
    await storage.ensureImportedAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    const held = await storage.snapshotAppCollection({
      collectionId: 'app-notes',
      encrypted: true
    })
    const importRow = (id: string) =>
      storage.importAppCollectionRow({
        collectionId: 'app-notes',
        encrypted: true,
        resourceId: id,
        contentType: 'application/json',
        content: { row: { id } },
        held
      })
    expect(await importRow('note-1')).toBe('accepted')
    const before = stores.descriptorOf('app-notes')!.currentEpoch

    // A revocation cascade in another tab rotates the epoch mid-run.
    const rotated = await removeRecipient({
      store: stores.storeFor('app-notes'),
      recipientId: extra.keyAgreementKey.id!,
      pull: async () => {},
      resolveRecipientKey: async kid =>
        kid === owner.keyAgreementKey.id
          ? ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })
          : null
    })
    expect(rotated.currentEpoch).not.toBe(before)

    expect(await importRow('note-2')).toBe('accepted')
    expect(putEpochs).toEqual([before, rotated.currentEpoch])
  })
})
