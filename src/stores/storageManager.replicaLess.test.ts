/**
 * Unit tests for the capability-bound, replica-less remote storage variant:
 *
 * - `WASRemoteStore` accepts an optional invocation capability and every
 *   request it makes rides it -- the navigational handles through the one
 *   private Space-handle helper, and the raw `was.request()` escape hatch
 *   sites directly. Absent the option, every handle and request carries no
 *   capability (root invocations, byte-identical to before).
 * - `StorageManager.initStorageClients` in a transient session constructs
 *   no `BrowserStore` (the versioned RxDB open alone creates the per-user
 *   database), routes every synced-collection operation through the
 *   remote-direct backend, starts no replication (no local end exists), and
 *   keeps the descriptor/meta caches on the persistence strategy's in-memory
 *   pair -- localStorage gains no key.
 * - A rotated user key reaches the remote-direct backend's ciphers: the
 *   in-band step holds the key material while the collections still carry the
 *   retiring epoch, and the post-fan-out adoption rebuilds the ciphers, so
 *   the next write seals under the fresh epoch.
 *
 * The WAS layer is faked at two seams matching the two subjects: a recording
 * fake `WasClient` under a real `WASRemoteStore` (so the store's own
 * capability threading is what is exercised), and a structural fake
 * `WASRemoteStore` under the real `StorageManager` (the sharing test's
 * pattern), with real EDV ciphers over freshly generated X25519 keys.
 *
 * @vitest-environment node
 */
import { describe, expect, it, vi } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { ZcapClient } from '@interop/ezcap'
import type {
  CollectionEncryption,
  IZcap,
  WasClient
} from '@interop/was-client'
import {
  ensureFirstEpoch,
  ownerRecipient,
  replaceRecipient
} from '@interop/was-client/edv'
import { cidFrom } from '@interop/was-client/sync'
import type { Json } from '@/lib/sync'
import {
  inMemorySessionPersistence,
  transientSessionStores
} from '@/session/persistence'
import type { ControllerProfile, User } from '@/types/auth'
import { BrowserStore } from './browserStore'
import { StorageManager } from './storageManager'
import { WASRemoteStore } from './wasRemoteStore'

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<Record<string, unknown>>()),
  WAS_SERVER_URL: 'https://was.example'
}))

/**
 * A minimal well-formed VC body; the storage layer treats it as opaque JSON.
 */
function makeCredential(name: string): IVerifiableCredential {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    issuer: 'did:key:z6MkTestIssuer',
    credentialSubject: { name }
  } as unknown as IVerifiableCredential
}

/**
 * A generated X25519 key pair plus the single-key resolver the session profile
 * supplies alongside it.
 */
async function generateKey(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}> {
  const key = await X25519KeyAgreementKey2020.generate({
    controller: 'did:key:z6MkTestController'
  })
  const keyResolver: IKeyResolver = async () => ({
    id: key.id!,
    type: key.type,
    publicKeyMultibase: key.publicKeyMultibase
  })
  return { keyAgreementKey: key as IKeyAgreementKey, keyResolver }
}

/**
 * The delegated Space-subtree zcap stand-in the capability assertions compare
 * by identity.
 */
const DELEGATED_ZCAP = {
  id: 'urn:uuid:generation-delegation',
  '@context': 'https://w3id.org/zcap/v1',
  controller: 'did:key:z6MkClientAnnex',
  invocationTarget: 'https://was.example/space/s-space',
  parentCapability: 'urn:zcap:root:...'
} as unknown as IZcap

/**
 * A recording fake `WasClient`: every `space()` handle records the options it
 * was created with, every raw `request()` records its input, and the handles
 * serve just enough structure (describe / list / resource.get) for the store
 * methods under test to complete.
 */
function recordingWas(): {
  was: WasClient
  spaceCalls: Array<{ spaceId: string; capability?: unknown }>
  requestCalls: Array<{ path?: string; method?: string; capability?: unknown }>
} {
  const spaceCalls: Array<{ spaceId: string; capability?: unknown }> = []
  const requestCalls: Array<{
    path?: string
    method?: string
    capability?: unknown
  }> = []
  const collectionHandle = (collectionId: string) => ({
    async describe() {
      return { name: collectionId, encryption: { scheme: 'edv' } }
    },
    async list() {
      return { items: [{ id: 'r1', url: `/x/${collectionId}/r1` }] }
    },
    resource(resourceId: string) {
      return {
        async get() {
          return { id: resourceId }
        }
      }
    }
  })
  const was = {
    space(spaceId: string, options: { capability?: unknown } = {}) {
      spaceCalls.push({ spaceId, capability: options.capability })
      return {
        async describe() {
          return { id: spaceId, controller: 'did:key:z6MkTestController' }
        },
        collection(collectionId: string) {
          return collectionHandle(collectionId)
        }
      }
    },
    async request(input: {
      path?: string
      method?: string
      capability?: unknown
    }) {
      requestCalls.push(input)
      return { data: { ok: true } }
    }
  } as unknown as WasClient
  return { was, spaceCalls, requestCalls }
}

/**
 * A real `WASRemoteStore` (optionally capability-bound) over the recording
 * fake client, plus the recorders.
 */
function makeRecordedStore({ capability }: { capability?: IZcap }): {
  store: WASRemoteStore
  spaceCalls: Array<{ spaceId: string; capability?: unknown }>
  requestCalls: Array<{ path?: string; method?: string; capability?: unknown }>
} {
  const store = new WASRemoteStore({
    storageServerUrl: 'https://was.example',
    zcapClient: {
      invocationSigner: { id: 'did:key:z6MkTest#z6MkTest' }
    } as unknown as ZcapClient,
    spaceId: 's-space',
    controller: 'did:key:z6MkTestController',
    capability
  })
  const { was, spaceCalls, requestCalls } = recordingWas()
  store.was = was
  return { store, spaceCalls, requestCalls }
}

/**
 * Drives one representative operation per request shape: the Space handle
 * (describe), a collection handle (describe, list), and every raw
 * `was.request()` site the remote-direct backend and the quota read use.
 */
async function driveStore(store: WASRemoteStore): Promise<void> {
  await store.userExists()
  await store.collectionEncryption({ collectionId: 'private-credentials' })
  await store.listSyncedResources({ logicalKey: 'privateCredentials' })
  await store.getSyncedResource({
    logicalKey: 'privateCredentials',
    resourceId: 'r1'
  })
  await store.putSyncedResource({
    logicalKey: 'privateCredentials',
    resourceId: 'r2',
    body: { a: 1 } as Json,
    epoch: 'e1'
  })
  await store.deleteSyncedResource({
    logicalKey: 'privateCredentials',
    resourceId: 'r2'
  })
  await store.getSpaceQuotas()
}

describe('WASRemoteStore invocation capability', () => {
  it('rides the bound capability on every handle and raw request', async () => {
    const { store, spaceCalls, requestCalls } = makeRecordedStore({
      capability: DELEGATED_ZCAP
    })
    await driveStore(store)
    expect(spaceCalls.length).toBeGreaterThan(0)
    expect(requestCalls.length).toBe(4)
    for (const call of spaceCalls) {
      expect(call.capability).toBe(DELEGATED_ZCAP)
    }
    for (const call of requestCalls) {
      expect(call.capability).toBe(DELEGATED_ZCAP)
    }
  })

  it('carries no capability when none is bound (root invocations)', async () => {
    const { store, spaceCalls, requestCalls } = makeRecordedStore({})
    await driveStore(store)
    for (const call of [...spaceCalls, ...requestCalls]) {
      expect(call.capability).toBeUndefined()
    }
  })
})

/**
 * The encrypted standard collections this fake provisions and rotates.
 */
const ENCRYPTED_COLLECTION_IDS = [
  'private-credentials',
  'wallet-activity',
  'contacts',
  'contacts-history'
]

/**
 * A structural fake of `WASRemoteStore` for the replica-less StorageManager:
 * per-collection descriptors served from `collectionEncryption`, and an
 * in-memory synced-resource map behind the remote-direct read/write surface.
 * `rotate` stands in for the cascade's collection fan-out, and `epochStamps`
 * records the key epoch each write was sealed under.
 */
function makeFakeRemote(): {
  remoteStore: WASRemoteStore
  descriptors: Record<string, CollectionEncryption>
  provision(owner: { keyAgreementKey: IKeyAgreementKey }): Promise<void>
  rotate(options: {
    from: { keyAgreementKey: IKeyAgreementKey }
    to: { keyAgreementKey: IKeyAgreementKey }
  }): Promise<void>
  epochStamps: Map<string, string[]>
} {
  const spaceId = 's-space'
  const descriptors: Record<string, CollectionEncryption> = {}
  const epochStamps = new Map<string, string[]>()
  const logicalToId: Record<string, string> = {
    privateCredentials: 'private-credentials',
    walletActivity: 'wallet-activity',
    publicCredentials: 'public-credentials',
    contacts: 'contacts',
    contactsHistory: 'contacts-history'
  }
  const resources = new Map<string, Map<string, Json>>()
  const versions = new Map<string, Map<string, number>>()
  const resourcesFor = (logicalKey: string): Map<string, Json> => {
    const id = logicalToId[logicalKey] ?? logicalKey
    let map = resources.get(id)
    if (!map) {
      map = new Map<string, Json>()
      resources.set(id, map)
    }
    return map
  }
  const versionsFor = (logicalKey: string): Map<string, number> => {
    const id = logicalToId[logicalKey] ?? logicalKey
    let map = versions.get(id)
    if (!map) {
      map = new Map<string, number>()
      versions.set(id, map)
    }
    return map
  }
  const remoteStore = {
    spaceId,
    spaceUrl: `https://was.example/space/${spaceId}`,
    // The replica-less init arm binds the collection map on construction;
    // this fake resolves collections by logical key, so the bind is a no-op.
    bindCollectionMap() {},
    async collectionEncryption({ collectionId }: { collectionId: string }) {
      return descriptors[collectionId]
    },
    async collectionMeta() {
      return undefined
    },
    async listSyncedResources({ logicalKey }: { logicalKey: string }) {
      return [...resourcesFor(logicalKey).keys()].map(id => ({
        id,
        url: `/space/${spaceId}/${logicalToId[logicalKey] ?? logicalKey}/${id}`
      }))
    },
    async getSyncedResource({
      logicalKey,
      resourceId
    }: {
      logicalKey: string
      resourceId: string
    }) {
      return resourcesFor(logicalKey).get(resourceId)
    },
    async getSyncedResourceWithEtag({
      logicalKey,
      resourceId
    }: {
      logicalKey: string
      resourceId: string
    }) {
      const data = resourcesFor(logicalKey).get(resourceId)
      if (data === undefined) {
        return undefined
      }
      return {
        data,
        etag: `"${versionsFor(logicalKey).get(resourceId) ?? 1}"`
      }
    },
    async putSyncedResource({
      logicalKey,
      resourceId,
      body,
      ifMatch,
      epoch
    }: {
      logicalKey: string
      resourceId: string
      body: Json
      ifMatch?: string
      epoch?: string
    }) {
      const collectionId = logicalToId[logicalKey] ?? logicalKey
      if (epoch) {
        epochStamps.set(collectionId, [
          ...(epochStamps.get(collectionId) ?? []),
          epoch
        ])
      }
      const map = resourcesFor(logicalKey)
      const resourceVersions = versionsFor(logicalKey)
      if (ifMatch !== undefined) {
        const current = resourceVersions.get(resourceId)
        if (current === undefined || ifMatch !== `"${current}"`) {
          throw Object.assign(new Error('precondition failed'), {
            status: 412
          })
        }
        map.set(resourceId, body)
        resourceVersions.set(resourceId, current + 1)
        return { created: true }
      }
      if (map.has(resourceId)) {
        return { created: false }
      }
      map.set(resourceId, body)
      resourceVersions.set(resourceId, 1)
      return { created: true }
    },
    async deleteSyncedResource({
      logicalKey,
      resourceId
    }: {
      logicalKey: string
      resourceId: string
    }) {
      resourcesFor(logicalKey).delete(resourceId)
      versionsFor(logicalKey).delete(resourceId)
    }
  } as unknown as WASRemoteStore
  // A CAS-backed minimal Collection per encrypted collection, so the real
  // `ensureFirstEpoch` and `replaceRecipient` write real epoch descriptors
  // (what provisioning and the cascade's fan-out would have written).
  const collectionVersions = new Map<string, number>()
  const collectionHandle = (collectionId: string) => ({
    async describeWithEtag() {
      return {
        description: {
          name: collectionId,
          encryption: descriptors[collectionId] ?? { scheme: 'edv' }
        },
        etag: `v${collectionVersions.get(collectionId) ?? 0}`
      }
    },
    async replaceDescription(
      fields: { encryption: CollectionEncryption },
      { ifMatch }: { ifMatch?: string }
    ) {
      const version = collectionVersions.get(collectionId) ?? 0
      if (ifMatch !== `v${version}`) {
        throw new Error('stale etag')
      }
      descriptors[collectionId] = fields.encryption
      collectionVersions.set(collectionId, version + 1)
    }
  })
  const provision = async (owner: { keyAgreementKey: IKeyAgreementKey }) => {
    for (const id of ENCRYPTED_COLLECTION_IDS) {
      const { descriptor } = await ensureFirstEpoch({
        collection: collectionHandle(id) as never,
        recipients: [ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })]
      })
      descriptors[id] = descriptor
    }
  }
  const rotate = async ({
    from,
    to
  }: {
    from: { keyAgreementKey: IKeyAgreementKey }
    to: { keyAgreementKey: IKeyAgreementKey }
  }) => {
    for (const id of ENCRYPTED_COLLECTION_IDS) {
      descriptors[id] = await replaceRecipient({
        collection: collectionHandle(id) as never,
        retire: from.keyAgreementKey.id!,
        recipient: ownerRecipient({ keyAgreementKey: to.keyAgreementKey }),
        owner: { keyAgreementKey: from.keyAgreementKey },
        // The pull axis ran elsewhere: the roster rotation is what retired
        // the key, and this fake has no zcaps to revoke.
        pull: async () => {}
      })
    }
  }
  return { remoteStore, descriptors, provision, rotate, epochStamps }
}

describe('replica-less remote-direct StorageManager', () => {
  it('serves credential and history reads/writes with no local replica and no browser-local residue', async () => {
    const owner = await generateKey()
    const { remoteStore, provision } = makeFakeRemote()
    await provision(owner)

    const persistence = inMemorySessionPersistence({
      stores: transientSessionStores(),
      clientAnnex: {
        clientAnnexDid: 'did:webvh:example:annex',
        invocationCapability: {} as IZcap
      }
    })
    const user: User = { id: 'did:key:z6MkTestClient' }
    const profile = {
      zcapClient: {} as ZcapClient,
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      persistence
    } as ControllerProfile

    const initClientSpy = vi
      .spyOn(WASRemoteStore, 'initClient')
      .mockResolvedValue({ remoteStore })
    const browserStoreSpy = vi.spyOn(BrowserStore, 'initClient')
    const localStorageBefore =
      typeof localStorage !== 'undefined' ? localStorage.length : undefined
    try {
      const { storage, userExists } = await StorageManager.initStorageClients({
        user,
        profile
      })

      // No BrowserStore was constructed: no per-user RxDB (IndexedDB)
      // database can have been created, and the manager reports no local
      // replica -- the sync controller's gate.
      expect(browserStoreSpy).not.toHaveBeenCalled()
      expect(storage.hasLocalReplica).toBe(false)
      // A transient session trusts the keyring hit that produced it.
      expect(userExists).toBe(true)
      // Reads need no local provisioning.
      await storage.ready()

      // Credential round trip over the remote-direct backend.
      const credential = makeCredential('Alice')
      const cid = await cidFrom({ doc: credential })
      await storage.addCredential({ credential, user })
      const listed = await storage.listCredentials()
      expect(listed).toEqual([{ cid, vc: credential }])
      expect(await storage.loadCredential({ cid })).toEqual(credential)

      // History round trip (addCredential recorded a Create entry itself).
      const items = await storage.listHistoryItems()
      expect(items.length).toBeGreaterThan(0)

      // The descriptor cache rode the strategy's in-memory pair, seeded at
      // login-time acquisition...
      const cached = await persistence
        .descriptorCache({ scope: remoteStore.spaceId })
        .readDescriptor({ collectionId: 'private-credentials' })
      expect(cached?.currentEpoch).toBeDefined()
      // ...and localStorage gained no key at all (guarded for the node
      // environment, where no localStorage exists to leak into).
      if (localStorageBefore !== undefined) {
        expect(localStorage.length).toBe(localStorageBefore)
      }
    } finally {
      initClientSpy.mockRestore()
      browserStoreSpy.mockRestore()
    }
  })

  it('serves the contacts round-trip through the remote-direct backend', async () => {
    const owner = await generateKey()
    const { remoteStore, provision } = makeFakeRemote()
    await provision(owner)

    const persistence = inMemorySessionPersistence({
      stores: transientSessionStores(),
      clientAnnex: {
        clientAnnexDid: 'did:webvh:example:annex',
        invocationCapability: {} as IZcap
      }
    })
    const user: User = { id: 'did:key:z6MkTestClient' }
    const profile = {
      zcapClient: {} as ZcapClient,
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      persistence
    } as ControllerProfile

    const initClientSpy = vi
      .spyOn(WASRemoteStore, 'initClient')
      .mockResolvedValue({ remoteStore })
    try {
      const { storage } = await StorageManager.initStorageClients({
        user,
        profile
      })
      await storage.ready()

      // Add + list + load through the facade (real EDV ciphers throughout).
      const stored = await storage.addContact({
        contact: { displayName: 'Alice' }
      })
      expect(stored.contactId).toBeTruthy()
      expect(await storage.listContacts()).toEqual([stored])
      expect(await storage.loadContact({ id: stored.id })).toEqual(stored)

      // Update rewrites the same row in place, preserving the identity.
      const updated = await storage.updateContact({
        id: stored.id,
        contact: { displayName: 'Alicia' }
      })
      expect(updated.id).toBe(stored.id)
      expect(updated.contactId).toBe(stored.contactId)
      const [head] = await storage.listContacts()
      expect(head.contact).toEqual({ displayName: 'Alicia' })

      // The facade paired each mutation with a contacts-history revision,
      // attributed to the in-memory strategy's own writerId.
      const writerId = persistence.getWriterId()
      const revisions = await storage.listContactRevisions({
        contactId: stored.contactId
      })
      expect(revisions.map(({ action }) => action)).toEqual([
        'update',
        'create'
      ])
      for (const revision of revisions) {
        expect(revision.writerId).toBe(writerId)
      }

      // Delete removes the remote head and appends the delete revision.
      await storage.deleteContact({ id: stored.id })
      expect(await storage.listContacts()).toEqual([])
      const afterDelete = await storage.listContactRevisions({
        contactId: stored.contactId
      })
      expect(afterDelete.map(({ action }) => action)).toEqual([
        'delete',
        'update',
        'create'
      ])
    } finally {
      initClientSpy.mockRestore()
    }
  })

  it('adopts a rotated user key past the fan-out, sealing later writes under the fresh epoch', async () => {
    const owner = await generateKey()
    const { remoteStore, descriptors, provision, rotate, epochStamps } =
      makeFakeRemote()
    await provision(owner)

    const persistence = inMemorySessionPersistence({
      stores: transientSessionStores(),
      clientAnnex: {
        clientAnnexDid: 'did:webvh:example:annex',
        invocationCapability: {} as IZcap
      }
    })
    const user: User = { id: 'did:key:z6MkTestClient' }
    const profile = {
      zcapClient: {} as ZcapClient,
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      persistence
    } as ControllerProfile

    const initClientSpy = vi
      .spyOn(WASRemoteStore, 'initClient')
      .mockResolvedValue({ remoteStore })
    try {
      const { storage } = await StorageManager.initStorageClients({
        user,
        profile
      })
      await storage.ready()

      const before = makeCredential('Before')
      await storage.addCredential({ credential: before, user })
      const firstEpoch = descriptors['private-credentials'].currentEpoch

      // The ceremony's in-band half, which fires BEFORE the collection
      // fan-out: the manager takes the rotated key material, and the ciphers
      // stay on the epoch the collections still carry.
      const rotated = await generateKey()
      storage.holdRotatedVaultKeys(rotated)

      // The fan-out: every encrypted collection re-epoch'd onto the rotated
      // key, which is what makes it a recipient of the current epoch.
      await rotate({ from: owner, to: rotated })
      const freshEpoch = descriptors['private-credentials'].currentEpoch
      expect(freshEpoch).not.toBe(firstEpoch)

      // The post-ceremony half: the rotated descriptors are refetched and the
      // ciphers rebuilt on them, with no unwrap failure.
      await storage.adoptRotatedVaultKeys(rotated)

      // A credential written next seals under the fresh epoch...
      const after = makeCredential('After')
      await storage.addCredential({ credential: after, user })
      expect(epochStamps.get('private-credentials')).toEqual([
        firstEpoch,
        freshEpoch
      ])
      // ...and the pre-rotation row still reads, the rotated key having been
      // escrowed into the epoch it was sealed under.
      const listed = await storage.listCredentials()
      expect(listed.map(({ vc }) => vc)).toEqual(
        expect.arrayContaining([before, after])
      )
    } finally {
      initClientSpy.mockRestore()
    }
  })

  it('refuses to rebuild the ciphers before the fan-out has run', async () => {
    const owner = await generateKey()
    const { remoteStore, provision } = makeFakeRemote()
    await provision(owner)

    const persistence = inMemorySessionPersistence({
      stores: transientSessionStores(),
      clientAnnex: {
        clientAnnexDid: 'did:webvh:example:annex',
        invocationCapability: {} as IZcap
      }
    })
    const user: User = { id: 'did:key:z6MkTestClient' }
    const profile = {
      zcapClient: {} as ZcapClient,
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      persistence
    } as ControllerProfile

    const initClientSpy = vi
      .spyOn(WASRemoteStore, 'initClient')
      .mockResolvedValue({ remoteStore })
    try {
      const { storage } = await StorageManager.initStorageClients({
        user,
        profile
      })
      await storage.ready()

      // Why the in-band step holds the keys rather than adopting them: the
      // collections still carry the epoch the rotation is about to retire, so
      // a full adoption there asks the rotated key to open an epoch it is not
      // yet a recipient of.
      const rotated = await generateKey()
      await expect(storage.adoptRotatedVaultKeys(rotated)).rejects.toThrow(
        expect.objectContaining({ name: 'KeyUnwrapError' })
      )
    } finally {
      initClientSpy.mockRestore()
    }
  })

  it('refuses a replica-less construction with no remote store', () => {
    expect(
      () =>
        new StorageManager({
          persistence: inMemorySessionPersistence({
            stores: transientSessionStores(),
            clientAnnex: {
              clientAnnexDid: 'did:webvh:example:annex',
              invocationCapability: {} as IZcap
            }
          })
        })
    ).toThrow(/remote WAS store/)
  })
})
