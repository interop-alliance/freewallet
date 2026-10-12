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
 *   the next write seals under the fresh epoch. An adoption the fan-out has
 *   not reached throws.
 * - A session built on collections no key epoch of which names its vault KAK
 *   gets refusing ciphers there, reported as stranded, and a refresh past the
 *   fan-out clears them. A named reader whose entry does not unwrap still
 *   fails the build.
 * - A contacts point read or edit that meets a head another client sealed
 *   under a rotated key epoch drives the facade's one-time descriptor refresh
 *   and re-runs, writing the edit once under the fresh epoch.
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
import { TEST_SERVICE_DESCRIPTION } from '../../tests/shared/wasServiceFixture'

import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import type {
  CollectionEncryption,
  IZcap,
  Space,
  WasClient
} from '@interop/was-client'
import {
  addRecipient,
  createEdvDocCipher,
  ensureFirstEpoch,
  ownerRecipient,
  removeRecipient,
  replaceRecipient
} from '@interop/was-client/edv'
import { cidFrom } from '@interop/was-client/sync'
import type { Json } from '@interop/was-sync'
import type { ContactData, ContactHeadPayload } from '@interop/social-core'
import {
  descriptorLogsFrom,
  memoryDescriptorStores,
  type MemoryDescriptorStores
} from '../../tests/unit/fakeDescriptorStores'
import {
  inMemorySessionPersistence,
  transientSessionStores
} from '@/session/persistence'
import type { ControllerProfile, Session, User } from '@/types/auth'
import type { StoredContact } from '@/types/contact'
import { mintUserKey, userKeyVaultKeys } from '@interop/wallet-core/keys'
import { adoptFollowerUserKey } from '@/session/userKeyAdoption'
import { BrowserStore } from './browserStore'
import { StorageManager, type DescriptorLogs } from './storageManager'
import { generateVaultKeys } from '@/stores/testing/vaultKeys'
import { WASRemoteStore } from './wasRemoteStore'

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<Record<string, unknown>>()),
  WAS_BASE_URL: 'https://was.example'
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
    async documents() {
      return [
        {
          kind: 'resource',
          id: 'r1',
          contentType: 'application/json',
          deleted: false,
          updatedAt: '2026-01-01T00:00:00.000Z',
          updatedAtCounter: 0,
          originId: 'stub',
          checkpoint: '1',
          data: { collectionId }
        }
      ]
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
    serviceDescription: TEST_SERVICE_DESCRIPTION,
    pinStore: memoryResourceLogPinStore(),
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
 * (describe), a collection handle (describe, documents), and every raw
 * `was.request()` site the remote-direct backend and the quota read use.
 */
async function driveStore(store: WASRemoteStore): Promise<void> {
  await store.userExists()
  await store.collectionEncryption({ collectionId: 'private-credentials' })
  await store.listSyncedDocuments({ logicalKey: 'privateCredentials' })
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
  descriptorLogs: DescriptorLogs
  provision(owner: { keyAgreementKey: IKeyAgreementKey }): Promise<void>
  rotate(options: {
    from: { keyAgreementKey: IKeyAgreementKey }
    to: { keyAgreementKey: IKeyAgreementKey }
  }): Promise<void>
  seed(collectionId: string, descriptor: CollectionEncryption): void
  epochStamps: Map<string, string[]>
  /**
   * The governing logs' in-memory stores, for a test that rotates one
   * collection's epoch the way another client would.
   */
  stores: MemoryDescriptorStores
} {
  const spaceId = 's-space'
  const descriptors: Record<string, CollectionEncryption> = {}
  // Each collection's descriptor now lives at the verified head of its
  // governing log rather than on the served Collection Description, so the
  // manager reads it through the injected `DescriptorLogs` seam. The fake
  // keeps both in step: `descriptors` is what the assertions read, and the
  // in-memory stores are what the manager reads.
  const descriptorStores = memoryDescriptorStores()
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
    async listSyncedDocuments({ logicalKey }: { logicalKey: string }) {
      return [...resourcesFor(logicalKey)].map(([id, data]) => ({ id, data }))
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
      descriptorStores.seed(id, descriptor)
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
        pull: async () => {},
        // The incoming key is the one survivor, and it never routes through
        // the resolver, so no roster entry is vouched for.
        resolveRecipientKey: async () => null
      })
      descriptorStores.seed(id, descriptors[id])
    }
  }
  return {
    remoteStore,
    descriptors,
    descriptorLogs: descriptorLogsFrom(descriptorStores),
    provision,
    rotate,
    // Replaces a collection's governed descriptor outright, as a host
    // serving a hand-built one would.
    seed(collectionId: string, descriptor: CollectionEncryption) {
      descriptors[collectionId] = descriptor
      descriptorStores.seed(collectionId, descriptor)
    },
    epochStamps,
    stores: descriptorStores
  }
}

/**
 * Installs an empty in-memory `localStorage` for one test, so a residue check
 * runs in the node environment too. The caller removes it with
 * `vi.unstubAllGlobals()`.
 *
 * @returns {{ keys: () => string[] }}
 */
function stubLocalStorage(): { keys: () => string[] } {
  const map = new Map<string, string>()
  vi.stubGlobal('localStorage', {
    get length() {
      return map.size
    },
    key: (index: number) => [...map.keys()][index] ?? null,
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, value: string) => void map.set(key, value),
    removeItem: (key: string) => void map.delete(key),
    clear: () => map.clear()
  })
  return { keys: () => [...map.keys()] }
}

describe('replica-less remote-direct StorageManager', () => {
  it('serves credential and history reads/writes with no local replica and no browser-local residue', async () => {
    const owner = await generateVaultKeys()
    const { remoteStore, descriptorLogs, provision } = makeFakeRemote()
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
      keyResolver: owner.keyResolver
    } as ControllerProfile

    const initClientSpy = vi
      .spyOn(WASRemoteStore, 'initClient')
      .mockResolvedValue({ remoteStore })
    const browserStoreSpy = vi.spyOn(BrowserStore, 'initClient')
    // Production reads the global at call time, so a cache write that leaked
    // past the in-memory strategy would land in this stub.
    const residue = stubLocalStorage()
    try {
      const { storage, userExists } = await StorageManager.initStorageClients({
        user,
        session: { profile, persistence },
        descriptorLogs
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
      const { entries: items } = await storage.listHistoryItems()
      expect(items.length).toBeGreaterThan(0)

      // The descriptor cache rode the strategy's in-memory pair, seeded at
      // login-time acquisition...
      const cached = await persistence
        .descriptorCache({ scope: remoteStore.spaceId })
        .readDescriptor({ collectionId: 'private-credentials' })
      expect(cached?.currentEpoch).toBeDefined()
      // ...and localStorage gained no key at all.
      expect(residue.keys()).toEqual([])
    } finally {
      initClientSpy.mockRestore()
      browserStoreSpy.mockRestore()
      vi.unstubAllGlobals()
    }
  })

  it('serves the contacts round-trip through the remote-direct backend', async () => {
    const owner = await generateVaultKeys()
    const { remoteStore, descriptorLogs, provision } = makeFakeRemote()
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
      keyResolver: owner.keyResolver
    } as ControllerProfile

    const initClientSpy = vi
      .spyOn(WASRemoteStore, 'initClient')
      .mockResolvedValue({ remoteStore })
    try {
      const { storage } = await StorageManager.initStorageClients({
        user,
        session: { profile, persistence },
        descriptorLogs
      })
      await storage.ready()

      // Add + list + load through the facade (real EDV ciphers throughout).
      const stored = await storage.addContact({
        contact: { displayName: 'Alice' }
      })
      expect(stored.contactId).toBeTruthy()
      expect(await storage.listContacts()).toEqual([stored])
      expect(await storage.loadContact({ id: stored.id })).toEqual(stored)

      // Update rewrites the same Resource in place, preserving the identity.
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
    const owner = await generateVaultKeys()
    const {
      remoteStore,
      descriptors,
      descriptorLogs,
      provision,
      rotate,
      epochStamps
    } = makeFakeRemote()
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
      keyResolver: owner.keyResolver
    } as ControllerProfile

    const initClientSpy = vi
      .spyOn(WASRemoteStore, 'initClient')
      .mockResolvedValue({ remoteStore })
    try {
      const { storage } = await StorageManager.initStorageClients({
        user,
        session: { profile, persistence },
        descriptorLogs
      })
      await storage.ready()

      const before = makeCredential('Before')
      await storage.addCredential({ credential: before, user })
      const firstEpoch = descriptors['private-credentials'].currentEpoch

      // The ceremony's in-band half, which fires BEFORE the collection
      // fan-out: the manager takes the rotated key material, and the ciphers
      // stay on the epoch the collections still carry.
      const rotated = await generateVaultKeys()
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
      // ...and the pre-rotation Resource still reads, the rotated key having
      // been escrowed into the epoch it was sealed under.
      const listed = await storage.listCredentials()
      expect(listed.map(({ vc }) => vc)).toEqual(
        expect.arrayContaining([before, after])
      )
    } finally {
      initClientSpy.mockRestore()
    }
  })

  it('refuses to adopt a rotated key before the fan-out has run', async () => {
    const owner = await generateVaultKeys()
    const { remoteStore, descriptorLogs, provision } = makeFakeRemote()
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
      keyResolver: owner.keyResolver
    } as ControllerProfile

    const initClientSpy = vi
      .spyOn(WASRemoteStore, 'initClient')
      .mockResolvedValue({ remoteStore })
    try {
      const { storage } = await StorageManager.initStorageClients({
        user,
        session: { profile, persistence },
        descriptorLogs
      })
      await storage.ready()

      // Why the in-band step holds the keys rather than adopting them: the
      // collections still carry the epoch the rotation is about to retire, so
      // a full adoption there asks the rotated key to open an epoch it is not
      // yet a recipient of. The adoption throws rather than installing
      // refusing ciphers, so its caller learns it did not land.
      const rotated = await generateVaultKeys()
      await expect(storage.adoptRotatedVaultKeys(rotated)).rejects.toThrow(
        expect.objectContaining({ name: 'KeyUnwrapError' })
      )
      expect(storage.strandedCollectionIds).toEqual([])
    } finally {
      initClientSpy.mockRestore()
    }
  })

  it('builds the session with refusing ciphers on stranded collections, and a refresh past the fan-out clears them', async () => {
    const retired = await generateVaultKeys()
    const { remoteStore, descriptorLogs, provision, rotate } = makeFakeRemote()
    // A rotation torn before its fan-out: every collection still names only
    // the retired key, and the session unlocks the current one.
    await provision(retired)
    const current = await generateVaultKeys()

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
      keyAgreementKey: current.keyAgreementKey,
      keyResolver: current.keyResolver
    } as ControllerProfile

    const initClientSpy = vi
      .spyOn(WASRemoteStore, 'initClient')
      .mockResolvedValue({ remoteStore })
    try {
      const { storage } = await StorageManager.initStorageClients({
        user,
        session: { profile, persistence },
        descriptorLogs
      })
      await storage.ready()
      expect([...storage.strandedCollectionIds].sort()).toEqual(
        [...ENCRYPTED_COLLECTION_IDS].sort()
      )
      // A stranded refusal is a not-a-recipient failure, never a purgeable
      // undecryptable one.
      await expect(
        storage.addCredential({ credential: makeCredential('Stranded'), user })
      ).rejects.toThrow(
        expect.objectContaining({
          name: 'KeyUnwrapError',
          message: expect.stringMatching(
            /no key epoch naming the current user key/
          )
        })
      )

      // The fan-out re-epochs every collection onto the current key; the
      // refresh behind it rebuilds the ciphers and clears the stranded set.
      await rotate({ from: retired, to: current })
      await storage.refreshEncryptedDescriptors()
      expect(storage.strandedCollectionIds).toEqual([])
      const credential = makeCredential('After')
      await storage.addCredential({ credential, user })
      const listed = await storage.listCredentials()
      expect(listed.map(({ vc }) => vc)).toEqual([credential])
    } finally {
      initClientSpy.mockRestore()
    }
  })

  it('tells the stranded callback once when a rebuild records a strand, and not before it is set', async () => {
    const retired = await generateVaultKeys()
    const { remoteStore, descriptorLogs, provision, rotate } = makeFakeRemote()
    await provision(retired)
    const current = await generateVaultKeys()

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
      keyAgreementKey: current.keyAgreementKey,
      keyResolver: current.keyResolver
    } as ControllerProfile

    const initClientSpy = vi
      .spyOn(WASRemoteStore, 'initClient')
      .mockResolvedValue({ remoteStore })
    try {
      const { storage } = await StorageManager.initStorageClients({
        user,
        session: { profile, persistence },
        descriptorLogs
      })
      // The construction-time strands are there to read; nothing was told,
      // since no callback existed yet.
      expect(storage.strandedCollectionIds.length).toBeGreaterThan(0)
      const onStranded = vi.fn()
      storage.setOnStranded(onStranded)
      await new Promise(resolve => setTimeout(resolve, 0))
      expect(onStranded).not.toHaveBeenCalled()

      // A refresh that leaves the collections stranded tells it once, with
      // no argument.
      await storage.refreshEncryptedDescriptors()
      await new Promise(resolve => setTimeout(resolve, 0))
      expect(onStranded).toHaveBeenCalledTimes(1)
      expect(onStranded).toHaveBeenCalledWith()

      // A refresh past the fan-out records no strand and tells nothing.
      await rotate({ from: retired, to: current })
      await storage.refreshEncryptedDescriptors()
      await new Promise(resolve => setTimeout(resolve, 0))
      expect(storage.strandedCollectionIds).toEqual([])
      expect(onStranded).toHaveBeenCalledTimes(1)
    } finally {
      initClientSpy.mockRestore()
    }
  })

  it('records a collection the follower adoption reaches before the fan-out as stranded, without throwing', async () => {
    const k1 = await mintUserKey()
    const k2 = await mintUserKey()
    const k1Vault = userKeyVaultKeys({ userKey: k1 })
    const { remoteStore, descriptorLogs, provision } = makeFakeRemote()
    // Another client rotated the roster to K2 and its fan-out tore before
    // reaching any collection: every collection still names K1 alone.
    await provision(k1Vault)

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
      keyAgreementKey: k1Vault.keyAgreementKey,
      keyResolver: k1Vault.keyResolver,
      userKey: k1,
      accountPointer: {
        did: 'did:webvh:QmScid:was.example:space:s-space',
        spaceId: 's-space',
        host: 'https://was.example'
      }
    } as ControllerProfile

    const initClientSpy = vi
      .spyOn(WASRemoteStore, 'initClient')
      .mockResolvedValue({ remoteStore })
    try {
      const { storage } = await StorageManager.initStorageClients({
        user,
        session: { profile, persistence },
        descriptorLogs
      })
      expect(storage.strandedCollectionIds).toEqual([])
      const session = {
        user,
        profile,
        storage,
        persistence,
        isGuest: false,
        disposal: new AbortController().signal,
        encounterGate: Promise.resolve()
      } as Session
      const roster = {
        scheme: 'edv',
        currentEpoch: k2.id,
        epochs: [
          { id: k1.id, recipients: [] },
          { id: k2.id, recipients: [] }
        ]
      } as unknown as CollectionEncryption

      const result = await adoptFollowerUserKey({
        session,
        read: { descriptor: roster, userKey: k2, latestEpochId: k2.id }
      })

      expect(result).toEqual({ adopted: true, position: 'current' })
      expect(session.profile.userKey).toBe(k2)
      expect([...storage.strandedCollectionIds].sort()).toEqual(
        [...ENCRYPTED_COLLECTION_IDS].sort()
      )
    } finally {
      initClientSpy.mockRestore()
    }
  })

  it('fails the session build on a recipient entry that does not unwrap', async () => {
    const owner = await generateVaultKeys()
    const { remoteStore, descriptorLogs, descriptors, provision, seed } =
      makeFakeRemote()
    await provision(owner)
    // The reader IS named in the current epoch, but its entry is corrupt.
    // The build throws `KeyUnwrapError` just as a stranded collection's
    // would, and fails loudly since this is not the stranded shape.
    const corrupt = structuredClone(descriptors['private-credentials'])
    const epoch = corrupt.epochs!.find(
      entry => entry.id === corrupt.currentEpoch
    )!
    const entry = epoch.recipients.find(
      recipient => recipient.header.kid === owner.keyAgreementKey.id
    )! as { encrypted_key: string }
    entry.encrypted_key = entry.encrypted_key.startsWith('A')
      ? `B${entry.encrypted_key.slice(1)}`
      : `A${entry.encrypted_key.slice(1)}`
    seed('private-credentials', corrupt)

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
      keyResolver: owner.keyResolver
    } as ControllerProfile

    const initClientSpy = vi
      .spyOn(WASRemoteStore, 'initClient')
      .mockResolvedValue({ remoteStore })
    try {
      await expect(
        StorageManager.initStorageClients({
          user,
          session: { profile, persistence },
          descriptorLogs
        })
      ).rejects.toThrow(
        expect.objectContaining({
          name: 'KeyUnwrapError',
          cause: expect.objectContaining({
            message: expect.stringMatching(/corrupt entry/)
          })
        })
      )
    } finally {
      initClientSpy.mockRestore()
    }
  })

  it('refuses a replica-less construction with no remote store', async () => {
    const vaultKeys = await generateVaultKeys()
    expect(
      () =>
        new StorageManager({
          vaultKeys,
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

/**
 * A Space handle for a rotation that revokes nothing.
 */
const NO_REVOKE_SPACE = {
  async revoke() {}
} as unknown as Space

/**
 * A transient session over the fake remote holding one contact, beside a
 * stand-in for another client that rotates the `contacts` key epoch and
 * rewrites that contact's head under the fresh epoch. A rekey emits no
 * change-feed entry, so the session's cipher stays on its stale descriptor.
 *
 * The `contacts` epoch starts with two readers beside the owner, so each of
 * two rotations removes one. The contacts cipher absorbs the first rotation
 * itself, through its own once-per-instance refresh. The second meets a
 * cipher whose refresh is spent, which is the case the facade's refresh
 * covers.
 *
 * @returns {Promise<object>}
 */
async function contactsRotationSession(): Promise<{
  storage: StorageManager
  stored: StoredContact
  firstEpoch: string
  epochStamps: Map<string, string[]>
  rotateAndRewrite(contact: ContactData): Promise<string>
  restore(): void
}> {
  const owner = await generateVaultKeys()
  const readers = [await generateVaultKeys(), await generateVaultKeys()]
  const {
    remoteStore,
    descriptors,
    descriptorLogs,
    provision,
    epochStamps,
    stores
  } = makeFakeRemote()
  await provision(owner)
  for (const reader of readers) {
    // Adding a reader escrows it into the current epoch without rotating.
    descriptors.contacts = await addRecipient({
      store: stores.storeFor('contacts'),
      recipient: ownerRecipient({ keyAgreementKey: reader.keyAgreementKey }),
      owner
    })
  }
  const firstEpoch = descriptors.contacts.currentEpoch!

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
    keyResolver: owner.keyResolver
  } as ControllerProfile
  const initClientSpy = vi
    .spyOn(WASRemoteStore, 'initClient')
    .mockResolvedValue({ remoteStore })
  const { storage } = await StorageManager.initStorageClients({
    user,
    session: { profile, persistence },
    descriptorLogs
  })
  await storage.ready()
  const stored = await storage.addContact({
    contact: { displayName: 'Alice' }
  })

  const vouched = [owner, ...readers].map(({ keyAgreementKey }) =>
    ownerRecipient({ keyAgreementKey })
  )
  const rotateAndRewrite = async (contact: ContactData): Promise<string> => {
    const reader = readers.shift()!
    const descriptor = await removeRecipient({
      store: stores.storeFor('contacts'),
      space: NO_REVOKE_SPACE,
      recipientId: reader.keyAgreementKey.id!,
      revoke: [],
      resolveRecipientKey: async kid =>
        vouched.find(recipient => recipient.id === kid) ?? null
    })
    descriptors.contacts = descriptor
    // The other client rewrites the head in place under the fresh epoch.
    const cipher = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'contacts',
      idDerivation: 'random',
      encryption: descriptor
    })
    const found = await remoteStore.getSyncedResourceWithEtag({
      logicalKey: 'contacts',
      resourceId: stored.id
    })
    const head: ContactHeadPayload = {
      contactId: stored.contactId,
      updatedAt: new Date().toISOString(),
      writerId: 'other-client-writer',
      contact
    }
    const { envelope, epoch } = await cipher.encryptUpdate!({
      id: stored.id,
      data: head as unknown as Json,
      current: found!.data
    })
    await remoteStore.putSyncedResource({
      logicalKey: 'contacts',
      resourceId: stored.id,
      body: envelope,
      epoch,
      ifMatch: found!.etag
    })
    return descriptor.currentEpoch!
  }

  return {
    storage,
    stored,
    firstEpoch,
    epochStamps,
    rotateAndRewrite,
    restore: () => initClientSpy.mockRestore()
  }
}

describe('replica-less contacts point reads after a rotation', () => {
  it('re-runs an edit once under the fresh epoch when a rotation lands between the read and the edit', async () => {
    const session = await contactsRotationSession()
    const { storage, stored, firstEpoch, epochStamps, rotateAndRewrite } =
      session
    try {
      const secondEpoch = await rotateAndRewrite({ displayName: 'Ally' })
      // The read the edit is built on.
      const loaded = await storage.loadContact({ id: stored.id })
      expect(loaded?.contact).toEqual({ displayName: 'Ally' })

      // Another client rotates again and rewrites the head before the edit.
      const thirdEpoch = await rotateAndRewrite({ displayName: 'Allie' })
      const updated = await storage.updateContact({
        id: stored.id,
        contact: { displayName: 'Alicia' }
      })
      expect(updated.id).toBe(stored.id)
      expect(updated.contactId).toBe(stored.contactId)

      // One write of the edit, sealed under the fresh epoch: the add, the
      // other client's two rewrites, then the edit.
      expect(epochStamps.get('contacts')).toEqual([
        firstEpoch,
        secondEpoch,
        thirdEpoch,
        thirdEpoch
      ])
      const head = await storage.loadContact({ id: stored.id })
      expect(head?.contact).toEqual({ displayName: 'Alicia' })
      // And one revision for it.
      const revisions = await storage.listContactRevisions({
        contactId: stored.contactId
      })
      expect(revisions.map(({ action }) => action)).toEqual([
        'update',
        'create'
      ])
    } finally {
      session.restore()
    }
  })

  it('loads a head sealed under a rotated epoch instead of resolving undefined', async () => {
    const session = await contactsRotationSession()
    const { storage, stored, rotateAndRewrite } = session
    try {
      await rotateAndRewrite({ displayName: 'Ally' })
      expect(await storage.listContacts()).toEqual([
        expect.objectContaining({ contact: { displayName: 'Ally' } })
      ])

      await rotateAndRewrite({ displayName: 'Allie' })
      const loaded = await storage.loadContact({ id: stored.id })
      expect(loaded).toEqual(
        expect.objectContaining({
          id: stored.id,
          contactId: stored.contactId,
          contact: { displayName: 'Allie' }
        })
      )
    } finally {
      session.restore()
    }
  })

  it("records a delete revision carrying the rotated head's snapshot", async () => {
    const session = await contactsRotationSession()
    const { storage, stored, rotateAndRewrite } = session
    try {
      await rotateAndRewrite({ displayName: 'Ally' })
      await storage.loadContact({ id: stored.id })

      await rotateAndRewrite({ displayName: 'Allie' })
      await storage.deleteContact({ id: stored.id })
      expect(await storage.listContacts()).toEqual([])
      const revisions = await storage.listContactRevisions({
        contactId: stored.contactId
      })
      expect(
        revisions.map(({ action, snapshot }) => [action, snapshot])
      ).toEqual([
        ['delete', { displayName: 'Allie' }],
        ['create', { displayName: 'Alice' }]
      ])
    } finally {
      session.restore()
    }
  })
})
