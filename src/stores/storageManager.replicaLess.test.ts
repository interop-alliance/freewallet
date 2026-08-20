/**
 * Unit tests for the capability-bound, replica-less remote storage posture:
 *
 * - `WASRemoteStore` accepts an optional invocation capability and every
 *   request it makes rides it -- the navigational handles through the one
 *   private Space-handle helper, and the raw `was.request()` escape hatch
 *   sites directly. Absent the option, every handle and request carries no
 *   capability (root invocations, byte-identical to before).
 * - `StorageManager.initStorageClients` in the transient posture constructs
 *   no `BrowserStore` (the versioned RxDB open alone durably creates the
 *   per-user database), routes every synced-collection operation through the
 *   remote-direct backend, starts no replication (no local end exists), and
 *   keeps the descriptor/meta caches on the persistence handle's in-memory
 *   pair -- localStorage gains no key.
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
import { ensureFirstEpoch, ownerRecipient } from '@interop/was-client/edv'
import { cidFrom } from '@interop/was-client/sync'
import type { Json } from '@/lib/sync'
import { transientSessionPersistence } from '@/session/persistence'
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
  controller: 'did:key:z6MkCompanion',
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
 * A structural fake of `WASRemoteStore` for the replica-less StorageManager:
 * per-collection descriptors served from `collectionEncryption`, and an
 * in-memory synced-resource map behind the remote-direct read/write surface.
 */
function makeFakeRemote(): {
  remoteStore: WASRemoteStore
  descriptors: Record<string, CollectionEncryption>
  provision(owner: { keyAgreementKey: IKeyAgreementKey }): Promise<void>
} {
  const spaceId = 's-space'
  const descriptors: Record<string, CollectionEncryption> = {}
  const logicalToId: Record<string, string> = {
    privateCredentials: 'private-credentials',
    walletActivity: 'wallet-activity',
    publicCredentials: 'public-credentials'
  }
  const resources = new Map<string, Map<string, Json>>()
  const resourcesFor = (logicalKey: string): Map<string, Json> => {
    const id = logicalToId[logicalKey] ?? logicalKey
    let map = resources.get(id)
    if (!map) {
      map = new Map<string, Json>()
      resources.set(id, map)
    }
    return map
  }
  const remoteStore = {
    spaceId,
    spaceUrl: `https://was.example/space/${spaceId}`,
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
    async putSyncedResource({
      logicalKey,
      resourceId,
      body
    }: {
      logicalKey: string
      resourceId: string
      body: Json
    }) {
      const map = resourcesFor(logicalKey)
      if (map.has(resourceId)) {
        return { created: false }
      }
      map.set(resourceId, body)
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
    }
  } as unknown as WASRemoteStore
  // A CAS-backed minimal Collection so the real `ensureFirstEpoch` installs
  // real epoch descriptors (what provisioning would have written).
  const provision = async (owner: { keyAgreementKey: IKeyAgreementKey }) => {
    for (const id of ['private-credentials', 'wallet-activity']) {
      let version = 0
      const fakeCollection = {
        async describeWithEtag() {
          return {
            description: {
              name: id,
              encryption: descriptors[id] ?? { scheme: 'edv' }
            },
            etag: `v${version}`
          }
        },
        async replaceDescription(
          fields: { encryption: CollectionEncryption },
          { ifMatch }: { ifMatch?: string }
        ) {
          if (ifMatch !== `v${version}`) {
            throw new Error('stale etag')
          }
          descriptors[id] = fields.encryption
          version++
        }
      }
      const { descriptor } = await ensureFirstEpoch({
        collection: fakeCollection as never,
        recipients: [ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })]
      })
      descriptors[id] = descriptor
    }
  }
  return { remoteStore, descriptors, provision }
}

describe('replica-less remote-direct StorageManager', () => {
  it('serves credential and history reads/writes with no local replica and no durable residue', async () => {
    const owner = await generateKey()
    const { remoteStore, provision } = makeFakeRemote()
    await provision(owner)

    const persistence = transientSessionPersistence()
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
      // The transient posture trusts the keyring hit that produced it.
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

      // The descriptor cache rode the handle's in-memory pair, seeded at
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

  it('refuses a replica-less construction with no remote store', () => {
    expect(
      () =>
        new StorageManager({
          persistence: transientSessionPersistence()
        })
    ).toThrow(/remote WAS store/)
  })
})
