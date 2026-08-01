/**
 * Unit tests for StorageManager's multi-recipient collection sharing surface:
 * `shareCollection` / `unshareCollection` / `listCollectionShares`, plus the
 * transparent unknown-epoch descriptor refresh on `listCredentials`.
 *
 * The remote WAS store is a structural fake -- an in-memory Collection
 * Description with a compare-and-swap etag (so the real `initRecipients` /
 * `addRecipient` / `removeRecipient` exercise their real write path against it),
 * a `collectionEncryption` served from that same description, and a `revoke`
 * recorder on the Space handle. The local store is a real BrowserStore on
 * memory RxDB, and the ciphers are real EDV codecs over freshly generated
 * X25519 keys, so an epoch written under one descriptor really fails to decrypt
 * under a stale one.
 *
 * @vitest-environment node
 */
import { afterEach, describe, expect, it } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import {
  PreconditionFailedError,
  ValidationError,
  type Collection,
  type CollectionEncryption,
  type IZcap,
  type Space
} from '@interop/was-client'
import { initRecipients, removeRecipient } from '@interop/was-client/edv'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import type { ControllerProfile, User } from '@/types/auth'
import { cidFrom } from '@interop/was-client/sync'
import type { Json } from '@/lib/sync'
import { BrowserStore } from './browserStore'
import {
  createEdvDocCipher,
  ownerRecipient,
  type DocCipher
} from '@interop/was-client/edv'
import { StorageManager } from './storageManager'
import type { WASRemoteStore } from './wasRemoteStore'

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
 * A CAS-backed in-memory `Collection`: one Collection Description with an
 * `encryption` descriptor and a monotonic version counter used as the compare-and-
 * swap etag, so the real recipient operations run their real write path.
 */
function makeFakeCollection(collectionId: string): {
  collection: Collection
  descriptor(): CollectionEncryption
} {
  let version = 0
  let description: {
    name?: string
    encryption: CollectionEncryption
  } = { name: collectionId, encryption: { scheme: 'edv' } }
  const fake = {
    async describeWithEtag() {
      return { description: { ...description }, etag: `v${version}` }
    },
    async replaceDescription(
      fields: { name?: string; encryption: CollectionEncryption },
      { ifMatch }: { ifMatch?: string }
    ) {
      if (ifMatch !== `v${version}`) {
        throw new PreconditionFailedError('stale collection description etag')
      }
      description = { ...description, ...fields }
      version++
    }
  }
  return {
    collection: fake as unknown as Collection,
    descriptor: () => description.encryption
  }
}

/**
 * A structural fake of WASRemoteStore over CAS-backed collections and a
 * revoke-recording Space handle. `collectionEncryption` and `collectionHandle`
 * share the same per-collection instance, so a recipient op through the handle
 * is visible to a later descriptor read.
 */
function makeFakeRemote(): {
  remoteStore: WASRemoteStore
  revoked: unknown[]
  collection(collectionId: string): ReturnType<typeof makeFakeCollection>
  seedResource(options: {
    logicalKey: string
    resourceId: string
    body: Json
  }): void
} {
  const spaceId = 's-space'
  const spaceUrl = 'https://was.example/space/s-space'
  const revoked: unknown[] = []
  const collections = new Map<string, ReturnType<typeof makeFakeCollection>>()
  const collection = (collectionId: string) => {
    let entry = collections.get(collectionId)
    if (!entry) {
      entry = makeFakeCollection(collectionId)
      collections.set(collectionId, entry)
    }
    return entry
  }
  // The raw synced-resource bodies keyed by logical collection key -- what the
  // remote-direct backend reads/writes over `listSyncedResources` etc.
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
  const space = {
    async revoke(zcap: unknown) {
      revoked.push(zcap)
    }
  } as unknown as Space
  const remoteStore = {
    spaceId,
    spaceUrl,
    async collectionEncryption({ collectionId }: { collectionId: string }) {
      return collection(collectionId).descriptor()
    },
    async ensureEncryptedCollection({ id }: { id: string }) {
      // The fake collection is declared `edv` from birth, so this mirrors the
      // real method's "already encrypted" return: the current descriptor (with any
      // epochs), never re-declaring.
      return collection(id).descriptor()
    },
    collectionHandle({ collectionId }: { collectionId: string }) {
      return collection(collectionId).collection
    },
    spaceHandle() {
      return space
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
  const seedResource = ({
    logicalKey,
    resourceId,
    body
  }: {
    logicalKey: string
    resourceId: string
    body: Json
  }) => {
    resourcesFor(logicalKey).set(resourceId, body)
  }
  return { remoteStore, revoked, collection, seedResource }
}

/**
 * Builds the encrypted-collection ciphers over the owner's keys and the given
 * per-collection descriptors (keyed by WAS collection id), mirroring what
 * StorageManager builds internally.
 */
async function buildCiphers(
  owner: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver },
  descriptors: Record<string, CollectionEncryption>
): Promise<Record<string, DocCipher>> {
  const specs: Array<[string, string]> = [
    ['privateCredentials', 'private-credentials'],
    ['walletActivity', 'wallet-activity']
  ]
  const entries = await Promise.all(
    specs.map(async ([key, id]) => [
      key,
      await createEdvDocCipher({
        keyAgreementKey: owner.keyAgreementKey,
        keyResolver: owner.keyResolver,
        collectionId: id,
        encryption: descriptors[id]
      })
    ])
  )
  return Object.fromEntries(entries)
}

/**
 * A stub zcapClient whose `delegate` records its arguments and returns a
 * distinct stub zcap document per call.
 */
function makeFakeZcapClient(): {
  zcapClient: ControllerProfile['zcapClient']
  calls: Array<Record<string, unknown>>
} {
  const calls: Array<Record<string, unknown>> = []
  const zcapClient = {
    async delegate(options: Record<string, unknown>) {
      calls.push(options)
      return { id: `urn:zcap:delegated:${calls.length}` }
    }
  } as unknown as ControllerProfile['zcapClient']
  return { zcapClient, calls }
}

let userCounter = 0
const openStores: BrowserStore[] = []

async function initLocalStore(
  ciphers: Record<string, DocCipher>
): Promise<{ localStore: BrowserStore; user: User }> {
  userCounter += 1
  const user: User = {
    id: `did:key:z6MkShareUser${userCounter}`,
    email: 'test@example.com'
  }
  const { localStore } = await BrowserStore.initClient({
    user,
    storage: getRxStorageMemory(),
    ciphers
  })
  await localStore.ensureUserCollections({ user })
  openStores.push(localStore)
  return { localStore, user }
}

/**
 * An owner profile: the vault keys, a stub delegation signer, and a truthy
 * `keyAgent` (the root key the share/unshare guards require for delegation).
 */
function makeProfile(
  owner: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver },
  zcapClient: ControllerProfile['zcapClient']
): ControllerProfile {
  return {
    keyAgreementKey: owner.keyAgreementKey,
    keyResolver: owner.keyResolver,
    zcapClient,
    keyAgent: { id: 'did:key:z6MkOwnerAgent' }
  } as unknown as ControllerProfile
}

/**
 * The JWE-recipient kids of a descriptor's current epoch roster.
 */
function currentEpochKids(descriptor: CollectionEncryption): string[] {
  const epoch = descriptor.epochs?.find(
    entry => entry.id === descriptor.currentEpoch
  )
  return (epoch?.recipients ?? []).map(recipient => recipient.header.kid)
}

afterEach(async () => {
  for (const store of openStores) {
    await store.wipeStorage()
  }
  openStores.length = 0
})

describe('StorageManager.shareCollection', () => {
  it('first share mints an epoch with the owner as recipient and delegates a GET/HEAD zcap', async () => {
    const owner = await generateKey()
    const reader = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore, user } = await initLocalStore(ciphers)
    const { remoteStore } = makeFakeRemote()
    const { zcapClient, calls } = makeFakeZcapClient()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })

    const { descriptor } = await storage.shareCollection({
      profile: makeProfile(owner, zcapClient),
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: reader.keyAgreementKey }),
      controller: 'did:key:z6MkReader'
    })

    // Read axis: the first epoch exists, and both the owner (recipient zero)
    // and the new reader are on its roster.
    expect(descriptor.epochs).toHaveLength(1)
    expect(descriptor.currentEpoch).toBeDefined()
    expect(currentEpochKids(descriptor)).toEqual(
      expect.arrayContaining([
        owner.keyAgreementKey.id,
        reader.keyAgreementKey.id
      ])
    )

    // Pull axis: exactly one read-only delegation on the collection URL.
    expect(calls).toHaveLength(1)
    expect(calls[0].allowedActions).toEqual(['GET', 'HEAD'])
    expect(calls[0].controller).toBe('did:key:z6MkReader')
    expect(calls[0].invocationTarget).toBe(
      'https://was.example/space/s-space/private-credentials'
    )

    // The share was recorded (with the delegated zcap for later revocation).
    const history = await storage.listHistoryItems()
    const shareEntry = history.find(({ doc }) =>
      doc.type?.includes('CollectionShare')
    )
    expect(shareEntry).toBeDefined()
    expect(
      (shareEntry!.doc.object as { zcap?: { id?: string } }).zcap?.id
    ).toBe('urn:zcap:delegated:1')
  })

  it('a second share adds a reader without rotating the epoch', async () => {
    const owner = await generateKey()
    const readerA = await generateKey()
    const readerB = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore, user } = await initLocalStore(ciphers)
    const { remoteStore } = makeFakeRemote()
    const { zcapClient } = makeFakeZcapClient()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })
    const profile = makeProfile(owner, zcapClient)

    const { descriptor: descriptor1 } = await storage.shareCollection({
      profile,
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: readerA.keyAgreementKey }),
      controller: 'did:key:z6MkReaderA'
    })
    const { descriptor: descriptor2 } = await storage.shareCollection({
      profile,
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: readerB.keyAgreementKey }),
      controller: 'did:key:z6MkReaderB'
    })

    // Adds are cheap: the current epoch is unchanged, but the roster grew.
    expect(descriptor2.currentEpoch).toBe(descriptor1.currentEpoch)
    expect(descriptor2.epochs).toHaveLength(1)
    expect(currentEpochKids(descriptor2)).toEqual(
      expect.arrayContaining([
        owner.keyAgreementKey.id,
        readerA.keyAgreementKey.id,
        readerB.keyAgreementKey.id
      ])
    )
  })
})

describe('StorageManager.unshareCollection', () => {
  it('rotates the epoch and revokes the recorded zcap(s)', async () => {
    const owner = await generateKey()
    const reader = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore, user } = await initLocalStore(ciphers)
    const { remoteStore, revoked } = makeFakeRemote()
    const { zcapClient } = makeFakeZcapClient()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })
    const profile = makeProfile(owner, zcapClient)

    const { descriptor: shared } = await storage.shareCollection({
      profile,
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: reader.keyAgreementKey }),
      controller: 'did:key:z6MkReader'
    })

    const rotated = await storage.unshareCollection({
      profile,
      user,
      collectionId: 'private-credentials',
      recipientId: reader.keyAgreementKey.id!
    })

    // Read axis: the epoch rotated and the removed reader is off the new roster.
    expect(rotated.currentEpoch).not.toBe(shared.currentEpoch)
    expect(currentEpochKids(rotated)).toEqual([owner.keyAgreementKey.id])
    expect(currentEpochKids(rotated)).not.toContain(reader.keyAgreementKey.id)

    // Pull axis: the recorded delegated zcap was handed to the revoke recorder.
    expect(revoked).toEqual([{ id: 'urn:zcap:delegated:1' }])

    // The unshare was recorded (no zcap on it).
    const history = await storage.listHistoryItems()
    expect(
      history.some(({ doc }) => doc.type?.includes('CollectionUnshare'))
    ).toBe(true)
  })

  it('lists current shares from the descriptor roster minus the owner', async () => {
    const owner = await generateKey()
    const reader = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore, user } = await initLocalStore(ciphers)
    const { remoteStore } = makeFakeRemote()
    const { zcapClient } = makeFakeZcapClient()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })

    await storage.shareCollection({
      profile: makeProfile(owner, zcapClient),
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: reader.keyAgreementKey }),
      controller: 'did:key:z6MkReader'
    })

    const shares = await storage.listCollectionShares({
      collectionId: 'private-credentials'
    })
    expect(shares).toHaveLength(1)
    expect(shares[0].recipientId).toBe(reader.keyAgreementKey.id)
    expect(shares[0].controller).toBe('did:key:z6MkReader')
  })

  it('carries a connected app name and origin through to the listing', async () => {
    const owner = await generateKey()
    const reader = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore, user } = await initLocalStore(ciphers)
    const { remoteStore } = makeFakeRemote()
    const { zcapClient } = makeFakeZcapClient()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })

    const { zcap } = await storage.shareCollection({
      profile: makeProfile(owner, zcapClient),
      user,
      collectionId: 'private-credentials',
      recipient: ownerRecipient({ keyAgreementKey: reader.keyAgreementKey }),
      controller: 'did:key:z6MkReader',
      app: { name: 'Text Editor', origin: 'https://app.example' }
    })

    // The pull zcap comes back to the caller (it goes in the response VP).
    expect(zcap.id).toBe('urn:zcap:delegated:1')

    const shares = await storage.listCollectionShares({
      collectionId: 'private-credentials'
    })
    expect(shares[0]).toMatchObject({
      appName: 'Text Editor',
      appOrigin: 'https://app.example'
    })
  })
})

describe('StorageManager.revokeAppGrants', () => {
  const APP_ORIGIN = 'https://app.example'
  const APP_SUBJECT = 'did:key:z6MkAppSubject'

  /**
   * A minimal delegated zcap document (enough to satisfy the revocation scan:
   * a `parentCapability` marks it delegated, a `controller` binds it to the app
   * key, and `expires` gates the already-expired skip).
   */
  function delegatedZcap({
    id,
    controller = APP_SUBJECT,
    expires
  }: {
    id: string
    controller?: string
    expires: string
  }): IZcap {
    return {
      '@context': ['https://w3id.org/zcap/v1'],
      id,
      parentCapability: 'urn:zcap:root:https%3A%2F%2Fwas.example%2Fspace%2Fx',
      controller,
      invocationTarget: 'https://was.example/space/x/private-credentials',
      allowedAction: ['GET', 'HEAD'],
      expires,
      proof: {} as unknown
    } as unknown as IZcap
  }

  /**
   * A remote store whose `spaceHandle().revoke` is the supplied recorder, over
   * the shared CAS-backed collections (unused by revocation but present for a
   * well-formed store).
   */
  function makeRevokeRemote(
    revoke: (zcap: unknown) => Promise<void>
  ): WASRemoteStore {
    const collections = new Map<string, ReturnType<typeof makeFakeCollection>>()
    const space = { revoke } as unknown as Space
    return {
      spaceId: 's-space',
      spaceUrl: 'https://was.example/space/s-space',
      collectionHandle({ collectionId }: { collectionId: string }) {
        let entry = collections.get(collectionId)
        if (!entry) {
          entry = makeFakeCollection(collectionId)
          collections.set(collectionId, entry)
        }
        return entry.collection
      },
      spaceHandle() {
        return space
      }
    } as unknown as WASRemoteStore
  }

  async function seedLogin(
    storage: StorageManager,
    user: User,
    grants: Array<{
      id: string
      target: string
      allowedActions: string[]
      expires: string
      zcap?: IZcap
    }>
  ) {
    await storage.addHistoryLogin({
      user,
      origin: APP_ORIGIN,
      grants,
      appConnect: { name: 'Example App', firstRun: true }
    })
  }

  it('revokes the active grant and skips expired and legacy entries', async () => {
    const owner = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore, user } = await initLocalStore(ciphers)
    const revoked: unknown[] = []
    const remoteStore = makeRevokeRemote(async zcap => {
      revoked.push(zcap)
    })
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })
    const future = new Date(Date.now() + 1_000_000).toISOString()
    const past = new Date(Date.now() - 1_000_000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-active',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET', 'HEAD'],
        expires: future,
        zcap: delegatedZcap({ id: 'z-active', expires: future })
      },
      {
        id: 'g-expired',
        target: 'https://was.example/space/x/wallet-activity',
        allowedActions: ['GET'],
        expires: past,
        zcap: delegatedZcap({ id: 'z-expired', expires: past })
      },
      {
        id: 'g-legacy',
        target: 'https://was.example/space/x/public-credentials',
        allowedActions: ['GET'],
        expires: future
      }
    ])

    const outcome = await storage.revokeAppGrants({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    expect(outcome).toEqual({ revoked: 1, skipped: 2 })
    expect(revoked).toHaveLength(1)
    expect((revoked[0] as { id: string }).id).toBe('z-active')
  })

  it('skips grants delegated to a different controller', async () => {
    const owner = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore, user } = await initLocalStore(ciphers)
    const revoked: unknown[] = []
    const remoteStore = makeRevokeRemote(async zcap => {
      revoked.push(zcap)
    })
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })
    const future = new Date(Date.now() + 1_000_000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-other',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: delegatedZcap({
          id: 'z-other',
          controller: 'did:key:z6MkSomeoneElse',
          expires: future
        })
      }
    ])

    const outcome = await storage.revokeAppGrants({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    expect(outcome).toEqual({ revoked: 0, skipped: 1 })
    expect(revoked).toHaveLength(0)
  })

  it('swallows ValidationError from an already-revoked grant', async () => {
    const owner = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore, user } = await initLocalStore(ciphers)
    const remoteStore = makeRevokeRemote(async () => {
      throw new ValidationError('already revoked')
    })
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })
    const future = new Date(Date.now() + 1_000_000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-active',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: delegatedZcap({ id: 'z-active', expires: future })
      }
    ])

    const outcome = await storage.revokeAppGrants({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    expect(outcome).toEqual({ revoked: 0, skipped: 1 })
  })

  it('propagates a non-ValidationError revoke failure', async () => {
    const owner = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore, user } = await initLocalStore(ciphers)
    const remoteStore = makeRevokeRemote(async () => {
      throw new Error('server unreachable')
    })
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })
    const future = new Date(Date.now() + 1_000_000).toISOString()

    await seedLogin(storage, user, [
      {
        id: 'g-active',
        target: 'https://was.example/space/x/private-credentials',
        allowedActions: ['GET'],
        expires: future,
        zcap: delegatedZcap({ id: 'z-active', expires: future })
      }
    ])

    await expect(
      storage.revokeAppGrants({ origin: APP_ORIGIN, subjectDid: APP_SUBJECT })
    ).rejects.toThrow('server unreachable')
  })

  it('is a no-op when no remote store is configured', async () => {
    const owner = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      localStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })

    const outcome = await storage.revokeAppGrants({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    expect(outcome).toEqual({ revoked: 0, skipped: 0 })
  })
})

describe('StorageManager.provisionAppCollection', () => {
  it('first provision mints an epoch with the owner and the app recipient', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore } = await initLocalStore(ciphers)
    const { remoteStore } = makeFakeRemote()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })

    const descriptor = await storage.provisionAppCollection({
      collectionId: 'app-docs',
      appRecipient: ownerRecipient({ keyAgreementKey: app.keyAgreementKey })
    })

    expect(descriptor.epochs).toHaveLength(1)
    expect(currentEpochKids(descriptor)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, app.keyAgreementKey.id])
    )
  })

  it('a reconnect after revoke re-adds the app without a second epoch', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore } = await initLocalStore(ciphers)
    const { remoteStore } = makeFakeRemote()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })
    const appRecipient = ownerRecipient({
      keyAgreementKey: app.keyAgreementKey
    })

    const descriptor1 = await storage.provisionAppCollection({
      collectionId: 'app-docs',
      appRecipient
    })
    // A revoke rotates the app off (owner alone on a fresh epoch).
    await removeRecipient({
      collection: remoteStore.collectionHandle({ collectionId: 'app-docs' }),
      space: remoteStore.spaceHandle(),
      recipientId: app.keyAgreementKey.id!,
      revoke: []
    })
    // Reconnect: the app is escrowed back in (add, not a rotation, so the
    // roster grows but the current epoch is the post-revoke one).
    const descriptor2 = await storage.provisionAppCollection({
      collectionId: 'app-docs',
      appRecipient
    })

    expect(descriptor1.currentEpoch).toBeDefined()
    expect(currentEpochKids(descriptor2)).toEqual(
      expect.arrayContaining([owner.keyAgreementKey.id, app.keyAgreementKey.id])
    )
  })

  it('is a no-op when the app is already a recipient of the current epoch', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore } = await initLocalStore(ciphers)
    const { remoteStore, collection } = makeFakeRemote()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })
    const appRecipient = ownerRecipient({
      keyAgreementKey: app.keyAgreementKey
    })

    const descriptor1 = await storage.provisionAppCollection({
      collectionId: 'app-docs',
      appRecipient
    })
    const descriptor2 = await storage.provisionAppCollection({
      collectionId: 'app-docs',
      appRecipient
    })

    // No rotation, no new epoch: the descriptor is unchanged.
    expect(descriptor2.currentEpoch).toBe(descriptor1.currentEpoch)
    expect(collection('app-docs').descriptor().epochs).toHaveLength(1)
  })
})

describe('StorageManager.revokeAppCollectionRecipients', () => {
  const APP_ORIGIN = 'https://app.example'
  const APP_SUBJECT = 'did:key:z6MkAppSubjectR'

  function delegatedZcap({
    id,
    target,
    expires
  }: {
    id: string
    target: string
    expires: string
  }): IZcap {
    return {
      '@context': ['https://w3id.org/zcap/v1'],
      id,
      parentCapability: 'urn:zcap:root:https%3A%2F%2Fwas.example%2Fspace%2Fx',
      controller: APP_SUBJECT,
      invocationTarget: target,
      allowedAction: ['GET', 'HEAD'],
      expires,
      proof: {} as unknown
    } as unknown as IZcap
  }

  it('rotates the app off each app-provisioned collection and revokes its grant', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore, user } = await initLocalStore(ciphers)
    const { remoteStore, revoked } = makeFakeRemote()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })

    await storage.provisionAppCollection({
      collectionId: 'app-docs',
      appRecipient: ownerRecipient({ keyAgreementKey: app.keyAgreementKey })
    })

    const future = new Date(Date.now() + 1_000_000).toISOString()
    const target = 'https://was.example/space/s-space/app-docs'
    await storage.addHistoryLogin({
      user,
      origin: APP_ORIGIN,
      grants: [
        {
          id: 'g-app-docs',
          target,
          allowedActions: ['GET', 'HEAD'],
          expires: future,
          zcap: delegatedZcap({ id: 'z-app-docs', target, expires: future })
        }
      ],
      appConnect: { name: 'Example App', firstRun: true }
    })

    const outcome = await storage.revokeAppCollectionRecipients({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    expect(outcome).toEqual({ collections: 1, rotated: 1, failed: 0 })
    // Read axis: the app is off the new current epoch; the owner remains.
    const descriptor = await remoteStore.collectionEncryption({
      collectionId: 'app-docs'
    })
    expect(currentEpochKids(descriptor!)).toEqual([owner.keyAgreementKey.id])
    // Pull axis: the recorded grant was revoked.
    expect((revoked as Array<{ id: string }>).map(zcap => zcap.id)).toContain(
      'z-app-docs'
    )
  })

  it('ignores grants on standard/protected collections', async () => {
    const owner = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore, user } = await initLocalStore(ciphers)
    const { remoteStore, revoked } = makeFakeRemote()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })

    const future = new Date(Date.now() + 1_000_000).toISOString()
    const target = 'https://was.example/space/s-space/private-credentials'
    await storage.addHistoryLogin({
      user,
      origin: APP_ORIGIN,
      grants: [
        {
          id: 'g-std',
          target,
          allowedActions: ['GET', 'HEAD'],
          expires: future,
          zcap: delegatedZcap({ id: 'z-std', target, expires: future })
        }
      ],
      appConnect: { name: 'Example App', firstRun: true }
    })

    const outcome = await storage.revokeAppCollectionRecipients({
      origin: APP_ORIGIN,
      subjectDid: APP_SUBJECT
    })

    expect(outcome).toEqual({ collections: 0, rotated: 0, failed: 0 })
    expect(revoked).toHaveLength(0)
  })
})

describe('StorageManager.decryptCollectionResource (app collection)', () => {
  it('decrypts an app-collection envelope with the vault KAK', async () => {
    const owner = await generateKey()
    const app = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore } = await initLocalStore(ciphers)
    const { remoteStore } = makeFakeRemote()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })

    const descriptor = await storage.provisionAppCollection({
      collectionId: 'app-docs',
      appRecipient: ownerRecipient({ keyAgreementKey: app.keyAgreementKey })
    })

    // A document written under the current epoch (the owner is recipient zero,
    // so a cipher built from the descriptor over the owner's keys can write it).
    const ownerCipher = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'app-docs',
      encryption: descriptor
    })
    const doc = { title: 'App note', body: 'hello' }
    const { envelope } = await ownerCipher.encrypt({
      data: doc as unknown as Json
    })

    const decrypted = await storage.decryptCollectionResource({
      collectionId: 'app-docs',
      data: envelope
    })
    expect(decrypted).toEqual(doc)
  })

  it('returns undefined for an app collection with no epoch roster', async () => {
    const owner = await generateKey()
    const ciphers = await buildCiphers(owner, {})
    const { localStore } = await initLocalStore(ciphers)
    const { remoteStore } = makeFakeRemote()
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: {}
    })

    // A well-formed EDV envelope shape, but the collection was never provisioned
    // multi-recipient, so the wallet has nothing to decrypt it with.
    const envelope = {
      id: 'z-fake',
      sequence: 0,
      jwe: { recipients: [{ header: { kid: 'did:key:zStranger#zStranger' } }] }
    } as unknown as Json

    const decrypted = await storage.decryptCollectionResource({
      collectionId: 'never-provisioned',
      data: envelope
    })
    expect(decrypted).toBeUndefined()
  })
})

describe('StorageManager unknown-epoch refresh', () => {
  it('re-reads the descriptor and returns a credential written under a newer epoch', async () => {
    const owner = await generateKey()
    const extra = await generateKey()
    const { remoteStore } = makeFakeRemote()

    // The fake collection starts on epoch 1 (owner + a soon-removed reader).
    const collectionHandle = remoteStore.collectionHandle({
      collectionId: 'private-credentials'
    })
    const descriptor1 = await initRecipients({
      collection: collectionHandle,
      recipients: [
        ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
        ownerRecipient({ keyAgreementKey: extra.keyAgreementKey })
      ]
    })

    // StorageManager (and the local store) build ciphers from the STALE
    // descriptor 1.
    const ciphers = await buildCiphers(owner, {
      'private-credentials': descriptor1
    })
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      vaultKeys: owner,
      descriptors: { 'private-credentials': descriptor1 }
    })

    // A rekey rotates the fake collection to epoch 2 (emitting no change feed
    // entry): removing the extra reader leaves the owner alone on the new
    // epoch.
    const descriptor2 = await removeRecipient({
      collection: collectionHandle,
      space: remoteStore.spaceHandle(),
      recipientId: extra.keyAgreementKey.id!,
      revoke: []
    })
    expect(descriptor2.currentEpoch).not.toBe(descriptor1.currentEpoch)

    // A credential is written locally under epoch 2 (as replication would land
    // it), which the stale epoch-1 cipher cannot route.
    const epoch2Cipher = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials',
      encryption: descriptor2
    })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    const { id, envelope, epoch } = await epoch2Cipher.encrypt({
      data: credential as unknown as Json
    })
    expect(epoch).toBe(descriptor2.currentEpoch)
    await localStore.rxCollection('privateCredentials').insert({
      id,
      updatedAt: new Date().toISOString(),
      version: 0,
      epoch,
      data: envelope
    })

    // listCredentials transparently refreshes the descriptor from the fake remote,
    // rebuilds the cipher, and returns the credential.
    const listed = await storage.listCredentials()
    expect(listed).toEqual([{ cid, vc: credential }])
  })

  it('remote-direct: refreshes the descriptor and returns a fresh-epoch credential', async () => {
    const owner = await generateKey()
    const extra = await generateKey()
    const { remoteStore, seedResource } = makeFakeRemote()

    const collectionHandle = remoteStore.collectionHandle({
      collectionId: 'private-credentials'
    })
    const descriptor1 = await initRecipients({
      collection: collectionHandle,
      recipients: [
        ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
        ownerRecipient({ keyAgreementKey: extra.keyAgreementKey })
      ]
    })

    // The remote-direct popup backend builds ciphers from the STALE descriptor 1.
    const ciphers = await buildCiphers(owner, {
      'private-credentials': descriptor1
    })
    const { localStore } = await initLocalStore(ciphers)
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      remoteDirect: true,
      vaultKeys: owner,
      descriptors: { 'private-credentials': descriptor1 }
    })

    // A rekey rotates the collection to epoch 2 (owner alone).
    const descriptor2 = await removeRecipient({
      collection: collectionHandle,
      space: remoteStore.spaceHandle(),
      recipientId: extra.keyAgreementKey.id!,
      revoke: []
    })

    // A credential lands in the remote collection under epoch 2, which the
    // stale epoch-1 cipher cannot route.
    const epoch2Cipher = await createEdvDocCipher({
      keyAgreementKey: owner.keyAgreementKey,
      keyResolver: owner.keyResolver,
      collectionId: 'private-credentials',
      encryption: descriptor2
    })
    const credential = makeCredential('Alice')
    const cid = await cidFrom({ doc: credential })
    const { id, envelope } = await epoch2Cipher.encrypt({
      data: credential as unknown as Json
    })
    seedResource({
      logicalKey: 'privateCredentials',
      resourceId: id,
      body: envelope
    })

    // The remote-direct listCredentials refreshes the descriptor, rebuilds the
    // backend's cipher via setCiphers, and re-reads -- returning the fresh row.
    const listed = await storage.listCredentials()
    expect(listed).toEqual([{ cid, vc: credential }])
  })
})
