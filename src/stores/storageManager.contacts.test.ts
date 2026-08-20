/**
 * Unit tests for the contact revision actions `StorageManager` records: an
 * ordinary edit appends an `update` revision, and the same write with
 * `action: 'restore'` (the restore-from-history path) appends a `restore` one.
 * Driven over a real local-mode session -- real ciphers, a real BrowserStore
 * on RxDB memory storage -- so the revision really round-trips through
 * `contacts-history`.
 *
 * @vitest-environment node
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { ContactData } from '@interop/social-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import type { ControllerProfile, User } from '@/types/auth'
import { durableSessionPersistence } from '@/session/persistence'
import { StorageManager } from './storageManager'

let userCounter = 0
const openSessions: StorageManager[] = []
let localStorageBacking: Record<string, string> = {}

/**
 * A generated X25519 key pair plus the single-key resolver the session profile
 * supplies alongside it -- the session's vault KAK, the sole recipient of a
 * local-mode epoch.
 *
 * @returns {Promise<object>}
 */
async function generateKey(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}> {
  const key = await X25519KeyAgreementKey2020.generate({
    controller: 'did:key:z6MkContactsController'
  })
  const keyResolver: IKeyResolver = async () => ({
    id: key.id!,
    type: key.type,
    publicKeyMultibase: key.publicKeyMultibase
  })
  return { keyAgreementKey: key as IKeyAgreementKey, keyResolver }
}

/**
 * A local-only session over RxDB memory storage, provisioned so the contact
 * collections can be read and written.
 *
 * @returns {Promise<object>}
 */
async function initLocalSession(): Promise<{
  storage: StorageManager
  user: User
}> {
  userCounter += 1
  const user = {
    id: `did:key:z6MkContactsUser${userCounter}`,
    email: 'test@example.com'
  } as User
  const owner = await generateKey()
  const profile = {
    keyAgreementKey: owner.keyAgreementKey,
    keyResolver: owner.keyResolver,
    keyAgent: { id: 'did:key:z6MkContactsAgent' },
    // A guest login's handle: durable pins, and no descriptor caches.
    persistence: durableSessionPersistence({ persistCaches: false })
  } as unknown as ControllerProfile
  const { storage } = await StorageManager.initStorageClients({
    user,
    profile,
    isGuest: true,
    storage: getRxStorageMemory()
  })
  await storage.ensureUserCollections({ user })
  openSessions.push(storage)
  return { storage, user }
}

/**
 * A minimal contact body.
 *
 * @param displayName {string}
 * @returns {ContactData}
 */
function makeContact(displayName: string): ContactData {
  return { displayName } as ContactData
}

beforeEach(() => {
  localStorageBacking = {}
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem: (key: string) => localStorageBacking[key] ?? null,
      setItem: (key: string, value: string) => {
        localStorageBacking[key] = value
      },
      removeItem: (key: string) => {
        delete localStorageBacking[key]
      }
    }
  })
  // `BrowserStore.userExists` probes the browser's database list; local mode
  // never branches on the answer, so an empty listing is enough.
  Object.defineProperty(globalThis, 'indexedDB', {
    configurable: true,
    value: { databases: async () => [] }
  })
})

afterEach(async () => {
  for (const session of openSessions) {
    await session.wipeStorage()
  }
  openSessions.length = 0
  Reflect.deleteProperty(globalThis, 'localStorage')
  Reflect.deleteProperty(globalThis, 'indexedDB')
})

describe('StorageManager.updateContact revision actions', () => {
  it('defaults to an `update` revision', async () => {
    const { storage } = await initLocalSession()
    const stored = await storage.addContact({ contact: makeContact('Ada') })
    await storage.updateContact({
      id: stored.id,
      contact: makeContact('Ada Lovelace')
    })

    const revisions = await storage.listContactRevisions({
      contactId: stored.contactId
    })
    expect(revisions.map(revision => revision.action).sort()).toEqual([
      'create',
      'update'
    ])
    const updated = revisions.find(revision => revision.action === 'update')
    expect(updated?.snapshot.displayName).toBe('Ada Lovelace')
  })

  it('records a `restore` revision when asked for one', async () => {
    const { storage } = await initLocalSession()
    const stored = await storage.addContact({ contact: makeContact('Grace') })
    await storage.updateContact({
      id: stored.id,
      contact: makeContact('Grace Hopper')
    })
    // The restore rewrites the contact wholesale with the earlier snapshot.
    await storage.updateContact({
      id: stored.id,
      contact: makeContact('Grace'),
      action: 'restore'
    })

    const revisions = await storage.listContactRevisions({
      contactId: stored.contactId
    })
    const restored = revisions.filter(revision => revision.action === 'restore')
    expect(restored).toHaveLength(1)
    expect(restored[0].snapshot.displayName).toBe('Grace')

    const head = await storage.loadContact({ id: stored.id })
    expect(head?.contact.displayName).toBe('Grace')
  })
})
