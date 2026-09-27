/**
 * The shared test harness for a `StorageManager` over a memory-RxDB
 * `BrowserStore` with real EDV ciphers and no remote store.
 *
 * Every caller wants the same thing: a replica whose rows really round-trip
 * through encrypt and decrypt, so a plaintext store's idempotent insert
 * cannot mask a missing dedupe. The only thing that differs between them is
 * which collections get a cipher, so that is the one argument.
 *
 * The stores the harness opens are held here and closed by
 * `closeMemoryStores`, which each caller registers in its own `afterEach`.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { createEdvDocCipher, type DocCipher } from '@interop/was-client/edv'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import { mintRecordEncryption } from '@/session/recordEnvelope'
import { browserLocalSessionPersistence } from '@/session/persistence'
import type { Session, User } from '@/types/auth'
import { BrowserStore } from '@/stores/browserStore'
import { StorageManager } from '@/stores/storageManager'
import { generateVaultKeys } from '@/stores/testing/vaultKeys'

/**
 * A logical cipher key paired with the WAS collection id it seals for.
 */
export type CollectionPair = readonly [logicalKey: string, collectionId: string]

/**
 * Every collection the content migration reads or writes.
 */
export const MIGRATION_COLLECTIONS: CollectionPair[] = [
  ['privateCredentials', 'private-credentials'],
  ['appConnections', 'app-connections'],
  ['walletActivity', 'wallet-activity'],
  ['contacts', 'contacts'],
  ['contactsHistory', 'contacts-history']
]

/**
 * What a `StorageManager` harness hands back.
 */
export interface MemoryStorageHarness {
  storage: StorageManager
  localStore: BrowserStore
  user: User
  ciphers: Record<string, DocCipher>
  key: IKeyAgreementKey
  keyResolver: IKeyResolver
}

const openStores: BrowserStore[] = []
let userCounter = 0

/**
 * Closes every store the harness opened. Register it in `afterEach`.
 *
 * @returns {Promise<void>}
 */
export async function closeMemoryStores(): Promise<void> {
  while (openStores.length > 0) {
    await openStores.pop()?.close()
  }
}

/**
 * A `StorageManager` over a fresh memory-RxDB `BrowserStore`, with a real EDV
 * cipher per named collection and no remote store.
 *
 * @param [options] {object}
 * @param [options.collections] {CollectionPair[]}   which collections get a
 *   cipher; defaults to every collection the migration touches
 * @param [options.controller] {string}   the test key's controller DID
 * @param [options.userIdPrefix] {string}   the per-harness user DID prefix
 * @returns {Promise<MemoryStorageHarness>}
 */
export async function memoryStorageManager({
  collections = MIGRATION_COLLECTIONS,
  controller = 'did:key:z6MkMigrationController',
  userIdPrefix = 'did:key:z6MkMigrationUser'
}: {
  collections?: CollectionPair[]
  controller?: string
  userIdPrefix?: string
} = {}): Promise<MemoryStorageHarness> {
  const { keyAgreementKey: key, keyResolver } = await generateVaultKeys({
    controller
  })
  const ciphers: Record<string, DocCipher> = {}
  for (const [logicalKey, collectionId] of collections) {
    // Every encrypted collection carries a key-epoch roster from birth, so
    // each cipher gets a local one-epoch descriptor wrapped to the test KAK.
    ciphers[logicalKey] = await createEdvDocCipher({
      keyAgreementKey: key,
      keyResolver,
      collectionId,
      encryption: await mintRecordEncryption({ keyAgreementKey: key })
    })
  }
  userCounter += 1
  const user: User = {
    id: `${userIdPrefix}${userCounter}`,
    email: 'test@example.com'
  }
  const { localStore } = await BrowserStore.initClient({
    user,
    storage: getRxStorageMemory(),
    ciphers
  })
  await localStore.ensureUserCollections({ user })
  openStores.push(localStore)
  const storage = new StorageManager({
    localStore,
    ciphers,
    vaultKeys: { keyAgreementKey: key, keyResolver },
    descriptors: {},
    persistence: browserLocalSessionPersistence()
  })
  return { storage, localStore, user, ciphers, key, keyResolver }
}

/**
 * The same harness as a `Session`: enough of one for a ceremony that reads
 * the storage manager, the persistence strategy, and the account's identity
 * alone.
 *
 * @param [options] {object}
 * @param [options.collections] {CollectionPair[]}
 * @param [options.controller] {string}
 * @param [options.userIdPrefix] {string}
 * @returns {Promise<Session>}
 */
export async function memorySession(
  options: {
    collections?: CollectionPair[]
    controller?: string
    userIdPrefix?: string
  } = {}
): Promise<Session> {
  const { storage, user } = await memoryStorageManager({
    userIdPrefix: 'did:key:z6MkMigrationTarget',
    ...options
  })
  return {
    user,
    profile: {} as Session['profile'],
    storage,
    persistence: browserLocalSessionPersistence(),
    isGuest: false
  }
}
