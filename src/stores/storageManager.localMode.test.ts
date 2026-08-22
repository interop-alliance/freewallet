/**
 * Unit tests for the local-mode (guest / no-WAS-server) storage provisioning
 * path: a session with no remote store still gets WORKING ciphers for every
 * encrypted standard collection, because `localOnlyDescriptors` mints a local
 * one-epoch descriptor per collection wrapped to the session's vault KAK.
 *
 * This is the regression the guest flows caught before that helper existed:
 * without a locally minted descriptor the ciphers are the fail-closed refusing
 * kind, and every read/write in a guest signup/login throws
 * `Collection "wallet-activity" has no encryption descriptor available`.
 *
 * Everything below the descriptor mint is real -- a real X25519 vault KAK, the
 * real `mintRecordEncryption` / `createEdvDocCipher` epoch path, and a real
 * BrowserStore on RxDB memory storage -- so a broken epoch construction fails
 * here rather than only in the browser.
 *
 * @vitest-environment node
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import type {
  IKeyAgreementKey,
  IKeyResolver,
  IVerifiableCredential
} from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import type { ControllerProfile, User } from '@/types/auth'
import { durableSessionPersistence } from '@/session/persistence'
import { StorageManager } from './storageManager'

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
 * supplies alongside it -- the session's vault KAK, the sole recipient of a
 * local-mode epoch.
 */
async function generateKey(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}> {
  const key = await X25519KeyAgreementKey2020.generate({
    controller: 'did:key:z6MkLocalModeController'
  })
  const keyResolver: IKeyResolver = async () => ({
    id: key.id!,
    type: key.type,
    publicKeyMultibase: key.publicKeyMultibase
  })
  return { keyAgreementKey: key as IKeyAgreementKey, keyResolver }
}

/**
 * A local-only session profile: the vault keys, the truthy `keyAgent` a full
 * session carries, and the durable persistence handle a login builds -- with
 * the caches off for a guest, exactly as `initSession` does.
 * No `zcapClient` -- nothing on this path signs.
 *
 * @param options {object}
 * @param options.owner {object}   the session's vault key material
 * @param options.isGuest {boolean}   guests persist no descriptor caches
 * @returns {ControllerProfile}
 */
function makeProfile({
  owner,
  isGuest
}: {
  owner: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  isGuest: boolean
}): ControllerProfile {
  return {
    keyAgreementKey: owner.keyAgreementKey,
    keyResolver: owner.keyResolver,
    keyAgent: { id: 'did:key:z6MkLocalModeAgent' },
    persistence: durableSessionPersistence({ persistCaches: !isGuest })
  } as unknown as ControllerProfile
}

let userCounter = 0
const openSessions: StorageManager[] = []

/**
 * A fresh synthetic session user (a distinct local database per test).
 *
 * @returns {User}
 */
function makeUser(): User {
  userCounter += 1
  return {
    id: `did:key:z6MkLocalModeUser${userCounter}`,
    email: 'test@example.com'
  }
}

/**
 * Runs `StorageManager.initStorageClients` the way a guest / no-WAS login
 * does -- the same descriptor mint, cipher build, and local replica -- with
 * RxDB memory storage injected in place of IndexedDB, then provisions the
 * local collections so reads and writes can run.
 *
 * @param options {object}
 * @param options.user {User}
 * @param options.owner {object}   the session's vault key material
 * @param options.isGuest {boolean}   guests are mint-only (no persistence)
 * @returns {Promise<StorageManager>}
 */
async function initLocalSession({
  user,
  owner,
  isGuest
}: {
  user: User
  owner: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  isGuest: boolean
}): Promise<StorageManager> {
  const { storage } = await StorageManager.initStorageClients({
    user,
    profile: makeProfile({ owner, isGuest }),
    isGuest,
    storage: getRxStorageMemory()
  })
  await storage.ensureUserCollections({ user })
  return storage
}

// `localOnlyDescriptors` and the descriptor cache both no-op without a
// `localStorage` (which is the node environment's state), so the persistence
// semantics need one -- a plain in-memory stand-in, reset between tests so a
// leaked entry cannot make a later assertion pass.
let localStorageBacking: Record<string, string> = {}

/**
 * The descriptor cache keys a non-guest local session persists its minted
 * descriptors under.
 *
 * @returns {string[]}
 */
function localCacheKeys(): string[] {
  return Object.keys(localStorageBacking).filter(key =>
    key.startsWith('freewallet:collection-encryption:local:')
  )
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
    await session.wipeLocalStorage()
  }
  openSessions.length = 0
  Reflect.deleteProperty(globalThis, 'localStorage')
  Reflect.deleteProperty(globalThis, 'indexedDB')
})

describe('StorageManager.initStorageClients in local mode', () => {
  it('a guest session gets working ciphers for the encrypted standard collections', async () => {
    const user = makeUser()
    const owner = await generateKey()
    const storage = await initLocalSession({ user, owner, isGuest: true })
    openSessions.push(storage)

    // `private-credentials`: the write encrypts under the minted epoch and the
    // read decrypts back to the same body. With a refusing cipher both throw.
    await storage.addCredential({ credential: makeCredential('Ada'), user })
    const credentials = await storage.listCredentials()
    expect(credentials).toHaveLength(1)
    expect((credentials[0].vc.credentialSubject as { name: string }).name).toBe(
      'Ada'
    )

    // `wallet-activity`: the credential write already recorded its Create
    // activity through the same encrypted path, and it reads back decrypted.
    const history = await storage.listHistoryItems()
    expect(history.length).toBeGreaterThanOrEqual(1)
    expect(history.some(({ doc }) => doc.type?.includes('Create'))).toBe(true)
  })

  it('a non-guest local session persists an epoch-bearing descriptor per encrypted collection', async () => {
    const user = makeUser()
    const owner = await generateKey()
    const storage = await initLocalSession({ user, owner, isGuest: false })
    openSessions.push(storage)
    await storage.addCredential({ credential: makeCredential('Grace'), user })

    const keys = localCacheKeys()
    expect(keys.some(key => key.endsWith(':private-credentials'))).toBe(true)
    expect(keys.some(key => key.endsWith(':wallet-activity'))).toBe(true)
    // Every cached descriptor is scoped to this user's DID (no Space id in
    // local mode) and carries a real key-epoch roster -- a descriptor with no
    // epochs is exactly what makes the cipher refuse.
    const scope = `freewallet:collection-encryption:local:${user.id}:`
    for (const key of keys) {
      expect(key.startsWith(scope)).toBe(true)
      const descriptor = JSON.parse(
        localStorageBacking[key]
      ) as CollectionEncryption
      expect(descriptor.epochs?.length).toBeGreaterThanOrEqual(1)
      expect(descriptor.currentEpoch).toBeDefined()
    }
  })

  it('a guest session persists no descriptors', async () => {
    const user = makeUser()
    const owner = await generateKey()
    const storage = await initLocalSession({ user, owner, isGuest: true })
    openSessions.push(storage)
    await storage.addCredential({ credential: makeCredential('Hopper'), user })

    expect(localCacheKeys()).toEqual([])
  })

  it('a non-guest local re-init reuses the cached epoch, so earlier rows still decrypt', async () => {
    const user = makeUser()
    const owner = await generateKey()
    const first = await initLocalSession({ user, owner, isGuest: false })
    await first.addCredential({
      credential: makeCredential('Lovelace'),
      user
    })
    expect(await first.listCredentials()).toHaveLength(1)
    await first.close()

    const cachedDescriptors = { ...localStorageBacking }

    // A returning local login: same user, same vault keys, a fresh
    // StorageManager over the same local database.
    const second = await initLocalSession({ user, owner, isGuest: false })
    openSessions.push(second)
    // The descriptors came back out of the cache rather than being re-minted;
    // a re-mint would seal a fresh epoch and strand the rows written above.
    expect(localStorageBacking).toEqual(cachedDescriptors)

    const credentials = await second.listCredentials()
    expect(
      credentials.map(
        ({ vc }) => (vc.credentialSubject as { name: string }).name
      )
    ).toContain('Lovelace')
  })
})
