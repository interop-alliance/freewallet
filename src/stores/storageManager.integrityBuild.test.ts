/**
 * Unit tests for a cipher build that fails its key-wrap check: a descriptor
 * recipient entry whose `kid` is this wallet's own key id but whose wrapped
 * epoch key fails the AES-KW check raises `IntegrityError` when the cipher is
 * built (was-client 0.99.1). The session is still built, the collection gets
 * a refusing cipher of the integrity kind, and nothing reports it as stranded
 * or as "no key epoch names this wallet".
 *
 * The build is driven through the local-mode harness (a real vault KAK, a
 * real minted descriptor, a real BrowserStore on RxDB memory storage), with
 * `createEdvDocCipher` replaced for one collection so it raises what the
 * package raises for a tampered entry.
 *
 * @vitest-environment node
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type {
  IKeyAgreementKey,
  IKeyResolver,
  IVerifiableCredential
} from '@interop/data-integrity-core'
import { addSink, captureSink } from '@interop/logger'
import { IntegrityError } from '@interop/was-client'
import type { Json } from '@interop/was-sync'
import { getRxStorageMemory } from 'rxdb/plugins/storage-memory'
import type { ControllerProfile, User } from '@/types/auth'
import { browserLocalSessionPersistence } from '@/session/persistence'
import { StorageManager } from './storageManager'
import { generateVaultKeys } from '@/stores/testing/vaultKeys'

const TAMPERED_COLLECTION = 'private-credentials'

vi.mock('@interop/was-client/edv', async importOriginal => {
  const actual =
    await importOriginal<typeof import('@interop/was-client/edv')>()
  return {
    ...actual,
    createEdvDocCipher: async (
      options: Parameters<typeof actual.createEdvDocCipher>[0]
    ) => {
      if (options.collectionId === TAMPERED_COLLECTION) {
        throw new IntegrityError(
          'The recipient entry for the current epoch names this reader but ' +
            'its wrapped key failed the AES-KW integrity check.'
        )
      }
      return actual.createEdvDocCipher(options)
    }
  }
})

function makeCredential(name: string): IVerifiableCredential {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    issuer: 'did:key:z6MkTestIssuer',
    credentialSubject: { name }
  } as unknown as IVerifiableCredential
}

let userCounter = 0
const openSessions: StorageManager[] = []

/**
 * A guest session over the local-mode path, the way `initSession` builds one.
 *
 * @param options {object}
 * @param options.owner {object}   the session's vault key material
 * @returns {Promise<{ storage: StorageManager, user: User }>}
 */
async function initGuestSession({
  owner
}: {
  owner: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
}): Promise<{ storage: StorageManager; user: User }> {
  userCounter += 1
  const user: User = {
    id: `did:key:z6MkIntegrityBuildUser${userCounter}`,
    email: 'test@example.com'
  }
  const { storage } = await StorageManager.initStorageClients({
    user,
    session: {
      profile: {
        keyAgreementKey: owner.keyAgreementKey,
        keyResolver: owner.keyResolver,
        keyAgent: { id: 'did:key:z6MkIntegrityBuildAgent' }
      } as unknown as ControllerProfile,
      persistence: browserLocalSessionPersistence({ persistCaches: false })
    },
    isGuest: true,
    storage: getRxStorageMemory()
  })
  await storage.ensureUserCollections({ user })
  openSessions.push(storage)
  return { storage, user }
}

beforeEach(() => {
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
  Reflect.deleteProperty(globalThis, 'indexedDB')
})

describe('StorageManager: a cipher build that fails its key-wrap check', () => {
  it('builds the session, warns of the tampered entry, and reports no stranding', async () => {
    const owner = await generateVaultKeys()
    const capture = captureSink()
    const removeSink = addSink(capture.sink)
    let storage: StorageManager
    try {
      ;({ storage } = await initGuestSession({ owner }))
    } finally {
      removeSink()
    }

    // The tamper warning names the collection and carries the error. No
    // "no key epoch names the current user key" line is logged for it.
    const warning = capture.events.find(
      event =>
        event.level === 'warn' &&
        event.msg.includes('failed its key-wrap check') &&
        (event.data as { collectionId?: string })?.collectionId ===
          TAMPERED_COLLECTION
    )
    expect(warning).toBeDefined()
    expect((warning?.err as Error).name).toBe('IntegrityError')
    expect(
      capture.events.some(event =>
        event.msg.includes('No key epoch of this collection names')
      )
    ).toBe(false)
    // Not stranded: a user key cascade cannot converge a tampered entry.
    // Listed as integrity-refused instead, so a page can name it.
    expect(storage.strandedCollectionIds).toEqual([])
    expect(storage.integrityRefusedCollectionIds).toEqual([TAMPERED_COLLECTION])
  })

  it('refuses the collection with IntegrityError and serves the others', async () => {
    const owner = await generateVaultKeys()
    const { storage, user } = await initGuestSession({ owner })

    await expect(
      storage.addCredential({ credential: makeCredential('Ada'), user })
    ).rejects.toMatchObject({ name: 'IntegrityError' })

    // `wallet-activity` was built from its own, intact descriptor.
    await storage.addHistoryWalletLogin({ user })
    const { entries } = await storage.listHistoryItems()
    expect(entries.length).toBeGreaterThanOrEqual(1)
  })

  it('counts every row of the refused collection in the integrity bucket, never purged', async () => {
    const owner = await generateVaultKeys()
    const { storage } = await initGuestSession({ owner })
    await storage.localCollection('privateCredentials').insert({
      id: 'z6UnderTamperedEntry',
      updatedAt: new Date().toISOString(),
      data: {
        id: 'z6UnderTamperedEntry',
        sequence: 0,
        jwe: { ciphertext: 'opaque' }
      } as Json
    })

    expect(await storage.listCredentials()).toHaveLength(0)
    expect(storage.integrityCredentials).toBe(1)
    expect(storage.undecryptableCredentials).toBe(0)
    expect(await storage.purgeUndecryptableCredentials()).toBe(0)
    expect(
      await storage.localCollection('privateCredentials').find().exec()
    ).toHaveLength(1)
  })
})
