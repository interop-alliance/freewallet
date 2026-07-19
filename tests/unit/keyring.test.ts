// @vitest-environment node
/**
 * Unit tests for the keyring v2 module (`src/session/keyring.ts`): the unlock
 * derivation (deterministic, secret-sensitive), the wrap/unwrap round-trip
 * and its record validation, and the `fetchKeyringSeed` / `bindPassphrase` /
 * `changePassphrase` public contract across the WAS-configured and cache-only
 * branches. The module is now method-agnostic -- unlock derivation runs off a
 * generic `{ secret, kdf }` pair (a string passphrase under PBKDF2, or uniform
 * byte material such as a passkey PRF output under HKDF) via the exported
 * `deriveUnlockIdentity` / `bindUnlockSecret` seam, and the passphrase
 * functions are thin wrappers over it; the frozen-vector block pins the
 * production salts. The unlock-Space WAS helpers are replaced by an in-memory fake
 * keyed by unlock Space id; the `freewallet-session` IndexedDB cache is backed
 * by a minimal in-memory `IDBFactory` (node has no IndexedDB). Tiny PBKDF2
 * iteration counts keep the derivation fast; the real EDV cipher and
 * CapabilityAgent / X25519 derivations run unmocked.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IDelegatedZcap,
  IKeyAgreementKey
} from '@interop/data-integrity-core'
import { WasError } from '@interop/was-client'
import { bufferToBase64Url, digestHash } from '@/lib/cidFrom'
import { createEdvDocCipher } from '@/stores/edvDocCipher'
import { loadKeyringCache } from '@/lib/sessionKey'
import {
  KEYRING_CACHE_TTL_MS,
  KEYRING_KDF,
  PASSKEY_KDF,
  UNLOCK_MANAGE_ZCAP_TTL_MS
} from '@/app.config'

/**
 * Shared mutable state for the two mocks: the configured WAS url (mutable so a
 * test can drop it to exercise the cache-only branch), the in-memory unlock
 * Spaces (spaceId to keyring record), and an optional error the remote GET
 * should throw.
 */
const wasState = vi.hoisted(() => ({
  url: 'https://was.example.test' as string | undefined,
  spaces: new Map<string, unknown>(),
  getError: undefined as unknown
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return wasState.url
  }
}))

vi.mock('@/stores/wasRemoteStore', () => ({
  ensureUnlockSpace: vi.fn(async () => {}),
  putUnlockKeyring: vi.fn(
    async ({ spaceId, record }: { spaceId: string; record: unknown }) => {
      wasState.spaces.set(spaceId, record)
    }
  ),
  getUnlockKeyring: vi.fn(async ({ spaceId }: { spaceId: string }) => {
    if (wasState.getError) {
      throw wasState.getError
    }
    return wasState.spaces.has(spaceId) ? wasState.spaces.get(spaceId) : null
  }),
  deleteUnlockSpace: vi.fn(async ({ spaceId }: { spaceId: string }) => {
    wasState.spaces.delete(spaceId)
  })
}))

import {
  bindPassphrase,
  bindUnlockSecret,
  changePassphrase,
  deleteKeyring,
  deriveUnlockIdentity,
  fetchKeyringSeed,
  KeyringRecordUnusableError,
  verifyPassphrase,
  WrongPassphraseError
} from '@/session/keyring'
import {
  deleteUnlockSpace,
  ensureUnlockSpace,
  getUnlockKeyring
} from '@/stores/wasRemoteStore'

const KDF = {
  version: 1,
  algorithm: 'PBKDF2',
  iterations: 2,
  hash: 'SHA-256',
  salt: 'freewallet/test/unlock'
} as const
const DATA_CONTROLLER = 'did:key:z6MkDataControllerForTests'

/**
 * A minimal in-memory `IDBFactory` sufficient for the session-store helpers in
 * `src/lib/sessionKey.ts` (a single object store, get/put/delete by key). Each
 * test gets a fresh one so caches start empty.
 *
 * @returns {IDBFactory}
 */
function createFakeIdb(): IDBFactory {
  const stores = new Map<string, Map<IDBValidKey, unknown>>()
  let initialized = false
  type Request = {
    onsuccess?: () => void
    onupgradeneeded?: () => void
    onerror?: () => void
    result?: unknown
  }
  function run(fn: () => unknown): Request {
    const request: Request = {}
    queueMicrotask(() => {
      request.result = fn()
      request.onsuccess?.()
    })
    return request
  }
  function storeApi(store: Map<IDBValidKey, unknown>) {
    return {
      get: (key: IDBValidKey) => run(() => store.get(key)),
      put: (value: unknown, key: IDBValidKey) =>
        run(() => {
          store.set(key, value)
          return key
        }),
      delete: (key: IDBValidKey) =>
        run(() => {
          store.delete(key)
          return undefined
        })
    }
  }
  function makeDb() {
    return {
      createObjectStore(name: string) {
        if (!stores.has(name)) {
          stores.set(name, new Map())
        }
        return {}
      },
      transaction(name: string) {
        let store = stores.get(name)
        if (!store) {
          store = new Map()
          stores.set(name, store)
        }
        return {
          objectStore: () => storeApi(store as Map<IDBValidKey, unknown>)
        }
      },
      close() {}
    }
  }
  return {
    open() {
      const request: Request = {}
      queueMicrotask(() => {
        request.result = makeDb()
        if (!initialized) {
          initialized = true
          request.onupgradeneeded?.()
        }
        request.onsuccess?.()
      })
      return request
    }
  } as unknown as IDBFactory
}

/**
 * Writes a raw value directly into the fake session store at a keyring-cache
 * key (bypassing `saveKeyringCache` and its write-time stamp), to simulate a
 * legacy cache entry written before timestamps existed.
 */
async function putRawCacheEntry({
  idb,
  spaceId,
  value
}: {
  idb: IDBFactory
  spaceId: string
  value: unknown
}): Promise<void> {
  const db = await new Promise<IDBDatabase>(resolve => {
    const request = idb.open('freewallet-session', 1)
    request.onsuccess = () => resolve(request.result)
  })
  await new Promise<void>(resolve => {
    const request = db
      .transaction('session', 'readwrite')
      .objectStore('session')
      .put(value, `keyring/${spaceId}`)
    request.onsuccess = () => resolve()
  })
}

/**
 * Independently derives the unlock identity (KAK + resolver + Space id) for a
 * passphrase, using the exact steps `src/session/keyring.ts` uses. Lets a test
 * craft records at the right unlock Space and assert derivation determinism.
 */
async function unlockFor(passphrase: string) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits']
  )
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: new TextEncoder().encode(KDF.salt),
      iterations: KDF.iterations,
      hash: KDF.hash
    },
    baseKey,
    256
  )
  const agent = await CapabilityAgent.fromSeed({
    seed: new Uint8Array(bits),
    handle: 'unlock',
    keyName: 'unlock-key'
  })
  const keyAgreementKey =
    X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
      keyPair: agent.getVerificationKeyPair()
    })
  const keyResolver = async () => ({
    id: keyAgreementKey.id,
    type: keyAgreementKey.type,
    publicKeyMultibase: keyAgreementKey.publicKeyMultibase
  })
  const spaceId = bufferToBase64Url(await digestHash(agent.id))
  return { agent, keyAgreementKey, keyResolver, spaceId }
}

/**
 * Builds a keyring record ({version, wrapped}) whose ciphertext decrypts (under
 * the given passphrase's unlock KAK) to an arbitrary plaintext, so the negative
 * validation paths can be exercised.
 */
async function craftRecord({
  passphrase,
  plaintext,
  version = 1
}: {
  passphrase: string
  plaintext: Record<string, string>
  version?: number
}) {
  const { keyAgreementKey, keyResolver, spaceId } = await unlockFor(passphrase)
  const cipher = await createEdvDocCipher({
    keyAgreementKey: keyAgreementKey as unknown as IKeyAgreementKey,
    keyResolver,
    collectionId: 'keyring'
  })
  const { envelope } = await cipher.encrypt({ data: plaintext })
  return { record: { version, wrapped: envelope }, spaceId }
}

function randomSeed(): Uint8Array {
  const seed = new Uint8Array(32)
  crypto.getRandomValues(seed)
  return seed
}

/**
 * Encodes raw bytes as an unpadded base64url string (matching the module's
 * internal encoder), for building crafted keyring plaintexts.
 */
function seedToBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

beforeEach(() => {
  wasState.url = 'https://was.example.test'
  wasState.spaces.clear()
  wasState.getError = undefined
  vi.clearAllMocks()
})

afterEach(() => {
  vi.useRealTimers()
  vi.clearAllMocks()
})

describe('unlock derivation', () => {
  it('is deterministic and matches bindPassphrase (same passphrase -> same Space)', async () => {
    const idb = createFakeIdb()
    const expected = await unlockFor('correct horse battery staple')

    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'correct horse battery staple',
      idb,
      kdf: KDF
    })

    const ensureArgs = vi.mocked(ensureUnlockSpace).mock.calls[0][0]
    expect(ensureArgs.spaceId).toBe(expected.spaceId)
    expect(ensureArgs.controller).toBe(expected.agent.id)
  })

  it('is passphrase-sensitive (different passphrase -> different Space)', async () => {
    const first = await unlockFor('passphrase one')
    const second = await unlockFor('passphrase two')
    expect(second.spaceId).not.toBe(first.spaceId)
  })
})

describe('wrap / unwrap', () => {
  it('round-trips seed and controller through bind + fetch', async () => {
    const idb = createFakeIdb()
    const seed = randomSeed()

    await bindPassphrase({
      seed,
      controller: DATA_CONTROLLER,
      passphrase: 'round-trip passphrase',
      idb,
      kdf: KDF
    })

    const found = await fetchKeyringSeed({
      passphrase: 'round-trip passphrase',
      idb,
      kdf: KDF
    })
    expect(found).not.toBeNull()
    expect(Array.from(found!.seed)).toEqual(Array.from(seed))
    expect(found!.controller).toBe(DATA_CONTROLLER)
  })

  it('rejects a record whose version is not 1', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'v2 passphrase',
      version: 2,
      plaintext: {
        seed: seedToBase64Url(randomSeed()),
        controller: DATA_CONTROLLER,
        createdAt: new Date().toISOString()
      }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      fetchKeyringSeed({ passphrase: 'v2 passphrase', idb, kdf: KDF })
    ).rejects.toThrow(/version/)
  })

  it('rejects a record with an empty controller', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'empty controller passphrase',
      plaintext: {
        seed: seedToBase64Url(randomSeed()),
        controller: '',
        createdAt: new Date().toISOString()
      }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      fetchKeyringSeed({
        passphrase: 'empty controller passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toThrow(/controller/)
  })

  it('rejects a record whose seed is not 32 bytes', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'short seed passphrase',
      plaintext: {
        seed: seedToBase64Url(new Uint8Array(16)),
        controller: DATA_CONTROLLER,
        createdAt: new Date().toISOString()
      }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      fetchKeyringSeed({ passphrase: 'short seed passphrase', idb, kdf: KDF })
    ).rejects.toThrow(/32 bytes/)
  })

  it('maps a corrupt remote record to KeyringRecordUnusableError and never caches it', async () => {
    const idb = createFakeIdb()
    const { spaceId } = await unlockFor('corrupt record passphrase')
    // A record with the right shape but an undecryptable payload -- the
    // "genuinely corrupt record under the correct unlock Space" case.
    wasState.spaces.set(spaceId, { version: 1, wrapped: { garbage: true } })

    await expect(
      fetchKeyringSeed({
        passphrase: 'corrupt record passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toThrow(KeyringRecordUnusableError)

    // The unusable record must not have refreshed the local cache.
    expect(await loadKeyringCache({ spaceId, idb })).toBeNull()
  })
})

describe('fetchKeyringSeed', () => {
  it('consults the remote even on a cache hit (the remote is the source of truth)', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'cache hit passphrase',
      idb,
      kdf: KDF
    })
    vi.clearAllMocks()

    const found = await fetchKeyringSeed({
      passphrase: 'cache hit passphrase',
      idb,
      kdf: KDF
    })
    expect(found).not.toBeNull()
    expect(getUnlockKeyring).toHaveBeenCalledOnce()
  })

  it('drops the cache and returns null when the remote keyring is gone (passphrase retired on another device)', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'retired passphrase',
      idb,
      kdf: KDF
    })
    // Simulate a passphrase change made on another device: the old unlock
    // Space is deleted remotely while this device's cache still holds the
    // record.
    wasState.spaces.clear()

    const found = await fetchKeyringSeed({
      passphrase: 'retired passphrase',
      idb,
      kdf: KDF
    })
    expect(found).toBeNull()

    const { spaceId } = await unlockFor('retired passphrase')
    await expect(loadKeyringCache({ spaceId, idb })).resolves.toBeNull()
  })

  it('falls back to a fresh cache when the remote is unreachable', async () => {
    const idb = createFakeIdb()
    const seed = randomSeed()
    await bindPassphrase({
      seed,
      controller: DATA_CONTROLLER,
      passphrase: 'offline fallback passphrase',
      idb,
      kdf: KDF
    })
    wasState.getError = new WasError('NetworkError when attempting to fetch', {
      cause: new TypeError('NetworkError when attempting to fetch')
    })

    const found = await fetchKeyringSeed({
      passphrase: 'offline fallback passphrase',
      idb,
      kdf: KDF
    })
    expect(found).not.toBeNull()
    expect(Array.from(found!.seed)).toEqual(Array.from(seed))
  })

  it('rethrows when the remote is unreachable and the cache has expired', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    const idb = createFakeIdb()
    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'expired cache passphrase',
      idb,
      kdf: KDF
    })
    vi.setSystemTime(Date.now() + KEYRING_CACHE_TTL_MS + 60_000)
    const networkError = new WasError('NetworkError when attempting to fetch', {
      cause: new TypeError('NetworkError when attempting to fetch')
    })
    wasState.getError = networkError

    await expect(
      fetchKeyringSeed({
        passphrase: 'expired cache passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBe(networkError)
  })

  it('rethrows when the remote is unreachable and the cached record predates timestamps', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'legacy cache passphrase',
      plaintext: {
        seed: seedToBase64Url(randomSeed()),
        controller: DATA_CONTROLLER,
        createdAt: new Date().toISOString()
      }
    })
    // A bare record at the cache key, as written before write-time stamps.
    await putRawCacheEntry({ idb, spaceId, value: record })
    const networkError = new WasError('NetworkError when attempting to fetch', {
      cause: new TypeError('NetworkError when attempting to fetch')
    })
    wasState.getError = networkError

    await expect(
      fetchKeyringSeed({ passphrase: 'legacy cache passphrase', idb, kdf: KDF })
    ).rejects.toBe(networkError)
  })

  it('reads remote on a cache miss and refreshes the cache', async () => {
    const seed = randomSeed()
    // Bind through one profile (populates remote + its cache), then fetch on a
    // fresh profile whose cache is empty.
    await bindPassphrase({
      seed,
      controller: DATA_CONTROLLER,
      passphrase: 'cache miss passphrase',
      idb: createFakeIdb(),
      kdf: KDF
    })
    vi.clearAllMocks()

    const freshIdb = createFakeIdb()
    const found = await fetchKeyringSeed({
      passphrase: 'cache miss passphrase',
      idb: freshIdb,
      kdf: KDF
    })
    expect(found).not.toBeNull()
    expect(getUnlockKeyring).toHaveBeenCalledOnce()

    const { spaceId } = await unlockFor('cache miss passphrase')
    await expect(
      loadKeyringCache({ spaceId, idb: freshIdb })
    ).resolves.not.toBeNull()
  })

  it('returns null when no keyring exists anywhere', async () => {
    const found = await fetchKeyringSeed({
      passphrase: 'unknown account passphrase',
      idb: createFakeIdb(),
      kdf: KDF
    })
    expect(found).toBeNull()
  })

  it('rethrows a network error rather than reporting no account', async () => {
    const networkError = new WasError('NetworkError when attempting to fetch', {
      cause: new TypeError('NetworkError when attempting to fetch')
    })
    wasState.getError = networkError
    await expect(
      fetchKeyringSeed({
        passphrase: 'offline passphrase',
        idb: createFakeIdb(),
        kdf: KDF
      })
    ).rejects.toBe(networkError)
  })

  it('is cache-only (no remote call) when no WAS server is configured', async () => {
    wasState.url = undefined
    const found = await fetchKeyringSeed({
      passphrase: 'no was passphrase',
      idb: createFakeIdb(),
      kdf: KDF
    })
    expect(found).toBeNull()
    expect(getUnlockKeyring).not.toHaveBeenCalled()
  })

  it('serves the cache with no TTL when no WAS server is configured', async () => {
    wasState.url = undefined
    const idb = createFakeIdb()
    const seed = randomSeed()
    await bindPassphrase({
      seed,
      controller: DATA_CONTROLLER,
      passphrase: 'no was warm cache passphrase',
      idb,
      kdf: KDF
    })
    // Far past the WAS-mode TTL: with no remote copy the cache is the
    // keyring's only copy and stays authoritative regardless of age.
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(Date.now() + KEYRING_CACHE_TTL_MS * 10)

    const found = await fetchKeyringSeed({
      passphrase: 'no was warm cache passphrase',
      idb,
      kdf: KDF
    })
    expect(found).not.toBeNull()
    expect(Array.from(found!.seed)).toEqual(Array.from(seed))
    expect(getUnlockKeyring).not.toHaveBeenCalled()
  })
})

describe('bindPassphrase', () => {
  it('writes both remote and cache when WAS is configured', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'bind remote passphrase',
      idb,
      kdf: KDF
    })

    const { spaceId } = await unlockFor('bind remote passphrase')
    expect(ensureUnlockSpace).toHaveBeenCalledOnce()
    expect(wasState.spaces.has(spaceId)).toBe(true)
    await expect(loadKeyringCache({ spaceId, idb })).resolves.not.toBeNull()
  })

  it('is cache-only when no WAS server is configured', async () => {
    wasState.url = undefined
    const idb = createFakeIdb()
    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'bind cache only passphrase',
      idb,
      kdf: KDF
    })

    const { spaceId } = await unlockFor('bind cache only passphrase')
    expect(ensureUnlockSpace).not.toHaveBeenCalled()
    expect(wasState.spaces.size).toBe(0)
    await expect(loadKeyringCache({ spaceId, idb })).resolves.not.toBeNull()
  })

  it('is idempotent (a second identical bind succeeds)', async () => {
    const idb = createFakeIdb()
    const seed = randomSeed()
    const args = {
      seed,
      controller: DATA_CONTROLLER,
      passphrase: 'idempotent passphrase',
      idb,
      kdf: KDF
    }
    const { spaceId } = await unlockFor('idempotent passphrase')
    await bindPassphrase(args)
    await expect(bindPassphrase(args)).resolves.toEqual({
      unlockSpaceId: spaceId
    })
    expect(wasState.spaces.has(spaceId)).toBe(true)
  })

  it('returns the unlock Space id it bound', async () => {
    const idb = createFakeIdb()
    const { unlockSpaceId } = await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'space id return passphrase',
      idb,
      kdf: KDF
    })
    const { spaceId } = await unlockFor('space id return passphrase')
    expect(unlockSpaceId).toBe(spaceId)
  })

  it('carries the email through the wrapped record to fetchKeyringSeed', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'email carrying passphrase',
      email: 'holder@example.com',
      idb,
      kdf: KDF
    })

    const found = await fetchKeyringSeed({
      passphrase: 'email carrying passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.email).toBe('holder@example.com')
  })

  it('omits the email when none was bound', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'no email passphrase',
      idb,
      kdf: KDF
    })

    const found = await fetchKeyringSeed({
      passphrase: 'no email passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.email).toBeUndefined()
  })
})

describe('changePassphrase', () => {
  it('retires the account (old Space + cache deleted)', async () => {
    const idb = createFakeIdb()
    const seed = randomSeed()
    await bindPassphrase({
      seed,
      controller: DATA_CONTROLLER,
      passphrase: 'old passphrase',
      idb,
      kdf: KDF
    })
    const oldSpace = (await unlockFor('old passphrase')).spaceId
    const newSpace = (await unlockFor('new passphrase')).spaceId

    const { oldPassphraseRetired } = await changePassphrase({
      seed,
      controller: DATA_CONTROLLER,
      oldPassphrase: 'old passphrase',
      newPassphrase: 'new passphrase',
      idb,
      kdf: KDF
    })

    expect(oldPassphraseRetired).toBe(true)
    expect(deleteUnlockSpace).toHaveBeenCalledOnce()
    expect(wasState.spaces.has(oldSpace)).toBe(false)
    expect(wasState.spaces.has(newSpace)).toBe(true)
    await expect(
      loadKeyringCache({ spaceId: oldSpace, idb })
    ).resolves.toBeNull()
    await expect(
      loadKeyringCache({ spaceId: newSpace, idb })
    ).resolves.not.toBeNull()
  })

  it('throws WrongPassphraseError when no keyring exists for the old passphrase', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'the real old passphrase',
      idb,
      kdf: KDF
    })

    await expect(
      changePassphrase({
        seed: randomSeed(),
        controller: DATA_CONTROLLER,
        oldPassphrase: 'a wrong old passphrase',
        newPassphrase: 'brand new passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBeInstanceOf(WrongPassphraseError)
  })

  it('rejects an old passphrase already retired on another device despite a cached record', async () => {
    const idb = createFakeIdb()
    const seed = randomSeed()
    await bindPassphrase({
      seed,
      controller: DATA_CONTROLLER,
      passphrase: 'stale old passphrase',
      idb,
      kdf: KDF
    })
    // Retired elsewhere: the unlock Space is gone remotely, the local cache
    // still holds the record. Verification must consult the remote and fail.
    wasState.spaces.clear()

    await expect(
      changePassphrase({
        seed,
        controller: DATA_CONTROLLER,
        oldPassphrase: 'stale old passphrase',
        newPassphrase: 'brand new passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBeInstanceOf(WrongPassphraseError)
  })

  it('throws WrongPassphraseError when the record controller does not match', async () => {
    const idb = createFakeIdb()
    // A record exists at the old passphrase's unlock Space, but it belongs to a
    // different data identity than the one being changed.
    const { record, spaceId } = await craftRecord({
      passphrase: 'mismatch old passphrase',
      plaintext: {
        seed: seedToBase64Url(randomSeed()),
        controller: 'did:key:z6MkSomeOtherDataController',
        createdAt: new Date().toISOString()
      }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      changePassphrase({
        seed: randomSeed(),
        controller: DATA_CONTROLLER,
        oldPassphrase: 'mismatch old passphrase',
        newPassphrase: 'brand new passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBeInstanceOf(WrongPassphraseError)
  })

  it('rethrows an unreachable remote during verify (not a wrong passphrase)', async () => {
    const idb = createFakeIdb()
    const seed = randomSeed()
    // Bind through a separate profile so the verify cache is empty and the
    // verify must hit the remote, which is then made unreachable.
    await bindPassphrase({
      seed,
      controller: DATA_CONTROLLER,
      passphrase: 'unreachable verify passphrase',
      idb: createFakeIdb(),
      kdf: KDF
    })
    const networkError = new WasError('NetworkError when attempting to fetch', {
      cause: new TypeError('NetworkError when attempting to fetch')
    })
    wasState.getError = networkError

    await expect(
      changePassphrase({
        seed,
        controller: DATA_CONTROLLER,
        oldPassphrase: 'unreachable verify passphrase',
        newPassphrase: 'brand new passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBe(networkError)
  })

  it('reports oldPassphraseRetired: false when the old Space deletion fails', async () => {
    const idb = createFakeIdb()
    const seed = randomSeed()
    await bindPassphrase({
      seed,
      controller: DATA_CONTROLLER,
      passphrase: 'delete-fails old passphrase',
      idb,
      kdf: KDF
    })
    vi.mocked(deleteUnlockSpace).mockRejectedValueOnce(
      new Error('delete failed')
    )

    const { oldPassphraseRetired } = await changePassphrase({
      seed,
      controller: DATA_CONTROLLER,
      oldPassphrase: 'delete-fails old passphrase',
      newPassphrase: 'delete-fails new passphrase',
      idb,
      kdf: KDF
    })

    expect(oldPassphraseRetired).toBe(false)
  })

  it('preserves the bound email across the rebind', async () => {
    const idb = createFakeIdb()
    const seed = randomSeed()
    await bindPassphrase({
      seed,
      controller: DATA_CONTROLLER,
      passphrase: 'email rebind old passphrase',
      email: 'holder@example.com',
      idb,
      kdf: KDF
    })

    await changePassphrase({
      seed,
      controller: DATA_CONTROLLER,
      oldPassphrase: 'email rebind old passphrase',
      newPassphrase: 'email rebind new passphrase',
      idb,
      kdf: KDF
    })

    const found = await fetchKeyringSeed({
      passphrase: 'email rebind new passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.email).toBe('holder@example.com')
  })

  it('does not delete the Space when old and new passphrases are equal', async () => {
    const idb = createFakeIdb()
    const seed = randomSeed()
    await bindPassphrase({
      seed,
      controller: DATA_CONTROLLER,
      passphrase: 'same passphrase',
      idb,
      kdf: KDF
    })
    const spaceId = (await unlockFor('same passphrase')).spaceId

    await changePassphrase({
      seed,
      controller: DATA_CONTROLLER,
      oldPassphrase: 'same passphrase',
      newPassphrase: 'same passphrase',
      idb,
      kdf: KDF
    })

    expect(deleteUnlockSpace).not.toHaveBeenCalled()
    expect(wasState.spaces.has(spaceId)).toBe(true)
  })
})

describe('verifyPassphrase', () => {
  it('resolves for the bound passphrase and correct controller', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'verify correct passphrase',
      idb,
      kdf: KDF
    })

    await expect(
      verifyPassphrase({
        controller: DATA_CONTROLLER,
        passphrase: 'verify correct passphrase',
        idb,
        kdf: KDF
      })
    ).resolves.toBeUndefined()
  })

  it('throws WrongPassphraseError for a wrong passphrase', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'the correct passphrase',
      idb,
      kdf: KDF
    })

    await expect(
      verifyPassphrase({
        controller: DATA_CONTROLLER,
        passphrase: 'a wrong passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBeInstanceOf(WrongPassphraseError)
  })

  it('throws WrongPassphraseError when the controller does not match', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'verify mismatch passphrase',
      plaintext: {
        seed: seedToBase64Url(randomSeed()),
        controller: 'did:key:z6MkSomeOtherDataController',
        createdAt: new Date().toISOString()
      }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      verifyPassphrase({
        controller: DATA_CONTROLLER,
        passphrase: 'verify mismatch passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBeInstanceOf(WrongPassphraseError)
  })

  it('rethrows an unreachable remote (not a wrong passphrase)', async () => {
    const seed = randomSeed()
    // Bind through a separate profile so the verify cache is empty and the
    // verify must hit the remote, which is then made unreachable.
    await bindPassphrase({
      seed,
      controller: DATA_CONTROLLER,
      passphrase: 'verify unreachable passphrase',
      idb: createFakeIdb(),
      kdf: KDF
    })
    const networkError = new WasError('NetworkError when attempting to fetch', {
      cause: new TypeError('NetworkError when attempting to fetch')
    })
    wasState.getError = networkError

    await expect(
      verifyPassphrase({
        controller: DATA_CONTROLLER,
        passphrase: 'verify unreachable passphrase',
        idb: createFakeIdb(),
        kdf: KDF
      })
    ).rejects.toBe(networkError)
  })
})

describe('deleteKeyring', () => {
  it('deletes the unlock Space and the local cache', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'delete keyring passphrase',
      idb,
      kdf: KDF
    })
    const { spaceId } = await unlockFor('delete keyring passphrase')

    const { unlockSpaceDeleted } = await deleteKeyring({
      passphrase: 'delete keyring passphrase',
      idb,
      kdf: KDF
    })

    expect(unlockSpaceDeleted).toBe(true)
    expect(deleteUnlockSpace).toHaveBeenCalledOnce()
    expect(wasState.spaces.has(spaceId)).toBe(false)
    await expect(loadKeyringCache({ spaceId, idb })).resolves.toBeNull()
    // The keyring is gone: no seed resolves for this passphrase any more.
    await expect(
      fetchKeyringSeed({
        passphrase: 'delete keyring passphrase',
        idb,
        kdf: KDF
      })
    ).resolves.toBeNull()
  })

  it('clears the cache and reports unlockSpaceDeleted: false when the remote delete fails', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'delete-fails keyring passphrase',
      idb,
      kdf: KDF
    })
    const { spaceId } = await unlockFor('delete-fails keyring passphrase')
    vi.mocked(deleteUnlockSpace).mockRejectedValueOnce(
      new Error('delete failed')
    )

    const { unlockSpaceDeleted } = await deleteKeyring({
      passphrase: 'delete-fails keyring passphrase',
      idb,
      kdf: KDF
    })

    expect(unlockSpaceDeleted).toBe(false)
    await expect(loadKeyringCache({ spaceId, idb })).resolves.toBeNull()
  })

  it('clears the cache with no remote call when no WAS server is configured', async () => {
    wasState.url = undefined
    const idb = createFakeIdb()
    await bindPassphrase({
      seed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'delete no-was passphrase',
      idb,
      kdf: KDF
    })
    const { spaceId } = await unlockFor('delete no-was passphrase')

    const { unlockSpaceDeleted } = await deleteKeyring({
      passphrase: 'delete no-was passphrase',
      idb,
      kdf: KDF
    })

    expect(unlockSpaceDeleted).toBe(true)
    expect(deleteUnlockSpace).not.toHaveBeenCalled()
    await expect(loadKeyringCache({ spaceId, idb })).resolves.toBeNull()
  })
})

describe('deriveUnlockIdentity (method-agnostic derivation)', () => {
  /**
   * Frozen derivation vectors: these pin the production KDF salts (and the
   * whole derivation pipeline, down to the did:key encoding and the spaceId
   * hash) forever. If any of these values changes, existing users can no
   * longer locate their keyring -- so a failure here is a red flag, not a
   * value to blindly update.
   */
  describe('frozen derivation vectors', () => {
    it('pins the passphrase (PBKDF2) unlock Space under the real KEYRING_KDF', async () => {
      const { agent, spaceId } = await deriveUnlockIdentity({
        secret: 'freewallet test vector passphrase',
        kdf: KEYRING_KDF
      })
      expect(agent.id).toBe(
        'did:key:z6Mku4aGYK4PLysHqrpUNzoNbiu4ixzAEUEkefqamgFwY6vD'
      )
      expect(spaceId).toBe('PVkVUyJ24oyQh2BebkeUOygDfR5opfhJhG4KkMYTlzU')
    })

    it('pins the passkey (HKDF) unlock Space under the real PASSKEY_KDF', async () => {
      const secret = new Uint8Array(32)
      for (let index = 0; index < 32; index++) {
        secret[index] = index
      }
      const { agent, spaceId } = await deriveUnlockIdentity({
        secret,
        kdf: PASSKEY_KDF
      })
      expect(agent.id).toBe(
        'did:key:z6MkrWQ669H4SiPPYSHKhcx1QnWS5oP1gbD45GkQLVU6ecPU'
      )
      expect(spaceId).toBe('aAW83Cs-iZk6xEx8eYqF8WcKo6v5PE8CwEeYToOELkM')
    })
  })

  describe('KDF-family and salt separation', () => {
    // A fixed 32-byte input reused across the separation cases, so any
    // difference in derived Space is attributable to the KDF alone.
    const fixedSecret = new Uint8Array(32)
    for (let index = 0; index < 32; index++) {
      fixedSecret[index] = (index * 7 + 3) & 0xff
    }

    it('derives different Spaces under PBKDF2 vs HKDF for the same input (equal salts)', async () => {
      const sharedSalt = 'freewallet/test/shared-salt'
      const pbkdf2 = await deriveUnlockIdentity({
        secret: fixedSecret,
        kdf: {
          version: 1,
          algorithm: 'PBKDF2',
          iterations: 2,
          hash: 'SHA-256',
          salt: sharedSalt
        }
      })
      const hkdf = await deriveUnlockIdentity({
        secret: fixedSecret,
        kdf: {
          version: 1,
          algorithm: 'HKDF',
          hash: 'SHA-256',
          salt: sharedSalt,
          info: 'freewallet/test/info'
        }
      })
      expect(hkdf.spaceId).not.toBe(pbkdf2.spaceId)
    })

    it('derives different Spaces under two HKDF kdfs differing only in salt', async () => {
      const info = 'freewallet/test/info'
      const saltA = await deriveUnlockIdentity({
        secret: fixedSecret,
        kdf: {
          version: 1,
          algorithm: 'HKDF',
          hash: 'SHA-256',
          salt: 'freewallet/test/salt-a',
          info
        }
      })
      const saltB = await deriveUnlockIdentity({
        secret: fixedSecret,
        kdf: {
          version: 1,
          algorithm: 'HKDF',
          hash: 'SHA-256',
          salt: 'freewallet/test/salt-b',
          info
        }
      })
      expect(saltB.spaceId).not.toBe(saltA.spaceId)
    })

    it('derives different Spaces under two HKDF kdfs differing only in info', async () => {
      const salt = 'freewallet/test/shared-salt'
      const infoA = await deriveUnlockIdentity({
        secret: fixedSecret,
        kdf: {
          version: 1,
          algorithm: 'HKDF',
          hash: 'SHA-256',
          salt,
          info: 'freewallet/test/info-a'
        }
      })
      const infoB = await deriveUnlockIdentity({
        secret: fixedSecret,
        kdf: {
          version: 1,
          algorithm: 'HKDF',
          hash: 'SHA-256',
          salt,
          info: 'freewallet/test/info-b'
        }
      })
      expect(infoB.spaceId).not.toBe(infoA.spaceId)
    })
  })

  describe('bindUnlockSecret with an injected PRF output', () => {
    it('binds and recovers a data seed under a 32-byte passkey-PRF secret', async () => {
      const idb = createFakeIdb()
      const prfOutput = new Uint8Array(32)
      crypto.getRandomValues(prfOutput)
      const seed = randomSeed()

      await bindUnlockSecret({
        seed,
        controller: DATA_CONTROLLER,
        secret: prfOutput,
        kdf: PASSKEY_KDF,
        idb
      })

      const found = await fetchKeyringSeed({
        secret: prfOutput,
        kdf: PASSKEY_KDF,
        idb
      })
      expect(found).not.toBeNull()
      expect(Array.from(found!.seed)).toEqual(Array.from(seed))
      expect(found!.controller).toBe(DATA_CONTROLLER)
    })

    it('misses (returns null) for a different 32-byte secret', async () => {
      const idb = createFakeIdb()
      const prfOutput = new Uint8Array(32)
      crypto.getRandomValues(prfOutput)

      await bindUnlockSecret({
        seed: randomSeed(),
        controller: DATA_CONTROLLER,
        secret: prfOutput,
        kdf: PASSKEY_KDF,
        idb
      })

      const otherOutput = new Uint8Array(32)
      crypto.getRandomValues(otherOutput)
      const miss = await fetchKeyringSeed({
        secret: otherOutput,
        kdf: PASSKEY_KDF,
        idb
      })
      expect(miss).toBeNull()
    })
  })
})

describe('management zcap delegation', () => {
  /**
   * The unlock Space URL a management zcap targets, built exactly as the module
   * builds it from the mocked WAS url.
   */
  function unlockSpaceUrl(spaceId: string): string {
    return new URL(`/space/${spaceId}`, wasState.url).toString()
  }

  describe('bindUnlockSecret with delegateManagementTo', () => {
    it('delegates a GET/DELETE zcap on the unlock Space to the data identity', async () => {
      const idb = createFakeIdb()
      const { manageCapability, unlockSpaceId } = await bindUnlockSecret({
        seed: randomSeed(),
        controller: DATA_CONTROLLER,
        secret: 'manage delegate passphrase',
        kdf: KDF,
        delegateManagementTo: DATA_CONTROLLER,
        idb
      })

      expect(manageCapability).toBeDefined()
      const cap = manageCapability as IDelegatedZcap
      expect(cap.controller).toBe(DATA_CONTROLLER)
      expect(cap.allowedAction).toEqual(['GET', 'DELETE'])
      expect(cap.invocationTarget).toBe(unlockSpaceUrl(unlockSpaceId))

      // ~10 years out, within a generous minute of the expected instant.
      const expiresMs = Date.parse(cap.expires)
      const expectedMs = Date.now() + UNLOCK_MANAGE_ZCAP_TTL_MS
      expect(Math.abs(expiresMs - expectedMs)).toBeLessThan(60_000)
    })

    it('returns no capability without delegateManagementTo', async () => {
      const idb = createFakeIdb()
      const { manageCapability } = await bindUnlockSecret({
        seed: randomSeed(),
        controller: DATA_CONTROLLER,
        secret: 'no delegate passphrase',
        kdf: KDF,
        idb
      })
      expect(manageCapability).toBeUndefined()
    })

    it('returns no capability when no WAS server is configured', async () => {
      wasState.url = undefined
      const idb = createFakeIdb()
      const { manageCapability } = await bindUnlockSecret({
        seed: randomSeed(),
        controller: DATA_CONTROLLER,
        secret: 'no was delegate passphrase',
        kdf: KDF,
        delegateManagementTo: DATA_CONTROLLER,
        idb
      })
      expect(manageCapability).toBeUndefined()
    })
  })

  describe('fetchKeyringSeed with mintManageCapability', () => {
    it('returns the unlock Space id and a capability delegated to the recovered controller', async () => {
      const idb = createFakeIdb()
      const { spaceId } = await unlockFor('mint on fetch passphrase')
      await bindPassphrase({
        seed: randomSeed(),
        controller: DATA_CONTROLLER,
        passphrase: 'mint on fetch passphrase',
        idb,
        kdf: KDF
      })

      const found = await fetchKeyringSeed({
        passphrase: 'mint on fetch passphrase',
        idb,
        kdf: KDF,
        mintManageCapability: true
      })

      expect(found).not.toBeNull()
      expect(found!.unlockSpaceId).toBe(spaceId)
      const cap = found!.manageCapability as IDelegatedZcap
      expect(cap.controller).toBe(DATA_CONTROLLER)
      expect(cap.allowedAction).toEqual(['GET', 'DELETE'])
      expect(cap.invocationTarget).toBe(unlockSpaceUrl(spaceId))
    })

    it('returns the unlock Space id but no capability without mintManageCapability', async () => {
      const idb = createFakeIdb()
      const { spaceId } = await unlockFor('no mint passphrase')
      await bindPassphrase({
        seed: randomSeed(),
        controller: DATA_CONTROLLER,
        passphrase: 'no mint passphrase',
        idb,
        kdf: KDF
      })

      const found = await fetchKeyringSeed({
        passphrase: 'no mint passphrase',
        idb,
        kdf: KDF
      })
      expect(found!.unlockSpaceId).toBe(spaceId)
      expect(found!.manageCapability).toBeUndefined()
    })
  })

  describe('changePassphrase return value', () => {
    it("returns the new passphrase's unlock Space id and management capability", async () => {
      const idb = createFakeIdb()
      const seed = randomSeed()
      await bindPassphrase({
        seed,
        controller: DATA_CONTROLLER,
        passphrase: 'change return old passphrase',
        idb,
        kdf: KDF
      })
      const newSpace = (await unlockFor('change return new passphrase')).spaceId

      const { unlockSpaceId, manageCapability } = await changePassphrase({
        seed,
        controller: DATA_CONTROLLER,
        oldPassphrase: 'change return old passphrase',
        newPassphrase: 'change return new passphrase',
        idb,
        kdf: KDF
      })

      expect(unlockSpaceId).toBe(newSpace)
      const cap = manageCapability as IDelegatedZcap
      expect(cap.controller).toBe(DATA_CONTROLLER)
      expect(cap.allowedAction).toEqual(['GET', 'DELETE'])
      expect(cap.invocationTarget).toBe(unlockSpaceUrl(newSpace))
    })
  })
})
