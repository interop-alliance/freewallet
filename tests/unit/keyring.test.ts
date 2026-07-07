// @vitest-environment node
/**
 * Unit tests for the keyring v2 module (`src/session/keyring.ts`): the unlock
 * derivation (deterministic, passphrase-sensitive), the wrap/unwrap round-trip
 * and its record validation, and the `fetchKeyringSeed` / `bindPassphrase` /
 * `changePassphrase` public contract across the WAS-configured and cache-only
 * branches. The unlock-Space WAS helpers are replaced by an in-memory fake
 * keyed by unlock Space id; the `freewallet-session` IndexedDB cache is backed
 * by a minimal in-memory `IDBFactory` (node has no IndexedDB). Tiny PBKDF2
 * iteration counts keep the derivation fast; the real EDV cipher and
 * CapabilityAgent / X25519 derivations run unmocked.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { WasError } from '@interop/was-client'
import { bufferToBase64Url, digestHash } from '@/lib/cidFrom'
import { createEdvDocCipher } from '@/stores/edvDocCipher'
import { loadKeyringCache } from '@/lib/sessionKey'

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
  changePassphrase,
  fetchKeyringSeed,
  WrongPassphraseError
} from '@/session/keyring'
import {
  deleteUnlockSpace,
  ensureUnlockSpace,
  getUnlockKeyring
} from '@/stores/wasRemoteStore'

const KDF = { iterations: 2, hash: 'SHA-256', salt: 'freewallet/test/unlock' }
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
})

describe('fetchKeyringSeed', () => {
  it('serves a cache hit without a remote read', async () => {
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
    expect(getUnlockKeyring).not.toHaveBeenCalled()
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
    await bindPassphrase(args)
    await expect(bindPassphrase(args)).resolves.toBeUndefined()

    const { spaceId } = await unlockFor('idempotent passphrase')
    expect(wasState.spaces.has(spaceId)).toBe(true)
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
