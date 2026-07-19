// @vitest-environment node
/**
 * Unit tests for the browser session key module (`src/lib/sessionKey.ts`):
 * did:key derivation from a
 * WebCrypto Ed25519 public key and the pluggable signer wrapper. The
 * IndexedDB persistence paths are exercised by the e2e-was suite (node has
 * no IndexedDB).
 */
import { describe, expect, it } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import {
  clearPersistedSession,
  deleteKeyringCache,
  deletePasskeySafetyNotice,
  deleteVaultEnvelope,
  loadKeyringCache,
  loadPasskeySafetyNotice,
  loadVaultEnvelope,
  savePasskeySafetyNotice,
  saveKeyringCache,
  saveSessionRecord,
  saveVaultEnvelope,
  loadSessionRecord,
  sessionKeyDid,
  sessionKeySigner
} from '@/lib/sessionKey'

/**
 * A minimal in-memory `IDBFactory` sufficient for the session-store helpers
 * (a single object store, get/put/delete by key). Node has no IndexedDB, so
 * the cache helpers are exercised against this fake instead.
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

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey('Ed25519', false, [
    'sign',
    'verify'
  ])) as CryptoKeyPair
}

describe('sessionKeyDid', () => {
  it('derives a did:key with the Ed25519 multicodec fingerprint', async () => {
    const { publicKey } = await generateKeyPair()
    const { did, verificationMethodId } = await sessionKeyDid({ publicKey })
    expect(did).toMatch(/^did:key:z6Mk/)
    const fingerprint = did.slice('did:key:'.length)
    expect(verificationMethodId).toBe(`${did}#${fingerprint}`)
  })

  it('is deterministic for the same public key', async () => {
    const { publicKey } = await generateKeyPair()
    const first = await sessionKeyDid({ publicKey })
    const second = await sessionKeyDid({ publicKey })
    expect(second).toEqual(first)
  })
})

describe('sessionKeySigner', () => {
  it('signs payloads verifiable against the exported public key', async () => {
    const keyPair = await generateKeyPair()
    const { signer, did } = await sessionKeySigner({ keyPair })
    expect(signer.id).toBe(`${did}#${did.slice('did:key:'.length)}`)

    const data = new TextEncoder().encode('capability invocation bytes')
    const signature = await signer.sign({ data })

    const publicKeyJwk = (await crypto.subtle.exportKey(
      'jwk',
      keyPair.publicKey
    )) as { kty: 'OKP'; crv: 'Ed25519'; x: string }
    const verificationKey = await Ed25519VerificationKey.fromJsonWebKey({
      type: 'JsonWebKey',
      publicKeyJwk
    })
    const verifier = verificationKey.verifier()
    expect(await verifier.verify({ data, signature })).toBe(true)
  })
})

describe('keyring cache helpers', () => {
  it('round-trips save / load / delete keyed by unlock Space id', async () => {
    const idb = createFakeIdb()
    const record = { version: 1, wrapped: { jwe: { ciphertext: 'x' } } }

    await expect(
      loadKeyringCache({ spaceId: 'space-a', idb })
    ).resolves.toBeNull()

    await saveKeyringCache({ spaceId: 'space-a', record, idb })
    await expect(
      loadKeyringCache({ spaceId: 'space-a', idb })
    ).resolves.toEqual({ record, cachedAt: expect.any(Number) })

    await deleteKeyringCache({ spaceId: 'space-a', idb })
    await expect(
      loadKeyringCache({ spaceId: 'space-a', idb })
    ).resolves.toBeNull()
  })

  it('stamps the entry with the write time', async () => {
    const idb = createFakeIdb()
    const before = Date.now()
    await saveKeyringCache({ spaceId: 'space-a', record: { n: 1 }, idb })
    const after = Date.now()

    const entry = await loadKeyringCache({ spaceId: 'space-a', idb })
    expect(entry!.cachedAt).toBeGreaterThanOrEqual(before)
    expect(entry!.cachedAt).toBeLessThanOrEqual(after)
  })

  it('returns a legacy bare record with cachedAt: null', async () => {
    const idb = createFakeIdb()
    const legacyRecord = { version: 1, wrapped: { jwe: { ciphertext: 'x' } } }
    // Written directly (no write-time stamp), as caches predating timestamps.
    const db = await new Promise<IDBDatabase>(resolve => {
      const request = idb.open('freewallet-session', 1)
      request.onsuccess = () => resolve(request.result)
    })
    await new Promise<void>(resolve => {
      const request = db
        .transaction('session', 'readwrite')
        .objectStore('session')
        .put(legacyRecord, 'keyring/space-legacy')
      request.onsuccess = () => resolve()
    })

    await expect(
      loadKeyringCache({ spaceId: 'space-legacy', idb })
    ).resolves.toEqual({ record: legacyRecord, cachedAt: null })
  })

  it('keeps separate caches per Space id', async () => {
    const idb = createFakeIdb()
    await saveKeyringCache({ spaceId: 'space-a', record: { n: 1 }, idb })
    await saveKeyringCache({ spaceId: 'space-b', record: { n: 2 }, idb })

    await expect(
      loadKeyringCache({ spaceId: 'space-a', idb })
    ).resolves.toMatchObject({ record: { n: 1 } })
    await expect(
      loadKeyringCache({ spaceId: 'space-b', idb })
    ).resolves.toMatchObject({ record: { n: 2 } })
  })

  it('survives clearPersistedSession (logout leaves the cache intact)', async () => {
    const idb = createFakeIdb()
    await saveSessionRecord({ record: { session: true }, idb })
    await saveKeyringCache({
      spaceId: 'space-a',
      record: { keyring: true },
      idb
    })

    await clearPersistedSession({ idb })

    await expect(loadSessionRecord({ idb })).resolves.toBeNull()
    await expect(
      loadKeyringCache({ spaceId: 'space-a', idb })
    ).resolves.toMatchObject({ record: { keyring: true } })
  })
})

describe('passkey-safety notice helpers', () => {
  it('round-trips save / load / delete keyed by controller', async () => {
    const idb = createFakeIdb()
    const controller = 'did:key:z6MkController'

    await expect(
      loadPasskeySafetyNotice({ controller, idb })
    ).resolves.toBeNull()

    await savePasskeySafetyNotice({
      controller,
      backupEligibility: true,
      backupState: false,
      idb
    })
    await expect(loadPasskeySafetyNotice({ controller, idb })).resolves.toEqual(
      {
        backupEligibility: true,
        backupState: false,
        createdAt: expect.any(String)
      }
    )

    await deletePasskeySafetyNotice({ controller, idb })
    await expect(
      loadPasskeySafetyNotice({ controller, idb })
    ).resolves.toBeNull()
  })

  it('stamps the notice with an ISO createdAt', async () => {
    const idb = createFakeIdb()
    const controller = 'did:key:z6MkController'
    const before = Date.now()
    await savePasskeySafetyNotice({
      controller,
      backupEligibility: false,
      backupState: false,
      idb
    })
    const after = Date.now()

    const notice = await loadPasskeySafetyNotice({ controller, idb })
    const stamped = Date.parse(notice!.createdAt)
    expect(stamped).toBeGreaterThanOrEqual(before)
    expect(stamped).toBeLessThanOrEqual(after)
  })

  it('keeps separate notices per controller', async () => {
    const idb = createFakeIdb()
    await savePasskeySafetyNotice({
      controller: 'did:key:z6MkA',
      backupEligibility: true,
      backupState: true,
      idb
    })
    await savePasskeySafetyNotice({
      controller: 'did:key:z6MkB',
      backupEligibility: false,
      backupState: false,
      idb
    })

    await expect(
      loadPasskeySafetyNotice({ controller: 'did:key:z6MkA', idb })
    ).resolves.toMatchObject({ backupEligibility: true, backupState: true })
    await expect(
      loadPasskeySafetyNotice({ controller: 'did:key:z6MkB', idb })
    ).resolves.toMatchObject({ backupEligibility: false, backupState: false })
  })
})

describe('vault envelope helpers', () => {
  /**
   * A distinct WebCrypto value for the wrapping-key half of the pair; the fake
   * IDB stores values by reference, so any object round-trips.
   *
   * @returns {Promise<CryptoKey>}
   */
  async function generateWrappingKey(): Promise<CryptoKey> {
    return (await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )) as CryptoKey
  }

  it('round-trips save / load / delete of the envelope pair', async () => {
    const idb = createFakeIdb()
    const wrappingKey = await generateWrappingKey()
    const envelope = { version: 1, iv: new Uint8Array([1, 2, 3]) }

    await expect(loadVaultEnvelope({ idb })).resolves.toBeNull()

    await saveVaultEnvelope({ wrappingKey, envelope, idb })
    await expect(loadVaultEnvelope({ idb })).resolves.toEqual({
      wrappingKey,
      envelope
    })

    await deleteVaultEnvelope({ idb })
    await expect(loadVaultEnvelope({ idb })).resolves.toBeNull()
  })

  it('returns null when either half of the pair is missing', async () => {
    const wrappingKey = await generateWrappingKey()
    const envelope = { version: 1 }

    // Envelope present, wrapping key missing.
    const idbNoKey = createFakeIdb()
    await saveVaultEnvelope({
      wrappingKey: undefined as unknown as CryptoKey,
      envelope,
      idb: idbNoKey
    })
    await expect(loadVaultEnvelope({ idb: idbNoKey })).resolves.toBeNull()

    // Wrapping key present, envelope missing.
    const idbNoEnvelope = createFakeIdb()
    await saveVaultEnvelope({
      wrappingKey,
      envelope: undefined,
      idb: idbNoEnvelope
    })
    await expect(loadVaultEnvelope({ idb: idbNoEnvelope })).resolves.toBeNull()
  })

  it('is removed by clearPersistedSession alongside the session record', async () => {
    const idb = createFakeIdb()
    const wrappingKey = await generateWrappingKey()
    await saveSessionRecord({ record: { session: true }, idb })
    await saveVaultEnvelope({ wrappingKey, envelope: { version: 1 }, idb })

    await clearPersistedSession({ idb })

    await expect(loadSessionRecord({ idb })).resolves.toBeNull()
    await expect(loadVaultEnvelope({ idb })).resolves.toBeNull()
  })
})
