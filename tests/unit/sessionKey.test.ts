// @vitest-environment node
/**
 * Unit tests for the browser session key module (`src/lib/sessionKey.ts`):
 * the `freewallet-session` IndexedDB caches (keyring cache, passkey-safety
 * notice). Node has no IndexedDB, so the cache helpers are exercised against
 * a minimal in-memory fake.
 */
import { describe, expect, it } from 'vitest'
import {
  deleteKeyringCache,
  deletePasskeySafetyNotice,
  loadKeyringCache,
  loadPasskeySafetyNotice,
  savePasskeySafetyNotice,
  saveKeyringCache
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
