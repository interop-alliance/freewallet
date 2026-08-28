// @vitest-environment node
/**
 * Unit tests for the browser session key module (`src/lib/sessionKey.ts`):
 * the `freewallet-session` IndexedDB caches (keyring cache, passkey-safety
 * notice). Node has no IndexedDB, so the cache helpers are exercised against
 * a minimal in-memory fake.
 */
import { describe, expect, it, vi } from 'vitest'
import {
  deleteAccountDidForSpace,
  deleteKeyringCache,
  hasClientKeyRecord,
  saveClientKeyRecord,
  loadAccountDidForSpace,
  saveAccountDidForSpace,
  deletePasskeySafetyNotice,
  loadKeyringCache,
  loadPasskeySafetyNotice,
  savePasskeySafetyNotice,
  saveKeyringCache,
  sessionDatabaseExists
} from '@/lib/sessionKey'
import { createFakeSessionIdb } from './fakeSessionIdb'

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
    onupgradeneeded?: (event: { oldVersion: number }) => void
    onerror?: () => void
    transaction?: { abort: () => void }
    result?: unknown
    error?: unknown
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
      let aborted = false
      request.transaction = {
        abort() {
          aborted = true
        }
      }
      queueMicrotask(() => {
        request.result = makeDb()
        if (!initialized) {
          // A versionless open of an absent database still upgrades from
          // version 0; aborting that transaction leaves nothing created.
          request.onupgradeneeded?.({ oldVersion: 0 })
          if (aborted) {
            request.error = { name: 'AbortError' }
            request.onerror?.()
            return
          }
          initialized = true
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

describe('the Space-to-account-DID mapping', () => {
  const SPACE_ID = 'space-a'
  const ACCOUNT_DID = 'did:webvh:QmScidA:example.com:space-a'

  it('round-trips the Space-to-account-DID mapping', async () => {
    const idb = createFakeIdb()
    await expect(
      loadAccountDidForSpace({ spaceId: SPACE_ID, idb })
    ).resolves.toBeNull()
    await saveAccountDidForSpace({
      spaceId: SPACE_ID,
      accountDid: ACCOUNT_DID,
      idb
    })
    await expect(
      loadAccountDidForSpace({ spaceId: SPACE_ID, idb })
    ).resolves.toBe(ACCOUNT_DID)
    await deleteAccountDidForSpace({ spaceId: SPACE_ID, idb })
    await expect(
      loadAccountDidForSpace({ spaceId: SPACE_ID, idb })
    ).resolves.toBeNull()
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

describe('sessionDatabaseExists (the two-tier create-nothing probe)', () => {
  it('answers from the enumeration API where the engine has it', async () => {
    const { idb, databaseNames } = createFakeSessionIdb()
    await expect(sessionDatabaseExists({ idb })).resolves.toBe(false)
    databaseNames.add('freewallet-session')
    await expect(sessionDatabaseExists({ idb })).resolves.toBe(true)
  })

  it('falls back to the versionless open, creating nothing when absent', async () => {
    const { idb, databaseNames } = createFakeSessionIdb({ enumerable: false })
    await expect(sessionDatabaseExists({ idb })).resolves.toBe(false)
    // The versionchange transaction was aborted, so the probe left no
    // database behind -- the whole point of the fallback.
    expect(databaseNames.has('freewallet-session')).toBe(false)
  })

  it('reports an existing database through the fallback', async () => {
    const { idb, databaseNames } = createFakeSessionIdb({ enumerable: false })
    await saveClientKeyRecord({
      spaceId: 'unlock-space-1',
      record: { wrapped: true },
      idb
    })
    expect(databaseNames.has('freewallet-session')).toBe(true)
    await expect(sessionDatabaseExists({ idb })).resolves.toBe(true)
  })
})

describe('hasClientKeyRecord (the create-nothing probe)', () => {
  /**
   * Wraps the in-memory fake with a `databases()` enumeration so the probe's
   * existence check can run against it, counting `open` calls.
   */
  function probeIdb() {
    const base = createFakeIdb()
    let created = false
    const open = vi.fn((name: string, version?: number) => {
      created = true
      return (base.open as (name: string, version?: number) => IDBRequest)(
        name,
        version
      )
    })
    return {
      idb: {
        open,
        databases: async () =>
          created ? [{ name: 'freewallet-session', version: 1 }] : []
      } as unknown as IDBFactory,
      open
    }
  }

  it('reports false without ever opening when the database is absent', async () => {
    const { idb, open } = probeIdb()
    await expect(
      hasClientKeyRecord({ spaceId: 'unlock-space-1', idb })
    ).resolves.toBe(false)
    expect(open).not.toHaveBeenCalled()
  })

  it('opens an existing database and reports the record per unlock Space', async () => {
    const { idb } = probeIdb()
    await saveClientKeyRecord({
      spaceId: 'unlock-space-1',
      record: { wrapped: true },
      idb
    })
    await expect(
      hasClientKeyRecord({ spaceId: 'unlock-space-1', idb })
    ).resolves.toBe(true)
    // The database exists (another credential's record created it), but THIS
    // credential holds no record: still false.
    await expect(
      hasClientKeyRecord({ spaceId: 'unlock-space-2', idb })
    ).resolves.toBe(false)
  })

  it('answers from the versionless probe when the factory cannot be enumerated', async () => {
    const { idb, open } = probeIdb()
    // An engine whose factory carries no `databases()` falls back to the
    // versionless open, which still tells an existing database from an
    // absent one -- so a browser that IS remembered is not silently
    // downgraded to the transient session.
    const blind = { open } as unknown as IDBFactory
    await expect(
      hasClientKeyRecord({ spaceId: 'unlock-space-1', idb: blind })
    ).resolves.toBe(false)
    await saveClientKeyRecord({
      spaceId: 'unlock-space-1',
      record: { wrapped: true },
      idb
    })
    await expect(
      hasClientKeyRecord({ spaceId: 'unlock-space-1', idb: blind })
    ).resolves.toBe(true)
    await expect(
      hasClientKeyRecord({ spaceId: 'unlock-space-2', idb: blind })
    ).resolves.toBe(false)
  })
})
