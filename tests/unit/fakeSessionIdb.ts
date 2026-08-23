/**
 * A fuller in-memory `IDBFactory` fake for tests that exercise the shared
 * wipe enumeration: beside the get/put/delete the sessionKey helpers need,
 * it supports `databases()` (the create-nothing probe), `getAllKeys()` (the
 * prefix scan), and transaction completion events -- and it exposes the
 * backing store so a test can assert wipe completeness by DIRECT
 * enumeration, not by the deleter's own report.
 */

/**
 * The `open` shape models the real create-nothing probe: a versionless open
 * of an absent database still fires `onupgradeneeded` with `oldVersion: 0`,
 * and aborting that versionchange transaction leaves the database
 * uncreated (the request then fails with an `AbortError`). With
 * `enumerable: false` the factory carries no `databases()` at all -- the
 * engine the fallback probe exists for.
 *
 * @param [options] {object}
 * @param [options.enumerable] {boolean}   whether the factory exposes
 *   `databases()` (default true)
 * @returns {{ idb: IDBFactory, sessionStore: Map<string, unknown>, databaseNames: Set<string> }}
 */
export function createFakeSessionIdb({
  enumerable = true
}: { enumerable?: boolean } = {}): {
  idb: IDBFactory
  sessionStore: Map<string, unknown>
  databaseNames: Set<string>
} {
  const databaseNames = new Set<string>()
  const storesByDb = new Map<string, Map<string, Map<string, unknown>>>()

  type Request = {
    onsuccess?: () => void
    onupgradeneeded?: (event: { oldVersion: number }) => void
    onerror?: () => void
    onblocked?: () => void
    transaction?: { abort: () => void }
    result?: unknown
    error?: unknown
  }

  function makeTransaction(stores: Map<string, Map<string, unknown>>) {
    let pending = 0
    let settledAny = false
    const transaction: {
      oncomplete?: () => void
      onerror?: () => void
      onabort?: () => void
      error?: unknown
      objectStore: (name: string) => unknown
    } = {
      objectStore(name: string) {
        let store = stores.get(name)
        if (!store) {
          store = new Map()
          stores.set(name, store)
        }
        const backing = store
        function run(fn: () => unknown): Request {
          pending++
          const request: Request = {}
          queueMicrotask(() => {
            request.result = fn()
            request.onsuccess?.()
            pending--
            settledAny = true
            if (pending === 0) {
              queueMicrotask(() => {
                if (pending === 0 && settledAny) {
                  settledAny = false
                  transaction.oncomplete?.()
                }
              })
            }
          })
          return request
        }
        return {
          get: (key: string) => run(() => backing.get(key)),
          put: (value: unknown, key: string) =>
            run(() => {
              backing.set(key, value)
              return key
            }),
          delete: (key: string) =>
            run(() => {
              backing.delete(key)
              return undefined
            }),
          getAllKeys: () => run(() => [...backing.keys()])
        }
      }
    }
    return transaction
  }

  function makeDb(name: string) {
    let stores = storesByDb.get(name)
    if (!stores) {
      stores = new Map()
      storesByDb.set(name, stores)
    }
    const dbStores = stores
    return {
      createObjectStore(storeName: string) {
        if (!dbStores.has(storeName)) {
          dbStores.set(storeName, new Map())
        }
        return {}
      },
      transaction: () => makeTransaction(dbStores),
      close() {}
    }
  }

  const idb = {
    open(name: string) {
      const request: Request = {}
      let aborted = false
      request.transaction = {
        abort() {
          aborted = true
        }
      }
      queueMicrotask(() => {
        const fresh = !databaseNames.has(name)
        request.result = makeDb(name)
        if (fresh) {
          request.onupgradeneeded?.({ oldVersion: 0 })
          if (aborted) {
            request.error = { name: 'AbortError' }
            request.onerror?.()
            return
          }
        }
        databaseNames.add(name)
        request.onsuccess?.()
      })
      return request
    },
    ...(enumerable
      ? {
          async databases() {
            return [...databaseNames].map(name => ({ name, version: 1 }))
          }
        }
      : {})
  } as unknown as IDBFactory

  // The single session object store, pre-wired so tests can seed and
  // enumerate it directly (created lazily on first open otherwise).
  const sessionStores = new Map<string, Map<string, unknown>>()
  storesByDb.set('freewallet-session', sessionStores)
  const sessionStore = new Map<string, unknown>()
  sessionStores.set('session', sessionStore)

  return { idb, sessionStore, databaseNames }
}
