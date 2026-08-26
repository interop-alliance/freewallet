/**
 * Residue-zero storage assertions for the transient-session e2e coverage:
 * after a transient (public-terminal) visit ends, the browser must hold no
 * trace of it -- no IndexedDB database (no `freewallet-session`, no
 * `*-wallet-db`), no new localStorage key, and an empty sessionStorage.
 *
 * The localStorage check is a before/after DELTA rather than a prefix match:
 * the UI-pref keys (`fw-theme`, `fw-ui-language`, ...) carry no `freewallet:`
 * prefix, so a prefix match would let them leak through. Capture the baseline
 * with `captureLocalStorageKeys` as soon as the page under test has loaded,
 * before any login input.
 *
 * The IndexedDB check goes through CDP (`IndexedDB.requestDatabaseNames`)
 * rather than the page's own `indexedDB.databases()`, so the assertion
 * inspects the browser's storage from outside the page under test.
 *
 * Shared by the WAS transient-login spec and, verbatim, by the login-form
 * rerun. The CHAPI popup variant uses the frame-scoped twin below: the popup
 * is a third-party iframe, so what has to come back empty is its PARTITIONED
 * bucket, not the origin's first-party one (a remembered browser's durable
 * database legitimately stands in the latter). A partitioned bucket has no
 * plain security origin to hand CDP, so that twin reads from inside a fresh
 * document in the same partition instead.
 */
import { expect, type Frame, type Page } from '@playwright/test'

/**
 * The localStorage keys present on the page's origin right now -- the
 * baseline for the before/after delta in `expectNoStorageResidue`.
 *
 * @param options {object}
 * @param options.page {Page}   a page on the origin under test
 * @returns {Promise<string[]>}
 */
export async function captureLocalStorageKeys({
  page
}: {
  page: Page
}): Promise<string[]> {
  return page.evaluate(() => Object.keys(window.localStorage))
}

/**
 * The residue-zero assertion set: IndexedDB holds no database at all on the
 * page's origin (via CDP), localStorage gained no key over the baseline, and
 * sessionStorage is empty.
 *
 * @param options {object}
 * @param options.page {Page}   a page on the origin under test (after a
 *   crash simulation, a fresh page in the same context)
 * @param options.baselineLocalStorageKeys {string[]}   the keys captured
 *   before the visit under test did anything
 * @returns {Promise<void>}
 */
export async function expectNoStorageResidue({
  page,
  baselineLocalStorageKeys
}: {
  page: Page
  baselineLocalStorageKeys: string[]
}): Promise<void> {
  const cdp = await page.context().newCDPSession(page)
  try {
    const origin = new URL(page.url()).origin
    const { databaseNames } = await cdp.send('IndexedDB.requestDatabaseNames', {
      securityOrigin: origin
    })
    expect(databaseNames, 'IndexedDB must hold no database').toEqual([])
  } finally {
    await cdp.detach()
  }

  const localStorageKeys = await captureLocalStorageKeys({ page })
  const gained = localStorageKeys.filter(
    key => !baselineLocalStorageKeys.includes(key)
  )
  expect(gained, 'localStorage must gain no key').toEqual([])

  const sessionStorageKeys = await page.evaluate(() =>
    Object.keys(window.sessionStorage)
  )
  expect(sessionStorageKeys, 'sessionStorage must be empty').toEqual([])
}

/**
 * The localStorage keys the given frame's partition holds right now -- the
 * frame-scoped baseline for {@link expectNoFrameStorageResidue}. A partition
 * whose storage the engine blocks outright (rather than partitioning) throws
 * on access; that reads as "holds nothing", which is what the caller is
 * asserting anyway.
 *
 * @param options {object}
 * @param options.frame {Frame}   the third-party frame under test
 * @returns {Promise<string[]>}
 */
export async function captureFrameLocalStorageKeys({
  frame
}: {
  frame: Frame
}): Promise<string[]> {
  return frame.evaluate(() => {
    try {
      return Object.keys(window.localStorage)
    } catch {
      return []
    }
  })
}

/**
 * The residue-zero assertion set for a third-party frame's partitioned
 * bucket: no IndexedDB database, no localStorage key gained over the
 * baseline, and an empty sessionStorage. Read from inside the frame, which
 * is the only accessor a partitioned bucket has -- so after a crash
 * simulation, pass a FRESH frame in the same partition rather than the one
 * the visit ran in.
 *
 * @param options {object}
 * @param options.frame {Frame}   a frame in the partition under test
 * @param options.baselineLocalStorageKeys {string[]}   the keys captured
 *   before the visit under test did anything
 * @returns {Promise<void>}
 */
export async function expectNoFrameStorageResidue({
  frame,
  baselineLocalStorageKeys
}: {
  frame: Frame
  baselineLocalStorageKeys: string[]
}): Promise<void> {
  // `indexedDB.databases()` is the only enumerator a partitioned bucket
  // exposes, and not every engine implements it (Firefox does not). An
  // engine that cannot enumerate must fail the assertion loudly rather than
  // pass it vacuously -- a silent empty list would read as "no residue" on
  // exactly the engines whose default this suite is meant to exercise.
  const databaseNames = await frame.evaluate(async () => {
    if (typeof indexedDB?.databases !== 'function') {
      return null
    }
    try {
      const databases = await indexedDB.databases()
      return databases.map(database => database.name ?? '')
    } catch {
      return []
    }
  })
  expect(
    databaseNames,
    'this engine cannot enumerate IndexedDB, so the popup partition cannot be checked from inside the frame'
  ).not.toBeNull()
  expect(
    databaseNames,
    "the popup partition's IndexedDB must hold no database"
  ).toEqual([])

  const localStorageKeys = await captureFrameLocalStorageKeys({ frame })
  const gained = localStorageKeys.filter(
    key => !baselineLocalStorageKeys.includes(key)
  )
  expect(gained, "the popup partition's localStorage must gain no key").toEqual(
    []
  )

  const sessionStorageKeys = await frame.evaluate(() => {
    try {
      return Object.keys(window.sessionStorage)
    } catch {
      return []
    }
  })
  expect(
    sessionStorageKeys,
    "the popup partition's sessionStorage must be empty"
  ).toEqual([])
}
