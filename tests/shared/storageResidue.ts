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
 * rerun and the CHAPI popup variant (which points these at the popup's
 * partitioned page).
 */
import { expect, type Page } from '@playwright/test'

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
