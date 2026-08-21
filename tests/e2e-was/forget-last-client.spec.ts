/**
 * The last-durable-client forget transition, end to end (WAS mode): an
 * account that has exactly one connected browser forgets it, and lands
 * client-less -- anchored on the sign-in credential's ladder alone, the same
 * shape a credential-anchored signup starts in.
 *
 * The walk: a credential-anchored signup (no durable client anywhere), a
 * second cold browser that self-enrolls durably and is therefore the
 * account's ONLY durable client, then that browser's Settings forget with
 * the transition copy confirmed. Afterwards the browser holds no wallet
 * database, the world-readable account log has grown by the transition's
 * entries and resolves with no durable client in `capabilityInvocation`
 * while the ladder VM still stands under `assertionMethod` and
 * `capabilityDelegation`, and a third cold terminal still reaches the
 * account -- and its stored credential -- with the passphrase alone.
 *
 * Every stage pays the deliberately slow unlock KDF on top of several WAS
 * ceremonies, hence `test.slow()` and the generous timeouts.
 */
import { test, expect, type Browser, type Page } from '@playwright/test'
import { readLogFromString, resolveDIDFromLog } from '@interop/did-method-webvh'
import {
  addCredentialViaPaste,
  fillSettled,
  forceRememberBrowser,
  signupViaWizard
} from './helpers'
import {
  captureLocalStorageKeys,
  expectNoStorageResidue
} from '../shared/storageResidue'

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

const REPLICA_DB_NAME_PATTERN = /-(?:wallet|credentials|sync)-db/

/**
 * Opens a fresh, cold browser context (empty IndexedDB and localStorage) to
 * stand in for another terminal. Callers must close the returned context.
 *
 * @param browser {Browser}
 * @returns {Promise<{ context: Awaited<ReturnType<Browser['newContext']>>,
 *   page: Page }>}
 */
async function coldTerminal(browser: Browser): Promise<{
  context: Awaited<ReturnType<Browser['newContext']>>
  page: Page
}> {
  const context = await browser.newContext({ baseURL: APP_URL })
  const page = await context.newPage()
  return { context, page }
}

/**
 * The wallet cards inside the connected-wallets list.
 *
 * @param page {Page}
 * @returns {import('@playwright/test').Locator}
 */
function walletCards(page: Page) {
  return page.getByTestId('enrolled-clients-list').locator('.MuiCard-root')
}

/**
 * Opens the Settings page and returns the world-readable `did.jsonl` URL the
 * page links, once did:webvh provisioning has landed (the rotate action only
 * renders behind a published log, so its presence is the signal).
 *
 * @param page {Page}
 * @returns {Promise<string>}
 */
async function readLogUrl(page: Page): Promise<string> {
  await page.goto('/#/settings')
  await expect(page.getByText('Published did:webvh DID')).toBeVisible({
    timeout: 30_000
  })
  await expect(
    page.getByRole('button', { name: 'Rotate update key' })
  ).toBeVisible({ timeout: 30_000 })
  const logLink = page.getByRole('link', { name: /\/id\/did\.jsonl$/ })
  await expect(logLink).toBeVisible()
  return (await logLink.getAttribute('href'))!
}

/**
 * Fetches and parses the world-readable account log through the page's
 * request context (an unauthenticated GET -- the log is public).
 *
 * @param page {Page}
 * @param logUrl {string}
 * @returns {Promise<ReturnType<typeof readLogFromString>>}
 */
async function fetchLog(page: Page, logUrl: string) {
  const response = await page.request.get(logUrl)
  expect(response.status()).toBe(200)
  return readLogFromString(await response.text())
}

/**
 * The IndexedDB database names this browser holds, read from inside the page.
 *
 * @param page {Page}
 * @returns {Promise<string[]>}
 */
async function readDatabaseNames(page: Page): Promise<string[]> {
  return page.evaluate(async () =>
    (await indexedDB.databases())
      .map(info => info.name)
      .filter((name): name is string => typeof name === 'string')
  )
}

/**
 * The keys left in the shared `freewallet-session` database, or an empty
 * list when the database is gone. The forget ceremony's grade clears the
 * account's entries out of that database rather than deleting the database
 * itself (it is browser-global, shared with every other account remembered
 * here), so the residue assertion is over its keys.
 *
 * @param page {Page}
 * @returns {Promise<string[]>}
 */
async function readSessionDatabaseKeys(page: Page): Promise<string[]> {
  return page.evaluate(async () => {
    const databases = await indexedDB.databases()
    if (!databases.some(info => info.name === 'freewallet-session')) {
      return []
    }
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open('freewallet-session')
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error)
    })
    try {
      const keys = await new Promise<IDBValidKey[]>((resolve, reject) => {
        const request = db
          .transaction('session', 'readonly')
          .objectStore('session')
          .getAllKeys()
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error)
      })
      return keys.filter((key): key is string => typeof key === 'string')
    } finally {
      db.close()
    }
  })
}

test.describe('The last-durable-client forget transition', () => {
  test('forgetting the only connected browser leaves the account ladder-anchored', async ({
    browser
  }, testInfo) => {
    test.slow()
    test.setTimeout(300_000)

    // --- Terminal A: the credential-anchored signup (no durable client). ---
    const first = await coldTerminal(browser)
    let passphrase: string
    try {
      const user = await signupViaWizard(first.page, testInfo, {
        rememberBrowser: false
      })
      passphrase = user.passphrase
      // Something to decrypt from a later terminal: the transient session
      // stores it over the replica-less remote-direct posture.
      await addCredentialViaPaste(first.page)
      await first.page.getByRole('button', { name: 'Log out' }).click()
      await expect(first.page).toHaveURL(/\/#?\/?$/)
    } finally {
      await first.context.close()
    }

    // --- Terminal B: the durable self-enrollment, then the forget. ---
    const second = await coldTerminal(browser)
    try {
      // The ceremony runs several ladder-signed WAS writes with no UI of its
      // own; a failure is far easier to place with the page's own errors in
      // hand, so they are collected and reported with the timeout.
      const pageErrors: string[] = []
      second.page.on('pageerror', err => {
        pageErrors.push(`pageerror: ${err.message}`)
      })
      second.page.on('console', message => {
        if (message.type() === 'error') {
          pageErrors.push(`console: ${message.text()}`)
        }
      })

      await second.page.goto('/#/login')
      // The cold profile is non-remembered, so the default login would be
      // transient; the standing passphrase self-enrolls this browser durably.
      await forceRememberBrowser(second.page)
      await fillSettled(
        second.page.locator('input[type="password"]'),
        passphrase
      )
      await second.page
        .getByRole('button', { name: 'Log in', exact: true })
        .click()
      await expect(second.page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })

      // The log as it stands before the transition, and the URL to re-read it
      // from afterwards (Settings is gone once the browser is forgotten).
      const logUrl = await readLogUrl(second.page)
      const logBefore = await fetchLog(second.page, logUrl)

      // Exactly one wallet card, and it is this browser: the account's only
      // durable client, so its exit is the transition rather than an
      // ordinary forget.
      await expect(walletCards(second.page)).toHaveCount(1, {
        timeout: 30_000
      })
      // Exact: the forget button's label ("Forget this browser") contains
      // the chip's text.
      await expect(
        second.page.getByText('This browser', { exact: true })
      ).toBeVisible()

      await second.page.getByTestId('forget-this-browser-button').click()
      // The transition copy is what the user confirms against, not the
      // ordinary forget copy.
      await expect(
        second.page.getByTestId('forget-last-client-copy')
      ).toBeVisible()
      await second.page.getByTestId('forget-this-browser-confirm').click()

      // The ceremony ends in a hard reload onto the login page (the wipe has
      // just deleted the storage this tab's handles point at).
      try {
        await expect(second.page).toHaveURL(/\/login/, { timeout: 180_000 })
      } catch (err) {
        throw new Error(
          `The forget transition did not reach the login page. Page errors:\n${pageErrors.join('\n')}`,
          { cause: err }
        )
      }

      // The wipe is real: the replica databases are gone, and the shared
      // session database holds neither this account's client-key record nor
      // its cached unlock records.
      await expect(async () => {
        const databases = await readDatabaseNames(second.page)
        expect(
          databases.filter(name => REPLICA_DB_NAME_PATTERN.test(name))
        ).toEqual([])
        const sessionKeys = await readSessionDatabaseKeys(second.page)
        expect(
          sessionKeys.filter(
            key => key.startsWith('client-keys/') || key.startsWith('keyring/')
          )
        ).toEqual([])
      }).toPass({ timeout: 60_000 })

      // The account log grew by the transition's entries and still resolves.
      const logAfter = await fetchLog(second.page, logUrl)
      expect(logAfter.length).toBeGreaterThanOrEqual(logBefore.length + 2)
      const resolved = await resolveDIDFromLog(logAfter)
      expect(resolved.meta.error).toBeUndefined()

      const document = resolved.doc as {
        capabilityInvocation?: unknown[]
        assertionMethod?: unknown[]
        capabilityDelegation?: unknown[]
      }
      // No durable client is left: the invocation relation the client
      // listing keys on is empty (or absent altogether).
      expect(document.capabilityInvocation ?? []).toHaveLength(0)
      // The account stays anchored by the credential's ladder VM.
      expect((document.assertionMethod ?? []).length).toBeGreaterThan(0)
      expect((document.capabilityDelegation ?? []).length).toBeGreaterThan(0)
    } finally {
      await second.context.close()
    }

    // --- Terminal C: the passphrase alone still opens the account. ---
    const third = await coldTerminal(browser)
    try {
      // The ordinary default transient login -- deliberately no remember
      // seam, and no durable client exists on the account to ride.
      await third.page.goto('/#/login')
      const baseline = await captureLocalStorageKeys({ page: third.page })
      await fillSettled(
        third.page.locator('input[type="password"]'),
        passphrase
      )
      await third.page
        .getByRole('button', { name: 'Log in', exact: true })
        .click()
      await expect(third.page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })

      // The credential terminal A stored still decrypts: the user key came
      // back through the credential's standing roster wrap, re-keyed by the
      // transition.
      await expect(
        third.page.getByRole('link', { name: 'E2E Test Credential' })
      ).toBeVisible({ timeout: 30_000 })

      await third.page.getByRole('button', { name: 'Log out' }).click()
      await expect(third.page).toHaveURL(/\/#?\/?$/)
      await expectNoStorageResidue({
        page: third.page,
        baselineLocalStorageKeys: baseline
      })
    } finally {
      await third.context.close()
    }
  })
})
