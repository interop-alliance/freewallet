/**
 * The torn remembered signup e2e (WAS mode): the signup is killed between
 * the credential-anchored establishment and the durable-login half (the
 * `__E2E_TEAR_SIGNUP_AFTER_ESTABLISHMENT__` seam), leaving a fully standing
 * unlock record but no client-key record and no enrolled client. Both later
 * entries must work from that state: a transient login with the same
 * passphrase enters through the ordinary composition (the standing record is
 * complete), and a durable login through the remember seam resumes the fold
 * -- self-enrolling this browser and leaving the same four-entry account log
 * a clean remembered signup produces.
 */
import { test, expect, type Browser, type Page } from '@playwright/test'
import {
  defaultWebvhLogVerifier,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import {
  fillSettled,
  forceRememberBrowser,
  submitTransientLogin,
  testUser
} from './helpers'

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

/**
 * A fresh, cold browser context (empty IndexedDB and localStorage). Callers
 * must close the returned page's context.
 *
 * @param browser {Browser}
 * @returns {Promise<Page>}
 */
async function coldPage(browser: Browser): Promise<Page> {
  const context = await browser.newContext({ baseURL: APP_URL })
  return context.newPage()
}

test.describe.serial('Torn remembered signup', () => {
  let passphrase: string
  let email: string

  test('the signup tears between establishment and the durable login', async ({
    page
  }, testInfo) => {
    test.slow()
    ;({ passphrase, email } = testUser(testInfo))

    await page.goto('/#/signup')
    await forceRememberBrowser(page)
    // The tear seam: `signUpWithPassphrase` throws right after the
    // establishment half succeeds, before the durable-login half runs --
    // the simulated tab death of design section 5.1's resume story.
    await page.evaluate(() => {
      ;(
        window as unknown as {
          __E2E_TEAR_SIGNUP_AFTER_ESTABLISHMENT__?: boolean
        }
      ).__E2E_TEAR_SIGNUP_AFTER_ESTABLISHMENT__ = true
    })
    await fillSettled(page.locator('input[type="password"]'), passphrase)
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled({
      timeout: 15_000
    })
    await page.getByRole('button', { name: 'Next' }).click()
    await page.locator('input[type="email"]').fill(email)
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
    await page.getByRole('button', { name: 'Create Wallet' }).click()

    // The establishment runs to completion (the KDF plus the whole
    // ceremony), then the seam throws and the page surfaces its generic
    // failure copy. The account exists server-side; this browser holds no
    // client-key record.
    await expect(
      page.getByText('Could not finish setting up your wallet')
    ).toBeVisible({ timeout: 60_000 })
    expect(page.url()).not.toMatch(/dashboard/)
  })

  test('a transient login enters the torn account', async ({ browser }) => {
    test.slow()
    // A cold terminal with nothing but the passphrase: the standing record
    // the establishment wrote is complete, so the DEFAULT (transient) login
    // enters through the ordinary composition.
    const page = await coldPage(browser)
    try {
      await page.goto('/#/login')
      await submitTransientLogin(page, passphrase)
    } finally {
      await page.context().close()
    }
  })

  test('a durable login resumes the fold and self-enrolls', async ({
    browser
  }) => {
    test.slow()
    const page = await coldPage(browser)
    try {
      await page.goto('/#/login')
      // The durable resume: the remember seam routes the login durable, and
      // its `canSelfEnroll` path enrolls this browser from the standing
      // record -- finishing what the torn signup started.
      await forceRememberBrowser(page)
      await fillSettled(page.locator('input[type="password"]'), passphrase)
      await page.getByRole('button', { name: 'Log in', exact: true }).click()
      await expect(page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })

      // The resumed account's log is the same four entries a clean
      // remembered signup leaves: genesis, the pointer entry, and the
      // self-enrollment pair -- and it fully verifies.
      await page.goto('/#/settings')
      await expect(page.getByText('Published did:webvh DID')).toBeVisible()
      const logLink = page.getByRole('link', { name: /did\.jsonl$/ })
      await expect(logLink).toBeVisible({ timeout: 30_000 })
      const logUrl = (await logLink.getAttribute('href'))!
      const logText = await (await page.request.get(logUrl)).text()
      const log = readLogFromString(logText)
      expect(log).toHaveLength(4)
      const resolved = await resolveDIDFromLog(log, {
        verifier: defaultWebvhLogVerifier
      })
      expect(resolved.meta.error).toBeUndefined()
      expect(resolved.meta.updateKeys).toHaveLength(1)
    } finally {
      await page.context().close()
    }
  })
})
