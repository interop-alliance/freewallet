/**
 * The torn credential-anchored establishment e2e (WAS mode): the signup is
 * killed between the record re-bind (and the registry write) and the Space
 * controller promotion (the `__E2E_TEAR_ESTABLISHMENT_BEFORE_PROMOTION__`
 * seam), leaving a record that names the account DID on a Space still
 * controlled by the bootstrap did:key. The next transient login meets that
 * state as a delegated roster read the server refuses; the shared mend
 * ceremony's promotion arm completes the promotion under the ladder VM's
 * bare did:key, retries the read, and the login lands on the dashboard.
 */
import { test, expect, type Browser, type Page } from '@playwright/test'
import { fillSettled, submitTransientLogin, testUser } from './helpers'

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

test.describe.serial('Torn establishment (before the promotion)', () => {
  let passphrase: string
  let email: string

  test('the signup tears between the re-bind and the promotion', async ({
    page
  }, testInfo) => {
    test.slow()
    ;({ passphrase, email } = testUser(testInfo))

    await page.goto('/#/signup')
    // The tear seam: the establishment's pre-promotion hook throws right
    // after the registry write, so the ceremony dies with the record
    // re-bound and the Space still under the bootstrap key.
    await page.evaluate(() => {
      ;(
        window as unknown as {
          __E2E_TEAR_ESTABLISHMENT_BEFORE_PROMOTION__?: boolean
        }
      ).__E2E_TEAR_ESTABLISHMENT_BEFORE_PROMOTION__ = true
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

    // The hook's throw fails the establishment, and the page surfaces its
    // generic failure copy; the account log and record exist server-side,
    // the promotion never ran.
    await expect(
      page.getByText('Could not finish setting up your wallet')
    ).toBeVisible({ timeout: 60_000 })
    expect(page.url()).not.toMatch(/dashboard/)
  })

  test('a transient login mends the promotion and enters', async ({
    browser
  }) => {
    test.slow()
    // A cold terminal with nothing but the passphrase. The delegated roster
    // read fails on the unpromoted Space; the mend ceremony's promotion arm
    // completes the promotion and the retried read carries the login
    // through to the dashboard.
    const page = await coldPage(browser)
    try {
      await page.goto('/#/login')
      await submitTransientLogin(page, passphrase)
    } finally {
      await page.context().close()
    }
  })
})
