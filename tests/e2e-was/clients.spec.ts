import { test, expect, type Browser, type Page } from '@playwright/test'
import { fillSettled, signupViaWizard } from './helpers'

/**
 * The Settings "Connected wallets" surface e2e (WAS mode): the enrolled
 * wallet clients listed from the locally verified did:webvh log. A fresh
 * account shows exactly one wallet (marked as this browser) and the honest
 * last-client copy; an issued recovery code NEVER appears in the list (its
 * key is keyAgreement-only, structurally excluded); enrolling a second
 * browser -- with a label chosen at approval -- lists two wallets;
 * disconnecting the second one drives the full revocation cascade, the list
 * updates, and the disconnected browser's next login is refused.
 *
 * PBKDF2 unlock derivations run several times across the ceremonies, on top
 * of a full signup -- hence `test.slow()` and the generous timeouts.
 */

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

/**
 * Opens a fresh, cold browser context (empty IndexedDB and localStorage) to
 * stand in for a second wallet client (a fresh browser profile). Callers
 * must close the returned page's context.
 *
 * @param browser {Browser}
 * @returns {Promise<Page>}
 */
async function coldClientPage(browser: Browser): Promise<Page> {
  const context = await browser.newContext({ baseURL: APP_URL })
  return context.newPage()
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

test.describe('The Settings connected-wallets surface', () => {
  test('lists, labels, excludes recovery, and disconnects end to end', async ({
    page,
    browser
  }, testInfo) => {
    test.slow()

    // Client 1: a fresh signup, then the listing -- one wallet, marked as
    // this browser, with the honest cannot-disconnect-the-last copy.
    const { passphrase } = await signupViaWizard(page, testInfo)
    await page.goto('/#/settings')
    await expect(page.getByText('Connected wallets')).toBeVisible()
    await expect(walletCards(page)).toHaveCount(1, { timeout: 30_000 })
    await expect(page.getByText('This browser')).toBeVisible()
    await expect(
      page.getByText('it cannot be disconnected', { exact: false })
    ).toBeVisible()

    // A recovery code never appears in the list: its key is published under
    // keyAgreement only, so the capabilityInvocation-keyed listing is blind
    // to it by construction.
    await page.getByRole('button', { name: 'Generate recovery code' }).click()
    await page.getByRole('button', { name: 'I saved this code' }).click()
    await expect(
      page.getByRole('button', { name: 'Revoke this recovery code' })
    ).toBeVisible({ timeout: 30_000 })
    // Remount the panel (sessions are in-memory, so no full reload): the
    // fresh listing re-reads the extended log and still shows one wallet.
    await page.goto('/#/dashboard')
    await page.goto('/#/settings')
    await expect(walletCards(page)).toHaveCount(1, { timeout: 30_000 })

    // Client 2 (cold profile): the not-enrolled login surfaces the connect
    // flow; the key set is minted locally and the code carries public halves.
    const secondClient = await coldClientPage(browser)
    try {
      await secondClient.goto('/#/login')
      await fillSettled(
        secondClient.locator('input[type="password"]'),
        passphrase
      )
      await secondClient
        .getByRole('button', { name: 'Log in', exact: true })
        .click()
      await secondClient
        .getByRole('button', { name: 'Connect this browser' })
        .click({ timeout: 30_000 })
      const codeField = secondClient.getByTestId('enroll-connect-code')
      await expect(codeField).toBeVisible({ timeout: 20_000 })
      const code = await codeField.inputValue()

      // Client 1 approves from the connected-wallets panel, naming the new
      // wallet at approval time.
      await page.getByRole('button', { name: 'Enroll another wallet' }).click()
      await fillSettled(page.getByTestId('enroll-code-input'), code)
      await expect(page.getByText(/New client key: did:key:z6Mk/)).toBeVisible()
      await fillSettled(page.getByTestId('enroll-label-input'), 'Office laptop')
      await page.getByRole('button', { name: 'Approve', exact: true }).click()
      await expect(
        page.getByText('The new browser was enrolled', { exact: false })
      ).toBeVisible({ timeout: 60_000 })

      // The list refreshes to two wallets, the new one under its label.
      await expect(walletCards(page)).toHaveCount(2, { timeout: 30_000 })
      await expect(page.getByText('Office laptop')).toBeVisible()

      // Client 2 completes the ceremony and lands enrolled.
      await secondClient
        .getByRole('button', { name: 'I approved it -- finish connecting' })
        .click()
      await expect(secondClient).toHaveURL(/#\/dashboard/, {
        timeout: 60_000
      })

      // Client 1 disconnects the new wallet: the full revocation cascade,
      // then the list updates back to one.
      const officeCard = walletCards(page).filter({
        hasText: 'Office laptop'
      })
      await officeCard
        .getByRole('button', { name: 'Disconnect', exact: true })
        .click()
      await page
        .getByRole('button', { name: 'Disconnect wallet', exact: true })
        .click()
      await expect(walletCards(page)).toHaveCount(1, { timeout: 120_000 })
      await expect(page.getByText('Office laptop')).not.toBeVisible()

      // The revoked client's next action fails: its stored keys no longer
      // appear in the document, so its login is refused rather than reaching
      // the dashboard.
      await secondClient.goto('/#/login')
      await fillSettled(
        secondClient.locator('input[type="password"]'),
        passphrase
      )
      await secondClient
        .getByRole('button', { name: 'Log in', exact: true })
        .click()
      await expect(secondClient.getByRole('alert')).toBeVisible({
        timeout: 60_000
      })
      expect(secondClient.url()).not.toMatch(/#\/dashboard/)
    } finally {
      await secondClient.context().close()
    }
  })
})
