import { test, expect, type Browser, type Page } from '@playwright/test'
import { fillSettled, signupViaWizard } from './helpers'

/**
 * The Settings "Connected wallets" surface e2e (WAS mode): the enrolled
 * wallet clients listed from the locally verified did:webvh log. A fresh
 * account shows exactly one wallet (marked as this browser) and the honest
 * last-client copy; an issued recovery code NEVER appears in the list (its
 * key is keyAgreement-only, structurally excluded); a second browser
 * self-enrolls with the standing passphrase and lists as a second wallet,
 * named inline from the panel; disconnecting it drives the full revocation
 * cascade, the list updates, and the disconnected browser's next login is
 * refused.
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

    // Client 2 (cold profile): the standing passphrase self-enrolls this
    // browser at login -- no approval, no code -- and lands enrolled.
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
      await expect(secondClient).toHaveURL(/#\/dashboard/, {
        timeout: 60_000
      })

      // Client 1 re-logs in (its in-memory verified-log memo predates the
      // self-enrollment) and the listing shows two wallets; the
      // self-enrolled one arrives unlabeled and is named inline from the
      // panel (labels live beside the keys, editable any time -- there is
      // no approval dialog to name it at).
      await page.getByRole('button', { name: 'Log out' }).click()
      await expect(page).toHaveURL(/\/#?\/?$/)
      await page.goto('/#/login')
      await fillSettled(page.locator('input[type="password"]'), passphrase)
      await page.getByRole('button', { name: 'Log in', exact: true }).click()
      await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })
      await page.goto('/#/settings')
      await expect(walletCards(page)).toHaveCount(2, { timeout: 30_000 })
      // Address the self-enrolled card as the one that is NOT this browser:
      // that filter stays stable while edit mode swaps the "Unnamed wallet"
      // text for the name field.
      const newCard = walletCards(page).filter({ hasNotText: 'This browser' })
      await expect(newCard).toHaveCount(1)
      await expect(newCard.getByText('Unnamed wallet')).toBeVisible()
      await newCard.getByRole('button', { name: 'Edit' }).click()
      await fillSettled(
        newCard.getByLabel('Wallet name', { exact: true }),
        'Office laptop'
      )
      await newCard.getByRole('button', { name: 'Save', exact: true }).click()
      await expect(page.getByText('Office laptop')).toBeVisible({
        timeout: 30_000
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
