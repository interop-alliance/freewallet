import { test, expect, type Browser, type Page } from '@playwright/test'
import {
  fillSettled,
  forceRememberBrowser,
  signupViaWizard,
  submitTransientLogin
} from './helpers'

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
      // The cold profile is non-remembered, so the default login would be
      // transient; this spec exercises the durable standing self-enrollment.
      await forceRememberBrowser(secondClient)
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

  /**
   * Guards the two-party enrollment's record rebind against dropping the
   * credential's standing members. The enrollee half (`completeEnrollment`
   * in `src/lib/enrollment.ts`) re-binds the unlock record with the freshly
   * minted key set; when it enumerated the standing members it knew about
   * (the bridge delegation and the ladder seed) instead of re-stating them
   * whole, it silently dropped the annex-Space `delegatedClients` sibling
   * delegation -- after which every later public-terminal (transient) login
   * with that passphrase refused with `TransientLoginUnavailableError`,
   * because the sibling is what enrolls the per-visit key into the annex
   * generation.
   *
   * The ordering is what makes the regression reachable: the annex
   * generation is minted (and the record therefore gains its sibling) while
   * the enrollee is holding its connect code, so the record the rebind
   * re-states is a full standing record.
   */
  test('the two-party enrollment rebind keeps transient login alive', async ({
    page,
    browser
  }, testInfo) => {
    test.slow()

    // Client 1: a durable signup. No annex generation yet, so a cold
    // browser's default (transient) login has nothing to enroll into --
    // which is exactly the login-page state the two-party ceremony starts
    // from.
    const { passphrase } = await signupViaWizard(page, testInfo)

    const enrollee = await coldClientPage(browser)
    const terminal = await coldClientPage(browser)
    try {
      // Client 2 (cold): the ordinary login form, deliberately without the
      // remember seam. The passphrase locates the account, the transient
      // route cannot serve it, and the page offers "Connect this browser".
      await enrollee.goto('/#/login')
      await fillSettled(enrollee.locator('input[type="password"]'), passphrase)
      await enrollee
        .getByRole('button', { name: 'Log in', exact: true })
        .click()
      await expect(
        enrollee.getByRole('button', { name: 'Connect this browser' })
      ).toBeVisible({ timeout: 60_000 })
      await enrollee
        .getByRole('button', { name: 'Connect this browser' })
        .click()
      const codeField = enrollee.getByTestId('enroll-connect-code')
      await expect(codeField).toBeVisible({ timeout: 30_000 })
      const connectCode = (await codeField.inputValue()).trim()
      expect(connectCode.startsWith('freewallet-connect:')).toBe(true)

      // Client 1 mints the annex generation (the non-production fixture
      // seam) BEFORE the enrollee finishes: the shared unlock record now
      // carries the `delegatedClients` sibling the rebind must preserve.
      await page.evaluate(
        async fixture => {
          const seam = (
            window as unknown as {
              __E2E_MINT_CLIENT_ANNEX_GENERATION__?: (options: {
                passphrase: string
              }) => Promise<void>
            }
          ).__E2E_MINT_CLIENT_ANNEX_GENERATION__
          if (!seam) {
            throw new Error(
              'The annex-generation fixture seam is not installed.'
            )
          }
          await seam(fixture)
        },
        { passphrase }
      )

      // Client 1 approves the pasted connect code (Settings > Connected
      // wallets > Connect another wallet, the paste half of the card).
      await page.goto('/#/settings')
      await expect(page.getByText('Connected wallets')).toBeVisible()
      await page.getByRole('button', { name: 'Connect another wallet' }).click()
      await fillSettled(page.getByTestId('enroll-code-input'), connectCode)
      await fillSettled(
        page.getByTestId('enroll-label-input'),
        'Second browser'
      )
      await page.getByRole('button', { name: 'Approve', exact: true }).click()
      await expect(
        page.getByText('The new browser was enrolled', { exact: false })
      ).toBeVisible({ timeout: 120_000 })

      // Client 2 finishes: `completeEnrollment` verifies the enrollment off
      // the log, reads the roster, and re-binds the unlock record.
      await enrollee
        .getByRole('button', { name: 'I approved it -- finish connecting' })
        .click()
      await expect(enrollee).toHaveURL(/#\/dashboard/, { timeout: 120_000 })

      // Client 3 (a public terminal): the DEFAULT transient login with the
      // same passphrase. It reaches the dashboard and decrypts the account's
      // data only if the rebound record still carries its sibling.
      await terminal.goto('/#/login')
      await submitTransientLogin(terminal, passphrase)
      await expect(
        terminal.getByRole('link', { name: 'Your First Credential' })
      ).toBeVisible({ timeout: 30_000 })
    } finally {
      await enrollee.context().close()
      await terminal.context().close()
    }
  })
})
