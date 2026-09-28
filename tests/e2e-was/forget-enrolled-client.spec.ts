/**
 * The ordinary forget ceremony, end to end (WAS mode), and the transient
 * login that seals the collection descriptor logs behind it.
 *
 * The walk: a remembered signup (browser A, an enrolled client), a second
 * cold browser that self-enrolls (browser B, the account's second enrolled
 * client), then browser B's Settings forget. B is not the last enrolled
 * client, so the ordinary ceremony runs rather than the last-client
 * transition. Its collection fan-out runs before its removal entry, so every
 * collection descriptor log head it leaves anchors at an account version
 * that still lists B's key, and B's key could keep appending there. Browser
 * A never logs in again, so no remembered-login sweep seals those logs.
 *
 * A cold transient login with the passphrase must seal them: its mender
 * block's collection cascade re-appends each head, anchored at or past the
 * removal entry and signed by the standing credential's ladder VM.
 *
 * The collection logs are capability-gated, so the assertions read the
 * teaching server's FileSystem backend off disk (`storedLogs.ts`). Every
 * stage pays the deliberately slow unlock KDF on top of several WAS
 * ceremonies, hence the generous timeouts.
 */
import { test, expect, type Page } from '@playwright/test'
import {
  addCredentialViaPaste,
  awaitLoginChain,
  coldTerminal,
  expectSealedCollectionLogs,
  expectUnsealedCollectionLogs,
  fillSettled,
  forceRememberBrowser,
  sessionSpaceId,
  signupViaWizard,
  submitTransientLogin
} from './helpers'

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

/**
 * The wallet cards inside the connected-wallets list.
 *
 * @param page {Page}
 * @returns {import('@playwright/test').Locator}
 */
function walletCards(page: Page) {
  return page.getByTestId('enrolled-clients-list').locator('.MuiCard-root')
}

test.describe('The ordinary forget ceremony', () => {
  test('a transient login seals the collection logs behind the removal entry', async ({
    browser
  }, testInfo) => {
    test.slow()
    test.setTimeout(540_000)

    // --- Browser A: the remembered signup, the first enrolled client. ---
    const first = await coldTerminal(browser, APP_URL)
    let passphrase: string
    let spaceId: string
    try {
      const user = await signupViaWizard(first.page, testInfo)
      passphrase = user.passphrase
      spaceId = await sessionSpaceId(first.page)
      await addCredentialViaPaste(first.page)
      // Settled before the context closes, so no login-time write is torn.
      await awaitLoginChain(first.page)
    } finally {
      await first.context.close()
    }

    // --- Browser B: the second enrolled client, then its forget. ---
    const second = await coldTerminal(browser, APP_URL)
    try {
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
      await forceRememberBrowser(second.page)
      await fillSettled(
        second.page.locator('input[type="password"]'),
        passphrase
      )
      await second.page
        .getByRole('button', { name: 'Log in', exact: true })
        .click()
      await expect(second.page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })
      await awaitLoginChain(second.page)

      await second.page.goto('/#/settings')
      // Two wallet cards: browser A and this browser. So this browser's exit
      // is the ordinary forget rather than the last-client transition.
      await expect(walletCards(second.page)).toHaveCount(2, {
        timeout: 30_000
      })
      await second.page.getByTestId('forget-this-browser-button').click()
      await expect(
        second.page.getByTestId('forget-last-client-copy')
      ).toHaveCount(0)
      await second.page.getByTestId('forget-this-browser-confirm').click()

      // The ceremony ends in a hard reload onto the login page.
      try {
        await expect(second.page).toHaveURL(/\/login/, { timeout: 180_000 })
      } catch (err) {
        throw new Error(
          `The forget ceremony did not reach the login page. Page errors:\n${pageErrors.join('\n')}`,
          { cause: err }
        )
      }
    } finally {
      await second.context.close()
    }

    // The fan-out ran before the removal entry, so the heads it left anchor
    // at an account version that still lists browser B's key.
    const removalIndex = await expectUnsealedCollectionLogs({
      spaceId: spaceId!
    })

    // --- Browser C: a cold transient login seals them. ---
    const third = await coldTerminal(browser, APP_URL)
    try {
      await third.page.goto('/#/login')
      await submitTransientLogin(third.page, passphrase)
      await awaitLoginChain(third.page)
      await expect(
        third.page.getByRole('link', { name: 'E2E Test Credential' })
      ).toBeVisible({ timeout: 30_000 })
    } finally {
      await third.context.close()
    }
    await expectSealedCollectionLogs({ spaceId: spaceId!, removalIndex })
  })
})
