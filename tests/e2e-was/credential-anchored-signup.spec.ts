/**
 * The credential-anchored signup's posture cell, pinned end to end: a fresh
 * browser context runs the DEFAULT signup through the real wizard (no
 * remember seam), which mints no durable client anywhere -- the account's
 * genesis is anchored on the passphrase's ladder, the visit lands on the
 * dashboard as a transient session over the replica-less remote-direct
 * posture, and the browser holds zero trace afterwards (the shared
 * assertions in `tests/shared/storageResidue.ts`).
 *
 * The second test is the standing-credential proof: a SECOND cold terminal
 * reaches the same account with nothing but the passphrase -- the ordinary
 * default transient login, riding the companion generation and the roster
 * wrap the signup itself established -- and reads back the credential the
 * signup visit stored.
 */
import { test, expect, type Browser, type Page } from '@playwright/test'
import { addCredentialViaPaste, fillSettled, signupViaWizard } from './helpers'
import {
  captureLocalStorageKeys,
  expectNoStorageResidue
} from '../shared/storageResidue'

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

/**
 * The public-terminal browser: a fresh context holding nothing.
 */
async function coldTerminal(browser: Browser): Promise<{
  context: Awaited<ReturnType<Browser['newContext']>>
  page: Page
}> {
  const context = await browser.newContext({ baseURL: APP_URL })
  const page = await context.newPage()
  return { context, page }
}

test.describe.serial('credential-anchored signup', () => {
  let passphrase: string

  test('the default signup mints no durable client and leaves zero residue', async ({
    browser
  }, testInfo) => {
    const { context, page } = await coldTerminal(browser)
    try {
      // The baseline is captured on the loaded app, before any input; the
      // wizard helper's own goto lands on the same origin state.
      await page.goto('/#/signup')
      const baseline = await captureLocalStorageKeys({ page })
      const user = await signupViaWizard(page, testInfo, {
        rememberBrowser: false
      })
      passphrase = user.passphrase

      // The transient session works: a credential stores over the
      // replica-less remote-direct posture.
      await addCredentialViaPaste(page)

      await page.getByRole('button', { name: 'Log out' }).click()
      await expect(page).toHaveURL(/\/#?\/?$/)
      await expectNoStorageResidue({
        page,
        baselineLocalStorageKeys: baseline
      })
    } finally {
      await context.close()
    }
  })

  test('a second cold terminal enters with the passphrase alone', async ({
    browser
  }) => {
    const { context, page } = await coldTerminal(browser)
    try {
      // The ordinary default transient login -- deliberately no remember
      // seam: the signup's establishment (standing record, companion
      // generation, roster wrap) is exactly what makes this work.
      await page.goto('/#/login')
      const baseline = await captureLocalStorageKeys({ page })
      await fillSettled(page.locator('input[type="password"]'), passphrase)
      await page.getByRole('button', { name: 'Log in', exact: true }).click()
      await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })

      // The credential the signup visit stored decrypts here: the user key
      // came back through the credential's standing roster wrap.
      await expect(
        page.getByRole('link', { name: 'E2E Test Credential' })
      ).toBeVisible({ timeout: 15_000 })

      await page.getByRole('button', { name: 'Log out' }).click()
      await expect(page).toHaveURL(/\/#?\/?$/)
      await expectNoStorageResidue({
        page,
        baselineLocalStorageKeys: baseline
      })
    } finally {
      await context.close()
    }
  })
})
