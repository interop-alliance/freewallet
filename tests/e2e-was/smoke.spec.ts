import type { Page } from '@playwright/test'
import { fillSettled, goToStorage, signupViaWizard } from './helpers'
import { accountSpaceIdFrom } from './storeOracle'
import { spaceExistsInStore } from '../shared/storeOracle'
import { WAS_E2E_DATA_DIR } from './wasDataDir'
import { test, expect } from '../shared/consoleCapture'

/**
 * PWS (remote storage) smoke tests. These run against the app in remote mode
 * (VITE_WAS_SERVER_URL set, see playwright.was.config.ts), backed by a local
 * was-teaching-server instance. They exercise the production storage path:
 * signing up creates a real Space + collections on the PWS server via
 * ZCap-signed HTTP.
 */

/**
 * Asserts the session's account Space exists in the server's store, and that
 * the storage page names it as the connected Space. The "Space (connected):"
 * label renders with or without a remote Space, so the Space URL beneath it
 * is what tells the two apart.
 *
 * @param page {Page}   a page holding a logged-in session
 * @returns {Promise<void>}
 */
async function expectConnectedSpace(page: Page): Promise<void> {
  const spaceId = await accountSpaceIdFrom(page)
  expect(
    await spaceExistsInStore({ dataDir: WAS_E2E_DATA_DIR, spaceId }),
    'the account Space exists on the server'
  ).toBe(true)
  await goToStorage(page)
  await expect(page.getByText(new RegExp(`/space/${spaceId}/?$`))).toBeVisible()
}

test.describe('PWS remote storage', () => {
  test('signing up provisions a remote Space and reaches the dashboard', async ({
    page
  }, testInfo) => {
    const token = `${Date.now()}-w${testInfo.workerIndex}`
    const passphrase = `Str0ngpass-${token}-Aa1!`
    const email = `e2e-${token}@example.com`

    await page.goto('/#/signup')
    await fillSettled(page.locator('input[type="password"]'), passphrase)
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await page.locator('input[type="email"]').fill(email)
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
    await page.getByRole('button', { name: 'Create Wallet' }).click()

    // Signup binds the keyring (a deliberately slow Argon2id derivation) on top of
    // the KMS keystore and did:web/did:webvh provisioning, so the redirect to
    // the dashboard can run past the default 5s assertion timeout.
    await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })

    await expectConnectedSpace(page)
  })

  test('storage page shows the connected remote Space', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await expectConnectedSpace(page)
  })
})
