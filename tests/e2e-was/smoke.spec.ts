import { test, expect } from '@playwright/test'
import { goToStorage, signupViaWizard } from './helpers'

/**
 * WAS (remote storage) smoke tests. These run against the app in remote mode
 * (VITE_WAS_SERVER_URL set, see playwright.was.config.ts), backed by a local
 * was-teaching-server instance. They exercise the production storage path:
 * signing up creates a real Space + collections on the WAS server via
 * ZCap-signed HTTP.
 */
test.describe('WAS remote storage', () => {
  test('signing up provisions a remote Space and reaches the dashboard', async ({
    page
  }, testInfo) => {
    const token = `${Date.now()}-w${testInfo.workerIndex}`
    const passphrase = `Str0ngpass-${token}-Aa1!`
    const email = `e2e-${token}@example.com`

    await page.goto('/#/signup')
    await page.locator('input[type="password"]').fill(passphrase)
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await page.locator('input[type="email"]').fill(email)
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
    await page.getByRole('button', { name: 'Create Wallet' }).click()

    await expect(page).toHaveURL(/#\/dashboard/)
  })

  test('storage page shows the connected remote Space', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await goToStorage(page)
  })
})
