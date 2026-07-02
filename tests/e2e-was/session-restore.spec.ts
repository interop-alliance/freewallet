import { test, expect } from '@playwright/test'
import { addCredentialViaPaste, goToStorage, signupViaWizard } from './helpers'

/**
 * Refresh-surviving delegated sessions e2e. At login the root key delegates
 * session zcaps to a non-extractable browser session key; a reload
 * reconstitutes a restricted session from them: the user stays logged in,
 * remote storage works through the delegated capabilities, but the vault
 * (encrypted collections) is locked until the passphrase is re-entered.
 */
test.describe('Refresh-surviving delegated session', () => {
  test('a reload restores a delegated session; re-login unlocks the vault', async ({
    page
  }, testInfo) => {
    const { passphrase } = await signupViaWizard(page, testInfo)
    // Vault content added while the session is full (also leaves ample time
    // for the fire-and-forget delegation persistence to land).
    await addCredentialViaPaste(page)
    await expect(
      page.getByRole('link', { name: 'E2E Test Credential' })
    ).toBeVisible()

    await page.reload()

    // Restored: still on the dashboard (not bounced to the landing page),
    // with the locked-vault notice -- and no decrypted credentials.
    await expect(page).toHaveURL(/#\/dashboard/)
    await expect(page.getByText(/vault is locked/)).toBeVisible()
    await expect(
      page.getByRole('link', { name: 'E2E Test Credential' })
    ).toHaveCount(0)

    // The storage browser reads the remote Space through the delegated
    // read capability.
    await goToStorage(page)

    // Re-entering the passphrase upgrades back to a full session: the
    // notice disappears and the vault decrypts again.
    await page.goto('/#/login')
    await page.locator('input[type="password"]').fill(passphrase)
    await page.getByRole('button', { name: 'Log in', exact: true }).click()
    await expect(page).toHaveURL(/#\/dashboard/)
    await expect(page.getByText(/vault is locked/)).toHaveCount(0)
    await expect(
      page.getByRole('link', { name: 'E2E Test Credential' })
    ).toBeVisible()
  })

  test('logging out ends the persisted session', async ({ page }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await page.reload()
    await expect(page.getByText(/vault is locked/)).toBeVisible()

    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/\/#?\/?$/)

    // The persisted records are gone: a fresh visit to a protected page
    // finds nothing to restore and bounces away.
    await page.goto('/#/dashboard')
    await expect(page).not.toHaveURL(/#\/dashboard/)
  })
})
