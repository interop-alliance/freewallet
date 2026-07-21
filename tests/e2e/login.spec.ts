import { test, expect } from '@playwright/test'

test.describe('Login page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/#/login')
  })

  test('is on the login route', async ({ page }) => {
    await expect(page).toHaveURL(/#\/login/)
  })

  test('shows app name and "Log in" heading', async ({ page }) => {
    await expect(
      page.getByRole('heading', { name: 'Freewallet', level: 6 })
    ).toBeVisible()
    await expect(
      page.getByRole('heading', { name: 'Log in', level: 1 })
    ).toBeVisible()
  })

  test('shows passphrase field and submit button', async ({ page }) => {
    await expect(page.locator('input[type="password"]')).toBeVisible()
    await expect(
      page.getByRole('button', { name: 'Log in', exact: true })
    ).toBeVisible()
  })

  test('has a link to the Sign up page', async ({ page }) => {
    await page.getByRole('link', { name: 'Sign up' }).click()
    await expect(page).toHaveURL(/#\/signup/)
  })

  test('successful login navigates to dashboard', async ({
    page
  }, testInfo) => {
    const token = `${Date.now()}-w${testInfo.workerIndex}`
    const passphrase = `Str0ngpass-${token}-Aa1!`
    const email = `e2e-${token}@example.com`
    // Sign up first to create the user
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

    // Log out, then log in. Wait for the logout redirect to land on the
    // landing page first.
    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/#\/$/)
    // Load /login as a fresh document (reload, not an in-app hash nav) so the
    // form fully mounts and settles before we type — reaching /login via an
    // in-app navigation can let StrictMode's mount/remount clear the just-typed
    // passphrase (the uncontrolled field loses its value), submitting it empty.
    await page.goto('/#/login')
    await page.reload()
    const passphraseInput = page.locator('input[type="password"]')
    await passphraseInput.fill(passphrase)
    await expect(passphraseInput).toHaveValue(passphrase)
    await page.getByRole('button', { name: 'Log in', exact: true }).click()
    await expect(page).toHaveURL(/#\/dashboard/)
  })
})
