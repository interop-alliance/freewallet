import { test, expect } from '@playwright/test'

test.describe('Sign up page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/#/signup')
  })

  test('is on the signup route', async ({ page }) => {
    await expect(page).toHaveURL(/#\/signup/)
  })

  test('shows app name and "Sign up" heading', async ({ page }) => {
    await expect(
      page.getByRole('heading', { name: 'Freewallet', level: 1 })
    ).toBeVisible()
    await expect(
      page.getByRole('heading', { name: 'Sign up', level: 2 })
    ).toBeVisible()
  })

  test('shows passphrase step first, then email after Next', async ({
    page
  }) => {
    await expect(page.locator('input[type="password"]')).toBeVisible()
    await expect(page.locator('input[type="email"]')).not.toBeVisible()
    await page
      .locator('input[type="password"]')
      .fill('Str0ng-passphrase!')
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await expect(page).toHaveURL(/#\/signup\?.*step=email/)
    await expect(page.locator('input[type="email"]')).toBeVisible()
  })

  test('browser back from email step returns to passphrase step', async ({
    page
  }) => {
    await page
      .locator('input[type="password"]')
      .fill('Str0ng-passphrase!')
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await expect(page.locator('input[type="email"]')).toBeVisible()

    await page.goBack()
    await expect(page).not.toHaveURL(/step=email/)
    await expect(page.locator('input[type="password"]')).toBeVisible()
    await expect(page.locator('input[type="email"]')).not.toBeVisible()
  })

  test('opening /signup?step=email shows email step', async ({ page }) => {
    await page.goto('/#/signup?step=email')
    await expect(page.locator('input[type="email"]')).toBeVisible()
    await expect(page.locator('input[type="password"]')).not.toBeVisible()
  })

  test('shows "Create Wallet" submit button', async ({ page }) => {
    await page
      .locator('input[type="password"]')
      .fill('Str0ng-passphrase!')
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await page.locator('input[type="email"]').fill('alice@example.com')
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
    await expect(
      page.getByRole('button', { name: 'Create Wallet' })
    ).toBeVisible()
  })

  test('successful sign up navigates to dashboard', async ({ page }, testInfo) => {
    const token = `${Date.now()}-w${testInfo.workerIndex}`
    const passphrase = `Str0ngpass-${token}-Aa1!`
    const email = `e2e-${token}@example.com`
    await page
      .locator('input[type="password"]')
      .fill(passphrase)
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await page.locator('input[type="email"]').fill(email)
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
    await page.getByRole('button', { name: 'Create Wallet' }).click()
    await expect(page).toHaveURL(/#\/dashboard/)
  })
})
