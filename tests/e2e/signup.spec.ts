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

  test('shows email and passphrase fields', async ({ page }) => {
    await expect(page.locator('input[type="email"]')).toBeVisible()
    await expect(page.locator('input[type="password"]')).toBeVisible()
  })

  test('shows "Create Wallet" submit button', async ({ page }) => {
    await expect(
      page.getByRole('button', { name: 'Create Wallet' })
    ).toBeVisible()
  })

  test('successful sign up navigates to dashboard', async ({ page }) => {
    await page.locator('input[type="email"]').fill('alice@example.com')
    await page.locator('input[type="password"]').fill('test-passphrase')
    await page.getByRole('button', { name: 'Create Wallet' }).click()
    await expect(page).toHaveURL(/#\/dashboard/)
  })
})
