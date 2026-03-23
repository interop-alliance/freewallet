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
      page.getByRole('heading', { name: 'Freewallet', level: 1 })
    ).toBeVisible()
    await expect(
      page.getByRole('heading', { name: 'Log in', level: 2 })
    ).toBeVisible()
  })

  test('shows passphrase field and submit button', async ({ page }) => {
    await expect(page.locator('input[type="password"]')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Log in' })).toBeVisible()
  })

  test('has a link to the Sign up page', async ({ page }) => {
    await page.getByRole('link', { name: 'Sign up' }).click()
    await expect(page).toHaveURL(/#\/signup/)
  })

  test('successful login navigates to dashboard', async ({ page }) => {
    await page.locator('input[type="password"]').fill('test-passphrase')
    await page.getByRole('button', { name: 'Log in' }).click()
    await expect(page).toHaveURL(/#\/dashboard/)
  })
})
