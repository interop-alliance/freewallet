import { test, expect } from '@playwright/test'
import { gotoGuestLogin } from './helpers/auth'

test.describe('Guest login page', () => {
  test.beforeEach(async ({ page }) => {
    await gotoGuestLogin(page)
  })

  test('is on the guest-login route', async ({ page }) => {
    await expect(page).toHaveURL(/#\/guest-login/)
  })

  test('shows app name and "Guest Mode Login" heading', async ({ page }) => {
    await expect(
      page.getByRole('heading', { name: 'Freewallet', level: 6 })
    ).toBeVisible()
    await expect(
      page.getByRole('heading', { name: 'Guest Mode Login', level: 1 })
    ).toBeVisible()
  })

  test('shows guest mode description text', async ({ page }) => {
    await expect(page.getByText('a random login will be created')).toBeVisible()
    await expect(
      page.getByText('login and storage will be deleted at end of session')
    ).toBeVisible()
  })

  test('shows "Guest Mode Log In" submit button', async ({ page }) => {
    await expect(
      page.getByRole('button', { name: 'Guest Mode Log In' })
    ).toBeVisible()
  })

  test('submitting navigates to dashboard', async ({ page }) => {
    await page.getByRole('button', { name: 'Guest Mode Log In' }).click()
    await expect(page).toHaveURL(/#\/dashboard/)
  })
})
