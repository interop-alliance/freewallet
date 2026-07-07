import { test, expect } from '@playwright/test'
import { loginAsGuest } from './helpers/auth'

test.describe('Settings page', () => {
  test('redirects to landing page when not logged in', async ({ page }) => {
    await page.goto('/#/settings')
    await expect(page).toHaveURL(/\/$|#\/$/)
    await expect(
      page.getByRole('heading', { name: 'Freewallet', level: 1 })
    ).toBeVisible()
  })

  test.describe('when logged in', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsGuest(page)
      await page.goto('/#/settings')
      await expect(page).toHaveURL(/#\/settings/)
    })

    test('shows "Settings" title', async ({ page }) => {
      await expect(
        page.getByRole('heading', { name: 'Settings', level: 3 })
      ).toBeVisible()
    })

    test('shows sidebar with navigation links', async ({ page }) => {
      await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible()
      await expect(page.getByRole('link', { name: 'Settings' })).toBeVisible()
    })

    test('shows "Delete Account" button with description', async ({ page }) => {
      await expect(
        page.getByRole('button', { name: 'Delete Account' })
      ).toBeVisible()
      await expect(
        page.getByText('Your login, keys, and all data will be deleted.')
      ).toBeVisible()
    })

    test('Dashboard nav link navigates back to dashboard', async ({ page }) => {
      await page.getByRole('link', { name: 'Dashboard' }).click()
      await expect(page).toHaveURL(/#\/dashboard/)
      await expect(
        page.getByRole('heading', { name: 'Freewallet Dashboard', level: 3 })
      ).toBeVisible()
    })
  })
})
