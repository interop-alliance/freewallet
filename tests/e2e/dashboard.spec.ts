import { test, expect } from '@playwright/test'
import { loginAsGuest } from './helpers/auth'

test.describe('Dashboard page', () => {
  test('redirects to landing page when not logged in', async ({ page }) => {
    await page.goto('/#/dashboard')
    await expect(page).toHaveURL(/\/$|#\/$/)
    await expect(
      page.getByRole('heading', { name: 'Freewallet', level: 1 })
    ).toBeVisible()
  })

  test.describe('when logged in', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsGuest(page)
    })

    test('is on the dashboard route', async ({ page }) => {
      await expect(page).toHaveURL(/#\/dashboard/)
    })

    test('shows "Freewallet Dashboard" title', async ({ page }) => {
      await expect(
        page.getByRole('heading', { name: 'Freewallet Dashboard', level: 3 })
      ).toBeVisible()
    })

    test('shows sidebar with navigation links', async ({ page }) => {
      await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible()
      await expect(page.getByRole('link', { name: 'Settings' })).toBeVisible()
    })

    test('shows Log out button', async ({ page }) => {
      await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible()
    })

    test('Log out button returns to landing page', async ({ page }) => {
      await page.getByRole('button', { name: 'Log out' }).click()
      await expect(page).toHaveURL(/\/$|#\/$/)
      await expect(
        page.getByRole('heading', { name: 'Freewallet', level: 1 })
      ).toBeVisible()
    })

    test('Settings nav link navigates to settings page', async ({ page }) => {
      await page.getByRole('link', { name: 'Settings' }).click()
      await expect(page).toHaveURL(/#\/settings/)
    })
  })
})
