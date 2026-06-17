import { test, expect } from '@playwright/test'

/**
 * Storage quota UI in local (non-WAS) mode — no remote space, so the quota
 * card should not appear. See playwright.config.ts (VITE_WAS_SERVER_URL unset).
 */
test.describe('Storage quota (local mode)', () => {
  test('does not show the quota card in guest mode', async ({ page }) => {
    await page.goto('/#/guest-login')
    await page.getByRole('button', { name: 'Guest Mode Log In' }).click()
    await expect(page).toHaveURL(/#\/dashboard/)

    await page.goto('/#/storage')
    await expect(
      page.getByRole('heading', { name: 'Storage usage', level: 6 })
    ).not.toBeVisible()
    await expect(
      page.getByText('No remote storage space is connected.')
    ).toBeVisible()
  })
})
