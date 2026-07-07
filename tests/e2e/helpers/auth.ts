import { expect, type Page } from '@playwright/test'

const GUEST_SUBMIT = 'Guest Mode Log In'

/**
 * Guest login via the UI. Waits for the lazy-loaded guest-login chunk before
 * clicking — `page.goto` alone can resolve while Suspense still shows a spinner.
 */
export async function loginAsGuest(page: Page) {
  await page.goto('/#/guest-login')
  const submit = page.getByRole('button', { name: GUEST_SUBMIT })
  await expect(submit).toBeVisible()
  await submit.click()
  await expect(page).toHaveURL(/#\/dashboard/)
}

export async function gotoGuestLogin(page: Page) {
  await page.goto('/#/guest-login')
  await expect(page.getByRole('button', { name: GUEST_SUBMIT })).toBeVisible()
}
