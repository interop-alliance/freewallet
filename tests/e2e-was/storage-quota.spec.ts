import { test, expect } from '@playwright/test'
import { expectQuotaCard, goToStorage, signupViaWizard } from './helpers'

/**
 * Storage quota UI — requires remote (WAS) mode; see playwright.was.config.ts.
 * The teaching server reports an unlimited filesystem backend by default.
 */
test.describe('Storage quota', () => {
  test('shows usage summary for a connected remote space', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await goToStorage(page)
    await expectQuotaCard(page)

    await expect(page.getByText('OK')).toBeVisible()
    await expect(page.getByText('Unlimited')).toBeVisible()
    await expect(page.getByText('Server Filesystem')).toBeVisible()
    await expect(page.getByText(/^Measured /)).toBeVisible()
  })

  test('lists wallet collections in the usage breakdown', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await goToStorage(page)
    await expectQuotaCard(page)

    await expect(page.getByText('Verifiable Credentials')).toBeVisible()
    await expect(page.getByText('Wallet Activity Log')).toBeVisible()
    await expect(
      page.getByText('Publicly Shared Verifiable Credentials')
    ).toBeVisible()
  })
})
