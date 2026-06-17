import { test, expect } from '@playwright/test'
import {
  addCredentialViaPaste,
  deleteCredential,
  expectCollectionUsage,
  expectQuotaCard,
  goToStorage,
  signupViaWizard
} from './helpers'

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

  test('keeps import enabled when storage is healthy', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await goToStorage(page)
    await expectQuotaCard(page)

    await expect(
      page.getByRole('button', { name: 'Import space' })
    ).toBeEnabled()
  })

  test('updates verifiable credentials usage after storing a credential', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await addCredentialViaPaste(page)
    await goToStorage(page)
    await expectQuotaCard(page)

    await expectCollectionUsage(page, 'Verifiable Credentials', /[1-9]\d* B/)
  })

  test('updates wallet activity usage after deleting a credential', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await deleteCredential(page)
    await goToStorage(page)
    await expectQuotaCard(page)

    await expectCollectionUsage(page, 'Wallet Activity Log', /[1-9]\d* B/)
  })
})
