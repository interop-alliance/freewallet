import { test, expect } from '@playwright/test'
import {
  addCredentialViaPaste,
  deleteCredential,
  expectCollectionUsage,
  expectQuotaCard,
  goToStorage,
  quotaCard,
  signupViaWizard
} from './helpers'

// Rendered usage is an amount immediately followed by its unit, no separating
// space (e.g. "24.0KB", "200B"); match a non-zero value in any unit.
const NONZERO_USAGE = /[1-9][\d.]*\s*[KMGT]?B/

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

    // Scope to the quota card: these names also appear in the collections
    // browser, and "Verifiable Credentials" is a substring of "Publicly Shared
    // Verifiable Credentials", so match exactly within the card.
    const card = quotaCard(page)
    await expect(
      card.getByText('Verifiable Credentials', { exact: true })
    ).toBeVisible()
    await expect(
      card.getByText('Wallet Activity Log', { exact: true })
    ).toBeVisible()
    await expect(
      card.getByText('Publicly Shared Verifiable Credentials', { exact: true })
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

    await expectCollectionUsage(page, 'Verifiable Credentials', NONZERO_USAGE)
  })

  test('updates wallet activity usage after deleting a credential', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await addCredentialViaPaste(page)
    await deleteCredential(page)
    await goToStorage(page)
    await expectQuotaCard(page)

    await expectCollectionUsage(page, 'Wallet Activity Log', NONZERO_USAGE)
  })
})
