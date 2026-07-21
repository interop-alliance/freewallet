import { test, expect } from '@playwright/test'
import {
  addCredentialViaPaste,
  deleteCredential,
  expectCollectionUsage,
  expectQuotaCard,
  goToStorage,
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

    // Per-collection usage renders as rows in the collections browser below the
    // aggregate card. Target each collection by its storage-path href, which is
    // unambiguous (matching display names by text is not: "Verifiable
    // Credentials" is a prefix of "Verifiable Credentials (Publicly Shared)").
    await expect(
      page.locator('a[href$="/storage/collections/private-credentials"]')
    ).toBeVisible()
    await expect(
      page.locator('a[href$="/storage/collections/wallet-activity"]')
    ).toBeVisible()
    await expect(
      page.locator('a[href$="/storage/collections/public-credentials"]')
    ).toBeVisible()
  })

  test('keeps import enabled when storage is healthy', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await goToStorage(page)
    await expectQuotaCard(page)

    // The loading-capable MUI Button renders nested elements that both expose
    // the button role and the same accessible name, so scope to the first.
    await expect(
      page.getByRole('button', { name: 'Import (Load) from Backup' }).first()
    ).toBeEnabled()
  })

  test('updates verifiable credentials usage after storing a credential', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await addCredentialViaPaste(page)
    await goToStorage(page)
    await expectQuotaCard(page)

    await expectCollectionUsage(page, 'private-credentials', NONZERO_USAGE)
  })

  test('updates wallet activity usage after deleting a credential', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await addCredentialViaPaste(page)
    await deleteCredential(page)
    await goToStorage(page)
    await expectQuotaCard(page)

    await expectCollectionUsage(page, 'wallet-activity', NONZERO_USAGE)
  })
})
