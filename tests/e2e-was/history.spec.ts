import { test, expect } from '@playwright/test'
import {
  addCredentialViaPaste,
  deleteCredential,
  expectHistoryEntry,
  goToHistory,
  signupViaWizard
} from './helpers'

/**
 * Wallet-activity history tests. History is only recorded when the app runs in
 * remote (WAS) mode — see playwright.was.config.ts.
 */
test.describe('Wallet activity history', () => {
  test('sign up records account and space creation entries', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await goToHistory(page)

    await expectHistoryEntry(page, 'Account Sign Up. did:key DID generated.')
    await expectHistoryEntry(
      page,
      'Account space created on remote storage server, collections initialized.'
    )
    await expect(page.getByText('No history items found.')).not.toBeVisible()
  })

  test('view source shows the activity JSON for a history entry', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await goToHistory(page)
    await expectHistoryEntry(page, 'Account Sign Up. did:key DID generated.')

    await page.getByRole('button', { name: 'View source' }).first().click()
    await expect(
      page.getByRole('heading', { name: 'History source', level: 6 })
    ).toBeVisible()
    await expect(page.locator('pre')).toContainText('"type":')
    await expect(page.locator('pre')).toContainText('Create')
  })

  test('adding a credential records a create entry on the history page', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await addCredentialViaPaste(page)
    await goToHistory(page)

    await expectHistoryEntry(page, 'E2E Test Credential created')
  })

  test('deleting a credential records a delete entry on the history page', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await addCredentialViaPaste(page)
    await deleteCredential(page)

    await goToHistory(page)
    await expectHistoryEntry(page, 'E2E Test Credential deleted')
  })
})
