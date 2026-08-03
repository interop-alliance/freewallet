import { test, expect, type Page } from '@playwright/test'
import {
  addCredentialViaPaste,
  signupViaWizard,
  E2E_TEST_CREDENTIAL
} from './helpers'

/**
 * Deleting a credential that has a live public link. The public copy is
 * retracted BEFORE the private credential is deleted, so a credential the user
 * deleted never stays world-readable; the deliberate "keep public copy" choice
 * is the one path that leaves the public URL live. Both need the remote WAS
 * Space the public URL resolves against -- see playwright.was.config.ts.
 */
test.describe('Deleting a credential with a public link', () => {
  test('retracts the public copy, leaving no world-readable orphan', async ({
    page
  }, testInfo) => {
    // A full signup, then two round trips through background replication.
    test.slow()
    await signupViaWizard(page, testInfo)
    await addCredentialViaPaste(page)
    const publicUrl = await createPublicLink(page)
    await expectPublicUrlStatus(page, publicUrl, 200)

    await page.getByRole('button', { name: 'Delete' }).click()
    await expect(
      page.getByRole('heading', { name: 'Delete this credential?' })
    ).toBeVisible()
    await page.getByRole('button', { name: 'Delete everything' }).click()
    await expect(page).toHaveURL(/#\/dashboard/)
    await expect(
      page.getByRole('link', { name: 'E2E Test Credential' })
    ).toHaveCount(0)

    // The world-readable copy is gone (replication pushes the retraction).
    await expectPublicUrlStatus(page, publicUrl, 404)
  })

  test('baseline: removing the public link retracts the remote copy', async ({
    page
  }, testInfo) => {
    test.slow()
    await signupViaWizard(page, testInfo)
    await addCredentialViaPaste(page)
    const publicUrl = await createPublicLink(page)
    await expectPublicUrlStatus(page, publicUrl, 200)

    await page.getByRole('button', { name: 'Remove public link' }).click()
    await expectPublicUrlStatus(page, publicUrl, 404)
  })

  test('keeps the public copy when the user chooses to', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await addCredentialViaPaste(page)
    const publicUrl = await createPublicLink(page)
    await expectPublicUrlStatus(page, publicUrl, 200)

    await page.getByRole('button', { name: 'Delete' }).click()
    await page.getByRole('button', { name: 'Keep public copy' }).click()
    await expect(page).toHaveURL(/#\/dashboard/)

    // A deliberate retention, not an accidental orphan: the link stays live.
    await page.waitForTimeout(2000)
    const response = await page.request.get(publicUrl)
    expect(response.status()).toBe(200)
  })
})

/**
 * Opens the credential added by `addCredentialViaPaste` and shares it, leaving
 * the page on the credential detail route.
 *
 * @param page {Page}
 * @returns {Promise<string>}   the public link's URL
 */
async function createPublicLink(page: Page): Promise<string> {
  await page.getByRole('link', { name: 'E2E Test Credential' }).click()
  await expect(page).toHaveURL(/#\/credential\//)
  await page.getByRole('button', { name: 'Create public link' }).click()
  // The rendered link text is truncated, so match on the href instead.
  const link = page.locator('a[href*="/public-credentials/"]')
  await expect(link).toBeVisible({ timeout: 15_000 })
  const url = await link.getAttribute('href')
  expect(url).toBeTruthy()
  return url as string
}

/**
 * Polls the world-readable public URL until it reaches the expected status.
 * Both directions go through background replication, so the remote copy
 * appears (and disappears) a beat after the wallet-side action.
 *
 * @param page {Page}
 * @param url {string}
 * @param status {number}
 * @returns {Promise<void>}
 */
async function expectPublicUrlStatus(
  page: Page,
  url: string,
  status: number
): Promise<void> {
  await expect
    .poll(
      async () => {
        const response = await page.request.get(url)
        if (response.status() === 200 && status === 200) {
          const body = await response.json()
          expect(JSON.stringify(body)).toContain(E2E_TEST_CREDENTIAL.name)
        }
        return response.status()
      },
      { timeout: 30_000, intervals: [500, 1000, 2000] }
    )
    .toBe(status)
}
