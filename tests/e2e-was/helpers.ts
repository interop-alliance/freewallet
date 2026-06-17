import { expect, type Page, type TestInfo } from '@playwright/test'

export function testUser(testInfo: TestInfo) {
  const token = `${Date.now()}-w${testInfo.workerIndex}`
  return {
    passphrase: `Str0ngpass-${token}-Aa1!`,
    email: `e2e-${token}@example.com`
  }
}

export async function signupViaWizard(page: Page, testInfo: TestInfo) {
  const { passphrase, email } = testUser(testInfo)

  await page.goto('/#/signup')
  await page.locator('input[type="password"]').fill(passphrase)
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
  await page.getByRole('button', { name: 'Next' }).click()
  await page.locator('input[type="email"]').fill(email)
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
  await page.getByRole('button', { name: 'Create Wallet' }).click()
  await expect(page).toHaveURL(/#\/dashboard/)

  return { passphrase, email }
}

export async function goToHistory(page: Page) {
  await page.getByRole('link', { name: 'History' }).click()
  await expect(page).toHaveURL(/#\/history/)
  await expect(
    page.getByRole('heading', { name: 'History', level: 3 })
  ).toBeVisible()
}

export async function goToStorage(page: Page) {
  await page.goto('/#/storage')
  await expect(page.getByText('Space (connected):')).toBeVisible()
}

export async function expectQuotaCard(page: Page) {
  await expect(
    page.getByRole('heading', { name: 'Storage usage', level: 6 })
  ).toBeVisible({ timeout: 15_000 })
}

export async function expectHistoryEntry(page: Page, summary: string | RegExp) {
  await expect(page.getByText(summary)).toBeVisible({ timeout: 15_000 })
}

export const E2E_TEST_CREDENTIAL = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential'],
  name: 'E2E Test Credential',
  issuer: 'did:example:e2e-issuer',
  credentialSubject: { id: 'did:example:e2e-subject' }
} as const

export const E2E_TEST_CREDENTIAL_JSON = JSON.stringify(E2E_TEST_CREDENTIAL)

export async function addCredentialViaPaste(page: Page) {
  await page.getByRole('link', { name: 'Add Credential' }).click()
  await expect(page).toHaveURL(/#\/add-credential/)
  await page.locator('textarea').fill(E2E_TEST_CREDENTIAL_JSON)
  await page.getByRole('button', { name: 'Add' }).click()
  await expect(page).toHaveURL(/#\/accept-credentials/)
  await page.getByRole('button', { name: 'Accept all' }).click()
  await expect(page).toHaveURL(/#\/dashboard/)
}
