import { test, expect } from '@playwright/test'
import { signupViaWizard } from './helpers'

/**
 * WebKMS keystore provisioning e2e. Runs against the app in remote mode
 * backed by a local was-teaching-server, whose `/kms` facet is the default
 * KMS (KMS_SERVER_URL derives from VITE_WAS_SERVER_URL). Signing up must
 * provision a keystore for the new controller, reported on the settings
 * page.
 */
test.describe('WebKMS keystore provisioning', () => {
  test('signing up provisions a keystore, shown on the settings page', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)

    await page.goto('/#/settings')
    await expect(page.getByText('Key management')).toBeVisible()
    await expect(page.getByText('Provisioned', { exact: true })).toBeVisible()
    // The keystore id is the KMS keystores URL plus a multibase (`z...`)
    // base58 local id.
    await expect(
      page.getByText(/\/kms\/keystores\/z[1-9A-HJ-NP-Za-km-z]+/)
    ).toBeVisible()
  })
})
