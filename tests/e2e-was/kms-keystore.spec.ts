import { test, expect } from '@playwright/test'
import { signupViaWizard } from './helpers'

/**
 * WebKMS provisioning e2e. Runs against the app in remote mode backed by a
 * local was-teaching-server, whose `/kms` facet is the default KMS
 * (KMS_SERVER_URL derives from VITE_WAS_SERVER_URL). Signing up must publish
 * the account's did:web projection and record the KMS-held signing key in
 * its document, both reported on the settings page.
 */
test.describe('WebKMS keystore provisioning', () => {
  test('signing up records the KMS signing key, shown on the settings page', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)

    await page.goto('/#/settings')
    await expect(page.getByText('Key management')).toBeVisible()
    await expect(
      page.getByText('Published', { exact: true }).first()
    ).toBeVisible()
    await expect(
      page.getByText('Key server signing key recorded', { exact: true })
    ).toBeVisible()
  })
})
