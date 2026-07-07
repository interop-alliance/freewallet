import { test, expect, type Browser, type Page } from '@playwright/test'
import { signupViaWizard } from './helpers'

/**
 * Keyring v2 e2e (WAS mode). A login derives an unlock identity from the
 * passphrase (PBKDF2), locates the keyring record in the unlock identity's own
 * WAS Space, unwraps the random data seed, and builds the session from it.
 * Signup binds a fresh random seed to the passphrase before creating the data
 * Space; a Settings action re-binds under a new passphrase and retires the old
 * unlock Space. The keyring is the only login path, so every login here routes
 * through it. Covers:
 *
 * 1. Second-device login: a cold profile (fresh browser context, empty
 *    IndexedDB including `freewallet-session`) logs in with the same passphrase,
 *    reaching the same spaceId and decrypting the welcome credential -- proving
 *    the random data seed round-tripped through the remote keyring alone.
 * 2. Passphrase change: the Settings action rebinds the seed under a new
 *    passphrase and deletes the old unlock Space, so on a cold profile the old
 *    passphrase no longer resolves to an account while the new one logs into the
 *    same wallet.
 * 3. Passphrase surface: a fresh signup shows the Settings Passphrase section
 *    with its change form.
 * 4. Guests are untouched: guest login works and shows no Passphrase section.
 *
 * The PBKDF2 unlock derivation is deliberately slow (see `KEYRING_KDF`), so
 * every login costs a visible fraction of a second on top of the KMS and DID
 * provisioning a signup already does -- hence the generous timeouts and
 * `test.slow()` throughout.
 */

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

/**
 * Reads the live session's remote spaceId through the E2E storage seam the auth
 * store publishes in non-production builds (`window.__E2E_STORAGE__`).
 *
 * @param page {Page}
 * @returns {Promise<string | undefined>}
 */
async function readSpaceId(page: Page): Promise<string | undefined> {
  return page.evaluate(
    () =>
      (window as unknown as { __E2E_STORAGE__?: { spaceId?: string } })
        .__E2E_STORAGE__?.spaceId
  )
}

/**
 * Logs in with a passphrase through the standard login form and waits for the
 * dashboard. Generous timeout: the PBKDF2 unlock derivation plus the remote
 * keyring fetch and session provisioning can run past the default assertion
 * timeout under load.
 *
 * @param page {Page}
 * @param passphrase {string}
 * @returns {Promise<void>}
 */
async function loginWithPassphrase(
  page: Page,
  passphrase: string
): Promise<void> {
  await page.goto('/#/login')
  await page.locator('input[type="password"]').fill(passphrase)
  await page.getByRole('button', { name: 'Log in', exact: true }).click()
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })
}

/**
 * Opens a fresh, cold browser context (empty IndexedDB and localStorage) to
 * stand in for a second device, and returns its first page. Callers must close
 * the returned page's context.
 *
 * @param browser {Browser}
 * @returns {Promise<Page>}
 */
async function coldDevicePage(browser: Browser): Promise<Page> {
  const context = await browser.newContext({ baseURL: APP_URL })
  return context.newPage()
}

test.describe('Keyring v2', () => {
  test('a second device logs in with the same passphrase and decrypts the vault', async ({
    page,
    browser
  }, testInfo) => {
    test.slow()

    // Device 1: a fresh signup mints a random data seed and publishes its
    // keyring to the remote unlock Space.
    const { passphrase } = await signupViaWizard(page, testInfo)
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 20_000 })
    const originalSpaceId = await readSpaceId(page)
    expect(originalSpaceId).toBeTruthy()

    // Log out of device 1 (its records are cleared) before the second device
    // comes online -- the second device shares nothing but the passphrase.
    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/\/#?\/?$/)

    // Device 2: a cold profile with empty storage (no cached keyring, no
    // session key) logs in with the same passphrase.
    const secondDevice = await coldDevicePage(browser)
    try {
      await loginWithPassphrase(secondDevice, passphrase)

      // Same wallet: the keyring round-tripped the random data seed through the
      // remote copy alone, so the derived spaceId matches.
      const secondSpaceId = await readSpaceId(secondDevice)
      expect(secondSpaceId).toBe(originalSpaceId)

      // The vault KAK (re-derived from the unwrapped seed) decrypts the welcome
      // credential, which replicates down from the remote Space.
      await expect(
        secondDevice.getByRole('link', { name: 'Your First Credential' })
      ).toBeVisible({ timeout: 30_000 })
    } finally {
      await secondDevice.context().close()
    }
  })

  test('changing the passphrase retires the old one and rebinds the new', async ({
    page,
    browser
  }, testInfo) => {
    test.slow()

    const { passphrase } = await signupViaWizard(page, testInfo)
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 20_000 })
    const originalSpaceId = await readSpaceId(page)
    expect(originalSpaceId).toBeTruthy()

    // A new passphrase strong enough to pass the signup-grade strength rules
    // (16+ chars, decent score).
    const newPassphrase = `Rebind3d-${Date.now()}-Zz9!`

    await page.goto('/#/settings')
    await expect(
      page.getByRole('heading', { name: 'Passphrase', exact: true })
    ).toBeVisible()
    await page
      .getByLabel('Current passphrase', { exact: true })
      .fill(passphrase)
    await page.getByLabel('New passphrase', { exact: true }).fill(newPassphrase)

    const changeButton = page.getByRole('button', { name: 'Change passphrase' })
    await expect(changeButton).toBeEnabled({ timeout: 30_000 })
    await changeButton.click()

    // The random-seed account's old unlock Space is deleted, so the success
    // copy is the fully-retired variant.
    await expect(
      page.getByText('The old passphrase no longer unlocks this wallet.')
    ).toBeVisible({ timeout: 30_000 })

    // Cold profile: the OLD passphrase no longer resolves to an account (its
    // unlock Space is gone and the data seed was never legacy-derivable), so
    // login falls through to signup with "profile not found".
    const oldDevice = await coldDevicePage(browser)
    try {
      await oldDevice.goto('/#/login')
      await oldDevice.locator('input[type="password"]').fill(passphrase)
      await oldDevice
        .getByRole('button', { name: 'Log in', exact: true })
        .click()
      await expect(oldDevice).toHaveURL(/#\/signup/, { timeout: 30_000 })
      await expect(
        oldDevice.getByText('This profile does not exist, please sign up.')
      ).toBeVisible()
    } finally {
      await oldDevice.context().close()
    }

    // Cold profile: the NEW passphrase logs into the same wallet.
    const newDevice = await coldDevicePage(browser)
    try {
      await loginWithPassphrase(newDevice, newPassphrase)
      expect(await readSpaceId(newDevice)).toBe(originalSpaceId)
      await expect(
        newDevice.getByRole('link', { name: 'Your First Credential' })
      ).toBeVisible({ timeout: 30_000 })
    } finally {
      await newDevice.context().close()
    }
  })

  test('a fresh signup surfaces the Passphrase section with its change form', async ({
    page
  }, testInfo) => {
    test.slow()

    await signupViaWizard(page, testInfo)

    await page.goto('/#/settings')
    await expect(
      page.getByRole('heading', { name: 'Passphrase', exact: true })
    ).toBeVisible()
    // A fresh signup is a full (passphrase) session, so the change form renders.
    await expect(
      page.getByLabel('Current passphrase', { exact: true })
    ).toBeVisible()
    await expect(
      page.getByRole('button', { name: 'Change passphrase' })
    ).toBeVisible()
  })

  test('a guest session has no keyring section on Settings', async ({
    page
  }) => {
    await page.goto('/#/guest-login')
    await page.getByRole('button', { name: 'Guest Mode Log In' }).click()
    await expect(page).toHaveURL(/#\/dashboard/, { timeout: 20_000 })

    await page.goto('/#/settings')
    // Anchor on the always-present About heading so the absence of the
    // Passphrase heading below is meaningful (not just a not-yet-loaded page).
    // Guests are keyring-exempt (the section is `!isGuest`-gated).
    await expect(
      page.getByRole('heading', { name: 'About', exact: true })
    ).toBeVisible()
    await expect(
      page.getByRole('heading', { name: 'Passphrase', exact: true })
    ).toHaveCount(0)
  })
})
