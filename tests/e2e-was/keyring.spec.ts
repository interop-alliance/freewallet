import { test, expect, type Browser, type Page } from '@playwright/test'
import { fillSettled, signupViaWizard } from './helpers'

/**
 * Keyring v2 e2e (WAS mode). A login derives an unlock identity from the
 * passphrase (PBKDF2), locates the account-pointer keyring record in the
 * unlock identity's own WAS Space, and unwraps this client's LOCAL key set
 * (the `freewallet-session` client-key record) to build the session -- the
 * account is never reconstructed from the passphrase. Signup binds this
 * client's fresh random key set to the passphrase before creating the data
 * Space; a Settings action re-binds under a new passphrase and retires the
 * old unlock Space. The keyring is the only login path, so every login here
 * routes through it. Covers:
 *
 * 1. Enrolled vs cold client: the enrolled client logs back in and reaches
 *    the same spaceId, while a cold profile (fresh browser context, empty
 *    IndexedDB including `freewallet-session`) sharing only the passphrase
 *    locates the account but is refused with the not-enrolled guidance --
 *    unlocking is not sufficient to BE the account.
 * 2. Passphrase change: the Settings action rebinds the client key set under
 *    a new passphrase and deletes the old unlock Space, so the old
 *    passphrase no longer resolves to an account anywhere, the new one logs
 *    into the same wallet on this client, and a cold profile with the new
 *    passphrase is refused as not enrolled.
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
  await fillSettled(page.locator('input[type="password"]'), passphrase)
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
  test('the enrolled client logs back in; a cold client with the same passphrase is refused', async ({
    page,
    browser
  }, testInfo) => {
    test.slow()

    // Client 1: a fresh signup mints this client's key set locally and
    // publishes the account-pointer keyring record to the remote unlock
    // Space.
    const { passphrase } = await signupViaWizard(page, testInfo)
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 20_000 })
    const originalSpaceId = await readSpaceId(page)
    expect(originalSpaceId).toBeTruthy()

    // Log out of client 1, then log back in: the passphrase unlocks the
    // locally stored client key set (no account is reconstructed from the
    // secret) and reaches the same wallet.
    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/\/#?\/?$/)
    await loginWithPassphrase(page, passphrase)
    expect(await readSpaceId(page)).toBe(originalSpaceId)
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 30_000 })

    // Client 2: a cold profile with empty storage shares nothing but the
    // passphrase. It locates the account (the keyring record) but holds no
    // client keys, so login is refused with the not-enrolled guidance --
    // unlocking is no longer sufficient to BE the account.
    const secondDevice = await coldDevicePage(browser)
    try {
      await secondDevice.goto('/#/login')
      await fillSettled(
        secondDevice.locator('input[type="password"]'),
        passphrase
      )
      await secondDevice
        .getByRole('button', { name: 'Log in', exact: true })
        .click()
      await expect(
        secondDevice.getByText('this browser does not hold its keys yet', {
          exact: false
        })
      ).toBeVisible({ timeout: 30_000 })
      await expect(secondDevice).toHaveURL(/#\/login/)
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
      await fillSettled(oldDevice.locator('input[type="password"]'), passphrase)
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

    // Same client: the NEW passphrase unlocks the re-wrapped local client
    // key set and logs back into the same wallet.
    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/\/#?\/?$/)
    await loginWithPassphrase(page, newPassphrase)
    expect(await readSpaceId(page)).toBe(originalSpaceId)
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 30_000 })

    // Cold profile: the NEW passphrase locates the account but holds no
    // client keys -- refused with the not-enrolled guidance.
    const newDevice = await coldDevicePage(browser)
    try {
      await newDevice.goto('/#/login')
      await fillSettled(
        newDevice.locator('input[type="password"]'),
        newPassphrase
      )
      await newDevice
        .getByRole('button', { name: 'Log in', exact: true })
        .click()
      await expect(
        newDevice.getByText('this browser does not hold its keys yet', {
          exact: false
        })
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
