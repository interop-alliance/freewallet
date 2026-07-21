import {
  test,
  expect,
  type CDPSession,
  type Page,
  type TestInfo
} from '@playwright/test'

/**
 * Passkey (WebAuthn PRF) unlock e2e (WAS mode). A passkey is a Layer 1 unlock
 * method: its per-credential PRF output derives an unlock identity that locates
 * and unwraps the account's random data seed through the keyring, exactly like
 * a passphrase. Signing up with a passkey binds a fresh seed to that PRF output
 * before creating the data Space; logging in runs a one-tap assertion whose PRF
 * output resolves the keyring; Settings adds and revokes passkeys against the
 * unlock-methods registry. Every ceremony is driven by a Chromium CDP virtual
 * authenticator (there is no relying-party server; the only property consumed
 * downstream is the PRF output). Covers:
 *
 * 1. Passkey signup reaches the dashboard with the welcome credential and the
 *    passkey-only safety prompt.
 * 2. One-tap passkey login from the login page lands on the dashboard at the
 *    same spaceId.
 * 3. New device: with the wallet and session IndexedDB cleared (the synced
 *    passkey still lives in the authenticator), a passkey login rebuilds the
 *    same wallet from the remote keyring alone and decrypts the welcome
 *    credential.
 * 4. A second passkey added from Settings shows two entries in the passkeys
 *    list.
 * 5. Revoking a passkey through its management zcap (no ceremony) retires it, so
 *    that passkey's login can no longer find a wallet.
 * 6. Last-method guard: a passkey-only account with a single passkey cannot
 *    remove it.
 * 7. A passkey whose authenticator cannot evaluate PRF surfaces the
 *    PRF-unsupported error and creates no session.
 *
 * The keyring's unlock derivation (a deliberately slow KDF) plus the KMS and DID
 * provisioning a signup already does make every login cost a visible fraction of
 * a second, hence the generous timeouts and `test.slow()` throughout.
 */

/**
 * Builds a unique, well-formed account email for a test worker so parallel and
 * repeated runs never collide on a passphrase-free passkey signup.
 *
 * @param testInfo {TestInfo}
 * @returns {string}
 */
function passkeyEmail(testInfo: TestInfo): string {
  return `e2e-passkey-${Date.now()}-w${testInfo.workerIndex}@example.com`
}

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
 * Opens a CDP session on the page and enables the WebAuthn virtual-authenticator
 * environment. The returned session owns every virtual authenticator added
 * through it, so tests keep it for the lifetime of their authenticators.
 *
 * @param page {Page}
 * @returns {Promise<CDPSession>}
 */
async function enableWebAuthn(page: Page): Promise<CDPSession> {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  return cdp
}

/**
 * Adds a CTAP2 internal virtual authenticator with a resident key and user
 * verification always satisfied, and returns its authenticator id. `hasPrf`
 * toggles WebAuthn PRF support: true for the working unlock flows, false to
 * exercise the PRF-unsupported error path.
 *
 * @param cdp {CDPSession}
 * @param options {object}
 * @param options.hasPrf {boolean}
 * @returns {Promise<string>}
 */
async function addAuthenticator(
  cdp: CDPSession,
  { hasPrf }: { hasPrf: boolean }
): Promise<string> {
  const { authenticatorId } = await cdp.send(
    'WebAuthn.addVirtualAuthenticator',
    {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        hasPrf
      }
    }
  )
  return authenticatorId
}

/**
 * Removes a virtual authenticator (and the discoverable credentials it holds)
 * from the CDP session, so a later ceremony cannot pick it.
 *
 * @param cdp {CDPSession}
 * @param authenticatorId {string}
 * @returns {Promise<void>}
 */
async function removeAuthenticator(
  cdp: CDPSession,
  authenticatorId: string
): Promise<void> {
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId })
}

/**
 * Confirms the "one more tap needed" PRF-retry dialog when it appears. Some
 * authenticators evaluate the WebAuthn PRF only during a follow-up assertion, so
 * registration surfaces a consent dialog; others evaluate it at creation and
 * show none. Waits briefly for the dialog and clicks through when present,
 * otherwise returns without acting.
 *
 * @param page {Page}
 * @returns {Promise<void>}
 */
async function confirmPrfRetryIfPrompted(page: Page): Promise<void> {
  const continueButton = page.getByRole('button', {
    name: 'Continue',
    exact: true
  })
  try {
    await continueButton.waitFor({ state: 'visible', timeout: 5_000 })
    await continueButton.click()
  } catch {
    // No retry dialog: the authenticator evaluated PRF during creation.
  }
}

/**
 * Drives the signup wizard's passkey path to the dashboard: the passkey method
 * choice at step 0, the email step, the storage step, then Create Wallet (which
 * runs the registration ceremony and binds the passkey's PRF output to a fresh
 * data seed). Consents to the PRF-retry dialog if the authenticator asks for it.
 *
 * @param page {Page}
 * @param options {object}
 * @param options.email {string}
 * @returns {Promise<void>}
 */
async function passkeySignup(
  page: Page,
  { email }: { email: string }
): Promise<void> {
  await page.goto('/#/signup')
  await page.getByRole('button', { name: 'Sign up with a Passkey' }).click()

  // Email step (optional field, but a bound email lets any later unlock method
  // recover it).
  await page.locator('input[type="email"]').fill(email)
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
  await page.getByRole('button', { name: 'Next' }).click()

  // Storage step: create the wallet.
  await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
  await page.getByRole('button', { name: 'Create Wallet' }).click()
  await confirmPrfRetryIfPrompted(page)
  // The passkey registration, the keyring bind (a deliberately slow KDF), and
  // the KMS + DID provisioning together can outrun the default assertion
  // timeout.
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 45_000 })
}

/**
 * Clicks "Log in with a Passkey" on the login page, running the one-tap
 * discoverable assertion. The caller asserts the outcome (a dashboard redirect
 * on a keyring hit, or the no-account error on a miss).
 *
 * @param page {Page}
 * @returns {Promise<void>}
 */
async function clickPasskeyLogin(page: Page): Promise<void> {
  await page.goto('/#/login')
  await page.getByRole('button', { name: 'Log in with a Passkey' }).click()
}

/**
 * Logs out through the dashboard header and waits for the landing page.
 *
 * @param page {Page}
 * @returns {Promise<void>}
 */
async function logout(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Log out' }).click()
  await expect(page).toHaveURL(/\/#?\/?$/)
}

/**
 * Deletes every IndexedDB database for the origin: the RxDB wallet database
 * (`<prefix>-wallet-db`) and the `freewallet-session` database that holds the
 * keyring cache and passkey-safety notice. Simulates a fresh device that still
 * carries the synced passkey (which lives in the authenticator, not page
 * storage). Best-effort per database: a blocked delete still resolves, and a
 * following reload closes the connection that blocked it.
 *
 * @param page {Page}
 * @returns {Promise<void>}
 */
async function clearAllIndexedDb(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const databases = await indexedDB.databases()
    await Promise.all(
      databases.map(
        info =>
          new Promise<void>(resolve => {
            if (!info.name) {
              resolve()
              return
            }
            const request = indexedDB.deleteDatabase(info.name)
            request.onsuccess = () => resolve()
            request.onerror = () => resolve()
            request.onblocked = () => resolve()
          })
      )
    )
  })
}

test.describe('Passkey unlock', () => {
  test('passkey signup, one-tap login, and a new device reach the same wallet', async ({
    page
  }, testInfo) => {
    test.slow()

    const cdp = await enableWebAuthn(page)
    await addAuthenticator(cdp, { hasPrf: true })

    // Signup with a passkey: a fresh data seed is bound to the credential's PRF
    // output, then the wallet is provisioned.
    await passkeySignup(page, { email: passkeyEmail(testInfo) })
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 20_000 })
    // A passkey-only account is left with a single unlock method, so the
    // dashboard raises the "add a second login method" safety prompt.
    await expect(page.getByRole('link', { name: 'Open Settings' })).toBeVisible(
      { timeout: 15_000 }
    )
    const originalSpaceId = await readSpaceId(page)
    expect(originalSpaceId).toBeTruthy()

    // One-tap login: log out, then the discoverable assertion resolves the
    // keyring and lands back in the same wallet.
    await logout(page)
    await clickPasskeyLogin(page)
    await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })
    expect(await readSpaceId(page)).toBe(originalSpaceId)
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 30_000 })

    // New device: clear the wallet and session IndexedDB (the passkey survives
    // in the authenticator), reload, and log in with the passkey. The random
    // data seed round-trips through the remote keyring alone, so the spaceId
    // matches and the vault decrypts the replicated welcome credential.
    await logout(page)
    await clearAllIndexedDb(page)
    await page.goto('/#/login')
    await page.reload()
    await page.getByRole('button', { name: 'Log in with a Passkey' }).click()
    await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })
    expect(await readSpaceId(page)).toBe(originalSpaceId)
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 30_000 })
  })

  test('Settings adds a second passkey, guards the last one, and revokes one', async ({
    page
  }, testInfo) => {
    test.slow()

    const cdp = await enableWebAuthn(page)
    const firstAuthenticator = await addAuthenticator(cdp, { hasPrf: true })

    // A passkey signup logs in with the root key, so Settings can manage passkeys.
    await passkeySignup(page, { email: passkeyEmail(testInfo) })
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 20_000 })

    await page.goto('/#/settings')
    await expect(
      page.getByRole('heading', { name: 'Passkeys', exact: true })
    ).toBeVisible({ timeout: 15_000 })

    // Last-method guard: the single passkey is the only way in, so its Remove
    // button is disabled and the explanatory line is shown.
    const removeButtons = page.getByRole('button', {
      name: 'Remove',
      exact: true
    })
    await expect(removeButtons).toHaveCount(1, { timeout: 20_000 })
    await expect(removeButtons.first()).toBeDisabled()
    await expect(
      page.getByText(
        'This is the only way to unlock this wallet, so it cannot be removed.',
        { exact: false }
      )
    ).toBeVisible()

    // Add a second passkey. `excludeCredentials` correctly refuses a duplicate on
    // the authenticator that already holds this wallet's passkey, so the new one
    // must land on a different authenticator -- retire the first and add a fresh,
    // empty one for the second credential. (The first passkey stays a valid entry
    // in the registry; only its authenticator is gone, as a lost device would be.)
    await removeAuthenticator(cdp, firstAuthenticator)
    await addAuthenticator(cdp, { hasPrf: true })
    await page.getByRole('button', { name: 'Add a passkey' }).click()
    await confirmPrfRetryIfPrompted(page)

    // The passkeys list now shows two entries.
    await expect(removeButtons).toHaveCount(2, { timeout: 30_000 })

    // Revoke the second passkey (the one whose credential is still present) via
    // its management zcap -- a confirm dialog, no authenticator tap.
    await removeButtons.nth(1).click()
    await expect(
      page.getByRole('heading', { name: 'Remove this passkey?' })
    ).toBeVisible()
    await page.getByRole('button', { name: 'Remove passkey' }).click()
    await expect(removeButtons).toHaveCount(1, { timeout: 30_000 })

    // The revoked passkey's unlock Space is gone, so its login now misses: the
    // only credential still in the authenticator environment is the revoked one,
    // and a one-tap login with it finds no wallet.
    await logout(page)
    await clickPasskeyLogin(page)
    await expect(
      page.getByText('No wallet was found for this passkey.', { exact: false })
    ).toBeVisible({ timeout: 30_000 })
    await expect(page).toHaveURL(/#\/login/)
  })

  test('a passkey without PRF support surfaces an error and creates no session', async ({
    page
  }, testInfo) => {
    test.slow()

    const cdp = await enableWebAuthn(page)
    await addAuthenticator(cdp, { hasPrf: false })

    // Drive the signup wizard's passkey path. The credential is created, but the
    // authenticator cannot evaluate PRF, so no unlock secret can be derived.
    await page.goto('/#/signup')
    await page.getByRole('button', { name: 'Sign up with a Passkey' }).click()
    await page.locator('input[type="email"]').fill(passkeyEmail(testInfo))
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
    await page.getByRole('button', { name: 'Create Wallet' }).click()
    // Depending on how the authenticator reports PRF, the retry dialog may appear
    // (declined by the assertion returning no PRF) or the error may surface at
    // once; confirm the dialog if shown.
    await confirmPrfRetryIfPrompted(page)

    await expect(
      page.getByText('cannot unlock Freewallet', { exact: false })
    ).toBeVisible({ timeout: 20_000 })
    // No session was created: the wizard stays on the storage step.
    await expect(
      page.getByRole('button', { name: 'Create Wallet' })
    ).toBeVisible()
    await expect(page).not.toHaveURL(/#\/dashboard/)
  })
})
