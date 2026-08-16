import {
  test,
  expect,
  type Browser,
  type CDPSession,
  type Page
} from '@playwright/test'
import { fillSettled, signupViaWizard } from './helpers'

/**
 * Revoking an unlock method from a client that did NOT create it (WAS mode).
 * A recovery code's and a passkey's unlock records are managed through a
 * delegated management zcap; that grant goes to the ACCOUNT IDENTITY (the
 * did:webvh on a promoted account), and an invocation picks its signer from
 * the capability's own controller. This spec is the proof that the grant
 * chains for any enrolled client rather than only for the one that issued
 * the method:
 *
 * 1. Second client: client 1 signs up, adds a passkey, and issues a recovery
 *    code; client 2 enrolls through the connect-code ceremony and revokes
 *    BOTH from its own Settings. The spent code then fails on the recover
 *    page, and client 1's passkey login finds no wallet.
 * 2. Post-recovery client: client 1 issues a code, a cold profile recovers
 *    with it (which force-issues a replacement code), and the recovered
 *    client -- whose account's original client key no longer exists -- revokes
 *    the replacement code from its own Settings.
 *
 * A signup, several PBKDF2 unlock derivations, an enrollment ceremony, and a
 * full recovery ceremony run per test, hence the generous per-test timeouts.
 */

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

const RECOVERED_PASSPHRASE = 'Recovered-passphrase-77!'

/**
 * Opens a fresh, cold browser context (empty IndexedDB and localStorage) to
 * stand in for another wallet client (a fresh browser profile). Callers must
 * close the returned page's context.
 *
 * @param browser {Browser}
 * @returns {Promise<Page>}
 */
async function coldClientPage(browser: Browser): Promise<Page> {
  const context = await browser.newContext({ baseURL: APP_URL })
  return context.newPage()
}

/**
 * Logs out via the logout route and waits for its deferred redirect to the
 * landing page to land. `/#/logout` is a same-document hash navigation, so
 * `goto` resolves before the logout page's async work finishes -- and its
 * trailing `navigate('/')` then fires late, yanking the router off whatever
 * page the test has since navigated to.
 *
 * @param page {Page}
 */
async function logOut(page: Page) {
  await page.goto('/#/logout')
  await expect(page).toHaveURL(/#\/$/, { timeout: 15_000 })
}

/**
 * Logs in with a passphrase from the login page.
 *
 * @param page {Page}
 * @param passphrase {string}
 */
async function logIn(page: Page, passphrase: string) {
  await page.goto('/#/login')
  await fillSettled(page.locator('input[type="password"]'), passphrase)
  await page.getByRole('button', { name: 'Log in', exact: true }).click()
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })
}

/**
 * Opens a CDP session on the page, enables the WebAuthn virtual-authenticator
 * environment, and adds one PRF-capable internal authenticator.
 *
 * @param page {Page}
 * @returns {Promise<CDPSession>}
 */
async function enableAuthenticator(page: Page): Promise<CDPSession> {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true
    }
  })
  return cdp
}

/**
 * Confirms the "one more tap needed" PRF-retry dialog when it appears. Some
 * authenticators evaluate the WebAuthn PRF only during a follow-up assertion,
 * so registration surfaces a consent dialog; others evaluate it at creation
 * and show none.
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
 * Issues a recovery code from Settings and returns it. Nothing binds until
 * the confirm-once dialog's "I saved this code", so the returned code is a
 * usable one.
 *
 * @param page {Page}
 * @param options {object}
 * @param [options.expectLabel] {string}   the row label to wait for
 * @returns {Promise<string>}
 */
async function issueRecoveryCode(
  page: Page,
  { expectLabel = 'Recovery code 1' }: { expectLabel?: string } = {}
): Promise<string> {
  await page.goto('/#/settings')
  await expect(page.getByText('Recovery codes', { exact: true })).toBeVisible()
  const generateButton = page.getByRole('button', {
    name: 'Generate recovery code'
  })
  await expect(generateButton).toBeEnabled({ timeout: 30_000 })
  await generateButton.click()
  await expect(
    page.getByText('This code is shown only once', { exact: false })
  ).toBeVisible()
  const code = (await page.locator('code').textContent()) ?? ''
  // Dash-grouped base58 (the alphabet has no 0, O, I, or l).
  expect(code).toMatch(/^[1-9A-HJ-NP-Za-km-z]{4}(-[1-9A-HJ-NP-Za-km-z]{1,4})+$/)
  await page.getByRole('button', { name: 'I saved this code' }).click()
  await expect(page.getByText(expectLabel)).toBeVisible({ timeout: 60_000 })
  return code
}

/**
 * Revokes the single listed recovery code from this page's Settings and waits
 * for the list to empty. The confirmation is a native `window.confirm`, which
 * Playwright dismisses by default -- accept it for the lifetime of the page.
 *
 * @param page {Page}
 * @returns {Promise<void>}
 */
async function revokeOnlyRecoveryCode(page: Page): Promise<void> {
  page.on('dialog', dialog => void dialog.accept())
  await page.goto('/#/settings')
  const revokeButton = page.getByRole('button', {
    name: 'Revoke this recovery code'
  })
  await expect(revokeButton).toHaveCount(1, { timeout: 30_000 })
  await expect(revokeButton).toBeEnabled({ timeout: 30_000 })
  await revokeButton.click()
  // A success is the row leaving the registry; a failed management invocation
  // would instead surface the revoke error alert.
  await expect(
    page.getByText('No recovery codes have been generated yet.')
  ).toBeVisible({ timeout: 120_000 })
  await expect(
    page.getByText('The recovery code could not be revoked', { exact: false })
  ).toHaveCount(0)
}

/**
 * Asserts that a spent or revoked code no longer resolves to an account on
 * the recover page.
 *
 * @param page {Page}
 * @param code {string}
 * @returns {Promise<void>}
 */
async function expectCodeNoLongerWorks(page: Page, code: string) {
  await page.goto('/#/recover')
  await expect(
    page.getByRole('heading', { name: 'Recover your wallet', level: 1 })
  ).toBeVisible()
  await fillSettled(page.locator('input[name="recovery-code"]'), code)
  await page.getByRole('button', { name: 'Check code', exact: true }).click()
  await expect(
    page.getByText(
      /No wallet was found for this recovery code|has been revoked or already used/
    )
  ).toBeVisible({ timeout: 30_000 })
}

test.describe('Unlock-method revocation from another client', () => {
  test('an enrolled second client revokes a recovery code and a passkey it did not create', async ({
    page,
    browser
  }, testInfo) => {
    // Beyond test.slow(): a signup, four PBKDF2 logins, a passkey
    // registration, the enrollment ceremony, and two revocations in one spec.
    test.setTimeout(480_000)

    const cdp = await enableAuthenticator(page)

    // Client 1: a fresh signup, then a re-login -- recovery-code issuance
    // gates on a promoted did:webvh pointer recovered from the keyring.
    const { passphrase } = await signupViaWizard(page, testInfo)
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 20_000 })
    await logOut(page)
    await logIn(page, passphrase)

    // Client 1 adds a passkey: a second unlock method whose management zcap
    // is delegated to the account identity, not to this client's key.
    await page.goto('/#/settings')
    await expect(
      page.getByRole('heading', { name: 'Passkeys', exact: true })
    ).toBeVisible({ timeout: 15_000 })
    await page.getByRole('button', { name: 'Add a passkey' }).click()
    await confirmPrfRetryIfPrompted(page)
    const removePasskeyButtons = page.getByRole('button', {
      name: 'Remove',
      exact: true
    })
    await expect(removePasskeyButtons).toHaveCount(1, { timeout: 30_000 })

    // Client 1 issues the recovery code.
    const code = await issueRecoveryCode(page)

    // Client 2 (cold profile): the standing passphrase self-enrolls this
    // browser at login as an ordinary enrolled client.
    const secondClient = await coldClientPage(browser)
    try {
      await secondClient.goto('/#/login')
      await fillSettled(
        secondClient.locator('input[type="password"]'),
        passphrase
      )
      await secondClient
        .getByRole('button', { name: 'Log in', exact: true })
        .click()
      await expect(secondClient).toHaveURL(/#\/dashboard/, { timeout: 60_000 })

      // The point of the spec: client 2 revokes the recovery code client 1
      // issued. The management zcap is the account identity's, so client 2's
      // own signing key carries the invocation.
      await revokeOnlyRecoveryCode(secondClient)

      // ...and the passkey client 1 added, tap-free through the same kind of
      // management zcap (no authenticator exists in this browser context).
      const secondClientRemove = secondClient.getByRole('button', {
        name: 'Remove',
        exact: true
      })
      await expect(secondClientRemove).toHaveCount(1, { timeout: 30_000 })
      await expect(secondClientRemove).toBeEnabled()
      await secondClientRemove.click()
      await expect(
        secondClient.getByRole('heading', { name: 'Remove this passkey?' })
      ).toBeVisible()
      await secondClient.getByRole('button', { name: 'Remove passkey' }).click()
      await expect(secondClientRemove).toHaveCount(0, { timeout: 60_000 })

      // The revoked code's unlock Space is gone, so the code resolves to
      // nothing.
      await expectCodeNoLongerWorks(secondClient, code)
    } finally {
      await secondClient.context().close()
    }

    // The revoked passkey's unlock Space is gone too: a one-tap login with
    // the credential still held by the virtual authenticator finds no wallet.
    await logOut(page)
    await page.goto('/#/login')
    await page.getByRole('button', { name: 'Log in with a Passkey' }).click()
    await expect(
      page.getByText('No wallet was found for this passkey.', { exact: false })
    ).toBeVisible({ timeout: 30_000 })
    await expect(page).toHaveURL(/#\/login/)

    await cdp.detach()
  })

  test('a post-recovery client revokes the replacement recovery code', async ({
    page,
    browser
  }, testInfo) => {
    // A signup, several PBKDF2 logins, the whole recovery ceremony, and the
    // revocation in one spec.
    test.setTimeout(480_000)

    // Client 1: a fresh signup, a re-login, and a recovery code.
    const { passphrase } = await signupViaWizard(page, testInfo)
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 20_000 })
    await logOut(page)
    await logIn(page, passphrase)
    const code = await issueRecoveryCode(page)

    // A cold profile holding nothing but the code recovers the account. The
    // ceremony retires client 1's key set from the document, so the recovered
    // client is the only client the account has -- and the original account
    // controller key no longer exists anywhere.
    const recoveredClient = await coldClientPage(browser)
    try {
      await recoveredClient.goto('/#/recover')
      await fillSettled(
        recoveredClient.locator('input[name="recovery-code"]'),
        code
      )
      await recoveredClient
        .getByRole('button', { name: 'Check code', exact: true })
        .click()
      await expect(
        recoveredClient.getByText('Found a wallet account', { exact: false })
      ).toBeVisible({ timeout: 30_000 })
      await fillSettled(
        recoveredClient.locator('input[id="new-passphrase"]'),
        RECOVERED_PASSPHRASE
      )
      await recoveredClient
        .getByRole('button', { name: 'Recover wallet', exact: true })
        .click()
      await expect(
        recoveredClient.getByText('Your wallet was recovered', { exact: false })
      ).toBeVisible({ timeout: 120_000 })

      // The replacement code is pushed hard: confirmed saved, then login.
      const replacement =
        (await recoveredClient
          .getByTestId('replacement-recovery-code')
          .textContent()) ?? ''
      expect(replacement).not.toBe(code)
      await recoveredClient
        .getByRole('button', { name: 'I saved the new code' })
        .click()
      await recoveredClient
        .getByRole('button', { name: 'Log in to your wallet' })
        .click()
      await expect(recoveredClient).toHaveURL(/#\/dashboard/, {
        timeout: 60_000
      })

      // The point of the spec: the post-recovery client revokes the
      // replacement code. Its record's management zcap chains under the
      // account's did:webvh, whose current key set is this client's --
      // the lost original client key is only an identity stamp.
      await recoveredClient.goto('/#/settings')
      await expect(
        recoveredClient.getByText('Replacement code', { exact: false })
      ).toBeVisible({ timeout: 60_000 })
      await revokeOnlyRecoveryCode(recoveredClient)

      // Both codes now resolve to nothing.
      await expectCodeNoLongerWorks(recoveredClient, replacement)
    } finally {
      await recoveredClient.context().close()
    }
  })
})
