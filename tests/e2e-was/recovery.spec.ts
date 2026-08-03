import { test, expect, type Browser, type Page } from '@playwright/test'
import {
  defaultWebvhLogVerifier,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import { fillSettled, signupViaWizard } from './helpers'

/**
 * The recovery-code flow e2e (WAS mode), end to end: a code issued from
 * Settings (the split posture: roster wrap, the code's `keyAgreement`
 * VM, `nextKeyHashes` commitment, delegated unlock record), then recovery on
 * a COLD browser profile holding nothing but the code -- the delegated log
 * write enrolls a brand-new client, the PUK comes out of the code's standing
 * wrap and is rotated off the spent code, a replacement code is pushed hard,
 * and the recovered session decrypts pre-recovery encrypted writes (the
 * welcome credential) across the rotation. The spent code then fails with
 * wording distinct from "wrong code", and the whole ceremony is verifiable
 * entries on the world-readable log.
 *
 * Several PBKDF2 unlock derivations run across the flow on top of a full
 * signup -- hence `test.slow()` and the generous timeouts.
 */

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

const NEW_PASSPHRASE = 'Recovered-passphrase-42!'

/**
 * Opens a fresh, cold browser context (empty IndexedDB and localStorage) to
 * stand in for a new wallet client (a fresh browser profile). Callers must
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
 * Scrapes the world-readable `did.jsonl` URL from the Settings page's
 * published did:webvh row, waiting for provisioning to land first.
 *
 * @param page {Page}
 * @returns {Promise<string>}
 */
async function readLogUrl(page: Page): Promise<string> {
  await page.goto('/#/settings')
  await expect(page.getByText('Published did:webvh DID')).toBeVisible()
  const logLink = page.getByRole('link', { name: /did\.jsonl$/ })
  await expect(logLink).toBeVisible({ timeout: 30_000 })
  return (await logLink.getAttribute('href'))!
}

/**
 * Logs out via the logout route and waits for its deferred redirect to the
 * landing page to land. `/#/logout` is a same-document hash navigation, so
 * `goto` resolves before the logout page's async work finishes -- and its
 * trailing `navigate('/')` then fires late, yanking the router off whatever
 * page the test has since navigated to (the recover page's Check code button
 * vanished exactly this way).
 *
 * @param page {Page}
 */
async function logOut(page: Page) {
  await page.goto('/#/logout')
  await expect(page).toHaveURL(/#\/$/, { timeout: 15_000 })
}

/**
 * Logs in with a passphrase from the login page.
 */
async function logIn(page: Page, passphrase: string) {
  await page.goto('/#/login')
  await fillSettled(page.locator('input[type="password"]'), passphrase)
  await page.getByRole('button', { name: 'Log in', exact: true }).click()
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })
}

test.describe('Recovery codes', () => {
  test('issue in Settings, recover on a cold profile, spent code fails, log verifies', async ({
    page,
    browser
  }, testInfo) => {
    // Beyond test.slow(): a signup plus five PBKDF2 logins plus the whole
    // ceremony run in one spec.
    test.setTimeout(360_000)

    // Client 1: a fresh signup; the welcome credential is an encrypted write
    // sealed BEFORE any recovery, under the pre-rotation PUK -- the escrow
    // assertion at the end depends on it.
    const { passphrase } = await signupViaWizard(page, testInfo)
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 20_000 })

    // A signup session predates the account pointer, so re-login: issuance
    // gates on a promoted did:webvh pointer recovered from the keyring.
    await logOut(page)
    await logIn(page, passphrase)

    // Capture the log URL and its length before issuance.
    const logUrl = await readLogUrl(page)
    const entriesBefore = readLogFromString(
      await (await page.request.get(logUrl)).text()
    ).length

    // Issue a recovery code from Settings: nothing binds until the
    // confirm-once dialog's "I saved this code".
    await page.goto('/#/settings')
    await expect(
      page.getByText('Recovery codes', { exact: true })
    ).toBeVisible()
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
    expect(code).toMatch(
      /^[1-9A-HJ-NP-Za-km-z]{4}(-[1-9A-HJ-NP-Za-km-z]{1,4})+$/
    )
    await page.getByRole('button', { name: 'I saved this code' }).click()
    await expect(page.getByText('Recovery code 1')).toBeVisible({
      timeout: 60_000
    })

    // Issuance is one verifiable log entry: the code's keyAgreement VM
    // plus the update-key commitment.
    const afterIssuance = readLogFromString(
      await (await page.request.get(logUrl)).text()
    )
    expect(afterIssuance).toHaveLength(entriesBefore + 1)

    // The cold profile: nothing but the code.
    const secondClient = await coldClientPage(browser)
    try {
      await secondClient.goto('/#/recover')

      // A well-formed code for no wallet: the honest "no account" wording,
      // distinct from a malformed code.
      await fillSettled(
        secondClient.locator('input[name="recovery-code"]'),
        '1111111111111111'
      )
      await secondClient
        .getByRole('button', { name: 'Check code', exact: true })
        .click()
      await expect(
        secondClient.getByText('No wallet was found for this recovery code', {
          exact: false
        })
      ).toBeVisible({ timeout: 30_000 })

      // Malformed text is rejected as not-a-code.
      await fillSettled(
        secondClient.locator('input[name="recovery-code"]'),
        'not a code'
      )
      await secondClient
        .getByRole('button', { name: 'Check code', exact: true })
        .click()
      await expect(
        secondClient.getByText('not a valid recovery code', { exact: false })
      ).toBeVisible()

      // The real code locates the account.
      await fillSettled(
        secondClient.locator('input[name="recovery-code"]'),
        code
      )
      await secondClient
        .getByRole('button', { name: 'Check code', exact: true })
        .click()
      await expect(
        secondClient.getByText('Found a wallet account', { exact: false })
      ).toBeVisible({ timeout: 30_000 })

      // A new passphrase for this browser, then the whole ceremony.
      await fillSettled(
        secondClient.locator('input[id="new-passphrase"]'),
        NEW_PASSPHRASE
      )
      await secondClient
        .getByRole('button', { name: 'Recover wallet', exact: true })
        .click()
      await expect(
        secondClient.getByText('Your wallet was recovered', { exact: false })
      ).toBeVisible({ timeout: 120_000 })

      // The replacement code is pushed hard: shown once, must be confirmed
      // saved before login unlocks.
      const replacement =
        (await secondClient
          .getByTestId('replacement-recovery-code')
          .textContent()) ?? ''
      expect(replacement).toMatch(
        /^[1-9A-HJ-NP-Za-km-z]{4}(-[1-9A-HJ-NP-Za-km-z]{1,4})+$/
      )
      expect(replacement).not.toBe(code)
      const loginButton = secondClient.getByRole('button', {
        name: 'Log in to your wallet'
      })
      await expect(loginButton).toBeDisabled()
      await secondClient
        .getByRole('button', { name: 'I saved the new code' })
        .click()
      await loginButton.click()
      await expect(secondClient).toHaveURL(/#\/dashboard/, {
        timeout: 60_000
      })

      // The recovered client decrypts pre-recovery history across the PUK
      // rotation: the welcome credential (sealed under the old PUK's epoch)
      // renders via the escrowed wraps.
      await expect(
        secondClient.getByRole('link', { name: 'Your First Credential' })
      ).toBeVisible({ timeout: 30_000 })

      // An ordinary re-login exercises the persisted client-key record.
      await logOut(secondClient)
      await logIn(secondClient, NEW_PASSPHRASE)

      // The spent code now fails, with wording distinct from "wrong code":
      // its unlock Space is gone and its posture left the document.
      await logOut(secondClient)
      await secondClient.goto('/#/recover')
      await expect(
        secondClient.getByRole('heading', {
          name: 'Recover your wallet',
          level: 1
        })
      ).toBeVisible()
      await fillSettled(
        secondClient.locator('input[name="recovery-code"]'),
        code
      )
      await secondClient
        .getByRole('button', { name: 'Check code', exact: true })
        .click()
      await expect(
        secondClient.getByText(
          /No wallet was found for this recovery code|has been revoked or already used/
        )
      ).toBeVisible({ timeout: 30_000 })
    } finally {
      await secondClient.context().close()
    }

    // The ceremony is verifiable entries on the public log: issuance (1) plus
    // the reveal-and-commit and add-and-retire continuation (2), and the
    // extended log still fully verifies (SCID, hash chain, prerotation,
    // proofs).
    const logText = await (await page.request.get(logUrl)).text()
    const log = readLogFromString(logText)
    expect(log).toHaveLength(entriesBefore + 3)
    const resolved = await resolveDIDFromLog(log, {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    // The original client and the recovered client hold update authority; the
    // spent code's update key does not stand.
    expect(resolved.meta.updateKeys).toHaveLength(2)
    // The document carries: the original client's two VMs, the two KMS VMs,
    // the recovered client's two VMs, and the replacement code's keyAgreement
    // VM (deliberately unmarked) -- the spent code's VM is gone, so exactly
    // three keyAgreement entries stand (two clients + one code) against two
    // capabilityInvocation entries (recovery keys never appear there).
    const keyAgreement = (resolved.doc?.keyAgreement ?? []) as string[]
    expect(keyAgreement).toHaveLength(3)
    expect(resolved.doc?.capabilityInvocation).toHaveLength(2)
    expect(resolved.doc?.verificationMethod).toHaveLength(7)
  })

  test('login and signup pages link to the recover flow', async ({ page }) => {
    await page.goto('/#/login')
    await page.getByRole('link', { name: 'Forgot your passphrase?' }).click()
    await expect(page).toHaveURL(/#\/recover/)
    await expect(
      page.getByRole('heading', { name: 'Recover your wallet', level: 1 })
    ).toBeVisible()

    await page.goto('/#/signup')
    await expect(
      page.getByRole('link', {
        name: 'Recover your existing wallet instead of starting over.'
      })
    ).toBeVisible()
  })
})
