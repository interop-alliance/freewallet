import { test, expect, type Browser, type Page } from '@playwright/test'
import {
  defaultWebvhLogVerifier,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import { fillSettled, signupViaWizard } from './helpers'

/**
 * The client enrollment ceremony e2e (WAS mode): connecting a second browser
 * profile to an existing account. The cold profile's passphrase login is
 * refused (not enrolled), the "Connect this browser" flow mints its key set
 * locally and shows a connect code, the first client approves the code from
 * Settings (the user key roster wrap, then the two-entry did:webvh ceremony), and
 * the cold profile completes: its first roster read -- signed with its
 * freshly published `<did:webvh>#<multibase>` key -- delivers the user key, and
 * the session decrypts the encrypted collections INCLUDING pre-enrollment
 * writes (the escrow-every-epoch semantics; the welcome credential was
 * sealed before the second client existed). The enrollment itself is two
 * verifiable entries on the world-readable log.
 *
 * PBKDF2 unlock derivations run several times across the ceremony, on top of
 * a full signup -- hence `test.slow()` and the generous timeouts.
 */

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

/**
 * Opens a fresh, cold browser context (empty IndexedDB and localStorage) to
 * stand in for a second wallet client (a fresh browser profile). Callers
 * must close the returned page's context.
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

test.describe('Client enrollment ceremony', () => {
  test('a second browser enrolls end to end and decrypts pre-enrollment data', async ({
    page,
    browser
  }, testInfo) => {
    test.slow()

    // Client 1: a fresh signup. The welcome credential is an encrypted write
    // sealed BEFORE the second client exists -- the pre-enrollment epoch the
    // escrow assertion at the end depends on.
    const { passphrase } = await signupViaWizard(page, testInfo)
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 20_000 })

    // Wait for did:webvh provisioning (it runs async off login) and capture
    // the log URL for the final verification.
    const logUrl = await readLogUrl(page)
    const entriesBefore = readLogFromString(
      await (await page.request.get(logUrl)).text()
    ).length

    // Client 2 (cold profile): the passphrase locates the account but the
    // login is refused as not enrolled, surfacing the connect flow.
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
      await expect(
        secondClient.getByText('this browser does not hold its keys yet', {
          exact: false
        })
      ).toBeVisible({ timeout: 30_000 })

      // Start the connect flow: the key set is minted locally and only the
      // public halves surface as the connect code.
      await secondClient
        .getByRole('button', { name: 'Connect this browser' })
        .click()
      const codeField = secondClient.getByTestId('enroll-connect-code')
      await expect(codeField).toBeVisible({ timeout: 20_000 })
      const code = await codeField.inputValue()
      expect(code.startsWith('freewallet-connect:')).toBe(true)
      // The fingerprint to compare on both screens.
      await expect(
        secondClient.getByText(/Key fingerprint: did:key:z6Mk/)
      ).toBeVisible()

      // Client 1 approves the code from Settings: the enrolling half of the
      // ceremony (roster wrap first, then the two log entries).
      await page.goto('/#/settings')
      await page.getByRole('button', { name: 'Connect another wallet' }).click()
      await fillSettled(page.getByTestId('enroll-code-input'), code)
      await expect(page.getByText(/New client key: did:key:z6Mk/)).toBeVisible()
      await page.getByRole('button', { name: 'Approve', exact: true }).click()
      await expect(
        page.getByText('The new browser was enrolled', { exact: false })
      ).toBeVisible({ timeout: 60_000 })

      // Client 2 completes: verifies the published log, performs its first
      // roster read with its did:webvh keyId, persists the key set, and logs
      // in as an ordinary enrolled client.
      await secondClient
        .getByRole('button', { name: 'I approved it -- finish connecting' })
        .click()
      await expect(secondClient).toHaveURL(/#\/dashboard/, {
        timeout: 60_000
      })

      // The escrowed user key decrypts the pre-enrollment epoch: the welcome
      // credential (an encrypted private-credentials write from before this
      // client existed) renders.
      await expect(
        secondClient.getByRole('link', { name: 'Your First Credential' })
      ).toBeVisible({ timeout: 30_000 })

      // A reload-then-login exercises the persisted client-key record (the
      // ordinary enrolled-login path, not ceremony state).
      await secondClient.goto('/#/login')
      await fillSettled(
        secondClient.locator('input[type="password"]'),
        passphrase
      )
      await secondClient
        .getByRole('button', { name: 'Log in', exact: true })
        .click()
      await expect(secondClient).toHaveURL(/#\/dashboard/, {
        timeout: 30_000
      })
    } finally {
      await secondClient.context().close()
    }

    // The enrollment is exactly two verifiable entries on the public log:
    // the commit and the add, and the extended log still fully verifies
    // (SCID, hash chain, prerotation, proofs).
    const logText = await (await page.request.get(logUrl)).text()
    const log = readLogFromString(logText)
    expect(log).toHaveLength(entriesBefore + 2)
    const resolved = await resolveDIDFromLog(log, {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    // Quorum-of-one left both clients authorized: two client update keys.
    expect(resolved.meta.updateKeys).toHaveLength(2)
    // The document roster now carries the second client's keys: two more
    // verification methods than the three a single-client account publishes.
    expect(resolved.doc?.verificationMethod).toHaveLength(5)
    expect(resolved.doc?.keyAgreement).toHaveLength(2)
  })
})
