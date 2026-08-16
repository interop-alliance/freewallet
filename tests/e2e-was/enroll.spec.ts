import { test, expect, type Browser, type Page } from '@playwright/test'
import {
  defaultWebvhLogVerifier,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import { fillSettled, signupViaWizard } from './helpers'

/**
 * The self-enrolling login e2e (WAS mode): connecting a second browser
 * profile to an existing account with nothing but the standing passphrase.
 * The cold profile's login runs the whole continuation in place -- the
 * reveal-and-commit and add entries through the record's bridge delegation,
 * then the first roster read signed with the freshly published
 * `<did:webvh>#<multibase>` key -- and the session decrypts the encrypted
 * collections INCLUDING pre-enrollment writes (the escrow-every-epoch
 * semantics; the welcome credential was sealed before the second client
 * existed). The self-enrollment is two verifiable entries on the
 * world-readable log, and the credential's own posture stands untouched for
 * the next fresh browser.
 *
 * PBKDF2 unlock derivations run several times across the flow, on top of a
 * full signup -- hence `test.slow()` and the generous timeouts.
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

test.describe('Self-enrolling login', () => {
  test('a second browser self-enrolls end to end and decrypts pre-enrollment data', async ({
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

    // Client 2 (cold profile): the standing passphrase self-enrolls this
    // browser at login -- no second party involved -- and lands on the
    // dashboard as an ordinary enrolled client.
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
      // ordinary enrolled-login path, not the self-enrollment).
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

    // The self-enrollment is exactly two verifiable entries on the public
    // log: the reveal-and-commit (ladder rung revealed, new client's hashes
    // committed) and the add (new client in, spent rung retired, the next
    // rung's hash standing), and the extended log still fully verifies
    // (SCID, hash chain, prerotation, proofs).
    const logText = await (await page.request.get(logUrl)).text()
    const log = readLogFromString(logText)
    expect(log).toHaveLength(entriesBefore + 2)
    const resolved = await resolveDIDFromLog(log, {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    // Both clients hold update authority; the revealed rung was retired by
    // the add entry, so exactly two client update keys stand.
    expect(resolved.meta.updateKeys).toHaveLength(2)
    // The document roster now carries the second client's keys: two more
    // verification methods than the four a single-client account publishes
    // (three Multikey entries plus the passphrase's commitment).
    expect(resolved.doc?.verificationMethod).toHaveLength(6)
    // Two client KAKs plus the passphrase's commitment entry.
    expect(resolved.doc?.keyAgreement).toHaveLength(3)
  })
})
