import {
  test,
  expect,
  type CDPSession,
  type Page,
  type TestInfo
} from '@playwright/test'
import { fillSettled, forceRememberBrowser, signupViaWizard } from './helpers'

/**
 * The login page's forget affordance (the no-unlock-material grade) e2e (WAS
 * mode). A wedged login -- a keyring forgery refusal or either continuity
 * refusal -- offers "Forget wallet data on this browser": a whole-database,
 * browser-scoped wipe that runs no ceremony and signs nothing, since nothing
 * derived from the typed secret is trusted in those states. Both cells wedge
 * the login by serving a forged unlock record, which is the only wedge left:
 * the wallet keeps no continuity pin across sessions, so no local state can
 * put a login into a refusal. Covers:
 *
 * 1. A PASSKEY login wedged by a forged unlock record offers the affordance
 *    with no passphrase ever typed, the confirm actually deletes every wallet
 *    database and `freewallet:` localStorage family, and the same passkey
 *    then self-enrolls this browser back into the same account.
 * 2. The stale-state rule: a passphrase refusal's forget affordance does not
 *    survive a following passkey attempt that fails for a different,
 *    non-forgettable reason (PRF unsupported) -- so a failure sequence can
 *    never act on the earlier account's state.
 *
 * Every login here pays the deliberately slow unlock KDF on top of the WAS
 * ceremonies, hence `test.slow()` and the generous timeouts.
 */

/**
 * Builds a unique, well-formed account email for a test worker so parallel and
 * repeated runs never collide on a passphrase-free passkey signup.
 *
 * @param testInfo {TestInfo}
 * @returns {string}
 */
function passkeyEmail(testInfo: TestInfo): string {
  return `e2e-forget-${Date.now()}-w${testInfo.workerIndex}@example.com`
}

/**
 * Opens a CDP session on the page and enables the WebAuthn
 * virtual-authenticator environment. The returned session owns every virtual
 * authenticator added through it, so tests keep it for the lifetime of their
 * authenticators.
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
 * Drives the signup wizard's passkey path to the dashboard: the passkey method
 * choice, the email step, the storage step, then Create Wallet (which
 * registers the passkey and binds its PRF output to a fresh account key set).
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
  await fillSettled(page.locator('input[type="email"]'), email)
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
  await page.getByRole('button', { name: 'Create Wallet' }).click()
  await confirmPrfRetryIfPrompted(page)
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 45_000 })
}

/**
 * Drives the signup wizard's passkey path on an authenticator that cannot
 * evaluate PRF: the credential IS registered (a discoverable passkey for this
 * origin), but no unlock secret can be derived, so the wizard stays on the
 * storage step with the PRF-unsupported error. Used purely to plant a
 * PRF-less passkey the login page can then pick up.
 *
 * @param page {Page}
 * @param options {object}
 * @param options.email {string}
 * @returns {Promise<void>}
 */
async function plantPrflessPasskey(
  page: Page,
  { email }: { email: string }
): Promise<void> {
  await page.goto('/#/signup')
  await page.getByRole('button', { name: 'Sign up with a Passkey' }).click()
  await fillSettled(page.locator('input[type="email"]'), email)
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
  await page.getByRole('button', { name: 'Create Wallet' }).click()
  await confirmPrfRetryIfPrompted(page)
  await expect(
    page.getByText('cannot unlock Freewallet', { exact: false })
  ).toBeVisible({ timeout: 20_000 })
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
 * The served unlock record's resource path: one plaintext JSON document per
 * unlock Space, at `/space/<unlockSpaceId>/keyring/keyring.json`. Matched as
 * a regular expression so a query string cannot slip past it.
 */
const UNLOCK_RECORD_URL = /\/keyring\/keyring\.json(?:\?|$)/

/**
 * Makes the storage server serve a FORGED unlock record: every GET of the
 * record is fetched for real and handed back with one byte of its
 * `proof.proofValue` flipped, so the proof no longer verifies under the key
 * the typed secret derives. The next login refuses with
 * `KeyringRecordForgedError` (`auth.errors.keyringForged`) -- one of the
 * forgettable refusals -- before the record is ever decrypted.
 *
 * Interception is the only wedge left: this wallet keeps no continuity pin
 * across sessions (`decisions/0012-no-durable-continuity-pins.md`), so no
 * local state can put a login into a refusal.
 *
 * @param page {Page}
 * @returns {Promise<void>}
 */
async function serveForgedUnlockRecord(page: Page): Promise<void> {
  await page.route(UNLOCK_RECORD_URL, async route => {
    if (route.request().method() !== 'GET') {
      await route.fallback()
      return
    }
    const response = await route.fetch()
    if (!response.ok()) {
      await route.fulfill({ response })
      return
    }
    const record = (await response.json()) as {
      proof?: { proofValue?: string }
    }
    const proofValue = record.proof?.proofValue
    if (typeof proofValue !== 'string' || proofValue.length === 0) {
      throw new Error('The served unlock record carries no proof to forge.')
    }
    // Flip the last character within the same base58 alphabet, so the value
    // stays well-formed and fails on the SIGNATURE rather than on decoding.
    const last = proofValue.at(-1)
    record.proof!.proofValue =
      proofValue.slice(0, -1) + (last === 'z' ? 'y' : 'z')
    await route.fulfill({
      response,
      json: record
    })
  })
}

/**
 * Stops serving the forged record, so a later login on the same page reaches
 * the genuine one.
 *
 * @param page {Page}
 * @returns {Promise<void>}
 */
async function serveGenuineUnlockRecord(page: Page): Promise<void> {
  await page.unroute(UNLOCK_RECORD_URL)
}

/**
 * Enumerates what the forget wipe is supposed to remove: the IndexedDB
 * database names for this origin and the `freewallet:`-prefixed localStorage
 * keys.
 *
 * @param page {Page}
 * @returns {Promise<{ databases: string[], localStorageKeys: string[] }>}
 */
async function readBrowserWalletData(
  page: Page
): Promise<{ databases: string[]; localStorageKeys: string[] }> {
  return page.evaluate(async () => {
    const databases = (await indexedDB.databases())
      .map(info => info.name)
      .filter((name): name is string => typeof name === 'string')
    const localStorageKeys: string[] = []
    for (let index = 0; index < localStorage.length; index++) {
      const key = localStorage.key(index)
      if (key?.startsWith('freewallet:')) {
        localStorageKeys.push(key)
      }
    }
    return { databases, localStorageKeys }
  })
}

const REPLICA_DB_NAME_PATTERN = /-(?:wallet|credentials|sync)-db/

test.describe('Forget wallet data on this browser', () => {
  test('a passkey continuity refusal offers forget, and the wipe is real', async ({
    page
  }, testInfo) => {
    test.slow()

    const cdp = await enableWebAuthn(page)
    await addAuthenticator(cdp, { hasPrf: true })

    // A passkey signup remembers this browser, so it holds a client-key
    // record and logs in as an enrolled client.
    await passkeySignup(page, { email: passkeyEmail(testInfo) })
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 20_000 })

    await logout(page)

    // Wedge the next login: the served record's proof no longer verifies
    // under the key the passkey's PRF output derives.
    await serveForgedUnlockRecord(page)
    const before = await readBrowserWalletData(page)
    expect(before.databases).toContain('freewallet-session')
    expect(
      before.databases.some(name => REPLICA_DB_NAME_PATTERN.test(name))
    ).toBe(true)

    // A PASSKEY login -- the passphrase field is never touched.
    await page.goto('/#/login')
    await forceRememberBrowser(page)
    await page.getByRole('button', { name: 'Log in with a Passkey' }).click()
    await expect(
      page.getByText('login record that is not authentic', { exact: false })
    ).toBeVisible({ timeout: 45_000 })

    const forgetButton = page.getByTestId('forget-browser-button')
    await expect(forgetButton).toBeVisible()
    await forgetButton.click()

    // The confirm dialog states the whole-browser blast radius and the
    // standing-document-client residue before offering the destructive button.
    await expect(
      page.getByRole('heading', {
        name: 'Forget all wallet data on this browser?'
      })
    ).toBeVisible()
    await expect(
      page.getByText('other accounts remembered here are affected too', {
        exact: false
      })
    ).toBeVisible()
    await expect(
      page.getByText('still list this browser as a connected wallet', {
        exact: false
      })
    ).toBeVisible()
    await page.getByTestId('forget-browser-confirm').click()

    await expect(
      page.getByText('All wallet data on this browser has been forgotten.')
    ).toBeVisible({ timeout: 30_000 })
    // The refusal that offered the affordance is cleared with it.
    await expect(
      page.getByText('login record that is not authentic', { exact: false })
    ).toHaveCount(0)

    // The wipe is asserted by direct enumeration, not by the toast.
    await expect(async () => {
      const after = await readBrowserWalletData(page)
      expect(after.databases).not.toContain('freewallet-session')
      expect(
        after.databases.filter(name => REPLICA_DB_NAME_PATTERN.test(name))
      ).toEqual([])
      expect(after.localStorageKeys).toEqual([])
    }).toPass({ timeout: 30_000 })

    // The passkey is a standing credential, so the forgotten browser
    // self-enrolls at the next login and lands back in the same wallet --
    // against the genuine record this time.
    await serveGenuineUnlockRecord(page)
    await page.goto('/#/login')
    await page.reload()
    await forceRememberBrowser(page)
    await page.getByRole('button', { name: 'Log in with a Passkey' }).click()
    await expect(page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 30_000 })
  })

  test('a passphrase refusal then a passkey failure cannot act on stale state', async ({
    page
  }, testInfo) => {
    test.slow()

    const { passphrase } = await signupViaWizard(page, testInfo)
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 20_000 })
    await logout(page)

    // Plant a discoverable passkey on an authenticator that cannot evaluate
    // PRF: the login page's passkey button will pick it and fail with the
    // non-forgettable PRF-unsupported error.
    const cdp = await enableWebAuthn(page)
    await addAuthenticator(cdp, { hasPrf: false })
    await plantPrflessPasskey(page, { email: passkeyEmail(testInfo) })

    await serveForgedUnlockRecord(page)

    // The PASSPHRASE login wedges on the forgery refusal and offers forget.
    await page.goto('/#/login')
    await forceRememberBrowser(page)
    await fillSettled(page.locator('input[type="password"]'), passphrase)
    await page.getByRole('button', { name: 'Log in', exact: true }).click()
    await expect(
      page.getByText('login record that is not authentic', { exact: false })
    ).toBeVisible({ timeout: 45_000 })
    await expect(page.getByTestId('forget-browser-button')).toBeVisible()

    // Do NOT click it. A fresh passkey attempt fails for a different,
    // non-forgettable reason.
    await page.getByRole('button', { name: 'Log in with a Passkey' }).click()
    await expect(
      page.getByText('cannot unlock Freewallet', { exact: false })
    ).toBeVisible({ timeout: 45_000 })

    // No stale affordance survives into the new error, and no dialog is open.
    await expect(page.getByTestId('forget-browser-button')).toHaveCount(0)
    await expect(
      page.getByRole('heading', {
        name: 'Forget all wallet data on this browser?'
      })
    ).toHaveCount(0)
    await expect(
      page.getByText('login record that is not authentic', { exact: false })
    ).toHaveCount(0)
    // Nothing was wiped: the browser still holds its wallet data.
    const after = await readBrowserWalletData(page)
    expect(after.databases).toContain('freewallet-session')
  })
})
