/**
 * The client-axis account ceremonies from a TRANSIENT session on a
 * credential-anchored account (FW-424). Two accounts, one per suite, so a
 * failure in one cell says which ceremony it belongs to.
 *
 * Suite 1, the unlock ceremonies beside a standing recovery code:
 *
 * 1. Recovery-code issuance and revocation, then a second issuance whose code
 *    stays unspent for the cells below.
 * 2. A passphrase change while that unspent code stands: it must not refuse,
 *    and the code's row survives it.
 * 3. That code still spends from a fresh terminal, across the two user-key
 *    rotations the revocation and the change ran.
 *
 * Suite 2, the client-axis pair:
 *
 * 4. Enrollment approval with the APPROVING side transient: a second cold
 *    browser mints a connect code, the transient session approves it, and the
 *    enrollee finishes and decrypts a credential stored before it existed.
 * 5. The disconnect of that enrolled client -- the account's LAST one -- from
 *    the transient session, which lands the account ladder-anchored again.
 * 6. A cold terminal still enters with the passphrase alone, and the
 *    disconnected browser's next login hits the forgotten-browser detector.
 *
 * Each suite's acting page is one long-lived transient visit: sessions are
 * in-memory, so a reload would end it. Nothing is written to that browser at
 * any point, which each suite's residue assertion pins.
 */
import {
  test,
  expect,
  type Browser,
  type BrowserContext,
  type Page
} from '@playwright/test'
import {
  defaultWebvhLogVerifier,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import {
  addCredentialViaPaste,
  awaitLoginChain,
  fillSettled,
  signupViaWizard
} from './helpers'
import {
  captureLocalStorageKeys,
  expectNoStorageResidue
} from '../shared/storageResidue'

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

/**
 * A fresh, cold browser context (empty IndexedDB and localStorage).
 *
 * @param browser {Browser}
 * @returns {Promise<{ context: BrowserContext, page: Page }>}
 */
async function coldTerminal(
  browser: Browser
): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ baseURL: APP_URL })
  const page = await context.newPage()
  return { context, page }
}

/**
 * The wallet cards inside the connected-wallets list.
 *
 * @param page {Page}
 * @returns {import('@playwright/test').Locator}
 */
function walletCards(page: Page) {
  return page.getByTestId('enrolled-clients-list').locator('.MuiCard-root')
}

/**
 * The world-readable `did.jsonl` URL the Settings page links, once did:webvh
 * provisioning has landed.
 *
 * @param page {Page}
 * @returns {Promise<string>}
 */
async function readLogUrl(page: Page): Promise<string> {
  await page.goto('/#/settings')
  await expect(page.getByText('Published did:webvh DID')).toBeVisible({
    timeout: 30_000
  })
  const logLink = page.getByRole('link', { name: /\/id\/did\.jsonl$/ })
  await expect(logLink).toBeVisible({ timeout: 30_000 })
  return (await logLink.getAttribute('href'))!
}

/**
 * The count of enrolled clients the world-readable account log resolves to
 * (`capabilityInvocation` membership, the keying every client listing uses).
 *
 * @param page {Page}
 * @param logUrl {string}
 * @returns {Promise<number>}
 */
async function enrolledClientCount(
  page: Page,
  logUrl: string
): Promise<number> {
  const response = await page.request.get(logUrl)
  expect(response.status()).toBe(200)
  const resolved = await resolveDIDFromLog(
    readLogFromString(await response.text()),
    { verifier: defaultWebvhLogVerifier }
  )
  expect(resolved.meta.error).toBeUndefined()
  return ((resolved.doc?.capabilityInvocation ?? []) as unknown[]).length
}

/**
 * Issues a recovery code from Settings and returns it. Nothing binds until
 * the confirm-once dialog's "I saved this code".
 *
 * @param page {Page}
 * @param options {object}
 * @param options.expectLabel {string}   the row label to wait for
 * @returns {Promise<string>}
 */
async function issueRecoveryCode(
  page: Page,
  { expectLabel }: { expectLabel: string }
): Promise<string> {
  await page.goto('/#/settings')
  const generate = page.getByRole('button', { name: 'Generate recovery code' })
  await expect(generate).toBeEnabled({ timeout: 60_000 })
  await generate.click()
  await expect(
    page.getByText('This code is shown only once', { exact: false })
  ).toBeVisible({ timeout: 30_000 })
  const code = (await page.locator('code').textContent()) ?? ''
  expect(code).toMatch(/^[1-9A-HJ-NP-Za-km-z]{4}(-[1-9A-HJ-NP-Za-km-z]{1,4})+$/)
  await page.getByRole('button', { name: 'I saved this code' }).click()
  await expect(page.getByText(expectLabel)).toBeVisible({ timeout: 120_000 })
  return code
}

test.describe.serial('recovery codes beside a passphrase change', () => {
  let context: BrowserContext
  let terminal: Page
  let baseline: string[]
  let passphrase: string
  let newPassphrase: string
  let unspentCode: string

  test.beforeAll(async ({ browser }, testInfo) => {
    test.setTimeout(240_000)
    const opened = await coldTerminal(browser)
    context = opened.context
    terminal = opened.page
    // The default signup: no remember seam, so the account is
    // credential-anchored and this visit is a transient session for its whole
    // life.
    await terminal.goto('/#/signup')
    baseline = await captureLocalStorageKeys({ page: terminal })
    const user = await signupViaWizard(terminal, testInfo, {
      rememberBrowser: false
    })
    passphrase = user.passphrase
    await addCredentialViaPaste(terminal)
  })

  test.afterAll(async () => {
    await context?.close()
  })

  test('issues and revokes a recovery code, then issues a second', async () => {
    test.setTimeout(300_000)
    // A native confirm gates the revoke.
    terminal.on('dialog', dialog => void dialog.accept())

    await issueRecoveryCode(terminal, { expectLabel: 'Recovery code 1' })

    // The revocation is the issuance reversal, and it drives the same epoch
    // cascade a client disconnect does -- ladder-signed here.
    const revoke = terminal.getByRole('button', {
      name: 'Revoke this recovery code'
    })
    await expect(revoke).toHaveCount(1, { timeout: 60_000 })
    await expect(revoke).toBeEnabled()
    await revoke.click()
    await expect(
      terminal.getByText('No recovery codes have been generated yet.')
    ).toBeVisible({ timeout: 180_000 })

    // The second code stays unspent through the change below.
    unspentCode = await issueRecoveryCode(terminal, {
      expectLabel: 'Recovery code 1'
    })
  })

  test('changes the passphrase with an unspent recovery code standing', async () => {
    test.setTimeout(300_000)
    newPassphrase = `Rebound-clients-${Date.now()}-Zz9!`
    await terminal.goto('/#/settings')
    await expect(
      terminal.getByRole('heading', { name: 'Passphrase', exact: true })
    ).toBeVisible()
    await fillSettled(
      terminal.getByLabel('Current passphrase', { exact: true }),
      passphrase
    )
    await fillSettled(
      terminal.getByLabel('New passphrase', { exact: true }),
      newPassphrase
    )
    const changeButton = terminal.getByRole('button', {
      name: 'Change passphrase'
    })
    await expect(changeButton).toBeEnabled({ timeout: 30_000 })
    await changeButton.click()
    // No refusal on the sibling record: under invariant 17 the unspent code's
    // bridge and sibling are signed by its OWN ladder VM, so the old
    // credential's strike rots nothing of it.
    await expect(
      terminal.getByText('Your content keys were rotated', { exact: false })
    ).toBeVisible({ timeout: 180_000 })

    // The code's row still stands.
    await terminal.goto('/#/dashboard')
    await terminal.goto('/#/settings')
    await expect(terminal.getByText('Recovery code 1')).toBeVisible({
      timeout: 60_000
    })

    // The visit wrote nothing to this browser across the three ceremonies.
    await terminal.goto('/#/dashboard')
    await terminal.getByRole('button', { name: 'Log out' }).click()
    await expect(terminal).toHaveURL(/\/#?\/?$/)
    await expectNoStorageResidue({
      page: terminal,
      baselineLocalStorageKeys: baseline
    })

    // The changed passphrase enters from the same cold browser.
    await terminal.goto('/#/login')
    await fillSettled(terminal.locator('input[type="password"]'), newPassphrase)
    await terminal.getByRole('button', { name: 'Log in', exact: true }).click()
    await expect(terminal).toHaveURL(/#\/dashboard/, { timeout: 90_000 })
  })

  test('the unspent recovery code still spends', async ({ browser }) => {
    test.setTimeout(360_000)
    const recoveredPassphrase = `Recovered-clients-${Date.now()}-Aa1!`
    const { context: spendContext, page } = await coldTerminal(browser)
    try {
      await page.goto('/#/recover')
      const recoverBaseline = await captureLocalStorageKeys({ page })
      await fillSettled(
        page.locator('input[name="recovery-code"]'),
        unspentCode
      )
      await page
        .getByRole('button', { name: 'Check code', exact: true })
        .click()
      await expect(
        page.getByText('Found a wallet account', { exact: false })
      ).toBeVisible({ timeout: 60_000 })

      await fillSettled(
        page.locator('input[id="new-passphrase"]'),
        recoveredPassphrase
      )
      await page
        .getByRole('button', { name: 'Recover wallet', exact: true })
        .click()
      await expect(
        page.getByText('Your wallet was recovered', { exact: false })
      ).toBeVisible({ timeout: 240_000 })

      await page.getByRole('button', { name: 'I saved the new code' }).click()
      await page.getByRole('button', { name: 'Log in to your wallet' }).click()
      await expect(page).toHaveURL(/#\/dashboard/, { timeout: 120_000 })
      // The account's history decrypts across the rotations the revocation
      // and the passphrase change ran before this spend.
      await expect(
        page.getByRole('link', { name: 'E2E Test Credential' })
      ).toBeVisible({ timeout: 60_000 })

      await page.getByRole('button', { name: 'Log out' }).click()
      await expect(page).toHaveURL(/\/#?\/?$/)
      await expectNoStorageResidue({
        page,
        baselineLocalStorageKeys: recoverBaseline
      })
    } finally {
      await spendContext.close()
    }
  })
})

test.describe
  .serial('enrollment approval and the last-client disconnect', () => {
  let terminalContext: BrowserContext
  let terminal: Page
  let enrolleeContext: BrowserContext
  let enrollee: Page
  let baseline: string[]
  let passphrase: string
  let logUrl: string

  test.beforeAll(async ({ browser }, testInfo) => {
    test.setTimeout(240_000)
    const opened = await coldTerminal(browser)
    terminalContext = opened.context
    terminal = opened.page
    await terminal.goto('/#/signup')
    baseline = await captureLocalStorageKeys({ page: terminal })
    const user = await signupViaWizard(terminal, testInfo, {
      rememberBrowser: false
    })
    passphrase = user.passphrase
    // A credential sealed before the second browser exists: what the
    // enrollment's escrow has to keep readable there.
    await addCredentialViaPaste(terminal)
    logUrl = await readLogUrl(terminal)
  })

  test.afterAll(async () => {
    await enrolleeContext?.close()
    await terminalContext?.close()
  })

  test('approves a second browser through the connect-code ceremony', async ({
    browser
  }) => {
    test.setTimeout(300_000)
    const opened = await coldTerminal(browser)
    enrolleeContext = opened.context
    enrollee = opened.page

    // The enrollee half. A cold browser's default login would simply
    // succeed transiently, so the connect card is opened through the
    // non-production seam that stands in until the login form grows its own
    // control.
    await enrollee.goto('/#/login')
    await enrollee.evaluate(() => {
      ;(
        window as unknown as { __E2E_OFFER_CONNECT_CARD__?: boolean }
      ).__E2E_OFFER_CONNECT_CARD__ = true
    })
    await fillSettled(enrollee.locator('input[type="password"]'), passphrase)
    await enrollee.getByRole('button', { name: 'Log in', exact: true }).click()
    const connectButton = enrollee.getByRole('button', {
      name: 'Connect this browser'
    })
    await expect(connectButton).toBeVisible({ timeout: 90_000 })
    await connectButton.click()
    const codeField = enrollee.getByTestId('enroll-connect-code')
    await expect(codeField).toBeVisible({ timeout: 60_000 })
    const connectCode = (await codeField.inputValue()).trim()
    expect(connectCode.startsWith('freewallet-connect:')).toBe(true)

    // The approving half, from the TRANSIENT session: the roster escrow
    // rides the licensed ladder append and the two log entries are
    // ladder-signed.
    await terminal.goto('/#/settings')
    await expect(terminal.getByText('Connected wallets')).toBeVisible()
    await terminal
      .getByRole('button', { name: 'Connect another wallet' })
      .click()
    await fillSettled(terminal.getByTestId('enroll-code-input'), connectCode)
    await fillSettled(terminal.getByTestId('enroll-label-input'), 'Home laptop')
    await terminal.getByRole('button', { name: 'Approve', exact: true }).click()
    await expect(
      terminal.getByText('The new browser was enrolled', { exact: false })
    ).toBeVisible({ timeout: 180_000 })

    // The enrollee finishes off the world-readable log and decrypts the
    // credential stored before it existed.
    await enrollee
      .getByRole('button', { name: 'I approved it -- finish connecting' })
      .click()
    await expect(enrollee).toHaveURL(/#\/dashboard/, { timeout: 180_000 })
    await expect(
      enrollee.getByRole('link', { name: 'E2E Test Credential' })
    ).toBeVisible({ timeout: 60_000 })
    // Let the enrollee's own login-time chain settle, so its sweeps cannot
    // race the ceremonies below.
    await awaitLoginChain(enrollee)

    expect(await enrolledClientCount(terminal, logUrl)).toBe(1)
  })

  test('disconnects the account last enrolled client', async () => {
    test.setTimeout(300_000)
    await terminal.goto('/#/dashboard')
    await terminal.goto('/#/settings')
    await expect(terminal.getByText('Connected wallets')).toBeVisible()
    await expect(walletCards(terminal)).toHaveCount(1, { timeout: 60_000 })
    // On the ladder branch the last row IS disconnectable, and the row says
    // what disconnecting it makes of the account.
    await expect(
      terminal.getByText('This is the last connected browser', {
        exact: false
      })
    ).toBeVisible()

    await terminal
      .getByRole('button', { name: 'Disconnect', exact: true })
      .click()
    await expect(
      terminal.getByTestId('disconnect-last-client-copy')
    ).toBeVisible()
    await terminal
      .getByRole('button', { name: 'Disconnect wallet', exact: true })
      .click()
    await expect(walletCards(terminal)).toHaveCount(0, { timeout: 240_000 })

    // The account is ladder-anchored again: the document lists no enrolled
    // client at all.
    expect(await enrolledClientCount(terminal, logUrl)).toBe(0)
  })

  test('the credential still enters and the disconnected browser is told', async ({
    browser
  }) => {
    test.setTimeout(300_000)
    // The acting visit wrote nothing to its own browser across both
    // ceremonies.
    await terminal.goto('/#/dashboard')
    await terminal.getByRole('button', { name: 'Log out' }).click()
    await expect(terminal).toHaveURL(/\/#?\/?$/)
    await expectNoStorageResidue({
      page: terminal,
      baselineLocalStorageKeys: baseline
    })

    // A cold terminal enters with the passphrase alone.
    const { context, page } = await coldTerminal(browser)
    try {
      await page.goto('/#/login')
      await fillSettled(page.locator('input[type="password"]'), passphrase)
      await page.getByRole('button', { name: 'Log in', exact: true }).click()
      await expect(page).toHaveURL(/#\/dashboard/, { timeout: 90_000 })
      await expect(
        page.getByRole('link', { name: 'E2E Test Credential' })
      ).toBeVisible({ timeout: 60_000 })
    } finally {
      await context.close()
    }

    // The disconnected browser still holds its client-key record, so its
    // next login routes remembered and meets the forgotten-browser
    // detector, which finishes the wipe and says so in place of a raw
    // authorization error. Its enrollment session is still live in that tab,
    // and a session is in-memory, so the reload is what ends it.
    await enrollee.goto('/#/logout')
    await expect(enrollee).toHaveURL(/#\/$/, { timeout: 30_000 })
    await enrollee.reload()
    await enrollee.goto('/#/login')
    await fillSettled(enrollee.locator('input[type="password"]'), passphrase)
    await enrollee.getByRole('button', { name: 'Log in', exact: true }).click()
    await expect(
      enrollee.getByText("This browser's wallet access was removed", {
        exact: false
      })
    ).toBeVisible({ timeout: 120_000 })
    expect(enrollee.url()).not.toMatch(/#\/dashboard/)
  })
})
