import {
  expect,
  type Locator,
  type Page,
  type TestInfo
} from '@playwright/test'

/**
 * Fills a form field and verifies the value survived, retrying until it
 * sticks. A `goto` resolves on the navigation itself, before React commits
 * the new route's tree; under parallel-worker load a fill issued in that
 * window can land on the outgoing route's input and be dropped with it,
 * leaving the freshly mounted field empty (the keyring login spec flaked
 * exactly this way). Use for the first fill after a navigation.
 *
 * @param locator {Locator}   the input to fill
 * @param value {string}   the value to fill in
 * @returns {Promise<void>}
 */
export async function fillSettled(
  locator: Locator,
  value: string
): Promise<void> {
  await expect(async () => {
    await locator.fill(value)
    await expect(locator).toHaveValue(value, { timeout: 500 })
  }).toPass({ timeout: 15_000 })
}

export function testUser(testInfo: TestInfo) {
  const token = `${Date.now()}-w${testInfo.workerIndex}`
  return {
    passphrase: `Str0ngpass-${token}-Aa1!`,
    email: `e2e-${token}@example.com`
  }
}

export async function signupViaWizard(
  page: Page,
  testInfo: TestInfo,
  {
    rememberBrowser = true
  }: {
    // The credential-anchored (transient-session) signup is the DEFAULT on a
    // non-remembered browser, so the durable fixtures every other suite
    // builds on force the remember seam; the credential-anchored signup spec
    // is the one caller passing false.
    rememberBrowser?: boolean
  } = {}
) {
  const { passphrase, email } = testUser(testInfo)

  await page.goto('/#/signup')
  if (rememberBrowser) {
    await forceRememberBrowser(page)
  }
  await fillSettled(page.locator('input[type="password"]'), passphrase)
  // The strength meter enables Next only after it scores the passphrase;
  // under a parallel-worker CPU squeeze that can outlast the default 5s.
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled({
    timeout: 15_000
  })
  await page.getByRole('button', { name: 'Next' }).click()
  await page.locator('input[type="email"]').fill(email)
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
  await page.getByRole('button', { name: 'Create Wallet' }).click()
  // Signup binds the keyring (a deliberately slow PBKDF2 derivation) on top of
  // the KMS keystore and did:web/did:webvh provisioning, so the redirect to the
  // dashboard can run past the default 5s assertion timeout.
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })

  return { passphrase, email }
}

export async function goToHistory(page: Page) {
  await page.getByRole('link', { name: 'History' }).click()
  await expect(page).toHaveURL(/#\/history/)
  await expect(
    page.getByRole('heading', { name: 'History', level: 1 })
  ).toBeVisible()
}

export async function goToStorage(page: Page) {
  await page.goto('/#/storage')
  await expect(page.getByText('Space (connected):')).toBeVisible()
}

export async function expectQuotaCard(page: Page) {
  await expect(
    page.getByRole('heading', { name: 'Storage usage', level: 6 })
  ).toBeVisible({ timeout: 15_000 })
}

/**
 * The storage-quota card, scoped by its unique "Storage usage" heading. The
 * collection display names also appear in the collections browser further down
 * the page, so quota assertions must be scoped to this card to stay
 * unambiguous.
 */
export function quotaCard(page: Page): Locator {
  return page
    .locator('.MuiPaper-root')
    .filter({ has: page.getByRole('heading', { name: 'Storage usage' }) })
}

export async function expectCollectionUsage(
  page: Page,
  collectionId: string,
  usagePattern: RegExp
) {
  // Per-collection usage renders on each collection's row in the collections
  // browser (the "Wallet Contents" / "Wallet System Collections" lists), not in
  // the aggregate "Storage usage" card. Target the row by its storage-path href
  // -- deterministic, and it sidesteps the "Verifiable Credentials" /
  // "Verifiable Credentials (Publicly Shared)" name-prefix clash. The row link
  // carries the usage amount (amount and unit render as adjacent spans with no
  // separating space, e.g. "24.0KB").
  const row = page.locator(`a[href$="/storage/collections/${collectionId}"]`)
  await expect(row).toContainText(usagePattern)
}

export async function expectHistoryEntry(page: Page, summary: string | RegExp) {
  // `.first()`: a pattern may legitimately match several entries (e.g. the
  // welcome credential seeded at signup also records a "Credential created"
  // entry); the assertion is that at least one matching entry is shown.
  await expect(page.getByText(summary).first()).toBeVisible({ timeout: 15_000 })
}

export const E2E_TEST_CREDENTIAL = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential'],
  name: 'E2E Test Credential',
  issuer: 'did:example:e2e-issuer',
  credentialSubject: { id: 'did:example:e2e-subject' }
} as const

export const E2E_TEST_CREDENTIAL_JSON = JSON.stringify(E2E_TEST_CREDENTIAL)

export async function addCredentialViaPaste(page: Page) {
  await page.getByRole('link', { name: 'Add Credential' }).click()
  await expect(page).toHaveURL(/#\/add-credential/)
  // MUI's multiline TextField renders a hidden shadow <textarea> alongside the
  // real one, so match by role/placeholder rather than the bare `textarea` tag.
  await page
    .getByRole('textbox', { name: /Paste a URL/ })
    .fill(E2E_TEST_CREDENTIAL_JSON)
  await page.getByRole('button', { name: 'Add' }).click()
  await expect(page).toHaveURL(/#\/accept-credentials/)
  await page.getByRole('button', { name: 'Accept all' }).click()
  await expect(page).toHaveURL(/#\/dashboard/)
}

export async function deleteCredential(page: Page) {
  await page.getByRole('link', { name: 'E2E Test Credential' }).click()
  await expect(page).toHaveURL(/#\/credential\//)
  await expect(page.getByRole('button', { name: 'Delete' })).toBeVisible({
    timeout: 15_000
  })
  await page.getByRole('button', { name: 'Delete' }).click()
  await expect(page).toHaveURL(/#\/dashboard/)
}

/**
 * Forces the durable login route (the programmatic remember-this-browser
 * entry) for login submits on this page. A transient session is the
 * default on a non-remembered browser, so specs exercising the standing
 * self-enrollment set this non-production seam before submitting. The flag
 * is read at submit time, so it can be set on an already-loaded page.
 *
 * @param page {Page}
 * @returns {Promise<void>}
 */
export async function forceRememberBrowser(page: Page): Promise<void> {
  await page.evaluate(() => {
    ;(
      window as unknown as { __E2E_REMEMBER_BROWSER__?: boolean }
    ).__E2E_REMEMBER_BROWSER__ = true
  })
}

/**
 * Submits the login form on an already-loaded login page WITHOUT the
 * remember-this-browser seam, so a non-remembered browser takes its default
 * durability -- the transient (public-terminal) login -- and waits for the
 * dashboard. Split from the `goto` so a caller can capture a localStorage
 * baseline on the loaded page before anything is typed.
 *
 * @param page {Page}
 * @param passphrase {string}
 * @returns {Promise<void>}
 */
export async function submitTransientLogin(
  page: Page,
  passphrase: string
): Promise<void> {
  await fillSettled(page.locator('input[type="password"]'), passphrase)
  await page.getByRole('button', { name: 'Log in', exact: true }).click()
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })
}
