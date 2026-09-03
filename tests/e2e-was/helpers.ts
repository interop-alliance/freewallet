import { Buffer } from 'node:buffer'
import {
  expect,
  type Locator,
  type Page,
  type TestInfo
} from '@playwright/test'
import { generateParallelDidWeb } from '@interop/did-method-webvh'
import { CapabilityAgent } from '@interop/webkms-client'
import { didKeyZcapClient } from '@interop/wallet-core/webvh'

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
    // non-remembered browser, so the remembered fixtures every other suite
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
 * Waits for the login-time pass chain (`session.registryReady`) and the annex
 * GC sweep forked off its tail to settle, through the non-production seam the
 * auth store publishes. Navigation to the dashboard waits on storage
 * provisioning alone, so a fixture that closes its context (or starts a
 * second visit) the moment the dashboard renders aborts those passes wherever
 * they happen to be, and which of them landed decides what the account looks
 * like afterwards.
 *
 * Call it in any fixture that builds a remembered session and then hands it
 * to something else. Neither promise rejects, so this resolves whether the
 * passes succeeded or warned and skipped.
 *
 * @param page {Page}   a page holding a logged-in session
 * @param [timeoutMs] {number}   how long to wait for the chain to settle
 * @returns {Promise<number>}   how long the wait actually took, in
 *   milliseconds -- a fixture can record it to show the chain was still in
 *   flight rather than already settled
 */
export async function awaitLoginChain(
  page: Page,
  timeoutMs = 120_000
): Promise<number> {
  return await page.evaluate(async (budgetMs: number) => {
    const startedAt = Date.now()
    const seam = () =>
      (
        window as unknown as {
          __E2E_LOGIN_CHAIN_SETTLED__?: () => Promise<void>
        }
      ).__E2E_LOGIN_CHAIN_SETTLED__
    const deadline = Date.now() + budgetMs
    while (!seam()) {
      if (Date.now() > deadline) {
        throw new Error(
          'No session published __E2E_LOGIN_CHAIN_SETTLED__ on this page.'
        )
      }
      await new Promise(resolve => setTimeout(resolve, 50))
    }
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      await Promise.race([
        seam()!(),
        new Promise((_resolve, reject) => {
          timer = setTimeout(
            () =>
              reject(
                new Error(
                  `The login-time pass chain did not settle in ${budgetMs}ms.`
                )
              ),
            Math.max(0, deadline - Date.now())
          )
        })
      ])
    } finally {
      clearTimeout(timer)
    }
    return Date.now() - startedAt
  }, timeoutMs)
}

/**
 * Forces the remembered login route (the programmatic remember-this-browser
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
 * login route -- the transient (public-terminal) login -- and waits for the
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

/**
 * A ZcapClient signing as a connected app: the same seed-to-key derivation the
 * wallet and was-react use (`keyName: 'app-key'`), from the seed the app-key
 * credential carries. Lets a test invoke a delegated grant from the runner,
 * standing in for the app itself.
 *
 * @param seedBase64url {string}   `credentialSubject.seed`, base64url-no-pad
 * @returns {Promise<ReturnType<typeof didKeyZcapClient>>}
 */
export async function appZcapClient(seedBase64url: string) {
  const seed = new Uint8Array(Buffer.from(seedBase64url, 'base64url'))
  const keyAgent = await CapabilityAgent.fromSeed({
    seed,
    handle: 'freewallet-app-key',
    keyName: 'app-key'
  })
  return didKeyZcapClient({ keyAgent })
}

/**
 * Polls the world-readable did:web projection until it IS the projection of
 * the resolved did:webvh document: the served `did.json` body deep-equals
 * `generateParallelDidWeb(doc.id, doc)`, the same derivation the wallet
 * writes. Comparing the whole document rather than a summary of it is what
 * catches a projection listing the right keys under the wrong relations, or
 * carrying a member the log has since dropped.
 *
 * The projection is republished by a whole-document publish, not by the
 * ladder-signed entries a credential-only ceremony makes, so the mender is
 * the next transient visit's `ensureDidWebProjection` -- best-effort and not
 * awaited by the login, hence the poll.
 *
 * @param options {object}
 * @param options.page {Page}   any page, for its request context
 * @param options.logUrl {string}   the `id/did.jsonl` URL Settings links
 * @param options.doc {unknown}   the resolved did:webvh document to match;
 *   its `id` is the DID the projection derives from
 * @param [options.timeout] {number}
 * @returns {Promise<void>}
 */
export async function expectDidWebProjectionMatches({
  page,
  logUrl,
  doc,
  timeout = 60_000
}: {
  page: Page
  logUrl: string
  doc: unknown
  timeout?: number
}): Promise<void> {
  const didJsonUrl = logUrl.replace(/\/did\.jsonl$/, '/did.json')
  // Round-tripped through JSON so the comparison runs in the form the server
  // stores and serves: a member whose value is `undefined` disappears on
  // both sides rather than reading as a difference.
  const expected = JSON.parse(
    JSON.stringify(
      generateParallelDidWeb(
        (doc as { id: string }).id,
        doc as Parameters<typeof generateParallelDidWeb>[1]
      )
    )
  ) as unknown
  await expect(async () => {
    const response = await page.request.get(didJsonUrl)
    expect(response.status()).toBe(200)
    expect((await response.json()) as unknown).toEqual(expected)
  }).toPass({ timeout })
}
