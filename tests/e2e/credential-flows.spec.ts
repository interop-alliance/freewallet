import { test, expect, type Page } from '@playwright/test'

/**
 * End-to-end coverage for the four core credential flows -- add, accept,
 * delete, and verify -- against the local (IndexedDB) storage backend. No WAS
 * server is required: a guest session provides an authenticated wallet whose
 * data lives entirely in the browser. All external network is blocked so the
 * flows (and background credential verification) run fully offline and
 * deterministically.
 */

/**
 * A distinct credential pasted through the manual import form. Its unique name
 * lets the add flow assert a brand-new card, separate from the seeded welcome
 * credential.
 */
const pastedCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  name: 'E2E Pasted Credential',
  credentialSubject: {
    description: 'Imported by pasting credential JSON.'
  },
  issuer: 'did:web:example.com'
}

/**
 * A credential served over the network for the accept-from-URL flow. The
 * wallet fetches remote credential URLs through a CORS proxy, which the test
 * intercepts.
 */
const remoteCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  name: 'E2E Remote Credential',
  credentialSubject: {
    description: 'Fetched from a remote URL.'
  },
  issuer: 'did:web:example.com'
}

/**
 * The welcome credential seeded into every fresh session. Used as the target
 * for the delete and verify flows.
 */
const WELCOME_TITLE = 'Your First Credential'

const ADD_PLACEHOLDER = 'Paste a URL or full credential JSON.'

/**
 * Aborts every request to a non-local host so the wallet flows run fully
 * offline. Credential verification and best-effort registrations then fail
 * fast and deterministically instead of hanging on (or depending on) real
 * network.
 */
async function blockExternalNetwork(page: Page) {
  await page.route(
    url => url.hostname !== 'localhost' && url.hostname !== '127.0.0.1',
    route => route.abort()
  )
}

/**
 * Logs in as a guest and lands on the dashboard. Guest sessions are fully
 * local and seed the welcome credential, so no WAS server is involved.
 */
async function loginAsGuest(page: Page) {
  await page.goto('/#/guest-login')
  await page.getByRole('button', { name: 'Guest Mode Log In' }).click()
  await expect(page).toHaveURL(/#\/dashboard/)
}

test.describe('Credential flows', () => {
  test.beforeEach(async ({ page }) => {
    await blockExternalNetwork(page)
    await loginAsGuest(page)
  })

  test('add: pasting credential JSON stores it and shows it on the dashboard', async ({
    page
  }) => {
    await page.getByRole('link', { name: 'Add Credential' }).click()
    await expect(page).toHaveURL(/#\/add-credential/)

    await page
      .getByPlaceholder(ADD_PLACEHOLDER)
      .fill(JSON.stringify(pastedCredential))
    await page.getByRole('button', { name: 'Add', exact: true }).click()

    // The add form funnels valid input into the accept confirmation screen.
    await expect(page).toHaveURL(/#\/accept-credentials/)
    await expect(page.getByText('E2E Pasted Credential')).toBeVisible()

    await page.getByRole('button', { name: 'Accept all' }).click()
    await expect(page).toHaveURL(/#\/dashboard/)
    await expect(page.getByText('E2E Pasted Credential')).toBeVisible()
  })

  test('accept: importing from a URL stores the fetched credential', async ({
    page
  }) => {
    // The wallet fetches remote credential URLs through a CORS proxy; serve
    // the credential JSON so no real network is needed. Registered here so it
    // takes precedence over the external-network block from beforeEach.
    await page.route(
      url => url.hostname === 'corsproxy.io',
      route =>
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: {
            'access-control-allow-origin': '*',
            'access-control-allow-headers': '*',
            'access-control-allow-methods': '*'
          },
          body: JSON.stringify(remoteCredential)
        })
    )

    await page.goto('/#/add-credential')
    await page
      .getByPlaceholder(ADD_PLACEHOLDER)
      .fill('https://issuer.example/credential.json')
    await page.getByRole('button', { name: 'Add', exact: true }).click()

    await expect(page).toHaveURL(/#\/accept-credentials/)
    await expect(page.getByText('E2E Remote Credential')).toBeVisible()

    await page.getByRole('button', { name: 'Accept all' }).click()
    await expect(page).toHaveURL(/#\/dashboard/)
    await expect(page.getByText('E2E Remote Credential')).toBeVisible()
  })

  test('delete: removing a credential clears it from the dashboard', async ({
    page
  }) => {
    await expect(page.getByText(WELCOME_TITLE)).toBeVisible()

    await page.getByText(WELCOME_TITLE).click()
    await expect(page).toHaveURL(/#\/credential\//)

    // A freshly stored credential has no public link, so delete is immediate
    // (no confirmation dialog) and returns to the dashboard.
    await page.getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page).toHaveURL(/#\/dashboard/)
    await expect(page.getByText(WELCOME_TITLE)).toHaveCount(0)
  })

  test('verify: opening a credential runs verification to a terminal state', async ({
    page
  }) => {
    await page.getByText(WELCOME_TITLE).click()
    await expect(page).toHaveURL(/#\/credential\//)

    // Verification runs automatically on the detail page. With the network
    // blocked it always reaches a terminal summary; assert that any terminal
    // outcome is reached rather than a specific (network-dependent) status.
    const summary = page.getByText(
      /verified successfully|verification warnings|cryptographic proof is still valid/
    )
    await expect(summary).toBeVisible({ timeout: 20000 })
  })
})
