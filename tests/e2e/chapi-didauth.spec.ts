import { test, expect, type Page } from '@playwright/test'

/**
 * E2E coverage for the CHAPI `/wallet/get` DID Authentication flows.
 *
 * A CHAPI popup normally receives its request event through the CHAPI mediator
 * handshake, which no automated browser can perform. `WalletGetPage` therefore
 * honors a non-production test seam: an event injected on
 * `window.__E2E_CHAPI_GET_EVENT__` (whose `respondWith` records the response on
 * `window.__E2E_CHAPI_RESPONSE__`) is used in place of `receiveCredentialEvent`.
 * These specs drive that seam in real Chromium, so the DID-Auth VP is signed by
 * the wallet's actual did:key just as it would be in production.
 */

type InjectedResponse = { value: unknown } | undefined

interface GetEventConfig {
  origin: string
  query: unknown
  challenge?: string
  domain?: string
}

/**
 * Registers an init script that injects a canned CHAPI get event before the app
 * loads. Runs on every subsequent document load in this context (survives the
 * reload used to mount the popup fresh).
 */
async function injectGetEvent(page: Page, config: GetEventConfig) {
  await page.addInitScript((cfg: GetEventConfig) => {
    const win = window as unknown as {
      __E2E_CHAPI_GET_EVENT__?: unknown
      __E2E_CHAPI_RESPONSE__?: { value: unknown }
    }
    win.__E2E_CHAPI_RESPONSE__ = undefined
    win.__E2E_CHAPI_GET_EVENT__ = {
      credentialRequestOrigin: cfg.origin,
      credentialRequestOptions: {
        web: {
          VerifiablePresentation: {
            query: cfg.query,
            challenge: cfg.challenge,
            domain: cfg.domain
          }
        }
      },
      respondWith(promise: Promise<unknown>) {
        Promise.resolve(promise).then(value => {
          win.__E2E_CHAPI_RESPONSE__ = { value: value ?? null }
        })
      }
    }
  }, config)
}

/**
 * Loads the /wallet/get popup fresh (reload re-runs the init script that sets
 * the injected event).
 */
async function openGetPopup(page: Page) {
  await page.goto('/#/wallet/get')
  await page.reload()
}

/**
 * Reads the recorded CHAPI response (undefined until the popup responds).
 */
function readResponse(page: Page): Promise<InjectedResponse> {
  return page.evaluate(
    () =>
      (window as unknown as { __E2E_CHAPI_RESPONSE__?: { value: unknown } })
        .__E2E_CHAPI_RESPONSE__
  )
}

/**
 * Creates a wallet (in local IndexedDB mode) so the popup's login form can
 * authenticate. Leaves the app on the dashboard.
 */
async function createWallet(page: Page, passphrase: string, email: string) {
  await page.goto('/#/signup')
  await page.locator('input[type="password"]').fill(passphrase)
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
  await page.getByRole('button', { name: 'Next' }).click()
  await page.locator('input[type="email"]').fill(email)
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
  await page.getByRole('button', { name: 'Create Wallet' }).click()
  await expect(page).toHaveURL(/#\/dashboard/)
}

test.describe('CHAPI DID Authentication', () => {
  test('DID-Auth-only request returns a signed VP bound to challenge/domain', async ({
    page
  }, testInfo) => {
    const token = `${Date.now()}-w${testInfo.workerIndex}`
    const passphrase = `Str0ngpass-${token}-Aa1!`
    const email = `e2e-${token}@example.com`
    const origin = 'https://verifier.example'
    const challenge = `chal-${token}`

    await createWallet(page, passphrase, email)

    await injectGetEvent(page, {
      origin,
      query: [
        { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] }
      ],
      challenge,
      domain: 'verifier.example'
    })
    await openGetPopup(page)

    // DID-Auth title and requesting origin are shown.
    await expect(
      page.getByRole('heading', { name: 'DID Authentication request' })
    ).toBeVisible()
    await expect(page.getByText(origin, { exact: true })).toBeVisible()

    // Log in inside the popup.
    await page.locator('input[type="password"]').fill(passphrase)
    await page.getByRole('button', { name: 'Continue' }).click()

    // Consent screen appears; approve.
    await expect(
      page.getByText(/is requesting DID Authentication/)
    ).toBeVisible()
    await page.getByRole('button', { name: 'Continue' }).click()

    await expect
      .poll(async () => (await readResponse(page)) !== undefined, {
        timeout: 15000
      })
      .toBe(true)

    const response = (await readResponse(page)) as { value: unknown }
    const payload = response.value as {
      dataType: string
      data: {
        holder: string
        verifiableCredential?: unknown
        proof: {
          proofPurpose: string
          challenge: string
          domain: string
        }
      }
    }

    expect(payload.dataType).toBe('VerifiablePresentation')
    expect(payload.data.holder).toMatch(/^did:key:/)
    expect(payload.data.verifiableCredential).toBeUndefined()
    expect(payload.data.proof.proofPurpose).toBe('authentication')
    expect(payload.data.proof.challenge).toBe(challenge)
    expect(payload.data.proof.domain).toBe('verifier.example')
  })

  test('domain mismatch is blocked before login and cancelling returns null', async ({
    page
  }) => {
    await injectGetEvent(page, {
      origin: 'https://verifier.example',
      query: [{ type: 'DIDAuthentication' }],
      challenge: 'chal-mismatch',
      domain: 'attacker.example'
    })
    await openGetPopup(page)

    // No login form -- the request is rejected up front.
    await expect(page.getByText(/match where it came from/)).toBeVisible()
    await expect(page.locator('input[type="password"]')).toHaveCount(0)

    await page.getByRole('button', { name: 'Cancel' }).click()
    await expect
      .poll(async () => (await readResponse(page)) !== undefined)
      .toBe(true)
    const response = (await readResponse(page)) as { value: unknown }
    expect(response.value).toBeNull()
  })

  test('unsupported DID method is blocked before login', async ({ page }) => {
    await injectGetEvent(page, {
      origin: 'https://verifier.example',
      query: [
        { type: 'DIDAuthentication', acceptedMethods: [{ method: 'web' }] }
      ],
      challenge: 'chal-unsupported',
      domain: 'verifier.example'
    })
    await openGetPopup(page)

    await expect(page.getByText(/DID method this wallet/)).toBeVisible()
    await expect(page.locator('input[type="password"]')).toHaveCount(0)
  })
})
