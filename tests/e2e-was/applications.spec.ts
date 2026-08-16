import { test, expect, type Browser, type Page } from '@playwright/test'
import { Buffer } from 'node:buffer'
import type { IDelegatedZcap } from '@interop/data-integrity-core'
import { CapabilityAgent } from '@interop/webkms-client'
import { didKeyZcapClient } from '@interop/wallet-core/webvh'
import { fillSettled, signupViaWizard } from './helpers'

/**
 * The Applications revocation surface e2e (WAS mode), modeled on
 * `clients.spec.ts`. An app connected through App Connect lists on
 * `/applications` with its recorded grants; revoking it retires the grant
 * server-side (asserted by invoking the delegated zcap from the test runner
 * with the app's own seed-derived key, before and after), removes the app key
 * from `app-connections` (so a reconnect is a first run under a fresh
 * identity). An app whose
 * grants were signed by a since-disconnected wallet client shows as
 * orphaned -- "reconnect needed", the current-key-set rule already killed
 * its grants -- and revoking it skips the per-grant POSTs while still
 * removing the app key.
 *
 * Lesson from `clients.spec.ts`: `page.reload()` logs out (sessions are
 * in-memory), so panels are remounted by navigating `#/dashboard` and back.
 * PBKDF2 unlock derivations run several times across the ceremonies --
 * hence `test.slow()` and the generous timeouts.
 */

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

const APP = {
  name: 'Test App',
  appUrl: 'https://app.example/editor'
}
const APP_ORIGIN = 'https://app.example'
const APP_DOMAIN = 'app.example'
const APP_COLLECTION = 'test-app-data'

async function injectGetEvent(
  page: Page,
  config: {
    origin: string
    query: unknown
    challenge?: string
    domain?: string
  }
) {
  await page.addInitScript(
    (cfg: {
      origin: string
      query: unknown
      challenge?: string
      domain?: string
    }) => {
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
    },
    config
  )
}

function readResponse(page: Page) {
  return page.evaluate(
    () =>
      (window as unknown as { __E2E_CHAPI_RESPONSE__?: { value: unknown } })
        .__E2E_CHAPI_RESPONSE__
  )
}

/**
 * The App Connect VPR: DID Authentication plus a single `AppConnectQuery`
 * asking for a read/write grant on one collection (the wallet fills the
 * `controller` with the app-key subject DID).
 */
function appConnectQuery() {
  return [
    { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] },
    {
      type: 'AppConnectQuery',
      app: APP,
      capabilityQuery: [
        {
          referenceId: APP_COLLECTION,
          allowedAction: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'],
          invocationTarget: {
            type: 'https://w3id.org/byoe#private-collection',
            name: APP_COLLECTION
          }
        }
      ]
    }
  ]
}

interface AppConnectResponse {
  data: {
    verifiableCredential: unknown
    zcap: IDelegatedZcap[]
  }
}

/**
 * The single app-key credential carried by an App Connect response, with the
 * members this spec uses (the seed, for the node-side invocation).
 */
function appKeyCredential(response: AppConnectResponse) {
  const carried = response.data.verifiableCredential
  return (Array.isArray(carried) ? carried[0] : carried) as {
    credentialSubject: { id: string; origin: string; seed: string }
  }
}

/**
 * Drives one App Connect popup visit for an already-created account on the
 * given page: injects the request, logs in in-popup, approves the consent
 * panel, and returns the recorded response. Leaves the page's own dashboard
 * session logged out (the popup route reload drops the in-memory session).
 */
async function connectViaPopup(
  page: Page,
  { passphrase, challenge }: { passphrase: string; challenge: string }
): Promise<AppConnectResponse> {
  await injectGetEvent(page, {
    origin: APP_ORIGIN,
    query: appConnectQuery(),
    challenge,
    domain: APP_DOMAIN
  })

  await page.goto('/#/wallet/get')
  await page.reload()

  await fillSettled(page.locator('input[type="password"]'), passphrase)
  await page.getByRole('button', { name: 'Continue' }).click()

  await expect(
    page.getByRole('heading', { name: 'Connect Test App to storage?' })
  ).toBeVisible({ timeout: 20_000 })
  await page.getByRole('button', { name: 'Connect' }).click()

  await expect
    .poll(async () => (await readResponse(page)) !== undefined, {
      timeout: 30_000
    })
    .toBe(true)

  const recorded = (await readResponse(page)) as { value: unknown }
  return recorded.value as AppConnectResponse
}

/**
 * A ZcapClient signing as the app itself: the same seed-to-key derivation the
 * wallet and was-react use (`keyName: 'app-key'`), from the seed the app-key
 * credential carries. Lets the test invoke the delegated grant server-side
 * from the runner, standing in for the connected app.
 */
async function appZcapClient(seedBase64url: string) {
  const seed = new Uint8Array(Buffer.from(seedBase64url, 'base64url'))
  const keyAgent = await CapabilityAgent.fromSeed({
    seed,
    handle: 'freewallet-app-key',
    keyName: 'app-key'
  })
  return didKeyZcapClient({ keyAgent })
}

/**
 * Logs the page's session in through the login form (used after a popup
 * visit dropped the in-memory session).
 */
async function loginViaForm(page: Page, passphrase: string) {
  // If the caller came through /#/logout, its page navigates to the landing
  // page asynchronously; opening the login form before that lands would get
  // clobbered mid-fill. Settle on a non-logout URL first.
  await expect(page).not.toHaveURL(/#\/logout/, { timeout: 30_000 })
  await page.goto('/#/login')
  await fillSettled(page.locator('input[type="password"]'), passphrase)
  await page.getByRole('button', { name: 'Log in', exact: true }).click()
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })
}

/**
 * Opens `/applications` and waits for the given app row to appear, remounting
 * the page (dashboard and back -- never `reload()`, which logs out) until
 * background replication has pulled the popup-written credential and Login
 * activity into the local store.
 */
async function openApplicationsWithApp(page: Page, appName: string) {
  await expect(async () => {
    await page.goto('/#/dashboard')
    await page.goto('/#/applications')
    await expect(page.getByText(appName).first()).toBeVisible({
      timeout: 5_000
    })
  }).toPass({ timeout: 90_000 })
}

/**
 * Opens a fresh, cold browser context (empty IndexedDB and localStorage) to
 * stand in for a second wallet client. Callers must close the returned
 * page's context.
 */
async function coldClientPage(browser: Browser): Promise<Page> {
  const context = await browser.newContext({ baseURL: APP_URL })
  return context.newPage()
}

test.describe('The Applications revocation surface', () => {
  test('lists a connected app and retires its grant server-side on revoke', async ({
    page
  }, testInfo) => {
    test.slow()

    const { passphrase } = await signupViaWizard(page, testInfo)
    const challenge = `chal-apps-${Date.now()}-w${testInfo.workerIndex}`

    const response = await connectViaPopup(page, { passphrase, challenge })
    const credential = appKeyCredential(response)
    const grant = response.data.zcap.find(zcap =>
      zcap.invocationTarget.endsWith(`/${APP_COLLECTION}`)
    )!
    expect(grant).toBeDefined()

    // The delegated grant works server-side: the app (its seed-derived key,
    // re-derived here in the runner) reads its collection. The invocation
    // action is the HTTP verb -- WAS's closed action vocabulary -- not
    // ezcap's `read` alias.
    const zcapClient = await appZcapClient(credential.credentialSubject.seed)
    const before = await zcapClient.request({
      url: grant.invocationTarget,
      capability: grant,
      method: 'GET',
      action: 'GET'
    })
    expect(before.status).toBe(200)

    // Back in the main app, the Applications page lists the app as live: no
    // "reconnect needed" marker (its grant is signed by this still-enrolled
    // client), with the cross-pointer to the Connected wallets panel.
    await loginViaForm(page, passphrase)
    await openApplicationsWithApp(page, 'Test App')
    await expect(page.getByText('Reconnect needed')).not.toBeVisible()
    await expect(
      page.getByRole('link', { name: 'Settings > Connected wallets' })
    ).toBeVisible()

    // The detail page shows the recorded grant.
    await page.getByText('Test App', { exact: true }).click()
    await expect(
      page.getByRole('heading', { name: 'App detail: Test App' })
    ).toBeVisible()
    await expect(page.getByText(grant.invocationTarget)).toBeVisible()

    // Revoke from the detail page: the live-app confirm copy, then the toast.
    await page.getByRole('button', { name: 'Revoke App Access' }).click()
    await expect(
      page.getByText(/removes Test App's app key from your wallet/)
    ).toBeVisible()
    await page
      .getByRole('button', { name: 'Revoke access', exact: true })
      .click()
    await expect(page).toHaveURL(/#\/applications$/, { timeout: 60_000 })
    // The removal toast: the app's only grant targets its own provisioned
    // collection, so the epoch-rotation half already revoked it indivisibly
    // and the per-grant pass counts it as skipped -- the UI then reports the
    // removal rather than a fresh grant revocation.
    await expect(page.getByText(/App (access revoked|removed)/)).toBeVisible({
      timeout: 15_000
    })
    await expect(page.getByText('No connected applications yet.')).toBeVisible()

    // The delegated zcap no longer verifies server-side.
    let revokedStatus: number | undefined
    try {
      await zcapClient.request({
        url: grant.invocationTarget,
        capability: grant,
        method: 'GET',
        action: 'GET'
      })
    } catch (err) {
      revokedStatus = (err as { status?: number }).status
    }
    expect(revokedStatus).toBeDefined()
    expect(revokedStatus!).toBeGreaterThanOrEqual(400)

    // Reconnecting after the revoke is a genuine first run: the app key was
    // deleted from `app-connections` with the revocation, so the wallet mints
    // a fresh identity rather than handing back the revoked one.
    const reconnected = await connectViaPopup(page, {
      passphrase,
      challenge: `${challenge}-again`
    })
    expect(appKeyCredential(reconnected).credentialSubject.id).not.toBe(
      credential.credentialSubject.id
    )
  })

  test('an app connected from a disconnected wallet shows as orphaned', async ({
    page,
    browser
  }, testInfo) => {
    test.slow()

    // Client 1: a fresh signup.
    const { passphrase } = await signupViaWizard(page, testInfo)

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
      await expect(secondClient).toHaveURL(/#\/dashboard/, {
        timeout: 60_000
      })

      // Client 1 re-logs in (its in-memory verified-log memo predates the
      // self-enrollment); the panel then shows the self-enrolled wallet
      // (unlabeled) -- name it inline so the disconnect below can address
      // it -- and the sibling-panel cross-pointer back to the Applications
      // surface renders.
      await page.goto('/#/logout')
      await loginViaForm(page, passphrase)
      await page.goto('/#/settings')
      await expect(
        page.getByRole('link', { name: 'Applications page' })
      ).toBeVisible({ timeout: 30_000 })
      // Address the self-enrolled card as the one that is NOT this browser:
      // that filter stays stable while edit mode swaps the "Unnamed wallet"
      // text for the name field.
      const unnamedCard = page
        .getByTestId('enrolled-clients-list')
        .locator('.MuiCard-root')
        .filter({ hasNotText: 'This browser' })
      await expect(unnamedCard).toHaveCount(1, { timeout: 30_000 })
      await expect(unnamedCard.getByText('Unnamed wallet')).toBeVisible()
      await unnamedCard.getByRole('button', { name: 'Edit' }).click()
      await fillSettled(
        unnamedCard.getByLabel('Wallet name', { exact: true }),
        'Office laptop'
      )
      await unnamedCard
        .getByRole('button', { name: 'Save', exact: true })
        .click()
      await expect(page.getByText('Office laptop')).toBeVisible({
        timeout: 30_000
      })

      // Client 2 connects the app: the grant is delegated under client 2's
      // key in the account document.
      const challenge = `chal-orphan-${Date.now()}-w${testInfo.workerIndex}`
      await connectViaPopup(secondClient, { passphrase, challenge })

      // Client 1 disconnects client 2 (the full revocation cascade): every
      // grant client 2 signed stops verifying with the document edit.
      await page.goto('/#/dashboard')
      await page.goto('/#/settings')
      const officeCard = page
        .getByTestId('enrolled-clients-list')
        .locator('.MuiCard-root')
        .filter({ hasText: 'Office laptop' })
      await expect(officeCard).toBeVisible({ timeout: 30_000 })
      await officeCard
        .getByRole('button', { name: 'Disconnect', exact: true })
        .click()
      await page
        .getByRole('button', { name: 'Disconnect wallet', exact: true })
        .click()
      await expect(
        page.getByTestId('enrolled-clients-list').locator('.MuiCard-root')
      ).toHaveCount(1, { timeout: 120_000 })

      // A fresh login pulls the popup-written app credential and activity,
      // then the Applications page derives the orphaned state from the
      // updated account document.
      await page.goto('/#/logout')
      await loginViaForm(page, passphrase)
      await openApplicationsWithApp(page, 'Test App')
      await expect(page.getByText('Reconnect needed')).toBeVisible({
        timeout: 30_000
      })

      // The detail page states the reconnect path.
      await page.getByText('Test App', { exact: true }).click()
      await expect(
        page.getByRole('heading', { name: 'App detail: Test App' })
      ).toBeVisible()
      await expect(
        page.getByText(/was set up from a wallet that has since been/)
      ).toBeVisible()

      // Revoking an orphaned app: the orphaned confirm copy (no live grants
      // to revoke server-side), then the orphaned toast.
      await page.getByRole('button', { name: 'Revoke App Access' }).click()
      await expect(
        page.getByText(/already stopped working when the wallet/)
      ).toBeVisible()
      await page
        .getByRole('button', { name: 'Revoke access', exact: true })
        .click()
      await expect(page).toHaveURL(/#\/applications$/, { timeout: 60_000 })
      await expect(
        page.getByText(
          'App removed. Its storage access had already ended when its ' +
            'wallet was disconnected.'
        )
      ).toBeVisible({ timeout: 15_000 })
      await expect(
        page.getByText('No connected applications yet.')
      ).toBeVisible()
    } finally {
      await secondClient.context().close()
    }
  })
})
