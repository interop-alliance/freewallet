/**
 * FW-203's e2e: the CHAPI popup running a transient session, driven through
 * the genuinely cross-site harness in `popupHarness.ts` rather than as a
 * first-party page.
 *
 * What the popup does now is decided by the browser's own ratchet state, not
 * by the popup being a popup. A cold terminal holds no client-key record and
 * routes transient; a remembered browser whose popup cannot reach that record
 * -- Storage Access denied, or an engine offering no unpartitioned-IndexedDB
 * request at all -- falls back to the same transient session
 * (`decisions/0009-popup-denied-storage-access-goes-transient.md`). Either
 * way the visit is replica-less and in-memory, so its PARTITIONED bucket must
 * come back empty afterwards, crash included.
 *
 * The response shape is the other half: a transient session's presentation
 * holds and signs as the visit key's bare did:key (app-connect-spec
 * `decisions/0004`), and its grants chain under the generation delegation
 * rather than the Space root (`decisions/0002`), which is what makes the
 * transient client visible nowhere on the account -- the connected-wallets
 * list on the durable client never grows a row for it.
 */
import { test, expect, type Browser, type Page } from '@playwright/test'
import { fillSettled, signupViaWizard } from './helpers'
import {
  captureFrameLocalStorageKeys,
  expectNoFrameStorageResidue
} from '../shared/storageResidue'
import {
  awaitPopupResponse,
  openPopupFrame,
  servePopupHost,
  submitPopupLogin,
  WALLET_ORIGIN,
  injectPopupGetEvent,
  withoutUnpartitionedStorageAccess
} from './popupHarness'

// Chromium's Local Network Access checks block a loopback subresource
// fetched from a DIFFERENT loopback origin, which is exactly the cross-site
// shape this suite needs (`127.0.0.1` embedding `localhost`). The check
// guards against real sites reaching a user's local network; here both ends
// are the test's own dev server, so it is turned off for this file alone
// rather than for the suite.
test.use({
  launchOptions: { args: ['--disable-features=LocalNetworkAccessChecks'] }
})

const APP = { name: 'Transient App', appUrl: 'https://transient.example/app' }
const APP_ORIGIN = 'https://transient.example'
const APP_DOMAIN = 'transient.example'
const APP_COLLECTION = 'transient-app-data'

// The popup path covers a whole annex enrollment (the loud log entry, the
// generation-delegation readiness stage, the roster read) plus the grant
// mint, all against a dev-mode teaching server that re-verifies the account
// log per request. The bound is deliberately loose: it is a regression guard
// against the path degrading into minutes, not a performance target.
const POPUP_LATENCY_BOUND_MS = 120_000

interface PopupResponse {
  data: {
    holder: string
    proof: { verificationMethod: string; challenge: string; domain: string }
    zcap: Array<{
      invocationTarget: string
      controller: string
      allowedAction: string[]
      expires?: string
      parentCapability?: string
    }>
    appConnect: { firstRun: boolean }
  }
}

/**
 * The App Connect VPR: DID Authentication plus one `AppConnectQuery` asking
 * for a read/write grant over a private collection the wallet provisions.
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

/**
 * A browser holding nothing: the public terminal an app sends its user to.
 */
async function coldTerminal(browser: Browser): Promise<{
  context: Awaited<ReturnType<Browser['newContext']>>
  page: Page
}> {
  const context = await browser.newContext({ baseURL: WALLET_ORIGIN })
  const page = await context.newPage()
  return { context, page }
}

/**
 * Drives one cross-site App Connect popup visit to the consent panel, and
 * returns the popup frame, the localStorage baseline captured in its
 * partition before anything happened, and the login latency.
 */
async function popupToConsent(
  page: Page,
  { passphrase, challenge }: { passphrase: string; challenge: string }
) {
  await servePopupHost({ page })
  await injectPopupGetEvent({
    page,
    origin: APP_ORIGIN,
    query: appConnectQuery(),
    challenge,
    domain: APP_DOMAIN
  })
  const frame = await openPopupFrame({ page })
  const baseline = await captureFrameLocalStorageKeys({ frame })
  const latencyMs = await submitPopupLogin({ frame, passphrase })
  await expect(
    frame.getByRole('heading', { name: `Connect ${APP.name} to storage?` })
  ).toBeVisible({ timeout: 30_000 })
  return { frame, baseline, latencyMs }
}

test.describe.serial('the CHAPI popup on a transient session', () => {
  // The popup path is ceremony-heavy (a signup fixture, then an annex
  // enrollment and a grant mint per visit) against a dev-mode teaching
  // server, so the default budget is far too small here.
  test.setTimeout(300_000)

  let passphrase: string

  test.beforeAll(async ({ browser }, testInfo) => {
    // The account fixture: the DEFAULT credential-anchored signup, which is
    // the account an app-first user actually arrives with -- no durable
    // client anywhere, the annex generation and the sibling-carrying
    // standing record established by the signup itself. The setup context
    // is discarded; every popup test below brings its own browser.
    const context = await browser.newContext({ baseURL: WALLET_ORIGIN })
    try {
      const page = await context.newPage()
      const user = await signupViaWizard(page, testInfo, {
        rememberBrowser: false
      })
      passphrase = user.passphrase
    } finally {
      await context.close()
    }
  })

  test('a cold terminal connects an app and answers as the visit key', async ({
    browser
  }) => {
    const { context, page } = await coldTerminal(browser)
    try {
      const challenge = `chal-popup-transient-${Date.now()}`
      const { frame, latencyMs } = await popupToConsent(page, {
        passphrase,
        challenge
      })
      await frame.getByRole('button', { name: 'Connect' }).click()
      const response = (await awaitPopupResponse({ frame })) as PopupResponse

      // The DIDAuth proof is bound to the request, and BOTH the holder and
      // the verification method are the visit key's bare did:key: the
      // `<clientAnnexDid>#<vm>` form belongs to WAS invocations alone,
      // and an app-side loader has to be able to resolve what it reads here.
      expect(response.data.proof.challenge).toBe(challenge)
      expect(response.data.proof.domain).toBe(APP_DOMAIN)
      expect(response.data.holder).toMatch(/^did:key:z6Mk/)
      expect(response.data.proof.verificationMethod).toMatch(
        new RegExp(`^${response.data.holder}#`)
      )
      expect(response.data.holder).not.toContain('did:webvh:')
      expect(response.data.proof.verificationMethod).not.toContain('did:webvh:')

      // The grant: delegated over the app's collection and chaining one
      // deeper than a durable session's would -- its parent is the
      // generation delegation, never the Space root, because the signing key
      // is an annex key the account document does not list.
      const grant = response.data.zcap.find(zcap =>
        zcap.invocationTarget.endsWith(`/${APP_COLLECTION}`)
      )
      expect(grant, 'the app collection grant').toBeDefined()
      expect(grant!.allowedAction).toContain('PUT')
      expect(grant!.parentCapability).toBeDefined()
      expect(grant!.parentCapability).not.toMatch(/^urn:zcap:root:/)
      // Clamped to the parent generation delegation, so it can never outlive
      // the annex membership it hangs from.
      expect(grant!.expires).toBeDefined()
      expect(Date.parse(grant!.expires!)).toBeGreaterThan(Date.now())

      expect(
        latencyMs,
        `the popup login-to-consent path took ${latencyMs}ms`
      ).toBeLessThan(POPUP_LATENCY_BOUND_MS)
    } finally {
      await context.close()
    }
  })

  test('the popup partition holds nothing after the visit, crash included', async ({
    browser
  }) => {
    const { context, page } = await coldTerminal(browser)
    try {
      const { frame, baseline } = await popupToConsent(page, {
        passphrase,
        challenge: `chal-popup-residue-${Date.now()}`
      })
      await frame.getByRole('button', { name: 'Connect' }).click()
      await awaitPopupResponse({ frame })

      // The simulated crash: the popup window dies with no teardown of its
      // own. The context stays live, so a fresh document in the SAME
      // partition can be asked what the bucket still holds.
      await page.close()
      const after = await context.newPage()
      await servePopupHost({ page: after })
      const afterFrame = await openPopupFrame({ page: after })
      await expectNoFrameStorageResidue({
        frame: afterFrame,
        baselineLocalStorageKeys: baseline
      })
    } finally {
      await context.close()
    }
  })

  test('a remembered browser denied Storage Access falls back to transient', async ({
    browser
  }, testInfo) => {
    // The engine default `decisions/0009` settles: on Safari and Firefox the
    // handle extension does not exist at all, so a remembered browser's popup
    // can never reach its first-party client-key record. Removing
    // `requestStorageAccess` is how a Chromium run exercises that rather than
    // assuming it.
    const context = await browser.newContext({ baseURL: WALLET_ORIGIN })
    try {
      const page = await context.newPage()
      // This browser IS a remembered durable client of its own account.
      const durable = await signupViaWizard(page, testInfo)

      await withoutUnpartitionedStorageAccess({ page })
      const { frame, baseline } = await popupToConsent(page, {
        passphrase: durable.passphrase,
        challenge: `chal-popup-denied-${Date.now()}`
      })
      await frame.getByRole('button', { name: 'Connect' }).click()
      const response = (await awaitPopupResponse({ frame })) as PopupResponse

      // It connected -- no refusal screen, on any engine -- and it answered
      // as a per-visit key rather than as the durable client standing on the
      // same browser.
      expect(response.data.holder).toMatch(/^did:key:z6Mk/)
      expect(response.data.appConnect.firstRun).toBe(true)

      // The durable client's own first-party database is untouched by any of
      // this; what has to be clean is the popup's partition.
      await expectNoFrameStorageResidue({
        frame,
        baselineLocalStorageKeys: baseline
      })

      // And the transient client is nowhere on the account: the annex holds
      // per-visit membership, the account document holds enrolled clients,
      // and only the latter feeds this list.
      await page.goto('/#/login')
      await fillSettled(
        page.locator('input[type="password"]'),
        durable.passphrase
      )
      await page.getByRole('button', { name: 'Log in', exact: true }).click()
      await expect(page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })
      await page.goto('/#/settings')
      await expect(page.getByText('Connected wallets')).toBeVisible({
        timeout: 30_000
      })
      await expect(
        page.getByTestId('enrolled-clients-list').locator('.MuiCard-root')
      ).toHaveCount(1, { timeout: 30_000 })
      await expect(
        page.getByText('This browser', { exact: true })
      ).toBeVisible()

      // The aftermath the durable client DOES see: the app the popup
      // connected, on the Applications page.
      await expect(async () => {
        await page.goto('/#/dashboard')
        await page.goto('/#/applications')
        await expect(page.getByText(APP.name).first()).toBeVisible({
          timeout: 5_000
        })
      }).toPass({ timeout: 90_000 })
    } finally {
      await context.close()
    }
  })
})
