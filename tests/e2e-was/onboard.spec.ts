import { test, expect, type Page } from '@playwright/test'
import {
  completeEnrollmentCore,
  encodeOnboardingResponse,
  EnrollmentPendingError,
  mintEnrollmentRequest
} from '@interop/wallet-core/enrollment'
import {
  walletOnboardingRequestOf,
  type IVPRQuery
} from '@interop/wallet-core/request'
import { signupViaWizard } from './helpers'

/**
 * The wallet-onboarding rendezvous e2e (WAS mode): the inviter's half of the
 * enrollment ceremony carried over an ephemeral exchange instead of a pasted
 * connect code. Settings mints an exchange holding a `WalletOnboardingQuery`
 * and shows its interaction URL (the QR payload); a malformed response
 * envelope is refused with the generate-a-new-code remedy; and a scripted
 * enrollee -- running in the test's own node context, standing in for the
 * camera-holding wallet -- reads the account pointer out of the stored VPR,
 * mints its key set, and posts the response envelope back. The inviter's
 * consent panel then drives the real `approveEnrollment`, and the enrollee
 * completes the ceremony against the published log.
 *
 * PBKDF2 unlock derivations and the two did:webvh log entries run on top of a
 * full signup -- hence `test.slow()` and the generous timeouts. The card polls
 * the exchange every three seconds, so every assertion that waits on a
 * round trip allows several poll ticks.
 */

/**
 * The suffix `createOnboardingExchange` appends to an exchange URL to make the
 * interaction URL the QR code carries.
 */
const INTERACTION_SUFFIX = '/protocols?iuv=1'

/**
 * Sleeps for `delayMs`, so the enrollee's completion retries space themselves
 * out rather than hammering the log.
 *
 * @param options {object}
 * @param options.delayMs {number}
 * @returns {Promise<void>}
 */
async function delay({ delayMs }: { delayMs: number }): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, delayMs))
}

/**
 * Retries `completeEnrollmentCore` until the enrollment is visible from the
 * published log, treating only `EnrollmentPendingError` as "not yet". Gives
 * up (rethrowing) once the deadline passes.
 *
 * @param options {object}   the `completeEnrollmentCore` options, forwarded
 *   verbatim on every attempt
 * @returns {Promise<Awaited<ReturnType<typeof completeEnrollmentCore>>>}
 */
async function completeEnrollmentWithRetry(
  options: Parameters<typeof completeEnrollmentCore>[0]
): Promise<Awaited<ReturnType<typeof completeEnrollmentCore>>> {
  const deadline = Date.now() + 60_000
  for (;;) {
    try {
      return await completeEnrollmentCore(options)
    } catch (err) {
      if (!(err instanceof EnrollmentPendingError) || Date.now() >= deadline) {
        throw err
      }
      await delay({ delayMs: 2000 })
    }
  }
}

/**
 * Reads the interaction URL the invite card displays (a monospace Typography,
 * so its text rather than an input value), waiting for the card to render it.
 *
 * @param page {Page}
 * @returns {Promise<string>}
 */
async function readInteractionUrl(page: Page): Promise<string> {
  const urlText = page.getByTestId('onboard-invite-url')
  await expect(urlText).toBeVisible({ timeout: 30_000 })
  return (await urlText.textContent())!.trim()
}

/**
 * The exchange URL behind an interaction URL: the same URL without the
 * interaction suffix.
 *
 * @param options {object}
 * @param options.interactionUrl {string}
 * @returns {string}
 */
function exchangeUrlOf({ interactionUrl }: { interactionUrl: string }): string {
  expect(interactionUrl.endsWith(INTERACTION_SUFFIX)).toBe(true)
  return interactionUrl.slice(0, -INTERACTION_SUFFIX.length)
}

test.describe('wallet onboarding over rendezvous', () => {
  test('refuses a malformed envelope, then onboards a scripted wallet', async ({
    page
  }, testInfo) => {
    test.slow()

    await signupViaWizard(page, testInfo)
    await page.goto('/#/settings')
    await expect(page.getByText('Connected wallets')).toBeVisible()
    await page.getByRole('button', { name: 'Connect another wallet' }).click()
    await expect(page.getByTestId('onboard-invite-card')).toBeVisible({
      timeout: 30_000
    })

    const firstInteractionUrl = await readInteractionUrl(page)
    const firstExchangeUrl = exchangeUrlOf({
      interactionUrl: firstInteractionUrl
    })

    // A response the envelope parser refuses (an unsupported version) flips
    // the card to its invalid-response state. The remedy for every malformed
    // envelope is the same: mint a fresh exchange.
    await page.request.post(firstExchangeUrl, {
      data: { walletOnboarding: { v: 999 } }
    })
    await expect(
      page.getByText('Generate a new code and try again', { exact: false })
    ).toBeVisible({ timeout: 30_000 })

    await page.getByRole('button', { name: 'Generate new code' }).click()
    // The fresh exchange is a different URL -- the refused one is abandoned,
    // not reused.
    await expect(page.getByTestId('onboard-invite-url')).not.toHaveText(
      firstInteractionUrl,
      { timeout: 30_000 }
    )
    const secondInteractionUrl = await readInteractionUrl(page)
    expect(secondInteractionUrl).not.toBe(firstInteractionUrl)
    const exchangeUrl = exchangeUrlOf({ interactionUrl: secondInteractionUrl })

    // The scripted enrollee: begin the exchange (an empty JSON body) and read
    // the account pointer out of the stored `WalletOnboardingQuery`. The
    // stored request arrives wrapped as a VC-API exchange reply
    // (`{ verifiablePresentationRequest }`).
    const beginResponse = await page.request.post(exchangeUrl, { data: {} })
    expect(beginResponse.ok()).toBe(true)
    const beginBody = (await beginResponse.json()) as {
      verifiablePresentationRequest?: { query?: IVPRQuery[] }
    }
    const onboarding = walletOnboardingRequestOf({
      queries: beginBody.verifiablePresentationRequest?.query ?? []
    })
    expect(onboarding).not.toBeNull()
    const pointer = {
      did: onboarding!.did,
      spaceId: onboarding!.spaceId,
      host: onboarding!.host
    }

    // Only public halves travel: the enrollee mints its whole key set locally
    // and posts the connect code back inside the response envelope.
    const minted = await mintEnrollmentRequest()
    const postResponse = await page.request.post(exchangeUrl, {
      data: encodeOnboardingResponse({
        code: minted.code,
        label: 'Pixel phone'
      })
    })
    expect(postResponse.ok()).toBe(true)

    // The inviter's next poll swaps the card for the consent panel, showing
    // the fingerprint to compare and the label the enrollee suggested.
    const consentPanel = page.getByTestId('onboard-consent-panel')
    await expect(consentPanel).toBeVisible({ timeout: 30_000 })
    await expect(consentPanel).toContainText(minted.clientDid)
    await expect(page.getByTestId('onboard-label-input')).toHaveValue(
      'Pixel phone'
    )

    // Approval runs the real ceremony: the user key wrapped into the roster
    // first, then the two did:webvh log entries.
    await page.getByRole('button', { name: 'Approve', exact: true }).click()
    await expect(
      page.getByText('The wallet was onboarded', { exact: false })
    ).toBeVisible({ timeout: 60_000 })
    await expect(page.getByText('Pixel phone')).toBeVisible({ timeout: 30_000 })

    // The enrollee completes against the published log: it verifies the
    // enrollment, then performs its first roster read with its freshly
    // published `<did:webvh>#<multibase>` key to obtain the user key. The
    // retry loop covers the window in which the add entry is not visible yet.
    const completed = await completeEnrollmentWithRetry({
      clientSeed: minted.clientSeed,
      webvhUpdateKeys: minted.webvhUpdateKeys,
      pointer
    })
    expect(completed.userKey).toBeTruthy()
    expect(typeof completed.latestEpochId).toBe('string')
    expect(completed.latestEpochId.length).toBeGreaterThan(0)
  })
})
