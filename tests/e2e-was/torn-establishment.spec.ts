/**
 * The torn credential-anchored establishment e2e (WAS mode): the signup is
 * killed between the record re-bind (and the registry write) and the Space
 * controller promotion (the `__E2E_TEAR_ESTABLISHMENT_BEFORE_PROMOTION__`
 * seam), leaving a record that names the account DID on a Space still
 * controlled by the bootstrap did:key. The next transient login meets that
 * state as a delegated roster read the server refuses; the shared mend
 * ceremony's promotion arm completes the promotion under the ladder VM's
 * bare did:key, retries the read, and the login lands on the dashboard.
 *
 * The ceremony event channel is the assertion surface for both halves: the
 * torn run's stages up to the re-bind, with no promotion stage, and the
 * mender event the next login's promotion arm emits.
 *
 * The second block tears by tab death rather than a seam: it holds the
 * annex generation's first write once the `account-log-read` stage lands,
 * closes the page, and reads the torn-run signature (stages, no outcome) off
 * the dev-log file. The next credential-only login's heal re-runs the whole
 * establishment, so the file then carries the establishment mender's event
 * and the converging run's outcome under a run id of its own.
 */
import { type Browser, type Page, type Route } from '@playwright/test'
import type { CredentialAnchoredEstablishmentStageName } from '@interop/wallet-core/clientAnnex'
import { test, expect } from '../shared/ceremonyEvents'
import {
  CEREMONY_STAGE_MSG,
  outcomeEvents,
  stageEvents
} from '../shared/ceremonyEventLines'
import { fillSettled, submitTransientLogin, testUser } from './helpers'

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'
// Matches `playwright.was.config.ts` (WAS_PORT).
const WAS_URL = 'http://localhost:3002'

/**
 * A fresh, cold browser context (empty IndexedDB and localStorage). Callers
 * must close the returned page's context.
 *
 * @param browser {Browser}
 * @returns {Promise<Page>}
 */
async function coldPage(browser: Browser): Promise<Page> {
  const context = await browser.newContext({ baseURL: APP_URL })
  return context.newPage()
}

test.describe.serial('Torn establishment (before the promotion)', () => {
  let passphrase: string
  let email: string

  test('the signup tears between the re-bind and the promotion', async ({
    page,
    ceremonyEvents
  }, testInfo) => {
    test.slow()
    ;({ passphrase, email } = testUser(testInfo))

    await page.goto('/#/signup')
    // The tear seam: the establishment's pre-promotion hook throws right
    // after the registry write, so the ceremony dies with the record
    // re-bound and the Space still under the bootstrap key.
    await page.evaluate(() => {
      ;(
        window as unknown as {
          __E2E_TEAR_ESTABLISHMENT_BEFORE_PROMOTION__?: boolean
        }
      ).__E2E_TEAR_ESTABLISHMENT_BEFORE_PROMOTION__ = true
    })
    await fillSettled(page.locator('input[type="password"]'), passphrase)
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled({
      timeout: 15_000
    })
    await page.getByRole('button', { name: 'Next' }).click()
    await page.locator('input[type="email"]').fill(email)
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
    await page.getByRole('button', { name: 'Create Wallet' }).click()

    // The hook's throw fails the establishment, and the page surfaces its
    // generic failure copy; the account log and record exist server-side,
    // the promotion never ran.
    await expect(
      page.getByText('Could not finish setting up your wallet')
    ).toBeVisible({ timeout: 60_000 })
    expect(page.url()).not.toMatch(/dashboard/)

    // The establishment reached the re-bind and stopped there: the hook's
    // throw is the run's `failed` outcome, and no promotion stage fired.
    await ceremonyEvents.waitForStage(
      'credential-anchored-genesis',
      'record-rebind'
    )
    const outcome = await ceremonyEvents.waitForOutcome(
      'credential-anchored-genesis',
      'failed'
    )
    const promoted = stageEvents({
      lines: await ceremonyEvents.lines(),
      stage: 'controller-promotion',
      run: outcome.data.run
    })
    expect(promoted).toEqual([])
  })

  test('a transient login mends the promotion and enters', async ({
    browser,
    ceremonyEvents
  }) => {
    test.slow()
    // A cold terminal with nothing but the passphrase. The delegated roster
    // read fails on the unpromoted Space; the mend ceremony's promotion arm
    // completes the promotion and the retried read carries the login
    // through to the dashboard.
    const page = await coldPage(browser)
    try {
      await ceremonyEvents.tag(page.context())
      await page.goto('/#/login')
      await submitTransientLogin(page, passphrase)
      // The mend's promotion arm is what converged the controller.
      await ceremonyEvents.expectMender(
        'space-controller-is-the-account-did',
        'clean'
      )
      await ceremonyEvents.expectNoFailedMenders({ page })
    } finally {
      await page.context().close()
    }
  })
})

test.describe
  .serial('Torn establishment (tab death before the annex generation)', () => {
  let passphrase: string
  let email: string
  let tornRun: unknown

  test('the tab dies between the account-log read and the annex generation', async ({
    page,
    ceremonyEvents
  }, testInfo) => {
    test.slow()
    ;({ passphrase, email } = testUser(testInfo))

    // Hold the annex generation's first write: the first non-GET request
    // once the page's own ring buffer holds the `account-log-read` stage.
    // The account log then resolves but its document points at no
    // generation, the tear whose mender re-runs the whole establishment
    // rather than re-binding the record. The page stays alive, with that
    // request pending, until the stage line has reached the dev-log file on
    // the sink's batch timer.
    let markHeld!: (route: Route) => void
    const held = new Promise<Route>(resolve => {
      markHeld = resolve
    })
    // Once the stage is seen it stays seen, so later requests skip the
    // in-page snapshot.
    let reached = false
    await page.route(`${WAS_URL}/**`, async route => {
      if (route.request().method() !== 'GET') {
        reached ||= await stageReached({ page, stage: 'account-log-read' })
        if (reached) {
          markHeld(route)
          return
        }
      }
      await route.continue()
    })

    await page.goto('/#/signup')
    await fillSettled(page.locator('input[type="password"]'), passphrase)
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled({
      timeout: 15_000
    })
    await page.getByRole('button', { name: 'Next' }).click()
    await page.locator('input[type="email"]').fill(email)
    await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
    await page.getByRole('button', { name: 'Next' }).click()
    await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
    await page.getByRole('button', { name: 'Create Wallet' }).click()

    const heldRoute = await held
    const boundary = await ceremonyEvents.waitForStage(
      'credential-anchored-genesis',
      'account-log-read',
      { timeoutMs: 60_000 }
    )

    // The tab dies with the annex write unsent. Playwright hands a route still
    // pending at `page.close()` on to the network, which would land the
    // write after all, so the context goes offline and the held request is
    // dropped first. Offline also keeps the dying page's last lines (the
    // establishment's reaction to the dropped request) out of the file: the
    // file then holds what a killed tab leaves.
    await page.context().setOffline(true)
    await heldRoute.abort('internetdisconnected').catch(() => undefined)
    await page.close()

    // The torn-run signature: the run's stages up to the boundary, and no
    // outcome.
    const run = boundary.data.run
    tornRun = run
    await ceremonyEvents.waitQuiet()
    const ofRun = await ceremonyEvents.lines()
    expect(
      stageEvents({ lines: ofRun, run }).map(line => line.data.stage)
    ).toEqual(expect.arrayContaining(['interim-bind', 'account-log-read']))
    expect([
      ...outcomeEvents({ lines: ofRun, run }),
      ...ofRun.filter(
        line => line.data.run === run && line.data.stage === 'annex-generation'
      )
    ]).toEqual([])
  })

  test("a credential-only login's heal re-runs the establishment", async ({
    browser,
    ceremonyEvents
  }) => {
    test.slow()
    // The record still points at the signup-time did:key and the account
    // document names no generation, so the transient login takes the heal
    // branch: the mend ceremony's establishment arm re-runs the whole
    // establishment, which converges under a run of its own.
    const page = await coldPage(browser)
    try {
      await ceremonyEvents.tag(page.context())
      await page.goto('/#/login')
      await submitTransientLogin(page, passphrase)
      const mended = await ceremonyEvents.expectMender(
        'unlock-record-points-at-the-account-did',
        'clean'
      )
      expect(mended.data.arm).toBe('established')
      // The converging run's outcome, under a run id of its own. The heal
      // delivers the collection epochs off the roster the torn run already
      // wrote rather than minting them. The establishment still reports
      // `epochsSkipped`, but a skip the roster delivered on the same run
      // leaves nothing to act on, so the converged heal is `clean`.
      const converged = await ceremonyEvents.waitForOutcome(
        'credential-anchored-genesis'
      )
      expect(converged.data.run).not.toBe(tornRun)
      expect(converged.data).toMatchObject({
        outcome: 'clean',
        failedStages: 0,
        epochsSkipped: true
      })
      // Its stages re-ran from the top, the ones already durable marked
      // `prior`.
      const reran = stageEvents({
        lines: await ceremonyEvents.lines(),
        run: converged.data.run
      })
      expect(
        reran.find(line => line.data.stage === 'webvh-genesis')?.data.prior
      ).toBe(true)
      expect(reran.map(line => line.data.stage)).toContain(
        'controller-promotion'
      )
      await ceremonyEvents.expectNoFailedMenders({ page })
    } finally {
      await page.context().close()
    }
  })
})

/**
 * Whether the page's own ring buffer already holds a stage event: the
 * in-page view of a boundary the dev-log file sees up to a flush later.
 *
 * @param options {object}
 * @param options.page {Page}
 * @param options.stage {string}
 * @returns {Promise<boolean>}
 */
async function stageReached({
  page,
  stage
}: {
  page: Page
  stage: CredentialAnchoredEstablishmentStageName
}): Promise<boolean> {
  return await page
    .evaluate(
      ({ name, stageMsg }) => {
        const handle = (
          window as unknown as {
            __fwLog?: {
              snapshot: () => Array<{ msg: string; data?: { stage?: string } }>
            }
          }
        ).__fwLog
        return (handle?.snapshot() ?? []).some(
          event => event.msg === stageMsg && event.data?.stage === name
        )
      },
      { name: stage, stageMsg: CEREMONY_STAGE_MSG }
    )
    .catch(() => false)
}
