/**
 * The residue-zero e2e: a fresh browser context runs the full DEFAULT
 * transient login through the real login form (no remember seam), does work
 * (stores a credential over the replica-less remote-direct variant), and
 * ends the visit -- once by logging out, once by a simulated crash (the page
 * closes with no logout) -- and in both cases the browser holds zero trace:
 * no IndexedDB database, no new localStorage key, an empty sessionStorage
 * (the shared assertions in `tests/shared/storageResidue.ts`).
 *
 * The transient login needs an annex generation the account document
 * points at and an unlock record carrying the delegated-clients sibling.
 * This suite's fixture is deliberately the DURABLE signup plus the
 * non-production `__E2E_MINT_CLIENT_ANNEX_GENERATION__` seam -- the remembered
 * account whose credential later visits public terminals. The
 * credential-anchored signup path (which mints the generation with no seam
 * and no durable client) has its own residue suite in
 * `credential-anchored-signup.spec.ts`.
 */
import { test, expect, type Browser, type Page } from '@playwright/test'
import {
  addCredentialViaPaste,
  signupViaWizard,
  submitTransientLogin
} from './helpers'
import {
  captureLocalStorageKeys,
  expectNoStorageResidue
} from '../shared/storageResidue'

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

/**
 * The public-terminal browser: a fresh context holding nothing.
 */
async function coldTerminal(browser: Browser): Promise<{
  context: Awaited<ReturnType<Browser['newContext']>>
  page: Page
}> {
  const context = await browser.newContext({ baseURL: APP_URL })
  const page = await context.newPage()
  return { context, page }
}

/**
 * The default transient login through the real login form -- deliberately no
 * `forceRememberBrowser`: a non-remembered browser's default is the
 * transient login. Returns the localStorage baseline captured on the loaded
 * login page, before any input.
 */
async function transientLogin(
  page: Page,
  passphrase: string
): Promise<string[]> {
  await page.goto('/#/login')
  const baseline = await captureLocalStorageKeys({ page })
  await submitTransientLogin(page, passphrase)
  return baseline
}

test.describe.serial('transient login residue', () => {
  let passphrase: string

  test.beforeAll(async ({ browser }, testInfo) => {
    // The account fixture: a durable signup, then the annex generation
    // and the sibling-carrying unlock record minted through the seam. The
    // setup context is durable on purpose and simply discarded.
    const context = await browser.newContext({ baseURL: APP_URL })
    try {
      const page = await context.newPage()
      const user = await signupViaWizard(page, testInfo)
      passphrase = user.passphrase
      await page.evaluate(
        async fixture => {
          const seam = (
            window as unknown as {
              __E2E_MINT_CLIENT_ANNEX_GENERATION__?: (options: {
                passphrase: string
              }) => Promise<void>
            }
          ).__E2E_MINT_CLIENT_ANNEX_GENERATION__
          if (!seam) {
            throw new Error(
              'The annex-generation fixture seam is not installed.'
            )
          }
          await seam(fixture)
        },
        { passphrase: user.passphrase }
      )
    } finally {
      await context.close()
    }
  })

  test('a transient visit ended by logout leaves zero residue', async ({
    browser
  }) => {
    const { context, page } = await coldTerminal(browser)
    try {
      const baseline = await transientLogin(page, passphrase)
      await addCredentialViaPaste(page)
      // The logging seam's durability invariant: the visit above ran the
      // wired loggers (the dev ring buffer holds events), and exercising
      // the dev handle's setFilter writes nothing durable -- the filter
      // override is in-memory only, so the residue assertions below must
      // still see an unchanged localStorage key set.
      await page.evaluate(() => {
        const handle = (
          window as unknown as {
            __fwLog?: {
              snapshot: () => unknown[]
              setFilter: (pattern: string | null) => void
              clear: () => void
            }
          }
        ).__fwLog
        if (!handle) {
          throw new Error('window.__fwLog is not installed in this dev build.')
        }
        handle.setFilter('fw:*')
        handle.setFilter(null)
      })
      await page.getByRole('button', { name: 'Log out' }).click()
      await expect(page).toHaveURL(/\/#?\/?$/)
      await expectNoStorageResidue({
        page,
        baselineLocalStorageKeys: baseline
      })
    } finally {
      await context.close()
    }
  })

  test('a transient visit ended by a crash leaves zero residue', async ({
    browser
  }) => {
    const { context, page } = await coldTerminal(browser)
    try {
      const baseline = await transientLogin(page, passphrase)
      await addCredentialViaPaste(page)
      // The simulated crash: the tab dies with no logout (scenario D). The
      // context stays live so the assertions can inspect what the origin
      // still holds afterwards.
      await page.close()
      const after = await context.newPage()
      await after.goto(`${APP_URL}/`)
      await expectNoStorageResidue({
        page: after,
        baselineLocalStorageKeys: baseline
      })
    } finally {
      await context.close()
    }
  })
})
