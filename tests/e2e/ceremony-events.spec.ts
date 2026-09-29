/**
 * The ceremony-event fixture's own e2e (`tests/shared/ceremonyEvents.ts`),
 * against the default suite's local-mode dev server: page-tag scoping keeps
 * an untagged page's lines out, `expectNoFailedMenders` waits on the login
 * chain's seam, and a healthy check's `noop` mender entry is visible because
 * the fixture sets the debug filter before the first navigation.
 */
import type { Page, TestInfo } from '@playwright/test'
import { E2E_LOG_TAG_MSG } from '@/lib/e2eLogTag'
import {
  test,
  expect,
  devLogFile,
  devLogReader
} from '../shared/ceremonyEvents'
import { menderEvents, type DevLogLine } from '../shared/ceremonyEventLines'

/**
 * Signs a fresh local-mode wallet up, logs out, and logs back in, landing
 * on the dashboard. The login is what runs the login-time mender block; a
 * local-mode signup runs none.
 *
 * @param options {object}
 * @param options.page {Page}
 * @param options.testInfo {TestInfo}
 * @returns {Promise<void>}
 */
async function signUpAndLogIn({
  page,
  testInfo
}: {
  page: Page
  testInfo: TestInfo
}): Promise<void> {
  const token = `${Date.now()}-w${testInfo.workerIndex}`
  const passphrase = `Str0ngpass-${token}-Aa1!`
  await page.goto('/#/signup')
  await page.locator('input[type="password"]').fill(passphrase)
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
  await page.getByRole('button', { name: 'Next' }).click()
  await page.locator('input[type="email"]').fill(`e2e-${token}@example.com`)
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
  await page.getByRole('button', { name: 'Create Wallet' }).click()
  await expect(page).toHaveURL(/#\/dashboard/)
  await page.getByRole('button', { name: 'Log out' }).click()
  await expect(page).toHaveURL(/#\/$/)
  // A fresh document, as in the login spec: an in-app navigation can let
  // the StrictMode remount clear the typed passphrase.
  await page.goto('/#/login')
  await page.reload()
  const passphraseInput = page.locator('input[type="password"]')
  await passphraseInput.fill(passphrase)
  await expect(passphraseInput).toHaveValue(passphrase)
  await page.getByRole('button', { name: 'Log in', exact: true }).click()
  await expect(page).toHaveURL(/#\/dashboard/)
}

test.describe('The ceremony-event fixture', () => {
  test("a healthy check's noop mender entry is visible", async ({
    page,
    ceremonyEvents
  }, testInfo) => {
    await signUpAndLogIn({ page, testInfo })
    const event = await ceremonyEvents.expectMender(
      'registry-lists-the-passphrase-method',
      'noop'
    )
    expect(event.level).toBe('debug')
    await ceremonyEvents.expectNoFailedMenders({ page })
  })

  test('expectNoFailedMenders waits on the login-chain seam', async ({
    page,
    ceremonyEvents
  }, testInfo) => {
    await signUpAndLogIn({ page, testInfo })
    // Hold the seam: the wrapped waiter settles a beat after the real one,
    // and records when it did.
    await page.evaluate(() => {
      const host = window as unknown as {
        __E2E_LOGIN_CHAIN_SETTLED__?: () => Promise<void>
        __heldSeamSettled__?: boolean
      }
      const real = host.__E2E_LOGIN_CHAIN_SETTLED__
      host.__E2E_LOGIN_CHAIN_SETTLED__ = async () => {
        await real?.()
        await new Promise(resolve => setTimeout(resolve, 1_500))
        host.__heldSeamSettled__ = true
      }
    })
    await ceremonyEvents.expectNoFailedMenders({ page })
    expect(
      await page.evaluate(
        () =>
          (window as unknown as { __heldSeamSettled__?: boolean })
            .__heldSeamSettled__
      )
    ).toBe(true)
  })

  test('expectNoFailedMenders refuses a page with no session', async ({
    page,
    ceremonyEvents
  }) => {
    await page.goto('/#/login')
    await expect(
      ceremonyEvents.expectNoFailedMenders({ page, timeoutMs: 1_000 })
    ).rejects.toThrow(/__E2E_LOGIN_CHAIN_SETTLED__/)
  })

  test("page-tag scoping ignores an untagged page's lines", async ({
    browser,
    page,
    ceremonyEvents
  }, testInfo) => {
    // One incremental reader over the whole file, polled below.
    const readAll = await devLogReader({ file: devLogFile() })
    await page.goto('/#/login')
    // The untagged page: a context the fixture never saw runs a login,
    // whose mender block reports entries at info and above.
    const untagged = await browser.newContext({
      baseURL: testInfo.project.use.baseURL
    })
    let untaggedPages: string[] = []
    try {
      await signUpAndLogIn({ page: await untagged.newPage(), testInfo })
      // Its lines reached the file: pages with mender lines and no marker.
      await expect
        .poll(
          async () => {
            untaggedPages = pagesWithoutMarker(await readAll())
            return untaggedPages.length
          },
          { timeout: 10_000 }
        )
        .toBeGreaterThan(0)
    } finally {
      await untagged.close()
    }
    const scoped = await ceremonyEvents.lines()
    expect(scoped.filter(line => untaggedPages.includes(line.page))).toEqual([])
  })
})

/**
 * The page ids among the dev-log lines that wrote a mender event and never a
 * page-tag marker.
 *
 * @param lines {DevLogLine[]}   every line read from the file
 * @returns {string[]}
 */
function pagesWithoutMarker(lines: DevLogLine[]): string[] {
  const marked = new Set(
    lines.filter(line => line.msg === E2E_LOG_TAG_MSG).map(line => line.page)
  )
  return [
    ...new Set(
      menderEvents({ lines })
        .filter(line => !marked.has(line.page))
        .map(line => line.page)
    )
  ]
}
