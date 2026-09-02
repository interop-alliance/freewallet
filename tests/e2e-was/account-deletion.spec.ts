/**
 * Account deletion from a transient session, end to end (WAS mode): the
 * public-terminal case the default session type exists to serve. The
 * deletion runs with no enrolled client acting, so every Space DELETE it
 * sends rides a ladder-signed, DELETE-only capability minted from the typed
 * passphrase, and the completeness claim is checked against the server's
 * store on disk rather than against its HTTP answers.
 *
 * The account shape under test, stated here because the walk depends on it:
 * a credential-anchored signup with TWO unlock methods, the passphrase and a
 * recovery code. Adding the second method needs a remembered session -- the
 * tier refusals -- so the setup runs one remembered login, which self-enrolls
 * that browser as an enrolled client. The deletion then runs from a fresh
 * cold terminal that has never been remembered, with the account document
 * still carrying both the passphrase's ladder VM and that enrolled client.
 *
 * The oracle is `storeOracle.ts`. An HTTP probe cannot answer "is this Space
 * gone": the server masks an authorization refusal as a 404, so once the
 * account Space is deleted every survivor controlled by the account
 * did:webvh answers 404 whether it was deleted or merely stranded.
 *
 * Every stage pays the deliberately slow unlock KDF on top of several WAS
 * ceremonies, hence the generous timeouts.
 */
import {
  test,
  expect,
  type Browser,
  type Page,
  type TestInfo
} from '@playwright/test'
import {
  awaitLoginChain,
  fillSettled,
  forceRememberBrowser,
  signupViaWizard,
  submitTransientLogin
} from './helpers'
import {
  accountSpaceIdFrom,
  annexSpaceIdsFromLog,
  expectSpacesGone,
  storedSpaceIdsSince,
  listStoredSpaceIds,
  survivingSpaceIds
} from './storeOracle'
import {
  captureLocalStorageKeys,
  expectNoStorageResidue
} from '../shared/storageResidue'

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

/**
 * One account under test, plus everything the oracle needs to name what it
 * owns.
 */
interface DeletableAccount {
  passphrase: string
  /** the data Space, off the live session's own StorageManager */
  accountSpaceId: string
  /** the auxiliary annex Spaces the account log's pointer history names */
  annexSpaceIds: string[]
  /** the world-readable `id/did.jsonl` URL, for the diagnostics dump */
  logUrl: string
  /** every Space the store gained while this account was built */
  spaceIds: string[]
}

/**
 * Opens a fresh, cold browser context (empty IndexedDB and localStorage) to
 * stand in for another terminal. Callers must close the returned context.
 *
 * @param browser {Browser}
 * @returns {Promise<{ context: Awaited<ReturnType<Browser['newContext']>>,
 *   page: Page }>}
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
 * The world-readable `id/did.jsonl` URL the Settings page links, once
 * did:webvh provisioning has landed.
 *
 * @param page {Page}
 * @returns {Promise<string>}
 */
async function readLogUrl(page: Page): Promise<string> {
  await page.goto('/#/settings')
  await expect(page.getByText('Published did:webvh DID')).toBeVisible({
    timeout: 30_000
  })
  const logLink = page.getByRole('link', { name: /\/id\/did\.jsonl$/ })
  await expect(logLink).toBeVisible({ timeout: 30_000 })
  return (await logLink.getAttribute('href'))!
}

/**
 * Builds the account shape the deletion runs against: ladder-anchored, with a
 * passphrase and a recovery code. See the file header for why the fixture
 * takes this route.
 *
 * @param browser {Browser}
 * @param testInfo {import('@playwright/test').TestInfo}
 * @returns {Promise<DeletableAccount>}
 */
async function buildLadderAnchoredAccount(
  browser: Browser,
  testInfo: TestInfo
): Promise<DeletableAccount> {
  const baseline = await listStoredSpaceIds()

  // --- Terminal A: the credential-anchored signup (no enrolled client). ---
  const first = await coldTerminal(browser)
  let passphrase: string
  let accountSpaceId: string
  try {
    const user = await signupViaWizard(first.page, testInfo, {
      rememberBrowser: false
    })
    passphrase = user.passphrase
    accountSpaceId = await accountSpaceIdFrom(first.page)
    await first.page.getByRole('button', { name: 'Log out' }).click()
    await expect(first.page).toHaveURL(/\/#?\/?$/)
  } finally {
    await first.context.close()
  }

  // --- Terminal B: the remembered self-enrollment and the second unlock
  // method, the one step the tier refusals keep off a transient session. ---
  const second = await coldTerminal(browser)
  let annexSpaceIds: string[]
  let logUrl: string
  try {
    await second.page.goto('/#/login')
    await forceRememberBrowser(second.page)
    await fillSettled(second.page.locator('input[type="password"]'), passphrase)
    await second.page
      .getByRole('button', { name: 'Log in', exact: true })
      .click()
    await expect(second.page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })

    logUrl = await readLogUrl(second.page)

    const generateButton = second.page.getByRole('button', {
      name: 'Generate recovery code'
    })
    await expect(generateButton).toBeEnabled({ timeout: 30_000 })
    await generateButton.click()
    await expect(
      second.page.getByText('This code is shown only once', { exact: false })
    ).toBeVisible()
    await second.page.getByRole('button', { name: 'I saved this code' }).click()
    await expect(second.page.getByText('Recovery code 1')).toBeVisible({
      timeout: 60_000
    })

    // The remembered login's own pass chain writes the standing refreshes
    // this account's later transient visits read; letting it settle keeps
    // the deletion under test rather than a half-run chain.
    await awaitLoginChain(second.page)

    annexSpaceIds = await annexSpaceIdsFromLog({
      request: second.page.request,
      logUrl
    })
  } finally {
    await second.context.close()
  }

  const spaceIds = await storedSpaceIdsSince({ baseline })
  // The oracle names what it is about to assert on: the data Space, at least
  // one auxiliary annex Space, and the two unlock Spaces named by difference.
  expect(spaceIds, 'the store gained the account data Space').toContain(
    accountSpaceId
  )
  expect(annexSpaceIds.length, 'the log names an annex Space').toBeGreaterThan(
    0
  )
  for (const annexSpaceId of annexSpaceIds) {
    expect(spaceIds, 'the store gained each annex Space').toContain(
      annexSpaceId
    )
  }
  // account + annex + the passphrase's and the recovery code's unlock Spaces.
  expect(spaceIds.length).toBeGreaterThanOrEqual(4)

  return { passphrase, accountSpaceId, annexSpaceIds, logUrl, spaceIds }
}

/**
 * What the deletion walk saw, dumped when it refuses where the spec expects
 * a completed run. The refusal that matters here is
 * `ladder-vm-not-anchored`, whose whole basis is a comparison between the
 * ladder VM ids the resolved account document lists and the multibase the
 * acting credential derives, so the dump names both sides: the document's
 * `assertionMethod` and `capabilityDelegation` entries out of the
 * world-readable log, and the app's own log ring buffer.
 *
 * @param options {object}
 * @param options.page {Page}
 * @param options.logUrl {string}
 * @returns {Promise<string>}
 */
async function deletionDiagnostics({
  page,
  logUrl
}: {
  page: Page
  logUrl: string
}): Promise<string> {
  const events = await page.evaluate(() => {
    const handle = (
      window as unknown as { __fwLog?: { snapshot: () => unknown[] } }
    ).__fwLog
    return handle
      ? JSON.stringify(handle.snapshot().slice(-60))
      : '(no __fwLog)'
  })
  let document: string
  try {
    const response = await page.request.get(logUrl)
    const lines = (await response.text()).trim().split('\n')
    const last = JSON.parse(lines[lines.length - 1]!) as {
      state?: {
        assertionMethod?: unknown
        capabilityDelegation?: unknown
        capabilityInvocation?: unknown
      }
    }
    document = JSON.stringify({
      assertionMethod: last.state?.assertionMethod,
      capabilityDelegation: last.state?.capabilityDelegation,
      capabilityInvocation: last.state?.capabilityInvocation
    })
  } catch (err) {
    document = `(unreadable: ${(err as Error).message})`
  }
  return `account document relations: ${document}\n\nlog ring buffer: ${events}`
}

/**
 * Opens the delete dialog on a Settings page and returns it.
 *
 * @param page {Page}
 * @returns {import('@playwright/test').Locator}
 */
function openDeleteDialog(page: Page) {
  return page.getByRole('dialog')
}

/**
 * A cold terminal logged in through the DEFAULT transient login, on the
 * Settings page with the delete dialog open. Returns the localStorage
 * baseline captured on the loaded login page, before anything was typed.
 *
 * @param page {Page}
 * @param passphrase {string}
 * @returns {Promise<string[]>}
 */
async function transientLoginToDeleteDialog(
  page: Page,
  passphrase: string
): Promise<string[]> {
  await page.goto('/#/login')
  const baseline = await captureLocalStorageKeys({ page })
  await submitTransientLogin(page, passphrase)
  await page.goto('/#/settings')
  await page
    .getByRole('button', { name: 'Delete Account', exact: true })
    .click()
  await expect(
    openDeleteDialog(page).getByRole('heading', {
      name: 'Delete your account?'
    })
  ).toBeVisible()
  return baseline
}

test.describe.serial('Account deletion from a transient session', () => {
  let account: DeletableAccount

  test.beforeAll(async ({ browser }, testInfo) => {
    test.setTimeout(900_000)
    account = await buildLadderAnchoredAccount(browser, testInfo)
  })

  test('a discovery refusal renders in the dialog and deletes nothing', async ({
    browser
  }) => {
    test.slow()
    test.setTimeout(300_000)

    const { context, page } = await coldTerminal(browser)
    try {
      await transientLoginToDeleteDialog(page, account.passphrase)
      const dialog = openDeleteDialog(page)

      // The (a2) registry read fails: a best-effort walk over an unreadable
      // registry would strand the sibling unlock Spaces, so the whole run
      // refuses with nothing deleted.
      await page.route('**/unlock-methods/**', async route => {
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: '{"message":"e2e-injected failure"}'
        })
      })

      await fillSettled(
        dialog.locator('input[name="freewallet-delete-confirm"]'),
        account.passphrase
      )
      await dialog
        .getByRole('button', { name: 'Delete account', exact: true })
        .click()

      // The refusal renders in the dialog rather than escaping as an
      // unhandled rejection.
      await expect(
        dialog.getByText(/Could not read this account.s list of sign-in/)
      ).toBeVisible({ timeout: 180_000 })
      await page.unroute('**/unlock-methods/**')

      // Nothing was deleted.
      expect(
        (await survivingSpaceIds({ spaceIds: account.spaceIds })).sort()
      ).toEqual([...account.spaceIds].sort())
    } finally {
      await context.close()
    }
  })

  test('deletes every Space the account owns and leaves no local residue', async ({
    browser
  }) => {
    test.slow()
    test.setTimeout(600_000)

    const { context, page } = await coldTerminal(browser)
    try {
      const baseline = await transientLoginToDeleteDialog(
        page,
        account.passphrase
      )
      const dialog = openDeleteDialog(page)

      // The confirm IS the ceremony's authentication, so a manager that saved
      // the passphrase at login must not offer to fill it.
      const confirmField = dialog.locator(
        'input[name="freewallet-delete-confirm"]'
      )
      await expect(confirmField).toHaveAttribute('autocomplete', 'off')

      await fillSettled(confirmField, account.passphrase)
      await dialog
        .getByRole('button', { name: 'Delete account', exact: true })
        .click()

      // A clean run ends in a logout and a hard reload onto the landing page.
      // A pre-flight refusal renders in the dialog instead, so the wait dumps
      // what the walk saw rather than reporting a bare timeout.
      try {
        await expect(page).toHaveURL(/\/#?\/?$/, { timeout: 300_000 })
      } catch (err) {
        throw new Error(
          `The deletion did not complete.\n${await deletionDiagnostics({
            page,
            logUrl: account.logUrl
          })}`,
          { cause: err }
        )
      }

      await expectSpacesGone({ spaceIds: account.spaceIds })
      await expectNoStorageResidue({
        page,
        baselineLocalStorageKeys: baseline
      })
    } finally {
      await context.close()
    }
  })
})

test.describe.serial('Account deletion torn after the pivot', () => {
  let account: DeletableAccount

  test.beforeAll(async ({ browser }, testInfo) => {
    test.setTimeout(900_000)
    account = await buildLadderAnchoredAccount(browser, testInfo)
  })

  test('the account Space is gone and the acting unlock Space stands', async ({
    browser
  }) => {
    test.slow()
    test.setTimeout(600_000)

    const { context, page } = await coldTerminal(browser)
    try {
      const baseline = await transientLoginToDeleteDialog(
        page,
        account.passphrase
      )
      const dialog = openDeleteDialog(page)

      // The tear: every Space DELETE after the pivot fails. (b6), the acting
      // credential's own unlock Space, is the only one past it, so this
      // leaves exactly the state the backstop (FW-401) is designed for.
      let pastThePivot = false
      page.on('response', response => {
        if (
          response.request().method() === 'DELETE' &&
          response.url().includes(account.accountSpaceId)
        ) {
          pastThePivot = true
        }
      })
      await page.route('**/space/*', async route => {
        if (route.request().method() === 'DELETE' && pastThePivot) {
          await route.abort('failed')
          return
        }
        await route.continue()
      })

      await fillSettled(
        dialog.locator('input[name="freewallet-delete-confirm"]'),
        account.passphrase
      )
      await dialog
        .getByRole('button', { name: 'Delete account', exact: true })
        .click()

      // Past the pivot, so (b6) reports rather than failing. The account is
      // gone, so the run must log out -- but the residue copy would go with
      // the hard reload, so the dialog states it and the logout waits on the
      // acknowledge.
      await expect(
        dialog.getByRole('heading', { name: 'Your account is deleted' })
      ).toBeVisible({ timeout: 300_000 })
      await expect(
        dialog.getByText(/The sign-in data for this method is still on the/)
      ).toBeVisible()
      await dialog
        .getByRole('button', { name: 'Sign out', exact: true })
        .click()
      await expect(page).toHaveURL(/\/#?\/?$/, { timeout: 60_000 })

      // The account Space and everything before the pivot are gone; exactly
      // one Space stands, the acting credential's own unlock Space.
      const surviving = await survivingSpaceIds({ spaceIds: account.spaceIds })
      expect(surviving).not.toContain(account.accountSpaceId)
      for (const annexSpaceId of account.annexSpaceIds) {
        expect(surviving).not.toContain(annexSpaceId)
      }
      expect(
        surviving,
        "only the acting credential's unlock Space stands"
      ).toHaveLength(1)

      // The browser still holds nothing: the local half runs past the pivot
      // too.
      await expectNoStorageResidue({
        page,
        baselineLocalStorageKeys: baseline
      })
    } finally {
      await context.close()
    }
  })
})

// The annex re-point variant (an account whose log carries two
// `#DelegatedClients` pointer entries) needs a generation swap forced from a
// test, which only the remembered-login GC chain performs today; there is no
// seam to drive it.
test.skip('deletes a superseded auxiliary annex Space too', () => {})

// The expired-sibling-zcap variant needs a registry entry whose
// `manageCapability` has lapsed, which is a year-long TTL with no clock seam
// in the app; the unit suite covers the reported-residue path instead.
test.skip('names an unlock Space whose management zcap has expired', () => {})
