/**
 * The account-management ceremonies run from a TRANSIENT session on a
 * credential-anchored account (FW-424). Every account here is the default
 * signup -- no remember seam, no enrolled client anywhere -- so each ceremony
 * is signed by the passphrase's update-key ladder and invoked by the visit's
 * annex verification method under the generation delegation, and each visit
 * must end leaving this browser exactly as it found it.
 *
 * This file carries the unlock-credential cells and the Space transfer:
 *
 * 1. The passphrase change (the design's required cell): the roster gains one
 *    epoch, a credential stored before the change still decrypts, the annex
 *    generation gains the new credential's rung commit and loses the old
 *    credential's rung with no generation swap, the account document and its
 *    did:web projection stop naming the old credential's ladder VM, the new
 *    passphrase enters transiently from a cold terminal and the old one is
 *    refused -- and the acting browser holds no residue afterwards.
 * 2. A passkey added from a passphrase transient session, then removed from
 *    the same session.
 * 3. Space export and import from a transient session.
 *
 * The client-axis cells (enrollment approval, the last-client disconnect,
 * recovery codes, and the unspent-code interference cell) live in
 * `transient-ceremonies-clients.spec.ts`.
 *
 * The roster and the annex log are capability-gated, so their assertions read
 * the teaching server's FileSystem backend off disk (`storedLogs.ts`), the
 * way the account-deletion suite already answers Space questions.
 */
import { Buffer } from 'node:buffer'
import {
  test,
  expect,
  type Browser,
  type BrowserContext,
  type CDPSession,
  type Page
} from '@playwright/test'
import {
  defaultWebvhLogVerifier,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import { delegatedClientsPointer } from '@interop/wallet-core/clientAnnex'
import {
  addCredentialViaPaste,
  expectDidWebProjectionMatches,
  fillSettled,
  signupViaWizard
} from './helpers'
import {
  annexLocationOf,
  readAnnexGeneration,
  readUserKeyRoster
} from './storedLogs'
import {
  captureLocalStorageKeys,
  expectNoStorageResidue
} from '../shared/storageResidue'

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

/**
 * The public-terminal browser: a fresh context holding nothing.
 *
 * @param browser {Browser}
 * @returns {Promise<{ context: BrowserContext, page: Page }>}
 */
async function coldTerminal(
  browser: Browser
): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ baseURL: APP_URL })
  const page = await context.newPage()
  return { context, page }
}

/**
 * The account Space id of the live session, through the E2E storage seam the
 * auth store publishes in non-production builds.
 *
 * @param page {Page}
 * @returns {Promise<string>}
 */
async function readSpaceId(page: Page): Promise<string> {
  const spaceId = await page.evaluate(
    () =>
      (window as unknown as { __E2E_STORAGE__?: { spaceId?: string } })
        .__E2E_STORAGE__?.spaceId
  )
  expect(spaceId, 'the session must name an account Space').toBeTruthy()
  return spaceId!
}

/**
 * The world-readable `did.jsonl` URL the Settings page links, once did:webvh
 * provisioning has landed.
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
 * The resolved account document, its entry count, and the annex generation it
 * points at, read from the world-readable log.
 *
 * @param page {Page}
 * @param logUrl {string}
 * @returns {Promise<object>}
 */
async function readAccountState(page: Page, logUrl: string) {
  const response = await page.request.get(logUrl)
  expect(response.status()).toBe(200)
  const log = readLogFromString(await response.text())
  const resolved = await resolveDIDFromLog(log, {
    verifier: defaultWebvhLogVerifier
  })
  expect(resolved.meta.error).toBeUndefined()
  const doc = resolved.doc as {
    authentication?: string[]
    capabilityDelegation?: string[]
    keyAgreement?: unknown[]
  } | null
  // A ladder VM stands under `capabilityDelegation` with no invocation and no
  // authentication relation, so the enrolled clients and the KMS-held
  // authentication key subtract out.
  const ladderVms = (doc?.capabilityDelegation ?? []).filter(
    id => !(doc?.authentication ?? []).includes(id)
  )
  const pointer = delegatedClientsPointer({
    doc: resolved.doc as Parameters<typeof delegatedClientsPointer>[0]['doc']
  })
  return {
    entries: log.length,
    doc: resolved.doc,
    ladderVms,
    keyAgreementCount: (doc?.keyAgreement ?? []).length,
    pointer
  }
}

test.describe.serial('the passphrase change from a transient session', () => {
  let oldPassphrase: string
  let newPassphrase: string
  let logUrl: string
  let accountSpaceId: string

  test('changes the passphrase, rotates the roster, and strikes the old ladder VM', async ({
    browser
  }, testInfo) => {
    test.setTimeout(360_000)
    const { context, page } = await coldTerminal(browser)
    try {
      // The default signup: no remember seam, so the account is
      // credential-anchored and the visit is a transient session. The
      // localStorage baseline is captured on the loaded wizard, before any
      // input.
      await page.goto('/#/signup')
      const baseline = await captureLocalStorageKeys({ page })
      const user = await signupViaWizard(page, testInfo, {
        rememberBrowser: false
      })
      oldPassphrase = user.passphrase

      // A credential stored BEFORE the change, sealed under the pre-change
      // user key: what the rotation's escrow has to keep readable.
      await addCredentialViaPaste(page)

      accountSpaceId = await readSpaceId(page)
      logUrl = await readLogUrl(page)
      const before = await readAccountState(page, logUrl)
      expect(before.ladderVms, 'the account is ladder-anchored').toHaveLength(1)
      expect(before.pointer, 'the account points at a generation').toBeTruthy()
      const annexBefore = annexLocationOf({ pointer: before.pointer! })
      const rosterBefore = await readUserKeyRoster({ spaceId: accountSpaceId })
      const generationBefore = await readAnnexGeneration(annexBefore)

      newPassphrase = `Rebound-transient-${Date.now()}-Zz9!`
      await page.goto('/#/settings')
      await expect(
        page.getByRole('heading', { name: 'Passphrase', exact: true })
      ).toBeVisible()
      // The change form renders on a transient session at all: before
      // FW-424 this section read "Log in with your passphrase to change it".
      await fillSettled(
        page.getByLabel('Current passphrase', { exact: true }),
        oldPassphrase
      )
      await fillSettled(
        page.getByLabel('New passphrase', { exact: true }),
        newPassphrase
      )
      const changeButton = page.getByRole('button', {
        name: 'Change passphrase'
      })
      await expect(changeButton).toBeEnabled({ timeout: 30_000 })
      await changeButton.click()

      // The old credential is retired for real -- document inventory out,
      // user key rotated, collections re-epoch'd -- so the success copy is
      // the rotated variant.
      await expect(
        page.getByText('Your content keys were rotated', { exact: false })
      ).toBeVisible({ timeout: 180_000 })

      // The roster gained exactly one epoch: the convergence append's fresh
      // user key. (The escrow append before it adds a recipient to the
      // existing epochs rather than an epoch.)
      const rosterAfter = await readUserKeyRoster({ spaceId: accountSpaceId })
      expect(rosterAfter.epochIds.length).toBe(rosterBefore.epochIds.length + 1)
      expect(rosterAfter.currentEpoch).not.toBe(rosterBefore.currentEpoch)
      for (const epochId of rosterBefore.epochIds) {
        expect(
          rosterAfter.epochIds,
          'every prior epoch is kept, so pre-change history stays readable'
        ).toContain(epochId)
      }

      // The credential stored before the change still decrypts in the live
      // session, which adopted the rotated user key in place.
      await page.goto('/#/dashboard')
      await expect(
        page.getByRole('link', { name: 'E2E Test Credential' })
      ).toBeVisible({ timeout: 30_000 })

      // The account log grew by the ceremony's two entries (the bind entry
      // signed by the old rung, the strike entry signed by the new rung 0),
      // and the old credential's ladder VM is gone.
      const after = await readAccountState(page, logUrl)
      expect(after.entries).toBe(before.entries + 2)
      expect(after.ladderVms).toHaveLength(1)
      expect(after.ladderVms[0]).not.toBe(before.ladderVms[0])
      expect(after.keyAgreementCount).toBe(before.keyAgreementCount)

      // No generation swap: the account still points at the same annex
      // generation, and that generation's log carries the new credential's
      // rung commit and no longer carries the old credential's rung.
      expect(after.pointer).toBe(before.pointer)
      const generationAfter = await readAnnexGeneration(annexBefore)
      expect(generationAfter.entries).toBeGreaterThan(generationBefore.entries)
      const committed = generationAfter.nextKeyHashes.filter(
        hash => !generationBefore.nextKeyHashes.includes(hash)
      )
      const struck = generationBefore.nextKeyHashes.filter(
        hash => !generationAfter.nextKeyHashes.includes(hash)
      )
      expect(committed, "the new credential's annex rung").toHaveLength(1)
      expect(struck, "the old credential's annex rung").toHaveLength(1)

      // The did:web projection kept up with the strike: it IS the projection
      // of the resolved document, so it names the new ladder VM and no
      // longer names the old one.
      await expectDidWebProjectionMatches({ page, logUrl, doc: after.doc })
      const projection = await (
        await page.request.get(logUrl.replace(/\/did\.jsonl$/, '/did.json'))
      ).text()
      const oldLadderMultibase = before.ladderVms[0]!.split('#')[1]!
      expect(projection).not.toContain(oldLadderMultibase)

      // The ceremony wrote nothing to this browser: no IndexedDB database
      // (no `freewallet-session`, no replica), no localStorage key gained,
      // an empty sessionStorage.
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

  test('the new passphrase enters transiently and the old one is refused', async ({
    browser
  }) => {
    test.setTimeout(240_000)
    const { context, page } = await coldTerminal(browser)
    try {
      // The old passphrase's unlock Space was deleted by the ceremony, so it
      // resolves to no account at all.
      await page.goto('/#/login')
      await fillSettled(page.locator('input[type="password"]'), oldPassphrase)
      await page.getByRole('button', { name: 'Log in', exact: true }).click()
      await expect(page).toHaveURL(/#\/signup/, { timeout: 60_000 })
      await expect(
        page.getByText('This profile does not exist, please sign up.')
      ).toBeVisible()

      // The new passphrase is standing: a cold terminal enters transiently
      // and reads the credential stored before the change.
      await page.goto('/#/login')
      const baseline = await captureLocalStorageKeys({ page })
      await fillSettled(page.locator('input[type="password"]'), newPassphrase)
      await page.getByRole('button', { name: 'Log in', exact: true }).click()
      await expect(page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })
      await expect(
        page.getByRole('link', { name: 'E2E Test Credential' })
      ).toBeVisible({ timeout: 30_000 })

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
})

/**
 * Adds a PRF-capable virtual authenticator to the page's context and returns
 * the CDP session that owns it.
 *
 * @param page {Page}
 * @returns {Promise<CDPSession>}
 */
async function enableAuthenticator(page: Page): Promise<CDPSession> {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true
    }
  })
  return cdp
}

/**
 * Confirms the "one more tap needed" PRF-retry dialog when it appears. Some
 * authenticators evaluate the WebAuthn PRF only during a follow-up assertion,
 * so registration surfaces a consent dialog; others evaluate it at creation
 * and show none.
 *
 * @param page {Page}
 * @returns {Promise<void>}
 */
async function confirmPrfRetryIfPrompted(page: Page): Promise<void> {
  const continueButton = page.getByRole('button', {
    name: 'Continue',
    exact: true
  })
  try {
    await continueButton.waitFor({ state: 'visible', timeout: 5_000 })
    await continueButton.click()
  } catch {
    // No retry dialog: the authenticator evaluated PRF during creation.
  }
}

test('a passkey is added and removed from a transient passphrase session', async ({
  browser
}, testInfo) => {
  test.setTimeout(360_000)
  const { context, page } = await coldTerminal(browser)
  try {
    await enableAuthenticator(page)
    await page.goto('/#/signup')
    const baseline = await captureLocalStorageKeys({ page })
    const { passphrase } = await signupViaWizard(page, testInfo, {
      rememberBrowser: false
    })
    const logUrl = await readLogUrl(page)
    const before = await readAccountState(page, logUrl)

    // The add: the establishment half of the recovery ceremony, signed by
    // the passphrase's ladder. The control renders on a transient session at
    // all, which is the FW-424 change.
    const addPasskey = page.getByRole('button', { name: 'Add a passkey' })
    await expect(addPasskey).toBeEnabled({ timeout: 30_000 })
    await addPasskey.click()
    await confirmPrfRetryIfPrompted(page)
    await expect(page.getByText('Passkey added', { exact: false })).toBeVisible(
      { timeout: 180_000 }
    )

    const removeButtons = page.getByRole('button', {
      name: 'Remove',
      exact: true
    })
    await expect(removeButtons).toHaveCount(1, { timeout: 60_000 })
    // The passphrase is the acting credential, so the passkey's own row is
    // removable (the ladder branch refuses only the credential it acts
    // through) and the passphrase remains as a second unlock method.
    await expect(removeButtons.first()).toBeEnabled()

    // The passkey's key-agreement entry stands in the document.
    const added = await readAccountState(page, logUrl)
    expect(added.keyAgreementCount).toBe(before.keyAgreementCount + 1)
    expect(added.ladderVms.length).toBeGreaterThan(before.ladderVms.length)

    // The remove: the retirement half, again ladder-signed.
    await removeButtons.first().click()
    await expect(
      page.getByRole('heading', { name: 'Remove this passkey?' })
    ).toBeVisible()
    await page.getByRole('button', { name: 'Remove passkey' }).click()
    await expect(
      page.getByText('Passkey removed', { exact: false })
    ).toBeVisible({ timeout: 180_000 })
    await expect(removeButtons).toHaveCount(0, { timeout: 60_000 })

    // The document is back to the passphrase alone.
    const removed = await readAccountState(page, logUrl)
    expect(removed.keyAgreementCount).toBe(before.keyAgreementCount)
    expect(removed.ladderVms).toHaveLength(before.ladderVms.length)

    // The removed passkey no longer locates the account.
    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/\/#?\/?$/)
    await page.goto('/#/login')
    await page.getByRole('button', { name: 'Log in with a Passkey' }).click()
    await expect(
      page.getByText('No wallet was found for this passkey.', { exact: false })
    ).toBeVisible({ timeout: 60_000 })

    // The passphrase still enters, and the two ceremonies left no residue.
    await fillSettled(page.locator('input[type="password"]'), passphrase)
    await page.getByRole('button', { name: 'Log in', exact: true }).click()
    await expect(page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })
    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/\/#?\/?$/)
    await expectNoStorageResidue({ page, baselineLocalStorageKeys: baseline })
  } finally {
    await context.close()
  }
})

/**
 * Drives the signup wizard's passkey path to the dashboard. A passkey signup
 * remembers the browser by construction, so the transient cell below starts
 * by clearing this browser's IndexedDB -- the synced passkey lives in the
 * authenticator, not in page storage.
 *
 * @param page {Page}
 * @param options {object}
 * @param options.email {string}
 * @returns {Promise<void>}
 */
async function passkeySignup(
  page: Page,
  { email }: { email: string }
): Promise<void> {
  await page.goto('/#/signup')
  await page.getByRole('button', { name: 'Sign up with a Passkey' }).click()
  await page.locator('input[type="email"]').fill(email)
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
  await page.getByRole('button', { name: 'Create Wallet' }).click()
  await confirmPrfRetryIfPrompted(page)
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 45_000 })
}

/**
 * Deletes every IndexedDB database for the origin, standing in for a fresh
 * browser that still carries the synced passkey.
 *
 * @param page {Page}
 * @returns {Promise<void>}
 */
async function clearAllIndexedDb(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const databases = await indexedDB.databases()
    await Promise.all(
      databases.map(
        info =>
          new Promise<void>(resolve => {
            if (!info.name) {
              resolve()
              return
            }
            const request = indexedDB.deleteDatabase(info.name)
            request.onsuccess = () => resolve()
            request.onerror = () => resolve()
            request.onblocked = () => resolve()
          })
      )
    )
  })
}

test('a passphrase is added from a transient passkey session', async ({
  browser
}, testInfo) => {
  test.setTimeout(360_000)
  const { context, page } = await coldTerminal(browser)
  try {
    await enableAuthenticator(page)
    await passkeySignup(page, {
      email: `e2e-passkey-${Date.now()}-w${testInfo.workerIndex}@example.com`
    })

    // A passkey signup remembers this browser, so the transient entry needs a
    // browser holding no client-key record: clear the databases, then log in
    // with the passkey WITHOUT the remember seam.
    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/\/#?\/?$/)
    await clearAllIndexedDb(page)
    await page.goto('/#/login')
    await page.reload()
    const baseline = await captureLocalStorageKeys({ page })
    await page.getByRole('button', { name: 'Log in with a Passkey' }).click()
    await expect(page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })

    // The add: the establishment half again, this time for a passphrase, with
    // the passkey's ladder signing.
    const addedPassphrase = `Added-transient-${Date.now()}-Zz9!`
    await page.goto('/#/settings')
    await expect(
      page.getByRole('heading', { name: 'Passphrase', exact: true })
    ).toBeVisible()
    await fillSettled(
      page.getByLabel('New passphrase', { exact: true }),
      addedPassphrase
    )
    const addButton = page.getByRole('button', { name: 'Add a passphrase' })
    await expect(addButton).toBeEnabled({ timeout: 30_000 })
    await addButton.click()
    await expect(
      page.getByText('Passphrase added', { exact: false }).first()
    ).toBeVisible({ timeout: 180_000 })

    // The added passphrase is standing: it enters this account on its own.
    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/\/#?\/?$/)
    await page.goto('/#/login')
    await fillSettled(page.locator('input[type="password"]'), addedPassphrase)
    await page.getByRole('button', { name: 'Log in', exact: true }).click()
    await expect(page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })
    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/\/#?\/?$/)
    await expectNoStorageResidue({ page, baselineLocalStorageKeys: baseline })
  } finally {
    await context.close()
  }
})

test('a Space exports and imports from a transient session', async ({
  browser
}, testInfo) => {
  test.setTimeout(300_000)
  const { context, page } = await coldTerminal(browser)
  try {
    await page.goto('/#/signup')
    const baseline = await captureLocalStorageKeys({ page })
    await signupViaWizard(page, testInfo, { rememberBrowser: false })
    await addCredentialViaPaste(page)

    await page.goto('/#/storage')
    await expect(page.getByText('Space (connected):')).toBeVisible()
    // Both buttons are offered on a transient session: before FW-424 they
    // rendered enabled and threw `StepUpRequiredError` into a generic toast.
    const exportButton = page.getByRole('button', {
      name: 'Export (Backup) Space Contents'
    })
    await expect(exportButton).toBeEnabled({ timeout: 30_000 })
    // The import control is a MUI Button rendered as a <label> wrapping a
    // hidden file input; both carry the accessible name, so address the label.
    await expect(
      page.locator('label[role="button"]', {
        hasText: 'Import (Load) from Backup'
      })
    ).toBeEnabled()

    // The export's sink is `showSaveFilePicker`, which headless Chromium does
    // not implement, so the bytes are read through the same live-session seam
    // `did-webvh.spec.ts` uses. What is under test is that the ZCap-signed
    // export runs at all under the visit's generation delegation.
    const exported = await page.evaluate(async () => {
      const storage = (
        window as unknown as {
          __E2E_STORAGE__: {
            exportSpace(): Promise<ReadableStream<Uint8Array>>
          }
        }
      ).__E2E_STORAGE__
      const reader = (await storage.exportSpace()).getReader()
      const parts: number[][] = []
      for (;;) {
        const { done, value } = await reader.read()
        if (done) {
          break
        }
        parts.push(Array.from(value))
      }
      return parts.flat()
    })
    expect(exported.length).toBeGreaterThan(0)

    // The import goes through the page's own button (a hidden file input
    // inside it), which is the surface the refusal used to reach.
    await page.locator('input[type="file"]').setInputFiles({
      name: 'space.tar',
      mimeType: 'application/x-tar',
      buffer: Buffer.from(Uint8Array.from(exported))
    })
    // Re-importing the Space's own bytes writes nothing new (the importer
    // merges and skips ids that already exist), so the assertion is that the
    // import completed rather than refusing.
    await expect(
      page.getByText('Import complete', { exact: false })
    ).toBeVisible({ timeout: 180_000 })

    // The wallet still works afterwards, and the two operations wrote
    // nothing to this browser.
    await page.goto('/#/dashboard')
    await expect(
      page.getByRole('link', { name: 'E2E Test Credential' })
    ).toBeVisible({ timeout: 30_000 })
    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/\/#?\/?$/)
    await expectNoStorageResidue({ page, baselineLocalStorageKeys: baseline })
  } finally {
    await context.close()
  }
})
