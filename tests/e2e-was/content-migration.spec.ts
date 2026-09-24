/**
 * Content migration (FW-541): one account's backup bundle read into a
 * DIFFERENT account, through the Storage page's "Import from another wallet"
 * action.
 *
 * Account A is built once -- credentials, a contact, and one connected app
 * holding both a grant of its own collection and a share of A's
 * `private-credentials` -- and exported through the real backup dialog, whose
 * `showSaveFilePicker` is stubbed so the bundle's bytes come back to node
 * (`stubSaveFilePicker` / `savedFileBytes`). Every cell below hands those
 * bytes to a second account's import dialog through the file input, with A's
 * passphrase as the secret.
 *
 * What the cells assert is what migrates and what does not. Content travels:
 * B lists A's credential and A's contact. Nothing else does: the walk reads
 * the file alone, so no request reaches A's Space while it runs, and no
 * `Login` or `CollectionShare` row lands, so the importing account's
 * Applications page names no app of A's and its shares dialog names no reader
 * of A's. The importing account's own disconnect and unshare still complete
 * afterwards, which is the check that the migrated rows did not poison the
 * grant and share harvesters.
 *
 * The guest cell stands for the no-WAS deployment. A guest session holds no
 * remote Space (`hasRemoteStorage` is false, the same branch a deployment
 * with no `VITE_WAS_SERVER_URL` takes), and it is the only local-only session
 * this config can build: `playwright.config.ts` pins `VITE_WAS_SERVER_URL`
 * empty, so a run under it could not produce the bundle in the first place.
 */
import { Buffer } from 'node:buffer'
import {
  test,
  expect,
  type BrowserContext,
  type Page,
  type Request
} from '@playwright/test'
import { readBundle } from '@interop/wallet-backup'
import {
  addCredentialViaPaste,
  coldTerminal,
  fillSettled,
  savedFileBytes,
  signupViaWizard,
  stubSaveFilePicker,
  submitTransientLogin
} from './helpers'

// Matches `playwright.was.config.ts` (APP_PORT / WAS_PORT). A manually
// created context does not inherit the config's `use.baseURL`.
const APP_URL = 'http://localhost:5274'

/**
 * The contact account A creates and B is expected to list after the import.
 */
const CONTACT_NAME = 'Ada Lovelace Migration'

/**
 * One connected app as the CHAPI harness below drives it: A's and the
 * importing account's are deliberately different apps, so a row of A's would
 * be unmistakable on the importing account's pages.
 */
interface AppFixture {
  name: string
  appUrl: string
  origin: string
  domain: string
  collection: string
}

const APP_A: AppFixture = {
  name: 'Alpha Migration App',
  appUrl: 'https://alpha.example/editor',
  origin: 'https://alpha.example',
  domain: 'alpha.example',
  collection: 'alpha-app-data'
}

const APP_B: AppFixture = {
  name: 'Beta Migration App',
  appUrl: 'https://beta.example/editor',
  origin: 'https://beta.example',
  domain: 'beta.example',
  collection: 'beta-app-data'
}

/**
 * One request the capture recorded: its URL and every header it carried, so a
 * cell can ask both whether it addressed A's Space and whether it carried a
 * capability naming it.
 */
interface CapturedRequest {
  url: string
  headerText: string
}

/**
 * What a bundle says about the account that wrote it, read in node from the
 * bundle alone: every Space it archives, and the controller its manifest
 * names. Both are what a request to A would have to name.
 */
interface BundleIdentity {
  spaceIds: string[]
  controller: string
}

/**
 * Reads a bundle's Space ids and its manifest controller.
 *
 * @param bytes {Uint8Array}
 * @returns {Promise<BundleIdentity>}
 */
async function bundleIdentity(bytes: Uint8Array): Promise<BundleIdentity> {
  const bundle = await readBundle(bytes)
  const spaceIds: string[] = []
  for await (const space of bundle.spaces) {
    spaceIds.push(space.spaceId)
    // The archive bytes are drained so the reader advances to the next entry.
    await space.bytes()
  }
  return {
    spaceIds,
    controller: bundle.manifest.meta.createdBy.controller
  }
}

/**
 * Records every request a page issues from now on.
 *
 * @param options {object}
 * @param options.page {Page}
 * @param options.into {CapturedRequest[]}
 * @returns {(request: Request) => void}   the listener, for `page.off`
 */
function captureRequests({
  page,
  into
}: {
  page: Page
  into: CapturedRequest[]
}): (request: Request) => void {
  const listener = (request: Request) => {
    into.push({
      url: request.url(),
      headerText: JSON.stringify(request.headers())
    })
  }
  page.on('request', listener)
  return listener
}

/**
 * Asserts no captured request addressed one of the bundle's Spaces or carried
 * a capability naming the account that wrote it. A root invocation carries its
 * target url-encoded in the `capability-invocation` header, so the Space id
 * survives verbatim in both places the check looks.
 *
 * @param options {object}
 * @param options.captured {CapturedRequest[]}
 * @param options.identity {BundleIdentity}
 * @returns {void}
 */
function expectNoContactWithBundleAccount({
  captured,
  identity
}: {
  captured: CapturedRequest[]
  identity: BundleIdentity
}): void {
  expect(captured.length).toBeGreaterThan(0)
  for (const request of captured) {
    for (const spaceId of identity.spaceIds) {
      expect(
        request.url.includes(spaceId),
        `a request addressed the old account's Space: ${request.url}`
      ).toBe(false)
      expect(
        request.headerText.includes(spaceId),
        `a request carried a capability naming the old account's Space: ${request.url}`
      ).toBe(false)
    }
    expect(
      request.headerText.includes(identity.controller),
      `a request carried the old account's DID: ${request.url}`
    ).toBe(false)
  }
}

/**
 * Runs one export through the Storage page's backup dialog in its
 * unprotected mode, and brings the bundle back to node from the stubbed
 * picker. The code the export mints travels in the clear, which is what makes
 * the file openable by the packed code as well as by the passphrase.
 *
 * @param options {object}
 * @param options.page {Page}   a page holding a logged-in session
 * @returns {Promise<Uint8Array>}   the bundle tar's bytes
 */
async function exportBundleBytes({
  page
}: {
  page: Page
}): Promise<Uint8Array> {
  await page.goto('/#/storage')
  const exportButton = page.getByRole('button', {
    name: 'Export (Backup) Space Contents'
  })
  await expect(exportButton).toBeEnabled({ timeout: 30_000 })
  await exportButton.click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByText('Back up this wallet')).toBeVisible()
  await dialog.getByRole('radio', { name: 'Unprotected' }).check()
  await dialog.getByRole('button', { name: 'Create backup' }).click()
  await expect(page.getByText('Backup written.')).toBeVisible({
    timeout: 240_000
  })
  const { bytes } = await savedFileBytes(page)
  expect(bytes.length).toBeGreaterThan(0)
  return bytes
}

/**
 * Runs one import through the Storage page's content-migration dialog: the
 * bundle handed to the file input as a buffer, the old wallet's passphrase
 * typed into the passphrase field, and the run awaited to its report.
 *
 * @param options {object}
 * @param options.page {Page}   a page holding the session imported INTO
 * @param options.bundle {Uint8Array}   the bundle tar's bytes
 * @param options.passphrase {string}   the OLD account's passphrase
 * @returns {Promise<void>}
 */
async function importBundleViaDialog({
  page,
  bundle,
  passphrase
}: {
  page: Page
  bundle: Uint8Array
  passphrase: string
}): Promise<void> {
  await page.goto('/#/storage')
  const action = page.getByRole('button', {
    name: 'Import from Another Wallet'
  })
  await expect(action).toBeEnabled({ timeout: 60_000 })
  await action.click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByText('Import from another wallet')).toBeVisible()
  // The picker input is visually hidden behind its label button;
  // `setInputFiles` drives it directly.
  await dialog.locator('input[type="file"]').setInputFiles({
    name: 'wallet-backup-e2e.tar',
    mimeType: 'application/x-tar',
    buffer: Buffer.from(bundle)
  })
  await expect(dialog.getByText(/wallet-backup-e2e\.tar/)).toBeVisible()
  await fillSettled(
    dialog.getByLabel('Old wallet passphrase', { exact: true }),
    passphrase
  )
  await dialog.getByRole('button', { name: 'Import content' }).click()
  await expect(dialog.getByText('Import report')).toBeVisible({
    timeout: 240_000
  })
  await expect(page.getByText('Import complete.')).toBeVisible({
    timeout: 30_000
  })
  await dialog.getByRole('button', { name: 'Close' }).click()
}

/**
 * Injects one CHAPI `get` event for the popup route to pick up, and records
 * what the popup responds with. Copied from `applications.spec.ts`, which
 * carries the same first-party popup driver.
 *
 * @param options {object}
 * @param options.page {Page}
 * @param options.app {AppFixture}
 * @param options.challenge {string}
 * @returns {Promise<void>}
 */
async function injectGetEvent({
  page,
  app,
  challenge
}: {
  page: Page
  app: AppFixture
  challenge: string
}): Promise<void> {
  await page.addInitScript(
    (config: {
      origin: string
      query: unknown
      challenge: string
      domain: string
    }) => {
      const win = window as unknown as {
        __E2E_CHAPI_GET_EVENT__?: unknown
        __E2E_CHAPI_RESPONSE__?: { value: unknown }
      }
      win.__E2E_CHAPI_RESPONSE__ = undefined
      win.__E2E_CHAPI_GET_EVENT__ = {
        credentialRequestOrigin: config.origin,
        credentialRequestOptions: {
          web: {
            VerifiablePresentation: {
              query: config.query,
              challenge: config.challenge,
              domain: config.domain
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
    {
      origin: app.origin,
      domain: app.domain,
      challenge,
      query: [
        { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] },
        {
          type: 'AppConnectQuery',
          app: { name: app.name, appUrl: app.appUrl },
          capabilityQuery: [
            {
              referenceId: app.collection,
              allowedAction: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'],
              invocationTarget: {
                type: 'https://w3id.org/byoe#private-collection',
                name: app.collection
              }
            },
            {
              referenceId: 'shared-credentials',
              allowedAction: ['GET'],
              invocationTarget: {
                type: 'https://w3id.org/byoe#shared-wallet-collection',
                name: 'private-credentials'
              }
            }
          ]
        }
      ]
    }
  )
}

/**
 * Drives one App Connect popup visit for an already-created account: the
 * request injected, the in-popup login, the consent panel approved, and the
 * response awaited. Leaves the page logged out, since the popup route's
 * reload drops the in-memory session.
 *
 * @param options {object}
 * @param options.page {Page}
 * @param options.app {AppFixture}
 * @param options.passphrase {string}
 * @returns {Promise<void>}
 */
async function connectViaPopup({
  page,
  app,
  passphrase
}: {
  page: Page
  app: AppFixture
  passphrase: string
}): Promise<void> {
  await injectGetEvent({
    page,
    app,
    challenge: `chal-migration-${app.domain}-${Date.now()}`
  })
  await page.goto('/#/wallet/get')
  await page.reload()

  await fillSettled(page.locator('input[type="password"]'), passphrase)
  await page.getByRole('button', { name: 'Continue' }).click()
  await expect(
    page.getByRole('heading', { name: `Connect ${app.name} to storage?` })
  ).toBeVisible({ timeout: 30_000 })
  await page.getByRole('button', { name: 'Connect' }).click()
  await expect
    .poll(
      async () =>
        await page.evaluate(
          () =>
            (window as unknown as { __E2E_CHAPI_RESPONSE__?: unknown })
              .__E2E_CHAPI_RESPONSE__ !== undefined
        ),
      { timeout: 60_000 }
    )
    .toBe(true)
}

/**
 * Logs a page's session in through the login form, after a popup visit
 * dropped the in-memory session.
 *
 * @param options {object}
 * @param options.page {Page}
 * @param options.passphrase {string}
 * @returns {Promise<void>}
 */
async function loginViaForm({
  page,
  passphrase
}: {
  page: Page
  passphrase: string
}): Promise<void> {
  await expect(page).not.toHaveURL(/#\/logout/, { timeout: 30_000 })
  await page.goto('/#/login')
  await fillSettled(page.locator('input[type="password"]'), passphrase)
  await page.getByRole('button', { name: 'Log in', exact: true }).click()
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })
}

/**
 * Adds one contact through the contacts form.
 *
 * @param options {object}
 * @param options.page {Page}
 * @param options.displayName {string}
 * @returns {Promise<void>}
 */
async function addContact({
  page,
  displayName
}: {
  page: Page
  displayName: string
}): Promise<void> {
  await page.goto('/#/contacts/new')
  await fillSettled(
    page.getByLabel('Display name', { exact: true }),
    displayName
  )
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(page).toHaveURL(/#\/contacts/, { timeout: 30_000 })
  await expect(page.getByText(displayName).first()).toBeVisible({
    timeout: 30_000
  })
}

/**
 * Opens the Applications page and waits for a row to appear, remounting the
 * page (dashboard and back -- never `reload()`, which logs out) until
 * replication has pulled the popup-written rows in.
 *
 * @param options {object}
 * @param options.page {Page}
 * @param options.appName {string}
 * @returns {Promise<void>}
 */
async function openApplicationsWithApp({
  page,
  appName
}: {
  page: Page
  appName: string
}): Promise<void> {
  await expect(async () => {
    await page.goto('/#/dashboard')
    await page.goto('/#/applications')
    await expect(page.getByText(appName).first()).toBeVisible({
      timeout: 5_000
    })
  }).toPass({ timeout: 120_000 })
}

test.describe.serial('Content migration from a backup bundle', () => {
  let accountA: BrowserContext
  let pageA: Page
  let passphraseA: string
  let bundle: Uint8Array
  let identity: BundleIdentity
  const importCapture: CapturedRequest[] = []

  test.beforeAll(async ({ browser }, testInfo) => {
    test.setTimeout(600_000)
    const terminal = await coldTerminal(browser, APP_URL)
    accountA = terminal.context
    pageA = terminal.page
    await stubSaveFilePicker(pageA)
    const credentials = await signupViaWizard(pageA, testInfo)
    passphraseA = credentials.passphrase
    await addCredentialViaPaste(pageA)
    await addContact({ page: pageA, displayName: CONTACT_NAME })
    // One connected app, holding a grant of its own collection and a share of
    // A's credentials: the two authorities the import must not carry across.
    await connectViaPopup({ page: pageA, app: APP_A, passphrase: passphraseA })
    await loginViaForm({ page: pageA, passphrase: passphraseA })
    await openApplicationsWithApp({ page: pageA, appName: APP_A.name })
    bundle = await exportBundleBytes({ page: pageA })
    identity = await bundleIdentity(bundle)
    expect(identity.spaceIds.length).toBeGreaterThan(0)
    expect(identity.controller).toMatch(/^did:/)
  })

  test.afterAll(async () => {
    await accountA?.close()
  })

  test('a transient session imports another account credentials and contacts', async ({
    browser
  }, testInfo) => {
    test.setTimeout(600_000)
    const { context, page } = await coldTerminal(browser, APP_URL)
    try {
      // Account B: the credential-anchored signup, so every visit is a
      // transient session with no local replica.
      const { passphrase } = await signupViaWizard(page, testInfo, {
        rememberBrowser: false
      })
      await page.getByRole('button', { name: 'Log out' }).click()
      await expect(page).toHaveURL(/\/#?\/?$/)
      await page.goto('/#/login')
      await submitTransientLogin(page, passphrase)

      // The capture runs over the import and is asserted on by the next cell.
      const listener = captureRequests({ page, into: importCapture })
      await importBundleViaDialog({ page, bundle, passphrase: passphraseA })
      page.off('request', listener)

      // A's credential and A's contact are B's now.
      await page.goto('/#/dashboard')
      await expect(
        page.getByRole('link', { name: /E2E Test Credential/ }).first()
      ).toBeVisible({ timeout: 60_000 })
      await page.goto('/#/contacts')
      await expect(page.getByText(CONTACT_NAME).first()).toBeVisible({
        timeout: 60_000
      })
    } finally {
      await context.close()
    }
  })

  test('the import run contacts no Space of the exporting account', async () => {
    // The capture is the previous cell's: the walk reads the file alone, so
    // nothing it issued may address A's Spaces or carry A's DID.
    expectNoContactWithBundleAccount({ captured: importCapture, identity })
  })

  test('a guest session imports the same bundle with no remote storage', async ({
    browser
  }) => {
    test.setTimeout(600_000)
    const { context, page } = await coldTerminal(browser, APP_URL)
    try {
      await page.goto('/#/guest-login')
      await page.getByRole('button', { name: 'Guest Mode Log In' }).click()
      await expect(page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })

      const captured: CapturedRequest[] = []
      const listener = captureRequests({ page, into: captured })
      await importBundleViaDialog({ page, bundle, passphrase: passphraseA })
      page.off('request', listener)
      expectNoContactWithBundleAccount({ captured, identity })

      await page.goto('/#/dashboard')
      await expect(
        page.getByRole('link', { name: /E2E Test Credential/ }).first()
      ).toBeVisible({ timeout: 60_000 })
      await page.goto('/#/contacts')
      await expect(page.getByText(CONTACT_NAME).first()).toBeVisible({
        timeout: 60_000
      })
    } finally {
      await context.close()
    }
  })

  test('no grant and no share of the exporting account travels', async ({
    browser
  }, testInfo) => {
    test.setTimeout(900_000)
    const { context, page } = await coldTerminal(browser, APP_URL)
    try {
      // Account D: its own connected app, so the page surfaces under test
      // have a live row of their own to keep working on.
      const { passphrase } = await signupViaWizard(page, testInfo)
      await connectViaPopup({ page, app: APP_B, passphrase })
      await loginViaForm({ page, passphrase })
      await openApplicationsWithApp({ page, appName: APP_B.name })

      const captured: CapturedRequest[] = []
      const listener = captureRequests({ page, into: captured })
      await importBundleViaDialog({ page, bundle, passphrase: passphraseA })
      page.off('request', listener)
      expectNoContactWithBundleAccount({ captured, identity })

      // The Applications page names D's app and no app of A's.
      await openApplicationsWithApp({ page, appName: APP_B.name })
      await expect(page.getByText(APP_A.name)).toHaveCount(0)

      // The shares dialog names D's one reader and no reader of A's, and the
      // unshare completes.
      await page.goto('/#/storage')
      const sharedChip = page.getByText(/^Shared/).first()
      await expect(sharedChip).toBeVisible({ timeout: 90_000 })
      await sharedChip.click()
      const sharesDialog = page.getByRole('dialog')
      await expect(
        sharesDialog.getByRole('button', { name: 'Remove access' })
      ).toHaveCount(1)
      await expect(sharesDialog.getByText(APP_A.name)).toHaveCount(0)
      await sharesDialog.getByRole('button', { name: 'Remove access' }).click()
      await page
        .getByRole('button', { name: 'Remove access', exact: true })
        .last()
        .click()
      await expect(page.getByText('Access removed.')).toBeVisible({
        timeout: 90_000
      })

      // The disconnect completes too: no migrated row reaches its harvester.
      await page.goto('/#/applications')
      await page.getByText(APP_B.name, { exact: true }).click()
      await expect(
        page.getByRole('heading', { name: `App detail: ${APP_B.name}` })
      ).toBeVisible({ timeout: 30_000 })
      await page.getByRole('button', { name: 'Revoke App Access' }).click()
      await page
        .getByRole('button', { name: 'Revoke access', exact: true })
        .click()
      await expect(page).toHaveURL(/#\/applications$/, { timeout: 90_000 })
      await expect(page.getByText(/App (access revoked|removed)/)).toBeVisible({
        timeout: 30_000
      })
      await expect(
        page.getByText('No connected applications yet.')
      ).toBeVisible({ timeout: 30_000 })
    } finally {
      await context.close()
    }
  })
})
