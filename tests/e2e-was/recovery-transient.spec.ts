/**
 * The TRANSIENT recovery posture cell, pinned end to end: recovering on a
 * cold terminal WITHOUT the remember seam runs the default (transient)
 * variant -- the add-and-retire entry publishes the fresh credential's
 * ladder VM in place of a durable client, a fresh companion generation is
 * minted and pointed, the mandatory rotation seals the spent code out, and
 * the visit continues as an ordinary transient session that leaves zero
 * local residue. A later cold visit then logs in transient with nothing but
 * the recovered passphrase, proving the ceremony's records (bridge, sibling,
 * generation, roster wrap) are coherent.
 *
 * The DURABLE (remembered) recovery cell is pinned in `recovery.spec.ts`.
 */
import { test, expect, type Browser, type Page } from '@playwright/test'
import {
  defaultWebvhLogVerifier,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import { fillSettled, signupViaWizard } from './helpers'
import {
  captureLocalStorageKeys,
  expectNoStorageResidue
} from '../shared/storageResidue'

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

const NEW_PASSPHRASE = 'Recovered-transient-42!'

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
 * Logs out via the logout route and waits for its deferred redirect to the
 * landing page to land (see `recovery.spec.ts` for why the wait matters).
 */
async function logOut(page: Page) {
  await page.goto('/#/logout')
  await expect(page).toHaveURL(/#\/$/, { timeout: 15_000 })
}

test.describe.serial('transient recovery (the recovery posture cell)', () => {
  let code: string
  let logUrl: string
  let entriesAfterIssuance: number

  test.beforeAll(async ({ browser }, testInfo) => {
    test.setTimeout(240_000)
    // The account fixture: a durable signup (the welcome credential is an
    // encrypted write sealed under the pre-recovery user key), a re-login
    // (issuance gates on the promoted pointer recovered from the keyring),
    // and a recovery code issued from Settings. The setup context is durable
    // on purpose and simply discarded.
    const context = await browser.newContext({ baseURL: APP_URL })
    try {
      const page = await context.newPage()
      const { passphrase } = await signupViaWizard(page, testInfo)
      await expect(
        page.getByRole('link', { name: 'Your First Credential' })
      ).toBeVisible({ timeout: 20_000 })
      await logOut(page)
      await page.goto('/#/login')
      await fillSettled(page.locator('input[type="password"]'), passphrase)
      await page.getByRole('button', { name: 'Log in', exact: true }).click()
      await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })

      await page.goto('/#/settings')
      await expect(page.getByText('Published did:webvh DID')).toBeVisible()
      const logLink = page.getByRole('link', { name: /did\.jsonl$/ })
      await expect(logLink).toBeVisible({ timeout: 30_000 })
      logUrl = (await logLink.getAttribute('href'))!

      const generateButton = page.getByRole('button', {
        name: 'Generate recovery code'
      })
      await expect(generateButton).toBeEnabled({ timeout: 30_000 })
      await generateButton.click()
      await expect(
        page.getByText('This code is shown only once', { exact: false })
      ).toBeVisible()
      code = (await page.locator('code').textContent()) ?? ''
      await page.getByRole('button', { name: 'I saved this code' }).click()
      await expect(page.getByText('Recovery code 1')).toBeVisible({
        timeout: 60_000
      })
      entriesAfterIssuance = readLogFromString(
        await (await page.request.get(logUrl)).text()
      ).length
    } finally {
      await context.close()
    }
  })

  test('recovering on a cold terminal lands client-less and residue-zero', async ({
    browser
  }) => {
    test.setTimeout(360_000)
    const { context, page } = await coldTerminal(browser)
    try {
      // Deliberately no remember seam: the default posture is the transient
      // variant. The localStorage baseline is captured before any input.
      await page.goto('/#/recover')
      const baseline = await captureLocalStorageKeys({ page })

      await fillSettled(page.locator('input[name="recovery-code"]'), code)
      await page
        .getByRole('button', { name: 'Check code', exact: true })
        .click()
      await expect(
        page.getByText('Found a wallet account', { exact: false })
      ).toBeVisible({ timeout: 30_000 })

      await fillSettled(
        page.locator('input[id="new-passphrase"]'),
        NEW_PASSPHRASE
      )
      await page
        .getByRole('button', { name: 'Recover wallet', exact: true })
        .click()
      await expect(
        page.getByText('Your wallet was recovered', { exact: false })
      ).toBeVisible({ timeout: 120_000 })

      // The replacement code is pushed hard, then the login lands the
      // ordinary transient composition.
      const replacement =
        (await page.getByTestId('replacement-recovery-code').textContent()) ??
        ''
      expect(replacement).toMatch(
        /^[1-9A-HJ-NP-Za-km-z]{4}(-[1-9A-HJ-NP-Za-km-z]{1,4})+$/
      )
      expect(replacement).not.toBe(code)
      const loginButton = page.getByRole('button', {
        name: 'Log in to your wallet'
      })
      await expect(loginButton).toBeDisabled()
      await page.getByRole('button', { name: 'I saved the new code' }).click()
      await loginButton.click()
      await expect(page).toHaveURL(/#\/dashboard/, { timeout: 60_000 })

      // The transient session decrypts pre-recovery history across the
      // mandatory rotation: the welcome credential renders via the escrowed
      // wraps of the fresh credential's standing roster entry.
      await expect(
        page.getByRole('link', { name: 'Your First Credential' })
      ).toBeVisible({ timeout: 30_000 })

      // The spent code fails afterwards, with wording distinct from "wrong
      // code": its unlock Space is gone and its posture left the document.
      await logOut(page)
      await page.goto('/#/recover')
      await fillSettled(page.locator('input[name="recovery-code"]'), code)
      await page
        .getByRole('button', { name: 'Check code', exact: true })
        .click()
      await expect(
        page.getByText(
          /No wallet was found for this recovery code|has been revoked or already used/
        )
      ).toBeVisible({ timeout: 30_000 })

      // Zero local residue: no IndexedDB database, no new localStorage key,
      // an empty sessionStorage -- the whole ceremony included, not just the
      // session (the locate step's chain-head pin rides in memory too).
      await expectNoStorageResidue({
        page,
        baselineLocalStorageKeys: baseline
      })

      // The account log shape: the continuation added exactly three entries
      // (reveal-and-commit, add-and-retire, the `#DelegatedClients`
      // re-point) and the extended log fully verifies.
      const logText = await (await page.request.get(logUrl)).text()
      const log = readLogFromString(logText)
      expect(log).toHaveLength(entriesAfterIssuance + 3)
      const resolved = await resolveDIDFromLog(log, {
        verifier: defaultWebvhLogVerifier
      })
      expect(resolved.meta.error).toBeUndefined()
      // Update authority: the original durable client plus the fresh
      // credential's ladder rung 0 -- the spent code's key does not stand.
      expect(resolved.meta.updateKeys).toHaveLength(2)
      // NO new durable client was minted anywhere: the original client's
      // signing key stays the only `capabilityInvocation` entry, and the
      // ladder VM stands under `assertionMethod` and `capabilityDelegation`
      // only.
      expect(resolved.doc?.capabilityInvocation).toHaveLength(1)
      const assertion = (resolved.doc?.assertionMethod ?? []) as string[]
      const delegationRelation = (resolved.doc?.capabilityDelegation ??
        []) as string[]
      const authentication = (resolved.doc?.authentication ?? []) as string[]
      const ladderVms = delegationRelation.filter(
        id => !authentication.includes(id)
      )
      expect(ladderVms).toHaveLength(1)
      expect(assertion).toContain(ladderVms[0])
      // keyAgreement: the original client's key, the original passphrase's
      // commitment, the replacement code's key, and the recovered
      // passphrase's commitment -- the spent code's key is gone.
      expect(resolved.doc?.keyAgreement).toHaveLength(4)
      // The fresh companion generation is pointed. Dispatch on the type IRI,
      // per the byoe service-entry convention (the fragment is non-semantic).
      const services = (resolved.doc?.service ?? []) as {
        id?: string
        type?: string | string[]
      }[]
      expect(
        services.some(entry =>
          (Array.isArray(entry.type) ? entry.type : [entry.type]).includes(
            'https://w3id.org/byoe#DelegatedClients'
          )
        )
      ).toBe(true)
    } finally {
      await context.close()
    }
  })

  test('a later cold visit logs in transient with the recovered passphrase', async ({
    browser
  }) => {
    test.setTimeout(240_000)
    const { context, page } = await coldTerminal(browser)
    try {
      await page.goto('/#/login')
      const baseline = await captureLocalStorageKeys({ page })
      await fillSettled(page.locator('input[type="password"]'), NEW_PASSPHRASE)
      await page.getByRole('button', { name: 'Log in', exact: true }).click()
      await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })
      await expect(
        page.getByRole('link', { name: 'Your First Credential' })
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
