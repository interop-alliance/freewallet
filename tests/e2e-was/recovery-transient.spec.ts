/**
 * The TRANSIENT recovery posture cell, pinned end to end: recovering on a
 * cold terminal WITHOUT the remember seam runs the default (transient)
 * variant -- the add-and-retire entry publishes the fresh credential's
 * ladder VM in place of a durable client, a fresh annex generation is
 * minted and pointed, the mandatory rotation seals the spent code out, and
 * the visit continues as an ordinary transient session that leaves zero
 * local residue. A later cold visit then logs in transient with nothing but
 * the recovered passphrase, proving the ceremony's records (bridge, sibling,
 * generation, roster wrap) are coherent.
 *
 * The last cell spends the replacement code with the roster append torn: it
 * pins the write ORDER the ceremony promises -- every annex write lands
 * before the add-and-retire entry, and the mandatory rotation's append is
 * the very next mutating request after it -- so the window in which the
 * typed code is dead and the new credential holds no wrap is the append
 * alone.
 *
 * The DURABLE (remembered) recovery cell is pinned in `recovery.spec.ts`.
 */
import { test, expect, type Browser, type Page } from '@playwright/test'
import {
  defaultWebvhLogVerifier,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import { delegatedClientsPointer } from '@interop/wallet-core/clientAnnex'
import { fillSettled, signupViaWizard } from './helpers'
import {
  captureLocalStorageKeys,
  expectNoStorageResidue
} from '../shared/storageResidue'

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

const NEW_PASSPHRASE = 'Recovered-transient-42!'
const TORN_PASSPHRASE = 'Torn-transient-43!'

/**
 * The annex generation an account document currently points at, read the way
 * every reader must: dispatching on the type IRI, never on the entry's
 * fragment (the byoe service-entry convention).
 *
 * @param doc {object | null | undefined}   a resolved account document
 * @returns {string | undefined}
 */
function delegatedClientsPointerOf(doc: object | null | undefined) {
  if (!doc) {
    return undefined
  }
  return delegatedClientsPointer({
    doc: doc as Parameters<typeof delegatedClientsPointer>[0]['doc']
  })
}

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
  let replacementCode: string
  let logUrl: string
  let entriesAfterIssuance: number
  let generationBeforeRecovery: string | undefined

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
      const issuedLog = readLogFromString(
        await (await page.request.get(logUrl)).text()
      )
      entriesAfterIssuance = issuedLog.length
      // The pre-recovery generation, so the assertion below can tell a moved
      // pointer from a merely present one.
      generationBeforeRecovery = delegatedClientsPointerOf(
        (
          await resolveDIDFromLog(issuedLog, {
            verifier: defaultWebvhLogVerifier
          })
        ).doc
      )
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
      replacementCode = replacement
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

      // The account log shape: the continuation added exactly two entries
      // (reveal-and-commit, then the add-and-retire that carries the
      // `#DelegatedClients` pointer with it) and the extended log fully
      // verifies.
      const logText = await (await page.request.get(logUrl)).text()
      const log = readLogFromString(logText)
      expect(log).toHaveLength(entriesAfterIssuance + 2)
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
      // The FRESH annex generation is pointed, by the add-and-retire entry
      // itself -- a pointer still naming the pre-recovery generation is the
      // stranding this ordering exists to prevent, so the value is compared,
      // not merely the entry's presence.
      const pointed = delegatedClientsPointerOf(resolved.doc)
      expect(pointed).toBeDefined()
      expect(pointed).not.toBe(generationBeforeRecovery)
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

  test('the roster append is the first write after the add-and-retire entry', async ({
    browser
  }) => {
    test.setTimeout(240_000)
    const { context, page } = await coldTerminal(browser)
    try {
      // Every mutating request the ceremony makes, in order (preflights and
      // reads excluded); aborted requests are recorded too.
      const writes: Array<{ method: string; pathname: string }> = []
      page.on('request', request => {
        const method = request.method()
        if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
          return
        }
        writes.push({ method, pathname: new URL(request.url()).pathname })
      })
      // The tear: the roster append itself fails. Reads of the roster log
      // pass through untouched.
      const isRosterLog = (url: URL) =>
        url.pathname.endsWith('/key-map/user-key.jsonl')
      await page.route(isRosterLog, async route => {
        if (route.request().method() === 'PUT') {
          await route.abort('failed')
          return
        }
        await route.continue()
      })

      await page.goto('/#/recover')
      await fillSettled(
        page.locator('input[name="recovery-code"]'),
        replacementCode
      )
      await page
        .getByRole('button', { name: 'Check code', exact: true })
        .click()
      await expect(
        page.getByText('Found a wallet account', { exact: false })
      ).toBeVisible({ timeout: 30_000 })
      await fillSettled(
        page.locator('input[id="new-passphrase"]'),
        TORN_PASSPHRASE
      )
      await page
        .getByRole('button', { name: 'Recover wallet', exact: true })
        .click()
      // The ceremony fails at the append and says so; nothing after it runs.
      await expect(
        page
          .getByRole('alert')
          .filter({ hasText: /Recovery failed|could not be reached/ })
      ).toBeVisible({ timeout: 120_000 })

      const accountLogPath = new URL(logUrl).pathname
      const accountLogWrites = writes
        .map((write, index) => ({ ...write, index }))
        .filter(
          write => write.method === 'PUT' && write.pathname === accountLogPath
        )
      // The continuation's two entries: reveal-and-commit, add-and-retire.
      expect(accountLogWrites).toHaveLength(2)
      const addAndRetire = accountLogWrites[1]!.index
      // Every annex write -- the generation genesis, its delegation embed,
      // the visit key's enrollment -- precedes the add-and-retire entry.
      const annexLogWrites = writes
        .map((write, index) => ({ ...write, index }))
        .filter(
          write =>
            write.pathname.endsWith('/did.jsonl') &&
            write.pathname !== accountLogPath
        )
      expect(annexLogWrites.length).toBeGreaterThan(0)
      for (const write of annexLogWrites) {
        expect(write.index).toBeLessThan(addAndRetire)
      }
      // The roster append is the very next mutating request after the entry
      // -- the one the tear aborted -- and nothing else is written after
      // it: every later write is a re-attempt of that same append.
      const afterEntry = writes.slice(addAndRetire + 1)
      expect(afterEntry.length).toBeGreaterThan(0)
      for (const write of afterEntry) {
        expect(write.method).toBe('PUT')
        expect(write.pathname.endsWith('/key-map/user-key.jsonl')).toBe(true)
      }
    } finally {
      await context.close()
    }
  })
})
