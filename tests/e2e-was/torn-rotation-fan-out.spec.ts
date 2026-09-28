/**
 * A user key rotation torn mid-fan-out on a credential-anchored account, and
 * the transient login that completes it.
 *
 * The account is the default signup (no remember seam), so every visit is a
 * transient session and no remembered login, with its cascade-completion
 * sweep, ever runs. The rotating ceremony is the passphrase change from a
 * transient session: it rotates the roster, then re-epochs every encrypted
 * collection onto the fresh user key. The tear is at the network: the
 * governing-log appends of two collections are aborted, so the roster's
 * rotation lands, the rest of the fan-out lands, and those two collections'
 * current epochs stay on the retired user key generation. That is the same
 * durable state a tab death mid-fan-out leaves, reached with no app seam.
 *
 * A cold transient login with the new passphrase must then complete the
 * rotation: its mender block's first registration re-epochs the stranded
 * collections onto the roster's current generation. A second cold login
 * finds nothing stale and appends to no collection log.
 *
 * The roster and the collection logs are capability-gated, so the
 * assertions read the teaching server's FileSystem backend off disk
 * (`storedLogs.ts`).
 */
import { test, expect } from '@playwright/test'
import {
  addCredentialViaPaste,
  awaitLoginChain,
  coldTerminal,
  fillSettled,
  sessionSpaceId,
  signupViaWizard,
  submitTransientLogin
} from './helpers'
import { readCollectionEpoch, readUserKeyRoster } from './storedLogs'

// Matches `playwright.was.config.ts` (APP_PORT). Manually created contexts do
// not inherit the config's `use.baseURL`, so pass it explicitly.
const APP_URL = 'http://localhost:5274'

// The encrypted standard collections every signup provisions.
const ENCRYPTED_COLLECTIONS = [
  'private-credentials',
  'wallet-activity',
  'contacts',
  'contacts-history',
  'app-connections'
]

// The collections whose rotation the tear aborts. The others rotate, so the
// tear is partial.
const TORN_COLLECTIONS = ['wallet-activity', 'contacts']

/**
 * Every encrypted collection's stored epoch state, keyed by collection id.
 *
 * @param spaceId {string}
 * @returns {Promise<Record<string, Awaited<ReturnType<typeof readCollectionEpoch>>>>}
 */
async function readCollectionEpochs(spaceId: string) {
  const epochs: Record<
    string,
    Awaited<ReturnType<typeof readCollectionEpoch>>
  > = {}
  for (const collectionId of ENCRYPTED_COLLECTIONS) {
    epochs[collectionId] = await readCollectionEpoch({ spaceId, collectionId })
  }
  return epochs
}

test.describe.serial('a user key rotation torn mid-fan-out', () => {
  let newPassphrase: string
  let spaceId: string
  let retiredGeneration: string
  let currentGeneration: string

  test('the passphrase change lands the roster and strands two collections', async ({
    browser
  }, testInfo) => {
    test.setTimeout(360_000)
    const { context, page } = await coldTerminal(browser, APP_URL)
    try {
      const user = await signupViaWizard(page, testInfo, {
        rememberBrowser: false
      })
      // A credential sealed under the pre-change user key, which the
      // rotation's escrow must keep readable.
      await addCredentialViaPaste(page)
      spaceId = await sessionSpaceId(page)
      const rosterBefore = await readUserKeyRoster({ spaceId })
      retiredGeneration = rosterBefore.currentEpoch!
      expect(retiredGeneration).toBeTruthy()
      const before = await readCollectionEpochs(spaceId)
      for (const collectionId of ENCRYPTED_COLLECTIONS) {
        expect(
          before[collectionId]!.generations,
          `${collectionId} starts on the signup's user key`
        ).toContain(retiredGeneration)
      }

      // The tear: every append to the torn collections' governing logs is
      // aborted. Reads pass through, and so do every other collection's
      // appends and the roster's.
      const isTornLog = (url: URL) =>
        TORN_COLLECTIONS.some(collectionId =>
          url.pathname.endsWith(`/${collectionId}/meta/log`)
        )
      await page.route(isTornLog, async route => {
        if (route.request().method() === 'PUT') {
          await route.abort('failed')
          return
        }
        await route.continue()
      })

      newPassphrase = `Torn-fan-out-${Date.now()}-Zz9!`
      await page.goto('/#/settings')
      await expect(
        page.getByRole('heading', { name: 'Passphrase', exact: true })
      ).toBeVisible()
      await fillSettled(
        page.getByLabel('Current passphrase', { exact: true }),
        user.passphrase
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
      // The fan-out is best-effort per collection, so the ceremony reports
      // the rotation even though two collections stayed behind.
      await expect(
        page.getByText('Your content keys were rotated', { exact: false })
      ).toBeVisible({ timeout: 180_000 })
    } finally {
      // Closed straight away: this visit runs no login chain again, so the
      // stranded collections stay stranded until the next login.
      await context.close()
    }

    // The roster's rotation landed: one more generation, and the current one
    // moved.
    const rosterAfter = await readUserKeyRoster({ spaceId })
    currentGeneration = rosterAfter.currentEpoch!
    expect(currentGeneration).not.toBe(retiredGeneration)
    expect(rosterAfter.epochIds).toContain(retiredGeneration)

    // The tear held: the torn collections' current epochs still name the
    // retired generation and not the current one, and the rest rotated.
    const after = await readCollectionEpochs(spaceId)
    for (const collectionId of ENCRYPTED_COLLECTIONS) {
      const { generations } = after[collectionId]!
      if (TORN_COLLECTIONS.includes(collectionId)) {
        expect(generations, `${collectionId} is stranded`).toContain(
          retiredGeneration
        )
        expect(generations).not.toContain(currentGeneration)
      } else {
        expect(generations, `${collectionId} rotated`).toContain(
          currentGeneration
        )
        expect(generations).not.toContain(retiredGeneration)
      }
    }
  })

  test('a cold transient login re-epochs the stranded collections', async ({
    browser
  }) => {
    test.setTimeout(240_000)
    const { context, page } = await coldTerminal(browser, APP_URL)
    try {
      await page.goto('/#/login')
      await submitTransientLogin(page, newPassphrase)
      await awaitLoginChain(page)
      // The credential stored before the change still decrypts.
      await expect(
        page.getByRole('link', { name: 'E2E Test Credential' })
      ).toBeVisible({ timeout: 30_000 })
    } finally {
      await context.close()
    }

    // The mend was a collection fan-out, not a second rotation: the roster's
    // current generation is unchanged.
    expect((await readUserKeyRoster({ spaceId })).currentEpoch).toBe(
      currentGeneration
    )
    const mended = await readCollectionEpochs(spaceId)
    for (const collectionId of ENCRYPTED_COLLECTIONS) {
      const { generations } = mended[collectionId]!
      expect(
        generations,
        `${collectionId} names the current generation`
      ).toContain(currentGeneration)
      expect(generations).not.toContain(retiredGeneration)
    }
  })

  test('a second cold transient login appends to no collection log', async ({
    browser
  }) => {
    test.setTimeout(240_000)
    const before = await readCollectionEpochs(spaceId)
    const { context, page } = await coldTerminal(browser, APP_URL)
    try {
      await page.goto('/#/login')
      await submitTransientLogin(page, newPassphrase)
      await awaitLoginChain(page)
    } finally {
      await context.close()
    }
    const after = await readCollectionEpochs(spaceId)
    for (const collectionId of ENCRYPTED_COLLECTIONS) {
      expect(
        after[collectionId]!.entries,
        `${collectionId} took no append`
      ).toBe(before[collectionId]!.entries)
      expect(after[collectionId]!.currentEpoch).toBe(
        before[collectionId]!.currentEpoch
      )
    }
  })
})
