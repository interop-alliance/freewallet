import {
  addCredentialViaPaste,
  collectionRow,
  deleteCredential,
  expectQuotaCard,
  goToStorage,
  readCollectionUsageBytes,
  sessionSpaceId,
  signupViaWizard,
  usageBytesOfRow
} from './helpers'
import { listStoredResourceIds } from '../shared/storedLogs'
import { WAS_E2E_DATA_DIR } from './wasDataDir'
import { test, expect } from '../shared/consoleCapture'

// Background replication pushes a local write a beat after the wallet-side
// action, so a usage figure is polled until the server's measurement moves.
const USAGE_POLL = { timeout: 60_000, intervals: [1000, 2000, 5000] }

/**
 * Storage quota UI — requires remote (PWS) mode; see playwright.was.config.ts.
 * The teaching server reports an unlimited filesystem backend by default.
 */
test.describe('Storage quota', () => {
  test('shows usage summary for a connected remote space', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await goToStorage(page)
    await expectQuotaCard(page)

    await expect(page.getByText('OK', { exact: true })).toBeVisible()
    await expect(page.getByText('Unlimited')).toBeVisible()
    await expect(page.getByText('Server Filesystem')).toBeVisible()
    await expect(page.getByText(/^Measured /)).toBeVisible()
  })

  test('lists wallet collections in the usage breakdown', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await goToStorage(page)
    await expectQuotaCard(page)

    // Per-collection usage renders as rows in the collections browser below the
    // aggregate card. Target each collection by its storage-path href, which is
    // unambiguous (matching display names by text is not: "Verifiable
    // Credentials" is a prefix of "Verifiable Credentials (Publicly Shared)").
    for (const collectionId of [
      'private-credentials',
      'wallet-activity',
      'public-credentials'
    ]) {
      await expect(collectionRow(page, collectionId)).toBeVisible()
    }

    // Every listed row carries its usage figure from the quota report's
    // per-collection breakdown, not only its name. The listing and the quota
    // report load side by side, so the figures are polled in.
    const rows = page.locator('a[href*="/storage/collections/"]')
    await expect(async () => {
      const rowTexts = await rows.allTextContents()
      expect(rowTexts.length).toBeGreaterThanOrEqual(3)
      for (const rowText of rowTexts) {
        expect(usageBytesOfRow(rowText), `usage on "${rowText}"`).toBeDefined()
      }
    }).toPass({ timeout: 15_000 })
  })

  test('keeps import enabled when storage is healthy', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await goToStorage(page)
    await expectQuotaCard(page)

    // The Import action links to the Import page, whose file picker is the
    // control the quota gates.
    await page.getByRole('link', { name: 'Import (Load) from Backup' }).click()
    await expect(page).toHaveURL(/\/storage\/import$/)
    await expectQuotaCard(page)
    // The loading-capable MUI Button renders nested elements that both expose
    // the button role and the same accessible name, so scope to the first.
    await expect(
      page.getByRole('button', { name: 'Choose archive' }).first()
    ).toBeEnabled()
  })

  test('updates verifiable credentials usage after storing a credential', async ({
    page
  }, testInfo) => {
    test.slow()
    await signupViaWizard(page, testInfo)
    const spaceId = await sessionSpaceId(page)
    // Signup already stored the welcome credential, so the figure is read
    // once that one has reached the server, as the baseline the new
    // credential has to move.
    await expectStoredResourceCount({
      spaceId,
      collectionId: 'private-credentials',
      count: 1
    })
    const before = await readCollectionUsageBytes(page, 'private-credentials')

    await page.goto('/#/dashboard')
    await addCredentialViaPaste(page)

    await expect
      .poll(
        async () => await readCollectionUsageBytes(page, 'private-credentials'),
        USAGE_POLL
      )
      .toBeGreaterThan(before)
  })

  test('updates wallet activity usage after deleting a credential', async ({
    page
  }, testInfo) => {
    test.slow()
    await signupViaWizard(page, testInfo)
    const spaceId = await sessionSpaceId(page)
    // The signup's own activity rows have reached the server once the
    // stored count holds still, and the store adds exactly one more.
    const afterSignup = await settledStoredResourceCount({
      spaceId,
      collectionId: 'wallet-activity'
    })
    await page.goto('/#/dashboard')
    await addCredentialViaPaste(page)
    await expectStoredResourceCount({
      spaceId,
      collectionId: 'wallet-activity',
      count: afterSignup + 1
    })
    // The baseline: every activity before the delete is on the server.
    const before = await readCollectionUsageBytes(page, 'wallet-activity')

    await page.goto('/#/dashboard')
    await deleteCredential(page)

    await expect
      .poll(
        async () => await readCollectionUsageBytes(page, 'wallet-activity'),
        USAGE_POLL
      )
      .toBeGreaterThan(before)
  })
})

/**
 * Polls the server's store until one of the account Space's collections
 * holds exactly `count` resources.
 *
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param options.count {number}
 * @returns {Promise<void>}
 */
async function expectStoredResourceCount({
  spaceId,
  collectionId,
  count
}: {
  spaceId: string
  collectionId: string
  count: number
}): Promise<void> {
  await expect
    .poll(
      async () =>
        (
          await listStoredResourceIds({
            dataDir: WAS_E2E_DATA_DIR,
            spaceId,
            collectionId
          })
        ).length,
      USAGE_POLL
    )
    .toBe(count)
}

/**
 * The number of resources one of the account Space's collections holds on
 * the server, once background replication has stopped moving it: two reads
 * a few seconds apart agree, on a collection that is not empty.
 *
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @returns {Promise<number>}
 */
async function settledStoredResourceCount({
  spaceId,
  collectionId
}: {
  spaceId: string
  collectionId: string
}): Promise<number> {
  let settled = 0
  await expect(async () => {
    const first = (
      await listStoredResourceIds({
        dataDir: WAS_E2E_DATA_DIR,
        spaceId,
        collectionId
      })
    ).length
    await new Promise(resolve => setTimeout(resolve, 3_000))
    const second = (
      await listStoredResourceIds({
        dataDir: WAS_E2E_DATA_DIR,
        spaceId,
        collectionId
      })
    ).length
    expect(first).toBeGreaterThan(0)
    expect(second).toBe(first)
    settled = second
  }).toPass({ timeout: 60_000 })
  return settled
}
