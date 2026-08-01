import { test, expect, type Page } from '@playwright/test'
import {
  fillSettled,
  signupViaWizard,
  goToHistory,
  expectHistoryEntry,
  E2E_TEST_CREDENTIAL
} from './helpers'

/**
 * WAS-backed E2E for the CHAPI "store" flow end-to-end: a credential accepted
 * through the `/wallet/store` popup must land in the remote WAS Space through
 * the remote-direct popup storage path (the popup's own IndexedDB is a
 * third-party partitioned bucket no sync controller drives), and then appear in
 * the main app's wallet once background replication pulls it. This is the exact
 * scenario that was broken until the remote-direct fix: without it a credential
 * stored in the popup was stranded in a partitioned bucket the main app never
 * reads.
 *
 * Like the other CHAPI specs, this drives the non-production injected-event
 * seam (`window.__E2E_CHAPI_STORE_EVENT__`) so no mediator handshake is
 * involved. Same-origin popup entry is enough here: partitioning itself cannot
 * be reproduced in-test, and what this spec verifies is the remote-direct write
 * plus the replication pull, not the Storage Access API recognition (that lives
 * in `chapi-saved-session.spec.ts`).
 */

type InjectedResponse = { value: unknown } | undefined

/**
 * Injects a ready-made CHAPI store event carrying an inline offer (a VP wrapping
 * one test VC) before every document in the page loads, with a `respondWith`
 * that records the response payload for later assertion.
 */
async function injectStoreEvent(page: Page, credential: unknown) {
  await page.addInitScript((offeredCredential: unknown) => {
    const win = window as unknown as {
      __E2E_CHAPI_STORE_EVENT__?: unknown
      __E2E_CHAPI_RESPONSE__?: { value: unknown }
    }
    win.__E2E_CHAPI_RESPONSE__ = undefined
    win.__E2E_CHAPI_STORE_EVENT__ = {
      credentialRequestOrigin: 'https://issuer.example',
      credential: {
        dataType: 'VerifiablePresentation',
        data: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiablePresentation'],
          verifiableCredential: [offeredCredential]
        }
      },
      respondWith(promise: Promise<unknown>) {
        Promise.resolve(promise).then(value => {
          win.__E2E_CHAPI_RESPONSE__ = { value: value ?? null }
        })
      }
    }
  }, credential)
}

function readResponse(page: Page): Promise<InjectedResponse> {
  return page.evaluate(
    () =>
      (window as unknown as { __E2E_CHAPI_RESPONSE__?: { value: unknown } })
        .__E2E_CHAPI_RESPONSE__
  )
}

test('a credential stored via the CHAPI popup lands in the wallet and history', async ({
  page
}, testInfo) => {
  // 1. A top-level signup provisions the remote WAS Space and its collections.
  const { passphrase } = await signupViaWizard(page, testInfo)

  // 2. Enter the store popup with an injected inline offer. The reload lets the
  // context init script install the event before the popup page reads it.
  await injectStoreEvent(page, E2E_TEST_CREDENTIAL)
  await page.goto('/#/wallet/store')
  await page.reload()

  // 3. Log in with the passphrase; the popup reaches the confirm screen, which
  // summarizes the offered credential.
  await fillSettled(page.locator('input[type="password"]'), passphrase)
  await page.getByRole('button', { name: 'Continue', exact: true }).click()
  await expect(page.getByText('E2E Test Credential')).toBeVisible({
    timeout: 30_000
  })

  // Store writes remote-direct to the WAS `private-credentials` collection.
  await page.getByRole('button', { name: 'Store', exact: true }).click()
  await expect(page.getByText(/stored successfully/i)).toBeVisible({
    timeout: 30_000
  })

  // Done echoes the stored presentation back to the (inline-offer) issuer.
  await page.getByRole('button', { name: 'Done', exact: true }).click()
  await expect
    .poll(async () => (await readResponse(page)) !== undefined, {
      timeout: 15_000
    })
    .toBe(true)

  const response = (await readResponse(page)) as { value: unknown }
  const payload = response.value as {
    dataType: string
    data: { verifiableCredential: Array<{ name: string }> }
  }
  expect(payload.dataType).toBe('VerifiablePresentation')
  expect(payload.data.verifiableCredential[0].name).toBe('E2E Test Credential')

  // 4. Back in the main app: log in, then let background replication pull the
  // remote-direct write into the local active replica. The Sync button kicks an
  // immediate replication cycle and reloads the list; poll it until the pulled
  // credential's card shows up (replication is asynchronous).
  await page.goto('/#/login')
  await fillSettled(page.locator('input[type="password"]'), passphrase)
  await page.getByRole('button', { name: 'Log in', exact: true }).click()
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })

  const card = page.getByRole('link', { name: 'E2E Test Credential' })
  await expect(async () => {
    await page.getByRole('button', { name: 'Sync' }).click()
    await expect(card).toBeVisible({ timeout: 5_000 })
  }).toPass({ timeout: 60_000 })

  // The card links to /credential/<cid>; the cid is what the credential-created
  // history summary keys on, so read it here to assert the popup credential's
  // own entry (signup self-issues a credential too, so a bare "Credential
  // created:" match is ambiguous).
  const href = await card.getAttribute('href')
  const cid = href!.split('/credential/')[1]

  // 5. History shows the credential-created entry recorded on the remote-direct
  // insert, pulled by the same replication.
  await goToHistory(page)
  await expectHistoryEntry(page, `Credential created: ${cid}`)
})
