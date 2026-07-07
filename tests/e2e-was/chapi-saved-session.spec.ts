import { test, expect, type Frame, type Page } from '@playwright/test'
import { signupViaWizard } from './helpers'

/**
 * The CHAPI popup saved-login flow (the popup half of refresh-surviving
 * sessions) end-to-end in real Chromium:
 *
 * 1. A top-level signup persists the delegated session (session key +
 *    zcaps) in the wallet origin's first-party IndexedDB.
 * 2. `/wallet/get` is then loaded as a THIRD-PARTY iframe under a
 *    cross-site top level (`embed-harness.html` on 127.0.0.1 embedding
 *    localhost -- the authn.io mediator popup shape), where the global
 *    IndexedDB is a partitioned bucket that holds no session.
 * 3. With the `storage-access` permission granted (what a user clicking
 *    "Allow" on Chrome's prompt produces -- granted browser-wide here
 *    because Chrome double-keys the permission by embedded origin +
 *    top-level site), the SavedSessionNotice reaches the first-party
 *    bucket through the Storage Access API beyond-cookies handle and
 *    recognizes the user.
 * 4. The passphrase login still completes the operation (vault decrypt
 *    needs the KAK until DIDAuth moves to a KMS-held key).
 *
 * The CHAPI request event arrives through the non-production
 * `__E2E_CHAPI_GET_EVENT__` seam (context init scripts run in iframes too);
 * no mediator handshake is involved.
 */

const APP_PORT = 5274
const WALLET = `http://localhost:${APP_PORT}`
const HARNESS_URL =
  `http://127.0.0.1:${APP_PORT}/embed-harness.html?src=` +
  encodeURIComponent(`${WALLET}/#/wallet/get`)

/**
 * Injects a canned `QueryByExample` (kind `'vc'`) CHAPI get event before
 * every document in the context loads, iframes included.
 */
async function injectVcGetEvent(page: Page) {
  await page.context().addInitScript(() => {
    const win = window as unknown as { __E2E_CHAPI_GET_EVENT__?: unknown }
    win.__E2E_CHAPI_GET_EVENT__ = {
      credentialRequestOrigin: 'https://verifier.example',
      credentialRequestOptions: {
        web: {
          VerifiablePresentation: {
            query: [
              {
                type: 'QueryByExample',
                credentialQuery: {
                  reason: 'Saved-login e2e',
                  example: { type: ['VerifiableCredential'] }
                }
              }
            ]
          }
        }
      },
      respondWith() {}
    }
  })
}

/**
 * Waits until the persisted-session record has landed in the wallet
 * origin's first-party IndexedDB (persistDelegatedSession runs
 * fire-and-forget after login). Polls without ever creating the database:
 * an `indexedDB.open` from the test before the app's own could otherwise
 * mint a version-1 database with no object store.
 */
async function waitForPersistedSession(page: Page) {
  await page.waitForFunction(async () => {
    const databases = await indexedDB.databases()
    if (!databases.some(db => db.name === 'freewallet-session')) {
      return false
    }
    return await new Promise<boolean>(resolve => {
      const request = indexedDB.open('freewallet-session', 1)
      request.onerror = () => resolve(false)
      request.onsuccess = () => {
        const db = request.result
        try {
          const get = db
            .transaction('session', 'readonly')
            .objectStore('session')
            .get('record')
          get.onsuccess = () => {
            db.close()
            resolve(get.result != null)
          }
          get.onerror = () => {
            db.close()
            resolve(false)
          }
        } catch {
          db.close()
          resolve(false)
        }
      }
    })
  })
}

function walletFrame(page: Page): Frame {
  const frame = page
    .frames()
    .find(candidate => candidate.url().startsWith(WALLET))
  expect(frame, 'the harness must embed the wallet').toBeTruthy()
  return frame!
}

test('a cross-site popup recognizes the saved login via the storage-access handle', async ({
  page,
  context
}, testInfo) => {
  // The user already clicked "Allow" on Chrome's storage-access prompt.
  await context.grantPermissions(['storage-access'])
  await injectVcGetEvent(page)

  // 1. Top-level signup on the wallet origin persists the delegated session.
  const { passphrase, email } = await signupViaWizard(page, testInfo)
  await waitForPersistedSession(page)

  // 2. Load /wallet/get as a third-party iframe under a cross-site top level.
  await page.goto(HARNESS_URL)
  const frame = walletFrame(page)

  // 3. The notice recognizes the user -- silently when Chrome honors the
  // prior grant without a gesture, else after the button click.
  const restored = frame.getByText(`Signed in as ${email}`)
  const useSaved = frame.getByRole('button', { name: 'Use saved login' })
  await expect(restored.or(useSaved)).toBeVisible({ timeout: 30_000 })
  if (!(await restored.isVisible())) {
    // The silent restore can complete between the visibility check and the
    // click, unmounting the button in favor of the recognized state -- race
    // the click against that outcome rather than insisting on the button.
    await Promise.race([
      useSaved.click().catch(() => undefined),
      restored.waitFor({ state: 'visible', timeout: 15_000 })
    ])
  }
  await expect(restored).toBeVisible()

  // 4. The passphrase still unlocks the vault for the actual operation:
  // the share screen renders with the decrypted credential list.
  await frame.locator('input[type="password"]').fill(passphrase)
  await frame.getByRole('button', { name: 'Continue', exact: true }).click()
  await expect(frame.getByText('Select a credential to share:')).toBeVisible({
    timeout: 15_000
  })
})
