import { test, expect, type Page } from '@playwright/test'
import { addCredentialViaPaste, goToStorage, signupViaWizard } from './helpers'

/**
 * Refresh-surviving delegated sessions e2e. At login the root key delegates
 * session zcaps to a non-extractable browser session key and wraps the vault
 * KAK as the session vault envelope; a reload reconstitutes a restricted
 * session from them: the user stays logged in, remote storage works through
 * the delegated capabilities, and the vault unlocks from the envelope. Fail
 * closed: without a usable envelope the vault stays locked until the
 * passphrase is re-entered.
 */

/**
 * Waits until the session vault envelope has landed in the wallet origin's
 * IndexedDB (persistDelegatedSession runs fire-and-forget after login).
 * Polls without ever creating the database: an `indexedDB.open` from the
 * test before the app's own could otherwise mint a version-1 database with
 * no object store.
 */
async function waitForVaultEnvelope(page: Page) {
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
            .get('vault-envelope')
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

/**
 * Deletes the session vault envelope pair from IndexedDB, simulating an
 * absent/unusable envelope so the restore exercises the fail-closed branch.
 */
async function deleteVaultEnvelope(page: Page) {
  await page.evaluate(async () => {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.open('freewallet-session', 1)
      request.onerror = () => reject(request.error)
      request.onsuccess = () => {
        const db = request.result
        const transaction = db.transaction('session', 'readwrite')
        const store = transaction.objectStore('session')
        store.delete('vault-envelope')
        store.delete('vault-key')
        transaction.oncomplete = () => {
          db.close()
          resolve()
        }
        transaction.onerror = () => {
          db.close()
          reject(transaction.error)
        }
      }
    })
  })
}

test.describe('Refresh-surviving delegated session', () => {
  test('a reload restores a delegated session with the vault unlocked', async ({
    page
  }, testInfo) => {
    await signupViaWizard(page, testInfo)
    // Vault content added while the session is full (also leaves ample time
    // for the fire-and-forget delegation persistence to land).
    await addCredentialViaPaste(page)
    await expect(
      page.getByRole('link', { name: 'E2E Test Credential' })
    ).toBeVisible()
    await waitForVaultEnvelope(page)

    await page.reload()

    // Restored: still on the dashboard (not bounced to the landing page),
    // and the session vault envelope unlocked the vault -- the credential
    // decrypts with no locked-vault notice.
    await expect(page).toHaveURL(/#\/dashboard/)
    await expect(
      page.getByRole('link', { name: 'E2E Test Credential' })
    ).toBeVisible()
    await expect(page.getByText(/vault is locked/)).toHaveCount(0)

    // The storage browser reads the remote Space through the delegated
    // read capability.
    await goToStorage(page)
  })

  test('without the envelope the vault stays locked; re-login unlocks', async ({
    page
  }, testInfo) => {
    const { passphrase } = await signupViaWizard(page, testInfo)
    await addCredentialViaPaste(page)
    await expect(
      page.getByRole('link', { name: 'E2E Test Credential' })
    ).toBeVisible()
    await waitForVaultEnvelope(page)

    // Simulate a missing/unusable envelope: the restore must fail closed.
    await deleteVaultEnvelope(page)
    await page.reload()

    // Restored but locked: on the dashboard with the locked-vault notice --
    // and no decrypted credentials.
    await expect(page).toHaveURL(/#\/dashboard/)
    await expect(page.getByText(/vault is locked/)).toBeVisible()
    await expect(
      page.getByRole('link', { name: 'E2E Test Credential' })
    ).toHaveCount(0)

    // Re-entering the passphrase upgrades back to a full session: the
    // notice disappears and the vault decrypts again. Login now pays the
    // keyring's deliberately slow PBKDF2 unlock derivation plus a remote
    // keyring fetch, so it can run past the default 5s assertion timeout.
    await page.goto('/#/login')
    await page.locator('input[type="password"]').fill(passphrase)
    await page.getByRole('button', { name: 'Log in', exact: true }).click()
    await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })
    await expect(page.getByText(/vault is locked/)).toHaveCount(0)
    await expect(
      page.getByRole('link', { name: 'E2E Test Credential' })
    ).toBeVisible()
  })

  test('logging out ends the persisted session', async ({ page }, testInfo) => {
    await signupViaWizard(page, testInfo)
    await waitForVaultEnvelope(page)
    await page.reload()
    await expect(page).toHaveURL(/#\/dashboard/)
    await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible()

    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/\/#?\/?$/)

    // The persisted records are gone: a fresh visit to a protected page
    // finds nothing to restore and bounces away.
    await page.goto('/#/dashboard')
    await expect(page).not.toHaveURL(/#\/dashboard/)
  })
})
