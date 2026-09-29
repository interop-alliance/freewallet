/**
 * The login-chain seam wait, shared by the WAS e2e suite and the
 * ceremony-event fixture the default suite runs.
 */
import type { Page } from '@playwright/test'

/**
 * Waits for the login-time mender block to settle, through the
 * non-production seam the auth store publishes: `session.mends`, which
 * settles when every registration of the block has reported, the app-key
 * sweep and the annex GC included. Navigation to the dashboard waits on
 * storage provisioning alone, so a fixture that closes its context (or
 * starts a second visit) the moment the dashboard renders aborts the block
 * wherever it happens to be, and which registrations landed decides what
 * the account looks like afterwards.
 *
 * Call it in any fixture that builds a remembered session and then hands it
 * to something else. The report never rejects, so this resolves whether the
 * registrations mended, refused, or failed.
 *
 * @param page {Page}   a page holding a logged-in session
 * @param [timeoutMs] {number}   how long to wait for the block to settle
 * @returns {Promise<number>}   how long the wait actually took, in
 *   milliseconds -- a fixture can record it to show the block was still in
 *   flight rather than already settled
 */
export async function awaitLoginChain(
  page: Page,
  timeoutMs = 120_000
): Promise<number> {
  return await page.evaluate(async (budgetMs: number) => {
    const startedAt = Date.now()
    const seam = () =>
      (
        window as unknown as {
          __E2E_LOGIN_CHAIN_SETTLED__?: () => Promise<void>
        }
      ).__E2E_LOGIN_CHAIN_SETTLED__
    const deadline = Date.now() + budgetMs
    while (!seam()) {
      if (Date.now() > deadline) {
        throw new Error(
          'No session published __E2E_LOGIN_CHAIN_SETTLED__ on this page.'
        )
      }
      await new Promise(resolve => setTimeout(resolve, 50))
    }
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      await Promise.race([
        seam()!(),
        new Promise((_resolve, reject) => {
          timer = setTimeout(
            () =>
              reject(
                new Error(
                  `The login-time pass chain did not settle in ${budgetMs}ms.`
                )
              ),
            Math.max(0, deadline - Date.now())
          )
        })
      ])
    } finally {
      clearTimeout(timer)
    }
    return Date.now() - startedAt
  }, timeoutMs)
}
