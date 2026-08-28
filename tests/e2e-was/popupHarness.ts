/**
 * The cross-site CHAPI popup harness: what the other popup specs approximate
 * by driving `/#/wallet/get` as a first-party top-level page, done for real.
 *
 * A CHAPI popup runs as a third-party iframe under the mediator's origin, and
 * everything FW-203 turns on -- which login route the popup takes, and
 * which storage bucket its residue would land in -- is invisible unless the
 * frame is genuinely cross-site. So the harness serves a bare host document
 * on `127.0.0.1` (a different site from `localhost`, and the reason
 * `playwright.was.config.ts` runs vite with `--host`) and embeds the wallet's
 * popup route in it. The frame's storage is then partitioned exactly as a
 * real popup's is.
 *
 * The CHAPI event arrives through the same `__E2E_CHAPI_GET_EVENT__` seam the
 * first-party specs use; `page.addInitScript` reaches every frame, so it
 * lands in the popup document without the harness having to inject across the
 * boundary.
 */
import { expect, type Frame, type Page } from '@playwright/test'
import { fillSettled } from './helpers'

// Matches `playwright.was.config.ts` (APP_PORT). The two hostnames are the
// point: the wallet is served from `localhost`, the embedding top level from
// `127.0.0.1`, so the popup frame is third-party.
export const APP_PORT = 5274
export const WALLET_ORIGIN = `http://localhost:${APP_PORT}`
export const HOST_ORIGIN = `http://127.0.0.1:${APP_PORT}`
export const HOST_URL = `${HOST_ORIGIN}/e2e-popup-host`

const POPUP_FRAME_NAME = 'chapi-popup'

/**
 * Installs the host document route. The document is served by the test rather
 * than by vite, so the top level carries none of the app's own storage
 * behavior and the frame's partition is the only thing under test.
 *
 * @param options {object}
 * @param options.page {Page}
 * @returns {Promise<void>}
 */
export async function servePopupHost({ page }: { page: Page }): Promise<void> {
  await page.route(HOST_URL, async route => {
    await route.fulfill({
      status: 200,
      contentType: 'text/html; charset=utf-8',
      body:
        '<!doctype html><meta charset="utf-8"><title>CHAPI host</title>' +
        `<iframe name="${POPUP_FRAME_NAME}" title="${POPUP_FRAME_NAME}" ` +
        `src="${WALLET_ORIGIN}/#/wallet/get" ` +
        'style="width:520px;height:760px;border:0"></iframe>'
    })
  })
}

/**
 * Injects a CHAPI `get` event for the popup frame to pick up, and records
 * whatever the popup responds with on the frame's own window.
 *
 * @param options {object}
 * @param options.page {Page}
 * @param options.origin {string}   the attested requesting origin
 * @param options.query {unknown}   the VPR query array
 * @param [options.challenge] {string}
 * @param [options.domain] {string}
 * @returns {Promise<void>}
 */
export async function injectPopupGetEvent({
  page,
  origin,
  query,
  challenge,
  domain
}: {
  page: Page
  origin: string
  query: unknown
  challenge?: string
  domain?: string
}): Promise<void> {
  await page.addInitScript(
    (cfg: {
      origin: string
      query: unknown
      challenge?: string
      domain?: string
    }) => {
      const win = window as unknown as {
        __E2E_CHAPI_GET_EVENT__?: unknown
        __E2E_CHAPI_RESPONSE__?: { value: unknown }
      }
      win.__E2E_CHAPI_RESPONSE__ = undefined
      win.__E2E_CHAPI_GET_EVENT__ = {
        credentialRequestOrigin: cfg.origin,
        credentialRequestOptions: {
          web: {
            VerifiablePresentation: {
              query: cfg.query,
              challenge: cfg.challenge,
              domain: cfg.domain
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
    { origin, query, challenge, domain }
  )
}

/**
 * Removes the Storage Access API's handle extension from every frame, which
 * is the steady state of every engine that offers no unpartitioned-IndexedDB
 * request (Safari and Firefox today). Under
 * `decisions/0009-popup-denied-storage-access-goes-transient.md` the popup
 * must fall back to the transient session there, even on a browser that IS a
 * remembered enrolled client -- so this stub is how a Chromium run exercises
 * the other engines' default rather than assuming it.
 *
 * @param options {object}
 * @param options.page {Page}
 * @returns {Promise<void>}
 */
export async function withoutUnpartitionedStorageAccess({
  page
}: {
  page: Page
}): Promise<void> {
  await page.addInitScript(() => {
    Object.defineProperty(document, 'requestStorageAccess', {
      configurable: true,
      value: undefined
    })
  })
}

/**
 * Opens the host document and returns the popup frame once its document has
 * loaded. Call after `servePopupHost` and any `addInitScript` seams.
 *
 * @param options {object}
 * @param options.page {Page}
 * @returns {Promise<Frame>}
 */
export async function openPopupFrame({ page }: { page: Page }): Promise<Frame> {
  await page.goto(HOST_URL)
  const frame = page.frame({ name: POPUP_FRAME_NAME })
  if (!frame) {
    throw new Error('The CHAPI popup frame did not attach.')
  }
  // The popup renders its login form (or a pre-login refusal) once the
  // injected event has been classified.
  await frame.waitForLoadState('domcontentloaded')
  return frame
}

/**
 * Submits the popup's passphrase form. Returns the milliseconds from submit
 * to the consent (or refusal) panel replacing it -- the popup path's latency,
 * which on the transient route covers the whole annex enrollment.
 *
 * @param options {object}
 * @param options.frame {Frame}
 * @param options.passphrase {string}
 * @returns {Promise<number>}
 */
export async function submitPopupLogin({
  frame,
  passphrase
}: {
  frame: Frame
  passphrase: string
}): Promise<number> {
  const field = frame.locator('input[type="password"]')
  await expect(field).toBeVisible({ timeout: 30_000 })
  await fillSettled(field, passphrase)
  const startedAt = Date.now()
  await frame.getByRole('button', { name: 'Continue' }).click()
  await expect(field).toHaveCount(0, { timeout: 120_000 })
  return Date.now() - startedAt
}

/**
 * The response the popup handed back through `respondWith`, or `undefined`
 * while it is still pending.
 *
 * @param options {object}
 * @param options.frame {Frame}
 * @returns {Promise<{ value: unknown } | undefined>}
 */
export function readPopupResponse({
  frame
}: {
  frame: Frame
}): Promise<{ value: unknown } | undefined> {
  return frame.evaluate(
    () =>
      (window as unknown as { __E2E_CHAPI_RESPONSE__?: { value: unknown } })
        .__E2E_CHAPI_RESPONSE__
  )
}

/**
 * Waits for the popup to respond and returns the delivered value.
 *
 * @param options {object}
 * @param options.frame {Frame}
 * @returns {Promise<unknown>}
 */
export async function awaitPopupResponse({
  frame
}: {
  frame: Frame
}): Promise<unknown> {
  await expect
    .poll(async () => (await readPopupResponse({ frame })) !== undefined, {
      timeout: 60_000
    })
    .toBe(true)
  const recorded = (await readPopupResponse({ frame })) as { value: unknown }
  return recorded.value
}
