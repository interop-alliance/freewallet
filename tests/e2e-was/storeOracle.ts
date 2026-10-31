/**
 * The Playwright-bound half of the store-side oracle. The store reads
 * themselves live in `tests/shared/storeOracle.ts` and
 * `tests/shared/storedLogs.ts`, which take the server's data root as an
 * argument; the PWS suite passes its run's root (`WAS_E2E_DATA_DIR`). What
 * stays here needs Playwright: a polled assertion over the store, the
 * account Space id read off a live page, and the annex Space ids read out of
 * the world-readable log over a request context.
 *
 * The ids come from public signals rather than test seams wherever one
 * exists: the account Space id off the live `StorageManager` the auth store
 * already publishes for the export/import spec, and the auxiliary annex
 * Space ids out of the world-readable `id/did.jsonl`. The unlock Space ids
 * have no such signal, so they are named by difference -- the Spaces the
 * store gained while the account was being built, minus the two kinds above.
 */
import { expect, type APIRequestContext, type Page } from '@playwright/test'
import { spaceIdOfUrl, survivingSpaceIds } from '../shared/storeOracle'
import { WAS_E2E_DATA_DIR } from './wasDataDir'

/**
 * Asserts every named Space is gone from the run's store, and reports the
 * ones that survived. Polled rather than read once: the deletion walk's last
 * requests and the app's own logout race each other, and the assertion is
 * about the walk having landed, not about which finished first.
 *
 * @param options {object}
 * @param options.spaceIds {string[]}
 * @param [options.message] {string}   what the assertion is about
 * @param [options.timeoutMs] {number}
 * @returns {Promise<void>}
 */
export async function expectSpacesGone({
  spaceIds,
  message = 'every Space the account owned must be gone from the store',
  timeoutMs = 15_000
}: {
  spaceIds: string[]
  message?: string
  timeoutMs?: number
}): Promise<void> {
  await expect
    .poll(
      async () =>
        await survivingSpaceIds({ dataDir: WAS_E2E_DATA_DIR, spaceIds }),
      { message, timeout: timeoutMs }
    )
    .toEqual([])
}

/**
 * The account Space id of the session this page holds, off the live
 * `StorageManager` the auth store publishes in non-production builds.
 *
 * @param page {Page}   a page holding a logged-in session
 * @returns {Promise<string>}
 */
export async function accountSpaceIdFrom(page: Page): Promise<string> {
  const spaceUrl = await page.evaluate(
    () =>
      (window as unknown as { __E2E_STORAGE__?: { spaceUrl?: string } })
        .__E2E_STORAGE__?.spaceUrl
  )
  if (!spaceUrl) {
    throw new Error('This page holds no session with a remote Space.')
  }
  return spaceIdOfUrl(spaceUrl)
}

/**
 * Every auxiliary annex Space the account log's `#DelegatedClients` pointer
 * has ever named, read out of the world-readable log. A superseded pointer
 * entry is append-only and its Space survives the move, so the enumeration
 * is over the whole log text rather than over the resolved document.
 *
 * The annex DID's shape is `did:webvh:<scid>:<host>:space:<spaceId>:<gen>`,
 * so the Space id is the segment before the generation id. Matching the raw
 * log text keeps the oracle independent of the log's entry serialization.
 *
 * @param options {object}
 * @param options.request {APIRequestContext}   an unauthenticated request
 *   context (the log is public)
 * @param options.logUrl {string}   the `id/did.jsonl` URL
 * @returns {Promise<string[]>}
 */
export async function annexSpaceIdsFromLog({
  request,
  logUrl
}: {
  request: APIRequestContext
  logUrl: string
}): Promise<string[]> {
  const response = await request.get(logUrl)
  expect(response.status(), 'the account log must be readable').toBe(200)
  const text = await response.text()
  const pattern = /did:webvh:[^"]*?:space:([^":]+):(gen-[^":]+)/g
  const spaceIds = new Set<string>()
  for (const match of text.matchAll(pattern)) {
    spaceIds.add(match[1]!)
  }
  return [...spaceIds]
}
