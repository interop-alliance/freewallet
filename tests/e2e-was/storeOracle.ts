/**
 * The store-side oracle for the account-deletion e2e: "does Space X still
 * exist on the server?", answered by inspecting the teaching server's
 * FileSystem backend directly rather than by asking the server over HTTP.
 *
 * An HTTP probe cannot answer it. The server masks an authorization refusal
 * on a Space request as a 404, so after the account Space is gone every
 * survivor whose controller was the account did:webvh answers 404 whether it
 * was deleted or merely stranded -- exactly the Spaces (the auxiliary annex
 * ones) the completeness assertion is about. The harness runs the teaching
 * server as a child process on that backend (`playwright.was.config.ts`), so
 * the runner can read the store off disk: a Space is the directory
 * `<server repo>/data/spaces/<spaceId>`, removed whole by a Space DELETE,
 * with no tombstone and no index file to consult.
 *
 * The ids come from public signals rather than test seams wherever one
 * exists: the account Space id off the live `StorageManager` the auth store
 * already publishes for the export/import spec, and the auxiliary annex
 * Space ids out of the world-readable `id/did.jsonl`. The unlock Space ids
 * have no such signal, so they are named by difference -- the Spaces the
 * store gained while the account was being built, minus the two kinds above.
 */
import fs from 'node:fs/promises'
import path from 'node:path'
import { expect, type APIRequestContext, type Page } from '@playwright/test'

// Matches `playwright.was.config.ts`: the sibling checkout the harness starts
// the teaching server from, overridable for non-standard layouts.
const WAS_SERVER_DIR = process.env.WAS_SERVER_DIR ?? '../was-teaching-server'

/**
 * The FileSystem backend's Spaces directory. `dataDir` is fixed relative to
 * the server module (`<server repo>/data`) with no env override, so the path
 * follows from the checkout alone.
 *
 * @returns {string}
 */
export function storedSpacesDir(): string {
  return path.resolve(process.cwd(), WAS_SERVER_DIR, 'data', 'spaces')
}

/**
 * Every Space id the store currently holds. An absent Spaces directory (a
 * server that has never written one) reads as an empty store rather than an
 * error, matching the backend's own `listSpaces`.
 *
 * @returns {Promise<string[]>}
 */
export async function listStoredSpaceIds(): Promise<string[]> {
  let entries
  try {
    entries = await fs.readdir(storedSpacesDir(), { withFileTypes: true })
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return []
    }
    throw err
  }
  return entries.filter(entry => entry.isDirectory()).map(entry => entry.name)
}

/**
 * Whether one Space still exists in the store. The Space id is the directory
 * name verbatim (no encoding), and a Space DELETE removes that directory
 * recursively, so its presence is the whole predicate.
 *
 * @param options {object}
 * @param options.spaceId {string}
 * @returns {Promise<boolean>}
 */
export async function spaceExistsInStore({
  spaceId
}: {
  spaceId: string
}): Promise<boolean> {
  try {
    const stats = await fs.stat(path.join(storedSpacesDir(), spaceId))
    return stats.isDirectory()
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return false
    }
    throw err
  }
}

/**
 * The Space ids the store gained since a baseline listing -- the Spaces one
 * account's setup created, when nothing else was writing to the server. The
 * WAS suite runs on a single worker, so a `beforeAll` baseline and a listing
 * taken once the account is built bracket exactly that account's Spaces.
 *
 * @param options {object}
 * @param options.baseline {string[]}   the listing taken before the account
 *   was created
 * @returns {Promise<string[]>}
 */
export async function storedSpaceIdsSince({
  baseline
}: {
  baseline: string[]
}): Promise<string[]> {
  const before = new Set(baseline)
  return (await listStoredSpaceIds()).filter(spaceId => !before.has(spaceId))
}

/**
 * Asserts every named Space is gone from the store, and reports the ones
 * that survived. Polled rather than read once: the deletion walk's last
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
    .poll(async () => await survivingSpaceIds({ spaceIds }), {
      message,
      timeout: timeoutMs
    })
    .toEqual([])
}

/**
 * Which of the named Spaces the store still holds.
 *
 * @param options {object}
 * @param options.spaceIds {string[]}
 * @returns {Promise<string[]>}
 */
export async function survivingSpaceIds({
  spaceIds
}: {
  spaceIds: string[]
}): Promise<string[]> {
  const held = new Set(await listStoredSpaceIds())
  return spaceIds.filter(spaceId => held.has(spaceId))
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
 * The Space id a WAS Space URL names.
 *
 * @param url {string}
 * @returns {string}
 */
export function spaceIdOfUrl(url: string): string {
  const match = /\/space\/([^/?#]+)/.exec(url)
  if (!match) {
    throw new Error(`Not a WAS Space URL: "${url}".`)
  }
  return decodeURIComponent(match[1]!)
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
