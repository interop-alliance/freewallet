/**
 * The filesystem root the WAS e2e run's teaching server stores under, and the
 * wipe that gives each run a fresh one.
 *
 * The teaching server otherwise stores under its own checkout's `data/`
 * directory, which every earlier run's Spaces accumulate in. The suite runs
 * serially against one long-lived server, so that accumulation is a variable
 * in every timing-sensitive assertion, and a failure late in the run cannot be
 * told apart from a failure the change under test caused. Pointing the server
 * at a directory the run owns, and emptying it first, removes the variable.
 */
import fs from 'node:fs/promises'
import path from 'node:path'

/**
 * The run's data root, outside `test-results/` (Playwright empties that at the
 * start of a run, which would take the store out from under the running
 * server).
 */
export const WAS_E2E_DATA_DIR = path.resolve(
  import.meta.dirname,
  '..',
  '..',
  '.was-e2e-data'
)

/**
 * Playwright `globalSetup`: empties the run's data root before the teaching
 * server starts. It runs once in the runner process, unlike the config module
 * itself, which every worker re-evaluates -- a wipe there would delete the
 * store mid-run.
 *
 * @returns {Promise<void>}
 */
export default async function emptyWasDataDir(): Promise<void> {
  await fs.rm(WAS_E2E_DATA_DIR, { recursive: true, force: true })
}
