/**
 * The ceremony-event e2e fixture: a Playwright fixture over the dev server's
 * NDJSON log file, keyed on the ceremony event channel's three events
 * (`'ceremony stage'`, `'ceremony outcome'`, `'ceremony mender'`).
 *
 * The file's path comes from `INTEROP_LOGGER_FILE`, which both Playwright
 * configs set for the dev server and for the test workers alike. Every
 * worker shares that one file, so the fixture tags each context it watches
 * with an init script carrying a per-test tag; a dev build announces the tag
 * in one marker line per page load (`src/lib/log.ts`), and the fixture reads
 * only the lines of the `page` ids whose marker carries its tag. The same
 * init script sets the logger's debug filter before the first navigation,
 * so stage events and `noop` mender entries reach the file.
 *
 * The NDJSON sink batches non-error lines on a 500 ms timer, so every wait
 * here polls. Lines are untrusted data (`ceremonyEventLines.ts`).
 *
 * Specs import `test` and `expect` from here in place of `@playwright/test`
 * and ask for the `ceremonyEvents` fixture. A context the spec creates
 * itself (`browser.newContext()`) is watched once passed to `tag()`.
 */
import { open, stat } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import {
  test as base,
  expect,
  type BrowserContext,
  type Page
} from '@playwright/test'
import type { CeremonyId, CeremonyOutcome } from '@interop/wallet-core'
import type { InvariantId } from '@interop/wallet-core/menders'
import type {
  CredentialAnchoredEstablishmentStageName,
  CredentialAnchoredGenesisStage,
  ForgetClientEventStage,
  LastClientTransitionEventStage,
  SelfEnrollmentEventStage
} from '@interop/wallet-core/clientAnnex'
import type { AccountGenesisEventStage } from '@interop/wallet-core/genesis'
import type { ClientRevocationStage } from '@interop/wallet-core/clients'
import type {
  EnrollmentApprovalStage,
  EnrollmentCompletionStage
} from '@interop/wallet-core/enrollment'
import type {
  RecoveryCodeIssuanceStage,
  RecoveryCodeRevocationStage,
  RecoveryCodeSpendStage
} from '@interop/wallet-core/recovery'
import type { UnlockCredentialRetirementStage } from '@interop/wallet-core/unlock'
import type { AccountDeletionStage } from '@/session/accountSettings'
import type { BackupExportStage } from '@/session/backupExport'
import type { ContentMigrationStage } from '@/session/contentMigration'
import type { WalletWipeStage } from '@/session/wipe'
import { E2E_LOG_TAG_GLOBAL } from '@/lib/e2eLogTag'
import {
  CEREMONY_MENDER_MSG,
  CEREMONY_OUTCOME_MSG,
  CEREMONY_STAGE_MSG,
  LOGGER_FILTER,
  LOGGER_FILTER_KEY,
  menderEvents,
  outcomeEvents,
  scopedLines,
  splitDevLogChunk,
  stageEvents,
  type DevLogLine
} from './ceremonyEventLines'
import { awaitLoginChain } from './loginChain'

export { expect }

/**
 * Each ceremony's exported stage union, so a stage id a spec waits on is a
 * compile-time dependency on the emitting module's export: a rename there
 * breaks the build here rather than timing out a run.
 */
export type CeremonyStages = {
  'account-genesis': AccountGenesisEventStage
  'credential-anchored-genesis':
    CredentialAnchoredEstablishmentStageName | CredentialAnchoredGenesisStage
  'self-enrollment': SelfEnrollmentEventStage
  'client-enrollment': EnrollmentApprovalStage | EnrollmentCompletionStage
  'client-revocation': ClientRevocationStage
  'recovery-code-issuance': RecoveryCodeIssuanceStage
  'recovery-code-spend': RecoveryCodeSpendStage
  'recovery-code-revocation': RecoveryCodeRevocationStage
  'unlock-credential-rotation': UnlockCredentialRetirementStage
  'forget-client': ForgetClientEventStage
  'last-client-transition': LastClientTransitionEventStage
  'account-deletion': AccountDeletionStage
  'wallet-wipe': WalletWipeStage
  'content-migration': ContentMigrationStage
  'backup-export': BackupExportStage
}

/**
 * How often a wait re-reads the file.
 */
const POLL_MS = 250

/**
 * How long the tagged pages must stay silent before the stream counts as
 * flushed: twice the sink's 500 ms flush timer.
 */
const QUIET_MS = 1_000

/**
 * The default budget for one wait.
 */
const DEFAULT_TIMEOUT_MS = 30_000

/**
 * The fixture's surface.
 */
export interface CeremonyEventsFixture {
  /**
   * Watches a context: every page it loads from now on is tagged and runs
   * with the debug filter set. The default `context` fixture is watched
   * already.
   */
  tag(target: BrowserContext): Promise<void>
  /**
   * Every event line the watched pages wrote so far, markers excluded.
   */
  lines(): Promise<DevLogLine[]>
  /**
   * Waits for one stage event of a ceremony and returns it.
   */
  waitForStage<Ceremony extends keyof CeremonyStages>(
    ceremony: Ceremony,
    stage: CeremonyStages[Ceremony],
    options?: { timeoutMs?: number }
  ): Promise<DevLogLine>
  /**
   * Waits for an outcome event of a ceremony, of one outcome when given,
   * and returns it.
   */
  waitForOutcome(
    ceremony: CeremonyId,
    outcome?: CeremonyOutcome,
    options?: { timeoutMs?: number }
  ): Promise<DevLogLine>
  /**
   * Waits for a mender event of one invariant with one outcome and returns
   * it. A `noop` entry is visible because the watched pages run with the
   * debug filter on.
   */
  expectMender(
    invariant: InvariantId,
    outcome: CeremonyOutcome,
    options?: { timeoutMs?: number }
  ): Promise<DevLogLine>
  /**
   * Waits until the watched pages stay silent for longer than the sink's
   * flush timer, so lines already emitted have reached the file. Gives up
   * silently at the budget.
   */
  waitQuiet(options?: { timeoutMs?: number }): Promise<void>
  /**
   * Awaits the page's login-chain seam, lets the stream go quiet, and
   * asserts that no mender event of the watched pages reported `failed`.
   */
  expectNoFailedMenders(options: {
    page: Page
    timeoutMs?: number
  }): Promise<void>
}

/**
 * The dev-log file the dev server writes, from the environment the configs
 * set.
 *
 * @returns {string}
 */
export function devLogFile(): string {
  const file = process.env.INTEROP_LOGGER_FILE
  if (!file) {
    throw new Error(
      'INTEROP_LOGGER_FILE is not set; the Playwright config sets it for the ' +
        'dev server and the test workers alike.'
    )
  }
  return file
}

/**
 * An incremental reader over the dev-log file: each call reads what was
 * appended since the last and hands back every complete line seen so far.
 * It starts from the file's size at creation, since no line written before
 * a test began can carry that test's tag.
 *
 * @param options {object}
 * @param options.file {string}
 * @returns {Promise<() => Promise<DevLogLine[]>>}
 */
export async function devLogReader({
  file
}: {
  file: string
}): Promise<() => Promise<DevLogLine[]>> {
  let offset = await fileSize({ file })
  let carry = ''
  const seen: DevLogLine[] = []
  return async function readNew(): Promise<DevLogLine[]> {
    const size = await fileSize({ file })
    if (size < offset) {
      // The dev server rotated the file under this test; start over.
      offset = 0
      carry = ''
    }
    if (size <= offset) {
      return seen
    }
    const handle = await open(file, 'r')
    try {
      const buffer = Buffer.alloc(size - offset)
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset)
      offset += bytesRead
      const split = splitDevLogChunk({
        carry,
        chunk: buffer.subarray(0, bytesRead).toString('utf8')
      })
      carry = split.carry
      seen.push(...split.lines)
    } finally {
      await handle.close()
    }
    return seen
  }
}

/**
 * The file's size in bytes, zero when it does not exist yet.
 *
 * @param options {object}
 * @param options.file {string}
 * @returns {Promise<number>}
 */
async function fileSize({ file }: { file: string }): Promise<number> {
  try {
    return (await stat(file)).size
  } catch {
    return 0
  }
}

/**
 * Polls until `find` returns a line from the scoped stream.
 *
 * @param options {object}
 * @param options.read {Function}   the scoped reader
 * @param options.find {Function}   picks the awaited line, if present
 * @param options.what {string}   what is awaited, for the timeout message
 * @param options.timeoutMs {number}
 * @returns {Promise<DevLogLine>}
 */
async function pollFor({
  read,
  find,
  what,
  timeoutMs
}: {
  read: () => Promise<DevLogLine[]>
  find: (lines: DevLogLine[]) => DevLogLine | undefined
  what: string
  timeoutMs: number
}): Promise<DevLogLine> {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const found = find(await read())
    if (found) {
      return found
    }
    if (Date.now() > deadline) {
      throw new Error(`No ${what} reached the dev log in ${timeoutMs}ms.`)
    }
    await new Promise(resolve => setTimeout(resolve, POLL_MS))
  }
}

/**
 * Builds the fixture for one test.
 *
 * @param options {object}
 * @param options.testTag {string}   the per-test tag
 * @param options.file {string}   the dev-log file
 * @returns {Promise<CeremonyEventsFixture>}
 */
export async function createCeremonyEvents({
  testTag,
  file
}: {
  testTag: string
  file: string
}): Promise<CeremonyEventsFixture> {
  const readAll = await devLogReader({ file })
  const read = async () => scopedLines({ lines: await readAll(), tag: testTag })

  /**
   * Waits until the scoped stream stops growing for longer than the flush
   * timer, or the budget runs out.
   *
   * @param timeoutMs {number}
   * @returns {Promise<void>}
   */
  async function waitQuiet(timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs
    let count = (await read()).length
    let quietSince = Date.now()
    while (Date.now() - quietSince < QUIET_MS) {
      if (Date.now() > deadline) {
        return
      }
      await new Promise(resolve => setTimeout(resolve, POLL_MS))
      const next = (await read()).length
      if (next !== count) {
        count = next
        quietSince = Date.now()
      }
    }
  }

  return {
    async tag(target) {
      await target.addInitScript(
        ({ key, value, filterKey, filter }) => {
          ;(window as unknown as Record<string, unknown>)[key] = value
          try {
            window.localStorage.setItem(filterKey, filter)
          } catch {
            // An opaque-origin frame has no storage; its lines stay debug-off.
          }
        },
        {
          key: E2E_LOG_TAG_GLOBAL,
          value: testTag,
          filterKey: LOGGER_FILTER_KEY,
          filter: LOGGER_FILTER
        }
      )
    },
    lines: read,
    async waitForStage(ceremony, stage, options) {
      return await pollFor({
        read,
        find: lines => stageEvents({ lines, ceremony, stage })[0],
        what: `'${CEREMONY_STAGE_MSG}' ${ceremony}/${stage}`,
        timeoutMs: options?.timeoutMs ?? DEFAULT_TIMEOUT_MS
      })
    },
    async waitForOutcome(ceremony, outcome, options) {
      return await pollFor({
        read,
        find: lines => outcomeEvents({ lines, ceremony, outcome })[0],
        what: `'${CEREMONY_OUTCOME_MSG}' ${ceremony}${outcome ? `/${outcome}` : ''}`,
        timeoutMs: options?.timeoutMs ?? DEFAULT_TIMEOUT_MS
      })
    },
    async expectMender(invariant, outcome, options) {
      return await pollFor({
        read,
        find: lines => menderEvents({ lines, invariant, outcome })[0],
        what: `'${CEREMONY_MENDER_MSG}' ${invariant}/${outcome}`,
        timeoutMs: options?.timeoutMs ?? DEFAULT_TIMEOUT_MS
      })
    },
    async waitQuiet(options) {
      await waitQuiet(options?.timeoutMs ?? DEFAULT_TIMEOUT_MS)
    },
    async expectNoFailedMenders({ page, timeoutMs = 120_000 }) {
      await awaitLoginChain(page, timeoutMs)
      // The block has settled, but its last lines may still sit in the
      // page's flush buffer: wait until the watched pages stay silent for
      // longer than the flush timer.
      await waitQuiet(timeoutMs)
      const failed = menderEvents({ lines: await read(), outcome: 'failed' })
      expect(
        failed.map(line => line.data.invariant),
        'no mender may report failed'
      ).toEqual([])
    }
  }
}

/**
 * The Playwright `test` with the `ceremonyEvents` fixture. The fixture is
 * automatic, so it tags the default context before any `beforeEach` hook
 * navigates: a page loaded before the tag would write untagged lines the
 * fixture cannot see.
 */
export const test = base.extend<{ ceremonyEvents: CeremonyEventsFixture }>({
  ceremonyEvents: [
    async ({ context }, use, testInfo) => {
      const fixture = await createCeremonyEvents({
        testTag: `${testInfo.testId}-${testInfo.retry}-${randomUUID()}`,
        file: devLogFile()
      })
      await fixture.tag(context)
      await use(fixture)
    },
    { auto: true }
  ]
})
