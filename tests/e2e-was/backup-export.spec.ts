/**
 * The wallet backup export (FW-530): the bundle a live session writes, read
 * back in node with no server contact.
 *
 * Every cell runs the export through the real dialog. The export ends at
 * `showSaveFilePicker`, which headless Chromium does not implement, so the
 * page gets a stubbed picker whose "file" is page memory, and the bytes the
 * dialog pipes into it come back to node from there. What the cells then
 * assert is what the bundle IS -- the manifest's provenance, the Space set
 * it names, the exporting server's Service Description inside each per-Space
 * archive, and that the account opens offline from the bundle plus one old
 * secret while no unlock record travels in the clear.
 *
 * The first block runs on a TRANSIENT session on a credential-anchored
 * account. That session holds no enrolled client at all, so an export that
 * names the annex archive and both unlock archives proves the three
 * ladder-anchored capabilities the ceremony rides: the generation delegation
 * on the account Space, the record's `delegatedClients` delegation on the
 * annex Space, and a freshly minted ladder-signed POST child of each
 * registry entry's management zcap on the siblings. The last cell repeats
 * the Space-set assertions on a remembered (enrolled) session, where the
 * same archives are reached by root invocation and by a POST-only child of
 * each stored management zcap, signed by the enrolled client, instead.
 */
import { test, expect, type BrowserContext, type Page } from '@playwright/test'
import {
  BUNDLE_ROLE,
  migrateBundle,
  readBundle,
  unpackRecoveryCode,
  type MigrationSink,
  type SinkOutcome
} from '@interop/wallet-backup'
import { readSpaceArchive } from '@interop/space-archive'
import {
  addCredentialViaPaste,
  coldTerminal,
  fillSettled,
  savedFileBytes,
  signupViaWizard,
  stubSaveFilePicker,
  submitTransientLogin
} from './helpers'

// Matches `playwright.was.config.ts` (APP_PORT / WAS_PORT). A manually
// created context does not inherit the config's `use.baseURL`.
const APP_URL = 'http://localhost:5274'
const WAS_URL = 'http://localhost:3002'

/**
 * The profile a backup bundle's manifest declares itself written to.
 */
const WALLET_PROFILE_ID = 'https://w3id.org/pws/wallet-profile'

/**
 * The label every code this suite mints is listed under in Settings.
 */

/**
 * One Space archive as node reads it back: which Space, which bundle role,
 * and its archive bytes.
 */
interface BundleSpace {
  spaceId: string
  role: string | undefined
  bytes: Uint8Array
}

/**
 * A bundle read into memory: its manifest, its small top-level files, and
 * every Space archive. The package's own walk is one-shot and streams, which
 * a test does not need at e2e sizes.
 */
interface OpenedBundle {
  manifest: Awaited<ReturnType<typeof readBundle>>['manifest']
  files: Map<string, Uint8Array>
  spaces: BundleSpace[]
}

/**
 * One Space archive read into memory: the Space id its manifest names, and
 * every file entry by its full archive path.
 */
interface OpenedArchive {
  spaceId: string
  files: Map<string, Uint8Array>
}

/**
 * Runs one export through the Storage page's dialog and brings the bundle
 * back to node: the mode picked, the export passphrase typed twice where
 * there is one, the run awaited to its success toast, and the stubbed
 * picker's file read back.
 *
 * @param options {object}
 * @param options.page {Page}   a page holding a logged-in session
 * @param [options.exportPassphrase] {string}   seals the packed code;
 *   absent, the unprotected mode is picked
 * @returns {Promise<Uint8Array>}   the bundle's tar bytes
 */
async function exportBundleBytes({
  page,
  exportPassphrase
}: {
  page: Page
  exportPassphrase?: string
}): Promise<Uint8Array> {
  await page.goto('/#/storage')
  const exportButton = page.getByRole('button', {
    name: 'Export (Backup) Space Contents'
  })
  await expect(exportButton).toBeEnabled({ timeout: 30_000 })
  await exportButton.click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByText('Back up this wallet')).toBeVisible()
  if (exportPassphrase) {
    await fillSettled(
      dialog.getByLabel('Export password', { exact: true }),
      exportPassphrase
    )
    await fillSettled(
      dialog.getByLabel('Confirm export password', { exact: true }),
      exportPassphrase
    )
  } else {
    await dialog.getByRole('radio', { name: 'Unprotected' }).check()
  }
  await dialog.getByRole('button', { name: 'Create backup' }).click()
  await expect(page.getByText('Backup written.')).toBeVisible({
    timeout: 240_000
  })
  const { name, bytes } = await savedFileBytes(page)
  expect(name).toMatch(/^wallet-backup-\d{4}-\d{2}-\d{2}\.tar$/)
  return bytes
}

/**
 * Reads a bundle into memory.
 *
 * @param bytes {Uint8Array}
 * @returns {Promise<OpenedBundle>}
 */
async function openBundle(bytes: Uint8Array): Promise<OpenedBundle> {
  const bundle = await readBundle(bytes)
  const spaces: BundleSpace[] = []
  for await (const space of bundle.spaces) {
    spaces.push({
      spaceId: space.spaceId,
      role: space.role,
      bytes: await space.bytes()
    })
  }
  return { manifest: bundle.manifest, files: bundle.files, spaces }
}

/**
 * Reads one per-Space export archive into memory, by full archive path.
 *
 * @param bytes {Uint8Array}
 * @returns {Promise<OpenedArchive>}
 */
async function openArchive(bytes: Uint8Array): Promise<OpenedArchive> {
  const archive = await readSpaceArchive(bytes)
  const files = new Map<string, Uint8Array>()
  for await (const entry of archive.entries) {
    if (entry.type === 'file') {
      files.set(entry.name, await entry.bytes())
    }
  }
  return { spaceId: archive.spaceId, files }
}

/**
 * The archive entries whose path matches, as decoded text. The archive names
 * a resource `space/<spaceId>/<collectionId>/r.<id>.<contentType>.<ext>`
 * with every dot inside a segment percent-encoded.
 *
 * @param options {object}
 * @param options.archive {OpenedArchive}
 * @param options.pattern {RegExp}
 * @returns {string[]}
 */
function archiveTexts({
  archive,
  pattern
}: {
  archive: OpenedArchive
  pattern: RegExp
}): string[] {
  const decoder = new TextDecoder()
  return [...archive.files.entries()]
    .filter(([name]) => pattern.test(name))
    .map(([, bytes]) => decoder.decode(bytes))
}

/**
 * The bundle's `recovery-code.json`, parsed.
 *
 * @param bundle {OpenedBundle}
 * @returns {Record<string, unknown>}
 */
function packedCodeOf(bundle: OpenedBundle): Record<string, unknown> {
  const bytes = bundle.files.get('recovery-code.json')
  expect(bytes, 'the bundle carries no recovery-code.json').toBeDefined()
  return JSON.parse(new TextDecoder().decode(bytes!)) as Record<string, unknown>
}

/**
 * A sink that accepts every row and records what it was handed, so a cell can
 * assert which collections opened.
 *
 * @returns {MigrationSink & { calls: Array<{ collectionId: string }> }}
 */
function recordingSink(): MigrationSink & {
  calls: Array<{ collectionId: string }>
} {
  const calls: Array<{ collectionId: string }> = []

  /**
   * The one import function every sink method delegates to.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @returns {Promise<SinkOutcome>}
   */
  async function record({
    collectionId
  }: {
    collectionId: string
  }): Promise<SinkOutcome> {
    calls.push({ collectionId })
    return 'accepted'
  }

  return {
    calls,
    importCredential: record,
    importContact: record,
    importContactRevision: record,
    importActivity: record
  }
}

/**
 * Asserts one per-Space archive carries the exporting server's Service
 * Description verbatim, beside its own manifest.
 *
 * @param options {object}
 * @param options.archive {OpenedArchive}
 * @param options.served {unknown}   the document `GET /service` answers with
 * @returns {void}
 */
function expectServiceDescription({
  archive,
  served
}: {
  archive: OpenedArchive
  served: unknown
}): void {
  const bytes = archive.files.get('service.json')
  expect(
    bytes,
    `the archive of Space "${archive.spaceId}" carries no service.json`
  ).toBeDefined()
  const carried = JSON.parse(new TextDecoder().decode(bytes!)) as unknown
  expect(carried).toEqual(served)
}

/**
 * The bundle's Space archives grouped by role.
 *
 * @param bundle {OpenedBundle}
 * @returns {{ account: BundleSpace[], annex: BundleSpace[], unlock: BundleSpace[] }}
 */
function spacesByRole(bundle: OpenedBundle): {
  account: BundleSpace[]
  annex: BundleSpace[]
  unlock: BundleSpace[]
} {
  return {
    account: bundle.spaces.filter(
      space => space.role === BUNDLE_ROLE.accountSpaceArchive
    ),
    annex: bundle.spaces.filter(
      space => space.role === BUNDLE_ROLE.clientAnnexSpaceArchive
    ),
    unlock: bundle.spaces.filter(
      space => space.role === BUNDLE_ROLE.unlockSpaceArchive
    )
  }
}

/**
 * Asserts the Space set a one-credential account's first backup names: one
 * account archive, one annex archive, and two unlock archives -- the
 * passphrase's Space and the Space of the code this very export minted.
 *
 * @param bundle {OpenedBundle}
 * @returns {{ account: BundleSpace, annex: BundleSpace, unlock: BundleSpace[] }}
 */
function expectAuxiliarySpaces(bundle: OpenedBundle): {
  account: BundleSpace
  annex: BundleSpace
  unlock: BundleSpace[]
} {
  const roles = spacesByRole(bundle)
  expect(roles.account).toHaveLength(1)
  expect(roles.annex).toHaveLength(1)
  expect(roles.unlock).toHaveLength(2)
  // Every archive is a distinct Space, and the bundle holds nothing else.
  expect(new Set(bundle.spaces.map(space => space.spaceId)).size).toBe(4)
  return {
    account: roles.account[0]!,
    annex: roles.annex[0]!,
    unlock: roles.unlock
  }
}

/**
 * The account DID the archived `id/did.jsonl` resolves to, read off the log's
 * last entry rather than from the page: what the bundle says its own
 * controller is has to be checkable from the bundle alone.
 *
 * @param archive {OpenedArchive}
 * @returns {string}
 */
function accountDidFromArchive(archive: OpenedArchive): string {
  const [log] = archiveTexts({
    archive,
    pattern: /\/id\/r\.did%2Ejsonl\./
  })
  expect(log, 'the account archive carries no id/did.jsonl').toBeDefined()
  const lines = log!.split('\n').filter(line => line.trim().length > 0)
  expect(lines.length).toBeGreaterThan(0)
  const last = JSON.parse(lines[lines.length - 1]!) as {
    state?: { id?: string }
  }
  expect(last.state?.id).toBeDefined()
  return last.state!.id!
}

/**
 * Asserts one bundle covers the whole account: the Space set, the manifest's
 * provenance, the Service Description in every archive, and the account
 * archive's own contents. Shared by the transient and the remembered cells,
 * which reach the same archives through different capabilities.
 *
 * @param options {object}
 * @param options.bundle {OpenedBundle}
 * @param options.served {unknown}   the document `GET /service` answers with
 * @returns {Promise<void>}
 */
async function expectWholeAccountBundle({
  bundle,
  served
}: {
  bundle: OpenedBundle
  served: unknown
}): Promise<void> {
  expect(bundle.manifest.spec.id).toBe(WALLET_PROFILE_ID)
  const { account, annex, unlock } = expectAuxiliarySpaces(bundle)

  const accountArchive = await openArchive(account.bytes)
  expect(accountArchive.spaceId).toBe(account.spaceId)
  const accountDid = accountDidFromArchive(accountArchive)
  expect(accountDid).toMatch(/^did:webvh:/)
  expect(bundle.manifest.meta.createdBy.controller).toBe(accountDid)

  // The account Space's own contents: the log, the user key roster, and the
  // credentials this account stored.
  expect(
    archiveTexts({
      archive: accountArchive,
      pattern: /\/key-map\/r\.user-key%2Ejsonl\./
    })
  ).toHaveLength(1)
  expect(
    [...accountArchive.files.keys()].filter(name =>
      /\/private-credentials\/r\./.test(name)
    ).length
  ).toBeGreaterThan(0)

  // Every archive in the bundle reads, and carries the exporting server's
  // Service Description beside its own manifest.
  expectServiceDescription({ archive: accountArchive, served })
  for (const space of [annex, ...unlock]) {
    const archive = await openArchive(space.bytes)
    expect(archive.spaceId).toBe(space.spaceId)
    expectServiceDescription({ archive, served })
  }
}

test.describe.serial('The backup export from a transient session', () => {
  let context: BrowserContext
  let page: Page
  let passphrase: string
  let served: unknown
  let bundleBytes: Uint8Array

  test.beforeAll(async ({ browser }, testInfo) => {
    test.setTimeout(300_000)
    const terminal = await coldTerminal(browser, APP_URL)
    context = terminal.context
    page = terminal.page
    await stubSaveFilePicker(page)
    await page.goto('/#/signup')
    // The credential-anchored signup: no remember seam anywhere, so every
    // visit to this account is a transient session.
    const credentials = await signupViaWizard(page, testInfo, {
      rememberBrowser: false
    })
    passphrase = credentials.passphrase
    await addCredentialViaPaste(page)
    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/\/#?\/?$/)
    await page.goto('/#/login')
    await submitTransientLogin(page, passphrase)
    const response = await page.request.get(`${WAS_URL}/service`)
    expect(response.status()).toBe(200)
    served = (await response.json()) as unknown
  })

  test.afterAll(async () => {
    await context?.close()
  })

  test('the bundle names the account, annex and unlock Spaces', async () => {
    test.setTimeout(300_000)
    bundleBytes = await exportBundleBytes({ page })
    expect(bundleBytes.length).toBeGreaterThan(0)

    const bundle = await openBundle(bundleBytes)
    await expectWholeAccountBundle({ bundle, served })

    // Unprotected: the code travels in the clear, so the file alone is the
    // secret.
    const packed = packedCodeOf(bundle)
    expect(packed.form).toBe('plain')
    expect(typeof packed.code).toBe('string')
    expect(packed.code as string).not.toHaveLength(0)
  })

  test('the bundle opens offline from the passphrase and from its own code', async () => {
    test.setTimeout(300_000)
    for (const secret of [{ passphrase }, { packedCode: {} }] as const) {
      const sink = recordingSink()
      const report = await migrateBundle({
        bundle: bundleBytes,
        secret,
        sink
      })
      const credentials = report.collections['private-credentials']
      expect(credentials?.accepted ?? 0).toBeGreaterThan(0)
      const activity = report.collections['wallet-activity']
      if (activity && activity.accepted + activity.unopenable > 0) {
        expect(activity.accepted).toBeGreaterThan(0)
      }
      for (const [collectionId, counts] of Object.entries(report.collections)) {
        expect(
          counts.unopenable,
          `${collectionId} left rows the secret could not open`
        ).toBe(0)
      }
    }
  })

  test('no unlock record and no roster entry carries key material in the clear', async () => {
    test.setTimeout(120_000)
    const bundle = await openBundle(bundleBytes)
    const { account, unlock } = expectAuxiliarySpaces(bundle)
    const accountArchive = await openArchive(account.bytes)
    const accountDid = accountDidFromArchive(accountArchive)

    // The roster's epochs carry wraps alone: one JWE recipient entry per
    // reader, and no raw key member anywhere in the log body.
    const [roster] = archiveTexts({
      archive: accountArchive,
      pattern: /\/key-map\/r\.user-key%2Ejsonl\./
    })
    expect(roster).not.toMatch(/secretKeyMultibase|privateKeyMultibase/)
    let epochsSeen = 0
    for (const line of roster!.split('\n').filter(text => text.trim())) {
      const entry = JSON.parse(line) as {
        state?: {
          epochs?: Array<{
            recipients?: Array<{
              header?: { kid?: string }
              encrypted_key?: string
            }>
          }>
        }
      }
      for (const epoch of entry.state?.epochs ?? []) {
        epochsSeen += 1
        expect(epoch.recipients?.length ?? 0).toBeGreaterThan(0)
        for (const recipient of epoch.recipients ?? []) {
          expect(typeof recipient.header?.kid).toBe('string')
          expect(typeof recipient.encrypted_key).toBe('string')
        }
      }
    }
    expect(epochsSeen).toBeGreaterThan(0)

    // Every unlock record: the frame members, the binding MAC, the proof, and
    // sealed members. Nothing else, and nothing naming the account.
    const frameMembers = new Set([
      'version',
      'encryption',
      'wrapped',
      'proof',
      'binding'
    ])
    let recordsSeen = 0
    for (const space of unlock) {
      const archive = await openArchive(space.bytes)
      for (const text of archiveTexts({
        archive,
        pattern: /\/keyring\/r\./
      })) {
        recordsSeen += 1
        const record = JSON.parse(text) as Record<string, unknown>
        for (const member of [
          'pointer',
          'ladderSeed',
          'delegation',
          'controller',
          'userKey'
        ]) {
          expect(
            record[member],
            `an unlock record carries "${member}" in the clear`
          ).toBeUndefined()
        }
        for (const [member, value] of Object.entries(record)) {
          if (frameMembers.has(member)) {
            continue
          }
          // A sealed member is self-contained: its own one-epoch descriptor
          // plus the envelope sealed under it.
          const sealed = value as { encryption?: unknown; wrapped?: unknown }
          expect(
            sealed?.encryption,
            `the unlock record member "${member}" is not sealed`
          ).toBeDefined()
          expect(
            sealed?.wrapped,
            `the unlock record member "${member}" is not sealed`
          ).toBeDefined()
        }
        expect(text).not.toContain(accountDid)
        expect(text).not.toContain(account.spaceId)
      }
    }
    expect(recordsSeen).toBeGreaterThan(0)
  })

  test('the protected mode seals the packed code under the export passphrase', async () => {
    test.setTimeout(300_000)
    const exportPassphrase = 'export-pass-e2e'
    const first = packedCodeOf(
      await openBundle(await exportBundleBytes({ page, exportPassphrase }))
    )
    const second = packedCodeOf(
      await openBundle(await exportBundleBytes({ page, exportPassphrase }))
    )

    expect(first.form).toBe('sealed')
    expect(second.form).toBe('sealed')
    // A per-bundle salt: two bundles sealed under the same passphrase share
    // no derived key.
    const saltOf = (packed: Record<string, unknown>) =>
      (packed.kdf as { salt?: string }).salt
    expect(typeof saltOf(first)).toBe('string')
    expect(saltOf(first)).not.toBe(saltOf(second))

    const code = await unpackRecoveryCode({
      document: first,
      exportPassphrase
    })
    expect(typeof code).toBe('string')
    expect(code).not.toHaveLength(0)

    const refusal = await unpackRecoveryCode({
      document: first,
      exportPassphrase: 'not-the-export-pass'
    }).then(
      () => undefined,
      (err: unknown) => err as Error
    )
    expect(refusal, 'a wrong export passphrase opened the code').toBeDefined()
    expect(refusal!.name).toBe('KeyUnwrapError')
  })

  test("the export lists its code in Settings under the dialog's label", async () => {
    test.setTimeout(120_000)
    await page.goto('/#/settings')
    await expect(page.getByText('Recovery codes', { exact: true })).toBeVisible(
      { timeout: 30_000 }
    )
    // Every run above minted one code labeled with the locale-formatted date.
    await expect(page.getByText(/^Backup /).first()).toBeVisible({
      timeout: 60_000
    })
  })
})

test('a remembered session exports the same Space set', async ({
  browser
}, testInfo) => {
  test.setTimeout(300_000)
  const { context, page } = await coldTerminal(browser, APP_URL)
  try {
    await stubSaveFilePicker(page)
    await page.goto('/#/signup')
    const { passphrase } = await signupViaWizard(page, testInfo, {
      rememberBrowser: true
    })
    await addCredentialViaPaste(page)
    await page.getByRole('button', { name: 'Log out' }).click()
    await expect(page).toHaveURL(/\/#?\/?$/)
    await page.goto('/#/login')
    await submitTransientLogin(page, passphrase)

    const response = await page.request.get(`${WAS_URL}/service`)
    expect(response.status()).toBe(200)
    const served = (await response.json()) as unknown

    // The same four archives, reached by root invocation on the account and
    // annex Spaces and by a POST-only child of each registry entry's
    // management zcap on the siblings.
    const bundle = await openBundle(await exportBundleBytes({ page }))
    await expectWholeAccountBundle({ bundle, served })
    expect(packedCodeOf(bundle).form).toBe('plain')
  } finally {
    await context.close()
  }
})
