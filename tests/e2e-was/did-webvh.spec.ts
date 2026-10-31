import type { Page, TestInfo } from '@playwright/test'
import { readLogFromString, resolveDIDFromLog } from '@interop/did-method-webvh'
import {
  classifyCollectionFile,
  parseArchivePath,
  policyFromFile,
  readSpaceArchive
} from '@interop/space-archive'
import { fillSettled, forceRememberBrowser, sessionSpaceId } from './helpers'
import { readStoredResource } from '../shared/storedLogs'
import { WAS_E2E_DATA_DIR } from './wasDataDir'
import { test, expect } from '../shared/consoleCapture'

/**
 * Hosted did:webvh DID log e2e (Track F, Phase 2). Runs against the app in
 * remote mode backed by the local was-teaching-server (whose `/kms` facet is
 * the default KMS). Covers:
 *
 * 1. Signing up publishes a hash-chained `did.jsonl` log as a world-readable
 *    WAS resource; a cold, unauthenticated fetch parses and
 *    `resolveDIDFromLog`-verifies it (SCID + chain + proof), version 1 with
 *    prerotation committed. The sibling `did.json` is now the log's did:web
 *    projection (Multikey verification methods, `alsoKnownAs` cross-link).
 * 2. The Settings rotation ceremony appends a verifying entry 2: the previously
 *    staged update key becomes active and the committed next-key hash rolls,
 *    while the did:web holder that DIDAuth presents is unchanged (decision 8).
 * 3. A Space export carries the hosted `did.jsonl` (and `did.json`)
 *    byte-exact, with the `id` collection's collection-level `PublicCanRead`:
 *    the exported log still `resolveDIDFromLog`-verifies (any
 *    re-serialization would break the JCS -> sha256 hash chain). Importing
 *    the archive back re-creates an emptied `key-map/keys.json` and leaves
 *    the standing `id` collection served as it was. The import never
 *    re-creates `id` itself here: the app imports only into the session's
 *    own Space, whose `id` collection must stand throughout.
 */

/**
 * The live `StorageManager`, published on `window.__E2E_STORAGE__` by the auth
 * store in non-production builds. Space export / import (and the whole-
 * `key-map` collection delete the import check needs) are ZCap-signed
 * operations that only the in-memory session can authorize, so the test
 * drives them here rather than through `page.request`.
 */
type E2EStorage = {
  exportSpace(): Promise<ReadableStream<Uint8Array>>
  importSpace(options: {
    tarFile: File
  }): Promise<{ collectionsCreated: number; resourcesCreated: number }>
  spaceId?: string
  pwsClient?: {
    space(spaceId: string): {
      collection(collectionId: string): { delete(): Promise<void> }
    }
  }
}

/**
 * Signup wizard walk with generous waits. Copied from `did-web.spec.ts`: each
 * test provisions a keystore plus the did:web/did:webvh keys against one
 * teaching server, so both the lazily-loaded password-strength engine and the
 * provisioning can exceed the helper's default 5s assertion timeout under load.
 */
async function signup(page: Page, testInfo: TestInfo) {
  const token = `${Date.now()}-w${testInfo.workerIndex}`
  const passphrase = `Str0ngpass-${token}-Aa1!`
  const email = `e2e-${token}@example.com`

  await page.goto('/#/signup')
  // These suites pin the REMEMBERED signup's artifacts (the KMS keystore,
  // the per-client update keys), so they force the remember seam: the
  // default signup on a non-remembered browser is credential-anchored.
  await forceRememberBrowser(page)
  await fillSettled(page.locator('input[type="password"]'), passphrase)
  const next = page.getByRole('button', { name: 'Next' })
  // The strength meter that gates "Next" lazy-loads its (large) zxcvbn
  // dictionaries; the first score can lag well past the default 5s.
  await expect(next).toBeEnabled({ timeout: 30_000 })
  await next.click()
  await page.locator('input[type="email"]').fill(email)
  await expect(next).toBeEnabled({ timeout: 15_000 })
  await next.click()
  await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
  await page.getByRole('button', { name: 'Create Wallet' }).click()
  // The remembered signup rides the credential-anchored fold (establishment
  // plus the remembered login's self-enrollment), so it runs well past the
  // old remembered flow's budget.
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })

  return { passphrase, email }
}

/**
 * Opens the Settings page and returns the world-readable resolution URLs the
 * page links (`did.json`, `did.jsonl`), once did:webvh provisioning has landed.
 */
async function readPublishedUrls(page: Page) {
  await page.goto('/#/settings')
  await expect(page.getByText('Published did:webvh DID')).toBeVisible()
  // The rotate action only renders once the log is provisioned; its presence is
  // the signal that did:webvh is published.
  await expect(
    page.getByRole('button', { name: 'Rotate update key' })
  ).toBeVisible({
    timeout: 20_000
  })
  const didJsonLink = page.getByRole('link', { name: /\/id\/did\.json$/ })
  const logLink = page.getByRole('link', { name: /\/id\/did\.jsonl$/ })
  await expect(didJsonLink).toBeVisible()
  await expect(logLink).toBeVisible()
  return {
    didJsonUrl: (await didJsonLink.getAttribute('href'))!,
    logUrl: (await logLink.getAttribute('href'))!
  }
}

test('signup publishes a verifying did:webvh log and a Multikey did:web projection', async ({
  page
}, testInfo) => {
  // Real KMS key generation (four keys now: three VMs + two update keys) plus
  // lazy dictionary loads against one teaching server; give it slack.
  test.slow()
  await signup(page, testInfo)

  const { didJsonUrl, logUrl } = await readPublishedUrls(page)

  // --- The did.jsonl log is world-readable and self-certifying. ---
  const logRes = await page.request.get(logUrl)
  expect(logRes.status()).toBe(200)
  const log = readLogFromString(await logRes.text())
  // Four entries -- the remembered signup rides the credential-anchored
  // fold: the ladder-anchored genesis, the `#DelegatedClients` pointer
  // entry, then the remembered login's self-enrollment pair
  // (reveal-and-commit and add).
  expect(log).toHaveLength(4)

  const resolved = await resolveDIDFromLog(log)
  // SCID + hash chain + entry proof all verify: no resolution error.
  expect(resolved.meta.error).toBeUndefined()
  expect(resolved.did).toMatch(/^did:webvh:.+:space:.+:id$/)
  expect(resolved.meta.scid.length).toBeGreaterThan(0)
  // Version 4 (the fold's four entries), with prerotation committed
  // (non-empty next-key hashes: the client's carry-over + staged hashes and
  // the passphrase's ladder-rung commitment).
  expect(resolved.meta.versionId.startsWith('4-')).toBe(true)
  expect(resolved.meta.updateKeys.length).toBeGreaterThan(0)
  expect(resolved.meta.nextKeyHashes.length).toBeGreaterThan(0)

  // --- did.json is the log's did:web projection: Multikey VMs + alsoKnownAs. ---
  const didRes = await page.request.get(didJsonUrl)
  expect(didRes.status()).toBe(200)
  const doc = (await didRes.json()) as {
    id: string
    alsoKnownAs?: string[]
    verificationMethod: Array<{ id: string; type: string }>
    authentication: string[]
  }
  expect(doc.id).toMatch(/^did:web:.+:space:.+:id$/)
  // The two ids cross-link: did.json advertises the did:webvh id it projects.
  expect(doc.alsoKnownAs).toContain(resolved.did)
  // Adopting the webvh projection flips the Phase 1 2020-suite VM types to
  // Multikey (same key material, new type + context). Five VMs: the
  // KMS-held authentication convenience, this client's Ed25519 signing key
  // and its X25519 key-agreement twin, the passphrase's ladder VM (it
  // survives the self-enrollment, under `assertionMethod` and
  // `capabilityDelegation` only), and the passphrase's standing
  // `keyAgreement` entry, published as a hash commitment
  // (`MultikeyCommitment`), never the key itself. The KMS keyAgreement key
  // is deliberately absent (no server-held key may be a wrap target), and no
  // KMS assertion key is minted (`assertionMethod` membership confers
  // resource-log-append authority).
  expect(doc.verificationMethod).toHaveLength(5)
  const types = doc.verificationMethod.map(vm => vm.type).sort()
  expect(types).toEqual([
    'Multikey',
    'Multikey',
    'Multikey',
    'Multikey',
    'MultikeyCommitment'
  ])
  const multibases = doc.verificationMethod.map(
    vm => (vm as { publicKeyMultibase?: string }).publicKeyMultibase ?? ''
  )
  // Exactly one X25519 key (z6LS...): the client's identity KAK. The
  // passphrase's key never appears verbatim.
  expect(multibases.filter(pkm => pkm.startsWith('z6LS'))).toHaveLength(1)
})

test('rotating the update key appends a verifying entry and rolls the staged key', async ({
  page
}, testInfo) => {
  test.slow()
  await signup(page, testInfo)

  const { didJsonUrl, logUrl } = await readPublishedUrls(page)

  // Capture the entry-1 state (and the did:web authentication VM, which the
  // rotation must NOT change -- decision 8).
  const before = readLogFromString(
    await (await page.request.get(logUrl)).text()
  )
  const resolvedBefore = await resolveDIDFromLog(before)
  expect(resolvedBefore.meta.error).toBeUndefined()
  const docBefore = (await (await page.request.get(didJsonUrl)).json()) as {
    id: string
    authentication: string[]
  }

  // --- Run the rotation ceremony from the Settings page. ---
  await page.getByRole('button', { name: 'Rotate update key' }).click()
  // Confirm the dialog.
  await expect(page.getByText('Rotate the did:webvh update key?')).toBeVisible()
  await page.getByRole('button', { name: 'Rotate', exact: true }).click()
  await expect(page.getByText(/The DID log was extended/)).toBeVisible({
    timeout: 30_000
  })

  // --- The published log gained a verifying rotation entry (entry 5, after
  //     the fold's four signup entries). ---
  const after = readLogFromString(await (await page.request.get(logUrl)).text())
  expect(after).toHaveLength(5)
  const resolvedAfter = await resolveDIDFromLog(after)
  expect(resolvedAfter.meta.error).toBeUndefined()
  // Same DID, advanced to version 5.
  expect(resolvedAfter.did).toBe(resolvedBefore.did)
  expect(resolvedAfter.meta.versionId.startsWith('5-')).toBe(true)
  // The active update key rolled to the previously staged key, and a fresh
  // next-key hash was committed.
  expect(resolvedAfter.meta.updateKeys).not.toEqual(
    resolvedBefore.meta.updateKeys
  )
  expect(resolvedBefore.meta.nextKeyHashes).not.toEqual(
    resolvedAfter.meta.nextKeyHashes
  )
  // The now-active update key was the one entry 1 pre-committed (its hash was
  // in entry 1's nextKeyHashes) -- prerotation held across the rotation.
  expect(resolvedAfter.meta.nextKeyHashes.length).toBeGreaterThan(0)

  // --- DIDAuth is unaffected: did.json still projects the same did:web id and
  //     authentication verification method (the holder DIDAuth presents). ---
  const docAfter = (await (await page.request.get(didJsonUrl)).json()) as {
    id: string
    alsoKnownAs?: string[]
    authentication: string[]
  }
  expect(docAfter.id).toBe(docBefore.id)
  expect(docAfter.authentication).toEqual(docBefore.authentication)
  expect(docAfter.alsoKnownAs).toContain(resolvedAfter.did)
  // The Settings page still shows the did:web DID as the published DID.
  await page.goto('/#/settings')
  await expect(page.getByText('Published DID', { exact: true })).toBeVisible()
  await expect(page.getByText(docBefore.id)).toBeVisible()
})

test('a Space export carries did.jsonl byte-exact and world-readable, and its import re-creates key-map', async ({
  page
}, testInfo) => {
  // Signup provisioning plus a full export and re-import against one teaching
  // server: give it slack.
  test.slow()
  await signup(page, testInfo)

  const { didJsonUrl, logUrl } = await readPublishedUrls(page)

  // --- Baseline: the published log + doc are world-readable and the log
  //     self-certifies. Capture the exact bytes to compare the export with.
  const logRes = await page.request.get(logUrl)
  expect(logRes.status()).toBe(200)
  const logBefore = await logRes.text()
  const didRes = await page.request.get(didJsonUrl)
  expect(didRes.status()).toBe(200)
  const docBefore = await didRes.text()
  const resolvedBefore = await resolveDIDFromLog(readLogFromString(logBefore))
  expect(resolvedBefore.meta.error).toBeUndefined()

  // --- Export the whole Space through the live (ZCap-signed)
  //     client, reading the tar stream to bytes in-page. `showSaveFilePicker`
  //     (the UI's sink) is absent in headless Chromium, so bypass the button
  //     and call the StorageManager directly via the test seam.
  const exportedTar = await page.evaluate(async () => {
    const storage = (window as unknown as { __E2E_STORAGE__: E2EStorage })
      .__E2E_STORAGE__
    const stream = await storage.exportSpace()
    const reader = stream.getReader()
    const chunks: number[] = []
    for (;;) {
      const { done, value } = await reader.read()
      if (done) {
        break
      }
      chunks.push(...value)
    }
    return chunks
  })
  expect(exportedTar.length).toBeGreaterThan(0)

  // --- The archive carries the `id` collection as served: the log and the
  //     projection byte-exact (no re-canonicalization, so the hash chain a
  //     restore would serve is intact), and the collection-level
  //     `PublicCanRead` policy that keeps both world-readable.
  const archive = await readIdCollection(new Uint8Array(exportedTar))
  const exportedLog = archive.resources.get('did.jsonl')
  const exportedDoc = archive.resources.get('did.json')
  expect(exportedLog, 'the archive carries id/did.jsonl').toBeDefined()
  expect(exportedDoc, 'the archive carries id/did.json').toBeDefined()
  expect(exportedLog).toBe(logBefore)
  expect(exportedDoc).toBe(docBefore)
  expect(archive.policyType, 'the id collection policy').toBe('PublicCanRead')
  // The exported log self-certifies on its own: SCID + chain + proofs
  // verify, at the version the server serves.
  const resolvedExported = await resolveDIDFromLog(
    readLogFromString(exportedLog!)
  )
  expect(resolvedExported.meta.error).toBeUndefined()
  expect(resolvedExported.did).toBe(resolvedBefore.did)
  expect(resolvedExported.meta.versionId).toBe(resolvedBefore.meta.versionId)

  // --- Empty a target collection so the re-import actually rewrites (import
  //     merges and SKIPS ids that already exist). The private `key-map`
  //     collection (holding keys.json) is the one emptied: on a promoted
  //     Space the `id` collection's history log is load-bearing -- the server
  //     resolves the did:webvh controller from it on every request -- so
  //     deleting it would revoke the very authority the import (and every
  //     request after it) needs. The app imports only into the session's own
  //     Space, where `id` always stands, so the import half of the `id`
  //     collection's round-trip is out of this test's reach: restoring a
  //     Space wholesale is a fresh-space flow, not an in-place one.
  await page.evaluate(async () => {
    const storage = (window as unknown as { __E2E_STORAGE__: E2EStorage })
      .__E2E_STORAGE__
    await storage
      .pwsClient!.space(storage.spaceId!)
      .collection('key-map')
      .delete()
  })
  // Still there: the log stayed published (and load-bearing) throughout.
  expect((await page.request.get(logUrl)).status()).toBe(200)

  // --- Re-import the exact exported bytes; the importer must actually write
  //     (not skip) into the now-empty `key-map` collection.
  const stats = await page.evaluate(async (bytes: number[]) => {
    const storage = (window as unknown as { __E2E_STORAGE__: E2EStorage })
      .__E2E_STORAGE__
    const tarFile = new File([new Uint8Array(bytes)], 'space.tar', {
      type: 'application/x-tar'
    })
    return await storage.importSpace({ tarFile })
  }, exportedTar)
  expect(stats.collectionsCreated).toBeGreaterThan(0)
  expect(stats.resourcesCreated).toBeGreaterThan(0)
  expect(archive.keyMapKeys, 'the archive carries key-map/keys.json').toEqual(
    expect.any(String)
  )
  const spaceId = await sessionSpaceId(page)
  expect(
    await readStoredResource({
      dataDir: WAS_E2E_DATA_DIR,
      spaceId,
      collectionId: 'key-map',
      resourceId: 'keys.json'
    }),
    'the import re-created key-map/keys.json from the archive'
  ).toBe(archive.keyMapKeys)

  // --- The merge left the standing `id` collection alone: both DID
  //     resources are still served, world-readable and unchanged.
  const logAfterRes = await page.request.get(logUrl)
  expect(logAfterRes.status()).toBe(200)
  expect(await logAfterRes.text()).toBe(logBefore)
  const didAfterRes = await page.request.get(didJsonUrl)
  expect(didAfterRes.status()).toBe(200)
  expect(await didAfterRes.text()).toBe(docBefore)
})

/**
 * What one Space export archive holds for the round-trip's assertions: the
 * `id` collection's resources as text, by resource id, the type of that
 * collection's own access policy, and the `key-map/keys.json` body. A
 * resource sits at `space/<spaceId>/<collectionId>/r.<id>.<type>.<ext>`,
 * and a collection's policy at `.collection.policy.json` beside it.
 *
 * @param bytes {Uint8Array}   the exported tar
 * @returns {Promise<{ resources: Map<string, string>,
 *   policyType: string | undefined, keyMapKeys: string | undefined }>}
 */
async function readIdCollection(bytes: Uint8Array): Promise<{
  resources: Map<string, string>
  policyType: string | undefined
  keyMapKeys: string | undefined
}> {
  const archive = await readSpaceArchive(bytes)
  const decoder = new TextDecoder()
  const resources = new Map<string, string>()
  let policyType: string | undefined
  let keyMapKeys: string | undefined
  for await (const entry of archive.entries) {
    if (entry.type !== 'file') {
      continue
    }
    const position = parseArchivePath(entry.name)
    if (position.area !== 'collection') {
      continue
    }
    const kind = classifyCollectionFile(position.fileName)
    if (position.collectionId === 'id') {
      if (kind.kind === 'representation') {
        resources.set(kind.resourceId, decoder.decode(await entry.bytes()))
      } else if (kind.kind === 'policy' && kind.scope === 'collection') {
        policyType = policyFromFile({ bytes: await entry.bytes() }).type
      }
    } else if (
      position.collectionId === 'key-map' &&
      kind.kind === 'representation' &&
      kind.resourceId === 'keys.json'
    ) {
      keyMapKeys = decoder.decode(await entry.bytes())
    }
  }
  return { resources, policyType, keyMapKeys }
}
