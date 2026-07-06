import { test, expect, type Page, type TestInfo } from '@playwright/test'
import { readLogFromString, resolveDIDFromLog } from '@interop/did-method-webvh'

/**
 * Hosted did:webvh DID log e2e (Track F, Phase 2). Runs against the app in
 * remote mode backed by the local was-teaching-server (whose `/kms` facet is
 * the default KMS), with `VITE_ENABLE_DID_WEBVH` at its default (enabled).
 * Covers:
 *
 * 1. Signing up publishes a hash-chained `did.jsonl` log as a world-readable
 *    WAS resource; a cold, unauthenticated fetch parses and
 *    `resolveDIDFromLog`-verifies it (SCID + chain + proof), version 1 with
 *    prerotation committed. The sibling `did.json` is now the log's did:web
 *    projection (Multikey verification methods, `alsoKnownAs` cross-link).
 * 2. The Settings rotation ceremony appends a verifying entry 2: the previously
 *    staged update key becomes active and the committed next-key hash rolls,
 *    while the did:web holder that DIDAuth presents is unchanged (decision 8).
 */

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
  await page.locator('input[type="password"]').fill(passphrase)
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
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 15_000 })

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
  expect(log).toHaveLength(1)

  const resolved = await resolveDIDFromLog(log)
  // SCID + hash chain + entry proof all verify: no resolution error.
  expect(resolved.meta.error).toBeUndefined()
  expect(resolved.did).toMatch(/^did:webvh:.+:space:.+:id$/)
  expect(resolved.meta.scid.length).toBeGreaterThan(0)
  // Version 1, with prerotation committed (a non-empty next-key hash).
  expect(resolved.meta.versionId.startsWith('1-')).toBe(true)
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
  // Multikey (same key material, new type + context).
  expect(doc.verificationMethod).toHaveLength(3)
  for (const vm of doc.verificationMethod) {
    expect(vm.type).toBe('Multikey')
  }
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

  // --- The published log now has a verifying entry 2. ---
  const after = readLogFromString(await (await page.request.get(logUrl)).text())
  expect(after).toHaveLength(2)
  const resolvedAfter = await resolveDIDFromLog(after)
  expect(resolvedAfter.meta.error).toBeUndefined()
  // Same DID, advanced to version 2.
  expect(resolvedAfter.did).toBe(resolvedBefore.did)
  expect(resolvedAfter.meta.versionId.startsWith('2-')).toBe(true)
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
