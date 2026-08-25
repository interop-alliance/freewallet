/**
 * The remembered signup e2e (WAS mode): the durable signup rides the
 * credential-anchored fold -- the establishment (ladder-anchored genesis plus
 * the `#DelegatedClients` pointer entry) followed by the ordinary durable
 * login's self-enrollment (the reveal-and-commit and add entries). The
 * world-readable account log therefore carries exactly four entries and still
 * fully verifies, the session lands on the dashboard as a durable client, a
 * credential stores, and a reload-then-login proves the client-key record
 * persisted (a remembered browser's default login is durable).
 *
 * PBKDF2 unlock derivations and the four-entry ceremony chain make this a
 * slow spec.
 */
import { test, expect, type Page } from '@playwright/test'
import {
  defaultWebvhLogVerifier,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import { addCredentialViaPaste, fillSettled, signupViaWizard } from './helpers'

/**
 * Scrapes the world-readable `did.jsonl` URL from the Settings page's
 * published did:webvh row, waiting for provisioning to land first.
 *
 * @param page {Page}
 * @returns {Promise<string>}
 */
async function readLogUrl(page: Page): Promise<string> {
  await page.goto('/#/settings')
  await expect(page.getByText('Published did:webvh DID')).toBeVisible()
  const logLink = page.getByRole('link', { name: /did\.jsonl$/ })
  await expect(logLink).toBeVisible({ timeout: 30_000 })
  return (await logLink.getAttribute('href'))!
}

test.describe('Remembered signup', () => {
  test('the durable signup rides the fold and persists the client-key record', async ({
    page
  }, testInfo) => {
    test.slow()

    // The default (remembered) wizard signup lands a durable session on the
    // dashboard, with the welcome content seeded.
    const { passphrase } = await signupViaWizard(page, testInfo)
    await expect(
      page.getByRole('link', { name: 'Your First Credential' })
    ).toBeVisible({ timeout: 20_000 })

    // The account log is the fold's four entries: the ladder-anchored
    // genesis, the `#DelegatedClients` pointer entry, then the
    // self-enrollment pair (reveal-and-commit and add) -- and the whole
    // log still verifies (SCID, hash chain, prerotation, proofs).
    const logUrl = await readLogUrl(page)
    const logText = await (await page.request.get(logUrl)).text()
    const log = readLogFromString(logText)
    expect(log).toHaveLength(4)
    const resolved = await resolveDIDFromLog(log, {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    // The add entry retired the revealed ladder rung, so exactly this
    // client's update key stands.
    expect(resolved.meta.updateKeys).toHaveLength(1)
    // The single-client document: the client's signing and key-agreement
    // methods, the KMS authentication convenience, and the passphrase's
    // commitment entry.
    expect(resolved.doc?.verificationMethod).toHaveLength(4)
    // The client's KAK plus the passphrase's commitment entry.
    expect(resolved.doc?.keyAgreement).toHaveLength(2)
    // The establishment's pointer entry survives the self-enrollment: the
    // document still names the delegated-clients annex.
    const services =
      (resolved.doc as { service?: { id?: string }[] } | undefined)?.service ??
      []
    expect(
      services.some(entry => entry.id?.endsWith('#delegated-clients'))
    ).toBe(true)

    // The durable session works: a credential stores through the replica.
    // (`readLogUrl` left the page on Settings; the Add Credential link
    // lives on the dashboard.)
    await page.goto('/#/dashboard')
    await addCredentialViaPaste(page)

    // A reload-then-login exercises the persisted client-key record: a
    // remembered browser's DEFAULT login (no seam) proceeds durable and
    // decrypts what the signup session stored.
    await page.goto('/#/login')
    await fillSettled(page.locator('input[type="password"]'), passphrase)
    await page.getByRole('button', { name: 'Log in', exact: true }).click()
    await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })
    await expect(
      page.getByRole('link', { name: 'E2E Test Credential' })
    ).toBeVisible({ timeout: 15_000 })
  })
})
