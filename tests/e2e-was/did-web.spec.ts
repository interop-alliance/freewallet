import {
  test,
  expect,
  type Frame,
  type Page,
  type TestInfo
} from '@playwright/test'
import { fillSettled, forceRememberBrowser } from './helpers'

/**
 * Signup wizard walk with generous waits. Same steps as the shared
 * `signupViaWizard`, but each test here provisions a keystore plus three
 * did:web keys against one teaching server, so both the lazily-loaded
 * password-strength engine and the provisioning can exceed the helper's
 * default 5s assertion timeout under that load.
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
 * Hosted did:web DID e2e (Track F, Phase 1). Runs against the app in remote
 * mode backed by the local was-teaching-server (whose `/kms` facet is the
 * default KMS). Covers two things:
 *
 * 1. Signing up provisions and publishes a did:web document as a world-readable
 *    WAS resource, while the sibling key-id map stays capability-only.
 * 2. A CHAPI DIDAuth request is signed by the KMS-held `authentication` key,
 *    and the VP's holder / verificationMethod resolve against the published
 *    `did.json`.
 */

interface GetEventConfig {
  origin: string
  query: unknown
  challenge?: string
  domain?: string
}

/**
 * Injects a canned CHAPI get event whose `respondWith` records the response on
 * `window.__E2E_CHAPI_RESPONSE__`.
 */
async function injectGetEvent(scope: Page, config: GetEventConfig) {
  await scope.addInitScript((cfg: GetEventConfig) => {
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
  }, config)
}

type DidAuthPayload = {
  dataType: string
  data: {
    holder: string
    verifiableCredential?: unknown
    proof: {
      proofPurpose: string
      verificationMethod: string
      challenge: string
      domain: string
    }
  }
}

function readResponse(scope: Page | Frame) {
  return scope.evaluate(
    () =>
      (window as unknown as { __E2E_CHAPI_RESPONSE__?: { value: unknown } })
        .__E2E_CHAPI_RESPONSE__
  )
}

test('signup publishes a did:web document and a DIDAuth VP is signed by the KMS key', async ({
  page
}, testInfo) => {
  // Real KMS key generation + lazy dictionary loads against one teaching
  // server; give it slack beyond the 30s default under load.
  test.slow()
  const { passphrase } = await signup(page, testInfo)

  // --- Provisioning: the DID document is published; keys.json lives in the
  //     private `key-map` collection and is not public. ---
  await page.goto('/#/settings')
  await expect(page.getByText('Published DID', { exact: true })).toBeVisible()
  await expect(
    page.getByText('Published', { exact: true }).first()
  ).toBeVisible({
    timeout: 15_000
  })

  // The settings page links the world-readable resolution URL.
  const didJsonLink = page.getByRole('link', { name: /\/id\/did\.json$/ })
  await expect(didJsonLink).toBeVisible()
  const didJsonUrl = (await didJsonLink.getAttribute('href'))!

  // A cold, unauthenticated GET resolves the DID document.
  const didRes = await page.request.get(didJsonUrl)
  expect(didRes.status()).toBe(200)
  const doc = (await didRes.json()) as {
    id: string
    verificationMethod: Array<{ id: string; type: string }>
    authentication: string[]
    assertionMethod: string[]
    keyAgreement: string[]
  }
  expect(doc.id).toMatch(/^did:web:.+:space:.+:id$/)
  // The webvh projection: one KMS-held VM (authentication, a server-side
  // convenience) plus this client's signing key and key-agreement twin, plus
  // the passphrase's standing `keyAgreement` entry as a hash commitment
  // (`MultikeyCommitment` -- never the key itself);
  // `authentication` lists the KMS key and the client key, while
  // `assertionMethod` lists the client key only (membership there confers
  // resource-log-append authority, so no KMS key is minted for it) and
  // `keyAgreement` is the client's KAK plus the passphrase commitment (no
  // server-held key is ever a wrap target).
  expect(doc.verificationMethod).toHaveLength(4)
  expect(doc.authentication).toHaveLength(2)
  expect(doc.assertionMethod).toHaveLength(1)
  expect(doc.keyAgreement).toHaveLength(2)
  // Each relationship references one of the document's verification methods.
  const vmIds = doc.verificationMethod.map(vm => vm.id)
  expect(vmIds).toContain(doc.authentication[0])
  expect(vmIds).toContain(doc.keyAgreement[0])

  // The key-id map lives alone in the private `key-map` collection and is not
  // public: an unauthenticated GET is refused (WAS returns 404 for both
  // not-found and unauthorized).
  const keysUrl = didJsonUrl.replace('/id/did.json', '/key-map/keys.json')
  const keysRes = await page.request.get(keysUrl)
  expect([401, 403, 404]).toContain(keysRes.status())

  // --- DIDAuth: the VP is signed by the KMS key and resolves against did.json. ---
  const origin = 'https://verifier.example'
  const challenge = `chal-${Date.now()}-w${testInfo.workerIndex}`
  await injectGetEvent(page, {
    origin,
    // Unconstrained method: the wallet presents its did:web holder.
    query: [{ type: 'DIDAuthentication' }],
    challenge,
    domain: 'verifier.example'
  })
  await page.goto('/#/wallet/get')
  await page.reload()

  // Log in with the passphrase, then approve the DIDAuth consent screen.
  await fillSettled(page.locator('input[type="password"]'), passphrase)
  await page.getByRole('button', { name: 'Continue' }).click()
  await expect(page.getByText(/is requesting DID Authentication/)).toBeVisible()
  await page.getByRole('button', { name: 'Continue' }).click()

  await expect
    .poll(async () => (await readResponse(page)) !== undefined, {
      timeout: 20_000
    })
    .toBe(true)

  const payload = ((await readResponse(page)) as { value: DidAuthPayload })
    .value
  expect(payload.dataType).toBe('VerifiablePresentation')
  // The holder is the published did:web DID; the signing key is its
  // authentication method, resolvable in the earlier-fetched did.json.
  expect(payload.data.holder).toBe(doc.id)
  expect(payload.data.proof.proofPurpose).toBe('authentication')
  expect(payload.data.proof.challenge).toBe(challenge)
  expect(payload.data.proof.verificationMethod).toContain(`${doc.id}#`)
  expect(doc.authentication).toContain(payload.data.proof.verificationMethod)
})
