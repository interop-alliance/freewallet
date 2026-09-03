import {
  test,
  expect,
  type Frame,
  type Page,
  type TestInfo
} from '@playwright/test'
import { fillSettled, forceRememberBrowser } from './helpers'

/**
 * The did:web projection e2e. Runs against the app in remote mode backed by
 * the local was-teaching-server (whose `/kms` facet is the default KMS).
 * Covers two things:
 *
 * 1. `id/did.json` is the did:webvh log's own projection and nothing else
 *    writes it -- the wallet mints no standalone did:web document, so exactly
 *    one PUT to that resource happens during a signup. The sibling key map
 *    stays capability-only.
 * 2. The DIDAuth holder dispatch: an unconstrained CHAPI request is answered
 *    with the projection id, a `webvh`-constrained one with the account's
 *    did:webvh, and a request accepting only a method no session can present
 *    is blocked before the password box.
 */

/**
 * Signup wizard walk with generous waits. Same steps as the shared
 * `signupViaWizard`, but each test here provisions a keystore and its one KMS
 * key against one teaching server, so both the lazily-loaded
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

/**
 * Answers one injected CHAPI DIDAuth request from a logged-out popup, through
 * the login form and the consent screen, and returns the recorded response.
 */
async function answerDidAuth({
  page,
  passphrase,
  query,
  challenge
}: {
  page: Page
  passphrase: string
  query: unknown
  challenge: string
}) {
  await injectGetEvent(page, {
    origin: 'https://verifier.example',
    query,
    challenge,
    domain: 'verifier.example'
  })
  await page.goto('/#/wallet/get')
  await page.reload()

  await fillSettled(page.locator('input[type="password"]'), passphrase)
  await page.getByRole('button', { name: 'Continue' }).click()
  await expect(page.getByText(/is requesting DID Authentication/)).toBeVisible()
  await page.getByRole('button', { name: 'Continue' }).click()

  await expect
    .poll(async () => (await readResponse(page)) !== undefined, {
      timeout: 20_000
    })
    .toBe(true)
  return ((await readResponse(page)) as { value: DidAuthPayload }).value
}

test('signup publishes the did:webvh projection as the only did.json writer', async ({
  page
}, testInfo) => {
  // Real KMS key generation + lazy dictionary loads against one teaching
  // server; give it slack beyond the 30s default under load.
  test.slow()

  // Every mutating request the signup makes (reads and the dev-server NDJSON
  // log sink excluded), so a non-PUT `did.json` writer cannot come back
  // silently.
  const writes: Array<{ method: string; pathname: string }> = []
  page.on('request', request => {
    const method = request.method()
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
      return
    }
    if (new URL(request.url()).pathname === '/__interop-logger') {
      return
    }
    writes.push({ method, pathname: new URL(request.url()).pathname })
  })

  await signup(page, testInfo)

  await page.goto('/#/settings')
  await expect(page.getByText('Published DID', { exact: true })).toBeVisible()
  await expect(
    page.getByText('Published', { exact: true }).first()
  ).toBeVisible({
    timeout: 15_000
  })
  // The KMS binding is its own fact beside the derived projection id: an
  // account whose keystore came up but whose KMS stage did not is
  // distinguishable here.
  await expect(
    page.getByText('Key server signing key recorded', { exact: true })
  ).toBeVisible({ timeout: 15_000 })

  // The settings page links the world-readable resolution URL.
  const didJsonLink = page.getByRole('link', { name: /\/id\/did\.json$/ })
  await expect(didJsonLink).toBeVisible()
  const didJsonUrl = (await didJsonLink.getAttribute('href'))!

  // One writer: the projection, republished by the log's own publish after
  // each entry (the genesis and the self-enrollment's two entries on a
  // remembered signup). Playwright does not expose the streamed PUT body,
  // so the wire check is the method alone and the served document below is
  // what proves every write was the projection: the retired hand-assembled
  // document never carried `alsoKnownAs`.
  const didJsonPath = new URL(didJsonUrl).pathname
  const didJsonWrites = writes.filter(write => write.pathname === didJsonPath)
  expect(didJsonWrites.length).toBeGreaterThan(0)
  expect(didJsonWrites.every(write => write.method === 'PUT')).toBe(true)

  // A cold, unauthenticated GET resolves the DID document.
  const didRes = await page.request.get(didJsonUrl)
  expect(didRes.status()).toBe(200)
  const doc = (await didRes.json()) as {
    id: string
    alsoKnownAs?: string[]
    verificationMethod: Array<{ id: string; type: string }>
    authentication: string[]
    assertionMethod: string[]
    capabilityInvocation: string[]
    keyAgreement: string[]
  }
  // The projection is the did:webvh document with its ids rewritten, so it
  // names the did:webvh in `alsoKnownAs` and carries the same relations.
  expect(doc.id).toMatch(/^did:web:.+:space:.+:id$/)
  expect(doc.alsoKnownAs?.some(aka => aka.startsWith('did:webvh:'))).toBe(true)
  // One KMS-held VM under `authentication` beside this client's signing key;
  // `assertionMethod` lists client-side keys only (membership there confers
  // resource-log-append authority, so no KMS key is minted for it), and
  // `keyAgreement` is the client's KAK plus the passphrase's standing entry
  // as a hash commitment -- never a server-held key, which may not be a wrap
  // target. Verification-method TYPES are deliberately not asserted: that
  // commitment is a `MultikeyCommitment`, not a `Multikey`.
  expect(doc.authentication).toHaveLength(2)
  expect(doc.keyAgreement).toHaveLength(2)
  // The KMS key is the one `authentication` entry no client is published
  // under: an enrolled client publishes its signing key under
  // `capabilityInvocation` too. `assertionMethod` is asserted by MEMBERSHIP
  // rather than by count, since the credential's ladder VM stands there
  // beside the client key after a remembered signup's self-enrollment.
  const invocationIds = new Set(doc.capabilityInvocation)
  const kmsVmIds = doc.authentication.filter(id => !invocationIds.has(id))
  expect(kmsVmIds).toHaveLength(1)
  for (const id of doc.capabilityInvocation) {
    expect(doc.assertionMethod).toContain(id)
  }
  for (const id of kmsVmIds) {
    expect(doc.assertionMethod).not.toContain(id)
  }
  // Each relationship references one of the document's verification methods,
  // under the projected did:web id.
  const vmIds = doc.verificationMethod.map(vm => vm.id)
  for (const id of [...doc.authentication, ...doc.keyAgreement]) {
    expect(vmIds).toContain(id)
    expect(id.startsWith(`${doc.id}#`)).toBe(true)
  }

  // The key-id map lives alone in the private `key-map` collection and is not
  // public: an unauthenticated GET is refused (WAS returns 404 for both
  // not-found and unauthorized).
  const keysUrl = didJsonUrl.replace('/id/did.json', '/key-map/keys.json')
  const keysRes = await page.request.get(keysUrl)
  expect([401, 403, 404]).toContain(keysRes.status())
})

test('the DIDAuth holder follows the request acceptedMethods', async ({
  page
}, testInfo) => {
  test.slow()
  const { passphrase } = await signup(page, testInfo)

  await page.goto('/#/settings')
  const didJsonLink = page.getByRole('link', { name: /\/id\/did\.json$/ })
  await expect(didJsonLink).toBeVisible({ timeout: 15_000 })
  const didJsonUrl = (await didJsonLink.getAttribute('href'))!
  const doc = (await (await page.request.get(didJsonUrl)).json()) as {
    id: string
    alsoKnownAs?: string[]
    authentication: string[]
  }
  const accountDid = (doc.alsoKnownAs ?? []).find(aka =>
    aka.startsWith('did:webvh:')
  )!

  // Unconstrained: the projection id, whose verification method resolves in
  // the fetched did.json.
  const unconstrained = await answerDidAuth({
    page,
    passphrase,
    query: [{ type: 'DIDAuthentication' }],
    challenge: `chal-web-${Date.now()}-w${testInfo.workerIndex}`
  })
  expect(unconstrained.dataType).toBe('VerifiablePresentation')
  expect(unconstrained.data.holder).toBe(doc.id)
  expect(unconstrained.data.proof.proofPurpose).toBe('authentication')
  expect(doc.authentication).toContain(
    unconstrained.data.proof.verificationMethod
  )

  // `webvh` accepted: the account's own did:webvh, under the same key's
  // did:webvh verification-method id. Blocked outright before this item.
  const webvh = await answerDidAuth({
    page,
    passphrase,
    query: [
      { type: 'DIDAuthentication', acceptedMethods: [{ method: 'webvh' }] }
    ],
    challenge: `chal-webvh-${Date.now()}-w${testInfo.workerIndex}`
  })
  expect(webvh.data.holder).toBe(accountDid)
  expect(webvh.data.proof.verificationMethod.startsWith(`${accountDid}#`)).toBe(
    true
  )
})

test('a DID method no session can present is blocked before login', async ({
  page
}, testInfo) => {
  await injectGetEvent(page, {
    origin: 'https://verifier.example',
    query: [
      { type: 'DIDAuthentication', acceptedMethods: [{ method: 'ion' }] }
    ],
    challenge: `chal-ion-${Date.now()}-w${testInfo.workerIndex}`,
    domain: 'verifier.example'
  })
  await page.goto('/#/wallet/get')
  await page.reload()

  // Deployment capability alone settles this one, so no password box renders.
  await expect(
    page.getByText(/only accepts DID methods/, { exact: false })
  ).toBeVisible({ timeout: 15_000 })
  await expect(page.locator('input[type="password"]')).toHaveCount(0)
})
