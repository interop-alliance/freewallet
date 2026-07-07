import {
  test,
  expect,
  type Frame,
  type Page,
  type TestInfo
} from '@playwright/test'

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
 * Hosted did:web DID e2e (Track F, Phase 1). Runs against the app in remote
 * mode backed by the local was-teaching-server (whose `/kms` facet is the
 * default KMS). Covers three things:
 *
 * 1. Signing up provisions and publishes a did:web document as a world-readable
 *    WAS resource, while the sibling key-id map stays capability-only.
 * 2. A full-tier CHAPI DIDAuth request is signed by the KMS-held
 *    `authentication` key, and the VP's holder / verificationMethod resolve
 *    against the published `did.json`.
 * 3. A refresh-restored (delegated) session completes a DIDAuth-only request in
 *    a cross-site CHAPI popup with NO passphrase -- the payoff of moving DIDAuth
 *    onto a KMS-held key.
 */

const APP_PORT = 5274
const WALLET = `http://localhost:${APP_PORT}`
const HARNESS_URL =
  `http://127.0.0.1:${APP_PORT}/embed-harness.html?src=` +
  encodeURIComponent(`${WALLET}/#/wallet/get`)

interface GetEventConfig {
  origin: string
  query: unknown
  challenge?: string
  domain?: string
}

/**
 * Injects a canned CHAPI get event whose `respondWith` records the response on
 * `window.__E2E_CHAPI_RESPONSE__`. Context-scoped so it also runs inside the
 * cross-site wallet iframe (test 3).
 */
async function injectGetEvent(
  scope: Page,
  config: GetEventConfig,
  { contextWide = false }: { contextWide?: boolean } = {}
) {
  const target = contextWide ? scope.context() : scope
  await target.addInitScript((cfg: GetEventConfig) => {
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
 * Waits until the delegated-session record has landed in the wallet origin's
 * first-party IndexedDB (persistDelegatedSession runs fire-and-forget after
 * login). Polls without ever creating the database.
 */
async function waitForPersistedSession(page: Page) {
  await page.waitForFunction(async () => {
    const databases = await indexedDB.databases()
    if (!databases.some(db => db.name === 'freewallet-session')) {
      return false
    }
    return await new Promise<boolean>(resolve => {
      const request = indexedDB.open('freewallet-session', 1)
      request.onerror = () => resolve(false)
      request.onsuccess = () => {
        const db = request.result
        try {
          const get = db
            .transaction('session', 'readonly')
            .objectStore('session')
            .get('record')
          get.onsuccess = () => {
            db.close()
            resolve(get.result != null)
          }
          get.onerror = () => {
            db.close()
            resolve(false)
          }
        } catch {
          db.close()
          resolve(false)
        }
      }
    })
  })
}

function walletFrame(page: Page): Frame {
  const frame = page
    .frames()
    .find(candidate => candidate.url().startsWith(WALLET))
  expect(frame, 'the harness must embed the wallet').toBeTruthy()
  return frame!
}

test('signup publishes a did:web document and a full-tier DIDAuth VP is signed by the KMS key', async ({
  page
}, testInfo) => {
  // Real KMS key generation + lazy dictionary loads against one teaching
  // server; give it slack beyond the 30s default under load.
  test.slow()
  const { passphrase } = await signup(page, testInfo)

  // --- Provisioning: the DID document is published, keys.json is not. ---
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
  expect(doc.verificationMethod).toHaveLength(3)
  expect(doc.authentication).toHaveLength(1)
  expect(doc.assertionMethod).toHaveLength(1)
  expect(doc.keyAgreement).toHaveLength(1)
  // Each relationship references one of the document's verification methods.
  const vmIds = doc.verificationMethod.map(vm => vm.id)
  expect(vmIds).toContain(doc.authentication[0])
  expect(vmIds).toContain(doc.keyAgreement[0])

  // The key-id map is not public: an unauthenticated GET is refused (WAS
  // returns 404 for both not-found and unauthorized).
  const keysUrl = didJsonUrl.replace('/did.json', '/keys.json')
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
  await page.locator('input[type="password"]').fill(passphrase)
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

test('a restored delegated session completes DIDAuth in a popup with no passphrase', async ({
  page,
  context
}, testInfo) => {
  test.slow()
  // The user already clicked "Allow" on Chrome's storage-access prompt.
  await context.grantPermissions(['storage-access'])

  const origin = 'https://verifier.example'
  const challenge = `chal-${Date.now()}-w${testInfo.workerIndex}`

  // 1. Top-level signup on the wallet origin provisions did:web and persists
  //    the delegated session (with its did:web key map) first-party. The CHAPI
  //    event is injected only afterwards, so its init script never runs on the
  //    signup page.
  await signup(page, testInfo)
  await waitForPersistedSession(page)

  await injectGetEvent(
    page,
    {
      origin,
      query: [{ type: 'DIDAuthentication' }],
      challenge,
      domain: 'verifier.example'
    },
    { contextWide: true }
  )

  // 2. Load /wallet/get as a third-party iframe under a cross-site top level.
  await page.goto(HARNESS_URL)
  const frame = walletFrame(page)

  // 3. The saved login is recognized (silently, or after the button); because
  //    the request is DIDAuth-only and a did:web is provisioned, the popup goes
  //    straight to the consent screen -- no passphrase form is used.
  const consent = frame.getByText(/is requesting DID Authentication/)
  const useSaved = frame.getByRole('button', { name: 'Use saved login' })
  await expect(consent.or(useSaved)).toBeVisible({ timeout: 15_000 })
  if (!(await consent.isVisible())) {
    // The silent restore can complete between the visibility check and the
    // click, unmounting the button in favor of the consent screen -- race
    // the click against that outcome rather than insisting on the button.
    await Promise.race([
      useSaved.click().catch(() => undefined),
      consent.waitFor({ state: 'visible', timeout: 15_000 })
    ])
  }
  await expect(consent).toBeVisible({ timeout: 15_000 })

  // 4. Approve; the VP comes back signed by the KMS key, no passphrase entered.
  await frame.getByRole('button', { name: 'Continue', exact: true }).click()
  await expect
    .poll(async () => (await readResponse(frame)) !== undefined, {
      timeout: 20_000
    })
    .toBe(true)

  const payload = ((await readResponse(frame)) as { value: DidAuthPayload })
    .value
  expect(payload.dataType).toBe('VerifiablePresentation')
  expect(payload.data.holder).toMatch(/^did:web:/)
  expect(payload.data.proof.proofPurpose).toBe('authentication')
  expect(payload.data.proof.challenge).toBe(challenge)
  expect(payload.data.proof.verificationMethod).toContain(
    `${payload.data.holder}#`
  )
})
