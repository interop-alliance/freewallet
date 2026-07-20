import { test, expect, type Page } from '@playwright/test'
import { signupViaWizard } from './helpers'

/**
 * WAS-backed E2E for the App Connect CHAPI consent flow. A single CHAPI `get`
 * carrying an `AppConnectQuery` (plus DID Authentication) replaces the generic
 * consent sections with the app-centric "Connect {app}?" panel. On the
 * approve path the wallet match-or-mints the app-key credential for the
 * requesting origin, delegates the requested collection capabilities to that
 * credential's subject DID, and returns credential + grants + a `firstRun`
 * marker in one signed presentation.
 *
 * Like `chapi-login-zcap.spec.ts`, this runs against the local WAS teaching
 * server so the wallet provisions the app's collection and delegates real,
 * Space-rooted zcaps; the popup is driven through the `__E2E_CHAPI_GET_EVENT__`
 * seam (see the note in `WalletGetPage`).
 */

const APP = {
  name: 'Test App',
  credentialType: 'TestAppKey',
  vocabBase: 'urn:test-app:vocab#'
}
const APP_ORIGIN = 'https://app.example'
const APP_DOMAIN = 'app.example'
const APP_COLLECTION = 'test-app-data'

async function injectGetEvent(
  page: Page,
  config: {
    origin: string
    query: unknown
    challenge?: string
    domain?: string
  }
) {
  await page.addInitScript(
    (cfg: {
      origin: string
      query: unknown
      challenge?: string
      domain?: string
    }) => {
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
    },
    config
  )
}

function readResponse(page: Page) {
  return page.evaluate(
    () =>
      (window as unknown as { __E2E_CHAPI_RESPONSE__?: { value: unknown } })
        .__E2E_CHAPI_RESPONSE__
  )
}

/**
 * The App Connect VPR: DID Authentication plus a single `AppConnectQuery`
 * naming the app and asking for a read/write grant on one collection. The
 * `capabilityQuery` deliberately omits `controller` -- the wallet fills it
 * with the app-key subject DID.
 */
function appConnectQuery() {
  return [
    { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] },
    {
      type: 'AppConnectQuery',
      app: APP,
      capabilityQuery: [
        {
          referenceId: APP_COLLECTION,
          allowedAction: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'],
          invocationTarget: {
            type: 'urn:was:collection',
            name: APP_COLLECTION
          }
        }
      ]
    }
  ]
}

interface AppConnectResponse {
  data: {
    verifiableCredential: unknown
    zcap: Array<{
      invocationTarget: string
      controller: string
      allowedAction: string[]
    }>
    appConnect: { firstRun: boolean }
    proof: { proofPurpose: string; challenge: string; domain: string }
  }
}

/**
 * The single app-key credential carried by an App Connect response (the VP's
 * `verifiableCredential` may be a single object or an array).
 */
function appKeyCredential(response: AppConnectResponse) {
  const carried = response.data.verifiableCredential
  const credential = (Array.isArray(carried) ? carried[0] : carried) as {
    type: string | string[]
    issuer: string | { id: string }
    credentialSubject: { id: string; origin: string }
  }
  return credential
}

/**
 * Drives one App Connect popup visit for an already-created account: injects
 * the request, logs in, approves the consent panel, and returns the recorded
 * response. `firstRun` selects which consent copy to assert.
 */
async function connectViaPopup(
  page: Page,
  {
    passphrase,
    challenge,
    firstRun
  }: { passphrase: string; challenge: string; firstRun: boolean }
): Promise<AppConnectResponse> {
  await injectGetEvent(page, {
    origin: APP_ORIGIN,
    query: appConnectQuery(),
    challenge,
    domain: APP_DOMAIN
  })

  await page.goto('/#/wallet/get')
  await page.reload()

  await page.locator('input[type="password"]').fill(passphrase)
  await page.getByRole('button', { name: 'Continue' }).click()

  // The app-centric consent panel: "Connect {app}?" plus the run-specific copy.
  await expect(
    page.getByRole('heading', { name: 'Connect Test App to storage?' })
  ).toBeVisible({ timeout: 15000 })
  if (firstRun) {
    await expect(
      page.getByText(/will keep an app key in your wallet/)
    ).toBeVisible()
  } else {
    await expect(
      page.getByText(/wants to use the app key saved in your wallet/)
    ).toBeVisible()
  }
  // The requested collection is previewed in the storage-access panel (the
  // collection id renders as its own monospace badge).
  await expect(page.getByText('test-app-data', { exact: true })).toBeVisible()

  await page.getByRole('button', { name: 'Connect' }).click()

  await expect
    .poll(async () => (await readResponse(page)) !== undefined, {
      timeout: 30000
    })
    .toBe(true)

  const recorded = (await readResponse(page)) as { value: unknown }
  return recorded.value as AppConnectResponse
}

test('first-run App Connect mints an app key and grants over its collection', async ({
  page
}, testInfo) => {
  const { passphrase } = await signupViaWizard(page, testInfo)
  const challenge = `chal-connect-${Date.now()}-w${testInfo.workerIndex}`

  const response = await connectViaPopup(page, {
    passphrase,
    challenge,
    firstRun: true
  })

  // Signed DID-Auth presentation bound to the request challenge/domain.
  expect(response.data.proof.proofPurpose).toBe('authentication')
  expect(response.data.proof.challenge).toBe(challenge)
  expect(response.data.proof.domain).toBe(APP_DOMAIN)

  // The app-key credential: type TestAppKey, self-issued (issuer == subject),
  // bound to the requesting origin.
  const credential = appKeyCredential(response)
  const types = Array.isArray(credential.type)
    ? credential.type
    : [credential.type]
  expect(types).toContain('TestAppKey')
  const subjectDid = credential.credentialSubject.id
  const issuer =
    typeof credential.issuer === 'string'
      ? credential.issuer
      : credential.issuer.id
  expect(subjectDid).toMatch(/^did:key:/)
  expect(issuer).toBe(subjectDid)
  expect(credential.credentialSubject.origin).toBe(APP_ORIGIN)

  // A grant over the app's collection, delegated to the app-key subject DID.
  expect(response.data.zcap.length).toBeGreaterThanOrEqual(1)
  const grant = response.data.zcap.find(zcap =>
    zcap.invocationTarget.endsWith(`/${APP_COLLECTION}`)
  )!
  expect(grant).toBeDefined()
  expect(grant.controller).toBe(subjectDid)
  expect(grant.allowedAction).toContain('PUT')

  // The wallet-provided first-run marker.
  expect(response.data.appConnect.firstRun).toBe(true)
})

test('returning App Connect reuses the same app key and marks firstRun false', async ({
  page
}, testInfo) => {
  const { passphrase } = await signupViaWizard(page, testInfo)
  const token = `${Date.now()}-w${testInfo.workerIndex}`

  const first = await connectViaPopup(page, {
    passphrase,
    challenge: `chal-first-${token}`,
    firstRun: true
  })
  expect(first.data.appConnect.firstRun).toBe(true)
  const firstSubjectDid = appKeyCredential(first).credentialSubject.id

  // A second visit by the same account finds the stored app key: returning copy,
  // the SAME subject DID, and firstRun === false.
  const second = await connectViaPopup(page, {
    passphrase,
    challenge: `chal-return-${token}`,
    firstRun: false
  })

  const secondSubjectDid = appKeyCredential(second).credentialSubject.id
  expect(secondSubjectDid).toBe(firstSubjectDid)
  expect(second.data.appConnect.firstRun).toBe(false)
})

test('an AppConnectQuery mixed with QueryByExample is blocked as malformed', async ({
  page
}) => {
  // One mental model per popup: mixing App Connect with a QueryByExample must
  // fail closed, not degrade into a partial generic flow. The mix is rejected
  // at classification time, before any login form is shown.
  await injectGetEvent(page, {
    origin: APP_ORIGIN,
    query: [
      { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] },
      {
        type: 'AppConnectQuery',
        app: APP,
        capabilityQuery: []
      },
      {
        type: 'QueryByExample',
        credentialQuery: {
          reason: 'Also asking for a credential.',
          example: { type: 'VerifiableCredential' }
        }
      }
    ],
    challenge: 'chal-mixed',
    domain: APP_DOMAIN
  })

  await page.goto('/#/wallet/get')
  await page.reload()

  await expect(
    page.getByText("This site didn't send a request this wallet can read.")
  ).toBeVisible({ timeout: 15000 })
  // Blocked before login -- no passphrase form.
  await expect(page.locator('input[type="password"]')).toHaveCount(0)
})
