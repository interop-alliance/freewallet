import { test, expect, type Page } from '@playwright/test'
import { signupViaWizard, goToHistory, expectHistoryEntry } from './helpers'

/**
 * WAS-backed E2E for "Login with Wallet" grants: a login VPR that requests
 * DID Authentication plus two WAS capabilities (a new RP collection and a
 * whole-Space read). Unlike the no-WAS `tests/e2e/chapi-login.spec.ts`, this
 * runs against the local WAS teaching server, so the wallet actually
 * provisions the collection and delegates real, Space-rooted zcaps.
 */

const RP_DID = 'did:key:z6MkrRPexampleRelyingPartyForE2ELoginTests'

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

test('login VPR provisions a collection and returns Space-rooted grants', async ({
  page
}, testInfo) => {
  const { passphrase } = await signupViaWizard(page, testInfo)
  const challenge = `chal-${Date.now()}-w${testInfo.workerIndex}`

  await injectGetEvent(page, {
    origin: 'https://app.example',
    query: [
      { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] },
      {
        type: 'AuthorizationCapabilityQuery',
        capabilityQuery: [
          {
            referenceId: 'example-app-data',
            reason: 'Example App stores your documents.',
            allowedAction: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'],
            controller: RP_DID,
            invocationTarget: {
              type: 'urn:was:collection',
              name: 'example-app-data'
            }
          },
          {
            referenceId: 'space-read',
            reason: 'Example App reads your wallet Space.',
            allowedAction: ['GET', 'HEAD', 'PUT'],
            controller: RP_DID,
            invocationTarget: { type: 'urn:was:space' }
          }
        ]
      }
    ],
    challenge,
    domain: 'app.example'
  })

  await page.goto('/#/wallet/get')
  await page.reload()

  await page.locator('input[type="password"]').fill(passphrase)
  await page.getByRole('button', { name: 'Continue' }).click()

  // Consent screen lists the grants; approve.
  await expect(page.getByText('Storage access')).toBeVisible()
  await expect(
    page.getByText('example-app-data', { exact: true })
  ).toBeVisible()
  await page.getByRole('button', { name: 'Continue' }).click()

  await expect
    .poll(async () => (await readResponse(page)) !== undefined, {
      timeout: 20000
    })
    .toBe(true)

  const response = (await readResponse(page)) as { value: unknown }
  const payload = response.value as {
    data: {
      proof: { proofPurpose: string }
      zcap: Array<{
        invocationTarget: string
        controller: string
        allowedAction: string[]
        expires: string
      }>
    }
  }

  expect(payload.data.proof.proofPurpose).toBe('authentication')
  expect(payload.data.zcap).toHaveLength(2)

  const collectionGrant = payload.data.zcap.find(zcap =>
    zcap.invocationTarget.endsWith('/example-app-data')
  )!
  expect(collectionGrant.controller).toBe(RP_DID)
  expect(collectionGrant.allowedAction).toContain('PUT')
  expect(new Date(collectionGrant.expires).getTime()).toBeGreaterThan(
    Date.now()
  )

  // The whole-Space grant is stripped to read-only.
  const spaceGrant = payload.data.zcap.find(
    zcap => !zcap.invocationTarget.endsWith('/example-app-data')
  )!
  expect(spaceGrant.allowedAction).toEqual(['GET', 'HEAD'])

  // The login is recorded in history. The popup page itself has no navigation
  // (after respondWith it stays on its terminal sharing screen; in a real
  // CHAPI flow the mediator closes it), so log in to the main app shell: it
  // opens the same per-user local replica the popup wrote the entry to, with
  // the vault unlocked. Login pays the keyring's deliberately slow PBKDF2
  // unlock derivation, so it can run past the default 5s assertion timeout.
  await page.goto('/#/login')
  await page.locator('input[type="password"]').fill(passphrase)
  await page.getByRole('button', { name: 'Log in', exact: true }).click()
  await expect(page).toHaveURL(/#\/dashboard/, { timeout: 30_000 })
  await goToHistory(page)
  await expectHistoryEntry(page, /Logged in to https:\/\/app\.example/)
})

test('public-collection VPR provisions a world-readable collection', async ({
  page,
  request
}, testInfo) => {
  const { passphrase } = await signupViaWizard(page, testInfo)
  const challenge = `chal-pub-${Date.now()}-w${testInfo.workerIndex}`

  await injectGetEvent(page, {
    origin: 'https://app.example',
    query: [
      { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] },
      {
        type: 'AuthorizationCapabilityQuery',
        capabilityQuery: [
          {
            referenceId: 'example-app-public',
            reason: 'Example App publishes your posts for anyone to read.',
            allowedAction: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'],
            controller: RP_DID,
            invocationTarget: {
              type: 'urn:was:public-collection',
              name: 'example-app-public'
            }
          }
        ]
      }
    ],
    challenge,
    domain: 'app.example'
  })

  await page.goto('/#/wallet/get')
  await page.reload()

  await page.locator('input[type="password"]').fill(passphrase)
  await page.getByRole('button', { name: 'Continue' }).click()

  // Consent screen shows the world-readable warning for the public grant.
  await expect(page.getByText('Storage access')).toBeVisible()
  await expect(
    page.getByText('example-app-public', { exact: true })
  ).toBeVisible()
  await expect(
    page.getByText(/anyone on the web will be able to read it/i)
  ).toBeVisible()
  // Public implies plaintext, so the ciphertext note never applies.
  await expect(
    page.getByText(/this site will only see ciphertext/i)
  ).toHaveCount(0)
  await page.getByRole('button', { name: 'Continue' }).click()

  await expect
    .poll(async () => (await readResponse(page)) !== undefined, {
      timeout: 20000
    })
    .toBe(true)

  const response = (await readResponse(page)) as { value: unknown }
  const payload = response.value as {
    data: {
      zcap: Array<{ invocationTarget: string; allowedAction: string[] }>
    }
  }

  // The delegated zcap carries a write action, capped to add-only: a public
  // collection is a publication surface, so the request's `PUT` and `DELETE`
  // are dropped and only `POST` survives alongside the reads.
  expect(payload.data.zcap).toHaveLength(1)
  const grant = payload.data.zcap[0]
  expect(grant.invocationTarget.endsWith('/example-app-public')).toBe(true)
  expect(grant.allowedAction).toEqual(['GET', 'HEAD', 'POST'])

  // The collection itself is world-readable: an unauthenticated (no zcap,
  // no cookies) GET on the collection URL lists it instead of being denied.
  const anonymousList = await request.get(grant.invocationTarget)
  expect(anonymousList.status()).toBe(200)
})
