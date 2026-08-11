import { test, expect, type Page } from '@playwright/test'

/**
 * E2E coverage for the CHAPI "Login with Wallet" flow (`/wallet/get`) in local
 * (no-WAS) mode: a login VPR that requests DID Authentication plus a
 * self-issued Login Credential (username).
 *
 * Like the DID-Auth specs, these drive the non-production injected-event seam
 * (`window.__E2E_CHAPI_GET_EVENT__`) so the response VP is signed by the
 * wallet's real did:key. The zcap-grant assertions (which need a remote Space
 * to delegate against) live under `tests/e2e-was/`; here a zcap request is
 * expected to block cleanly, since a no-WAS wallet has nothing to delegate.
 */

type InjectedResponse = { value: unknown } | undefined

interface GetEventConfig {
  origin: string
  query: unknown
  challenge?: string
  domain?: string
}

async function injectGetEvent(page: Page, config: GetEventConfig) {
  await page.addInitScript((cfg: GetEventConfig) => {
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

async function openGetPopup(page: Page) {
  await page.goto('/#/wallet/get')
  await page.reload()
}

function readResponse(page: Page): Promise<InjectedResponse> {
  return page.evaluate(
    () =>
      (window as unknown as { __E2E_CHAPI_RESPONSE__?: { value: unknown } })
        .__E2E_CHAPI_RESPONSE__
  )
}

async function createWallet(page: Page, passphrase: string, email: string) {
  await page.goto('/#/signup')
  await page.locator('input[type="password"]').fill(passphrase)
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
  await page.getByRole('button', { name: 'Next' }).click()
  await page.locator('input[type="email"]').fill(email)
  await expect(page.getByRole('button', { name: 'Next' })).toBeEnabled()
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page).toHaveURL(/#\/signup\?.*step=storage/)
  await page.getByRole('button', { name: 'Create Wallet' }).click()
  await expect(page).toHaveURL(/#\/dashboard/)
}

/**
 * Sets the login handle in Settings (self-issues + stores a LoginCredential).
 */
async function setHandle(page: Page, username: string) {
  await page.goto('/#/settings')
  const field = page.getByLabel('Preferred username')
  await expect(field).toBeVisible()
  await field.fill(username)
  await page.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByText('Login handle saved.')).toBeVisible()
}

/**
 * The login VPR: DID Authentication + a QueryByExample for a LoginCredential.
 */
function loginQuery(challenge: string) {
  return {
    origin: 'https://app.example',
    query: [
      { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] },
      {
        type: 'QueryByExample',
        credentialQuery: {
          reason: 'Show your username on Example App.',
          example: { type: 'LoginCredential' }
        }
      }
    ],
    challenge,
    domain: 'app.example'
  }
}

async function loginInPopup(page: Page, passphrase: string) {
  await page.locator('input[type="password"]').fill(passphrase)
  await page.getByRole('button', { name: 'Continue' }).click()
}

test.describe('CHAPI Login with Wallet', () => {
  test('returns a signed VP carrying the LoginCredential with the handle', async ({
    page
  }, testInfo) => {
    const token = `${Date.now()}-w${testInfo.workerIndex}`
    const passphrase = `Str0ngpass-${token}-Aa1!`
    const email = `e2e-${token}@example.com`
    const challenge = `chal-${token}`

    await createWallet(page, passphrase, email)
    await setHandle(page, 'alice')

    await injectGetEvent(page, loginQuery(challenge))
    await openGetPopup(page)

    await loginInPopup(page, passphrase)

    // Consent screen: the friendly "share your username" row is shown.
    await expect(page.getByText(/share your username alice/i)).toBeVisible()
    await page.getByRole('button', { name: 'Continue' }).click()

    await expect
      .poll(async () => (await readResponse(page)) !== undefined, {
        timeout: 15000
      })
      .toBe(true)

    const response = (await readResponse(page)) as { value: unknown }
    const payload = response.value as {
      dataType: string
      data: {
        holder: string
        verifiableCredential?: Array<{
          type: string[]
          issuer: string
          credentialSubject: { id: string; preferredUsername: string }
        }>
        proof: { proofPurpose: string; challenge: string }
      }
    }

    expect(payload.dataType).toBe('VerifiablePresentation')
    expect(payload.data.proof.proofPurpose).toBe('authentication')
    expect(payload.data.proof.challenge).toBe(challenge)

    const vcs = payload.data.verifiableCredential
    expect(vcs).toBeDefined()
    expect(vcs).toHaveLength(1)
    const login = vcs![0]
    expect(login.type).toContain('LoginCredential')
    expect(login.issuer).toBe(payload.data.holder)
    expect(login.issuer).toBe(login.credentialSubject.id)
    expect(login.credentialSubject.preferredUsername).toBe('alice')
  })

  test('with no handle set, the login still succeeds without a VC', async ({
    page
  }, testInfo) => {
    const token = `${Date.now()}-w${testInfo.workerIndex}`
    const passphrase = `Str0ngpass-${token}-Aa1!`
    const email = `e2e-${token}@example.com`
    const challenge = `chal-${token}`

    await createWallet(page, passphrase, email)

    await injectGetEvent(page, loginQuery(challenge))
    await openGetPopup(page)

    await loginInPopup(page, passphrase)

    // No matching credential; the login (DID Auth) still proceeds.
    await expect(page.getByText(/no matching credentials/i)).toBeVisible()
    await page.getByRole('button', { name: 'Continue' }).click()

    await expect
      .poll(async () => (await readResponse(page)) !== undefined, {
        timeout: 15000
      })
      .toBe(true)

    const response = (await readResponse(page)) as { value: unknown }
    const payload = response.value as {
      dataType: string
      data: {
        verifiableCredential?: unknown
        proof: { proofPurpose: string }
      }
    }
    expect(payload.data.proof.proofPurpose).toBe('authentication')
    expect(payload.data.verifiableCredential).toBeUndefined()
  })

  test('an empty share disables Continue (only Cancel answers)', async ({
    page
  }, testInfo) => {
    const token = `${Date.now()}-w${testInfo.workerIndex}`
    const passphrase = `Str0ngpass-${token}-Aa1!`
    const email = `e2e-${token}@example.com`

    await createWallet(page, passphrase, email)

    // A VC-only request (no DID Authentication) for a credential type the
    // wallet does not hold: nothing to share, so Continue must stay disabled
    // -- an enabled Continue would compose an empty response and leave an
    // exchange-sourced verifier waiting on an answer that never comes.
    await injectGetEvent(page, {
      origin: 'https://app.example',
      query: [
        {
          type: 'QueryByExample',
          credentialQuery: {
            reason: 'Show a movie ticket.',
            example: { type: 'MovieTicketCredential' }
          }
        }
      ],
      challenge: `chal-${token}`
    })
    await openGetPopup(page)

    await loginInPopup(page, passphrase)

    await expect(page.getByText(/no matching credentials/i)).toBeVisible()
    await expect(page.getByRole('button', { name: 'Continue' })).toBeDisabled()

    await page.getByRole('button', { name: 'Cancel' }).click()
    await expect
      .poll(async () => (await readResponse(page)) !== undefined)
      .toBe(true)
    const response = (await readResponse(page)) as { value: unknown }
    expect(response.value).toBeNull()
  })

  test('a generic untyped request leaves the Login Credential unchecked', async ({
    page
  }, testInfo) => {
    const token = `${Date.now()}-w${testInfo.workerIndex}`
    const passphrase = `Str0ngpass-${token}-Aa1!`
    const email = `e2e-${token}@example.com`

    await createWallet(page, passphrase, email)
    await setHandle(page, 'alice')

    // A generic "any VC" request that never asks for a LoginCredential: the
    // stored Login Credential is still listed, but it must not be pre-checked
    // -- sharing the username has to be a deliberate click.
    await injectGetEvent(page, {
      origin: 'https://app.example',
      query: [
        {
          type: 'QueryByExample',
          credentialQuery: {
            reason: 'Present any credential.',
            example: {}
          }
        }
      ],
      challenge: `chal-${token}`
    })
    await openGetPopup(page)

    await loginInPopup(page, passphrase)

    // The row is shown with the friendly username label, but nothing is
    // pre-checked for a request that did not ask for a Login Credential.
    await expect(page.getByText(/share your username alice/i)).toBeVisible()
    await expect(page.getByRole('checkbox', { checked: true })).toHaveCount(0)
  })

  test('a LoginCredential-typed request pre-checks the Login Credential', async ({
    page
  }, testInfo) => {
    const token = `${Date.now()}-w${testInfo.workerIndex}`
    const passphrase = `Str0ngpass-${token}-Aa1!`
    const email = `e2e-${token}@example.com`
    const challenge = `chal-${token}`

    await createWallet(page, passphrase, email)
    await setHandle(page, 'alice')

    // The login VPR explicitly requests a LoginCredential, so the matching row
    // is pre-checked (one Continue completes the common login case).
    await injectGetEvent(page, loginQuery(challenge))
    await openGetPopup(page)

    await loginInPopup(page, passphrase)

    await expect(page.getByText(/share your username alice/i)).toBeVisible()
    await expect(page.getByRole('checkbox', { checked: true })).toHaveCount(1)
  })

  test('a zcap request blocks cleanly on a no-WAS wallet', async ({
    page
  }, testInfo) => {
    const token = `${Date.now()}-w${testInfo.workerIndex}`
    const passphrase = `Str0ngpass-${token}-Aa1!`
    const email = `e2e-${token}@example.com`

    await createWallet(page, passphrase, email)

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
              allowedAction: ['GET', 'HEAD', 'PUT'],
              controller: 'did:key:z6MkrRPexample',
              invocationTarget: {
                type: 'https://w3id.org/byoe#private-collection',
                name: 'example-app-data'
              }
            }
          ]
        }
      ],
      challenge: `chal-${token}`,
      domain: 'app.example'
    })
    await openGetPopup(page)

    await loginInPopup(page, passphrase)

    // Post-login, before the consent screen: the request is blocked.
    await expect(page.getByText(/needs remote storage/i)).toBeVisible()
    await page.getByRole('button', { name: 'Cancel' }).click()
    await expect
      .poll(async () => (await readResponse(page)) !== undefined)
      .toBe(true)
    const response = (await readResponse(page)) as { value: unknown }
    expect(response.value).toBeNull()
  })
})
