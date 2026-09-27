import { test, expect, type Page } from '@playwright/test'
import { signupViaWizard } from './helpers'

/**
 * WAS-backed E2E for a plain CHAPI `get` carrying a standalone capability
 * query (no App Connect query). Plain CHAPI delegates no capabilities: only
 * App Connect and the interaction-URL page grant storage access, since each
 * lists its grantees and can revoke them. So the popup refuses the request
 * before its login form renders, even on a wallet with a remote Space to
 * delegate against. The grant mechanics themselves are covered on the App
 * Connect path (`chapi-app-connect.spec.ts`) and the agent path
 * (`agent-grant.spec.ts`).
 */

const RP_DID = 'did:key:z6MkkxrCpdyM52QkhCaGrGRMdps26M8JQ8TmapYHPwc7n8MJ'

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

test('a login VPR carrying a capability query is refused before login', async ({
  page
}, testInfo) => {
  await signupViaWizard(page, testInfo)
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
            allowedAction: ['GET', 'HEAD', 'PUT'],
            controller: RP_DID,
            invocationTarget: {
              type: 'https://w3id.org/byoe#private-collection',
              name: 'example-app-data'
            }
          },
          {
            referenceId: 'public-credentials-read',
            reason: 'Example App reads your published credentials.',
            allowedAction: ['GET', 'HEAD'],
            controller: RP_DID,
            invocationTarget: {
              type: 'https://w3id.org/byoe#private-collection',
              name: 'public-credentials'
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

  // Refused pre-consent: no login form, no consent screen.
  await expect(
    page.getByText(/grants storage access only to apps that connect/i)
  ).toBeVisible()
  await expect(page.locator('input[type="password"]')).toHaveCount(0)
  await expect(page.getByText('Storage access', { exact: true })).toHaveCount(0)

  // Cancel answers the channel with null: nothing is delegated.
  await page.getByRole('button', { name: 'Cancel' }).click()
  await expect
    .poll(async () => (await readResponse(page)) !== undefined)
    .toBe(true)
  const response = (await readResponse(page)) as { value: unknown }
  expect(response.value).toBeNull()
})
