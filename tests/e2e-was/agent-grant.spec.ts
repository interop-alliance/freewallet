import { test, expect } from '@playwright/test'
import { CapabilityAgent } from '@interop/webkms-client'
import { WasClient, type Collection } from '@interop/was-client'
import {
  composeCapabilityRequest,
  createEphemeralExchange,
  pollEphemeralExchange
} from '@interop/wallet-core/request'
import type { IZcap } from '@interop/wallet-core/request'
import { externalRequestPath } from '@/lib/walletRequest/externalRequest'
import { fillSettled, signupViaWizard } from './helpers'

/**
 * The agent-grant e2e (WAS mode): a CLI agent asking for storage access
 * through the interaction-URL entry point, with was-client standing in for
 * the CLI. The agent mints its own did:key, stores a zcap-only VPR (one
 * `#public-collection` descriptor named `web`) on an ephemeral exchange, and
 * hands the wallet the deep link; the `/external/request` page renders the
 * storage-access consent panel, delegates on approval, and POSTs the
 * zcap-only presentation back. The agent then polls the exchange, invokes
 * the returned zcap to PUT `index.html` as `text/html`, and reads it back
 * anonymously -- the whole point of a public collection.
 *
 * Both entry states are covered in one run, since the account signup is the
 * expensive part: the first grant is answered by the session already live in
 * the app, the second by the page's own login-in-place after a reload has
 * dropped the in-memory session.
 */

const WAS_URL = 'http://localhost:3002'

/**
 * The page the agent publishes through its grant, and the content type it
 * must come back as.
 */
const PAGE_HTML = '<!doctype html><title>agent</title><h1>Hello</h1>'
const PAGE_CONTENT_TYPE = 'text/html'
const E2E_AGENT_NAME = 'e2e-agent'

/**
 * A fresh agent identity: 32 random bytes, held only by the test, standing in
 * for the key a CLI mints for itself. Nothing about it is wallet-custodied --
 * an agent is a zcap grantee, not a wallet client.
 *
 * @returns {Promise<CapabilityAgent>}
 */
async function mintAgent(): Promise<CapabilityAgent> {
  return CapabilityAgent.fromSeed({
    seed: crypto.getRandomValues(new Uint8Array(32)),
    handle: 'e2e-agent'
  })
}

/**
 * Stores the agent's zcap-only request on a fresh ephemeral exchange and
 * returns both URLs: the interaction URL for the wallet's deep link, and the
 * exchange URL the agent polls.
 *
 * @param options {object}
 * @param options.controller {string}   the agent's did:key
 * @param options.collectionName {string}   the public collection asked for
 * @returns {Promise<{ exchangeUrl: string, interactionUrl: string }>}
 */
async function storeAgentRequest({
  controller,
  collectionName
}: {
  controller: string
  collectionName: string
}): Promise<{ exchangeUrl: string; interactionUrl: string }> {
  return createEphemeralExchange({
    serverUrl: WAS_URL,
    request: composeCapabilityRequest({
      agent: { name: E2E_AGENT_NAME },
      capabilityQueries: [
        {
          referenceId: collectionName,
          // A read is asked for beside the write because was-client's upsert
          // pre-reads the resource to compare-and-swap on its ETag.
          allowedAction: ['GET', 'PUT'],
          controller,
          invocationTarget: {
            type: 'https://w3id.org/byoe#public-collection',
            name: collectionName
          }
        }
      ]
    })
  })
}

/**
 * Polls the exchange for the wallet's answer and returns the delegated zcaps
 * embedded in the response presentation.
 *
 * @param options {object}
 * @param options.exchangeUrl {string}
 * @returns {Promise<IZcap[]>}
 */
async function grantedZcaps({
  exchangeUrl
}: {
  exchangeUrl: string
}): Promise<IZcap[]> {
  const response = (await pollEphemeralExchange({
    exchangeUrl,
    timeoutMs: 60_000,
    intervalMs: 1000
  })) as { verifiablePresentation?: { zcap?: IZcap[] } }
  return response?.verifiablePresentation?.zcap ?? []
}

/**
 * The agent's half of the grant: rebuild a collection handle from the
 * delegated zcap, PUT the page, and read it back with an unauthenticated
 * fetch. Returns the anonymous response.
 *
 * @param options {object}
 * @param options.agent {CapabilityAgent}
 * @param options.zcap {IZcap}
 * @param options.resourceId {string}
 * @returns {Promise<Response>}
 */
async function publishAndFetch({
  agent,
  zcap,
  resourceId
}: {
  agent: CapabilityAgent
  zcap: IZcap
  resourceId: string
}): Promise<Response> {
  const was = WasClient.fromSigner({
    serverUrl: WAS_URL,
    signer: agent.getSigner()
  })
  const collection = was.fromCapability(zcap) as Collection
  await collection.put(
    resourceId,
    new Blob([PAGE_HTML], { type: PAGE_CONTENT_TYPE }),
    { contentType: PAGE_CONTENT_TYPE }
  )
  // No authorization header at all: a public collection is world-readable,
  // which is exactly what the agent asked the wallet for.
  return fetch(`${zcap.invocationTarget}/${resourceId}`)
}

/**
 * Asserts the granted zcap covers the collection asked for, publishes
 * through it, and asserts the anonymous read.
 *
 * @param options {object}
 * @param options.agent {CapabilityAgent}
 * @param options.exchangeUrl {string}
 * @param options.collectionName {string}
 * @param options.resourceId {string}
 * @returns {Promise<void>}
 */
async function expectPublishedPage({
  agent,
  exchangeUrl,
  collectionName,
  resourceId
}: {
  agent: CapabilityAgent
  exchangeUrl: string
  collectionName: string
  resourceId: string
}): Promise<void> {
  const zcaps = await grantedZcaps({ exchangeUrl })
  expect(zcaps.length).toBe(1)
  const zcap = zcaps[0]!
  expect(zcap.invocationTarget.endsWith(`/${collectionName}`)).toBe(true)
  expect(zcap.controller).toBe(agent.id)

  const published = await publishAndFetch({ agent, zcap, resourceId })
  expect(published.status).toBe(200)
  expect(published.headers.get('content-type')).toMatch(/^text\/html/)
  expect(await published.text()).toContain('Hello')
}

test.describe('agent grant over an interaction URL', () => {
  test('grants a public collection to a CLI agent, from a live session and from a login in place', async ({
    page
  }, testInfo) => {
    test.slow()

    const agent = await mintAgent()
    const collectionName = 'web'
    const { passphrase } = await signupViaWizard(page, testInfo)

    // The live-session path: the page adopts the session already in the app
    // and goes straight to consent.
    const live = await storeAgentRequest({
      controller: agent.id,
      collectionName
    })
    await page.goto(`/#${externalRequestPath({ url: live.interactionUrl })}`)
    await expect(
      page.getByRole('button', { name: 'Grant access' })
    ).toBeVisible({ timeout: 30_000 })
    // The self-declared name renders beside the key, marked as the agent's
    // own claim.
    await expect(
      page.getByText(`An agent calling itself "${E2E_AGENT_NAME}"`)
    ).toBeVisible()
    await page.getByRole('button', { name: 'Grant access' }).click()
    await expect(
      page.getByText('Access granted', { exact: false })
    ).toBeVisible({ timeout: 60_000 })
    await expectPublishedPage({
      agent,
      exchangeUrl: live.exchangeUrl,
      collectionName,
      resourceId: 'index.html'
    })

    // The login-in-place path: a reload drops the in-memory session, so the
    // page runs the ordinary login itself (durable here -- this browser
    // holds the client-key record signup wrote) and then consents.
    const second = await storeAgentRequest({
      controller: agent.id,
      collectionName
    })
    await page.goto(`/#${externalRequestPath({ url: second.interactionUrl })}`)
    // The `goto` is a same-document hash change, so the reload is what
    // actually drops the in-memory session and re-opens the request cold.
    await page.reload()
    await fillSettled(page.locator('input[type="password"]'), passphrase)
    await page.getByRole('button', { name: 'Continue' }).click()
    await expect(
      page.getByRole('button', { name: 'Grant access' })
    ).toBeVisible({ timeout: 60_000 })
    await page.getByRole('button', { name: 'Grant access' }).click()
    await expect(
      page.getByText('Access granted', { exact: false })
    ).toBeVisible({ timeout: 60_000 })
    await expectPublishedPage({
      agent,
      exchangeUrl: second.exchangeUrl,
      collectionName,
      resourceId: 'about.html'
    })
  })
})
