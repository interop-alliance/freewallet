import { test, expect, type Page } from '@playwright/test'
import { CapabilityAgent } from '@interop/capability-agent'
import {
  WasClient,
  type Collection,
  type CollectionEncryption,
  type JsonObject
} from '@interop/was-client'
import {
  createEdvEncryption,
  isEncryptedEnvelope,
  x25519RecipientFromDidKey
} from '@interop/was-client/edv'
import { agentsFromKeyAgent } from '@interop/was-client/identity'
import {
  composeCapabilityRequest,
  createEphemeralExchange,
  pollEphemeralExchange
} from '@interop/wallet-request'
import type { IZcap } from '@interop/wallet-request'
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
 * dropped the in-memory session. A third case brings its own account: the
 * transient session a non-remembered browser defaults to, whose grants chain
 * under the generation delegation rather than the Space root. A fourth case
 * asks for a private collection, which the wallet provisions encrypted with
 * the agent's key-agreement key escrowed beside the user's, and checks that
 * revoking the agent rotates the collection's key off it.
 */

const WAS_URL = 'http://localhost:3002'

/**
 * The page the agent publishes through its grant, and the content type it
 * must come back as.
 */
const PAGE_HTML = '<!doctype html><title>agent</title><h1>Hello</h1>'
const PAGE_CONTENT_TYPE = 'text/html'
const E2E_AGENT_NAME = 'e2e-agent'
const PUBLIC_COLLECTION = 'https://w3id.org/byoe#public-collection'
const PRIVATE_COLLECTION = 'https://w3id.org/byoe#private-collection'

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
 * @param options.collectionName {string}   the collection asked for
 * @param [options.type] {string}   the descriptor type; a public collection
 *   unless given
 * @returns {Promise<{ exchangeUrl: string, interactionUrl: string }>}
 */
async function storeAgentRequest({
  controller,
  collectionName,
  type = PUBLIC_COLLECTION
}: {
  controller: string
  collectionName: string
  type?: string
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
          invocationTarget: { type, name: collectionName }
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
  // which is exactly what the agent asked the wallet for. The granted target
  // is a container URL, so it already carries its trailing slash.
  return fetch(new URL(resourceId, zcap.invocationTarget).toString())
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
  expect(zcap.invocationTarget.endsWith(`/${collectionName}/`)).toBe(true)
  expect(zcap.controller).toBe(agent.id)

  const published = await publishAndFetch({ agent, zcap, resourceId })
  expect(published.status).toBe(200)
  expect(published.headers.get('content-type')).toMatch(/^text\/html/)
  expect(await published.text()).toContain('Hello')
}

/**
 * Reads a collection's current `encryption` descriptor through the wallet's
 * own session (the non-production `window.__E2E_STORAGE__` seam), since the
 * agent's pull may already be revoked when this is asked.
 *
 * @param options {object}
 * @param options.page {Page}   a page holding the wallet's live session
 * @param options.collectionUrl {string}   the collection's container URL
 * @returns {Promise<CollectionEncryption>}
 */
async function walletReadDescriptor({
  page,
  collectionUrl
}: {
  page: Page
  collectionUrl: string
}): Promise<CollectionEncryption> {
  const meta = await page.evaluate(async (url: string) => {
    const storage = (
      window as unknown as {
        __E2E_STORAGE__?: {
          fetchCollectionMeta(options: { url: string }): Promise<unknown>
        }
      }
    ).__E2E_STORAGE__
    if (!storage) {
      throw new Error('No session published __E2E_STORAGE__ on this page.')
    }
    return storage.fetchCollectionMeta({ url })
  }, collectionUrl)
  const encryption = (meta as { encryption?: CollectionEncryption } | null)
    ?.encryption
  expect(encryption).toBeDefined()
  return encryption!
}

/**
 * The recipient key ids the descriptor's current epoch wraps to.
 *
 * @param descriptor {CollectionEncryption}
 * @returns {string[]}
 */
function currentEpochKids(descriptor: CollectionEncryption): string[] {
  const current = descriptor.epochs?.find(
    epoch => epoch.id === descriptor.currentEpoch
  )
  expect(current).toBeDefined()
  return current!.recipients.map(entry => entry.header.kid)
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
    // page runs the ordinary login itself (remembered here -- this browser
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

  test('grants a public collection from a transient session', async ({
    page
  }, testInfo) => {
    test.slow()

    // The default entry: a browser that remembers nothing, on a
    // credential-anchored account with no enrolled client anywhere. Its
    // grants are signed by the visit's annex key and chain under the
    // generation delegation rather than the Space root, so this arm is what
    // proves that chain verifies at the server -- under an annex VM
    // published for invocation alone the PUT below came back 404.
    const agent = await mintAgent()
    const collectionName = 'web'
    await signupViaWizard(page, testInfo, { rememberBrowser: false })

    const { exchangeUrl, interactionUrl } = await storeAgentRequest({
      controller: agent.id,
      collectionName
    })
    await page.goto(`/#${externalRequestPath({ url: interactionUrl })}`)
    await expect(
      page.getByRole('button', { name: 'Grant access' })
    ).toBeVisible({ timeout: 30_000 })
    await page.getByRole('button', { name: 'Grant access' }).click()
    await expect(
      page.getByText('Access granted', { exact: false })
    ).toBeVisible({ timeout: 60_000 })

    const zcaps = await grantedZcaps({ exchangeUrl })
    expect(zcaps.length).toBe(1)
    const zcap = zcaps[0]!
    // One deeper than a remembered session's grant: the parent is the
    // generation delegation rather than the Space root.
    const { parentCapability } = zcap as { parentCapability?: string }
    expect(parentCapability).toBeDefined()
    expect(parentCapability).not.toMatch(/^urn:zcap:root:/)

    const published = await publishAndFetch({
      agent,
      zcap,
      resourceId: 'transient.html'
    })
    expect(published.status).toBe(200)
    expect(await published.text()).toContain('Hello')
  })

  test('grants an encrypted private collection and rotates it off the agent on revoke', async ({
    page
  }, testInfo) => {
    test.slow()

    const agent = await mintAgent()
    const collectionName = 'agent-notes'
    // The agent's key-agreement key, the X25519 twin of its signing key. The
    // wallet derives the same key from the agent's did:key alone, so the kid
    // the agent decrypts with is the kid the wallet escrowed.
    const agentKeys = agentsFromKeyAgent({ keyAgent: agent })
    const agentKid = x25519RecipientFromDidKey({ did: agent.id }).id
    expect(agentKeys.keyAgreementKey.id).toBe(agentKid)

    await signupViaWizard(page, testInfo)

    const { exchangeUrl, interactionUrl } = await storeAgentRequest({
      controller: agent.id,
      collectionName,
      type: PRIVATE_COLLECTION
    })
    await page.goto(`/#${externalRequestPath({ url: interactionUrl })}`)
    await expect(
      page.getByRole('button', { name: 'Grant access' })
    ).toBeVisible({ timeout: 30_000 })
    await page.getByRole('button', { name: 'Grant access' }).click()
    await expect(
      page.getByText('Access granted', { exact: false })
    ).toBeVisible({ timeout: 60_000 })

    const zcaps = await grantedZcaps({ exchangeUrl })
    expect(zcaps.length).toBe(1)
    const zcap = zcaps[0]!
    const collectionUrl = zcap.invocationTarget
    expect(collectionUrl.endsWith(`/${collectionName}/`)).toBe(true)
    expect(zcap.controller).toBe(agent.id)

    // The collection is provisioned with key epochs, and the current one
    // wraps to the agent beside the user.
    const granted = await walletReadDescriptor({ page, collectionUrl })
    const grantedKids = currentEpochKids(granted)
    expect(grantedKids).toContain(agentKid)
    expect(grantedKids.length).toBeGreaterThanOrEqual(2)

    // The agent writes through its grant with its own key-agreement key.
    const encrypted = WasClient.fromSigner({
      serverUrl: WAS_URL,
      signer: agent.getSigner(),
      encryption: createEdvEncryption({
        resolveKeys: async () => ({
          keyAgreementKey: agentKeys.keyAgreementKey,
          keyResolver: agentKeys.keyResolver
        })
      })
    })
    const collection = encrypted.fromCapability(zcap) as Collection
    const note = { note: 'written by the agent', n: 1 }
    const { id: resourceId } = await collection.add(note)
    const resourceUrl = new URL(resourceId, collectionUrl).toString()

    // What the server stores is a JWE envelope, not the note.
    const raw = await agentKeys.zcapClient.request({
      url: resourceUrl,
      capability: zcap,
      method: 'GET',
      action: 'GET'
    })
    expect(raw.status).toBe(200)
    const envelope = raw.data as JsonObject
    expect(isEncryptedEnvelope(envelope)).toBe(true)
    expect(JSON.stringify(envelope)).not.toContain(note.note)

    // A private collection is not world-readable at all.
    const anonymous = await fetch(resourceUrl)
    expect(anonymous.status).not.toBe(200)

    // The agent decrypts its own write.
    expect(await collection.get(resourceId)).toEqual(note)

    // The wallet decrypts the agent's write as recipient zero. The wallet
    // has no path that writes into a grantee's collection, so this is the
    // other direction of the round-trip.
    const walletRead = await page.evaluate(
      async ({ collectionId, id, envelopeJson }) => {
        const storage = (
          window as unknown as {
            __E2E_STORAGE__?: {
              decryptCollectionResource(options: {
                collectionId: string
                resourceId: string
                data: unknown
              }): Promise<unknown>
            }
          }
        ).__E2E_STORAGE__
        return storage?.decryptCollectionResource({
          collectionId,
          resourceId: id,
          data: JSON.parse(envelopeJson) as unknown
        })
      },
      // Crossed as a string: the envelope's JSON type is too deep for the
      // evaluate argument's serializable type.
      {
        collectionId: collectionName,
        id: resourceId,
        envelopeJson: JSON.stringify(envelope)
      }
    )
    expect(walletRead).toEqual(note)

    // Revoke the agent on the Applications page.
    await page.goto('/#/applications')
    await expect(page.getByText(E2E_AGENT_NAME)).toBeVisible({
      timeout: 30_000
    })
    await page.getByRole('button', { name: 'Revoke Agent Access' }).click()
    await expect(page.getByText('Revoke agent access?')).toBeVisible()
    await page
      .getByRole('button', { name: 'Revoke access', exact: true })
      .click()
    await expect(page.getByText('Agent access revoked.')).toBeVisible({
      timeout: 60_000
    })

    // The collection gained a fresh epoch that no longer wraps to the agent.
    const rotated = await walletReadDescriptor({ page, collectionUrl })
    expect(rotated.currentEpoch).not.toBe(granted.currentEpoch)
    const rotatedKids = currentEpochKids(rotated)
    expect(rotatedKids).not.toContain(agentKid)
    expect(rotatedKids.length).toBeGreaterThanOrEqual(1)

    // And the agent's pull is dead.
    let revokedStatus: number | undefined
    try {
      const after = await agentKeys.zcapClient.request({
        url: resourceUrl,
        capability: zcap,
        method: 'GET',
        action: 'GET'
      })
      revokedStatus = after.status
    } catch (err) {
      revokedStatus = (err as { status?: number }).status
    }
    expect(revokedStatus).toBeDefined()
    expect(revokedStatus!).toBeGreaterThanOrEqual(400)
  })
})
